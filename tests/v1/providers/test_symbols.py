from __future__ import annotations

import json
import shutil
from collections.abc import Sequence
from pathlib import Path
from typing import Any

import pytest

from tests.v1.conftest import CLOCK
from traust_core.v1.errors import ServiceError, ValidationError
from traust_core.v1.models.code_facts import SymbolFact
from traust_core.v1.providers.process import ProcessResult, ProcessRunner
from traust_core.v1.providers.symbols import CTAGS_BINARIES, SymbolIndex
from traust_core.v1.providers.tools import ToolRequest

GO_FILE = """package reconciler

const MaxRetries = 5

var (
\tdefaultRegistry = "quay.io/example/"
\tallowInsecure   = false
)

type KubeReconciler struct{}

func (r *KubeReconciler) mergeAgentEnvironment(base map[string]string) map[string]string {
\treturn base
}

func isAllowedRegistry(image string) bool {
\treturn len(image) > 0
}
"""

PY_FILE = '''"""Runner auth helpers."""

TOKEN_HEADER = "X-Example-Token"


class CredentialBroker:
    def issue_token(self, scope):
        return scope


def redact_secrets(text):
    return text
'''

TS_FILE = """export interface PreviewBridge {
  origin: string;
}

export function requestCapture(target: string): void {
}

export const sendFeedback = async (payload: string) => {
  return payload;
};
"""


@pytest.fixture
def clone(tmp_path: Path) -> Path:
    repo = tmp_path / "clone"
    for d in ("internal", "runner", "ui/src", "vendor/dep", "cmd"):
        (repo / d).mkdir(parents=True)
    (repo / "internal" / "reconciler.go").write_text(GO_FILE)
    (repo / "runner" / "auth.py").write_text(PY_FILE)
    (repo / "ui" / "src" / "bridge.ts").write_text(TS_FILE)
    (repo / "vendor" / "dep" / "dep.go").write_text("package dep\n\nfunc VendoredFn() {}\n")
    (repo / "cmd" / "main.go").write_text(
        'package main\n\nfunc main() {\n\t_ = isAllowedRegistry("x") // isAllowedRegistryX\n}\n'
    )
    return repo


@pytest.fixture
def index(monkeypatch: pytest.MonkeyPatch) -> SymbolIndex:
    monkeypatch.setattr(shutil, "which", lambda _: None)
    return SymbolIndex(ProcessRunner(CTAGS_BINARIES), CLOCK)


def names(index: SymbolIndex, root: Path) -> dict[str, SymbolFact]:
    facts = index.enumerate(ToolRequest(workspace=root)).data
    return {f.name: f for f in facts if isinstance(f, SymbolFact)}


@pytest.mark.parametrize(
    "expected",
    [
        "KubeReconciler",
        "mergeAgentEnvironment",
        "isAllowedRegistry",
        "MaxRetries",
        "defaultRegistry",
        "allowInsecure",
        "CredentialBroker",
        "issue_token",
        "redact_secrets",
        "TOKEN_HEADER",
        "PreviewBridge",
        "requestCapture",
        "sendFeedback",
    ],
)
def test_the_builtin_engine_finds_definitions(
    index: SymbolIndex, clone: Path, expected: str
) -> None:
    assert expected in names(index, clone)


def test_a_definition_carries_its_path_line_kind_and_language(
    index: SymbolIndex, clone: Path
) -> None:
    found = names(index, clone)["isAllowedRegistry"]
    assert (found.location.path, found.location.line) == ("internal/reconciler.go", 16)
    assert (found.kind, found.language) == ("func", "Go")
    assert names(index, clone)["KubeReconciler"].kind in {"type", "type-receiver"}


def test_vendored_code_and_symlinks_are_not_indexed(
    index: SymbolIndex, clone: Path, tmp_path: Path
) -> None:
    outside = tmp_path / "host.go"
    outside.write_text("package host\n\nfunc HostSecret() {}\n")
    (clone / "linked.go").symlink_to(outside)
    found = names(index, clone)
    assert "VendoredFn" not in found
    assert "HostSecret" not in found


def test_the_engine_is_reported(index: SymbolIndex, clone: Path) -> None:
    assert index.check().detail == "engine: builtin"
    assert index.enumerate(ToolRequest(workspace=clone)).acquisition.source == "builtin"


def test_a_missing_workspace_is_rejected(index: SymbolIndex, tmp_path: Path) -> None:
    with pytest.raises(ValidationError, match="not a directory"):
        index.enumerate(ToolRequest(workspace=tmp_path / "missing"))


def test_references_are_word_bounded_with_context(index: SymbolIndex, clone: Path) -> None:
    refs = index.references(clone, {"isAllowedRegistry"})
    assert {(r.path, r.line) for r in refs} == {
        ("internal/reconciler.go", 16),
        ("cmd/main.go", 4),
    }
    caller = next(r for r in refs if r.path == "cmd/main.go")
    assert caller.context.splitlines()[0] == "1: package main"
    assert "4: \t_ = isAllowedRegistry" in caller.context


def test_references_to_several_names_take_one_pass_and_keep_each_name(
    index: SymbolIndex, clone: Path
) -> None:
    refs = index.references(clone, {"KubeReconciler", "Kube", "redact_secrets"})
    assert {r.symbol for r in refs} == {"KubeReconciler", "redact_secrets"}
    assert index.references(clone, set()) == []


class _Ctags:
    def __init__(self, tags: Sequence[dict[str, Any]], returncode: int = 0) -> None:
        self.tags, self.returncode = tags, returncode

    def allows(self, binary: str) -> bool:
        return True

    def run(self, argv: Sequence[str], **_: Any) -> ProcessResult:
        if "--version" in argv:
            return ProcessResult(tuple(argv), 0, b"Universal Ctags 6.1.0", b"", 0.0)
        assert "--options=NONE" in argv
        out = "\n".join(json.dumps(t) for t in self.tags).encode()
        return ProcessResult(tuple(argv), self.returncode, out, b"", 0.0)


def test_universal_ctags_is_preferred_when_installed(
    monkeypatch: pytest.MonkeyPatch, clone: Path
) -> None:
    monkeypatch.setattr(shutil, "which", lambda name: f"/opt/{name}")
    tags = [
        {"_type": "tag", "name": "Run", "path": "./cmd/main.go", "line": 3, "kind": "func"},
        {"_type": "ptag", "name": "TAG_PROGRAM_NAME"},
        {"_type": "tag", "name": "", "path": "x.go", "line": 1},
    ]
    index = SymbolIndex(_Ctags(tags), CLOCK)  # type: ignore[arg-type]
    result = index.enumerate(ToolRequest(workspace=clone))
    assert result.acquisition.source == "ctags"
    assert [(f.name, f.location.path) for f in result.data if isinstance(f, SymbolFact)] == [
        ("Run", "cmd/main.go")
    ]


def test_a_failing_ctags_raises(monkeypatch: pytest.MonkeyPatch, clone: Path) -> None:
    monkeypatch.setattr(shutil, "which", lambda name: f"/opt/{name}")
    index = SymbolIndex(_Ctags([], returncode=1), CLOCK)  # type: ignore[arg-type]
    with pytest.raises(ServiceError, match="ctags exited 1"):
        index.enumerate(ToolRequest(workspace=clone))


def test_ctags_outside_the_allowlist_never_runs(
    monkeypatch: pytest.MonkeyPatch, clone: Path
) -> None:
    monkeypatch.setattr(shutil, "which", lambda name: f"/opt/{name}")
    result = SymbolIndex(ProcessRunner(()), CLOCK).enumerate(ToolRequest(workspace=clone))
    assert result.acquisition.source == "builtin"
