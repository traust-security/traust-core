"""golang.org/x/crypto usage: import lines and go.mod refs outside vendored trees, and the
reachable functions of each main package through the go-callgraph tool. Ported from traust
tests/test_scan_xcrypto_usage.py."""

from __future__ import annotations

import shlex
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

import pytest

from traust_core.v1.errors import ConfigError, IntegrityError, ValidationError
from traust_core.v1.models.code_facts import (
    GO_CALLGRAPH,
    GoCallgraph,
    GoEntrypoint,
    XcryptoReplace,
    XcryptoUsageFact,
)
from traust_core.v1.providers.base import Acquisition, ProviderRegistry, Readiness, Result
from traust_core.v1.providers.clock import FixedClock
from traust_core.v1.providers.tools import ToolProvider, ToolRequest
from traust_core.v1.providers.xcrypto import XcryptoUsage, package_of, reachable

AT = datetime(2026, 10, 26, tzinfo=UTC)
FIXTURE = Path(__file__).parents[2] / "fixtures/code_facts/xcrypto"
REPO = FIXTURE / "repo"
APP = "example.com/app/cmd/app"


def edges(path: Path) -> tuple[tuple[str, str], ...]:
    return tuple(tuple(shlex.split(line)) for line in path.read_text().splitlines())  # type: ignore[misc]


GRAPH = GoCallgraph(
    entrypoints=(
        GoEntrypoint(entrypoint="cmd/app", package=APP, edges=edges(FIXTURE / "cmd-app.digraph")),
        GoEntrypoint(entrypoint="cmd/tool", package="example.com/app/cmd/tool", error="exit 1"),
    )
)


class FakeCallgraph:
    name = GO_CALLGRAPH

    def __init__(self, found: object = GRAPH, ready: bool = True) -> None:
        self.found, self.ready, self.requests = found, ready, []

    def check(self) -> Readiness:
        return Readiness(ready=self.ready, detail="" if self.ready else "callgraph not on PATH")

    def acquire(self, request: ToolRequest) -> Result[Any]:
        self.requests.append(request)
        return Result(self.found, Acquisition(provider=self.name, acquired_at=AT))


def usage(tool: FakeCallgraph | None = None, **params: Any) -> XcryptoUsageFact:
    tools = ProviderRegistry[ToolProvider[Any]]("tool")
    if tool is not None:
        tools.register(GO_CALLGRAPH, lambda: tool)
    found = XcryptoUsage(FixedClock(AT), tools).enumerate(
        ToolRequest(workspace=REPO, params=params)
    )
    (fact,) = found.data
    assert isinstance(fact, XcryptoUsageFact)
    return fact


def test_import_sites_skip_vendored_copies() -> None:
    sites = {(str(s.location.path), s.location.line, s.package) for s in usage().imports}
    assert sites == {
        ("cmd/app/main.go", 7, "golang.org/x/crypto/ssh"),
        ("pkg/hash/hash.go", 3, "golang.org/x/crypto/bcrypt"),
        ("pkg/hash/hash_test.go", 6, "golang.org/x/crypto/bcrypt"),
        ("pkg/hash/hash_test.go", 7, "golang.org/x/crypto/hkdf"),
        ("docs/examples/openpgp.go", 3, "golang.org/x/crypto/openpgp"),
        ("third_party/lib/lib.go", 3, "golang.org/x/crypto/md4"),
    }


def test_go_mod_require_and_replace_outside_vendor() -> None:
    (module,) = usage().modules
    assert (module.path, module.require) == ("go.mod", ("v0.43.0",))
    assert module.replace == (XcryptoReplace(target="github.com/fork/crypto", version="v0.0.1"),)


def test_no_callgraph_unless_asked() -> None:
    tool = FakeCallgraph()
    assert usage(tool).callgraph is None
    assert tool.requests == []


def test_callgraph_reaches_xcrypto_with_a_shortest_witness() -> None:
    tool = FakeCallgraph()
    app, failed = usage(tool, callgraph=True).callgraph or ()
    assert tool.requests == [ToolRequest(workspace=REPO)]
    assert (failed.entrypoint, failed.error, failed.reachable) == ("cmd/tool", "exit 1", ())
    by = {r.function: r for r in app.reachable}
    assert by["golang.org/x/crypto/ssh.InsecureIgnoreHostKey"].witness == (
        f"{APP}.main",
        "golang.org/x/crypto/ssh.InsecureIgnoreHostKey",
    )
    encrypt = by["(*golang.org/x/crypto/blowfish.Cipher).Encrypt"]
    assert encrypt.package == "golang.org/x/crypto/blowfish"
    # the chain `digraph somepath` printed for the same graph (full and fixture subset)
    assert encrypt.witness == (
        f"{APP}.main",
        "example.com/app/pkg/hash.Sum",
        "golang.org/x/crypto/bcrypt.GenerateFromPassword",
        "golang.org/x/crypto/bcrypt.newFromPassword",
        "golang.org/x/crypto/bcrypt.bcrypt",
        encrypt.function,
    )
    # reached only from init: the witness starts there
    assert by["golang.org/x/crypto/ssh.init"].witness == (
        f"{APP}.init",
        "golang.org/x/crypto/ssh.init",
    )
    assert all(r.package.startswith("golang.org/x/crypto/") for r in app.reachable)


def test_a_function_no_root_reaches_has_no_witness() -> None:
    entry = GoEntrypoint(
        entrypoint=".", package="m", edges=(("m.helper", "golang.org/x/crypto/ssh.Dial"),)
    )
    (fn,) = reachable(entry).reachable
    assert (fn.function, fn.witness) == ("golang.org/x/crypto/ssh.Dial", ())


@pytest.mark.parametrize(
    ("function", "package"),
    [
        ("golang.org/x/crypto/ssh.Dial", "golang.org/x/crypto/ssh"),
        ("(*golang.org/x/crypto/ssh/agent.client).List", "golang.org/x/crypto/ssh/agent"),
        ("(golang.org/x/crypto/ssh.truncatingMAC).Size", "golang.org/x/crypto/ssh"),
        ("golang.org/x/crypto/bcrypt.bcrypt$1", "golang.org/x/crypto/bcrypt"),
        ("crypto/sha256.New", None),
        ("example.com/golang.org/x/crypto/ssh.Dial", None),
    ],
)
def test_package_of(function: str, package: str | None) -> None:
    assert package_of(function) == package


@pytest.mark.parametrize(
    ("tool", "error"),
    [
        (None, ConfigError),  # not registered
        (FakeCallgraph(ready=False), ConfigError),
        (FakeCallgraph(found=b"digraph"), IntegrityError),
    ],
)
def test_callgraph_asked_but_unavailable_raises(
    tool: FakeCallgraph | None, error: type[Exception]
) -> None:
    with pytest.raises(error):
        usage(tool, callgraph=True)


def test_callgraph_param_must_be_a_boolean() -> None:
    with pytest.raises(ValidationError):
        usage(FakeCallgraph(), callgraph="yes")


def test_a_checkout_without_go_has_no_usage(tmp_path: Path) -> None:
    (tmp_path / "app.py").write_text("import hashlib\n")
    tools = ProviderRegistry[ToolProvider[Any]]("tool")
    (fact,) = XcryptoUsage(FixedClock(AT), tools).enumerate(ToolRequest(workspace=tmp_path)).data
    assert fact == XcryptoUsageFact()
