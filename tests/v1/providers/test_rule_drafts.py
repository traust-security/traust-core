"""The rule-drafts directory: rule specs resolved against it and the pack, sweep and regression
drafts staged in it. Ported from traust-engine tests/test_sweep_engine.py and traust
tests/test_sweep_regression_drafts.py (traust 71c3f34)."""

from __future__ import annotations

from pathlib import Path
from uuid import UUID

import pytest
import yaml

from traust_core.v1.context.documents import yaml_documents, yaml_text
from traust_core.v1.errors import NotFoundError, ValidationError
from traust_core.v1.models.detection_quality import PairFile, RegressionPair
from traust_core.v1.models.rule_mining import DraftSource, SweepDraft
from traust_core.v1.providers.rule_drafts import RuleDraftDirectory

AUTHORED = """rules:
  - id: traust-go-sweep-cwe-78
    languages: [go]
    severity: ERROR
    message: sh -c command execution sink
    metadata:
      cwe: ["CWE-78"]
      category: sweep-generalization
      generalized_from:
        - source_finding: "FIND-001"
          repo: "repoa"
          location: "pkg/run.go:10"
          artifact: "ledger:prod/repoa"
    pattern: exec.Command("sh", "-c", ...)
"""
PACK_RULE = """rules:
  - id: traust-go-cmd-injection
    languages: [go]
    metadata:
      cwe: ["CWE-78"]
      regression_of: {fingerprint: abc, source_finding: f-1}
    pattern: exec.Command("sh", "-c", ...)
"""
FINDING = UUID("00000000-0000-0000-0000-000000000001")
VULN = 'import os\n\n\ndef run(arg):\n    os.system("ls " + arg)\n'
SAFE = 'import subprocess\n\n\ndef run(arg):\n    subprocess.run(["ls", arg])\n'
PAIR = RegressionPair(
    finding_id=FINDING,
    repository_url="https://github.com/org/repo-a",
    fingerprint="0123456789abcdef",
    title="Command injection in run",
    cwes=("CWE-78",),
    severity="high",
    language="python",
    pre_fix_sha="a" * 40,
    fix_sha="b" * 40,
    rationale="Commit bbbbbbb passes argv",
    files=(
        PairFile(path="app/run.py", before=VULN, after=SAFE),
        PairFile(path="app/old.py", before=VULN, after=None),
    ),
)


@pytest.fixture
def drafts(tmp_path: Path) -> RuleDraftDirectory:
    pack = tmp_path / "pack"
    (pack / "go").mkdir(parents=True)
    (pack / "go" / "injection.yaml").write_text(PACK_RULE)
    authored = tmp_path / "rule-drafts" / "sweep-go-cwe-78"
    authored.mkdir(parents=True)
    (authored / "rule.skeleton.yaml").write_text(AUTHORED)
    return RuleDraftDirectory(tmp_path / "rule-drafts", pack, yaml_documents, yaml_text)


def test_held_drafts_and_their_rule_ids(drafts: RuleDraftDirectory) -> None:
    assert drafts.names() == {"sweep-go-cwe-78"}
    assert drafts.rule_ids() == {"traust-go-sweep-cwe-78"}


def test_a_missing_directory_holds_nothing(tmp_path: Path) -> None:
    empty = RuleDraftDirectory(tmp_path / "none", tmp_path / "none", yaml_documents, yaml_text)
    assert (empty.names(), empty.rule_ids()) == (frozenset(), frozenset())


@pytest.mark.parametrize(
    ("spec", "where"),
    [
        ("sweep-go-cwe-78", "rule-drafts/sweep-go-cwe-78/rule.skeleton.yaml"),
        ("traust-go-sweep-cwe-78", "rule-drafts/sweep-go-cwe-78/rule.skeleton.yaml"),
        ("traust-go-cmd-injection", "pack/go/injection.yaml"),
        ("{tmp}/rule-drafts/sweep-go-cwe-78", "rule-drafts/sweep-go-cwe-78/rule.skeleton.yaml"),
        ("{tmp}/pack/go/injection.yaml", "pack/go/injection.yaml"),
    ],
)
def test_a_rule_spec_resolves_by_path_draft_or_id(
    drafts: RuleDraftDirectory, tmp_path: Path, spec: str, where: str
) -> None:
    assert drafts.resolve(spec.format(tmp=tmp_path)).path == (tmp_path / where).resolve()


def test_a_resolved_rule_carries_its_ids_and_provenance(drafts: RuleDraftDirectory) -> None:
    rule = drafts.resolve("traust-go-sweep-cwe-78")
    assert (rule.ids, rule.unauthored) == (("traust-go-sweep-cwe-78",), False)
    assert rule.provenance[0]["source_finding"] == "FIND-001"  # type: ignore[index]
    assert drafts.resolve("traust-go-cmd-injection").provenance == (
        {"fingerprint": "abc", "source_finding": "f-1"},
    )


def test_an_unknown_rule_is_not_found(drafts: RuleDraftDirectory) -> None:
    with pytest.raises(NotFoundError, match="rule not found: no-such-rule"):
        drafts.resolve("no-such-rule")


def test_a_rule_file_without_an_id_is_refused(drafts: RuleDraftDirectory, tmp_path: Path) -> None:
    (tmp_path / "x.yaml").write_text("rules: []\n")
    with pytest.raises(ValidationError, match="no rule id"):
        drafts.resolve(str(tmp_path / "x.yaml"))


def test_a_todo_skeleton_is_unauthored(drafts: RuleDraftDirectory, tmp_path: Path) -> None:
    (tmp_path / "todo.yaml").write_text("rules:\n  - id: x-sweep\n    pattern: TODO\n")
    assert drafts.resolve(str(tmp_path / "todo.yaml")).unauthored


SWEEP_DRAFT = SweepDraft(
    cwe="CWE-798",
    language="go",
    count=2,
    repos=1,
    severity="ERROR",
    sources=(
        DraftSource(
            source_finding="f-1", repo="repoc", file="cmd/main.go", line=9, artifact="ledger:r"
        ),
        DraftSource(source_finding="f-2", repo="repoc", file="cmd/x.go", artifact="ledger:r"),
    ),
)


def test_a_sweep_draft_is_staged_with_its_skeleton_and_notes(drafts: RuleDraftDirectory) -> None:
    drafts.stage_sweep(SWEEP_DRAFT)
    staged = drafts.root / "sweep-go-cwe-798"
    (rule,) = yaml.safe_load((staged / "rule.skeleton.yaml").read_text())["rules"]
    assert (rule["id"], rule["languages"], rule["severity"]) == (
        "traust-go-sweep-cwe-798",
        ["go"],
        "ERROR",
    )
    assert rule["metadata"]["generalized_from"][0] == {
        "source_finding": "f-1",
        "repo": "repoc",
        "location": "cmd/main.go:9",
        "artifact": "ledger:r",
    }
    assert rule["metadata"]["generalized_from"][1]["location"] == "cmd/x.go"
    notes = (staged / "DRAFT.md").read_text()
    assert "**CWE-798 × go**" in notes and "`repoc` — cmd/main.go:9" in notes  # noqa: RUF001
    assert "traust sweep sweep --rule sweep-go-cwe-798" in notes
    assert drafts.resolve("sweep-go-cwe-798").unauthored


def test_a_regression_draft_holds_both_sides_of_the_fix(drafts: RuleDraftDirectory) -> None:
    drafts.stage_regression(PAIR)
    draft = drafts.root / PAIR.id
    assert (draft / "before/app/run.py").read_text() == VULN
    assert (draft / "after/app/run.py").read_text() == SAFE
    assert (draft / "before/app/old.py").is_file() and not (draft / "after/app/old.py").exists()
    (rule,) = yaml.safe_load((draft / "rule.skeleton.yaml").read_text())["rules"]
    assert (rule["id"], rule["severity"], rule["languages"]) == (PAIR.rule_id, "ERROR", ["python"])
    assert rule["metadata"]["regression_of"] == {
        "fingerprint": PAIR.fingerprint,
        "source_finding": str(FINDING),
        "repo": PAIR.repository_url,
        "fix_commit": "b" * 40,
    }
    notes = (draft / "DRAFT.md").read_text()
    assert "Commit bbbbbbb passes argv" in notes
    assert f"traust sweep verify-draft {draft}" in notes


def test_restaging_a_regression_draft_replaces_it(drafts: RuleDraftDirectory) -> None:
    drafts.stage_regression(PAIR)
    authored = drafts.root / PAIR.id / "rule.skeleton.yaml"
    authored.write_text("authored")
    (drafts.root / PAIR.id / "before" / "stale.py").write_text("x")
    drafts.stage_regression(PAIR)
    assert authored.read_text() != "authored"
    assert not (drafts.root / PAIR.id / "before" / "stale.py").exists()
