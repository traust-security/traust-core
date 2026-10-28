"""The adopter's rule-drafts directory (`locations.rule_drafts`): candidate rules staged for
authoring, one directory each, and the `--rule` specs the sweep resolves against it and the
pack. Nothing is written outside it."""

from __future__ import annotations

import re
import shutil
from collections.abc import Callable
from pathlib import Path
from typing import Any

from traust_core.v1.errors import NotFoundError, ValidationError
from traust_core.v1.models.detection_quality import RegressionPair
from traust_core.v1.models.rule_mining import RuleFile, SweepDraft
from traust_core.v1.models.vocabulary import FindingKind
from traust_core.v1.providers.config_matrix import YamlLoader

SKELETON = "rule.skeleton.yaml"
NOTES = "DRAFT.md"
_RULE_ID = re.compile(r"^\s*-\s*id:\s*(\S+)", re.MULTILINE)
YamlDumper = Callable[[object], str]
_TIMES = "\N{MULTIPLICATION SIGN}"


class RuleDraftDirectory:
    def __init__(self, root: Path, pack: Path, load: YamlLoader, dump: YamlDumper) -> None:
        self.root = root
        self._pack = pack
        self._load = load
        self._dump = dump

    def names(self) -> frozenset[str]:
        """The draft directories staged so far."""
        return (
            frozenset(d.name for d in self.root.glob("*/")) if self.root.is_dir() else frozenset()
        )

    def rule_ids(self) -> frozenset[str]:
        """The rule ids the staged skeletons declare."""
        skeletons = self.root.glob(f"*/{SKELETON}") if self.root.is_dir() else ()
        return frozenset(i for path in skeletons for i in _RULE_ID.findall(_text(path)))

    def resolve(self, spec: str) -> RuleFile:
        """A rule yaml path, a draft dir (or draft name), or a bare rule id searched across the
        pack and the drafts."""
        path = Path(spec)
        if path.is_dir():
            path = path / SKELETON
        if not path.is_file() and (self.root / spec).is_dir():
            path = self.root / spec / SKELETON
        if not path.is_file():
            declares = re.compile(rf"^\s*-\s*id:\s*{re.escape(spec)}\s*$", re.MULTILINE)
            path = next((p for p in self._candidates() if declares.search(_text(p))), Path())
        if not path.is_file():
            raise NotFoundError(f"rule not found: {spec}")
        text = _text(path)
        ids = tuple(_RULE_ID.findall(text))
        if not ids:
            raise ValidationError(f"no rule id in {path}")
        return RuleFile(
            path=path.resolve(),
            ids=ids,
            unauthored="TODO" in text,
            provenance=self._provenance(text, spec if spec in ids else ids[0]),
        )

    def stage_sweep(self, draft: SweepDraft) -> None:
        """A sweep draft's skeleton and notes; the caller never re-stages a held draft."""
        target = self.root / draft.slug
        target.mkdir(parents=True, exist_ok=True)
        (target / SKELETON).write_text(_sweep_skeleton(draft), encoding="utf-8")
        (target / NOTES).write_text(_sweep_notes(draft), encoding="utf-8")

    def stage_regression(self, pair: RegressionPair) -> None:
        """A regression draft: the finding's files before and after the fix, a skeleton citing
        the fix, and the notes; replaces a draft of the same name."""
        target = self.root / pair.id
        if target.exists():
            shutil.rmtree(target)
        for side in ("before", "after"):
            (target / side).mkdir(parents=True)
        for f in pair.files:
            for side, text in (("before", f.before), ("after", f.after)):
                if text is not None:
                    path = target / side / f.path  # a RepoPath: relative, no `..`
                    path.parent.mkdir(parents=True, exist_ok=True)
                    path.write_text(text, encoding="utf-8")
        (target / SKELETON).write_text(self._dump(_regression_rule(pair)), encoding="utf-8")
        (target / NOTES).write_text(_regression_notes(target, pair), encoding="utf-8")

    def _candidates(self) -> list[Path]:
        pack = sorted(self._pack.rglob("*.yaml")) if self._pack.is_dir() else []
        drafts = sorted(self.root.glob(f"*/{SKELETON}")) if self.root.is_dir() else []
        return pack + drafts

    def _provenance(self, text: str, rule_id: str) -> tuple[Any, ...]:
        """The confirmed findings the rule's metadata says it was generalized from."""
        try:
            docs = self._load(text)
        except ValidationError:
            return ()
        doc = docs[0] if docs and isinstance(docs[0], dict) else {}
        for rule in doc.get("rules") or []:
            if not isinstance(rule, dict) or rule.get("id") != rule_id:
                continue
            meta = rule.get("metadata") or {}
            if meta.get("generalized_from"):
                return tuple(meta["generalized_from"])
            if meta.get("regression_of"):
                return (meta["regression_of"],)
        return ()


def _text(path: Path) -> str:
    try:
        return path.read_text(encoding="utf-8")
    except (OSError, UnicodeDecodeError):
        return ""


def _at(line: int | None) -> str:
    return f":{line}" if line else ""


def _sweep_skeleton(draft: SweepDraft) -> str:
    cited = "".join(
        f'        - source_finding: "{s.source_finding}"\n'
        f'          repo: "{s.repo}"\n'
        f'          location: "{s.file}{_at(s.line)}"\n'
        f'          artifact: "{s.artifact}"\n'
        for s in draft.sources
    )
    return (
        "rules:\n"
        f"  - id: {draft.rule_id}\n"
        f"    languages: [{draft.language}]\n"
        f"    severity: {draft.severity}\n"
        "    message: >-\n"
        "      TODO — one-sentence description of the confirmed syntactic\n"
        f"      shape this class generalizes. {draft.cwe}.\n"
        "    metadata:\n"
        f'      cwe: ["{draft.cwe}"]\n'
        + (f"      kind: {draft.kind}\n" if draft.kind == FindingKind.WEAKNESS else "")
        + "      category: sweep-generalization\n"
        "      confidence: HIGH\n"
        "      generalized_from:\n"
        f"{cited}"
        "    patterns:\n"
        "      - pattern: TODO   # author from the cited confirmed findings' evidence\n"
    )


def _sweep_notes(draft: SweepDraft) -> str:
    cites = "\n".join(
        f"- `{s.repo}` — {s.file}{_at(s.line)} · finding `{s.source_finding}` · from `{s.artifact}`"
        for s in draft.sources
    )
    return f"""# Rule draft: {draft.rule_id}

**Class-generalization sweep candidate**:
{draft.count} confirmed finding(s) across {draft.repos} repo(s)
pin the same syntactic shape — **{draft.cwe} {_TIMES} {draft.language}** —
and no shipped traust rule covers the class.

**Source confirmed findings (specification material):**

{cites}

**Authoring contract:** write `patterns:` in `rule.skeleton.yaml` from
the cited findings' evidence so the rule fires on each source shape.
Calibrate via the rule calibration path (fixture `ruleid:`/`ok:` lines,
the test-and-calibrate gate) before promotion into the pack — the
sweep engine will refuse to run an unauthored (TODO) skeleton. Once
authored, the corpus-wide sweep runs BY DEFAULT:

    traust sweep sweep --rule {draft.slug}
    traust sweep emit  --rule {draft.slug}

Sweep hits are triage input material only — feed them to the triage
workflow; they never become filed findings automatically.
"""


def _regression_rule(pair: RegressionPair) -> dict[str, Any]:
    return {
        "rules": [
            {
                "id": pair.rule_id,
                "languages": [pair.language],
                "severity": pair.rule_severity,
                "message": (
                    f"TODO: one sentence on the vulnerable shape and the fix. {pair.cwes[0]}."
                ),
                "metadata": {
                    "cwe": list(pair.cwes),
                    "category": "regression",
                    "confidence": "HIGH",
                    "regression_of": {
                        "fingerprint": pair.fingerprint,
                        "source_finding": str(pair.finding_id),
                        "repo": pair.repository_url,
                        "fix_commit": pair.fix_sha,
                    },
                },
                "patterns": [
                    {"pattern": "TODO: author from before/ (must fire) vs after/ (must not)"}
                ],
            }
        ]
    }


def _regression_notes(draft: Path, pair: RegressionPair) -> str:
    excerpt = " ".join((pair.rationale or "").split())[:500]
    return f"""# Rule draft: {pair.rule_id}

**Regression guard for:** {pair.title or "(untitled finding)"}
**CWE:** {", ".join(pair.cwes)} · **severity:** {pair.severity}
**Repo:** {pair.repository_url}
**Pre-fix commit:** `{pair.pre_fix_sha}` · **fix commit:** `{pair.fix_sha}`
**Fingerprint:** `{pair.fingerprint}` · **finding:** `{pair.finding_id}`

**Fix rationale (verification evidence):**

> {excerpt}

**Authoring contract:** write `patterns:` in `rule.skeleton.yaml` so that
`traust sweep verify-draft {draft}` fires on every file in `before/` and on
nothing in `after/`. Then move the rule into the pack category file in
the security pack (`packs/security/detection/opengrep-rules/`; not a `regression.yaml`
dump, match the pack's category layout) with `ruleid:`-annotated fixture
lines, and delete this draft dir.
"""
