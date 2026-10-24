from __future__ import annotations

import json
import re
from collections import Counter
from collections.abc import Collection, Iterable, Sequence
from datetime import datetime
from enum import StrEnum
from typing import Any, Self
from uuid import UUID

import pydantic

from traust_core.v1.errors import ConflictError, NotFoundError, ValidationError
from traust_core.v1.models.base import Dto, Model
from traust_core.v1.models.common import ArtifactRef, CodeSpan, RepoPath
from traust_core.v1.models.dependencies import (
    AffectedPackage,
    ConsumedVersion,
    FixUptake,
    FixUptakeState,
    Version,
)
from traust_core.v1.models.findings import (
    CweId,
    Decision,
    FindingCandidate,
    FindingView,
    Label,
    SkillInput,
)
from traust_core.v1.models.inventory import OrgName
from traust_core.v1.models.values import HttpsRepoUrl
from traust_core.v1.models.vocabulary import (
    CrossRepoPropagation,
    DispositionResolution,
    Ecosystem,
    FindingOrigin,
    FixStrategy,
    FleetFixMatcherKind,
    ForkHost,
    ForkVisibility,
    PatchEvidenceKind,
    RemediationStatus,
    ScannerSeverity,
    Validity,
    VerificationVerdict,
)


# Shapes land with their implementation slice.
class ExternalRef(Model):
    """A thing in another system: a merge request, a commit or a ticket, by URL or key."""

    system: str
    ref: str


class FleetFixSpec(Model): ...


class FleetTarget(Model): ...


class PatchResult(Model): ...


class WorkItemFilter(Model):
    """A repository's work items, optionally only those at one status."""

    repository_id: UUID
    status: RemediationStatus | None = None


class FleetFixMatcher(Model):
    kind: FleetFixMatcherKind


PROVES = "proves"
FAILS_TO_PROVE = "fails_to_prove"
_NOT_ATTEMPTED = "not_attempted: "


class EvidenceItem(Model):
    """One base-versus-patch observation: the remediation schema's `patch_evidence`."""

    kind: PatchEvidenceKind
    outcome: str = pydantic.Field(pattern=r"^(proves|fails_to_prove|not_attempted: .+)$")
    base_observation: str | None = pydantic.Field(default=None, min_length=1)
    patched_observation: str | None = pydantic.Field(default=None, min_length=1)
    tool: str | None = None
    command: str | None = None
    log_path: str | None = None
    deterministic_steps: str = pydantic.Field(default="ran", pattern=r"^(ran|skipped: .+)$")

    @pydantic.model_validator(mode="after")
    def _claims_carry_both_observations(self) -> Self:
        # The schema's rule: a check that never ran can't count as evidence.
        if self.outcome in (PROVES, FAILS_TO_PROVE) and not (
            self.base_observation and self.patched_observation
        ):
            raise ValueError(f"{self.outcome} needs both the base and the patched observation")
        return self

    def not_attempted(self, reason: str, step: str | None = None) -> EvidenceItem:
        return self.model_copy(
            update={
                "outcome": f"{_NOT_ATTEMPTED}{reason}",
                "deterministic_steps": f"skipped: {step or reason}",
                "base_observation": None,
                "patched_observation": None,
            }
        )


TIMEOUT_RC = 124  # `timeout` exits 124 when it had to kill the run
_MEWT_TEST_SUFFIX = "_test.go"
_PYTEST_PASSED, _PYTEST_FAILED, _PYTEST_NO_TESTS = 0, 1, 5
_PYTEST_EXIT = {
    _PYTEST_PASSED: "passed",
    _PYTEST_FAILED: "failed",
    2: "was interrupted",
    3: "hit an internal pytest error",
    4: "was a pytest usage error",
    _PYTEST_NO_TESTS: "collected no tests",
    TIMEOUT_RC: "exceeded its timeout",
}


class _MewtTarget(Dto):
    path: str = ""
    total_mutants: int = 0
    tested: int = 0
    caught: int = 0
    uncaught: int = 0
    skipped: int = 0
    untested: int = 0
    timeout: int = 0


class _MewtStatus(Dto):
    targets: tuple[_MewtTarget, ...] = ()


def _command(base: str, boundary: str) -> str:
    # Nested podman and an attested sandbox are not equally strong; the reader must see which.
    return f"{base}  [boundary: {boundary}]" if boundary else base


def mutation_evidence(
    target: str, rc: int, tool_version: str, log_path: str, status: bytes | None, boundary: str = ""
) -> EvidenceItem:
    """A mewt campaign's `status --format json` as evidence: proof only when every mutant of the
    patched (non-test) code ran and was caught."""
    version = tool_version.strip()
    item = EvidenceItem(
        kind=PatchEvidenceKind.MUTATION,
        outcome=f"{_NOT_ATTEMPTED}pending",
        tool=version if version.lower().startswith("mewt") else f"mewt {version}".strip(),
        command=_command(f'mewt run --test.cmd "go test ./..." {target}', boundary),
        log_path=log_path,
    )
    if rc == TIMEOUT_RC:
        return item.not_attempted("campaign exceeded its timeout", "timeout")
    if not status:
        exited = f"mewt exited {rc} and produced" if rc else "mewt produced"
        return item.not_attempted(f"{exited} no readable status json")
    try:
        rows = _MewtStatus.model_validate(json.loads(status)).targets
    except (ValueError, pydantic.ValidationError):
        return item.not_attempted("mewt status json was unparseable")
    src = [r for r in rows if not r.path.endswith(_MEWT_TEST_SUFFIX)]
    tests = len(rows) - len(src)
    generated = sum(r.total_mutants for r in src)
    if generated == 0:
        return item.not_attempted(f"mewt generated no mutants for {target}")
    tested, caught, uncaught, skipped, untested, timed_out = (
        sum(getattr(r, k) for r in src)
        for k in ("tested", "caught", "uncaught", "skipped", "untested", "timeout")
    )
    unexercised = skipped + untested
    base = (
        f"{generated} mutant(s) generated across {len(src)} non-test file(s) in {target}; "
        f"{tested} exercised against the suite as patched"
        + (f"; {tests} test-file target(s) excluded from the claim" if tests else "")
    )
    patched = (
        f"{caught} caught, {uncaught} uncaught, {timed_out} timed out, "
        f"{unexercised} never exercised (skipped {skipped}, untested {untested})"
    )
    # mewt skips milder mutants on a line whose severe one escaped: zero uncaught isn't proof.
    if uncaught or timed_out:
        outcome = FAILS_TO_PROVE
    elif unexercised:
        outcome, patched = (
            FAILS_TO_PROVE,
            f"{patched} — nothing escaped, but not every mutant was run",
        )
    elif tested and caught == generated:
        outcome = PROVES
    else:
        return item.not_attempted("mewt status did not account for every generated mutant")
    return item.model_copy(
        update={"outcome": outcome, "base_observation": base, "patched_observation": patched}
    )


def property_evidence(
    test_path: str,
    base_ref: str,
    base_rc: int,
    patched_rc: int,
    tool_version: str = "",
    base_log: str = "",
    patched_log: str = "",
    boundary: str = "",
) -> EvidenceItem:
    """A base-versus-patched property run as evidence: proof only when the property fails on the
    base and passes on the patch (one that held before witnesses nothing)."""
    item = EvidenceItem(
        kind=PatchEvidenceKind.PROPERTY,
        outcome=f"{_NOT_ATTEMPTED}pending",
        tool=tool_version or "hypothesis",
        command=_command(f"pytest {test_path}", boundary),
        log_path=patched_log,
    )
    if TIMEOUT_RC in (base_rc, patched_rc):
        return item.not_attempted("property run exceeded its timeout", "timeout")
    if _PYTEST_NO_TESTS in (base_rc, patched_rc):
        return item.not_attempted(
            f"pytest collected no tests from {test_path} — the property was not injected into "
            "the base revision, or the path is wrong",
            "no tests collected",
        )
    for label, rc in (("base", base_rc), ("patched", patched_rc)):
        if rc not in (_PYTEST_PASSED, _PYTEST_FAILED):
            said = _PYTEST_EXIT.get(rc, f"exited {rc}")
            return item.not_attempted(
                f"the {label} revision's run {said}, so there is no base-versus-patch comparison",
                f"{label} run {said}",
            )
    patched = f"on the patched revision the property {_PYTEST_EXIT[patched_rc]}"
    if base_rc == _PYTEST_PASSED:
        outcome = FAILS_TO_PROVE
        patched += " — but it also held before the patch, so it does not witness this finding"
    elif patched_rc == _PYTEST_FAILED:
        outcome, patched = FAILS_TO_PROVE, f"{patched} — the property still finds a counterexample"
    else:
        outcome = PROVES
    return item.model_copy(
        update={
            "outcome": outcome,
            "base_observation": f"on the unpatched revision ({base_ref}) the property "
            f"{_PYTEST_EXIT[base_rc]} — log at {base_log}",
            "patched_observation": patched,
        }
    )


class Fork(Model):
    """Where a fix is pushed: a private mirror of the upstream, or the repository itself."""

    host: ForkHost
    owner: OrgName
    url: HttpsRepoUrl
    visibility: ForkVisibility


# Forward-only: a retry after a failed attempt is a new work item.
_STEP = {
    "candidate": 0,
    "forked": 1,
    "patched": 2,
    "checks_passed": 3,
    "checks_failed": 3,
    "revalidated_fixed": 4,
    "revalidated_still_vulnerable": 4,
    "pr_opened": 5,
    "merged": 6,
    "abandoned": 7,
}
_FINAL = frozenset({"merged", "abandoned"})
# What each status says about the findings' resolution; None = no answer yet. A merged fix is a
# claim, still fix_in_progress: only a verification marks a finding resolved.
_RESOLUTION: dict[str, str | None] = {
    "candidate": None,
    "forked": "fix_in_progress",
    "patched": "fix_in_progress",
    "checks_passed": "fix_in_progress",
    "revalidated_fixed": "fix_in_progress",
    "pr_opened": "fix_in_progress",
    "checks_failed": "open",
    "revalidated_still_vulnerable": "open",
    "abandoned": "open",
    "merged": "fix_in_progress",
}


def furthest(statuses: Iterable[str]) -> RemediationStatus:
    """Where a work item stands: steps only move forward, so the furthest one said."""
    return RemediationStatus(max(statuses, key=_STEP.__getitem__))


def resolution_for(status: RemediationStatus) -> DispositionResolution | None:
    said = _RESOLUTION[status]
    return None if said is None else DispositionResolution(said)


class WorkItem(Model):
    """One remediation attempt: a `remediation` assessment of the commit the findings were found
    on, its status from its decisions, and its report once recorded."""

    work_item_id: UUID
    repository_ref_id: UUID
    finding_ids: tuple[UUID, ...]
    status: RemediationStatus
    opened_at: datetime
    strategy: FixStrategy | None = None
    fork: Fork | None = None
    tracker: ExternalRef | None = None
    evidence: tuple[EvidenceItem, ...] = ()
    report: ArtifactRef | None = None

    def advance(self, status: RemediationStatus) -> WorkItem:
        """The item at `status`: forward only, nothing after merged or abandoned."""
        if status == self.status:
            return self
        if self.status in _FINAL or (status != "abandoned" and _STEP[status] <= _STEP[self.status]):
            raise ConflictError(
                f"work item {self.work_item_id}: {self.status} can't move to {status}"
            )
        return self.model_copy(update={"status": status})

    def is_done(self) -> bool:
        return self.report is not None


# The SKILL.md's preferred strategy per weakness class; anything else is the agent's call.
_STRATEGY_BY_CWE = {
    **dict.fromkeys(("22", "73", "78", "88", "94"), "input-validation"),
    **dict.fromkeys(("400", "770", "789"), "bound-resource"),
    **dict.fromkeys(("918", "941"), "url-allowlist"),
    **dict.fromkeys(("284", "285", "862", "863"), "rbac-scope-down"),
    **dict.fromkeys(("306", "287"), "auth-add"),
    **dict.fromkeys(("295", "319"), "tls-enforce"),
    **dict.fromkeys(("494", "829"), "digest-pin"),
    **dict.fromkeys(("1188", "276"), "config-default-harden"),
}


def preferred_strategy(finding: FindingView) -> FixStrategy | None:
    """A vulnerable dependency is bumped; a known weakness class has its preferred fix."""
    if finding.finding.advisory_id is not None:
        return FixStrategy("dependency-bump")
    known = (_STRATEGY_BY_CWE.get(c.removeprefix("CWE-")) for c in finding.cwes)
    return next((FixStrategy(s) for s in known if s), None)


class RemediationItem(Model):
    """One finding to fix: as it stands, every judgement on it (the triage rationale first
    among them), and the preferred strategy for its class."""

    finding: FindingView
    decisions: tuple[Decision, ...] = ()
    strategy: FixStrategy | None = None


class RemediationInput(SkillInput):
    """What the skill patches: the work item, its findings, where to push."""

    work_item: WorkItem
    items: tuple[RemediationItem, ...]
    fork: Fork
    fix_branch: str


class FleetFix(Model):
    matcher: FleetFixMatcher
    spec: FleetFixSpec
    target_ids: tuple[UUID, ...] = ()
    approval_id: UUID | None = None


# Verification: a `verification` assessment of the patched commit, its report, one decision per
# verified finding (reason = the verdict) and the regressions it reported as occurrences.


class FindingVerdict(Model):
    finding_id: UUID
    verdict: VerificationVerdict


class Verification(Model):
    """One verification run of a repository's findings against a patched commit."""

    verification_id: UUID
    repository_ref_id: UUID
    verified_at: datetime
    verdicts: tuple[FindingVerdict, ...]
    work_item_ids: tuple[UUID, ...] = ()
    regression_ids: tuple[UUID, ...] = ()
    artifact: ArtifactRef


class VerificationFilter(Model):
    """A repository's verifications, optionally only those touching one work item's findings."""

    repository_id: UUID
    work_item_id: UUID | None = None


class VerificationItem(Model):
    """One finding to re-check: as it stands and every judgement on it."""

    finding: FindingView
    decisions: tuple[Decision, ...] = ()


class VerificationInput(SkillInput):
    """What the skill verifies: the work item (its fork, branch and report), its findings, the
    repository's baseline when the work item was opened, and earlier verifications."""

    work_item: WorkItem
    items: tuple[VerificationItem, ...]
    verifications: tuple[Verification, ...] = ()


class PropagationEvidence(Model):
    """One package of a fixed advisory, as the component's commit carries it."""

    ecosystem: Ecosystem
    name: str
    fixed: Version
    state: FixUptakeState
    checked: tuple[ConsumedVersion, ...] = ()

    @classmethod
    def of(cls, package: AffectedPackage, fixed: Version, uptake: FixUptake) -> Self:
        """Each version the commit carries judged by the advisory's own spans, not one bound:
        1.57.0 is past a first fix of 1.56.3 and still affected (fixed again in 1.57.1)."""
        checked = tuple(
            c.model_copy(update={"consumed": None if hit is None else not hit})
            for c in uptake.checked
            for hit in [package.affects(c.version)]
        )
        state = (
            uptake.state
            if not checked
            else FixUptakeState.CONSUMED
            if all(c.consumed for c in checked)
            else FixUptakeState.PENDING
        )
        return cls(
            ecosystem=package.ecosystem,
            name=package.name,
            fixed=fixed,
            state=state,
            checked=checked,
        )


class Propagation(Model):
    work_item_id: UUID
    component_id: UUID
    status: CrossRepoPropagation
    evidence: tuple[PropagationEvidence, ...] = ()


def propagated(evidence: Sequence[PropagationEvidence]) -> CrossRepoPropagation:
    """Pending while any package the commit carries is vulnerable, consumed once every one it
    carries is fixed; carrying none is module_absent, which a verifier judges (it may be vendored
    under another name)."""
    states = {e.state for e in evidence}
    if FixUptakeState.NOT_OBSERVED in states or not states:
        raise NotFoundError("the component's commit has no SBOM yet: record one first")
    if FixUptakeState.PENDING in states:
        return CrossRepoPropagation("pending")
    held = states - {FixUptakeState.MODULE_ABSENT}
    return CrossRepoPropagation("consumed" if held else "module_absent")


_VERDICT_RESOLUTION = {
    "resolved": "resolved",
    "new_approach": "resolved",
    "partially_resolved": "partially_resolved",
    "unresolved": "open",
    "regression": "regression_introduced",
    "risk_accepted": "risk_accepted",
}
FIXED_VERDICTS = frozenset({"resolved", "new_approach"})


def verdict_statement(
    verdict: VerificationVerdict, propagation: str | None = None
) -> tuple[Validity | None, DispositionResolution | None]:
    """What a verdict says (validity, resolution), never both: a false positive is a validity a
    person must countersign; a partial fix the product hasn't consumed is still in progress."""
    if verdict == "false_positive":
        return Validity.FALSE_POSITIVE, None
    if verdict == "partially_resolved" and propagation == "pending":
        return None, DispositionResolution("fix_in_progress")
    return None, DispositionResolution(_VERDICT_RESOLUTION[verdict])


_ATTRIBUTED = frozenset({"resolved", "partially_resolved", "new_approach", "regression"})
_NEEDS_RATIONALE = frozenset({"false_positive", "risk_accepted"})


def check_verification(doc: Any) -> list[str]:
    """The report's own consistency (verdict counts, coverage, attribution, the cross-repo rule);
    errors raise, warnings come back."""
    findings, regressions = doc.verified_findings, doc.regressions
    errors: list[str] = []
    warnings: list[str] = []
    ids = [f.original_id for f in findings]
    errors += [
        f"duplicate verified_findings original_id {i}" for i, n in Counter(ids).items() if n > 1
    ]
    repository = str(doc.metadata.repository).rstrip("/").lower()
    for i, f in enumerate(findings):
        at = f"verified_findings[{i}] ({f.original_id})"
        cross = f.cross_repo
        if cross is not None and cross.propagation == "pending" and f.verdict == "resolved":
            errors.append(
                f"{at}: 'resolved' while {cross.fix_repo} is not consumed (propagation pending); "
                "use partially_resolved"
            )
        if cross is not None and cross.fix_repo.rstrip("/").lower() == repository:
            errors.append(f"{at}: cross_repo.fix_repo is this repository; drop the block")
        commits = f.remediation_commits
        if commits and f.unattributed:
            errors.append(f"{at}: unattributed but remediation_commits is non-empty")
        if not commits and not f.unattributed and f.verdict in _ATTRIBUTED:
            errors.append(f"{at}: '{f.verdict}' needs remediation_commits or unattributed: true")
        if f.verdict in _NEEDS_RATIONALE and not f.disposition_rationale:
            errors.append(f"{at}: '{f.verdict}' needs disposition_rationale (who and why)")
        if f.verdict == "partially_resolved" and not f.residual_risk:
            errors.append(f"{at}: 'partially_resolved' needs residual_risk")
        if f.verdict == "new_approach" and not f.residual_risk:
            warnings.append(f"{at}: 'new_approach' should state its residual_risk")
        errors += [
            f"{at}: short_sha {c.short_sha} is not a prefix of {c.sha}"
            for c in commits
            if not c.sha.startswith(c.short_sha)
        ]
    summary = doc.summary
    if summary.total_findings != len(findings):
        errors.append(f"summary.total_findings {summary.total_findings} != {len(findings)}")
    said = Counter(f.verdict for f in findings)
    errors += [
        f"summary.by_verdict.{v} {getattr(summary.by_verdict, v)} != {said[v]}"
        for v in _VERDICTS
        if getattr(summary.by_verdict, v) != said[v]
    ]
    if summary.regressions != len(regressions):
        errors.append(f"summary.regressions {summary.regressions} != {len(regressions)}")
    previous: datetime | None = None
    for i, t in enumerate(doc.commit_timeline):
        if not t.full_sha.startswith(t.sha):
            errors.append(f"commit_timeline[{i}]: {t.sha} is not a prefix of {t.full_sha}")
        errors += [
            f"commit_timeline[{i}] names unknown finding {a}" for a in t.addresses if a not in ids
        ]
        when = datetime.fromisoformat(t.date)
        if previous is not None and when < previous:
            errors.append(f"commit_timeline[{i}] ({t.sha}) is out of chronological order")
        previous = when
    attributed = {c.sha for f in findings for c in f.remediation_commits}
    timeline = {t.full_sha for t in doc.commit_timeline}
    warnings += [
        f"remediation commit {s} is not in commit_timeline" for s in sorted(attributed - timeline)
    ]
    warnings += [
        f"commit_timeline {s} is in no finding's remediation_commits"
        for s in sorted(timeline - attributed)
    ]
    patched = doc.metadata.patched_commit[:7]
    warnings += [
        f"regression {r.id}: short sha is not the patched commit's ({patched})"
        for r in regressions
        if f"-{patched}-REG-" not in r.id
    ]
    if errors:
        raise ValidationError("verification report: " + "; ".join(errors))
    return warnings


_VERDICTS = (
    "resolved",
    "partially_resolved",
    "unresolved",
    "new_approach",
    "regression",
    "false_positive",
    "risk_accepted",
)


class ScanFact(Model):
    """A scanner's fact on one revision: a rule firing on a path."""

    rule: str | None = None
    path: str
    line: int | None = None


Selector = tuple[str | None, str | None]  # (rule, path); None matches any


def _matching(facts: Sequence[ScanFact], selectors: Collection[Selector]) -> list[ScanFact]:
    # Lines are not part of the match: a patch moves lines, so every fact would read as cleared.
    return [
        f
        for f in facts
        if any((r is None or f.rule == r) and (p is None or f.path == p) for r, p in selectors)
    ]


def _describe(facts: Sequence[ScanFact]) -> str:
    said = "; ".join(
        f"{f.rule or '?'} at {f.path}:{f.line}" if f.line else f"{f.rule or '?'} in {f.path}"
        for f in facts[:3]
    )
    return said + (f" (+{len(facts) - 3} more)" if len(facts) > 3 else "")


def scanner_differential(
    tool: str,
    selectors: Collection[Selector],
    base: Sequence[ScanFact] | None,
    patched: Sequence[ScanFact] | None,
    base_ref: str,
    base_scan: str,
) -> EvidenceItem:
    """The backing scanner on both revisions: proof only that the fact a finding rested on is
    gone (not that the fix is correct); nothing on the base revision is no differential at all."""
    # An unrestricted differential answers a question nobody asked: (None, None) selects nothing.
    selectors = sorted({s for s in selectors if s != (None, None)}, key=str)
    selector = ", ".join(r or f"any rule in {p}" for r, p in selectors)
    item = EvidenceItem(
        kind=PatchEvidenceKind.SCANNER_DIFFERENTIAL,
        outcome=f"{_NOT_ATTEMPTED}pending",
        tool=tool,
        command=f"{tool} on {base_ref} vs the patched revision, selector: {selector}",
    )
    if not selectors:
        return item.not_attempted(
            "no scanner fact backs these findings on the unpatched revision: not scanner-backed",
            "no backing fact on base",
        )
    if base is None or patched is None:
        which = "base" if base is None else "patched"
        return item.not_attempted(
            f"no {tool} scan of the {which} revision", f"{which} scan missing"
        )
    before, after = _matching(base, selectors), _matching(patched, selectors)
    if not before:
        return item.not_attempted(
            f"{selector} does not fire on the unpatched revision, so there is no differential to "
            "observe — the finding may not be scanner-backed, or the rule pack has moved since "
            "the audit",
            "no backing fact on base",
        )
    observed = f"on the patched revision it reports {len(after)} matching fact(s)" + (
        f": {_describe(after)}" if after else ""
    )
    return item.model_copy(
        update={
            "outcome": FAILS_TO_PROVE if after else PROVES,
            "base_observation": f"on the unpatched revision ({base_ref}) the backing scanner "
            f"reports {len(before)} matching fact(s): {_describe(before)} — from {base_scan}",
            "patched_observation": observed
            + (
                " — the patch has not cleared its own backing evidence"
                if after
                else " — the pattern that evidenced this finding is gone; this does not "
                "establish the fix is correct or minimal"
            ),
        }
    )


class SweepTier(StrEnum):
    CLAIMED = "T1"  # someone claims a fix: the latest word on a finding's resolution is a claim
    CRITICAL = "T2"  # the head moved and a critical finding is open
    HIGH = "T3"
    OTHER = "T4"


class SweepSkip(StrEnum):
    UNOBSERVED = "unobserved"  # no default-branch head observed yet
    ALREADY_VERIFIED = "already_verified"  # a verification of the current head exists
    NOTHING_OPEN = "nothing_open"  # nothing a verification report could cover
    HEAD_UNCHANGED = "head_unchanged"  # nothing landed since the findings were last judged


class SweepEntry(Model):
    """Whether a repository is worth re-verifying, and how urgently; the sweep routes only."""

    repository_id: UUID
    head_sha: str | None = None
    pinned_sha: str | None = None
    verified_at_head: bool = False
    open_findings: int = 0
    criticals: int = 0
    highs: int = 0
    claims: int = 0
    archived: bool | None = None
    tier: SweepTier | None = None
    skip: SweepSkip | None = None

    def classified(self) -> SweepEntry:
        return self.model_copy(update=dict(zip(("tier", "skip"), self._classify(), strict=True)))

    def _classify(self) -> tuple[SweepTier | None, SweepSkip | None]:
        if self.head_sha is None:
            return None, SweepSkip.UNOBSERVED
        if self.verified_at_head:
            return None, SweepSkip.ALREADY_VERIFIED
        if not self.open_findings and not self.claims:
            return None, SweepSkip.NOTHING_OPEN
        if self.claims:
            return SweepTier.CLAIMED, None
        if self.pinned_sha == self.head_sha:
            return None, SweepSkip.HEAD_UNCHANGED
        if self.criticals:
            return SweepTier.CRITICAL, None
        return (SweepTier.HIGH if self.highs else SweepTier.OTHER), None


class VerifySweep(Model):
    """Queued repositories by tier then criticals and highs, and every skipped one with why."""

    queued: tuple[SweepEntry, ...]
    skipped: tuple[SweepEntry, ...]

    @classmethod
    def of(cls, entries: Iterable[SweepEntry]) -> VerifySweep:
        done = [e.classified() for e in entries]
        tiers = list(SweepTier)
        return cls(
            queued=tuple(
                sorted(
                    (e for e in done if e.tier),
                    key=lambda e: (tiers.index(e.tier), -e.criticals, -e.highs),  # type: ignore[arg-type]
                )
            ),
            skipped=tuple(e for e in done if e.skip),
        )


_FIRST_LINE = re.compile(r"\d+")


def regression_candidates(doc: Any, repository_id: UUID) -> list[FindingCandidate]:
    """The new vulnerabilities a verification found, for intake as findings of its own."""
    return [
        FindingCandidate(
            label=Label(r.id),
            repository_id=repository_id,
            title=r.title,
            description=r.description,
            cwes=tuple(CweId(c) for c in r.cwes),
            locations=tuple(
                CodeSpan(
                    path=RepoPath(loc.path),
                    line=int(m.group()) if (m := _FIRST_LINE.search(loc.lines or "")) else None,
                )
                for loc in r.locations
            ),
            reported_severity=ScannerSeverity(r.severity),
            origin=FindingOrigin("verify-remediation"),
        )
        for r in doc.regressions
    ]
