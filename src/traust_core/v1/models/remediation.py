from __future__ import annotations

import json
from collections.abc import Iterable
from datetime import datetime
from typing import Self
from uuid import UUID

import pydantic

from traust_core.v1.errors import ConflictError
from traust_core.v1.models.base import Dto, Model
from traust_core.v1.models.common import ArtifactRef
from traust_core.v1.models.findings import Decision, FindingView, SkillInput
from traust_core.v1.models.inventory import OrgName
from traust_core.v1.models.values import HttpsRepoUrl
from traust_core.v1.models.vocabulary import (
    CrossRepoPropagation,
    DispositionResolution,
    FixStrategy,
    FleetFixMatcherKind,
    ForkHost,
    ForkVisibility,
    PatchEvidenceKind,
    RemediationStatus,
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


class PropagationEvidence(Model): ...


class WorkItemFilter(Model):
    """A repository's work items, optionally only those at one status."""

    repository_id: UUID
    status: RemediationStatus | None = None


class VerificationFilter(Model): ...


class VerificationInput(SkillInput): ...


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
# What each status says about the findings' resolution; None = no answer yet.
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
    "merged": "resolved",
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


class Verification(Model):
    work_item_id: UUID
    repository_ref_id: UUID
    verdict: VerificationVerdict
    regression_ids: tuple[UUID, ...] = ()
    artifact: ArtifactRef


class Propagation(Model):
    work_item_id: UUID
    component_id: UUID
    status: CrossRepoPropagation
    evidence: tuple[PropagationEvidence, ...] = ()
