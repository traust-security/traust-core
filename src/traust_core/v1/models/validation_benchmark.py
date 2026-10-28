from __future__ import annotations

from datetime import datetime
from enum import StrEnum

from pydantic import Field

from traust_core.v1.errors import ValidationError
from traust_core.v1.models.base import Dto, Model

# The validation lanes measured the way the recall benchmark measures the auditor: vulnerable
# fixtures they must confirm, safe twins they must refute with sound evidence, and severity
# against the planted CVSS. Run on release cuts that touch these paths, and monthly for drift.
# Prefixes are relative to the mono checkout root.
TRIGGER_PATHS = (
    "traust/harnessing/5-validate/validate-findings/",
    "traust/harnessing/5-validate/validate-core-ocp/",
    "traust/harnessing/5-validate/validate-browser-finding/",
    "traust/harnessing/5-validate/validate-operator-live/",
    "traust/src/traust/cli/emit_validation_ledger_events.py",
    "traust/src/traust/cli/attest_target.py",
    "traust/src/traust/cli/build_cumulative.py",
)


class BenchmarkVariant(StrEnum):
    VULN = "vuln"
    SAFE = "safe"

    @property
    def metric(self) -> str:
        return "confirm_recall" if self is BenchmarkVariant.VULN else "refute_precision"


class BenchmarkClaim(Dto):
    title: str
    severity: str
    cvss: float
    cvss_vector: str
    cwes: tuple[str, ...] = ()
    category: str


class BenchmarkFixture(Dto):
    id: str
    claim: BenchmarkClaim
    probe_class: str
    controls_hint: str
    vuln_manifest: str
    safe_manifest: str | None = None
    expected: dict[BenchmarkVariant, str] = Field(default_factory=dict)


class BenchmarkFloors(Dto):
    confirm_recall: float
    refute_precision: float
    severity_within: float

    def floor(self, variant: BenchmarkVariant) -> float:
        return self.confirm_recall if variant is BenchmarkVariant.VULN else self.refute_precision


class ValidationBenchmark(Dto):
    """The benchmark's `expected.json`: fixture pairs, their claims and the floors."""

    namespace: str
    fixtures: tuple[BenchmarkFixture, ...] = ()
    floors: BenchmarkFloors | None = None

    def required_floors(self) -> BenchmarkFloors:
        if self.floors is None:
            raise ValidationError("the benchmark's expected.json names no floors to score against")
        return self.floors


class ClaimLocation(Model):
    path: str


class WorklistClaim(Model):
    """A planned claim for the lanes to validate; its validity stays unanswered until they do."""

    id: str
    title: str
    severity: str
    cvss_score: float
    cvss_vector: str
    cwes: tuple[str, ...]
    category: str
    description: str
    locations: tuple[ClaimLocation, ...]


class WorklistMetadata(Model):
    benchmark: bool = True
    namespace: str
    generated_at: datetime


class BenchmarkWorklist(Model):
    """`benchmark-findings.json`: the claims /validate-findings runs against the fixtures."""

    metadata: WorklistMetadata
    findings: tuple[WorklistClaim, ...] = ()

    @classmethod
    def of(cls, bench: ValidationBenchmark, generated_at: datetime) -> BenchmarkWorklist:
        return cls(
            metadata=WorklistMetadata(namespace=bench.namespace, generated_at=generated_at),
            findings=tuple(
                WorklistClaim(
                    id=fx.id,
                    title=fx.claim.title,
                    severity=fx.claim.severity,
                    cvss_score=fx.claim.cvss,
                    cvss_vector=fx.claim.cvss_vector,
                    cwes=fx.claim.cwes,
                    category=fx.claim.category,
                    description=(
                        f"Validation benchmark fixture {fx.id} (probe class {fx.probe_class}). "
                        f"Hints: {fx.controls_hint}"
                    ),
                    locations=(ClaimLocation(path=f"benchmark/fixtures/{fx.vuln_manifest}"),),
                )
                for fx in bench.fixtures
            ),
        )


class SeverityValidation(Dto):
    demonstrated_score_estimate: float | None = None


class ValidatedFinding(Dto):
    source_id: str | None = None
    verdict: str | None = None
    soundness_flag: str | None = None
    severity_validation: SeverityValidation | None = None


class ValidationRun(Dto):
    """The parts of a lane's validation report the benchmark scores."""

    validated_findings: tuple[ValidatedFinding, ...] = ()


class ScoreRow(Model):
    fixture: str
    expected: str
    got: str
    soundness_flag: str | None = None
    ok: bool
    severity_within_floor: bool | None = None


class BenchmarkScore(Model):
    """One lane run scored: a flagged verdict counts as a miss."""

    variant: BenchmarkVariant
    confirm_recall: float | None = None
    refute_precision: float | None = None
    severity_accuracy: float | None = None
    rows: tuple[ScoreRow, ...] = ()
    n: int
    scored_at: datetime | None = None
    report: str | None = None

    @property
    def value(self) -> float | None:
        return (
            self.confirm_recall if self.variant is BenchmarkVariant.VULN else self.refute_precision
        )

    @classmethod
    def of(
        cls, bench: ValidationBenchmark, run: ValidationRun, variant: BenchmarkVariant
    ) -> BenchmarkScore:
        floors = bench.required_floors()
        by_id = {str(vf.source_id or "").rsplit("/", 1)[-1]: vf for vf in run.validated_findings}
        rows: list[ScoreRow] = []
        hits = sev_ok = sev_n = 0
        for fx in bench.fixtures:
            if variant not in fx.expected:
                raise ValidationError(f"benchmark fixture {fx.id} expects no {variant} verdict")
            want = fx.expected[variant]
            vf = by_id.get(fx.id)
            got = (vf.verdict if vf else None) or "missing"
            flag = vf.soundness_flag if vf else None
            ok = got == want and not flag
            hits += ok
            within = None
            severity = vf.severity_validation if vf else None
            est = severity.demonstrated_score_estimate if severity else None
            if variant is BenchmarkVariant.VULN and got == "confirmed" and est is not None:
                sev_n += 1
                within = abs(est - fx.claim.cvss) <= floors.severity_within
                sev_ok += within
            rows.append(
                ScoreRow(
                    fixture=fx.id,
                    expected=want,
                    got=got,
                    soundness_flag=flag,
                    ok=ok,
                    severity_within_floor=within,
                )
            )
        n = len(bench.fixtures)
        return cls(
            variant=variant,
            **{variant.metric: round(hits / n, 3) if n else None},
            severity_accuracy=round(sev_ok / sev_n, 3) if sev_n else None,
            rows=tuple(rows),
            n=n,
        )


class BenchmarkScorecard(Model):
    runs: tuple[BenchmarkScore, ...] = ()


class BenchmarkTrigger(Model):
    """The validation-lane paths changed since a release: any means the benchmark must run."""

    since: str
    paths: tuple[str, ...] = ()

    @classmethod
    def of(cls, since: str, changed: list[str]) -> BenchmarkTrigger:
        return cls(
            since=since,
            paths=tuple(sorted({p for p in changed if p.startswith(TRIGGER_PATHS)})),
        )
