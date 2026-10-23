from __future__ import annotations

import importlib.metadata
import re
from collections.abc import Sequence
from datetime import UTC, date, datetime, time
from typing import Any, Protocol

from traust_core.v1.models.artifacts import TriageArtifact
from traust_core.v1.models.common import Provenance
from traust_core.v1.models.findings import FindingView, Location
from traust_core.v1.models.insight import ViewFilter, ViewModel, ViewName
from traust_core.v1.models.operations import RunOrder
from traust_core.v1.rendering import Report, Section, Table, inline
from traust_core.v1.services.artifact_publishing import ArtifactPublisher, PublishResult
from traust_core.v1.services.operations import OpsService


class View(Protocol):
    name: ViewName

    def build(self, filter: ViewFilter) -> ViewModel: ...


class InsightService:
    def __init__(
        self, views: Sequence[View], publisher: ArtifactPublisher, ops: OpsService
    ) -> None:
        self._views = {v.name: v for v in views}
        self._publisher = publisher
        self._ops = ops

    def build(self, view: ViewName, filter: ViewFilter) -> ViewModel:
        raise NotImplementedError("stub: replaces each dashboard builder's main()")

    def publish(self, view: ViewName, filter: ViewFilter, provenance: Provenance) -> PublishResult:
        raise NotImplementedError("stub: replaces dashboards' md/html/json writes")

    def refresh(self, views: Sequence[ViewName] | None) -> list[RunOrder]:
        raise NotImplementedError("stub: replaces cli/refresh_dashboards.py")


# Registered views (internal); each replaces the dashboard named in its stub.
class _StubView:
    name: ViewName
    replaces = ""

    def build(self, filter: ViewFilter) -> ViewModel:
        raise NotImplementedError(f"stub: replaces {self.replaces}")


class FindingsRollupView(_StubView):
    name, replaces = ViewName.FINDINGS_ROLLUP, "insecure-patterns, rbac-tenancy-rollup, team report"


class FindingsTrendView(_StubView):
    name, replaces = ViewName.FINDINGS_TREND, "findings-trends"


class CoverageView(_StubView):
    name, replaces = ViewName.COVERAGE, "census"


class LocView(_StubView):
    name, replaces = ViewName.LOC, "loc-dashboard"


class AttackCoverageView(_StubView):
    name, replaces = ViewName.ATTACK_COVERAGE, "attack-coverage"


class ThreatRegisterView(_StubView):
    name, replaces = ViewName.THREAT_REGISTER, "threat-register"


class ExposureView(_StubView):
    name, replaces = ViewName.EXPOSURE, "refresh-dashboards/build_dependency_exposure"


class ValidationFuzzView(_StubView):
    name, replaces = ViewName.VALIDATION_FUZZ, "validation-fuzz-dashboard"


class PqcView(_StubView):
    name, replaces = ViewName.PQC, "pqc dashboard, product reports, vendor/xcrypto trackers"


class ComplianceDashboardView(_StubView):
    name, replaces = ViewName.COMPLIANCE, "compliance/dashboard.py"


class ProgramView(_StubView):
    name, replaces = ViewName.PROGRAM, "traust-metrics, financial-tracking"


class ExecutiveSummaryView(_StubView):
    name, replaces = ViewName.EXECUTIVE_SUMMARY, "executive-summary-findings"


class ReviewCardView(_StubView):
    name, replaces = ViewName.REVIEW_CARD, "countersign render_*_card"


class TriageView:
    """A triage document as a report: act on these, hardening, undetermined, dropped."""

    name = ViewName.TRIAGE
    _SEVERITY = ("critical", "high", "medium", "low", "informational")

    def build(self, filter: ViewFilter) -> ViewModel:
        raise NotImplementedError("stub: a triage view over stored triage artifacts")

    def report(self, doc: TriageArtifact) -> Report:
        findings = doc.findings
        by = {
            v: [f for f in findings if f.verdict == v]
            for v in ("true_positive", "hardening", "undetermined", "false_positive", "duplicate")
        }
        sections = [
            self._summary(doc),
            Section(heading="Act on these", body=self._confirmed(by["true_positive"])),
            Section(
                heading="Hardening backlog",
                body="Real gaps confirmed by verification, with no concrete exploit path "
                "(exclusion "
                "rule 13: defense in depth, benchmark and best-practice deviations). Track them as "
                "engineering hygiene, not vulnerabilities. These are NOT false positives."
                + ("" if by["hardening"] else "\n\n_None._"),
                table=self._table(
                    ("id", "title", "location", "owner", "why hardening"),
                    [
                        (
                            f.id,
                            f.title,
                            _where(f),
                            f.owner_hint or "-",
                            _first_sentence(f.rationale),
                        )
                        for f in sorted(by["hardening"], key=lambda f: -(f.confidence or 0))
                    ],
                ),
            ),
        ]
        if by["undetermined"]:
            sections.append(
                Section(
                    heading="Undetermined",
                    body="Nothing was proven or refuted: cited material was missing or "
                    "unreadable, or "
                    "verification couldn't decide. A person must review these; they are not false "
                    "positives.",
                    table=self._table(
                        ("id", "title", "location", "why undetermined"),
                        [
                            (
                                f.id,
                                f.title,
                                _where(f),
                                _first_sentence(f.rationale or ", ".join(f.refute_reasons)),
                            )
                            for f in by["undetermined"]
                        ],
                    ),
                )
            )
        dropped = [
            (
                f.id,
                f.title,
                _where(f),
                (", ".join(f.refute_reasons) or "refuted")
                + (f" (rule {f.exclusion_rule})" if f.exclusion_rule is not None else ""),
            )
            for f in by["false_positive"]
        ] + [(f.id, f.title, _where(f), f"duplicate of {f.duplicate_of}") for f in by["duplicate"]]
        sections.append(
            Section(
                heading="Dropped",
                body="" if dropped else "_None._",
                table=self._table(("id", "title", "location", "why dropped"), dropped),
            )
        )
        when = datetime.combine(date.fromisoformat(str(doc.triage_completed)), time(), UTC)
        return Report(title="Triage Report", generated_at=when, sections=tuple(sections))

    def _summary(self, doc: TriageArtifact) -> Section:
        s, ctx = doc.summary, doc.triage_context
        by_severity = s.by_severity
        severities = " / ".join(
            f"{getattr(by_severity, k)} {k}"
            for k in self._SEVERITY
            if getattr(by_severity, k, None) is not None
        )
        counts = (
            f"{s.input_count} in: {s.true_positives} confirmed ({severities}), "
            f"{s.hardening} hardening, {s.undetermined} undetermined, {s.duplicates} duplicates, "
            f"{s.false_positives} false positives"
        )
        context = (
            f"Context: {inline(ctx.mode)}; environment = {inline(ctx.environment)}; "
            f"{inline(ctx.votes_per_finding)}-vote verification; "
            f"harness {inline(ctx.harness_version)}; "
            f"completed {inline(doc.triage_completed)}"
        )
        return Section(heading="Summary", body=f"{counts}\n\n{context}")

    def _confirmed(self, findings: Sequence[Any]) -> str:
        if not findings:
            return "_No confirmed findings._"
        rank = {s: i for i, s in enumerate(self._SEVERITY)}
        entries = []
        for f in sorted(
            findings, key=lambda f: (rank.get(str(f.severity).lower(), 9), -(f.confidence or 0))
        ):
            meta = f"{_where(f)} | {inline(f.category or '-')}"
            if f.claimed_severity:
                meta += f" | claimed {inline(f.claimed_severity)}"
                if f.severity_alignment is not None:
                    meta += f" (alignment {inline(f.severity_alignment)})"
            if f.confidence is not None:
                meta += f" | confidence {f.confidence}/10"
            lines = [
                f"### [{inline(str(f.severity or '?').upper())}] "
                f"{inline(f.title)} ({inline(f.id)})",
                meta,
            ]
            fields = (
                ("Source finding", f.orig_id),
                ("Owner", f.owner_hint),
                (
                    "Verdict",
                    f"{inline(f.verify_verdict or 'confirmed')}, votes {_votes(f.vote_breakdown)}",
                ),
                ("Preconditions", "; ".join(map(inline, f.preconditions))),
                ("Threat-model match", f.threat_match),
                ("Why", f.rationale),
                ("Reachability evidence", ", ".join(map(inline, f.first_links))),
            )
            lines += [f"**{label}:** {inline(value)}" for label, value in fields if value]
            if f.verify_verdict == "needs_manual_test":
                lines.append("> Recommend a person build a PoC; static reasoning hit its limit.")
            entries.append("\n".join(lines))
        return "\n\n".join(entries)

    @staticmethod
    def _table(columns: tuple[str, ...], rows: Sequence[tuple[Any, ...]]) -> Table | None:
        return (
            Table(columns=columns, rows=tuple(tuple(map(str, r)) for r in rows)) if rows else None
        )


def _where(f: Any) -> str:
    """`file:line`; backticks stripped so a hostile path can't close the code span."""
    path = inline(f.file or "-").replace("`", "")
    return f"`{path}:{f.line}`" if f.line is not None else f"`{path}`"


def _votes(v: Any) -> str:
    if v is None:
        return "-"
    return f"{v.true_positive}T/{v.hardening}H/{v.false_positive}F/{v.cannot_verify}C"


def _first_sentence(text: str | None, limit: int = 220) -> str:
    text = inline(text)
    for stop in (". ", "; "):
        if 0 < (i := text.find(stop)) < limit:
            return text[: i + 1]
    return text[:limit] + ("…" if len(text) > limit else "")


class SarifExport:
    """Findings as SARIF 2.1.0 for code scanning: a one-way projection, never a store. False
    positives and accepted risks arrive as suppressions, resolved findings as `absent`."""

    name = ViewName.SARIF

    def document(self, views: Sequence[FindingView], repository_url: str) -> dict[str, Any]:
        categories = list(dict.fromkeys(_category(v) for v in views))
        version = _version()
        driver = {
            "name": "traust",
            "version": version,
            "semanticVersion": version,
            "rules": [
                {
                    "id": c,
                    "name": c.replace("-", " ").title().replace(" ", ""),
                    "shortDescription": {"text": f"Finding category: {c}"},
                    "properties": {"tags": ["security", c]},
                }
                for c in categories
            ],
        }
        run = {
            "tool": {"driver": driver},
            "columnKind": "utf16CodeUnits",
            "results": [_sarif_result(v, categories.index(_category(v))) for v in views],
            "properties": {
                "traust/repository": repository_url,
                "traust/authoritative_source": "traust-core decisions; this file is a projection",
            },
            "versionControlProvenance": [{"repositoryUri": repository_url}],
        }
        return {"$schema": SARIF_SCHEMA, "version": "2.1.0", "runs": [run]}


SARIF_SCHEMA = "https://json.schemastore.org/sarif-2.1.0.json"
# severity -> (SARIF level, GitHub security-severity)
_SARIF_LEVEL = {
    "critical": ("error", "9.5"),
    "high": ("error", "8.0"),
    "medium": ("warning", "5.0"),
    "low": ("note", "2.0"),
    "informational": ("note", "0.5"),
}
# Not files: a package, an image config or layer, named rather than located.
_PSEUDO_PATH = re.compile(r"^(pkg:|oci-config:|layer:|sha256:)")


def _version() -> str:
    try:
        return importlib.metadata.version("traust-core")
    except importlib.metadata.PackageNotFoundError:
        return "0.0.0"


def _category(view: FindingView) -> str:
    return view.label("category") or "uncategorized"


def _sarif_location(loc: Location) -> dict[str, Any]:
    if _PSEUDO_PATH.match(loc.path):
        return {"logicalLocations": [{"fullyQualifiedName": loc.path}]}
    physical: dict[str, Any] = {"artifactLocation": {"uri": loc.path}}
    if loc.line_start is not None:
        physical["region"] = {"startLine": loc.line_start}
        if loc.line_end is not None and loc.line_end != loc.line_start:
            physical["region"]["endLine"] = loc.line_end
    return {"physicalLocation": physical}


def _sarif_result(view: FindingView, rule_index: int) -> dict[str, Any]:
    severity = str(view.effective_severity)
    level, security_severity = _SARIF_LEVEL.get(severity, ("note", "0.5"))
    disposition = view.disposition
    properties: dict[str, Any] = {
        "security-severity": security_severity,
        "traust/severity": severity,
        "traust/validity": (disposition.validity if disposition else None) or "not_verified",
    }
    if view.cwes:
        properties["tags"] = ["security", *view.cwes]
    if view.occurrence is not None and view.occurrence.cvss_vector:
        properties["traust/cvss"] = {
            "vector": view.occurrence.cvss_vector,
            "score": str(view.occurrence.cvss_score),
        }
    if disposition is not None:
        properties["traust/disposition"] = disposition.model_dump(mode="json")
    result: dict[str, Any] = {
        "ruleId": _category(view),
        "ruleIndex": rule_index,
        "level": level,
        "message": {"text": view.finding.title},
        "locations": [_sarif_location(loc) for loc in view.locations],
        "partialFingerprints": {
            "traustFindingId/v1": str(view.finding.id),
            "traustFingerprint/v1": view.finding.fingerprint,
        },
        "properties": properties,
    }
    suppressions = [
        {"kind": "external", "status": "accepted", "justification": f"traust disposition: {why}"}
        for said, why in (
            (disposition and disposition.validity == "false_positive", "validity=false_positive"),
            (disposition and disposition.resolution == "risk_accepted", "resolution=risk_accepted"),
        )
        if said
    ]
    if suppressions:
        result["suppressions"] = suppressions
    if disposition is not None and disposition.resolution == "resolved":
        result["baselineState"] = "absent"
    return result


class OscalExport(_StubView):
    name, replaces = ViewName.OSCAL, "run_compliance_check.export_oscal"
