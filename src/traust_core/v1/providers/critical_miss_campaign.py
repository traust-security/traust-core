from __future__ import annotations

import re
from pathlib import Path
from typing import TypeVar

from pydantic import AliasChoices, Field, StrictBool, TypeAdapter
from pydantic import ValidationError as ModelValidationError

from traust_core.v1.errors import DocumentError, Issue, NotFoundError, ServiceError
from traust_core.v1.models.artifacts import (
    FindingsCurrentArtifact,
    ReportArtifact,
    SecurityAuditArtifact,
)
from traust_core.v1.models.base import Dto
from traust_core.v1.models.critical_misses import (
    CampaignFinding,
    CampaignRepositoryReports,
    CampaignTriage,
    CriticalCandidate,
    CriticalInstrument,
    CriticalMissCampaign,
)

_CWE = re.compile(r"CWE-\d{1,5}\b")
_ADVISORY = re.compile(r"\b(?:CVE-\d{4}-\d{4,}|GHSA-[A-Za-z0-9-]+)\b", re.IGNORECASE)
_D = TypeVar("_D", bound=Dto)


class _Delta(Dto):
    title: str = "(untitled)"
    severity: str | None = None
    cwe: str | None = None
    file: str | None = None
    rationale: str | None = None


class _Deltas(Dto):
    slug: str | None = None
    deltas: tuple[_Delta, ...]


class _Votes(Dto):
    true_positive: int | None = Field(default=None, ge=0)
    false_positive: int | None = Field(default=None, ge=0)


class _TriageFinding(Dto):
    source: str | None = None
    verdict: str | None = None
    orig_id: str | None = None
    confidence: float | None = Field(default=None, allow_inf_nan=False)
    vote_breakdown: _Votes | None = None


class _Triage(Dto):
    findings: tuple[_TriageFinding, ...]


class _ReplayCandidate(Dto):
    slug: str = Field(default="?", validation_alias=AliasChoices("slug", "repository"))
    cve: str | None = None
    ghsa: str | None = None
    advisory_id: str | None = None
    severity: str | None = None
    summary: str = ""
    present_at_audit: StrictBool | None = None
    audit_verdict: str | None = None


class _Replay(Dto):
    rows: tuple[_ReplayCandidate, ...] = Field(validation_alias=AliasChoices("rows", "candidates"))


class _Sample(Dto):
    slug: str
    report: str
    audit: str | None = None


class CriticalMissCampaignReader:
    def __init__(self, campaign: Path) -> None:
        self._campaign = campaign

    def read(self) -> CriticalMissCampaign:
        root = self._campaign
        try:
            if not root.is_dir():
                raise NotFoundError(f"critical-miss campaign directory not found: {root}")
            return self._read(root)
        except OSError as e:
            raise ServiceError(f"reading critical-miss campaign {root}: {e}") from e

    def _read(self, root: Path) -> CriticalMissCampaign:
        candidates: list[CriticalCandidate] = []
        triage: dict[str, CampaignTriage] = {}
        repositories: dict[str, CampaignRepositoryReports] = {}
        sources: list[str] = []
        for instrument, pattern in (
            (CriticalInstrument.B_LITE, "b-lite/*-delta.json"),
            (CriticalInstrument.MATRIX, "matrix/*-delta*.json"),
        ):
            for path in sorted(root.glob(pattern)):
                doc = _document(path, _Deltas)
                rel = path.relative_to(root).as_posix()
                sources.append(str(path))
                for index, delta in enumerate(doc.deltas):
                    cwe = _CWE.search(delta.cwe or f"{delta.title} {delta.rationale or ''}")
                    candidates.append(
                        CriticalCandidate(
                            instrument=instrument,
                            slug=doc.slug or path.stem.split("-delta", 1)[0],
                            title=delta.title,
                            severity=delta.severity,
                            cwe=cwe.group() if cwe else None,
                            file=delta.file,
                            source_key=f"{rel}#{index}",
                            evidence_path=f"{rel}#{index}",
                        )
                    )
        for path in sorted(root.rglob("*-triage.json")):
            doc = _document(path, _Triage)
            sources.append(str(path))
            for finding in doc.findings:
                if not finding.source or "#" not in finding.source:
                    continue
                votes = finding.vote_breakdown
                entry = CampaignTriage(
                    source_key=finding.source,
                    verdict=finding.verdict,
                    true_positive_votes=votes.true_positive if votes else None,
                    false_positive_votes=votes.false_positive if votes else None,
                    confidence=finding.confidence,
                    original_id=finding.orig_id,
                    evidence_path=path.relative_to(root).as_posix(),
                )
                triage[entry.source_key] = entry
        replay = root / "cve-replay" / "candidates.json"
        if replay.is_file():
            sources.append(str(replay))
            for index, row in enumerate(_document(replay, _Replay).rows):
                advisory = row.advisory_id or row.cve or row.ghsa
                cwe = _CWE.search(row.summary)
                candidates.append(
                    CriticalCandidate(
                        instrument=CriticalInstrument.CVE_REPLAY,
                        slug=row.slug,
                        title=f"{advisory or '(unidentified advisory)'}: {row.summary.strip()}",
                        severity=row.severity,
                        cwe=cwe.group() if cwe else None,
                        advisory_id=advisory,
                        source_key=f"cve-replay/candidates.json#{index}",
                        evidence_path=f"cve-replay/candidates.json#{index}",
                        present_at_audit=row.present_at_audit,
                        audit_verdict=row.audit_verdict,
                    )
                )
        for path in sorted(root.glob("*sample*.json")):
            sources.append(str(path))
            try:
                entries = TypeAdapter(tuple[_Sample, ...]).validate_json(_bytes(path))
            except ModelValidationError as e:
                raise _invalid(path, e) from e
            for entry in entries:
                current = _resolve(root, entry.report)
                if entry.audit:
                    baseline = _resolve(root, entry.audit)
                elif current.name.endswith("-findings-current.json"):
                    baseline = current.with_name(
                        current.name.removesuffix("-findings-current.json") + "-security-audit.json"
                    )
                else:
                    raise DocumentError(
                        str(path),
                        [Issue(entry.slug, "report needs a findings-current name or audit")],
                    )
                reports = CampaignRepositoryReports(
                    slug=entry.slug,
                    baseline_source=str(baseline) if baseline.is_file() else None,
                    current_source=str(current) if current.is_file() else None,
                    baseline=_report(baseline, SecurityAuditArtifact),
                    current=_report(current, FindingsCurrentArtifact),
                )
                previous = repositories.get(entry.slug)
                if previous is not None and previous != reports:
                    raise DocumentError(
                        str(path), [Issue(entry.slug, "conflicting sample reports")]
                    )
                repositories[entry.slug] = reports
                sources.extend(s for s in (reports.baseline_source, reports.current_source) if s)
        return CriticalMissCampaign(
            source=str(root),
            candidates=tuple(candidates),
            triage=tuple(triage.values()),
            repositories=tuple(repositories.values()),
            sources=tuple(dict.fromkeys(sources)),
        )


def _resolve(root: Path, value: str) -> Path:
    path = Path(value)
    return path if path.is_absolute() else root / path


def _bytes(path: Path) -> bytes:
    try:
        return path.read_bytes()
    except OSError as e:
        raise ServiceError(f"reading critical-miss campaign source {path}: {e}") from e


def _document(path: Path, kind: type[_D]) -> _D:
    try:
        return kind.model_validate_json(_bytes(path))
    except ModelValidationError as e:
        raise _invalid(path, e) from e


def _invalid(path: Path, error: ModelValidationError) -> DocumentError:
    return DocumentError(
        str(path),
        [Issue(".".join(map(str, issue["loc"])), issue["msg"]) for issue in error.errors()],
    )


def _report(path: Path, kind: type[ReportArtifact]) -> tuple[CampaignFinding, ...]:
    if not path.is_file():
        return ()
    try:
        doc = kind.parse(_bytes(path))
    except DocumentError as e:
        raise DocumentError(str(path), e.issues) from e
    return tuple(
        CampaignFinding(
            original_id=finding.id,
            paths=tuple(location.path for location in finding.locations),
            cwes=tuple(finding.cwes),
            advisory_ids=tuple(
                dict.fromkeys(
                    value.upper()
                    for value in (
                        ((finding.dependency.advisory,) if finding.dependency else ())
                        + tuple(
                            _ADVISORY.findall(f"{finding.title or ''} {finding.description or ''}")
                        )
                    )
                )
            ),
            validity=(finding.disposition.validity if finding.disposition else None)
            or finding.validation_status,
            refuted_awaiting_signoff=bool(
                getattr(finding.disposition, "refuted_awaiting_signoff", False)
            ),
        )
        for finding in doc.findings
    )
