"""A dependency finding's identity: the exposure key (repository, advisory, package) that an
impact analysis and a report both mint, so one advisory reaching one package in one
repository is one finding, whichever records first."""

from __future__ import annotations

from collections.abc import Sequence
from typing import TYPE_CHECKING

from traust_core.v1.models.artifacts import AssessmentArtifact, ReportArtifact, VulnFindingsArtifact
from traust_core.v1.models.dependencies import Advisory, Ecosystem, package_name
from traust_core.v1.models.findings import ExposureKey, FindingCandidate

if TYPE_CHECKING:
    from traust_core.v1.services.exposure import StoredAdvisories


def stored_name(ecosystem: str, module: str) -> str:
    """The package name as core stores it for its ecosystem (`package_name`): PyPI names
    compare normalised, npm names lower-case; other ecosystems keep their spelling."""
    try:
        return package_name(Ecosystem(ecosystem), module)
    except ValueError:
        return module


def exposure_key(advisory: Advisory, ecosystem: str, module: str) -> ExposureKey:
    """The key both an impact analysis and a report use, the package spelled as core stores it."""
    assert advisory.id is not None
    return ExposureKey(
        advisory_id=advisory.id,
        advisory=advisory.identifier,
        ecosystem=ecosystem,
        package=stored_name(ecosystem, module),
    )


def with_exposures(
    doc: AssessmentArtifact,
    candidates: Sequence[FindingCandidate],
    advisories: StoredAdvisories | None,
) -> list[FindingCandidate]:
    """A report or vuln-scan finding whose `dependency` names a stored advisory and its module
    is identified as the dependency finding an impact analysis files for it. An omitted
    ecosystem is taken from the stored advisory only when it names the module in exactly one;
    a dependency naming an advisory core doesn't keep stays fingerprinted as reported.
    Recording and the settling of held moves both call this, so a candidate has one identity
    in either."""
    if advisories is None or not isinstance(doc, ReportArtifact | VulnFindingsArtifact):
        # a report's and a vuln-scan's findings state `dependency` (traust-contracts#190)
        return list(candidates)
    stated = {str(e.id): e.dependency for e in doc.findings if e.dependency is not None}
    if not stated:
        return list(candidates)
    out = []
    for candidate in candidates:
        dependency = stated.get(str(candidate.label))
        if dependency is None or candidate.exposure is not None or not dependency.module:
            out.append(candidate)
            continue
        canonical = advisories.canonical(dependency.advisory)
        ecosystem = (
            str(dependency.ecosystem)
            if dependency.ecosystem
            else advisories.ecosystem_of(canonical.id, dependency.module)
            if canonical is not None and canonical.id is not None
            else None
        )
        if canonical is None or ecosystem is None:
            out.append(candidate)
            continue
        key = exposure_key(canonical, ecosystem, dependency.module)
        out.append(candidate.model_copy(update={"exposure": key}))
    return out
