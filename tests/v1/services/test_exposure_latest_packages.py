from __future__ import annotations

import json
from copy import deepcopy
from datetime import timedelta

import pytest
from sqlalchemy.engine import Engine

from tests.v1.services.test_exposure_impact import AT, GHSA, GRPC, engine, provenance, refs
from tests.v1.services.test_exposure_reads import reads
from traust_core.v1.errors import ValidationError
from traust_core.v1.models.artifacts import ImpactAnalysisArtifact
from traust_core.v1.models.common import PageRequest, TimeBucket
from traust_core.v1.models.dependencies import (
    AffectedPackage,
    AffectedSpan,
    ExposureDimension,
    ExposureFilter,
    ImpactFilter,
    ImpactInput,
    Version,
)
from traust_core.v1.models.vocabulary import (
    Ecosystem,
    ImpactGovulncheck,
    ImpactManifestScan,
)
from traust_core.v1.services.exposure import ExposureService

__all__ = ["engine"]

GO, NPM = Ecosystem.GO, Ecosystem.NPM


def inventory(*purls: str) -> bytes:
    return json.dumps(
        {
            "bomFormat": "CycloneDX",
            "components": [{"purl": purl} for purl in purls],
        }
    ).encode()


@pytest.fixture
def mixed(engine: Engine) -> ExposureService:
    advisory = GRPC.model_copy(
        update={
            "affected": (
                AffectedPackage(
                    ecosystem=GO,
                    name="lib",
                    spans=(AffectedSpan(introduced=Version("0"), fixed=Version("3.0.0")),),
                ),
                AffectedPackage(
                    ecosystem=GO,
                    name="other",
                    spans=(AffectedSpan(introduced=Version("0"), fixed=Version("1.0.0")),),
                ),
                AffectedPackage(
                    ecosystem=NPM,
                    name="lib",
                    spans=(AffectedSpan(introduced=Version("0"), fixed=Version("2.0.0")),),
                ),
            ),
        }
    )
    exposure = reads(engine, advisory=advisory)
    [ref] = refs(engine, 1)
    assert ref.id is not None
    exposure.ingest_sbom(
        inventory(
            "pkg:golang/lib@1.0.5",
            "pkg:golang/lib@2.0.5",
            "pkg:golang/other@1.0.5",
            "pkg:npm/lib@1.0.5",
        ),
        ref.id,
    )
    known = exposure.find_advisory(GHSA)
    assert known is not None and known.advisory_id is not None
    prepared = {
        (item.package.ecosystem, item.package.name, item.installed_version): item
        for item in exposure.prepare(known.advisory_id, ref.id)
    }
    assert set(prepared) == {
        (GO, "lib", "1.0.5"),
        (GO, "lib", "2.0.5"),
        (GO, "other", "1.0.5"),
        (NPM, "lib", "1.0.5"),
    }
    scopes = {item.preparation_scope for item in prepared.values()}
    assert len(scopes) == 1
    [scope] = scopes
    assert scope is not None and len(scope.members) == 4
    go_one = prepared[GO, "lib", "1.0.5"]
    go_two = prepared[GO, "lib", "2.0.5"]
    npm = prepared[NPM, "lib", "1.0.5"]
    affected = go_one.model_copy(
        update={
            "evidence": go_one.evidence.model_copy(
                update={
                    "govulncheck": ImpactGovulncheck.SYMBOL_REACHABLE,
                    "govulncheck_trace": ("app.main", "lib.Decode"),
                }
            )
        }
    )

    def keep(item: ImpactInput, *, day: int = 0, milliseconds: int = 0) -> None:
        exposure.record(
            ref.id,
            item.document("1"),
            provenance().model_copy(
                update={
                    "occurred_at": AT + timedelta(days=day, milliseconds=milliseconds),
                }
            ),
        )

    for tick, item in enumerate((affected, go_two, npm, prepared[GO, "other", "1.0.5"])):
        keep(item, milliseconds=tick)
    keep(
        go_one.model_copy(
            update={
                "evidence": go_one.evidence.model_copy(
                    update={
                        "govulncheck": ImpactGovulncheck.MODULE_REQUIRED_NOT_OBSERVED,
                    }
                )
            }
        ),
        day=1,
    )
    keep(
        npm.model_copy(
            update={
                "evidence": npm.evidence.model_copy(
                    update={
                        "manifest_scan": ImpactManifestScan.MODULE_NOT_IN_MANIFESTS,
                    }
                )
            }
        ),
        day=2,
    )
    keep(
        go_two.model_copy(
            update={
                "evidence": go_two.evidence.model_copy(
                    update={
                        "govulncheck": ImpactGovulncheck.MODULE_REQUIRED_NOT_OBSERVED,
                    }
                )
            }
        ),
        day=3,
    )
    exposure.ingest_sbom(
        inventory(
            "pkg:golang/lib@3.0.5",
            "pkg:golang/other@1.0.5",
        ),
        ref.id,
    )
    corrected = {item.package.name: item for item in exposure.prepare(known.advisory_id, ref.id)}
    assert set(corrected) == {"lib", "other"}
    assert corrected["lib"].preparation_scope != scope
    keep(corrected["other"], day=4)
    keep(corrected["lib"], day=5)
    return exposure


@pytest.mark.parametrize(
    "day,milliseconds,expected",
    [
        (0, -1, {}),
        (0, 2, {}),
        (0, 3, {"affected": 1}),
        (1, -1, {"affected": 1}),
        (1, 0, {"likely_affected": 1}),
        (2, 0, {"inconclusive": 1}),
        (3, 0, {"not_observed": 1}),
        (4, 0, {"not_observed": 1}),
        (5, -1, {"not_observed": 1}),
        (5, 0, {"version_not_in_range": 1}),
    ],
)
def test_complete_snapshot_replaces_obsolete_versions_only_at_its_completion_boundary(
    mixed: ExposureService,
    day: int,
    milliseconds: int,
    expected: dict[str, int],
) -> None:
    result = mixed.summary(
        ExposureFilter(as_of=AT + timedelta(days=day, milliseconds=milliseconds)),
        ExposureDimension.CLASSIFICATION,
    )
    assert {row.key: row.commits for row in result} == expected
    assert sum(row.commits for row in result) == (1 if expected else 0)


def test_latest_complete_multi_package_snapshot_aggregates_worst_not_last_safe_packet(
    mixed: ExposureService,
) -> None:
    at = ExposureFilter(as_of=AT + timedelta(milliseconds=3))
    packages = mixed.summary(at, ExposureDimension.PACKAGE)
    assert {row.key: dict(row.by_classification) for row in packages} == {
        "go/lib": {"affected": 1},
        "go/other": {"version_not_in_range": 1},
        "npm/lib": {"likely_affected": 1},
    }
    ecosystems = mixed.summary(at, ExposureDimension.ECOSYSTEM)
    assert {row.key: dict(row.by_classification) for row in ecosystems} == {
        "go": {"affected": 1},
        "npm": {"likely_affected": 1},
    }
    for dimension in (
        ExposureDimension.ADVISORY,
        ExposureDimension.REPOSITORY,
        ExposureDimension.PRODUCT,
    ):
        [row] = mixed.summary(at, dimension)
        assert (row.commits, row.exposed, row.affected) == (1, 1, 1)
    [npm] = mixed.summary(
        at.model_copy(update={"ecosystem": NPM}),
        ExposureDimension.ADVISORY,
    )
    assert (npm.commits, npm.exposed, npm.affected) == (1, 1, 0)
    assert dict(npm.by_classification) == {"likely_affected": 1}
    assert mixed.summary(ExposureFilter(ecosystem=NPM), ExposureDimension.ADVISORY) == []


def test_timeline_preserves_history_while_complete_corrected_inventory_clears_old_versions(
    mixed: ExposureService,
) -> None:
    points = mixed.timeline(ExposureFilter(), TimeBucket.DAY)
    assert [(row.commits, row.exposed, row.affected, row.analysed) for row in points] == [
        (1, 1, 1, 4),
        (1, 1, 0, 1),
        (1, 1, 0, 1),
        (1, 0, 0, 1),
        (1, 0, 0, 1),
        (1, 0, 0, 1),
    ]
    assert [dict(row.by_classification) for row in points] == [
        {"affected": 1},
        {"likely_affected": 1},
        {"inconclusive": 1},
        {"not_observed": 1},
        {"not_observed": 1},
        {"version_not_in_range": 1},
    ]
    bounded = mixed.timeline(
        ExposureFilter(as_of=AT + timedelta(days=5, microseconds=-1)),
        TimeBucket.DAY,
    )
    assert dict(bounded[-1].by_classification) == {"not_observed": 1}
    assert bounded[-1].analysed == 0
    npm = mixed.timeline(ExposureFilter(ecosystem=NPM), TimeBucket.DAY)
    assert (npm[-1].commits, npm[-1].exposed, npm[-1].analysed) == (0, 0, 0)
    report = mixed.export_impacts(GHSA)
    assert (report.commits, report.analyses) == (1, 2)
    assert {(row.ecosystem, row.module, row.version) for row in report.repos} == {
        (GO, "lib", "3.0.5"),
        (GO, "other", "1.0.5"),
    }
    assert report.classifications["version_not_in_range"] == 2
    assert sum(report.classifications.values()) == report.analyses


def test_ecosystem_filter_cannot_resurrect_affected_members_removed_by_a_complete_scope(
    engine: Engine,
) -> None:
    advisory = GRPC.model_copy(
        update={
            "affected": tuple(
                AffectedPackage(
                    ecosystem=ecosystem,
                    name=name,
                    spans=(AffectedSpan(introduced=Version("0"), fixed=Version("2.0.0")),),
                )
                for ecosystem, name in ((GO, "lib"), (NPM, "one"), (NPM, "two"))
            )
        }
    )
    exposure = reads(engine, advisory=advisory)
    [ref] = refs(engine, 1)
    assert ref.id is not None
    npm_inventory = ("pkg:npm/one@3.0.0", "pkg:npm/two@3.0.0")
    exposure.ingest_sbom(inventory("pkg:golang/lib@1.0.0", *npm_inventory), ref.id)
    known = exposure.find_advisory(GHSA)
    assert known is not None and known.advisory_id is not None
    for item in exposure.prepare(known.advisory_id, ref.id):
        if item.package.ecosystem == GO:
            item = item.model_copy(
                update={
                    "evidence": item.evidence.model_copy(
                        update={
                            "govulncheck": ImpactGovulncheck.SYMBOL_REACHABLE,
                            "govulncheck_trace": ("app.main", "lib.Decode"),
                        }
                    )
                }
            )
        exposure.record(ref.id, item.document("1"), provenance())
    exposure.ingest_sbom(inventory(*npm_inventory), ref.id)
    corrected = exposure.prepare(known.advisory_id, ref.id)
    assert len(corrected) == 2 and all(item.package.ecosystem == NPM for item in corrected)
    for day, item in enumerate(corrected, start=1):
        exposure.record(
            ref.id,
            item.document("1"),
            provenance().model_copy(update={"occurred_at": AT + timedelta(days=day)}),
        )
    before_completion = AT + timedelta(days=2, microseconds=-1)
    for as_of in (AT + timedelta(days=1), before_completion):
        [prior] = exposure.summary(
            ExposureFilter(ecosystem=GO, as_of=as_of), ExposureDimension.ADVISORY
        )
        assert (prior.commits, prior.exposed, prior.affected) == (1, 1, 1)
    for dimension in ExposureDimension:
        assert exposure.summary(ExposureFilter(ecosystem=GO), dimension) == []
    [current] = exposure.summary(ExposureFilter(), ExposureDimension.ADVISORY)
    assert (current.commits, current.exposed, current.affected) == (1, 0, 0)
    historical = exposure.timeline(
        ExposureFilter(ecosystem=GO, as_of=before_completion), TimeBucket.DAY
    )
    assert historical[-1].affected == 1
    points = exposure.timeline(ExposureFilter(ecosystem=GO), TimeBucket.DAY)
    assert [point.affected for point in points] == [1, 1, 0]
    assert (points[-1].commits, points[-1].exposed, points[-1].analysed) == (0, 0, 0)
    exported = exposure.export_impacts(GHSA)
    assert exported.analyses == 2
    assert {(row.ecosystem, row.module) for row in exported.repos} == {
        (NPM, "one"),
        (NPM, "two"),
    }


@pytest.mark.parametrize("invalid", ["missing-own-member", "same-digest-different-members"])
def test_record_refuses_invalid_scope_membership_without_retaining_a_partial_assessment(
    mixed: ExposureService,
    invalid: str,
) -> None:
    report = mixed.export_impacts(GHSA)
    [packet] = [row for row in report.repos if row.module == "lib"]
    document = deepcopy(packet.document)
    scope = document["metadata"]["preparation_scope"]
    wanted = "other" if invalid == "missing-own-member" else "lib"
    scope["members"] = [member for member in scope["members"] if member["module"] == wanted]
    malformed = ImpactAnalysisArtifact.from_document(document)
    before = mixed.impacts(ImpactFilter(), PageRequest(limit=100)).items
    with pytest.raises(ValidationError):
        mixed.record(
            packet.repository_ref_id,
            malformed,
            provenance().model_copy(update={"occurred_at": AT + timedelta(days=6)}),
        )
    assert mixed.impacts(ImpactFilter(), PageRequest(limit=100)).items == before
    assert mixed.export_impacts(GHSA) == report
