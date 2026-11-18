from __future__ import annotations

import json
import logging
from collections.abc import Iterator
from contextlib import contextmanager
from pathlib import Path
from uuid import UUID

import pytest
from sqlalchemy.engine import Engine

from tests.v1.conftest import git
from tests.v1.repositories.tables.conftest import Seed
from tests.v1.services import test_remediation as remediation
from traust_core.v1.context import Context
from traust_core.v1.errors import (
    ConflictError,
    DocumentError,
    IntegrityError,
    RepositoryError,
    ValidationError,
)
from traust_core.v1.models.analysis_results import ResultKind
from traust_core.v1.models.artifacts import RemediationArtifact
from traust_core.v1.models.assessment import Artifact
from traust_core.v1.models.common import PageRequest
from traust_core.v1.models.integrity import sha256_hex
from traust_core.v1.models.remediation import WorkItem, WorkItemFilter
from traust_core.v1.models.vocabulary import RemediationStatus
from traust_core.v1.repositories.contract import SqlTraustUnitOfWork
from traust_core.v1.repositories.objects.store import ObjectKey, ObjectRef
from traust_core.v1.repositories.traust.assessments import SqlArtifactRepository
from traust_core.v1.services.artifact_publishing import AssessmentLog
from traust_core.v1.services.findings.decisions import FindingDecisions
from traust_core.v1.services.remediation import RemediationService

engine = remediation.engine
context = remediation.context
service = remediation.service
workspace = remediation.workspace


@pytest.mark.parametrize("replay", [False, True])
@pytest.mark.parametrize("prepublished", [False, True])
def test_report_and_patch_uploads_do_not_hold_write_intent(
    context: Context,
    service: RemediationService,
    engine: Engine,
    monkeypatch: pytest.MonkeyPatch,
    replay: bool,
    prepublished: bool,
) -> None:
    ref, found = remediation.seeded(engine)
    service.open(remediation.ids(found), ref.id)
    diff = b"+bounded\n"
    doc = remediation.report(remediation.ids(found), patch__diff_sha256=sha256_hex(diff))
    provenance = remediation.provenance(
        service._publisher.publish_ref(doc) if prepublished else None
    )
    if replay:
        service.record(doc, provenance)
    locked = 0
    write, put = service._uow.write, context.object_store.put
    get_or_add = SqlArtifactRepository.get_or_add_with_status
    uploaded: list[bytes] = []

    @contextmanager
    def tracked_write() -> Iterator[SqlTraustUnitOfWork]:
        nonlocal locked
        with write() as uow:
            locked += 1
            try:
                yield uow
            finally:
                locked -= 1

    def upload(key: ObjectKey, data: bytes) -> ObjectRef:
        assert not locked, "object upload holds write intent"
        uploaded.append(data)
        return put(key, data)

    def index(repository: SqlArtifactRepository, record: Artifact) -> tuple[Artifact, bool]:
        assert locked, "artifact metadata written outside write intent"
        return get_or_add(repository, record)

    monkeypatch.setattr(service._uow, "write", tracked_write)
    monkeypatch.setattr(context.object_store, "put", upload)
    monkeypatch.setattr(SqlArtifactRepository, "get_or_add_with_status", index)
    recorded = service.record(doc, provenance, diff=diff)
    assert set(uploaded) == ({diff} if replay or prepublished else {diff, doc.payload})
    assert recorded.report is not None and recorded.patch is not None


def test_record_retains_the_assembled_patch_by_id_and_replays_without_new_rows(
    context: Context, service: RemediationService, engine: Engine, workspace: tuple[Path, str]
) -> None:
    path, base = workspace
    item, found = remediation.work_item(engine, service, base)
    draft = service.assemble(
        item.work_item_id, path, remediation.NARRATIVE, [remediation.check("pass")]
    )
    recorded = service.record(draft.report, remediation.provenance(), diff=draft.diff)
    assert recorded.patch is not None and recorded.report is not None
    assert recorded.patch_refusal is None
    assert recorded.patch.digest == draft.report.patch.diff_sha256 == sha256_hex(draft.diff)
    assert recorded.patch.name == "remediation-patch.diff"
    assert context.services().artifacts.payload(recorded.patch.id) == draft.diff
    assert context.services().artifacts.payload(recorded.report.id) == draft.report.payload
    assert service.get(item.work_item_id) == recorded
    listed = service.list(WorkItemFilter(repository_id=found.repository_id), PageRequest())
    assert listed.items == (recorded,)
    before = remediation.decisions(engine, found)
    with SqlTraustUnitOfWork(engine) as uow:
        held = uow.artifacts.list_for_assessment(item.work_item_id)
    assert {row.kind for row in held} == {"remediation", "remediation-patch.diff"}
    assert service.record(draft.report, remediation.provenance(), diff=draft.diff) == recorded
    assert remediation.decisions(engine, found) == before
    with SqlTraustUnitOfWork(engine) as uow:
        assert uow.artifacts.list_for_assessment(item.work_item_id) == held


@pytest.mark.parametrize("diff", [b"", b"\n", b"--- a/example\n+++ b/example\n+bounded\n"])
def test_a_report_recorded_without_patch_bytes_can_receive_its_patch_on_replay(
    service: RemediationService, engine: Engine, diff: bytes
) -> None:
    ref, found = remediation.seeded(engine)
    item = service.open(remediation.ids(found), ref.id)
    doc = remediation.report(remediation.ids(found), patch__diff_sha256=sha256_hex(diff))
    before = service.record(doc, remediation.provenance())
    assert before.patch is None and before.patch_refusal is None
    recorded = service.record(doc, remediation.provenance(), diff=diff)
    assert recorded.report == before.report and recorded.patch is not None
    assert service._publisher.payload(recorded.patch.id) == diff
    assert recorded.work_item_id == item.work_item_id


@pytest.mark.parametrize("replay", [False, True])
@pytest.mark.parametrize(
    ("diff", "digest", "error", "message"),
    [
        (b"wrong bytes", "0" * 64, IntegrityError, "diff digest"),
        (b"\xff", sha256_hex(b"\xff"), DocumentError, "UTF-8"),
        (b"+token=ghp_" + b"A" * 36, None, DocumentError, "high-confidence secret"),
    ],
)
def test_bad_patch_bytes_are_rejected_without_publication_or_progress_changes(
    context: Context,
    service: RemediationService,
    engine: Engine,
    diff: bytes,
    digest: str | None,
    error: type[Exception],
    message: str,
    replay: bool,
) -> None:
    ref, found = remediation.seeded(engine)
    item = service.open(remediation.ids(found), ref.id)
    doc = remediation.report(remediation.ids(found), patch__diff_sha256=digest or sha256_hex(diff))
    if replay:
        item = service.record(doc, remediation.provenance())
    before = remediation.decisions(engine, found[0])
    objects = tuple(context.object_store.list())
    with pytest.raises(error, match=message):
        service.record(doc, remediation.provenance(), diff=diff)
    assert tuple(context.object_store.list()) == objects
    assert service.get(item.work_item_id) == item
    assert remediation.decisions(engine, found[0]) == before


@pytest.mark.parametrize("replay", [False, True])
@pytest.mark.parametrize("prefix", ["-", " "], ids=["removed", "context"])
def test_a_secret_outside_added_lines_skips_only_the_patch(
    context: Context,
    service: RemediationService,
    engine: Engine,
    caplog: pytest.LogCaptureFixture,
    replay: bool,
    prefix: str,
) -> None:
    secret = "ghp_" + "A" * 36
    hunk = "@@ -1 +1 @@\n" if prefix == "-" else "@@ -1 +1,2 @@\n"
    diff = (
        "diff --git a/config.py b/config.py\n"
        f"--- a/config.py\n+++ b/config.py\n{hunk}"
        f'{prefix}token = "{secret}"\n+token = os.environ["API_TOKEN"]\n'
    ).encode()
    ref, found = remediation.seeded(engine)
    item = service.open(remediation.ids(found), ref.id)
    doc = remediation.report(remediation.ids(found), patch__diff_sha256=sha256_hex(diff))
    if replay:
        item = service.record(doc, remediation.provenance())
    before = remediation.decisions(engine, found[0])
    logger = logging.getLogger("traust_core.v1.services.remediation")
    with caplog.at_level(logging.WARNING, logger=logger.name):
        logger.addHandler(caplog.handler)
        try:
            recorded = service.record(doc, remediation.provenance(), diff=diff)
        finally:
            logger.removeHandler(caplog.handler)
    assert recorded.report is not None and recorded.patch is None
    assert recorded.patch_refusal == "unredacted high-confidence secret (github-token)"
    assert secret not in recorded.model_dump_json()
    assert recorded.status == "checks_passed"
    assert recorded.work_item_id == item.work_item_id
    stored = recorded.model_copy(update={"patch_refusal": None})
    assert service.get(item.work_item_id) == stored
    listed = service.list(WorkItemFilter(repository_id=found[0].repository_id), PageRequest())
    assert listed.items == (stored,)
    assert context.services().artifacts.payload(recorded.report.id) == doc.payload
    assert {
        context.object_store.get(context.object_store.stat(key))
        for key in context.object_store.list()
    } == {doc.payload}
    with SqlTraustUnitOfWork(engine) as uow:
        assert uow.artifacts.find(None, sha256_hex(diff)) is None
        assert {row.kind for row in uow.artifacts.list_for_assessment(item.work_item_id)} == {
            "remediation"
        }
    if replay:
        assert remediation.decisions(engine, found[0]) == before
    else:
        assert remediation.decisions(engine, found[0])[-1].reason == "checks_passed"
    assert "patch not retained" in caplog.text
    assert str(item.work_item_id) in caplog.text and sha256_hex(diff) in caplog.text
    assert "github-token" in caplog.text
    assert secret not in caplog.text and diff.decode() not in caplog.text
    before_retry = remediation.decisions(engine, found[0])
    assert service.record(doc, remediation.provenance(), diff=diff) == recorded
    assert remediation.decisions(engine, found[0]) == before_retry
    assert service.record(doc, remediation.provenance()) == stored


@pytest.mark.parametrize("replay", [False, True])
def test_removing_pem_delimiters_with_a_benign_addition_records_only_the_report(
    context: Context, service: RemediationService, engine: Engine, replay: bool
) -> None:
    ref, found = remediation.seeded(engine)
    item = service.open(remediation.ids(found), ref.id)
    diff = b"------BEGIN PRIVATE KEY-----\n-QWERTY\n+bounded\n------END PRIVATE KEY-----\n"
    doc = remediation.report(remediation.ids(found), patch__diff_sha256=sha256_hex(diff))
    if replay:
        service.record(doc, remediation.provenance())
    recorded = service.record(doc, remediation.provenance(), diff=diff)
    assert recorded.work_item_id == item.work_item_id
    assert recorded.report is not None and recorded.patch is None
    assert recorded.patch_refusal == "unredacted high-confidence secret (pem-private-key)"
    assert service.get(item.work_item_id).report == recorded.report
    assert context.services().artifacts.payload(recorded.report.id) == doc.payload
    assert {
        context.object_store.get(context.object_store.stat(key))
        for key in context.object_store.list()
    } == {doc.payload}


@pytest.mark.parametrize("replay", [False, True])
def test_the_skipped_patch_warning_waits_for_the_owning_transaction_commit(
    service: RemediationService,
    engine: Engine,
    caplog: pytest.LogCaptureFixture,
    replay: bool,
) -> None:
    ref, found = remediation.seeded(engine)
    item = service.open(remediation.ids(found), ref.id)
    diff = b"-token=ghp_" + b"A" * 36 + b"\n+token=read_env()\n"
    doc = remediation.report(remediation.ids(found), patch__diff_sha256=sha256_hex(diff))
    if replay:
        item = service.record(doc, remediation.provenance())
    logger = logging.getLogger("traust_core.v1.services.remediation")
    with caplog.at_level(logging.WARNING, logger=logger.name):
        logger.addHandler(caplog.handler)
        try:
            with service._uow:
                recorded = service.record(doc, remediation.provenance(), diff=diff)
                assert recorded.report is not None and recorded.patch is None
                assert "patch not retained" not in caplog.text
            assert "patch not retained" not in caplog.text
        finally:
            logger.removeHandler(caplog.handler)
    assert service.get(item.work_item_id) == item


def test_wrong_report_provenance_does_not_publish_a_patch(
    context: Context, service: RemediationService, engine: Engine
) -> None:
    ref, found = remediation.seeded(engine)
    item = service.open(remediation.ids(found), ref.id)
    diff = b"+bounded\n"
    doc = remediation.report(remediation.ids(found), patch__diff_sha256=sha256_hex(diff))
    other = remediation.report(remediation.ids(found), summary__status="patched")
    published = service._publisher.publish_ref(other)
    before = tuple(context.object_store.list())
    with pytest.raises(IntegrityError, match="doc digest"):
        service.record(doc, remediation.provenance(published), diff=diff)
    assert tuple(context.object_store.list()) == before
    assert service.get(item.work_item_id) == item


@pytest.mark.parametrize("recording", ["fresh", "recorded", "legacy"])
@pytest.mark.parametrize(
    "diff",
    [None, b"+bounded\n", b"-token=ghp_" + b"A" * 36 + b"\n+token=read_env()\n"],
    ids=["report-only", "retained-patch", "refused-patch"],
)
def test_failed_progress_rolls_back_report_patch_tickets_and_decisions(
    service: RemediationService,
    engine: Engine,
    monkeypatch: pytest.MonkeyPatch,
    recording: str,
    diff: bytes | None,
) -> None:
    ref, found = remediation.seeded(engine, findings=2)
    item = service.open(remediation.ids(found), ref.id)
    doc = remediation.report(remediation.ids(found), patch__diff_sha256=sha256_hex(diff or b""))
    if recording == "recorded":
        item = service.record(doc, remediation.provenance())
    elif recording == "legacy":
        published = service._publisher.publish_ref(doc)
        with service._uow as uow:
            service._log.attach(item.work_item_id, published.id, published.digest)
            uow.commit()
        item = service.get(item.work_item_id)
    before = [remediation.decisions(engine, finding) for finding in found]
    with SqlTraustUnitOfWork(engine) as uow:
        held = uow.artifacts.list_for_assessment(item.work_item_id)
        report = uow.artifacts.find(None, sha256_hex(doc.payload))
        links = uow.finding_external_refs.list_for_findings(remediation.ids(found))
    advance = service._record_progress

    def interrupted(
        current: WorkItem,
        status: RemediationStatus,
        artifact_id: UUID | None = None,
        *,
        replay: bool = False,
    ) -> None:
        advance(current, status, artifact_id, replay=replay)
        raise RepositoryError("progress interrupted")

    with monkeypatch.context() as patch:
        patch.setattr(service, "_record_progress", interrupted)
        with pytest.raises(RepositoryError, match="progress interrupted"):
            service.record(doc, remediation.provenance(), diff=diff)
    assert service.get(item.work_item_id) == item
    assert [remediation.decisions(engine, finding) for finding in found] == before
    with SqlTraustUnitOfWork(engine) as uow:
        assert uow.artifacts.list_for_assessment(item.work_item_id) == held
        assert uow.artifacts.find(None, sha256_hex(doc.payload)) == report
        if diff is not None:
            assert uow.artifacts.find(None, sha256_hex(diff)) is None
        assert uow.finding_external_refs.list_for_findings(remediation.ids(found)) == links
    recorded = service.record(doc, remediation.provenance(), diff=diff)
    assert recorded.report is not None and recorded.status == "checks_passed"
    assert (recorded.patch is not None) == (diff == b"+bounded\n")


@pytest.mark.parametrize("replay", [False, True])
def test_failed_patch_attachment_rolls_back_publication_and_retries_cleanly(
    service: RemediationService, engine: Engine, monkeypatch: pytest.MonkeyPatch, replay: bool
) -> None:
    ref, found = remediation.seeded(engine)
    item = service.open(remediation.ids(found), ref.id)
    diff = b"+bounded\n"
    doc = remediation.report(remediation.ids(found), patch__diff_sha256=sha256_hex(diff))
    if replay:
        item = service.record(doc, remediation.provenance())
    with SqlTraustUnitOfWork(engine) as uow:
        held = uow.artifacts.list_for_assessment(item.work_item_id)
        published = uow.artifacts.find(None, sha256_hex(doc.payload))
    attach = AssessmentLog.attach

    def failed(
        log: AssessmentLog,
        assessment_id: UUID,
        artifact_id: UUID,
        digest: str,
        run_order_id: UUID | None = None,
    ) -> Artifact:
        if log.get_artifact(artifact_id).kind == "remediation-patch.diff":
            raise RepositoryError("patch attachment failed")
        return attach(log, assessment_id, artifact_id, digest, run_order_id)

    with monkeypatch.context() as patch:
        patch.setattr(AssessmentLog, "attach", failed)
        with pytest.raises(RepositoryError, match="patch attachment failed"):
            service.record(doc, remediation.provenance(), diff=diff)
    assert service.get(item.work_item_id) == item
    with SqlTraustUnitOfWork(engine) as uow:
        assert uow.artifacts.list_for_assessment(item.work_item_id) == held
        assert uow.artifacts.find(None, sha256_hex(diff)) is None
        assert uow.artifacts.find(None, sha256_hex(doc.payload)) == published
    recorded = service.record(doc, remediation.provenance(), diff=diff)
    assert recorded.report is not None and recorded.patch is not None


def test_an_abandoned_attempt_retains_its_no_changes_diff(
    service: RemediationService, engine: Engine, workspace: tuple[Path, str]
) -> None:
    path, _ = workspace
    item, _ = remediation.work_item(engine, service, git(path, "rev-parse", "HEAD"))
    narrative = remediation.NARRATIVE.model_copy(update={"status": "abandoned"})
    draft = service.assemble(item.work_item_id, path, narrative, [remediation.check("skip")])
    recorded = service.record(draft.report, remediation.provenance(), diff=draft.diff)
    assert recorded.status == "abandoned" and recorded.patch is not None
    assert service._publisher.payload(recorded.patch.id) == draft.diff == b"\n"


def test_patch_backfill_after_merge_does_not_overwrite_a_later_resolution(
    context: Context, service: RemediationService, engine: Engine
) -> None:
    ref, found = remediation.seeded(engine)
    finding = found[0]
    item = service.open(remediation.ids(found), ref.id)
    diff = b"+bounded\n"
    doc = remediation.report(remediation.ids(found), patch__diff_sha256=sha256_hex(diff))
    service.record(doc, remediation.provenance())
    service.record_progress(item.work_item_id, RemediationStatus.MERGED)
    with SqlTraustUnitOfWork(engine) as uow:
        Seed(uow).decision(
            finding,
            resolution="resolved",
            repository_ref_id=ref.id,
            actor="human:a@example.com",
            occurred_at=context.clock.now(),
        )
        uow.commit()
    before = remediation.decisions(engine, finding)
    recorded = service.record(doc, remediation.provenance(), diff=diff)
    assert recorded.status == "merged" and recorded.patch is not None
    assert remediation.decisions(engine, finding) == before
    assert not context.services().findings.get(finding.id).is_open()


@pytest.mark.parametrize("later", ["resolved", "merged"])
def test_retry_after_failed_recording_preserves_later_resolution_and_terminal_progress(
    context: Context,
    service: RemediationService,
    engine: Engine,
    monkeypatch: pytest.MonkeyPatch,
    later: str,
) -> None:
    ref, found = remediation.seeded(engine)
    finding = found[0]
    item = service.open(remediation.ids(found), ref.id)
    diff = b"+bounded\n"
    doc = remediation.report(
        remediation.ids(found),
        patch__diff_sha256=sha256_hex(diff),
        summary__status="abandoned" if later == "merged" else "checks_passed",
    )

    def interrupted(*args: object, **kwargs: object) -> None:
        raise RepositoryError("resolution interrupted")

    with monkeypatch.context() as patch:
        patch.setattr(FindingDecisions, "record_resolution", interrupted)
        with pytest.raises(RepositoryError, match="resolution interrupted"):
            service.record(doc, remediation.provenance())
    assert service.get(item.work_item_id) == item
    if later == "resolved":
        with SqlTraustUnitOfWork(engine) as uow:
            Seed(uow).decision(
                finding,
                resolution="resolved",
                repository_ref_id=ref.id,
                actor="human:a@example.com",
                occurred_at=context.clock.now(),
            )
            uow.commit()
    else:
        service.record_progress(item.work_item_id, RemediationStatus.MERGED)
    if later == "resolved":
        recovered = service.record(doc, remediation.provenance(), diff=diff)
        assert recovered.patch is not None
        assert recovered.status == "checks_passed"
        assert not context.services().findings.get(finding.id).is_open()
        assert remediation.decisions(engine, finding)[-1].resolution is None
    else:
        with pytest.raises(ValidationError, match="no single open work item"):
            service.record(doc, remediation.provenance(), diff=diff)
        current = service.get(item.work_item_id)
        assert current.status == "merged" and current.report is None and current.patch is None
        assert not any(d.reason == "abandoned" for d in remediation.decisions(engine, finding))


def test_matching_digest_provenance_of_the_wrong_kind_is_refused_before_patch_publication(
    context: Context, service: RemediationService, engine: Engine
) -> None:
    ref, found = remediation.seeded(engine)
    item = service.open(remediation.ids(found), ref.id)
    diff = b"+bounded\n"
    doc = remediation.report(remediation.ids(found), patch__diff_sha256=sha256_hex(diff))
    raw = json.loads(doc.payload)
    raw["patch"]["diff_sha256"] = sha256_hex(doc.payload)
    wrong_kind = service._publisher.publish_companion(
        RemediationArtifact.parse(json.dumps(raw).encode()),
        ResultKind.REMEDIATION_PATCH,
        doc.payload,
    )
    before = tuple(context.object_store.list())
    with pytest.raises(IntegrityError, match="not a remediation document"):
        service.record(doc, remediation.provenance(wrong_kind), diff=diff)
    assert tuple(context.object_store.list()) == before
    assert service.get(item.work_item_id) == item


def test_patch_digest_comes_from_retained_report_bytes_not_a_mutated_document_mapping(
    context: Context, service: RemediationService, engine: Engine
) -> None:
    import json

    ref, found = remediation.seeded(engine)
    item = service.open(remediation.ids(found), ref.id)
    original, changed = b"+original\n", b"+different\n"
    raw = json.loads(
        remediation.report(remediation.ids(found), patch__diff_sha256=sha256_hex(original)).payload
    )
    doc = RemediationArtifact.from_document(raw)
    raw["patch"]["diff_sha256"] = sha256_hex(changed)
    with pytest.raises(IntegrityError, match="diff digest"):
        service.record(doc, remediation.provenance(), diff=changed)
    assert tuple(context.object_store.list()) == ()
    assert service.get(item.work_item_id) == item
    recorded = service.record(doc, remediation.provenance(), diff=original)
    assert recorded.patch is not None and recorded.patch.digest == sha256_hex(original)


def test_a_conflicting_recording_indexes_only_the_winners_report_and_patch(
    context: Context,
    service: RemediationService,
    engine: Engine,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    ref, found = remediation.seeded(engine)
    item = service.open(remediation.ids(found), ref.id)
    first, winner = b"+first\n", b"+winner\n"
    doc = remediation.report(remediation.ids(found), patch__diff_sha256=sha256_hex(first))
    other = remediation.report(remediation.ids(found), patch__diff_sha256=sha256_hex(winner))
    reported_item = service._reported_item

    def interleaved(wanted: tuple[UUID, ...], digest: str, work_item_id: UUID | None) -> WorkItem:
        stale = reported_item(wanted, digest, work_item_id)
        context.services().remediation.record(other, remediation.provenance(), diff=winner)
        return stale

    monkeypatch.setattr(service, "_reported_item", interleaved)
    with pytest.raises(ConflictError, match="already holds another report"):
        service.record(doc, remediation.provenance(), diff=first)
    recorded = service.get(item.work_item_id)
    assert recorded.report is not None and recorded.patch is not None
    assert service._publisher.payload(recorded.report.id) == other.payload
    assert service._publisher.payload(recorded.patch.id) == winner
    assert {
        context.object_store.get(context.object_store.stat(key))
        for key in context.object_store.list()
    } == {other.payload, winner, doc.payload, first}
    with SqlTraustUnitOfWork(engine) as uow:
        assert uow.artifacts.find(None, sha256_hex(first)) is None
        assert uow.artifacts.find(None, sha256_hex(doc.payload)) is None
        assert {row.digest for row in uow.artifacts.list_for_assessment(item.work_item_id)} == {
            sha256_hex(other.payload),
            sha256_hex(winner),
        }


def test_a_resolution_before_recording_locks_is_not_reopened(
    context: Context,
    service: RemediationService,
    engine: Engine,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    ref, found = remediation.seeded(engine)
    finding = found[0]
    item = service.open(remediation.ids(found), ref.id)
    reported_item = service._reported_item

    def interleaved(wanted: tuple[UUID, ...], digest: str, work_item_id: UUID | None) -> WorkItem:
        stale = reported_item(wanted, digest, work_item_id)
        with SqlTraustUnitOfWork(engine) as uow:
            Seed(uow).decision(
                finding,
                resolution="resolved",
                repository_ref_id=ref.id,
                actor="human:a@example.com",
                occurred_at=context.clock.now(),
            )
            uow.commit()
        return stale

    monkeypatch.setattr(service, "_reported_item", interleaved)
    recorded = service.record(remediation.report(remediation.ids(found)), remediation.provenance())
    assert recorded.work_item_id == item.work_item_id and recorded.status == "checks_passed"
    assert not context.services().findings.get(finding.id).is_open()


def test_legacy_report_replay_rechecks_terminal_progress_after_staging(
    context: Context,
    service: RemediationService,
    engine: Engine,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    ref, found = remediation.seeded(engine)
    item = service.open(remediation.ids(found), ref.id)
    diff = b"+bounded\n"
    doc = remediation.report(
        remediation.ids(found), summary__status="abandoned", patch__diff_sha256=sha256_hex(diff)
    )

    published = service._publisher.publish_ref(doc)
    with service._uow as uow:
        service._log.attach(item.work_item_id, published.id, published.digest)
        uow.commit()
    reported_item = service._reported_item

    def interleaved(wanted: tuple[UUID, ...], digest: str, work_item_id: UUID | None) -> WorkItem:
        stale = reported_item(wanted, digest, work_item_id)
        context.services().remediation.record_progress(item.work_item_id, RemediationStatus.MERGED)
        return stale

    monkeypatch.setattr(service, "_reported_item", interleaved)
    recovered = service.record(doc, remediation.provenance(), diff=diff)
    assert recovered.status == "merged" and recovered.patch is not None
    assert not any(d.reason == "abandoned" for d in remediation.decisions(engine, found[0]))


def test_progress_cannot_use_a_stale_read_to_move_a_merged_attempt(
    context: Context,
    service: RemediationService,
    engine: Engine,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    ref, found = remediation.seeded(engine)
    item = service.open(remediation.ids(found), ref.id)
    get = service.get

    def interleaved(work_item_id: UUID) -> WorkItem:
        stale = get(work_item_id)
        context.services().remediation.record_progress(work_item_id, RemediationStatus.MERGED)
        return stale

    monkeypatch.setattr(service, "get", interleaved)
    with pytest.raises(ConflictError, match="merged can't move to abandoned"):
        service.record_progress(item.work_item_id, RemediationStatus.ABANDONED)
    assert get(item.work_item_id).status == "merged"


@pytest.mark.parametrize("phase", ["progress", "record", "retry"])
def test_nondefault_line_resolution_survives_every_remediation_recording_phase(
    context: Context,
    service: RemediationService,
    engine: Engine,
    monkeypatch: pytest.MonkeyPatch,
    phase: str,
) -> None:
    main, found = remediation.seeded(engine)
    finding = found[0]
    with SqlTraustUnitOfWork(engine) as uow:
        seed = Seed(uow)
        repository = uow.repositories.get(main.repository_id)
        release = seed.repository_ref(repository, name="release", sha="b" * 40)
        seed.occurrence(finding, seed.assessment(main), severity="high")
        seed.occurrence(finding, seed.assessment(release), severity="high")
        uow.commit()
    item = service.open(remediation.ids(found), release.id)
    doc = remediation.report(remediation.ids(found))
    if phase == "retry":

        def interrupted(*args: object, **kwargs: object) -> None:
            raise RepositoryError("resolution interrupted")

        with monkeypatch.context() as patch:
            patch.setattr(FindingDecisions, "record_resolution", interrupted)
            with pytest.raises(RepositoryError, match="resolution interrupted"):
                service.record(doc, remediation.provenance())
        assert service.get(item.work_item_id) == item
    with SqlTraustUnitOfWork(engine) as uow:
        Seed(uow).decision(
            finding,
            resolution="resolved",
            repository_ref_id=release.id,
            actor="human:a@example.com",
            occurred_at=context.clock.now(),
        )
        uow.commit()
    if phase == "progress":
        service.record_progress(item.work_item_id, RemediationStatus.MERGED)
    else:
        service.record(doc, remediation.provenance())
    views = context.services().findings
    assert views.list_by_ids(remediation.ids(found), repository_ref_id=main.id)[0].is_open()
    assert not views.list_by_ids(remediation.ids(found), repository_ref_id=release.id)[0].is_open()


def test_ref_scoped_reads_reject_findings_from_another_repository(
    context: Context, engine: Engine
) -> None:
    ref, _ = remediation.seeded(engine)
    _, other = remediation.seeded(engine)
    with pytest.raises(remediation.ValidationError, match="is not in commit"):
        context.services().findings.list_by_ids(remediation.ids(other), repository_ref_id=ref.id)


def test_an_empty_ref_scoped_read_is_empty(context: Context, engine: Engine) -> None:
    ref, _ = remediation.seeded(engine)
    assert context.services().findings.list_by_ids([], repository_ref_id=ref.id) == []
