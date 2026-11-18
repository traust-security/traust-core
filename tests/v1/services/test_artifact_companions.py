from __future__ import annotations

import json
import logging

import pytest
from sqlalchemy.engine import Engine

from tests.v1.services import test_artifact_publishing as publishing
from tests.v1.services.test_remediation import REPORT
from traust_core.v1.errors import (
    ConfigError,
    DocumentError,
    IntegrityError,
    RemovedSecretError,
    RepositoryError,
    ValidationError,
)
from traust_core.v1.models.analysis_results import ResultKind
from traust_core.v1.models.artifacts import ArtifactDocument, RemediationArtifact, TriageArtifact
from traust_core.v1.models.integrity import sha256_hex
from traust_core.v1.repositories.contract import SqlTraustUnitOfWork
from traust_core.v1.repositories.objects import InMemoryObjectStore
from traust_core.v1.repositories.objects.store import ObjectKey
from traust_core.v1.repositories.traust.assessments import SqlArtifactRepository
from traust_core.v1.services.artifact_publishing import (
    ArtifactPublisher,
    Companion,
    PublishSpec,
    PublishSpecs,
    _split_diff,
)

engine = publishing.engine
KIND = ResultKind.REMEDIATION_PATCH
SECRET = "ghp_" + "A" * 36


@pytest.fixture
def setup(engine: Engine) -> publishing.Publishing:
    unit, store = SqlTraustUnitOfWork(engine), InMemoryObjectStore()
    specs = PublishSpecs(PublishSpec(RemediationArtifact), PublishSpec(TriageArtifact))
    return publishing.Publishing(ArtifactPublisher(specs, store, unit), store, unit)


@pytest.fixture
def document() -> RemediationArtifact:
    raw = json.loads(json.dumps(REPORT))
    raw["patch"]["diff_sha256"] = sha256_hex(b"+bounded\n")
    return RemediationArtifact.parse(json.dumps(raw).encode())


@pytest.mark.parametrize("entry_point", ["publish_companion", "stage_companion"])
@pytest.mark.parametrize(
    ("artifact_type", "kind"),
    [
        (TriageArtifact, KIND),
        (RemediationArtifact, ResultKind.TRIAGE_MD),
        (TriageArtifact, ResultKind.TRIAGE_MD),
    ],
)
def test_only_remediation_patch_companions_are_allowed_before_any_write(
    setup: publishing.Publishing,
    document: RemediationArtifact,
    entry_point: str,
    artifact_type: type[ArtifactDocument],
    kind: ResultKind,
) -> None:
    doc = (
        document
        if artifact_type is RemediationArtifact
        else TriageArtifact.parse(publishing.triage_with(publishing.FINDING))
    )
    payload = b"+bounded\n"
    with pytest.raises(ValidationError, match="only remediation reports"):
        getattr(setup.service, entry_point)(doc, kind, payload)
    assert list(setup.store.list()) == []
    assert setup.service.find(sha256_hex(payload)) is None


def test_a_companion_is_indexed_idempotently_and_read_with_its_recorded_digest(
    setup: publishing.Publishing, document: RemediationArtifact
) -> None:
    doc = document
    diff = b"+bounded\n"
    ref = setup.service.publish_companion(doc, KIND, diff)
    assert setup.service.publish_companion(doc, KIND, diff) == ref
    assert (ref.name, ref.digest) == (KIND.value, sha256_hex(diff))
    assert setup.service.payload(ref.id) == diff
    assert setup.service.metadata(ref.id).assessment_id is None
    assert len(list(setup.store.list())) == 1
    setup.store.put(ObjectKey.parse(setup.service.metadata(ref.id).uri), b"tampered")
    with pytest.raises(IntegrityError, match="sha256"):
        setup.service.payload(ref.id)


@pytest.mark.parametrize("entry_point", ["publish_companion", "stage_companion"])
@pytest.mark.parametrize("declaration", ["omitted", "mismatched"])
@pytest.mark.parametrize("mutated", [False, True])
def test_companions_require_the_reports_declared_digest_before_any_write(
    setup: publishing.Publishing,
    document: RemediationArtifact,
    entry_point: str,
    declaration: str,
    mutated: bool,
) -> None:
    payload = b"+bounded\n"
    raw = json.loads(document.payload)
    if declaration == "omitted":
        raw["patch"].pop("diff_sha256", None)
    else:
        raw["patch"]["diff_sha256"] = sha256_hex(b"+another patch\n")
    doc = RemediationArtifact.from_document(raw)
    if mutated:
        raw["patch"]["diff_sha256"] = sha256_hex(payload)
    error = IntegrityError if declaration == "mismatched" else ValidationError
    with pytest.raises(error, match="diff digest"):
        getattr(setup.service, entry_point)(doc, KIND, payload)
    assert list(setup.store.list()) == []
    assert setup.service.find(sha256_hex(payload)) is None


def test_companion_staging_needs_no_database_and_indexing_needs_no_object_io(
    setup: publishing.Publishing, document: RemediationArtifact, monkeypatch: pytest.MonkeyPatch
) -> None:
    doc = document
    diff = b"+bounded\n"

    def unexpected(*args: object) -> None:
        pytest.fail("unexpected I/O during companion publication phase")

    with monkeypatch.context() as patch:
        patch.setattr(SqlTraustUnitOfWork, "__enter__", unexpected)
        staged = setup.service.stage_companion(doc, KIND, diff)
    assert setup.service.find(sha256_hex(diff)) is None
    with monkeypatch.context() as patch:
        for method in ("put", "get", "stat"):
            patch.setattr(setup.store, method, unexpected)
        ref = setup.service.record_companion(staged)
    assert ref == setup.service.publish_companion(doc, KIND, diff)
    assert setup.service.payload(ref.id) == diff


def test_staged_companion_metadata_and_success_log_wait_for_the_outer_commit(
    setup: publishing.Publishing, document: RemediationArtifact, caplog: pytest.LogCaptureFixture
) -> None:
    doc = document
    diff = b"+bounded\n"
    staged = setup.service.stage_companion(doc, KIND, diff)
    with caplog.at_level(logging.INFO, logger="traust_core.v1.services.artifact_publishing"):
        with setup.uow:
            setup.service.record_companion(staged)
            assert "companion published" not in caplog.text
        assert "companion published" not in caplog.text
        assert setup.service.find(sha256_hex(diff)) is None
        assert len(list(setup.store.list())) == 1
        retried = setup.service.record_companion(setup.service.stage_companion(doc, KIND, diff))
    assert "companion published" in caplog.text
    assert retried == setup.service.publish_companion(doc, KIND, diff)
    assert len(list(setup.store.list())) == 1


@pytest.mark.parametrize("case", ["digest", "schema", "unregistered", "report secret"])
def test_companion_admission_validates_the_primary_and_digest_before_any_write(
    setup: publishing.Publishing, document: RemediationArtifact, case: str
) -> None:
    doc = document
    diff = b"+bounded\n"
    publisher = setup.service
    error = DocumentError
    if case == "digest":
        diff, error = b"+changed\n", IntegrityError
    elif case == "schema":
        doc = RemediationArtifact(b"{}", {})
    elif case == "unregistered":
        publisher = ArtifactPublisher(PublishSpecs(), setup.store, setup.uow)
        error = ConfigError
    else:
        raw = json.loads(doc.payload)
        raw["title"] = f"Remediation: {SECRET}"
        doc = RemediationArtifact.parse(json.dumps(raw).encode())
    with pytest.raises(error) as caught:
        publisher.publish_companion(doc, KIND, diff)
    assert type(caught.value) is error
    assert list(setup.store.list()) == []


@pytest.mark.parametrize(
    ("diff", "error"),
    [
        (f"-token={SECRET}\n+token=read_env()\n", RemovedSecretError),
        (f" token={SECRET}\n+bounded\n", RemovedSecretError),
        (f"+token={SECRET}\n", DocumentError),
        (f"-token={SECRET}\n+token={SECRET}\n", DocumentError),
        (f"@@ -1 +1 @@\n-old\n+++ token={SECRET}\n", DocumentError),
        (
            "------BEGIN PRIVATE KEY-----\n-QWERTY\n------END PRIVATE KEY-----\n+read_env()\n",
            RemovedSecretError,
        ),
        (
            "------BEGIN PRIVATE KEY-----\n+bounded\n------END PRIVATE KEY-----\n",
            RemovedSecretError,
        ),
        (
            "------BEGIN PRIVATE KEY-----\n-QWERTY\n+bounded\n------END PRIVATE KEY-----\n",
            RemovedSecretError,
        ),
        (
            f"------BEGIN PRIVATE KEY-----\n+token={SECRET}\n------END PRIVATE KEY-----\n",
            DocumentError,
        ),
        (
            " -----BEGIN PRIVATE KEY-----\n-QWERTY\n -----END PRIVATE KEY-----\n",
            RemovedSecretError,
        ),
        (
            " -----BEGIN PRIVATE KEY-----\n+QWERTY\n -----END PRIVATE KEY-----\n",
            DocumentError,
        ),
        (
            "+-----BEGIN PRIVATE KEY-----\n+QWERTY\n+-----END PRIVATE KEY-----\n",
            DocumentError,
        ),
        (
            "+-----BEGIN PRIVATE KEY-----\n QWERTY\n -----END PRIVATE KEY-----\n",
            DocumentError,
        ),
        (
            " -----BEGIN PRIVATE KEY-----\n QWERTY\n+-----END PRIVATE KEY-----\n",
            DocumentError,
        ),
        (
            "------BEGIN PRIVATE KEY-----\n+QWERTY\n -----END PRIVATE KEY-----\n",
            DocumentError,
        ),
        (
            " -----BEGIN PRIVATE KEY-----\n+QWERTY\n------END PRIVATE KEY-----\n",
            DocumentError,
        ),
    ],
    ids=[
        "removed-token",
        "context-token",
        "added-token",
        "removed-and-added-token",
        "added-plus-plus-content",
        "removed-pem",
        "removed-delimiters-benign-addition",
        "removed-key-benign-addition",
        "removed-delimiters-added-token",
        "removed-pem-body",
        "added-pem-body",
        "added-pem",
        "added-pem-begin",
        "added-pem-end",
        "removed-begin-added-body",
        "removed-end-added-body",
    ],
)
def test_patch_secret_refusals_distinguish_added_secrets_without_storing_bytes(
    setup: publishing.Publishing,
    document: RemediationArtifact,
    diff: str,
    error: type[DocumentError],
) -> None:
    payload = diff.encode()
    raw = json.loads(document.payload)
    raw["patch"]["diff_sha256"] = sha256_hex(payload)
    doc = RemediationArtifact.parse(json.dumps(raw).encode())
    with pytest.raises(error) as caught:
        setup.service.publish_companion(doc, KIND, payload)
    assert type(caught.value) is error
    assert caught.value.issues[0].path == "companions/remediation-patch.diff"
    assert SECRET not in str(caught.value)
    assert list(setup.store.list()) == []
    with setup.uow as uow:
        assert uow.artifacts.find(None, sha256_hex(payload)) is None


def test_nonpatch_companions_keep_the_existing_secret_refusal(
    setup: publishing.Publishing,
) -> None:
    doc = TriageArtifact.parse(publishing.triage_with(publishing.FINDING))
    payload = f"-token={SECRET}\n".encode()
    publisher = ArtifactPublisher(
        PublishSpecs(
            PublishSpec(
                TriageArtifact, companions=(Companion(ResultKind.TRIAGE_MD, lambda _: payload),)
            )
        ),
        setup.store,
        setup.uow,
    )
    with pytest.raises(DocumentError) as caught:
        publisher.publish_artifact(doc)
    assert type(caught.value) is DocumentError
    assert list(setup.store.list()) == []


@pytest.mark.parametrize(
    ("text", "added", "other"),
    [
        ("", "", ""),
        ("+new\n-old\n context\n", "new\n", "-old\n context\n"),
        ("--- a/file\n+++ b/file\n", "", "--- a/file\n+++ b/file\n"),
        (
            "@@ -1 +1 @@\n-old\n+++ content\n",
            "++ content\n",
            "@@ -1 +1 @@\n-old\n",
        ),
        (
            "@@ -1 +1 @@\n+first\ndiff --git a/next b/next\n+++ b/next\n",
            "first\n",
            "@@ -1 +1 @@\ndiff --git a/next b/next\n+++ b/next\n",
        ),
        ("+new", "new", ""),
        (
            "------BEGIN PRIVATE KEY-----\n-QWERTY\n+bounded\n------END PRIVATE KEY-----\n",
            "bounded\n",
            "------BEGIN PRIVATE KEY-----\n-QWERTY\n------END PRIVATE KEY-----\n",
        ),
    ],
)
def test_diff_additions_exclude_file_headers_but_not_plus_plus_content(
    text: str, added: str, other: str
) -> None:
    assert _split_diff(text) == (added, other)


def test_companion_metadata_failure_has_no_success_log_or_indexed_row(
    setup: publishing.Publishing,
    document: RemediationArtifact,
    monkeypatch: pytest.MonkeyPatch,
    caplog: pytest.LogCaptureFixture,
) -> None:
    def failed(*_: object) -> None:
        raise RepositoryError("database unavailable")

    monkeypatch.setattr(SqlArtifactRepository, "get_or_add_with_status", failed)
    doc = document
    diff = b"+bounded\n"
    with (
        caplog.at_level(logging.INFO, logger="traust_core.v1.services.artifact_publishing"),
        pytest.raises(RepositoryError, match="database unavailable"),
    ):
        setup.service.publish_companion(doc, KIND, diff)
    assert "companion published" not in caplog.text
    assert setup.service.find(sha256_hex(diff)) is None
