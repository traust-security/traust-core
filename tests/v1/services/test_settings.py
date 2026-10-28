from __future__ import annotations

import json
from collections.abc import Iterator
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any
from uuid import uuid4

import pytest
from sqlalchemy.engine import Engine

from tests.v1.conftest import SQL_BACKENDS, contract_db
from tests.v1.settings_support import ADMIN
from traust_core.v1.context import Config, Context
from traust_core.v1.errors import (
    ConflictError,
    DocumentError,
    ForbiddenError,
    NotFoundError,
    SettingNotSet,
    ValidationError,
)
from traust_core.v1.models.artifacts import (
    BudgetArtifact,
    ExecutionBoundariesArtifact,
    OrgParametersArtifact,
)
from traust_core.v1.models.common import Cursor, PageRequest, Provenance
from traust_core.v1.models.identity import IdentitySource, Principal
from traust_core.v1.models.settings import SettingSource
from traust_core.v1.models.vocabulary import ActorKind, SettingKind, SourceType
from traust_core.v1.services.settings import SettingsService

T0 = datetime(2026, 11, 2, 10, tzinfo=UTC)
BUDGET = SettingKind("budget")
EXEC = SettingKind("execution-boundaries")
ORG = SettingKind("org-parameters")
PODMAN = {"version": 1, "sandbox": "podman"}
ORG_DOC = {
    "version": 1,
    "declared_by": "platform-security",
    "parameters": {"allowed_data_regions": {"value": ["eu-west-1"], "controls": ["gdpr:art-44"]}},
}
READER = Principal(
    identity="bob@example.com", kind=ActorKind.HUMAN, display="bob", verified_by=IdentitySource.OIDC
)


class Ticking:
    """A clock that moves a second per read: each change is its own instant."""

    def __init__(self) -> None:
        self.at = T0

    def now(self) -> datetime:
        self.at += timedelta(seconds=1)
        return self.at


@pytest.fixture(params=SQL_BACKENDS)
def engine(request: pytest.FixtureRequest, tmp_path: Path) -> Iterator[Engine]:
    with contract_db(request.param, tmp_path) as eng:
        yield eng


@pytest.fixture
def context(engine: Engine, tmp_path: Path) -> Context:
    ctx = Context(Config(home=tmp_path), clock=Ticking())
    ctx.__dict__["database"] = engine
    return ctx


def settings(context: Context) -> SettingsService:
    return context.services().settings


def test_every_kind_is_listed_default_or_not_set(context: Context) -> None:
    listed = {s.kind: s for s in settings(context).list()}
    assert set(listed) == set(SettingKind)
    defaults = {k for k, s in listed.items() if s.source == SettingSource.DEFAULT}
    assert defaults == {
        SettingKind(k) for k in ("budget", "sla-policy", "rule-pack-allowlist", "feed-access", EXEC)
    }
    assert listed[EXEC].version is not None and listed[EXEC].version.version == 1
    assert listed[EXEC].summary == "version: 1; sandbox: none"
    assert listed[ORG].version is None and listed[ORG].summary == ""


def test_a_kind_without_a_default_is_not_set_until_someone_sets_it(context: Context) -> None:
    service = settings(context)
    with pytest.raises(SettingNotSet, match="traust settings set org-parameters"):
        service.show(ORG)
    assert service.find_document(OrgParametersArtifact) is None
    with pytest.raises(ValidationError, match="no shipped default"):
        service.reset(ORG, "start over", ADMIN)
    change = service.set(ORG, ORG_DOC, "declared by the platform team", ADMIN)
    assert (change.changed, change.version.version, change.version.default) == (True, 1, False)
    assert settings(context).show(ORG).document == ORG_DOC


def test_set_history_diff_reset_round_trip_with_attribution(context: Context) -> None:
    service = settings(context)
    first = service.set(EXEC, PODMAN, "isolate target builds", ADMIN)
    assert (first.changed, first.version.version) == (True, 2)
    assert '-  "sandbox": "none"' in first.diff and '+  "sandbox": "podman"' in first.diff
    reset = settings(context).reset(EXEC, "podman is not on the runners", ADMIN)
    assert (reset.changed, reset.version.version) == (True, 3)
    history = settings(context).history(EXEC, PageRequest())
    assert [(v.version, v.default, v.set_by, v.reason) for v in history.items] == [
        (3, False, ADMIN.ref, "podman is not on the runners"),
        (2, False, ADMIN.ref, "isolate target builds"),
        (1, True, None, None),
    ]
    assert history.next is None and all(v.set_at for v in history.items[:2])
    diff = settings(context).diff(EXEC, 2, 3)
    assert (diff.from_version, diff.to_version) == (2, 3)
    assert diff.diff.startswith(f"--- {EXEC} v2\n+++ {EXEC} v3\n")
    assert settings(context).show(EXEC).document == {"version": 1, "sandbox": "none"}
    assert settings(context).diff(EXEC, 1, 3).diff == ""


def test_setting_the_effective_document_again_changes_nothing(context: Context) -> None:
    service = settings(context)
    assert service.set(EXEC, {"version": 1, "sandbox": "none"}, "same", ADMIN).changed is False
    service.set(EXEC, PODMAN, "isolate", ADMIN)
    again = settings(context).set(EXEC, PODMAN, "isolate again", ADMIN)
    assert (again.changed, again.version.version, again.diff) == (False, 2, "")
    assert settings(context).reset(EXEC, "back", ADMIN).changed is True
    assert settings(context).reset(EXEC, "back again", ADMIN).changed is False


def test_an_admin_may_set_an_older_document_and_history_shows_it(context: Context) -> None:
    service = settings(context)
    service.set(EXEC, PODMAN, "isolate", ADMIN)
    service.set(EXEC, {"version": 1, "sandbox": "none"}, "runners cannot nest", ADMIN)
    back = settings(context).set(EXEC, PODMAN, "nested podman works now", ADMIN)
    assert (back.changed, back.version.version) == (True, 4)
    assert [v.reason for v in settings(context).history(EXEC, PageRequest()).items][:1] == [
        "nested podman works now"
    ]


def test_the_caller_never_writes_the_revision(context: Context) -> None:
    forged = {**PODMAN, "revision": {"set_by": "human:mallory", "reason": "x", "set_at": "x"}}
    change = settings(context).set(EXEC, forged, "isolate", ADMIN)
    assert (change.version.set_by, change.version.reason) == (ADMIN.ref, "isolate")
    assert "revision" not in settings(context).show(EXEC).document


@pytest.mark.parametrize(
    "principal",
    [READER, ADMIN.model_copy(update={"verified_by": None})],
    ids=["not-an-admin", "unverified-admin"],
)
def test_only_a_verified_admin_changes_a_setting(context: Context, principal: Principal) -> None:
    with pytest.raises(ForbiddenError, match="admin"):
        settings(context).set(EXEC, PODMAN, "isolate", principal)
    with pytest.raises(ForbiddenError, match="admin"):
        settings(context).reset(EXEC, "back", principal)
    assert settings(context).show(EXEC).version.default


@pytest.mark.parametrize("reason", ["", "   "])
def test_a_change_needs_a_reason(context: Context, reason: str) -> None:
    with pytest.raises(ValidationError, match="needs a reason"):
        settings(context).set(EXEC, PODMAN, reason, ADMIN)


@pytest.mark.parametrize(
    ("kind", "document", "error", "match"),
    [
        (EXEC, {"version": 1, "sandbox": "docker"}, DocumentError, "sandbox"),
        (SettingKind("rule-pack-allowlist"), {"packs": []}, DocumentError, "packs"),
        (
            SettingKind("feed-access"),
            {"sources": {"osv": {"access": "offline"}}},
            DocumentError,
            "feed-access",
        ),
        (
            BUDGET,
            {
                "lanes": [
                    {"lane": "full-audit", "monthly_usd": 1, "enforcement": "observe"},
                    {"lane": "full-audit", "monthly_usd": 2, "enforcement": "advisory"},
                ]
            },
            ValidationError,
            "more than one budget per lane",
        ),
    ],
    ids=["schema", "allowlist-shape", "feed-access", "two-budgets-one-lane"],
)
def test_a_document_that_breaks_its_kind_is_refused_and_nothing_is_stored(
    context: Context, kind: SettingKind, document: dict[str, Any], error: type, match: str
) -> None:
    with pytest.raises(error, match=match):
        settings(context).set(kind, document, "try", ADMIN)
    assert settings(context).show(kind).version.default


def test_history_pages_newest_first_down_to_the_default(context: Context) -> None:
    for days in (1, 2, 3):
        lanes = [{"lane": "full-audit", "monthly_usd": days, "enforcement": "observe"}]
        settings(context).set(BUDGET, {"lanes": lanes}, f"day {days}", ADMIN)
    first = settings(context).history(BUDGET, PageRequest(limit=2))
    assert [v.version for v in first.items] == [4, 3] and first.next == "3"
    last = settings(context).history(BUDGET, PageRequest(limit=2, cursor=first.next))
    assert [v.version for v in last.items] == [2, 1] and last.next is None
    assert settings(context).history(ORG, PageRequest()).items == ()
    for bad in ("x", "9", "0"):
        with pytest.raises(ValidationError, match="not a version"):
            settings(context).history(BUDGET, PageRequest(cursor=Cursor(bad)))
    with pytest.raises(ValidationError, match="positive"):
        settings(context).history(BUDGET, PageRequest(limit=0))


def test_diff_of_a_version_that_does_not_exist_is_not_found(context: Context) -> None:
    with pytest.raises(NotFoundError, match="has no version 2"):
        settings(context).diff(EXEC, 1, 2)
    with pytest.raises(NotFoundError, match="has no version 1"):
        settings(context).diff(ORG, 1, 1)


def test_a_concurrent_writer_is_a_conflict_not_a_lost_update(
    context: Context, monkeypatch: pytest.MonkeyPatch
) -> None:
    slow = settings(context)
    publish = slow._publisher.publish_successor

    def raced(*args: Any) -> Any:
        settings(context).set(EXEC, PODMAN, "first", ADMIN)
        return publish(*args)

    monkeypatch.setattr(slow._publisher, "publish_successor", raced)
    with pytest.raises(ConflictError, match="another writer"):
        slow.set(EXEC, {"version": 2, "sandbox": "none"}, "second", ADMIN)
    assert settings(context).show(EXEC).document == PODMAN


def test_a_domain_record_is_attributed_to_its_run_and_replays_as_a_no_op(
    context: Context,
) -> None:
    run = Provenance(run_id=uuid4(), source=SourceType.INTERACTIVE, occurred_at=T0)
    doc = OrgParametersArtifact.from_document(ORG_DOC)
    first = settings(context).record(doc, run, "recorded by a run")
    assert first.written and settings(context).record(doc, run, "again").written == ()
    assert settings(context).record(doc, run, "again").artifact_id == first.artifact_id
    (version,) = settings(context).history(ORG, PageRequest()).items
    assert (version.set_by, version.reason) == (f"run:{run.run_id}", "recorded by a run")


def test_superseded_is_the_content_of_an_older_stored_version(context: Context) -> None:
    service = settings(context)
    service.set(EXEC, PODMAN, "isolate", ADMIN)
    service.set(EXEC, {"version": 1, "sandbox": "none"}, "back", ADMIN)
    current = settings(context)
    assert current.superseded(ExecutionBoundariesArtifact.from_document(PODMAN))
    assert not current.superseded(
        ExecutionBoundariesArtifact.from_document({"version": 1, "sandbox": "none"})
    )


def test_digests_name_every_document_in_force(context: Context) -> None:
    settings(context).set(EXEC, PODMAN, "isolate", ADMIN)
    digests = {d.name: d for d in settings(context).digests()}
    assert set(digests) == {
        "budget",
        "sla-policy",
        "rule-pack-allowlist",
        "feed-access",
        "execution-boundaries",
    }
    assert digests["execution-boundaries"].artifact_id is not None
    assert digests["budget"].artifact_id is None


def test_typed_reads_carry_no_revision(context: Context) -> None:
    settings(context).set(BUDGET, {"lanes": []}, "explicitly none", ADMIN)
    assert settings(context).show(BUDGET).version.version == 1
    lanes = [{"lane": "diff-scan", "monthly_usd": 5, "enforcement": "advisory"}]
    settings(context).set(BUDGET, {"lanes": lanes}, "cap diff scans", ADMIN)
    document = settings(context).document(BudgetArtifact)
    assert json.loads(document.payload) == {"lanes": lanes}


def test_a_shipped_default_must_meet_its_schema(context: Context) -> None:
    with pytest.raises(DocumentError):
        SettingsService(settings(context)._publisher, context.clock, {EXEC: {"sandbox": "none"}})
