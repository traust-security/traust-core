from __future__ import annotations

from typing import Annotated, Any

from fastapi import APIRouter, Query
from pydantic import Field

from traust_core.v1.models.base import Model
from traust_core.v1.models.common import Cursor, Page, PageRequest
from traust_core.v1.models.settings import (
    Setting,
    SettingChange,
    SettingDiff,
    SettingSummary,
    SettingVersion,
)
from traust_core.v1.models.vocabulary import SettingKind
from traust_core.v1.rest.common.deps import Caller
from traust_core.v1.rest.common.problems import PROBLEMS
from traust_core.v1.rest.settings.service import Settings

router = APIRouter()


class SettingBody(Model):
    """A new version of a setting: the whole document and why; the kind is the path."""

    document: dict[str, Any]
    reason: Annotated[str, Field(min_length=1, max_length=2000)]


@router.get("/v1/settings", responses=PROBLEMS(401))
def list_settings(settings: Settings, _: Caller) -> list[SettingSummary]:
    return settings.list()


@router.get("/v1/settings/{kind}", responses=PROBLEMS(401, 404, 422))
def show_setting(kind: SettingKind, settings: Settings, _: Caller) -> Setting:
    return settings.show(kind)


@router.put("/v1/settings/{kind}", responses=PROBLEMS(401, 403, 409, 422))
def set_setting(
    kind: SettingKind, body: SettingBody, settings: Settings, caller: Caller
) -> SettingChange:
    """A new version (admins); the same content as the effective document changes nothing."""
    return settings.set(kind, body.document, body.reason, caller)


@router.get("/v1/settings/{kind}/versions", responses=PROBLEMS(401, 422))
def list_setting_versions(
    kind: SettingKind,
    settings: Settings,
    _: Caller,
    limit: Annotated[int, Query(ge=1, le=1000)] = 100,
    cursor: Cursor | None = None,
) -> Page[SettingVersion]:
    return settings.history(kind, PageRequest(limit=limit, cursor=cursor))


@router.get("/v1/settings/{kind}/diff", responses=PROBLEMS(401, 404, 422))
def diff_setting(
    kind: SettingKind,
    settings: Settings,
    _: Caller,
    from_version: Annotated[int, Query(ge=1)],
    to_version: Annotated[int, Query(ge=1)],
) -> SettingDiff:
    return settings.diff(kind, from_version, to_version)
