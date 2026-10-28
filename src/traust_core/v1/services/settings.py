from __future__ import annotations

import difflib
import json
import logging
from collections.abc import Mapping
from typing import Any, TypeVar

from traust_core.v1.errors import ForbiddenError, NotFoundError, SettingNotSet, ValidationError
from traust_core.v1.models.artifacts import ArtifactDocument
from traust_core.v1.models.assessment import Artifact
from traust_core.v1.models.common import Cursor, Page, PageRequest, Provenance
from traust_core.v1.models.identity import Principal, Role
from traust_core.v1.models.integrity import sha256_hex
from traust_core.v1.models.operations import ConfigDigest
from traust_core.v1.models.settings import (
    REVISION,
    SETTING_ARTIFACTS,
    SETTING_CHECKS,
    Setting,
    SettingChange,
    SettingDiff,
    SettingSource,
    SettingSummary,
    SettingVersion,
    summary,
    without_revision,
)
from traust_core.v1.models.vocabulary import SettingKind
from traust_core.v1.providers.clock import Clock
from traust_core.v1.services.artifact_publishing import ArtifactPublisher, PublishResult

log = logging.getLogger(__name__)
A = TypeVar("A", bound=ArtifactDocument)
# Settings change by hand: a kind's whole history fits one bounded read.
HISTORY_LIMIT = 1000


class SettingsService:
    """Tier 2 settings over the scope-ref artifacts: a kind's newest stored document is in
    force, else its shipped default (version 1); a kind with neither is not set."""

    def __init__(
        self,
        publisher: ArtifactPublisher,
        clock: Clock,
        defaults: Mapping[SettingKind, Mapping[str, Any]] | None = None,
    ) -> None:
        self._publisher = publisher
        self._clock = clock
        self._defaults = {
            kind: SETTING_ARTIFACTS[kind].from_document(without_revision(doc))
            for kind, doc in (defaults or {}).items()
        }
        self._effective: dict[SettingKind, Setting | None] = {}

    def list(self) -> list[SettingSummary]:
        """Every kind: default, changed or not set, and the version in force."""
        return [self._summary(kind) for kind in SettingKind]

    def show(self, kind: SettingKind) -> Setting:
        """The effective document; SettingNotSet for a kind with no default nobody has set."""
        found = self._current(kind)
        if found is None:
            raise SettingNotSet(
                f"{kind} is not set and has no shipped default: "
                f"`traust settings set {kind} <file> --reason <why>`"
            )
        return found

    def document(self, artifact: type[A]) -> A:
        return artifact.from_document(self.show(SettingKind(artifact.schema)).document)

    def find_document(self, artifact: type[A]) -> A | None:
        """The effective document, None when the kind is not set."""
        found = self._current(SettingKind(artifact.schema))
        return None if found is None else artifact.from_document(found.document)

    def set(
        self, kind: SettingKind, document: Mapping[str, Any], reason: str, principal: Principal
    ) -> SettingChange:
        """A new version of `kind` (an admin's); the same content as the effective one is a
        no-op. Any `revision` in `document` is replaced by the caller and the clock."""
        _require_admin(principal, kind)
        return self._write(kind, document, principal.ref, _reason(reason))[0]

    def reset(self, kind: SettingKind, reason: str, principal: Principal) -> SettingChange:
        """Back to the shipped default, as a new version so the history shows it."""
        _require_admin(principal, kind)
        if (default := self._defaults.get(kind)) is None:
            raise ValidationError(f"{kind} has no shipped default to reset to; set it instead")
        return self._write(kind, json.loads(default.payload), principal.ref, _reason(reason))[0]

    def record(self, doc: ArtifactDocument, provenance: Provenance, reason: str) -> PublishResult:
        """A domain door's write (a recording run), checked like any set and attributed to the
        run; recording what is already stored writes nothing."""
        change, published = self._write(
            SettingKind(doc.schema),
            json.loads(doc.payload),
            f"run:{provenance.run_id}",
            reason,
            store=True,
        )
        if published is not None:
            return published
        assert change.version.artifact_id is not None
        return PublishResult(artifact=doc.name, written=(), artifact_id=change.version.artifact_id)

    def superseded(self, doc: ArtifactDocument) -> bool:
        """Whether `doc` is the content of an older stored version, not the one in force."""
        artifact = SETTING_ARTIFACTS[SettingKind(doc.schema)]
        content = without_revision(json.loads(doc.payload))
        rows = self._publisher.history(artifact, HISTORY_LIMIT)
        return any(without_revision(self._stored(artifact, r)) == content for r in rows[1:])

    def history(self, kind: SettingKind, page: PageRequest) -> Page[SettingVersion]:
        """Versions newest first, the shipped default last; the cursor is the last version."""
        if page.limit <= 0:
            raise ValidationError("page limit must be positive")
        latest = self._latest_version(kind)
        if page.cursor is None:
            start = latest
        elif page.cursor.isdigit() and 1 <= int(page.cursor) <= latest:
            start = int(page.cursor) - 1
        else:
            raise ValidationError(f"{kind} history: cursor {page.cursor!r} is not a version")
        versions = list(range(start, max(start - page.limit, 0), -1))
        items = [self._version_at(kind, v, latest)[0] for v in versions]
        more = bool(versions) and versions[-1] > 1
        return Page(items=tuple(items), next=Cursor(str(versions[-1])) if more else None)

    def diff(self, kind: SettingKind, from_version: int, to_version: int) -> SettingDiff:
        (_, old), (_, new) = (
            self._version_at(kind, from_version),
            self._version_at(kind, to_version),
        )
        return SettingDiff(
            kind=kind,
            from_version=from_version,
            to_version=to_version,
            diff=_diff(old, new, f"{kind} v{from_version}", f"{kind} v{to_version}"),
        )

    def digests(self) -> tuple[ConfigDigest, ...]:
        """The documents in force, for a run manifest's config."""
        return tuple(
            ConfigDigest(
                name=kind, digest=found.version.digest, artifact_id=found.version.artifact_id
            )
            for kind in SettingKind
            if (found := self._current(kind)) is not None
        )

    def _write(
        self,
        kind: SettingKind,
        document: Mapping[str, Any],
        set_by: str,
        reason: str,
        *,
        store: bool = False,
    ) -> tuple[SettingChange, PublishResult | None]:
        artifact = SETTING_ARTIFACTS[kind]
        content = without_revision(document)
        checked = artifact.from_document(content)
        if (check := SETTING_CHECKS.get(kind)) is not None:
            check(checked)
        self._effective.pop(kind, None)
        current = self._current(kind)
        prior = None if current is None else current.version.artifact_id
        if current is not None and current.document == content and (prior or not store):
            return SettingChange(version=current.version, changed=False), None
        revision = {"set_by": set_by, "reason": reason, "set_at": self._clock.now().isoformat()}
        published = self._publisher.publish_successor(
            artifact.from_document({**content, REVISION: revision}), prior
        )
        self._effective.pop(kind, None)
        now = self.show(kind)
        log.info("setting %s is now v%d (%s)", kind, now.version.version, published.artifact_id)
        before = {} if current is None else current.document
        label = "(not set)" if current is None else f"v{current.version.version}"
        change = SettingChange(
            version=now.version,
            changed=True,
            diff=_diff(before, content, f"{kind} {label}", f"{kind} v{now.version.version}"),
        )
        return change, published

    def _current(self, kind: SettingKind) -> Setting | None:
        if kind not in self._effective:
            found = None
            if latest := self._latest_version(kind):
                version, document = self._version_at(kind, latest, latest)
                found = Setting(version=version, document=document)
            self._effective[kind] = found
        return self._effective[kind]

    def _summary(self, kind: SettingKind) -> SettingSummary:
        found = self._current(kind)
        if found is None:
            return SettingSummary(kind=kind, source=SettingSource.NOT_SET)
        source = SettingSource.DEFAULT if found.version.default else SettingSource.CHANGED
        return SettingSummary(
            kind=kind, source=source, version=found.version, summary=summary(found.document)
        )

    def _offset(self, kind: SettingKind) -> int:
        return 1 if kind in self._defaults else 0

    def _latest_version(self, kind: SettingKind) -> int:
        return self._publisher.count_imported(SETTING_ARTIFACTS[kind]) + self._offset(kind)

    def _version_at(
        self, kind: SettingKind, version: int, latest: int | None = None
    ) -> tuple[SettingVersion, dict[str, Any]]:
        offset = self._offset(kind)
        latest = self._latest_version(kind) if latest is None else latest
        if not 1 <= version <= latest:
            raise NotFoundError(f"{kind} has no version {version} (latest is v{latest})")
        if version == 1 and offset:
            default = self._defaults[kind]
            meta = SettingVersion(
                kind=kind, version=1, default=True, digest=sha256_hex(default.payload)
            )
            return meta, json.loads(default.payload)
        artifact = SETTING_ARTIFACTS[kind]
        (row,) = self._publisher.history(artifact, 1, offset=latest - version)
        document = self._stored(artifact, row)
        revision = document.get(REVISION) or {}
        assert row.id is not None
        meta = SettingVersion(
            kind=kind,
            version=version,
            default=False,
            digest=row.digest,
            artifact_id=row.id,
            set_by=revision.get("set_by"),
            reason=revision.get("reason"),
            set_at=row.created_at,
        )
        return meta, without_revision(document)

    def _stored(self, artifact: type[ArtifactDocument], row: Artifact) -> dict[str, Any]:
        assert row.id is not None
        return json.loads(self._publisher.read(row.id, artifact).payload)  # type: ignore[no-any-return]


def _require_admin(principal: Principal, kind: SettingKind) -> None:
    if not principal.has_role(Role.ADMIN):
        raise ForbiddenError(f"{principal.ref}: changing {kind} is an admin's")


def _reason(reason: str) -> str:
    if not (reason := reason.strip()):
        raise ValidationError("a settings change needs a reason")
    return reason


def _diff(old: Mapping[str, Any], new: Mapping[str, Any], before: str, after: str) -> str:
    def lines(doc: Mapping[str, Any]) -> list[str]:
        return (json.dumps(doc, indent=2, sort_keys=True) + "\n").splitlines(keepends=True)

    return "".join(difflib.unified_diff(lines(old), lines(new), before, after))
