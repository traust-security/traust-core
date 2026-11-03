from __future__ import annotations

import csv
import hashlib
import re
from collections.abc import Mapping, Sequence
from datetime import timedelta
from pathlib import Path
from urllib.parse import urlsplit

from pydantic import ValidationError as ModelValidationError

from traust_core.v1.errors import ServiceError, ValidationError
from traust_core.v1.models.inventory import ReleaseBump, release_bump, release_version
from traust_core.v1.models.release_inventory import (
    RELEASE_INVENTORY_FEED,
    InventoryRelease,
    ReleaseArtifactKind,
    ReleaseInventorySnapshot,
    ReleaseObservation,
)
from traust_core.v1.providers.base import Acquisition, Readiness, Result
from traust_core.v1.providers.clock import Clock
from traust_core.v1.providers.feeds import Previous
from traust_core.v1.providers.process import ProcessRunner

_VERSION = re.compile(r"(?<![\d.])(\d+)\.(\d+)(?:\.(\d+))?(?![\d.])")
_HEAD = re.compile(r"[0-9a-f]{40}|[0-9a-f]{64}")
_IMAGE_COLUMNS = ("Payload Image Key(s)", "Payload Image(s)")


def inventory_identity(path: str) -> tuple[str, str] | None:
    match = _VERSION.search(path)
    if match is None:
        return None
    version = ".".join((match[1], match[2], match[3] or "0"))
    return _VERSION.sub("{V}", path), version


def _https(value: str) -> str:
    parsed = urlsplit(value)
    if parsed.scheme != "https" or not parsed.hostname or parsed.username or parsed.password:
        raise ValidationError("release inventory requires an HTTPS URL without credentials")
    return value


def parse_release_snapshot(raw: bytes) -> ReleaseInventorySnapshot:
    try:
        return ReleaseInventorySnapshot.model_validate_json(raw)
    except ModelValidationError as error:
        raise ValidationError(
            "release inventory snapshot is malformed; refusing to reseed"
        ) from error


class ReleaseInventoryFeed:
    """Inventory images and watched dist-git heads, incrementally snapshotted by the feed owner."""

    name = RELEASE_INVENTORY_FEED
    filename = "release-inventory.json"
    max_age = timedelta(days=3)

    def __init__(
        self,
        inputs: Path,
        process: ProcessRunner,
        clock: Clock,
        *,
        watched: Sequence[str] = (),
        products: Mapping[str, str] | None = None,
    ) -> None:
        self._inputs, self._process, self._clock = inputs, process, clock
        self._watched, self._products = tuple(dict.fromkeys(watched)), dict(products or {})

    def check(self) -> Readiness:
        if not self._inputs.is_dir():
            return Readiness(ready=False, detail="release inventory inputs directory is missing")
        if self._watched and not self._process.allows("git"):
            return Readiness(ready=False, detail="dist-git discovery requires git")
        return Readiness(ready=True)

    def fetch(self, previous: Previous = lambda: None) -> Result[bytes]:
        raw = previous()
        old = ReleaseInventorySnapshot() if raw is None else parse_release_snapshot(raw)
        seen, observations = set(old.seen_images), list(old.observations)
        releases = {release.inventory: release for release in old.releases}
        versions, heads, skipped = dict(old.versions), dict(old.distgit_heads), {}
        if not self._inputs.is_dir():
            skipped["inventory"] = "release inventory inputs directory is missing"
        for path in sorted(self._inputs.rglob("*-payload-repos.csv")):
            if not path.is_file():
                continue
            inventory = path.relative_to(self._inputs).as_posix()
            identity = inventory_identity(inventory)
            family, version = identity if identity else (None, None)
            change = (
                release_bump(version, old.versions.get(family)) if identity else ReleaseBump.UNKNOWN
            )
            repositories: set[str] = set()
            try:
                with path.open(newline="", encoding="utf-8") as stream:
                    rows = csv.DictReader(stream)
                    column = next((c for c in _IMAGE_COLUMNS if c in (rows.fieldnames or [])), None)
                    if column is None:
                        continue
                    for row in rows:
                        repository = (row.get("GitHub URL") or "").strip() or None
                        if repository is not None and not repository.startswith("https://"):
                            repository = None
                        if repository is not None:
                            repository = _https(repository)
                            repositories.add(repository)
                        for token in (row.get(column) or "").split(";"):
                            image = token.strip()
                            if not image or image.upper().startswith("N/A"):
                                continue
                            qualified = "@sha256:" in image or (
                                "/" in image and ":" in image.rsplit("/", 1)[-1]
                            )
                            key = image if qualified else f"{inventory}::{image}"
                            if key not in seen and raw is not None:
                                observations.append(
                                    ReleaseObservation(
                                        key=hashlib.sha256(f"image:{key}".encode()).hexdigest(),
                                        kind=ReleaseArtifactKind.CONTAINER,
                                        target=image,
                                        repository=repository,
                                        inventory=inventory,
                                        family=family,
                                        version=version,
                                        change=change,
                                    )
                                )
                            seen.add(key)
            except (OSError, UnicodeError, csv.Error) as error:
                raise ValidationError(
                    f"cannot read release inventory {inventory}: {error}"
                ) from error
            if identity:
                releases[inventory] = InventoryRelease(
                    inventory=inventory,
                    family=family,
                    version=version,
                    product=self._products.get(family),
                    repositories=tuple(sorted(repositories)),
                )
                held = versions.get(family)
                current = None if held is None else release_version(held)
                observed = release_version(version)
                if observed is not None and (current is None or observed > current):
                    versions[family] = version
        for repository in self._watched:
            try:
                _https(repository)
                result = self._process.run(
                    ["git", "ls-remote", "--", repository, "HEAD"],
                    env={"GIT_ALLOW_PROTOCOL": "https", "GIT_TERMINAL_PROMPT": "0"},
                    timeout_seconds=60,
                )
                head = next(
                    (
                        sha
                        for line in result.stdout.decode().splitlines()
                        if len(parts := line.split()) == 2
                        and parts[1] == "HEAD"
                        and _HEAD.fullmatch(sha := parts[0])
                    ),
                    None,
                )
                if head is None:
                    raise ValidationError("dist-git did not report a HEAD commit")
            except (ServiceError, ValidationError, UnicodeError) as error:
                skipped[repository] = str(error)
                continue
            if repository in heads and heads[repository] != head:
                identity = f"distgit:{repository}:{head}:{len(observations)}"
                observations.append(
                    ReleaseObservation(
                        key=hashlib.sha256(identity.encode()).hexdigest(),
                        kind=ReleaseArtifactKind.RPM,
                        target=repository,
                        repository=repository,
                        head=head,
                    )
                )
            heads[repository] = head
        snapshot = ReleaseInventorySnapshot(
            seen_images=tuple(sorted(seen)),
            distgit_heads=heads,
            versions=versions,
            releases=tuple(releases[key] for key in sorted(releases)),
            observations=tuple(observations),
            skipped=skipped,
        )
        return Result(
            snapshot.model_dump_json().encode(),
            Acquisition(
                provider=self.name, source=str(self._inputs), acquired_at=self._clock.now()
            ),
        )
