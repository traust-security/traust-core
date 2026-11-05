from __future__ import annotations

import fcntl
import os
import tempfile
from collections.abc import Callable, Mapping, Sequence
from pathlib import Path

import pydantic

from traust_core.v1.errors import ConfigError, ValidationError
from traust_core.v1.models.inventory_reference import InventoryReference, RepositoryDeclaration
from traust_core.v1.models.values import HttpsRepoUrl


class InventoryReferenceFile:
    """The deployment's declared inventory handoff, outside domain tables."""

    def __init__(
        self,
        path: Path,
        hosts: Mapping[str, str],
        load: Callable[[str], list[object]],
        dump: Callable[[object], str],
    ) -> None:
        self.path = path
        self._hosts = hosts
        self._load, self._dump = load, dump

    def read(self) -> InventoryReference:
        try:
            text = self.path.read_text(encoding="utf-8")
        except FileNotFoundError:
            return InventoryReference()
        except (OSError, UnicodeError) as e:
            raise ConfigError(f"cannot read inventory reference {self.path}: {e}") from e
        try:
            documents = self._load(text)
            if len(documents) != 1:
                raise ValidationError("expected one inventory reference document")
            reference = InventoryReference.model_validate(documents[0])
        except (ValidationError, pydantic.ValidationError) as e:
            raise ValidationError(f"invalid inventory reference {self.path}: {e}") from e
        return self._canonical(reference)

    def _canonical(self, reference: InventoryReference) -> InventoryReference:
        if reference.version != 1:
            raise ValidationError(f"unsupported inventory reference version {reference.version}")
        rows = {}
        for row in reference.repositories:
            url = str(HttpsRepoUrl.parse(row.repo_url, self._hosts))
            if url in rows:
                raise ValidationError(f"duplicate inventory reference repository {url}")
            rows[url] = row.model_copy(update={"repo_url": url})
        return reference.model_copy(update={"repositories": tuple(rows.values())})

    def merge(
        self, declarations: Sequence[RepositoryDeclaration], *, append_versions: bool = False
    ) -> InventoryReference:
        given = self._canonical(InventoryReference(repositories=tuple(declarations)))
        try:
            self.path.parent.mkdir(parents=True, exist_ok=True)
            with self.path.with_suffix(self.path.suffix + ".lock").open("a") as lock:
                fcntl.flock(lock, fcntl.LOCK_EX)
                current = self.read()
                rows = {r.repo_url: r for r in current.repositories}
                for declaration in given.repositories:
                    previous = rows.get(declaration.repo_url)
                    values = declaration.model_dump(exclude_unset=True)
                    if previous is not None and append_versions:
                        for field in ("payload_versions", "operator_versions"):
                            if field in values:
                                values[field] = tuple(
                                    dict.fromkeys(
                                        (*getattr(previous, field), *getattr(declaration, field))
                                    )
                                )
                    rows[declaration.repo_url] = (
                        declaration if previous is None else previous.model_copy(update=values)
                    )
                result = current.model_copy(
                    update={"repositories": tuple(rows[url] for url in sorted(rows))}
                )
                if result != current:
                    self._write(result)
                return result
        except OSError as e:
            raise ConfigError(f"cannot update inventory reference {self.path}: {e}") from e

    def _write(self, reference: InventoryReference) -> None:
        temporary: Path | None = None
        try:
            with tempfile.NamedTemporaryFile(
                mode="w", encoding="utf-8", dir=self.path.parent, delete=False
            ) as stream:
                temporary = Path(stream.name)
                stream.write(self._dump(reference.model_dump(mode="json")))
                stream.flush()
                os.fsync(stream.fileno())
            temporary.replace(self.path)
        finally:
            if temporary is not None:
                temporary.unlink(missing_ok=True)
