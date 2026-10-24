from __future__ import annotations

from collections.abc import Sequence
from typing import Protocol
from uuid import UUID

from traust_core.v1.models.attestation import Comment
from traust_core.v1.models.base import Dto
from traust_core.v1.models.remediation import ExternalRef
from traust_core.v1.providers.base import Readiness, Result


class TrackerIssue(Dto): ...


class ProductDocument(Dto):
    """One official documentation guide page as fetched (html)."""

    product_slug: str
    version: str
    guide: str
    url: str
    html: str


class RegisterFile(Dto):
    """One file of an ADR register, read at the register's pin."""

    path: str
    text: str
    url: str


class CommentSource(Protocol):
    name: str

    def check(self) -> Readiness: ...

    def comments(self, ref: ExternalRef) -> Result[list[Comment]]: ...


class TrackerProvider(Protocol):
    name: str

    def check(self) -> Readiness: ...

    def issues(self, ref: ExternalRef) -> Result[list[TrackerIssue]]: ...

    def link(self, issue: ExternalRef, target: ExternalRef) -> None: ...


class DocSource(Protocol):
    name: str

    def check(self) -> Readiness: ...

    def fetch(self, product_id: UUID) -> Result[list[ProductDocument]]: ...


class AdrSource(Protocol):
    """Reads ADR register files at a pinned commit; NEED(engine): the forge implementation."""

    name: str

    def check(self) -> Readiness: ...

    def files(self, repo: str, pin: str, paths: Sequence[str]) -> Result[list[RegisterFile]]: ...
