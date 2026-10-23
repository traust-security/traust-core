from __future__ import annotations

from enum import StrEnum
from uuid import UUID

from pydantic import Field

from traust_core.v1.models.base import Model
from traust_core.v1.models.common import CodeSpan, RepoPath


class CodeFactKind(StrEnum):
    SYMBOL = "symbol"
    ROUTE_GUARD = "route-guard"
    CONFIG = "config"
    SANITIZER = "sanitizer"
    FORK_LAG = "fork-lag"
    TAINT_FLOW = "taint-flow"
    CRYPTO = "crypto"
    BINARY = "binary"
    LANGUAGES = "languages"
    IAC_PATH = "iac-path"
    PRIVILEGE = "privilege"


# One detail model per enumerator; fields land with the enumerator's slice.
class SymbolFact(Model):
    name: str
    location: CodeSpan
    kind: str | None
    language: str | None


class RouteGuardFact(Model): ...


class ConfigFact(Model): ...


class SanitizerFact(Model): ...


class ForkLagFact(Model): ...


class TaintFlowFact(Model): ...


class CryptoFact(Model): ...


class BinaryFact(Model): ...


class LanguageCount(Model):
    name: str
    files: int | None
    code: int
    comments: int | None
    blanks: int | None


class LanguageStats(Model):
    languages: tuple[LanguageCount, ...]


class IacPathFact(Model): ...


class PrivilegeFact(Model): ...


CodeFactDetail = (
    SymbolFact
    | RouteGuardFact
    | ConfigFact
    | SanitizerFact
    | ForkLagFact
    | TaintFlowFact
    | CryptoFact
    | BinaryFact
    | LanguageStats
    | IacPathFact
    | PrivilegeFact
)


class SymbolQuery(Model):
    name: str | None = Field(default=None, min_length=1)
    path: RepoPath | None = None
    limit: int = Field(default=100, gt=0, le=1000)


class CodeFact(Model):
    repository_ref_id: UUID
    kind: CodeFactKind
    location: CodeSpan | None = None
    detail: CodeFactDetail


class CollectResult(Model):
    repository_ref_id: UUID
    assessment_id: UUID
    artifact_id: UUID
    facts: tuple[CodeFact, ...]


class CodeFactCursor(Model):
    artifact_id: UUID
    kinds: tuple[CodeFactKind, ...]
    offset: int = Field(ge=0, strict=True)
