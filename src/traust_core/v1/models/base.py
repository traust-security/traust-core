from __future__ import annotations

from uuid import UUID

import pydantic


class Model(pydantic.BaseModel):
    model_config = pydantic.ConfigDict(frozen=True, extra="forbid")


class Dto(pydantic.BaseModel):
    model_config = pydantic.ConfigDict(frozen=True, extra="ignore")


class Entity(Model):
    id: UUID


def new_id() -> UUID:
    raise NotImplementedError("stub: entity identity is a UUIDv7 minted by the owning service")
