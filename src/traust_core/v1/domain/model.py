from __future__ import annotations

import pydantic


class Model(pydantic.BaseModel):
    model_config = pydantic.ConfigDict(frozen=True, extra="forbid")


class Dto(pydantic.BaseModel):
    model_config = pydantic.ConfigDict(frozen=True, extra="ignore")
