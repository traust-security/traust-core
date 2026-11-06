from __future__ import annotations

from typing import Annotated

from fastapi import Depends

from traust_core.v1.context import Context
from traust_core.v1.errors import ConfigError
from traust_core.v1.providers.model_catalog import ModelCatalog
from traust_core.v1.rest.common.deps import context


def models(ctx: Annotated[Context, Depends(context)]) -> ModelCatalog:
    """The deployment's model registry; a deployment without one cannot answer routing."""
    if ctx.model_catalog is None:
        raise ConfigError("no model registry (Context.register_model_catalog)")
    return ctx.model_catalog


Models = Annotated[ModelCatalog, Depends(models)]
