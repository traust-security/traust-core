from __future__ import annotations

from typing import Annotated

from fastapi import Depends

from traust_core.v1.rest.common.deps import CoreServices
from traust_core.v1.services.settings import SettingsService


def settings(services: CoreServices) -> SettingsService:
    return services.settings


Settings = Annotated[SettingsService, Depends(settings)]
