from __future__ import annotations

from typing import Annotated

from fastapi import Depends

from traust_core.v1.rest.common.deps import CoreServices
from traust_core.v1.services.artifact_publishing import ArtifactPublisher


def artifacts(services: CoreServices) -> ArtifactPublisher:
    return services.artifacts


Artifacts = Annotated[ArtifactPublisher, Depends(artifacts)]
