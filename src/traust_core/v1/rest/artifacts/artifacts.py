from __future__ import annotations

from uuid import UUID

from fastapi import APIRouter, Response

from traust_core.v1.models.assessment import Artifact
from traust_core.v1.rest.artifacts.service import Artifacts
from traust_core.v1.rest.common.deps import Caller
from traust_core.v1.rest.common.problems import PROBLEMS

router = APIRouter()


@router.get(
    "/v1/artifacts/{artifact_id}",
    responses=PROBLEMS(401, 404),
)
def get_artifact(artifact_id: UUID, artifacts: Artifacts, _: Caller) -> Artifact:
    return artifacts.metadata(artifact_id)


@router.get(
    "/v1/artifacts/{artifact_id}/content",
    response_class=Response,
    responses={
        **PROBLEMS(401, 404, 409),
        200: {
            "content": {
                "application/octet-stream": {"schema": {"type": "string", "format": "binary"}}
            }
        },
    },
)
def get_artifact_content(artifact_id: UUID, artifacts: Artifacts, _: Caller) -> Response:
    return Response(content=artifacts.payload(artifact_id), media_type="application/octet-stream")
