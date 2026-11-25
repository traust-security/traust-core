from __future__ import annotations

from uuid import UUID

from fastapi import APIRouter, Response

from traust_core.v1.models.artifacts import CONTENT_MEDIA_TYPES, ArtifactView
from traust_core.v1.rest.artifacts.service import Artifacts
from traust_core.v1.rest.common.deps import Caller
from traust_core.v1.rest.common.problems import PROBLEMS

router = APIRouter()

_CONTENT_HEADERS = {
    "Content-Length": {
        "description": "The artifact's size in bytes.",
        "schema": {"type": "integer"},
    },
    "ETag": {
        "description": "The artifact's digest (sha256, hex).",
        "schema": {"type": "string"},
    },
    "Traust-Artifact-Kind": {
        "description": "The artifact's kind.",
        "schema": {"$ref": "#/components/schemas/ArtifactKind"},
    },
}


@router.get(
    "/v1/artifacts/{artifact_id}",
    responses=PROBLEMS(401, 404),
)
def get_artifact(artifact_id: UUID, artifacts: Artifacts, _: Caller) -> ArtifactView:
    return artifacts.describe(artifact_id)


@router.get(
    "/v1/artifacts/{artifact_id}/content",
    response_class=Response,
    responses={
        **PROBLEMS(401, 404, 409),
        200: {
            "description": "The artifact's exact retained bytes.",
            "content": {
                media: {"schema": {"type": "string", "format": "binary"}}
                for media in CONTENT_MEDIA_TYPES
            },
            "headers": _CONTENT_HEADERS,
        },
    },
)
def get_artifact_content(artifact_id: UUID, artifacts: Artifacts, _: Caller) -> Response:
    view, payload = artifacts.content(artifact_id)
    return Response(
        content=payload,
        media_type=view.media_type,
        headers={"ETag": view.digest, "Traust-Artifact-Kind": view.kind.value},
    )
