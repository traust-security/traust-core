"""3a · Assessments - what was examined. One repository per table."""

from __future__ import annotations

from contextlib import AbstractContextManager
from typing import TYPE_CHECKING, Protocol, Self

from traust_core.v1.repositories.traust.assessments.artifact import (
    ARTIFACT,
    ArtifactRepository,
    SqlArtifactRepository,
)
from traust_core.v1.repositories.traust.assessments.assessment import (
    ASSESSMENT,
    AssessmentRepository,
    SqlAssessmentRepository,
)
from traust_core.v1.repositories.traust.assessments.location import (
    LOCATION,
    LocationRepository,
    SqlLocationRepository,
)
from traust_core.v1.repositories.traust.assessments.occurrence import (
    OCCURRENCE,
    OccurrenceRepository,
    SqlOccurrenceRepository,
)
from traust_core.v1.repositories.unit_of_work import UnitOfWork

if TYPE_CHECKING:
    from traust_core.v1.repositories.contract import AssessmentReads

TABLES = (ASSESSMENT, ARTIFACT, OCCURRENCE, LOCATION)


class AssessmentsUnitOfWork(UnitOfWork, Protocol):
    def write(self) -> AbstractContextManager[Self]: ...

    assessments: AssessmentRepository
    assessment_reads: AssessmentReads
    artifacts: ArtifactRepository
    occurrences: OccurrenceRepository
    locations: LocationRepository


__all__ = [
    "TABLES",
    "ArtifactRepository",
    "AssessmentRepository",
    "AssessmentsUnitOfWork",
    "LocationRepository",
    "OccurrenceRepository",
    "SqlArtifactRepository",
    "SqlAssessmentRepository",
    "SqlLocationRepository",
    "SqlOccurrenceRepository",
]
