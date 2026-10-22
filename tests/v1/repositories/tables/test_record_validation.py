import pytest
import sqlalchemy as sa
from pydantic import ValidationError as ModelValidationError

from tests.v1.repositories.tables.conftest import Seed, repository_for
from traust_core.v1.models.vocabulary import Severity


@pytest.mark.parametrize("table", ["occurrence", "decision"])
def test_copied_invalid_severity_is_rejected_before_insert(seed: Seed, table: str) -> None:
    record = seed.new(table).model_copy(update={"severity": "urgent"})
    repository = repository_for(seed.uow, table)

    with pytest.raises(ModelValidationError, match="severity"):
        repository.add(record)

    assert (
        seed.uow.connection.execute(
            sa.select(sa.func.count()).select_from(repository.table)
        ).scalar_one()
        == 0
    )


@pytest.mark.parametrize("table", ["occurrence", "decision"])
def test_copied_valid_severity_is_validated_and_persisted(seed: Seed, table: str) -> None:
    record = seed.new(table).model_copy(update={"severity": "informational"})
    repository = repository_for(seed.uow, table)
    saved = repository.add(record)
    seed.uow.commit()

    assert saved.severity is Severity.INFORMATIONAL
    assert repository.get(saved.id).severity is Severity.INFORMATIONAL


def test_copied_decision_can_leave_severity_unanswered(seed: Seed) -> None:
    record = seed.new_decision(severity="high").model_copy(update={"severity": None})
    saved = seed.uow.decisions.add(record)
    seed.uow.commit()

    assert saved.severity is None
    assert seed.uow.decisions.get(saved.id).severity is None


def test_copied_invalid_update_does_not_change_the_saved_record(seed: Seed) -> None:
    finding = seed.finding(title="Original title")
    seed.uow.commit()

    with pytest.raises(ModelValidationError, match="title"):
        seed.uow.findings.update(finding.model_copy(update={"title": 7}))

    assert seed.uow.findings.get(finding.id).title == "Original title"
