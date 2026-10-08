import pytest

from tests.v1.example.model import Task, TaskStatus
from tests.v1.example.router import TaskRouter
from traust_core.v1.models.operations import Refusal
from traust_core.v1.models.values import HttpsRepoUrl

REPO = HttpsRepoUrl("example.com", "org/repo")


@pytest.mark.parametrize(
    ("task", "refusals", "lane"),
    [
        (Task("t1", REPO, TaskStatus.DONE), [], None),
        (Task("t1", REPO, attempts=3), [], "manual-review"),
        (Task("t1", REPO), [Refusal(subject="t1", lane="retry", reason="x")], None),
        (Task("t1", REPO), [Refusal(subject="other", lane="retry", reason="x")], "retry"),
        (Task("t1", REPO), [], "retry"),
    ],
)
def test_route(task: Task, refusals: list[Refusal], lane: str | None) -> None:
    assert TaskRouter().route(task, [], refusals).lane == lane
