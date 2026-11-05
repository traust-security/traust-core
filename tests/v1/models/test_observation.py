from __future__ import annotations

from datetime import UTC, datetime
from uuid import UUID

import pytest

from traust_core.v1.errors import DocumentError
from traust_core.v1.models.inventory import Liveness, RepoLiveness
from traust_core.v1.models.observation import SENSITIVE_RX, is_deps_manifest, is_first_party
from traust_core.v1.models.vocabulary import LivenessStatus


@pytest.mark.parametrize(
    ("path", "first_party", "sensitive", "deps"),
    [
        ("pkg/server.go", True, False, False),
        ("vendor/lib/x.go", False, False, False),
        ("node_modules/a/b.js", False, False, False),
        ("third_party/x/y.c", False, False, False),
        ("dist/app.js", False, False, False),
        ("api/zz_generated.deepcopy.go", False, False, False),
        ("pkg/api.pb.go", False, False, False),
        ("docs/README.md", False, False, False),
        ("CHANGES.MD", False, False, False),
        ("internal/auth/login.go", True, True, False),
        ("pkg/tls_config.go", True, True, False),
        ("go.mod", True, False, True),
        ("ui/package-lock.json", True, False, True),
        ("requirements-dev.txt", True, False, True),
        ("requirements.in", True, False, False),
    ],
)
def test_router_and_diff_scope_classify_a_path_the_same_way(
    path: str, first_party: bool, sensitive: bool, deps: bool
) -> None:
    assert is_first_party(path) is first_party
    assert bool(SENSITIVE_RX.search(path)) is sensitive
    assert is_deps_manifest(path) is deps


@pytest.mark.parametrize("status", list(LivenessStatus))
def test_liveness_reference_round_trip_retains_identity_status_and_transition_time(
    status: LivenessStatus,
) -> None:
    repository_id = UUID("10000000-0000-4000-8000-000000000001")
    first = datetime(2026, 10, 1, tzinfo=UTC)
    latest = datetime(2026, 11, 1, tzinfo=UTC)
    row = Liveness(
        repository_id=repository_id,
        url="https://github.com/example/old",
        status=status,
        status_since=first,
        observed_at=latest,
        canonical_url="https://github.com/example/new" if status == LivenessStatus.MOVED else None,
        pushed_at="2026-09-01T00:00:00Z",
        dormant=True,
    )
    reference = RepoLiveness(
        generated="2026-10-01T00:00:00Z", repositories={repository_id: row}
    ).to_artifact()
    stored = RepoLiveness.of(reference).repositories[repository_id]
    assert (stored.repository_id, stored.url, stored.status) == (
        repository_id,
        row.url,
        status,
    )
    assert (stored.status_since, stored.observed_at) == (first, latest)
    assert stored.canonical_url == row.canonical_url
    assert stored.pushed_at == row.pushed_at
    assert stored.dormant is None


def test_an_unqueried_row_cannot_be_published_as_an_observation() -> None:
    repository_id = UUID("10000000-0000-4000-8000-000000000001")
    row = Liveness(repository_id=repository_id, url="https://github.com/example/repo")
    with pytest.raises(DocumentError):
        RepoLiveness(
            generated="2026-10-01T00:00:00Z", repositories={repository_id: row}
        ).to_artifact()
