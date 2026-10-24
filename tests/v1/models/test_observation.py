from __future__ import annotations

import pytest

from traust_core.v1.models.observation import SENSITIVE_RX, is_deps_manifest, is_first_party


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
