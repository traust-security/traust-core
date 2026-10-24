import pytest

from traust_core.v1.providers.base import Readiness, on_path


@pytest.mark.parametrize(
    ("installed", "binaries", "missing", "expected"),
    [
        ({"gh", "glab"}, ("gh", "glab"), "", Readiness(ready=True)),
        ({"gh"}, ("gh", "glab"), "", Readiness(ready=False, detail="glab")),
        (set(), ("gh", "glab"), "", Readiness(ready=False, detail="gh, glab")),
        ({"syft"}, ("syft",), " not on PATH", Readiness(ready=True)),
        (set(), ("syft",), " not on PATH", Readiness(ready=False, detail="syft not on PATH")),
        (
            set(),
            ("oc",),
            " not found in PATH",
            Readiness(ready=False, detail="oc not found in PATH"),
        ),
    ],
    ids=["all there", "one missing", "both missing", "named ready", "named", "named, other words"],
)
def test_ready_only_when_every_binary_is_on_path(
    monkeypatch: pytest.MonkeyPatch, installed, binaries, missing, expected
) -> None:
    monkeypatch.setattr("shutil.which", lambda b: f"/usr/bin/{b}" if b in installed else None)
    assert on_path(*binaries, missing=missing) == expected
