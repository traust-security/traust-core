import json

import pytest

from tests.v1.observation_support import HOSTS, NOW
from traust_core.v1.models.values import HttpsRepoUrl
from traust_core.v1.providers.clock import FixedClock
from traust_core.v1.providers.forge import CommandSourceProvider
from traust_core.v1.providers.process import ProcessResult
from traust_core.v1.providers.sources import SourceError


class Replay:
    def __init__(self, payload, returncode=0, stderr=b""):
        self.payload, self.returncode, self.stderr = payload, returncode, stderr
        self.calls = []

    def run(self, argv, **kwargs):
        self.calls.append(tuple(argv))
        return ProcessResult(tuple(argv), self.returncode, self.payload, self.stderr, 0)


def source(payload, **kwargs):
    replay = Replay(payload, **kwargs)
    return CommandSourceProvider(replay, FixedClock(NOW), HOSTS), replay


@pytest.mark.parametrize(
    "host,phase,payload",
    [
        ("github.com", "info", b"{bad"),
        ("github.com", "info", b"[]"),
        ("github.com", "info", b'{"pushed_at": 123}'),
        ("github.com", "info", b'{"visibility": ["public"]}'),
        ("github.com", "compare", b"null"),
        ("github.com", "compare", b'{"ahead_by": "oops", "files": []}'),
        ("github.com", "compare", b'{"ahead_by": null, "files": []}'),
        ("github.com", "compare", b'{"ahead_by": true, "files": []}'),
        ("github.com", "compare", b'{"ahead_by": 1.5, "files": []}'),
        ("github.com", "compare", b'{"ahead_by": 1, "files": [{}]}'),
        ("github.com", "compare", b'{"files": [{"filename": "a.py", "changes": {}}]}'),
        ("gitlab.com", "info", b"[]"),
        ("gitlab.com", "info", b'{"forked_from_project": ["invalid"]}'),
        ("gitlab.com", "compare", b'{"diffs": [null]}'),
        ("gitlab.com", "compare", b'{"diffs": [{"diff": 123}]}'),
    ],
)
def test_malformed_response_is_a_typed_source_error(host, phase, payload):
    provider, _ = source(payload)
    repo = HttpsRepoUrl(host, "o/r")
    with pytest.raises(SourceError) as error:
        if phase == "info":
            provider.info(repo)
        else:
            provider.compare(repo, "abcdef1", "main")
    assert error.value.observation_status == "error"
    assert payload.decode() not in str(error.value)


@pytest.mark.parametrize(
    "stderr,status",
    [
        ("HTTP 401 Unauthorized", "no-credentials"),
        ("dial tcp failed", "unreachable"),
        ("HTTP 500", "error"),
    ],
)
def test_command_failure_classification(stderr, status):
    provider, _ = source(b"", returncode=1, stderr=stderr.encode())
    with pytest.raises(SourceError) as error:
        provider.info(HttpsRepoUrl("github.com", "o/r"))
    assert error.value.observation_status == status


def test_gitlab_subgroups_branch_escaping_and_diff_metrics():
    data = {
        "commits": [{}, {}],
        "diffs": [{"new_path": "a.py", "diff": "--- a\n+++ b\n@@ 1 @@\n-old\n+new"}],
    }
    provider, replay = source(json.dumps(data).encode())
    result = provider.compare(
        HttpsRepoUrl("gitlab.com", "o/sub/r"), "abcdef1", "release/x&secret=1"
    )
    assert replay.calls == [
        (
            "glab",
            "api",
            "--hostname",
            "gitlab.com",
            "projects/o%2Fsub%2Fr/repository/compare?from=abcdef1&to=release%2Fx%26secret%3D1",
        )
    ]
    assert result.data.ahead_by == 2 and result.data.files[0].changes == 2
    assert result.acquisition.acquired_at == NOW


@pytest.mark.parametrize(
    "data",
    [
        # A collapsed entry omits its diff content entirely.
        {"commits": [{"id": "a"}], "diffs": [{"new_path": "b.py", "collapsed": True}]},
        # Per-diff too_large: same omission, different flag.
        {"commits": [{"id": "a"}], "diffs": [{"new_path": "b.py", "too_large": True}]},
        # Response-level too_large can accompany partial diffs.
        {
            "commits": [{"id": "a"}],
            "too_large": True,
            "diffs": [{"new_path": "a.py", "diff": "+x"}],
        },
    ],
    ids=["collapsed", "per-diff-too-large", "response-too-large"],
)
def test_gitlab_omitted_diffs_mark_the_comparison_incomplete(data):
    provider, _ = source(json.dumps(data).encode())
    result = provider.compare(HttpsRepoUrl("gitlab.com", "o/r"), "abcdef1", "main")
    assert result.data.truncated is True


@pytest.mark.parametrize("sha", ["bad", "-ref", "a" * 40 + "?x=y"])
def test_invalid_baseline_executes_nothing(sha):
    provider, replay = source(b"{}")
    with pytest.raises(SourceError):
        provider.compare(HttpsRepoUrl("github.com", "o/r"), sha, "HEAD")
    assert replay.calls == []


def test_undeterminable_quota_remains_unknown():
    provider, _ = source(b"bad")
    assert provider.quota(HttpsRepoUrl("github.com", "o/r")).data.remaining is None


def test_github_commands_explicitly_select_the_validated_host():
    provider, replay = source(b'{"ahead_by": 0, "files": []}')
    repo = HttpsRepoUrl("github.com", "o/r")
    provider.info(repo)
    provider.compare(repo, "abcdef1", "HEAD")
    provider.quota(repo)
    assert len(replay.calls) == 3
    for argv in replay.calls:
        assert argv[argv.index("--hostname") + 1] == repo.host


def test_a_github_commit_is_its_files_and_patches():
    payload = {"files": [{"filename": "a.py", "patch": "@@ -1 +1 @@\n-x\n+y"}, {"filename": "bin"}]}
    forge, replay = source(json.dumps(payload).encode())
    commit = forge.commit(HttpsRepoUrl.parse("https://github.com/org/lib", HOSTS), "abc1234").data
    assert replay.calls == [
        ("gh", "api", "repos/org/lib/commits/abc1234", "--hostname", "github.com")
    ]
    assert [(f.filename, f.patch) for f in commit.files] == [
        ("a.py", "@@ -1 +1 @@\n-x\n+y"),
        ("bin", ""),
    ]


def test_a_gitlab_commit_reads_its_diff():
    forge, replay = source(json.dumps([{"new_path": "src/a.c", "diff": "+int f(void)"}]).encode())
    repo = HttpsRepoUrl.parse("https://gitlab.com/group/sub/lib", HOSTS)
    commit = forge.commit(repo, "abc1234").data
    assert replay.calls[0][-1] == "projects/group%2Fsub%2Flib/repository/commits/abc1234/diff"
    assert [f.filename for f in commit.files] == ["src/a.c"]


@pytest.mark.parametrize(
    ("host", "payload", "sha"),
    [
        ("github.com", b"[]", "abc1234"),
        ("gitlab.com", b"{}", "abc1234"),
        ("github.com", b"{}", "HEAD;rm"),
    ],
)
def test_a_bad_commit_answer_or_sha_is_a_source_error(host, payload, sha):
    forge, _ = source(payload)
    path = "org/lib" if host == "github.com" else "group/lib"
    with pytest.raises(SourceError):
        forge.commit(HttpsRepoUrl.parse(f"https://{host}/{path}", HOSTS), sha)
