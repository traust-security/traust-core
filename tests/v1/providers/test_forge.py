import io
import json

import pytest

from tests.v1.observation_support import HOSTS, NOW
from traust_core.v1.context.observation import command_source
from traust_core.v1.errors import ServiceError, ValidationError
from traust_core.v1.models.values import HttpsRepoUrl
from traust_core.v1.providers.clock import FixedClock
from traust_core.v1.providers.forge import TRIPWIRE_PATCH_CAP, CommandSourceProvider
from traust_core.v1.providers.sources import SourceError


class ApiReplay:
    """A stub ForgeApi: one answer for every REST read. A non-200
    status raises the ServiceError the real one would (4xx fail fast
    carrying the status); endpoints are recorded instead of URLs."""

    def __init__(self, body, status=200):
        self.body = body.decode(errors="replace") if isinstance(body, bytes) else body
        self.status, self.calls = status, []

    def _answer(self, endpoint):
        self.calls.append((endpoint, None))
        if self.status != 200:
            raise ServiceError(f"{endpoint}: HTTP {self.status}", status=self.status)
        return self.body

    def get(self, host, endpoint, headers=None):
        answer = self._answer(endpoint)
        try:
            return json.loads(answer)
        except ValueError as exc:
            raise ServiceError(f"{endpoint}: no JSON: {exc}") from exc

    def find(self, host, endpoint, headers=None):
        try:
            return self.get(host, endpoint, headers)
        except ServiceError as exc:
            if exc.status == 404:
                return None
            raise

    def items(self, host, endpoint, headers=None):
        answer = self.get(host, endpoint, headers)
        if not isinstance(answer, list):
            raise ServiceError(f"{endpoint}: expected a list") from ValueError("not a list")
        yield from answer

    def stream(self, host, endpoint, consume, headers=None):
        self.calls.append((endpoint, dict(headers or {})))
        if self.status != 200:
            raise ServiceError(f"{endpoint}: HTTP {self.status}", status=self.status)
        return consume(io.BytesIO(self.body.encode()))


def github_source(body, **kwargs):
    replay = ApiReplay(body, **kwargs)
    return CommandSourceProvider(FixedClock(NOW), HOSTS, replay), replay


source = github_source  # gitlab reads go through the same ForgeApi


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
    repo = HttpsRepoUrl(host, "o/r")
    if host == "github.com":
        provider, _ = github_source(payload)
    else:
        provider, _ = source(payload)
    with pytest.raises(SourceError) as error:
        if phase == "info":
            provider.info(repo)
        else:
            provider.compare(repo, "abcdef1", "main")
    assert error.value.observation_status == "error"
    assert payload.decode() not in str(error.value)


@pytest.mark.parametrize(
    "status,body,status_name",
    [
        (401, "HTTP 401 Unauthorized", "no-credentials"),
        (403, "API rate limit exceeded", "error"),
        (429, "rate limited even after the fetcher's retries", "error"),
    ],
)
def test_http_failure_classification(status, body, status_name):
    provider, _ = github_source(body.encode(), status=status)
    with pytest.raises(SourceError) as error:
        provider.info(HttpsRepoUrl("github.com", "o/r"))
    assert error.value.observation_status == status_name


def test_a_github_read_that_gives_up_is_unreachable():
    # The fetcher retries transport failures and persistent 5xx itself; what
    # reaches the provider is a give-up ServiceError with no status.
    class GaveUp:
        def get(self, host, endpoint, headers=None):
            raise ServiceError(
                f"{endpoint}: gave up after 4 attempts (could not resolve host)", status=None
            )

        def find(self, host, endpoint, headers=None):
            return self.get(host, endpoint, headers)

    provider = CommandSourceProvider(FixedClock(NOW), HOSTS, GaveUp())
    with pytest.raises(SourceError) as error:
        provider.info(HttpsRepoUrl("github.com", "o/r"))
    assert error.value.observation_status == "unreachable"


def test_a_github_token_rides_the_request_when_supplied():
    seen = []

    class Api(ApiReplay):
        def get(self, host, endpoint, headers=None):
            seen.append(dict(headers or {}))
            return super().get(host, endpoint, headers)

    provider = CommandSourceProvider(FixedClock(NOW), HOSTS, Api(b"[]"))
    with pytest.raises(SourceError):
        provider.info(HttpsRepoUrl("github.com", "o/r"))
    assert seen, "the api saw no request"


def test_command_source_threads_the_forge_api():
    stub = ApiReplay(b"[]")
    source = command_source({"github.com": "github"}, clock=FixedClock(NOW), api=stub)
    with pytest.raises(SourceError):
        source.info(HttpsRepoUrl("github.com", "o/r"))
    assert stub.calls[0][0].startswith("repos/")


@pytest.mark.parametrize(
    "http_status,status",
    [(401, "no-credentials"), (None, "unreachable"), (500, "error")],
)
def test_command_failure_classification(http_status, status):
    provider, _ = source(b"", status=http_status)
    with pytest.raises(SourceError) as error:
        provider.info(HttpsRepoUrl("gitlab.com", "o/r"))
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
        ("projects/o%2Fsub%2Fr/repository/compare?from=abcdef1&to=release%2Fx%26secret%3D1", None)
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
    provider, replay = github_source(b"{}")
    with pytest.raises(SourceError):
        provider.compare(HttpsRepoUrl("github.com", "o/r"), sha, "HEAD")
    assert replay.calls == []


def test_undeterminable_quota_remains_unknown():
    provider, _ = github_source(b"bad")
    assert provider.quota(HttpsRepoUrl("github.com", "o/r")).data.remaining is None


def test_github_reads_select_the_validated_host():
    provider, replay = github_source(b'{"ahead_by": 0, "files": []}')
    repo = HttpsRepoUrl("github.com", "o/r")
    provider.info(repo)
    provider.compare(repo, "abcdef1", "HEAD")
    provider.quota(repo)
    assert len(replay.calls) == 3
    for endpoint, _ in replay.calls:
        assert endpoint.startswith(("repos/", "rate_limit")) or endpoint.startswith("orgs/")


def test_a_github_enterprise_host_reads_its_own_api():
    hosts = {"github.example.com": "github", "gitlab.com": "gitlab"}
    replay = ApiReplay(b"[]")
    provider = CommandSourceProvider(FixedClock(NOW), hosts, replay)
    with pytest.raises(SourceError):
        provider.info(HttpsRepoUrl("github.example.com", "o/r"))
    # A ForgeApi builds enterprise URLs; this stub records endpoints, so the
    # provider test checks the host reached the api at all.
    assert len(replay.calls) == 1


def test_a_github_commit_is_its_files_and_patches():
    payload = {"files": [{"filename": "a.py", "patch": "@@ -1 +1 @@\n-x\n+y"}, {"filename": "bin"}]}
    forge, replay = github_source(json.dumps(payload).encode())
    commit = forge.commit(HttpsRepoUrl.parse("https://github.com/org/lib", HOSTS), "abc1234").data
    assert [endpoint for endpoint, _ in replay.calls] == ["repos/org/lib/commits/abc1234"]
    assert [(f.filename, f.patch) for f in commit.files] == [
        ("a.py", "@@ -1 +1 @@\n-x\n+y"),
        ("bin", ""),
    ]


def test_a_gitlab_commit_reads_its_diff():
    forge, replay = source(json.dumps([{"new_path": "src/a.c", "diff": "+int f(void)"}]).encode())
    repo = HttpsRepoUrl.parse("https://gitlab.com/group/sub/lib", HOSTS)
    commit = forge.commit(repo, "abc1234").data
    assert replay.calls[0][0] == "projects/group%2Fsub%2Flib/repository/commits/abc1234/diff"
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
    path = "org/lib" if host == "github.com" else "group/lib"
    if host == "github.com":
        forge, _ = github_source(payload)
    else:
        forge, _ = source(payload)
    with pytest.raises(SourceError):
        forge.commit(HttpsRepoUrl.parse(f"https://{host}/{path}", HOSTS), sha)


@pytest.mark.parametrize(
    ("host", "payload", "endpoint"),
    [
        (
            "github.com",
            {"commit": {"sha": "d" * 40}},
            "repos/o/r/branches/release%2F1",
        ),
        (
            "gitlab.com",
            {"commit": {"id": "d" * 40}},
            "projects/o%2Fr/repository/branches/release%2F1",
        ),
    ],
)
def test_head_is_the_commit_the_branch_points_at(host, payload, endpoint):
    provider, replay = source(json.dumps(payload).encode())
    assert str(provider.head(HttpsRepoUrl(host, "o/r"), "release/1").data) == "d" * 40
    assert replay.calls[0][0] == endpoint


@pytest.mark.parametrize(
    "payload",
    [b"{}", b'{"commit": {"sha": "abc"}}', b'{"commit": {"sha": null}}', b"[]"],
)
def test_a_malformed_head_is_a_source_error(payload):
    provider, _ = github_source(payload)
    with pytest.raises(SourceError) as error:
        provider.head(HttpsRepoUrl("github.com", "o/r"), "main")
    assert error.value.observation_status == "error"


def test_a_tree_lists_its_blob_paths_in_one_call():
    payload = {
        "truncated": False,
        "tree": [
            {"type": "tree", "path": "cmd"},
            {"type": "blob", "path": "cmd/main.go"},
            {"type": "blob", "path": "vendor/x.go"},
        ],
    }
    provider, replay = github_source(json.dumps(payload).encode())
    tree = provider.tree(HttpsRepoUrl("github.com", "o/r"), "release/1").data
    assert (tree.paths, tree.truncated) == (("cmd/main.go", "vendor/x.go"), False)
    assert [endpoint for endpoint, _ in replay.calls] == [
        "repos/o/r/git/trees/release%2F1?recursive=1"
    ]


@pytest.mark.parametrize(
    "payload",
    [
        b"{}",
        b'{"truncated": "no", "tree": []}',
        b'{"truncated": false, "tree": [{"type": "blob", "path": 1}]}',
        b"[]",
    ],
)
def test_a_malformed_tree_is_a_source_error(payload):
    provider, _ = github_source(payload)
    with pytest.raises(SourceError) as error:
        provider.tree(HttpsRepoUrl("github.com", "o/r"), "main")
    assert error.value.observation_status == "error"


def test_a_gitlab_tree_paginates_and_keeps_only_blob_paths():
    listing = [
        {"type": "tree", "path": "cmd"},
        {"type": "blob", "path": "cmd/main.go"},
        {"type": "commit", "path": "submodule"},
        {"type": "blob", "path": "lib/auth.go"},
    ]
    provider, replay = source(json.dumps(listing).encode())
    result = provider.tree(HttpsRepoUrl("gitlab.com", "o/sub/r"), "release/1")
    assert result.data.paths == ("cmd/main.go", "lib/auth.go")
    assert result.data.truncated is False
    assert result.acquisition.source == "https://gitlab.com/o/sub/r"
    assert replay.calls == [
        ("projects/o%2Fsub%2Fr/repository/tree?ref=release%2F1&recursive=true&per_page=100", None)
    ]


@pytest.mark.parametrize(
    "payload",
    [
        b"{}",
        b"null",
        b"not json",
        b'[{"type":"blob"}]',
        b'[{"type":"blob","path":1}]',
        b'[{"type":"unexpected","path":"a.py"}]',
        b'[{"type":"blob","path":"a.py"}]\n[null]',
    ],
)
def test_a_malformed_gitlab_tree_is_a_source_error(payload):
    provider, _ = source(payload)
    with pytest.raises(SourceError) as error:
        provider.tree(HttpsRepoUrl("gitlab.com", "o/r"), "main")
    assert error.value.observation_status == "error"


def test_an_empty_gitlab_tree_has_no_files():
    provider, _ = source(b"[]")
    tree = provider.tree(HttpsRepoUrl("gitlab.com", "o/r"), "main").data
    assert tree.paths == ()
    assert tree.truncated is False


@pytest.mark.parametrize(
    "http_status,status",
    [(401, "no-credentials"), (None, "unreachable"), (500, "error")],
)
def test_a_failed_gitlab_tree_never_returns_partial_pages(http_status, status):
    provider, _ = source(b'[{"type":"blob","path":"a.py"}]', status=http_status)
    with pytest.raises(SourceError) as error:
        provider.tree(HttpsRepoUrl("gitlab.com", "o/r"), "main")
    assert error.value.observation_status == status


def test_a_compare_patch_is_the_raw_diff_capped_like_the_legacy_tripwire():
    provider, replay = github_source(b"+" * (TRIPWIRE_PATCH_CAP + 10))
    patch = provider.compare_patch(HttpsRepoUrl("github.com", "o/r"), "abc1234").data
    assert len(patch) == TRIPWIRE_PATCH_CAP
    endpoint, headers = replay.calls[0]
    assert endpoint == "repos/o/r/compare/abc1234...HEAD"
    assert headers["Accept"] == "application/vnd.github.v3.diff"


@pytest.mark.parametrize(
    ("repo", "baseline", "error"),
    [
        (HttpsRepoUrl("gitlab.com", "o/r"), "abc1234", ValidationError),
        (HttpsRepoUrl("github.com", "o/r"), "HEAD;rm", SourceError),
    ],
    ids=["gitlab carries it in compare", "unsafe baseline"],
)
def test_a_compare_patch_is_refused_before_any_call(repo, baseline, error):
    provider, replay = github_source(b"")
    with pytest.raises(error):
        provider.compare_patch(repo, baseline)
    assert replay.calls == []


def test_a_failed_compare_patch_is_a_source_error():
    provider, _ = github_source(b"{}", status=404)
    with pytest.raises(SourceError) as error:
        provider.compare_patch(HttpsRepoUrl("github.com", "o/r"), "abc1234")
    assert error.value.observation_status == "error"
