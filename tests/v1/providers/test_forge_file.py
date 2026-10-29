"""CommandSourceProvider.file: one file at a pinned commit over the forge's REST API (github
contents, gitlab raw files), with the forge's host and path rules."""

import base64
import json

import pytest

from tests.v1.providers.test_forge_inventory import forge, http, ok
from traust_core.v1.errors import ValidationError
from traust_core.v1.models.values import GitSha, HttpsRepoUrl, RepoPath
from traust_core.v1.providers.sources import SourceError

SHA = GitSha("c" * 40)
CSV = RepoPath("bundle/manifests/operator.clusterserviceversion.yaml")
TEXT = "apiVersion: operators.coreos.com/v1alpha1\nkind: ClusterServiceVersion\n"
GITHUB = HttpsRepoUrl("github.com", "example-org/operator")
GITLAB = HttpsRepoUrl("gitlab.example.com", "example-group/sub/operator")


def contents(**answer):
    return json.dumps({"type": "file", "encoding": "base64", **answer})


def test_a_github_file_is_its_decoded_contents_at_the_commit():
    provider, _, fetch = forge(
        {}, github={"contents/": http(contents(content=base64.b64encode(TEXT.encode()).decode()))}
    )
    assert provider.file(GITHUB, CSV, SHA).data == TEXT
    assert fetch.calls == [f"repos/example-org/operator/contents/{CSV}?ref={SHA}"]


def test_a_gitlab_file_is_the_raw_file_at_the_commit():
    provider, script, _ = forge({"/raw?ref=": ok(TEXT)})
    assert provider.file(GITLAB, CSV, SHA).data == TEXT
    assert script.calls == [
        "projects/example-group%2Fsub%2Foperator/repository/files/"
        f"bundle%2Fmanifests%2Foperator.clusterserviceversion.yaml/raw?ref={SHA}"
    ]


@pytest.mark.parametrize("repo", [GITHUB, GITLAB])
def test_a_file_the_commit_lacks_is_none(repo):
    provider, _, _ = forge({})
    assert provider.file(repo, CSV, SHA).data is None


@pytest.mark.parametrize(
    "answer,status",
    [
        ((401, "HTTP 401 Unauthorized"), "no-credentials"),
        ((0, OSError("dial tcp: i/o timeout")), "unreachable"),
        (http("not json"), "error"),
        (http("{}"), "error"),
        (http(contents(content="not base64!")), "error"),
        (http(contents(content=None)), "error"),
        (http(json.dumps({"type": "file", "encoding": "none", "content": ""})), "error"),
        (http(json.dumps({"type": "symlink", "encoding": None, "content": None})), "error"),
    ],
)
def test_credentials_network_garbage_and_unreadable_files_fail_loudly(answer, status):
    provider, _, _ = forge({}, github={"contents/": answer})
    with pytest.raises(SourceError) as error:
        provider.file(GITHUB, CSV, SHA)
    assert error.value.observation_status == status


@pytest.mark.parametrize(
    "repo,path,sha",
    [
        (HttpsRepoUrl("evil.example", "o/r"), CSV, SHA),
        (HttpsRepoUrl("github.com", "o/r/extra"), CSV, SHA),
        (GITHUB, str(CSV), SHA),
        (GITHUB, CSV, "main"),
        (GITHUB, CSV, str(SHA)),
        (GITHUB, CSV, GitSha("main")),
    ],
)
def test_a_bad_host_path_or_ref_runs_nothing(repo, path, sha):
    provider, script, fetch = forge({})
    with pytest.raises(ValidationError):
        provider.file(repo, path, sha)
    assert script.calls == [] and fetch.calls == []


@pytest.mark.parametrize("repo", [GITHUB, GITLAB])
@pytest.mark.parametrize("status", [403, 500, 503])
def test_a_file_read_failure_is_not_a_missing_file(repo, status):
    provider, _, _ = forge(
        {"/raw?ref=": (status, "nope")},
        github={"contents/": (status, "nope")},
    )
    with pytest.raises(SourceError) as error:
        provider.file(repo, CSV, SHA)
    assert error.value.observation_status == "error"
