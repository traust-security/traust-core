import base64
import json
from pathlib import Path

import pytest

from tests.v1.observation_support import NOW
from traust_core.v1.errors import ValidationError
from traust_core.v1.models.inventory import OrgName
from traust_core.v1.models.values import HttpsRepoUrl
from traust_core.v1.providers.clock import FixedClock
from traust_core.v1.providers.forge import CommandSourceProvider, approvers_from_owners
from traust_core.v1.providers.process import ProcessResult
from traust_core.v1.providers.sources import OwnerOrigin, SourceError

FIXTURES = Path(__file__).parents[2] / "fixtures/inventory"
HOSTS = {"github.com": "github", "gitlab.com": "gitlab", "gitlab.example.com": "gitlab"}
NOT_FOUND = (1, "", "gh: Not Found (HTTP 404)")
HTTP_NOT_FOUND = (404, "")


class Script:
    """Answers each gitlab CLI call by the first endpoint fragment it contains."""

    def __init__(self, answers):
        self.answers, self.calls = answers, []

    def run(self, argv, **kwargs):
        self.calls.append(tuple(argv))
        code, out, err = next(
            (a for k, a in self.answers.items() if any(k in arg for arg in argv)), NOT_FOUND
        )
        return ProcessResult(tuple(argv), code, out.encode(), err.encode(), 0)


class Fetch:
    """Answers each GitHub REST read by the first URL fragment it contains."""

    def __init__(self, answers):
        self.answers, self.calls = answers, []

    def __call__(self, url, headers):
        self.calls.append(url)
        status, body = next(
            (a for k, a in self.answers.items() if k in url), HTTP_NOT_FOUND
        )
        if isinstance(body, Exception):
            raise body
        return status, body


def forge(answers, github=None):
    """A provider answering gitlab CLI calls from `answers` (a Script) and
    GitHub REST reads from `github` (a Fetch); both record their calls."""
    script = Script(answers)
    fetch = Fetch(github or {})
    provider = CommandSourceProvider(script, FixedClock(NOW), HOSTS, fetch=fetch)
    return provider, script, fetch


def ok(text):
    return (0, text, "")


def http(text, status=200):
    return (status, text)


def contents(b64: str) -> str:
    return json.dumps({"type": "file", "encoding": "base64", "content": b64})


def contributors(logins) -> str:
    return json.dumps([{"login": name} for name in logins])


@pytest.mark.parametrize(
    "text,approvers",
    [
        (
            (FIXTURES / "OWNERS.fixture").read_text(),
            ["approver-a", "approver-b", "approver-c", "approver-d"],
        ),
        ("reviewers:\n- r1\napprovers:\n  - alice\n  - bob\nlabels: [x]\n", ["alice", "bob"]),
        ("approvers: [alice, 'bob']\n", ["alice", "bob"]),
        ("# comment\n*.go @carol @acme/team\ndocs/ @dave\n", ["carol", "acme/team", "dave"]),
        ("approvers:\n- alice\n*.go @alice @erin\n", ["alice", "erin"]),
        ("", []),
    ],
)
def test_approvers_come_from_owners_yaml_or_codeowners(text, approvers):
    assert approvers_from_owners(text) == approvers


@pytest.mark.parametrize(
    "url,host,path",
    [
        ("https://github.com/acme/api", "github.com", "acme/api"),
        ("https://github.com/acme/api.git/", "github.com", "acme/api"),
        ("https://gitlab.example.com/grp/sub/proj", "gitlab.example.com", "grp/sub/proj"),
    ],
)
def test_repo_urls_are_canonical_https_forge_urls(url, host, path):
    assert HttpsRepoUrl.parse(url, HOSTS) == HttpsRepoUrl(host, path)


@pytest.mark.parametrize(
    "url",
    [
        "http://github.com/acme/api",
        "https://github.com/acme",
        "https://example.com/acme/api",
        "git@github.com:acme/api.git",
        "https://github.com/acme/api;rm -rf /",
    ],
)
def test_anything_but_an_https_forge_repo_url_is_refused(url):
    with pytest.raises(ValidationError):
        HttpsRepoUrl.parse(url, HOSTS)


def test_github_owners_are_owners_file_approvers_then_contributors_without_bots():
    owners = base64.b64encode((FIXTURES / "OWNERS.fixture").read_bytes()).decode()
    logins = (FIXTURES / "github-contributors.txt").read_text().split()
    provider, _, fetch = forge(
        {},
        github={
            "contents/OWNERS": http(contents(owners)),
            "contributors": http(contributors(logins)),
        },
    )
    hints = provider.owners(HttpsRepoUrl("github.com", "example-org/api")).data
    assert [(h.origin, h.handle, h.file) for h in hints] == [
        (OwnerOrigin.OWNERS_FILE, "approver-a", "OWNERS"),
        (OwnerOrigin.OWNERS_FILE, "approver-b", "OWNERS"),
        (OwnerOrigin.OWNERS_FILE, "approver-c", "OWNERS"),
        (OwnerOrigin.OWNERS_FILE, "approver-d", "OWNERS"),
        (OwnerOrigin.CONTRIBUTOR, "person-a", None),
        (OwnerOrigin.CONTRIBUTOR, "person-b", None),
        (OwnerOrigin.CONTRIBUTOR, "person-c", None),
        (OwnerOrigin.CONTRIBUTOR, "approver-b", None),
        (OwnerOrigin.CONTRIBUTOR, "person-d", None),
    ]
    assert all(u.startswith("https://api.github.com/") for u in fetch.calls)


def test_a_missing_owners_file_falls_through_to_the_next_candidate():
    codeowners = base64.b64encode(b"* @example-org/platform\n").decode()
    provider, _, fetch = forge(
        {},
        github={
            ".github/CODEOWNERS": http(contents(codeowners)),
            "contributors": http("[]"),
        },
    )
    hints = provider.owners(HttpsRepoUrl("github.com", "example-org/api")).data
    assert [(h.handle, h.file) for h in hints] == [("example-org/platform", ".github/CODEOWNERS")]
    assert [u.split("/contents/")[-1] for u in fetch.calls[:3]] == [
        "OWNERS",
        "CODEOWNERS",
        ".github/CODEOWNERS",
    ]


def test_a_repository_with_no_owners_file_or_contributors_has_no_hints():
    provider, _, _ = forge({})
    assert provider.owners(HttpsRepoUrl("github.com", "example-org/empty")).data == []


def test_gitlab_owners_read_the_raw_file_and_contributor_names():
    contributors = [
        {"name": "Person A"},
        {"name": "", "email": "b@example.com"},
        {"name": "x[bot]"},
    ]
    provider, script, _ = forge(
        {
            "files/OWNERS/raw": ok("approvers:\n- approver-a\n"),
            "repository/contributors": ok(json.dumps(contributors)),
        }
    )
    hints = provider.owners(HttpsRepoUrl("gitlab.com", "example-group/sub/api")).data
    assert [h.handle for h in hints] == ["approver-a", "Person A", "b@example.com"]
    assert script.calls[0] == (
        "glab",
        "api",
        "--hostname",
        "gitlab.com",
        "projects/example-group%2Fsub%2Fapi/repository/files/OWNERS/raw?ref=HEAD",
    )


@pytest.mark.parametrize(
    "github,status",
    [
        ({"contents/OWNERS": (401, "HTTP 401 Unauthorized")}, "no-credentials"),
        ({"contents/OWNERS": (0, OSError("dial tcp: i/o timeout"))}, "unreachable"),
        ({"contents/OWNERS": http("not json!")}, "error"),
        ({"contributors": (401, "HTTP 401 Unauthorized")}, "no-credentials"),
    ],
)
def test_owner_reads_fail_loudly_on_credentials_network_or_garbage(github, status):
    provider, _, _ = forge({}, github=github)
    with pytest.raises(SourceError) as error:
        provider.owners(HttpsRepoUrl("github.com", "example-org/api"))
    assert error.value.observation_status == status


def test_a_malformed_gitlab_contributor_list_is_a_source_error():
    provider, _, _ = forge({"repository/contributors": ok("{")})
    with pytest.raises(SourceError):
        provider.owners(HttpsRepoUrl("gitlab.com", "example-group/api"))


def test_a_github_org_lists_its_live_source_repositories_sorted():
    # The fixture rows are the projected shape; a REST answer carries the
    # full objects, so wrap each row the way the forge sends it.
    rows = [
        json.loads(line) for line in (FIXTURES / "github-org-repos.jsonl").read_text().splitlines()
    ]
    payload = json.dumps(
        [dict(row, html_url=row.pop("url")) for row in rows]
    )
    provider, _, fetch = forge({}, github={"orgs/": http(payload)})
    result = provider.list_org(OrgName("example-org"), "github.com")
    repos = [str(i.repo) for i in result.data]
    assert len(repos) == 11 and repos == sorted(repos)
    assert "https://github.com/example-org/project-02" not in repos
    assert {i.visibility for i in result.data} == {"public"}
    assert result.acquisition.source == "github.com/example-org"
    assert fetch.calls == [
        "https://api.github.com/orgs/example-org/repos?type=sources&per_page=100&page=1"
    ]


def test_a_gitlab_group_lists_subgroup_projects_across_pages_without_forks():
    provider, script, _ = forge({"groups/": ok((FIXTURES / "gitlab-group-projects.json").read_text())})
    infos = provider.list_org(OrgName("example-group"), "gitlab.com").data
    assert [(str(i.repo), i.visibility) for i in infos] == [
        ("https://gitlab.com/example-group/api", "public"),
        ("https://gitlab.com/example-group/tools/cli", "internal"),
    ]
    assert script.calls[0][-1] == (
        "groups/example-group/projects?include_subgroups=true&archived=false&per_page=100"
    )


def test_a_gitlab_subgroup_is_escaped():
    provider, script, _ = forge({"groups/": ok("[]")})
    assert provider.list_org(OrgName("grp/sub"), "gitlab.example.com").data == []
    assert script.calls[0][-1].startswith("groups/grp%2Fsub/projects?")


@pytest.mark.parametrize(
    "org,host",
    [
        ("example-org", "example.com"),
        ("a;b", "github.com"),
        ("-x", "github.com"),
        ("", "github.com"),
        ("grp/sub", "github.com"),
        ("grp/../x", "gitlab.com"),
    ],
)
def test_an_unlistable_org_runs_nothing(org, host):
    provider, script, fetch = forge({})
    with pytest.raises(ValidationError):
        provider.list_org(OrgName(org), host)
    assert script.calls == [] and fetch.calls == []


@pytest.mark.parametrize(
    "payload",
    [
        "{bad",
        '{"archived": false}',
        *(
            json.dumps(dict(url=url, archived=False, visibility="public", fork=False))
            for url in ("https://gitlab.com/o/r", "https://github.com/o")
        ),
        '{"url": "https://github.com/o/r", "archived": "no", "fork": false}',
    ],
)
def test_a_malformed_org_listing_is_a_source_error(payload):
    provider, _, _ = forge({}, github={"orgs/": http(payload)})
    with pytest.raises(SourceError) as error:
        provider.list_org(OrgName("o"), "github.com")
    assert error.value.observation_status == "error"
