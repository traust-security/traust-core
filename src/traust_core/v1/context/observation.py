from collections.abc import Mapping

from traust_core.v1.providers.clock import Clock, SystemClock
from traust_core.v1.providers.collaboration import CommentSource
from traust_core.v1.providers.comments import FORGE, JIRA, ForgeCommentSource, JiraCommentSource
from traust_core.v1.providers.forge import CommandSourceProvider
from traust_core.v1.providers.forge_api import ForgeApi
from traust_core.v1.providers.http import HttpFetcher
from traust_core.v1.providers.process import ProcessRunner

# Preserve forge CLI credentials during the existing batch command's migration.
_FORGE_ENV = (
    "PATH",
    "HOME",
    "LANG",
    "LC_ALL",
    "TMPDIR",
    "GH_TOKEN",
    "GITHUB_TOKEN",
    "GH_ENTERPRISE_TOKEN",
    "GITHUB_ENTERPRISE_TOKEN",
    "GH_HOST",
    "GH_CONFIG_DIR",
    "GITLAB_TOKEN",
    "GITLAB_HOST",
    "GLAB_CONFIG_DIR",
    "XDG_CONFIG_HOME",
)
_JIRA_ENV = (
    "PATH",
    "HOME",
    "LANG",
    "LC_ALL",
    "TMPDIR",
    "JIRA_API_TOKEN",
    "JIRA_CONFIG_FILE",
    "XDG_CONFIG_HOME",
)


def command_source(
    hosts: Mapping[str, str],
    *,
    timeout_seconds: float = 120,
    clock: Clock | None = None,
    api: ForgeApi | None = None,
) -> CommandSourceProvider:
    """The forge source provider. GitHub hosts read the REST API over the
    shared ForgeApi (tokens ride its headers from Config.forge_token_values);
    GitLab still reads through the glab CLI until its mirror lands."""
    return CommandSourceProvider(
        ProcessRunner(("gh", "glab"), keep_env=_FORGE_ENV, timeout_seconds=timeout_seconds),
        clock or SystemClock(),
        hosts,
        api or ForgeApi(HttpFetcher("traust-core"), hosts),
    )


def comment_sources(
    hosts: Mapping[str, str], *, timeout_seconds: float = 120, clock: Clock | None = None
) -> dict[str, CommentSource]:
    """Where human statements are read from, by provider name (`finding_external_ref.system`)."""
    clock = clock or SystemClock()
    forge = ProcessRunner(("gh", "glab"), keep_env=_FORGE_ENV, timeout_seconds=timeout_seconds)
    jira = ProcessRunner(("jira",), keep_env=_JIRA_ENV, timeout_seconds=timeout_seconds)
    return {
        FORGE: ForgeCommentSource(forge, clock, hosts),
        JIRA: JiraCommentSource(jira, clock),
    }
