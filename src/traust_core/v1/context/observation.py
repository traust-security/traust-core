from collections.abc import Mapping

from traust_core.v1.providers.clock import Clock, SystemClock
from traust_core.v1.providers.collaboration import CommentSource
from traust_core.v1.providers.comments import FORGE, JIRA, ForgeCommentSource, JiraCommentSource
from traust_core.v1.providers.forge import CommandSourceProvider
from traust_core.v1.providers.forge_api import ForgeApi
from traust_core.v1.providers.http import HttpFetcher
from traust_core.v1.providers.process import ProcessRunner

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
    hosts: Mapping[str, str], *, clock: Clock | None = None, api: ForgeApi | None = None
) -> CommandSourceProvider:
    """The forge source provider: every read over the forge's REST API (`ForgeApi`)."""
    return CommandSourceProvider(
        clock or SystemClock(), hosts, api or ForgeApi(HttpFetcher("traust-core"), hosts)
    )


def comment_sources(
    api: ForgeApi, *, timeout_seconds: float = 120, clock: Clock | None = None
) -> dict[str, CommentSource]:
    """Where human statements are read from, by provider name (`finding_external_ref.system`)."""
    clock = clock or SystemClock()
    jira = ProcessRunner(("jira",), keep_env=_JIRA_ENV, timeout_seconds=timeout_seconds)
    return {
        FORGE: ForgeCommentSource(api, clock),
        JIRA: JiraCommentSource(jira, clock),
    }
