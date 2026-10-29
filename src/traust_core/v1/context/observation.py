import os
from collections.abc import Mapping

from traust_core.v1.providers.clock import Clock, SystemClock
from traust_core.v1.providers.collaboration import CommentSource
from traust_core.v1.providers.comments import FORGE, JIRA, ForgeCommentSource, JiraCommentSource
from traust_core.v1.providers.forge import CommandSourceProvider
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
    github_token: str | None = None,
) -> CommandSourceProvider:
    """The forge source provider. GitHub hosts read the REST API over the
    network; the token comes from wiring (env reads live in context/, the
    ratchet's rule), read here when the caller does not supply one."""
    return CommandSourceProvider(
        ProcessRunner(("gh", "glab"), keep_env=_FORGE_ENV, timeout_seconds=timeout_seconds),
        clock or SystemClock(),
        hosts,
        github_token=github_token if github_token is not None else _github_env_token(),
    )


def _github_env_token() -> str | None:
    return os.environ.get("GH_TOKEN") or os.environ.get("GITHUB_TOKEN")


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
