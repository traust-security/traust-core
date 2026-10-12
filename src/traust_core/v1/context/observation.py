from collections.abc import Mapping

from traust_core.v1.providers.clock import Clock, SystemClock
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


def command_source(
    hosts: Mapping[str, str], *, timeout_seconds: float = 120, clock: Clock | None = None
) -> CommandSourceProvider:
    return CommandSourceProvider(
        ProcessRunner(("gh", "glab"), keep_env=_FORGE_ENV, timeout_seconds=timeout_seconds),
        clock or SystemClock(),
        hosts,
    )
