"""Deployment-config errors that never echo what the file holds: a credential pasted into a
config file (as a value, a key, a tag or a line of its own) must stay out of the startup error
and out of the cause it chains."""

from __future__ import annotations

import yaml


class ConfigParseError(Exception):
    """A config file's parse failure, as a cause: its kind and position only. The parser's own
    exception carries document text (an unknown tag or alias, the offending line)."""


def yaml_cause(e: yaml.YAMLError) -> ConfigParseError:
    """The redacted cause for a YAML failure, and `where` it is (`at line L, column C` or '')."""
    return ConfigParseError(f"{type(e).__name__}{yaml_where(e)}")


def yaml_where(e: yaml.YAMLError) -> str:
    mark = getattr(e, "problem_mark", None)
    return f" at line {mark.line + 1}, column {mark.column + 1}" if mark else ""
