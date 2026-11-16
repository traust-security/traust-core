"""Deployment-config errors that never echo what the file holds: a credential pasted into a
config file (as a value, a key, a tag or a line of its own) must stay out of the startup error
and out of the cause it chains."""

from __future__ import annotations

import re
from collections.abc import Iterable
from pathlib import Path

import yaml

from traust_core.v1.contracts import SchemaViolation, config_property_names, config_schema_errors
from traust_core.v1.errors import ConfigError, DocumentError, Issue


class ConfigParseError(Exception):
    """A config file's parse failure, as a cause: its kind and position only. The parser's own
    exception carries document text (an unknown tag or alias, the offending line)."""


def yaml_cause(e: yaml.YAMLError) -> ConfigParseError:
    """The redacted cause for a YAML failure, and `where` it is (`at line L, column C` or '')."""
    return ConfigParseError(f"{type(e).__name__}{yaml_where(e)}")


def yaml_where(e: yaml.YAMLError) -> str:
    mark = getattr(e, "problem_mark", None)
    return f" at line {mark.line + 1}, column {mark.column + 1}" if mark else ""


def locate(
    root: yaml.Node | None, path: Iterable[int | str], names: frozenset[str]
) -> tuple[int | None, str]:
    """Where a path into a YAML document is: the line of the deepest node it reaches, and the
    path showing list indexes and the schema's own property names only. Any other key (a custom
    name, an unquoted number, a pasted key) shows as the line it's on, never its text."""
    # the root's own line, so an error at `$` (a scalar where a mapping goes) is located too
    node, shown = root, []
    line = root.start_mark.line + 1 if root is not None else None
    for part in path:
        if isinstance(node, yaml.SequenceNode) and isinstance(part, int):
            shown.append(str(part))
            node = node.value[part] if part < len(node.value) else None
            line = node.start_mark.line + 1 if node is not None else line
            continue
        key_line, node = _entry(node, part)
        line = key_line or line
        if isinstance(part, str) and part in names:
            shown.append(part)
        else:
            shown.append(f"<key at line {key_line}>" if key_line else "<key>")
    return line, "/".join(shown) or "$"


def _entry(node: yaml.Node | None, key: int | str) -> tuple[int | None, yaml.Node | None]:
    """A mapping's entry for `key`: the LAST one, as `yaml.safe_load` keeps the last value of
    a repeated key, so an error points at the value that was validated."""
    found: tuple[int | None, yaml.Node | None] = (None, None)
    if isinstance(node, yaml.MappingNode):
        for k, v in node.value:
            if k.value == str(key):
                found = (k.start_mark.line + 1, v)
    return found


def schema_issue(root: yaml.Node | None, error: SchemaViolation, names: frozenset[str]) -> str:
    """One contract violation of a YAML config, located and in the schema's words: the rule
    broken, and for a disallowed key, where that key is. Never the instance."""
    path = list(error.absolute_path)
    line, where = locate(root, path, names)
    at = f"line {line}: " if line else ""
    return f"{at}{where}: {_rule(root, error, names)}"


def _rule(root: yaml.Node | None, error: SchemaViolation, names: frozenset[str]) -> str:
    value = error.validator_value
    match error.validator:
        case "required":
            return str(error.message)  # the missing property's name, from the schema
        case "pattern":
            return f"does not match the pattern {value!r}"
        case "enum":
            return f"is not one of {value!r}"
        case "const":
            return f"is not {value!r}"
        case "type":
            return f"is not of type {value!r}"
        case "additionalProperties" | "unevaluatedProperties":
            return f"has a property the schema does not allow: {_extras(root, error, names)}"
        case "propertyNames":
            return f"has a property name the schema does not allow: {_extras(root, error, names)}"
        case "not" if isinstance(value, dict) and set(value) == {"required"}:
            return f"cannot set {' and '.join(map(str, value['required']))} together"
        case "anyOf" | "oneOf":
            closest = min(error.context or (), key=lambda e: -len(e.absolute_path), default=None)
            hint = f" (closest: {schema_issue(root, closest, names)})" if closest else ""
            return f"matches none of the schema's alternatives{hint}"
        case _:
            return f"breaks the schema's {error.validator!r} rule ({value!r})"


def _extras(root: yaml.Node | None, error: SchemaViolation, names: frozenset[str]) -> str:
    """The keys an `additionalProperties`/`propertyNames` error is about, each by its line (or
    its name, if it's one the schema declares elsewhere)."""
    instance = error.instance if isinstance(error.instance, dict) else {}
    schema = error.schema if isinstance(error.schema, dict) else {}
    declared = schema.get("properties", {}) if isinstance(schema.get("properties"), dict) else {}
    if error.validator == "propertyNames":
        keys = [k for k in instance if not _name_ok(k, value=error.validator_value)]
    else:
        keys = [k for k in instance if k not in declared]
    shown = []
    for key in keys or ():
        _, where = locate(root, [*error.absolute_path, key], names)
        shown.append(where.rsplit("/", 1)[-1])
    return ", ".join(shown) or "(not located)"


def _name_ok(name: object, *, value: object) -> bool:
    pattern = value.get("pattern") if isinstance(value, dict) else None
    return isinstance(name, str) and (pattern is None or re.search(pattern, name) is not None)


def load_yaml_config(
    path: Path, schema: str, *, label: str | None = None, empty: object = None
) -> tuple[str, object]:
    """A YAML config file from the deployment's home, read and checked against its contract,
    as `(text, document)`. Every error is a ConfigError that never echoes the file: a YAML
    failure by kind and position, a contract violation located by line and worded by the
    schema, each with a cause redacted the same way. An empty file is `empty` (traust.yaml: {})."""
    name = label or str(path)
    try:
        raw = path.read_bytes()
    except OSError as e:
        raise ConfigError(f"cannot read {name}: {e.strerror or type(e).__name__}") from e
    try:
        text = raw.decode()  # exact: no newline translation, so a caller can hash it
    except UnicodeDecodeError as e:
        # the position only: the error's own text quotes the offending byte
        where = f"byte {e.start}"
        cause = ConfigParseError(f"{type(e).__name__} at {where}")
        raise ConfigError(f"cannot read {name}: not UTF-8 text ({where})") from cause
    try:
        document = yaml.safe_load(text)
        if document is None:
            document = empty
    except yaml.YAMLError as e:
        raise ConfigError(f"cannot read {name}: invalid YAML{yaml_where(e)}") from yaml_cause(e)
    if errors := config_schema_errors(schema, document):
        names = config_property_names(schema)
        root = yaml.compose(text)
        issues = [schema_issue(root, e, names) for e in errors]
        cause = DocumentError(schema, [Issue("$", issue) for issue in issues])
        raise ConfigError(f"{name}: {'; '.join(issues)}") from cause
    return text, document
