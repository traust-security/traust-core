"""YAML in and out of the context layer; providers get these passed in, they don't import yaml."""

from __future__ import annotations

from typing import Any

import yaml

from traust_core.v1.errors import ValidationError


class _LineLoader(yaml.SafeLoader):
    """SafeLoader that records each mapping's source line under `__line__`."""


def _mapping_with_line(
    loader: yaml.SafeLoader, node: yaml.MappingNode, deep: bool = False
) -> dict[Any, Any]:
    mapping = loader.construct_mapping(node, deep=deep)
    mapping["__line__"] = node.start_mark.line + 1
    return mapping


_LineLoader.add_constructor(yaml.resolver.BaseResolver.DEFAULT_MAPPING_TAG, _mapping_with_line)


def yaml_documents(text: str) -> list[object]:
    """Every document of a YAML text (safe loader); ValidationError when it doesn't parse."""
    try:
        return list(yaml.safe_load_all(text))
    except yaml.YAMLError as e:
        raise ValidationError(f"unparseable YAML: {e}") from e


def yaml_documents_with_lines(text: str) -> list[object]:
    """`yaml_documents` with each mapping carrying its source line (`k8s_hardening.Scanner` cites
    file:line)."""
    try:
        return list(yaml.load_all(text, Loader=_LineLoader))
    except yaml.YAMLError as e:
        raise ValidationError(f"unparseable YAML: {e}") from e


def yaml_text(document: object) -> str:
    """A document as YAML, keys in their given order."""
    return yaml.safe_dump(document, sort_keys=False, width=100)
