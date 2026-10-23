"""docs/configuration.md's example is a real config: it parses, so the doc can't drift."""

from __future__ import annotations

import re
from pathlib import Path

import yaml

from traust_core.v1.context import Config

DOC = Path(__file__).parents[3] / "docs" / "configuration.md"


def test_the_documented_example_is_a_valid_config() -> None:
    block = re.search(r"```yaml\n(.*?)```", DOC.read_text(), re.S)
    assert block is not None
    config = Config.model_validate(yaml.safe_load(block.group(1)))
    assert config.ledger is not None and config.identity is not None
    assert config.identity.login is not None
