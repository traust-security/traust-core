from collections.abc import Callable

import pytest

from traust_core.v1.context.documents import yaml_documents, yaml_documents_with_lines
from traust_core.v1.errors import ValidationError


@pytest.mark.parametrize("load", [yaml_documents, yaml_documents_with_lines])
def test_yaml_errors_preserve_the_cause_without_exposing_source(
    load: Callable[[str], list[object]],
) -> None:
    with pytest.raises(ValidationError, match="unparseable YAML") as caught:
        load("private: [PRIVATE_PARSER_SENTINEL\n")
    assert "PRIVATE_PARSER_SENTINEL" not in str(caught.value)
    assert caught.value.__cause__ is not None
