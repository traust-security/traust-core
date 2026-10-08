import inspect
from collections.abc import Callable
from typing import Any

import pytest


def public_methods(obj: object) -> list[Callable[..., Any]]:
    return [
        getattr(obj, name)
        for name, _ in inspect.getmembers(type(obj), inspect.isfunction)
        if not name.startswith("_")
    ]


def assert_stub(fn: Callable[..., Any]) -> None:
    with pytest.raises(NotImplementedError, match="stub"):
        fn(*[None] * len(inspect.signature(fn).parameters))
