from typing import Any

__all__ = [
    "Hit",
    "Result",
    "Rule",
    "compare",
    "counts",
    "scan",
    "scan_source",
]


# Lazy import to address the previous PR comments.
def __getattr__(name: str) -> Any:
    if name in __all__:
        from traust_core.v1.checks import ratchet

        return getattr(ratchet, name)
    raise AttributeError(f"module {__name__!r} has no attribute {name!r}")
