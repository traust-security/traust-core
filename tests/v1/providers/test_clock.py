from __future__ import annotations

from datetime import UTC, datetime

import pytest

from traust_core.v1.errors import ConfigError
from traust_core.v1.providers.clock import FixedClock, SystemClock


def test_the_system_clock_is_timezone_aware() -> None:
    assert SystemClock().now().utcoffset() is not None


def test_a_fixed_clock_refuses_a_naive_time() -> None:
    at = datetime(2026, 11, 1, tzinfo=UTC)
    assert FixedClock(at).now() == at
    with pytest.raises(ConfigError):
        FixedClock(datetime(2026, 11, 1))
