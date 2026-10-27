from __future__ import annotations

from datetime import UTC, datetime

import pytest

from tests.v1.services.reporting.documents import TODAY
from traust_core.v1.context import Config, Context
from traust_core.v1.providers.clock import FixedClock
from traust_core.v1.providers.report_files import ReportFiles
from traust_core.v1.services.artifact_publishing import RedactionPolicy
from traust_core.v1.services.reporting import ReportingService
from traust_core.v1.services.reporting.checks import CheckContext


@pytest.fixture(scope="session")
def reporting(tmp_path_factory: pytest.TempPathFactory) -> ReportingService:
    now = datetime(TODAY.year, TODAY.month, TODAY.day, 9, tzinfo=UTC)
    home = tmp_path_factory.mktemp("home")
    return Context(Config(home=home), clock=FixedClock(now)).services().reporting


@pytest.fixture
def context() -> CheckContext:
    return CheckContext(today=TODAY, redaction=RedactionPolicy(), files=ReportFiles())
