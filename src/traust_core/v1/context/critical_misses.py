from __future__ import annotations

from pathlib import Path

from traust_core.v1.models.critical_misses import CriticalMissCampaign, CriticalMissReport
from traust_core.v1.providers.critical_miss_campaign import CriticalMissCampaignReader
from traust_core.v1.services.critical_miss_report import render_critical_miss_report


def read_critical_campaign(path: Path) -> CriticalMissCampaign:
    return CriticalMissCampaignReader(path).read()


def critical_miss_markdown(report: CriticalMissReport) -> str:
    return render_critical_miss_report(report)
