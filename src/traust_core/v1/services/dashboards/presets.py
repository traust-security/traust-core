"""The preset registry: the named, code-defined queries SCI's cards reference.
Each is a saved DashboardQuery — the access filter stays empty; the caller's
grant fills it at run time. Every preset is validated against the catalog at
import, so one the present build does not serve fails loudly, not at a card's
first poll."""

from __future__ import annotations

from traust_core.v1.errors import ValidationError
from traust_core.v1.models.dashboard import DashboardPreset, DashboardQuery
from traust_core.v1.services.dashboards import catalog

PRESETS: tuple[DashboardPreset, ...] = (
    DashboardPreset(
        id="findings-count",
        description="Every finding in scope: one number.",
        query=DashboardQuery(subject="findings", measures=("findings",)),
    ),
    DashboardPreset(
        id="open-findings-by-severity",
        description="Open findings broken down by severity.",
        query=DashboardQuery(
            subject="findings",
            measures=("findings",),
            group_by=("severity",),
            where={"state": ("open",)},
        ),
    ),
    DashboardPreset(
        id="findings-by-category",
        description="Findings broken down by first category label.",
        query=DashboardQuery(subject="findings", measures=("findings",), group_by=("category",)),
    ),
    DashboardPreset(
        id="top-repositories-by-findings",
        description="The ten repositories with the most findings.",
        query=DashboardQuery(
            subject="findings",
            measures=("findings",),
            group_by=("repository",),
            order=({"by": "findings", "desc": True},),
            limit=10,
        ),
    ),
    DashboardPreset(
        id="open-critical-high-by-severity",
        description="Open critical and high findings, broken down by severity.",
        query=DashboardQuery(
            subject="findings",
            measures=("findings",),
            group_by=("severity",),
            where={"state": ("open",), "severity": ("critical", "high")},
        ),
    ),
)

_BY_ID = {preset.id: preset for preset in PRESETS}


def resolve(preset_id: str) -> DashboardPreset:
    try:
        return _BY_ID[preset_id]
    except KeyError as e:
        raise ValidationError(f"unknown dashboard preset: {preset_id}") from e


for _preset in PRESETS:
    catalog.require(
        _preset.query.subject,
        _preset.query.group_by,
        _preset.query.measures,
        _preset.query.where,
    )
