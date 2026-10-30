"""Preflight: does this deployment have what its enabled pack assets require? One check for
the engine's start gate, the platform doors and `traust doctor` (`Context.preflight`)."""

from __future__ import annotations

import os
from collections.abc import Iterable, Sequence
from typing import TYPE_CHECKING

from traust_core.v1.context.home import config_completeness_audit
from traust_core.v1.errors import PreflightError
from traust_core.v1.models.artifacts import RECORDED_FACTS
from traust_core.v1.models.operations import MODEL_REGISTRY, Requirement
from traust_core.v1.providers.tools.toolchain import preflight_failures
from traust_core.v1.repositories.contract import SqlTraustUnitOfWork

if TYPE_CHECKING:
    from traust_core.v1.context.context import Context

# The record door each required fact is recorded through; the fix preflight names.
_FACT_RECORDINGS: dict[str, str] = {
    "adr-registry": "ComplianceService.record",
    "benchmark-target": "DetectionQualityService.record",
    "org-parameters": "ComplianceService.record",
    "product-definitions-map": "PortfolioService.record_product_map",
    "sla-policy": "InsightService.record_sla_policy",
}


def preflight(ctx: Context, requirements: Iterable[Requirement]) -> None:
    """Raise `PreflightError` listing every unmet requirement with its fix; None when the
    deployment has everything the enabled assets need."""
    findings = preflight_findings(ctx, requirements)
    if findings:
        raise PreflightError(
            f"preflight: {len(findings)} unmet requirement(s):\n"
            + "\n".join(f"- {finding}" for finding in findings)
        )


def preflight_findings(ctx: Context, requirements: Iterable[Requirement]) -> list[str]:
    """Every gap at once: the assets' requirements (tools, config, facts, feeds, secrets)
    and the config home's audit, each line naming its fix."""
    merged = _merged(requirements)
    errors, warnings = config_completeness_audit()
    return [
        *_tool_findings(ctx, merged.tools),
        *_config_findings(ctx, merged.config),
        *_fact_findings(ctx, merged.facts),
        *_feed_findings(ctx, merged.feeds),
        *_secret_findings(merged.secrets),
        *errors,
        *warnings,
    ]


def _tool_findings(ctx: Context, tools: Sequence[str]) -> list[str]:
    # An empty tool list leaves the toolchain untouched: nothing requires it.
    return [] if not tools else preflight_failures(ctx.toolchain.preflight(sorted(tools)))


def _secret_findings(secrets: Sequence[str]) -> list[str]:
    return [f"secrets: ${name} is not set" for name in sorted(secrets) if not os.environ.get(name)]


def _merged(requirements: Iterable[Requirement]) -> Requirement:
    listed = list(requirements)
    return Requirement(
        **{
            kind: sorted({entry for r in listed for entry in getattr(r, kind)})
            for kind in ("tools", "config", "facts", "feeds", "secrets")
        }
    )


def _config_findings(ctx: Context, keys: Sequence[str]) -> list[str]:
    findings = []
    for key in sorted(keys):
        if key == MODEL_REGISTRY:
            if ctx.model_catalog is None:
                findings.append(
                    "config: model-registry is not registered -- register one "
                    "(Context.register_model_catalog; traust ships config/model-registry.yaml)"
                )
        elif key not in ctx.config.provided:
            findings.append(
                f"config: `{key}` is not set -- set it in traust.yaml "
                "(copy traust.example.yaml to start)"
            )
    return findings


def _fact_findings(ctx: Context, facts: Sequence[str]) -> list[str]:
    if not facts:
        return []
    kinds = {fact.name: fact.schema for fact in RECORDED_FACTS}
    with ctx.unit_of_work(SqlTraustUnitOfWork) as uow:
        return [
            f"facts: {name} is not recorded -- record one ({_FACT_RECORDINGS[name]})"
            for name in sorted(facts)
            if uow.artifacts.latest_imported(kinds[name]) is None
        ]


def _feed_findings(ctx: Context, feeds: Sequence[str]) -> list[str]:
    findings = []
    for name in sorted(feeds):
        if name in ctx.feed_sources.names():
            source = ctx.feed_sources.get(name)
        elif name in ctx.feeds.names():
            source = ctx.feeds.get(name)
        else:
            findings.append(
                f"feeds: {name} is not an enabled source -- enable it in the feeds "
                "registry (Context.register_feeds)"
            )
            continue
        if not (ready := source.check()).ready:
            findings.append(f"feeds: {name} is not reachable -- {ready.detail}")
    return findings
