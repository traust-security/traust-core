from __future__ import annotations

from traust_core.v1.domain.analysis_results import ResultKind
from traust_core.v1.rendering import markdown_table
from traust_core.v1.security.artifacts import TriageArtifact
from traust_core.v1.services.artifact_publishing import Companion, PublishSpec, PublishSpecs


def _cell(value: object) -> str:
    return "—" if value is None else str(value)


def _location(finding: object) -> str:
    file, line = getattr(finding, "file", None), getattr(finding, "line", None)
    return _cell(f"{file}:{line}" if file and line else file)


def render_triage_md(triage: TriageArtifact) -> bytes:
    ctx, summary = triage.triage_context, triage.summary
    counts = (
        "input_count",
        "true_positives",
        "hardening",
        "false_positives",
        "undetermined",
        "duplicates",
    )
    lines = [
        f"# Triage: {ctx.repo}",
        "",
        f"_Completed {triage.triage_completed} · harness {ctx.harness_version} · "
        f"{ctx.votes_per_finding} vote(s) per finding_",
        "",
        "## Summary",
        "",
        *markdown_table(
            ("Input", "True positive", "Hardening", "False positive", "Undetermined", "Duplicate"),
            [tuple(_cell(getattr(summary, c)) for c in counts)],
        ),
        "",
        "## Findings",
        "",
    ]
    rows = [(f.id, f.title, f.verdict, _cell(f.severity), _location(f)) for f in triage.findings]
    header = ("ID", "Title", "Verdict", "Severity", "Location")
    lines += markdown_table(header, rows) if rows else ["No findings."]
    return ("\n".join(lines) + "\n").encode()


TRIAGE = PublishSpec(
    TriageArtifact, companions=(Companion(ResultKind.TRIAGE_MD, render_triage_md),)
)


def example_specs() -> PublishSpecs:
    return PublishSpecs(TRIAGE)
