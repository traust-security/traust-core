"""The rule-mining lane's pure policies (delta, gate reachability, allowlist precision) and the
markdown its stages render; no I/O."""

from __future__ import annotations

from collections.abc import Mapping, Sequence
from datetime import datetime
from uuid import UUID

from traust_core.v1.models.detection_quality import (
    REDISCOVERY_GATE,
    RuleCluster,
    RuleMining,
    RulePack,
    TruePositive,
)
from traust_core.v1.models.rule_mining import (
    PRECISION_GATE,
    WATCHED_LANGS,
    Allowlist,
    AllowlistPrecision,
    AllowlistRow,
    Attention,
    ChangedCluster,
    GateCrossing,
    GateDirection,
    LaneDelta,
    LanguageReach,
    NewCluster,
    PackReach,
    Reachability,
    ReachCrossing,
    ReachDirection,
    RepoHits,
    ResolvedCluster,
    SweepCandidates,
    TpCorpus,
)

_STAMP = "%Y-%m-%dT%H:%M:%SZ"


def _key(c: RuleCluster) -> str:
    return f"{c.cwe}/{c.language}"


def lane_delta(prev: RuleMining | None, cur: RuleMining, now: datetime) -> LaneDelta:
    """The fresh mine against the previous one: new, resolved and changed uncovered clusters,
    precision crossing the gate, TP-corpus growth."""
    tp = TpCorpus(confirmed_tps=len(cur.corpus), ruleable_tps=cur.ruleable)
    if prev is None:
        return LaneDelta(
            generated_at=now,
            baseline=True,
            tp_corpus=tp,
            attention=Attention(
                reasons=("baseline run — no previous rule-mining.json to diff against",)
            ),
        )
    prev_unc = {_key(c): c for c in prev.uncovered}
    cur_unc = {_key(c): c for c in cur.uncovered}
    new = tuple(
        NewCluster(
            cluster=k,
            count=cur_unc[k].count,
            repos=cur_unc[k].repositories,
            example_findings=tuple(map(str, cur_unc[k].examples[:3])),
        )
        for k in sorted(set(cur_unc) - set(prev_unc))
    )
    resolved = tuple(
        ResolvedCluster(cluster=k, previous_count=prev_unc[k].count)
        for k in sorted(set(prev_unc) - set(cur_unc))
    )
    changed = tuple(
        ChangedCluster(cluster=k, previous_count=prev_unc[k].count, count=cur_unc[k].count)
        for k in sorted(set(prev_unc) & set(cur_unc))
        if prev_unc[k].count != cur_unc[k].count
    )
    before = {p.rule: p.precision for p in prev.precision}
    crossings = []
    for p in sorted(cur.precision, key=lambda p: p.rule):
        if (now_p := p.precision) is None:
            continue
        was = before.get(p.rule)
        if was is None:
            direction = GateDirection.ENTERED_BELOW if now_p < PRECISION_GATE else None
        elif was >= PRECISION_GATE > now_p:
            direction = GateDirection.FELL_BELOW
        elif was < PRECISION_GATE <= now_p:
            direction = GateDirection.ROSE_ABOVE
        else:
            direction = None
        if direction is not None:
            crossings.append(
                GateCrossing(
                    rule=p.rule, previous_precision=was, precision=now_p, direction=direction
                )
            )
    reasons = []
    if new:
        reasons.append(f"{len(new)} new uncovered cluster(s) — rule-authoring backlog grew")
    if grown := [c for c in changed if c.count > c.previous_count]:
        reasons.append(
            f"{len(grown)} uncovered cluster(s) grew — the gap is accumulating confirmed TPs"
        )
    if below := [c for c in crossings if c.direction is not GateDirection.ROSE_ABOVE]:
        reasons.append(
            f"{len(below)} rule(s) below the {PRECISION_GATE:.0%} precision gate — tighten "
            "or retire per the plan"
        )
    return LaneDelta(
        generated_at=now,
        baseline=False,
        tp_corpus=tp.model_copy(update={"growth": len(cur.corpus) - len(prev.corpus)}),
        new_uncovered_clusters=new,
        resolved_uncovered_clusters=resolved,
        changed_uncovered_clusters=changed,
        precision_gate_crossings=tuple(crossings),
        attention=Attention(needed=bool(reasons), reasons=tuple(reasons)),
    )


def reachability(
    corpus: Sequence[TruePositive], packs: Mapping[str, RulePack | str | None]
) -> Reachability:
    """Per watched language and pack, whether a covered CWE spans enough repositories for a rule
    to clear the rediscovery gate; a pack not fetched (None) or unreadable (its reason) is
    skipped, never reported unreachable."""
    if not corpus:
        return Reachability(available=False, reason="no confirmed true positives recorded")
    out: dict[str, PackReach] = {}
    for name, pack in packs.items():
        covered = {c for r in pack.rules for c in r.cwes} if isinstance(pack, RulePack) else set()
        if not covered:
            reason = pack if isinstance(pack, str) else "pack not cached"
            out[name] = PackReach(available=False, reason=reason)
            continue
        langs = {}
        for lang in WATCHED_LANGS:
            targets = _targets(corpus, lang)
            span, cwe = _widest(targets, covered)
            langs[lang] = LanguageReach(
                repos=len(targets),
                max_span=span,
                widest_covered_cwe=cwe,
                reachable=span >= REDISCOVERY_GATE,
            )
        out[name] = PackReach(available=True, languages=langs)
    return Reachability(available=True, packs=out)


def _targets(corpus: Sequence[TruePositive], lang: str) -> dict[tuple[UUID, UUID], set[str]]:
    """The CWEs confirmed per (repository, commit) in `lang`."""
    grouped: dict[tuple[UUID, UUID], set[str]] = {}
    for tp in corpus:
        if tp.language.lower() != lang or tp.repository_ref_id is None or not tp.paths:
            continue
        grouped.setdefault((tp.repository_id, tp.repository_ref_id), set()).update(
            {*tp.cwes, tp.cwe}
        )
    return grouped


def _widest(
    targets: Mapping[tuple[UUID, UUID], set[str]], covered: set[str]
) -> tuple[int, str | None]:
    per_cwe: dict[str, set[UUID]] = {}
    for (repository_id, _), cwes in targets.items():
        for cwe in cwes & covered:
            per_cwe.setdefault(cwe, set()).add(repository_id)
    if not per_cwe:
        return 0, None
    cwe, repos = max(sorted(per_cwe.items()), key=lambda kv: len(kv[1]))
    return len(repos), cwe


def reach_crossings(prev: Reachability | None, cur: Reachability) -> tuple[ReachCrossing, ...]:
    """Languages whose gate opened (or closed) since the last run; an opening is the news."""
    if not cur.available:
        return ()
    was_packs = prev.packs if prev else {}
    crossings = []
    for name, pack in sorted(cur.packs.items()):
        if not pack.available:
            continue
        was = was_packs[name].languages if name in was_packs else {}
        for lang, row in sorted(pack.languages.items()):
            if lang not in was or was[lang].reachable == row.reachable:
                continue
            crossings.append(
                ReachCrossing(
                    pack=name,
                    language=lang,
                    direction=ReachDirection.OPENED if row.reachable else ReachDirection.CLOSED,
                    max_span=row.max_span,
                    widest_covered_cwe=row.widest_covered_cwe,
                    repos=row.repos,
                )
            )
    return tuple(crossings)


def allowlist_precision(mining: RuleMining, allowlist: Allowlist | None) -> AllowlistPrecision:
    """Measured precision of every rule enabled from an external pack: the half of the promotion
    gate Stage A can't measure before a rule has run. Unjudged rules are listed, not passed."""
    if allowlist is None:
        return AllowlistPrecision(available=False, reason="no rule-pack-allowlist.yaml")
    if allowlist.unreadable is not None:
        return AllowlistPrecision(
            available=False, reason=f"allowlist unreadable: {allowlist.unreadable}"
        )
    tally = {p.rule: p for p in mining.precision}
    rows, unmeasured = [], []
    for rule in sorted(allowlist.rules):
        p = tally.get(rule)  # type: ignore[call-overload]
        if p is None or p.precision is None:
            unmeasured.append(rule)
            continue
        rows.append(
            AllowlistRow(
                rule=rule,
                precision=p.precision,
                below_gate=p.precision < PRECISION_GATE,
                promoted=p.promoted,
                dismissed=p.dismissed,
            )
        )
    return AllowlistPrecision(
        available=True,
        enabled=len(allowlist.rules),
        measured=tuple(rows),
        unmeasured=tuple(unmeasured),
        below_gate=tuple(r for r in rows if r.below_gate),
    )


def render_delta(delta: LaneDelta) -> str:
    """lane-delta.md."""
    a = delta.attention
    lines = [
        "# Rule-mining lane — delta report",
        "",
        f"_Generated {delta.generated_at.strftime(_STAMP)} by `traust sweep rule-lane` "
        "(deterministic stages only; authoring + calibration follow in the scheduled rule "
        "calibration session)._",
        "",
    ]
    if delta.baseline:
        lines += [
            "**Baseline run** — no previous rule-mining.json; the current picture is "
            "inventory, not news.",
            "",
        ]
    tc = delta.tp_corpus
    growth = f", **{tc.growth:+d}** vs the previous mine" if tc.growth is not None else ""
    attention = "YES — " + "; ".join(a.reasons) if a.needed else "none"
    lines += [
        f"- **TP corpus:** {tc.confirmed_tps} confirmed ({tc.ruleable_tps} rule-able){growth}",
        f"- **Attention:** {attention}",
        "",
    ]
    if delta.new_uncovered_clusters:
        lines += [
            "## New uncovered clusters",
            "",
            "| Cluster | TPs | Repos | Example findings |",
            "|---|---|---|---|",
            *(
                f"| {c.cluster} | {c.count} | {c.repos} | {', '.join(c.example_findings)} |"
                for c in delta.new_uncovered_clusters
            ),
            "",
        ]
    if delta.changed_uncovered_clusters:
        lines += [
            "## Changed uncovered clusters",
            "",
            "| Cluster | Previous TPs | TPs |",
            "|---|---|---|",
            *(
                f"| {c.cluster} | {c.previous_count} | {c.count} |"
                for c in delta.changed_uncovered_clusters
            ),
            "",
        ]
    if delta.resolved_uncovered_clusters:
        lines += [
            "## Resolved uncovered clusters (covered or emptied)",
            "",
            *(
                f"- {c.cluster} (was {c.previous_count} TPs)"
                for c in delta.resolved_uncovered_clusters
            ),
            "",
        ]
    if delta.precision_gate_crossings:
        lines += [
            f"## Precision movements across the {delta.precision_gate:.0%} gate",
            "",
            "| Rule | Previous | Now | Direction |",
            "|---|---|---|---|",
        ]
        for x in delta.precision_gate_crossings:
            prev = "n/a" if x.previous_precision is None else f"{x.previous_precision:.0%}"
            lines.append(f"| {x.rule} | {prev} | {x.precision:.0%} | {x.direction} |")
        lines.append("")
    lines += _render_reach(delta)
    lines += _render_allowlist(delta)
    lines += ["## Stage results", "", "| Stage | Status | Summary |", "|---|---|---|"]
    lines += [f"| {s.stage} | {s.status} | {s.summary[:200]} |" for s in delta.stages]
    lines.append("")
    return "\n".join(lines)


def _render_reach(delta: LaneDelta) -> list[str]:
    reach = delta.reachability
    lines: list[str] = []
    if reach is not None and reach.available:
        lines += [
            f"## Stage-A gate reachability (gate = {reach.gate} repos)",
            "",
            "Can a language be calibrated at all yet? A rule clears the gate only by firing in "
            ">= gate repos that share a CWE the pack targets, so an unreachable language returns "
            "a table of structural zeros — untestable, **not** a verdict on the pack.",
            "",
        ]
        for name, pack in sorted(reach.packs.items()):
            if not pack.available:
                lines += [f"**{name}** — skipped ({pack.reason})", ""]
                continue
            lines += [
                f"**{name}**",
                "",
                "| Language | Repos | Widest covered CWE | Max span | Reachable |",
                "|---|---:|---|---:|---|",
                *(
                    f"| {lang} | {r.repos} | {r.widest_covered_cwe or '—'} | {r.max_span} | "
                    f"{'**YES**' if r.reachable else 'no'} |"
                    for lang, r in sorted(pack.languages.items())
                ),
                "",
            ]
    for c in delta.reachability_crossings:
        lines += [
            f"> **Gate {c.direction.upper()}: {c.language} vs {c.pack}** — "
            f"{c.widest_covered_cwe} now spans {c.max_span} of {c.repos} repos.",
            "",
        ]
    return lines


def _render_allowlist(delta: LaneDelta) -> list[str]:
    ap = delta.allowlist_precision
    if ap is None or not ap.available:
        return []
    lines = [
        f"## Enabled external-pack rules vs the {delta.precision_gate:.0%} precision gate",
        "",
        f"{ap.enabled} rule(s) enabled by the `rule-pack-allowlist` setting; "
        f"{len(ap.measured)} have measured precision, {len(ap.unmeasured)} not yet judged in "
        "any audit (silence is not a pass).",
        "",
    ]
    if ap.measured:
        lines += ["| Rule | Precision | Promoted | Dismissed | |", "|---|---:|---:|---:|---|"]
        lines += [
            f"| {r.rule} | {r.precision:.0%} | {r.promoted} | {r.dismissed} | "
            f"{'**DEMOTE**' if r.below_gate else 'ok'} |"
            for r in sorted(ap.measured, key=lambda r: r.precision)
        ]
        lines.append("")
    return lines


def render_mining(mining: RuleMining) -> str:
    """rule-mining.md."""
    lines = [
        "# Ledger Rule-Mining Report",
        "",
        f"Generated from traust-core's recorded findings against `{mining.pack.name} "
        f"{mining.pack.version}` — **{len(mining.corpus)} confirmed true positives** "
        f"({mining.ruleable} in rule-able languages).",
        "",
        "## Uncovered clusters (rule-authoring backlog)",
        "",
        "| CWE | Language | TPs | Repos | Example findings |",
        "|---|---|---|---|---|",
        *(
            f"| {c.cwe} | {c.language} | {c.count} | {c.repositories} | "
            f"{', '.join(map(str, c.examples[:3]))} |"
            for c in mining.uncovered[:25]
        ),
    ]
    if not mining.uncovered:
        lines.append("| — | — | — | — | all rule-able clusters covered |")
    lines += [
        "",
        "## Per-language coverage",
        "",
        "| Language | Confirmed TPs | Covered clusters | Uncovered clusters | Uncovered TPs | "
        "Pack rules |",
        "|---|---|---|---|---|---|",
        *(
            f"| {r.language} | {r.confirmed} | {r.covered_clusters} | {r.uncovered_clusters} | "
            f"{r.uncovered_tps} | {r.pack_rules} |"
            for r in mining.languages
        ),
    ]
    if not mining.languages:
        lines.append("| — | — | — | — | — | empty corpus |")
    lines += [
        "",
        "## Covered clusters",
        "",
        "| CWE | Language | TPs | Covered by |",
        "|---|---|---|---|",
        *(
            f"| {c.cwe} | {c.language} | {c.count} | {', '.join(c.covered_by)} |"
            for c in mining.covered
        ),
        "",
        "## Per-rule precision (from audit judge decisions)",
        "",
    ]
    if mining.precision:
        lines += ["| Rule | Promoted | Dismissed | Precision |", "|---|---|---|---|"]
        for p in mining.precision:
            prec = "n/a" if p.precision is None else f"{p.precision:.0%}"
            lines.append(f"| {p.rule} | {p.promoted} | {p.dismissed} | {prec} |")
    else:
        lines.append(
            "No structured opengrep judge decisions found yet — audits emit them via "
            "scanner_correlation (see /secure-code-audit, Deterministic semantic pre-scan)."
        )
    lines += [
        "",
        f"Calibration worklist: {len(mining.worklist)} repo(s) with covered-cluster TPs "
        "(rule-mining.json).",
        "",
    ]
    return "\n".join(lines)


def render_sweep_summary(
    report: SweepCandidates, per_repo: Sequence[RepoHits], provenance: Sequence[str], out: str
) -> str:
    """sweep-summary.md."""
    lines = [
        f"# Sweep summary — `{report.rule_id}`",
        "",
        f"> {report.purpose}",
        "",
        f"- Generated: {report.generated.isoformat(timespec='seconds')} · harness "
        f"{report.harness_version}",
        f"- Repos swept: {report.repos_swept} ({report.repos_with_hits} with hits, "
        f"{report.repo_errors} errored)",
        f"- Candidates: {len(report.candidates)}",
        "- Source confirmed findings: "
        f"{', '.join(provenance) or '(none recorded in rule metadata)'}",
        "",
        "| repo | hits |",
        "|---|---:|",
        *(
            f"| {r.repo} | {r.hits}" + (f" ({r.error})" if r.error else "") + " |"
            for r in sorted(per_repo, key=lambda r: -r.hits)
        ),
        "",
        f"Next step: triage workflow on {out} — verdicts belong to triage; rule promotion stays "
        "with the rule calibration path.",
        "",
    ]
    return "\n".join(lines)
