#!/usr/bin/env python3
"""Backfill traust.decision.actor/evidence_grade from the ledger events.

The migration recorded the judgements (54,430 decision rows) but not their
attribution: actor and evidence_grade are NULL on every row, so the decisions
tab renders no Actor cell and no E0-E3 chip. The proof each decision appended
— its ledger event — carries both: core's own appends serialize the decision
as it stood (the payload is the decision's own dump), and the replayed legacy
events keep the layer-event shape with the actor under source.actor
({kind, identity}).

What it does
------------
1. Reads the decisions missing actor or evidence_grade, each with its ledger
   event's payload (traust_ledger.events, one per decision) and the flag that
   rules eligibility: a decision an assessment made can never take an actor
   (the table's own CHECK — never two "who"s), so its derived actor is a
   recorded gap, not a write.
2. Derives what the payload states: the actor in core's `<kind>:<identity>`
   spelling (a decision-dump actor string as-is; a layer-event source.actor
   object folded), the evidence_grade when it is one of E0-E3. Unparseable
   payloads, unknown grades and ineligible actors go to the review list —
   the accepted gaps, visible rather than invented.
3. Applies the derivations in batched transactions. traust.decision is
   append-only (the decision_reject_mutation trigger refuses UPDATE), so each
   batch disables that one trigger and re-enables it inside the same
   transaction (the truncate guard stays armed; a failed batch rolls back
   with the trigger still in place). Idempotent: COALESCE keeps any value a
   row already carries, and only rows still missing something are touched,
   so a re-run converges.
4. Writes a JSON report and a CSV review list.

The database is reached only through the psql command given on the command
line, so no credentials live in this script or its output. Reads use
COPY ... TO STDOUT (FORMAT csv); writes pipe a SQL script with inline CSV COPY
data, so every value is quoted by the CSV layer, never by hand.

Examples
--------
Dry run (the default) against an environment through the migration-label
query pod:

    python3 scripts/backfill_decision_attribution.py \
      --psql-core "oc -n sci exec -i dbq -- psql -X -v ON_ERROR_STOP=1 -d traust_core" \
      --report /tmp/attribution-backfill-report.json \
      --review /tmp/attribution-backfill-review.csv

Apply:

    ... --apply --batch-size 2000
"""

from __future__ import annotations

import argparse
import csv
import io
import json
import re
import shlex
import subprocess
import sys
from dataclasses import dataclass, field
from pathlib import Path

GRADES = {"E0", "E1", "E2", "E3"}
# Core's actor spelling (Principal.ref): `<kind>:<identity>`, kind one of the
# actor-kind registry's human/machine, the identity nonempty.
ACTOR = re.compile(r"(?:human|machine):.+")

# The append-only guard this backfill must lift for its UPDATE, by name.
MUTATION_TRIGGER = "decision_reject_mutation"


def positive_int(raw: str) -> int:
    """A batch size the range() loop can step by (zero crashes, negative skips silently)."""
    value = int(raw)
    if value < 1:
        raise argparse.ArgumentTypeError(f"must be a positive integer, not {raw!r}")
    return value


class Psql:
    """Runs reads and writes through a caller-supplied psql command prefix."""

    def __init__(self, cmd: str) -> None:
        # The template is one shell-quoted argument; split it the way a shell
        # would so embedded quoting in the caller's command survives.
        self.cmd = shlex.split(cmd)

    def read_csv(self, sql: str) -> list[list[str]]:
        """Rows of a COPY ... TO STDOUT (FORMAT csv) query."""
        proc = subprocess.run(
            [*self.cmd, "-At", "-c", sql],
            capture_output=True,
            text=True,
            timeout=300,
            check=True,
        )
        if not proc.stdout.strip():
            return []
        return list(csv.reader(io.StringIO(proc.stdout)))

    def script(self, sql: str) -> None:
        """Feed one SQL script (with inline COPY data) to psql's stdin."""
        proc = subprocess.run(
            [*self.cmd, "-X", "-v", "ON_ERROR_STOP=1"],
            input=sql,
            capture_output=True,
            text=True,
            timeout=600,
        )
        if proc.returncode != 0:
            raise RuntimeError(f"psql failed ({proc.returncode}): {proc.stderr[-2000:]}")
        if "ERROR" in proc.stderr:
            raise RuntimeError(f"psql reported an error: {proc.stderr[-2000:]}")


@dataclass
class Unattributed:
    """One decision waiting for its attribution."""

    decision_id: str
    by_assessment: bool
    has_actor: bool
    has_grade: bool
    payload: str  # the event's bytea as psql prints it (\x…), '' when none


@dataclass
class Attribution:
    """One derivation ready to write."""

    decision_id: str
    actor: str | None
    evidence_grade: str | None


@dataclass
class Plan:
    """The backfill's computed plan and its diagnostics."""

    updates: list[Attribution] = field(default_factory=list)
    ineligible: list[dict] = field(
        default_factory=list
    )  # actors an assessment's decision can't take
    malformed: list[dict] = field(default_factory=list)  # stated actors outside core's shape
    unparseable: list[dict] = field(default_factory=list)
    unknown_grades: list[dict] = field(default_factory=list)
    no_event: list[str] = field(default_factory=list)
    no_actor: int = 0  # events that state none (the gap accepted)
    counted: dict[str, int] = field(
        default_factory=lambda: {
            "missing": 0,
            "with_events": 0,
        }
    )


# The decisions missing attribution, each with its event's payload: the bytea
# prints as \x-hex, '' when the decision never appended one.
MISSING_SQL = """
COPY (
  SELECT d.id::text,
         (d.assessment_id IS NOT NULL),
         (d.actor IS NOT NULL),
         (d.evidence_grade IS NOT NULL),
         COALESCE(e.event_payload::text, '')
  FROM traust.decision d
  LEFT JOIN traust_ledger.events e ON e.decision_id = d.id
  WHERE d.actor IS NULL OR d.evidence_grade IS NULL
  ORDER BY d.id
) TO STDOUT (FORMAT csv)
"""


def parse_payload(raw: str) -> dict | None:
    """The event's payload as JSON, or None when there is no event or it won't parse."""
    if not raw.startswith("\\x"):
        return None
    try:
        loaded = json.loads(bytes.fromhex(raw[2:]))
    except ValueError:
        return None
    return loaded if isinstance(loaded, dict) else None


def actor_of(payload: dict) -> tuple[str | None, str]:
    """(the actor the payload states in core's `<kind>:<identity>` spelling, why not).

    A stated actor outside core's shape is returned as (None, why) — it goes to the
    review list, never onto a decision row.
    """
    actor = payload.get("actor")
    if isinstance(actor, str) and actor:
        return (actor, "") if ACTOR.fullmatch(actor) else (None, f"malformed actor: {actor!r}")
    source = payload.get("source")
    if isinstance(source, dict):
        who = source.get("actor")
        if isinstance(who, dict):
            kind, identity = who.get("kind"), who.get("identity")
            if (
                isinstance(kind, str)
                and isinstance(identity, str)
                and kind in ("human", "machine")
                and identity
            ):
                return f"{kind}:{identity}", ""
            return None, f"malformed source.actor: {repr(who)[:120]}"
        if isinstance(who, str) and who:
            return (who, "") if ACTOR.fullmatch(who) else (None, f"malformed actor: {who!r}")
    return None, ""


def grade_of(payload: dict) -> tuple[str | None, bool]:
    """(the grade the payload states, whether one was stated but unknown).

    A non-string grade (an array or object reach here through parsed JSON) counts
    as stated-but-unknown, same as a word outside E0-E3 — never a crash.
    """
    grade = payload.get("evidence_grade")
    if isinstance(grade, str) and grade in GRADES:
        return grade, False
    return None, grade is not None


def load_plan(core: Psql) -> Plan:
    plan = Plan()
    for row in core.read_csv(MISSING_SQL):
        if len(row) < 5 or not row[0]:
            continue
        waiting = Unattributed(row[0], row[1] == "t", row[2] == "t", row[3] == "t", row[4])
        plan.counted["missing"] += 1
        payload = parse_payload(waiting.payload)
        if payload is None:
            if waiting.payload:
                plan.unparseable.append({"decision_id": waiting.decision_id})
            else:
                plan.no_event.append(waiting.decision_id)
            continue
        plan.counted["with_events"] += 1
        actor, why = actor_of(payload)
        grade, unknown = grade_of(payload)
        if why:
            plan.malformed.append({"decision_id": waiting.decision_id, "detail": why})
        if unknown:
            plan.unknown_grades.append(
                {"decision_id": waiting.decision_id, "grade": repr(payload["evidence_grade"])[:120]}
            )
        if actor is not None and waiting.by_assessment:
            # never two who's: an assessment's decision keeps its actor NULL
            plan.ineligible.append({"decision_id": waiting.decision_id, "actor": actor})
            actor = None
        elif actor is None and not why:
            plan.no_actor += 1
        if (actor is not None and not waiting.has_actor) or (
            grade is not None and not waiting.has_grade
        ):
            plan.updates.append(Attribution(waiting.decision_id, actor, grade))
    return plan


def csv_block(rows: list[Attribution]) -> str:
    out = io.StringIO()
    w = csv.writer(out, lineterminator="\n")
    for row in rows:
        w.writerow([row.decision_id, row.actor, row.evidence_grade])
    return out.getvalue()


def apply_updates(core: Psql, updates: list[Attribution], batch_size: int) -> int:
    """Record the attributions in batched transactions.

    traust.decision is append-only — the decision_reject_mutation trigger
    refuses UPDATE — so each batch disables that one trigger and re-enables
    it inside the same transaction (the truncate guard stays armed; a failed
    batch rolls back with the trigger still in place). Idempotent: COALESCE
    keeps any value a row already carries, and only rows still missing
    something are touched, so a re-run converges.
    """
    total = 0
    for start in range(0, len(updates), batch_size):
        batch = updates[start : start + batch_size]
        sql = (
            "BEGIN;\n"
            f"ALTER TABLE traust.decision DISABLE TRIGGER {MUTATION_TRIGGER};\n"
            "CREATE TEMP TABLE attribution_backfill"
            " (decision_id uuid, actor text, evidence_grade text) ON COMMIT DROP;\n"
            "COPY attribution_backfill (decision_id, actor, evidence_grade) "
            "FROM STDIN (FORMAT csv);\n"
            f"{csv_block(batch)}\\.\n"
            "UPDATE traust.decision d "
            "SET actor = COALESCE(d.actor, b.actor), "
            "evidence_grade = COALESCE(d.evidence_grade, b.evidence_grade) "
            "FROM attribution_backfill b "
            "WHERE d.id = b.decision_id "
            "AND (d.actor IS NULL OR d.evidence_grade IS NULL) "
            "AND (b.actor IS NULL OR d.assessment_id IS NULL);\n"
            f"ALTER TABLE traust.decision ENABLE TRIGGER {MUTATION_TRIGGER};\n"
            "COMMIT;\n"
        )
        core.script(sql)
        total += len(batch)
    return total


def verify_trigger_armed(core: Psql) -> None:
    """The mutation guard must exist and be enabled when this script exits.

    tgenabled lives on pg_trigger (information_schema.triggers does not
    expose it): 'D' is disabled, anything else is armed.
    """
    rows = core.read_csv(
        "COPY (SELECT count(*) FILTER (WHERE t.tgenabled = 'D'), count(*) "
        "FROM pg_trigger t "
        "JOIN pg_class c ON c.oid = t.tgrelid "
        "JOIN pg_namespace n ON n.oid = c.relnamespace "
        "WHERE n.nspname = 'traust' AND c.relname = 'decision' "
        f"AND t.tgname = '{MUTATION_TRIGGER}') "
        "TO STDOUT (FORMAT csv)"
    )
    if not rows or not rows[0] or len(rows[0]) < 2:
        raise RuntimeError(f"could not read traust.decision trigger {MUTATION_TRIGGER} state")
    disabled, found = rows[0][0], rows[0][1]
    if found != "1":
        raise RuntimeError(f"traust.decision trigger {MUTATION_TRIGGER} is missing after the run")
    if disabled != "0":
        raise RuntimeError(
            f"traust.decision trigger {MUTATION_TRIGGER} is not enabled after the run"
        )


def write_review(path: str, plan: Plan) -> None:
    with Path(path).open("w", newline="") as f:
        w = csv.writer(f)
        w.writerow(["kind", "decision_id", "detail"])
        for r in plan.ineligible:
            w.writerow(["ineligible-actor", r["decision_id"], r["actor"]])
        for r in plan.malformed:
            w.writerow(["malformed-actor", r["decision_id"], r["detail"]])
        for r in plan.unparseable:
            w.writerow(["unparseable-payload", r["decision_id"], ""])
        for r in plan.unknown_grades:
            w.writerow(["unknown-evidence-grade", r["decision_id"], r["grade"]])
        for decision_id in plan.no_event:
            w.writerow(["no-event", decision_id, ""])


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument(
        "--psql-core",
        required=True,
        help="psql command prefix reaching the traust_core database "
        '(e.g. "oc -n sci exec -i dbq -- psql -X -d traust_core")',
    )
    ap.add_argument(
        "--apply",
        action="store_true",
        help="record the attributions (default: dry run, report only)",
    )
    ap.add_argument(
        "--batch-size",
        type=positive_int,
        default=2000,
        help="rows per UPDATE transaction (default 2000)",
    )
    ap.add_argument("--report", help="write the JSON report here")
    ap.add_argument("--review", help="write the review-list CSV here")
    args = ap.parse_args(argv)

    core = Psql(args.psql_core)
    plan = load_plan(core)
    actors = sum(1 for u in plan.updates if u.actor is not None)
    grades = sum(1 for u in plan.updates if u.evidence_grade is not None)
    print(
        f"core holds {plan.counted['missing']} decisions missing attribution "
        f"({plan.counted['with_events']} appended an event, "
        f"{len(plan.no_event) + len(plan.unparseable)} did not or it won't parse)"
    )
    print(
        f"  actors derivable      {actors:>6}  (another {len(plan.ineligible)} name one an "
        "assessment's decision can't take — the accepted gap; "
        f"{len(plan.malformed)} stated one outside core's shape)"
    )
    print(
        f"  evidence grades       {grades:>6}  ({len(plan.unknown_grades)} stated an unknown "
        f"value; {plan.no_actor} events state no actor at all)"
    )
    print(
        f"updates to write: {len(plan.updates)} "
        f"(idempotent: existing values are kept, only still-missing columns fill)"
    )

    applied = 0
    if args.apply:
        applied = apply_updates(core, plan.updates, args.batch_size)
        verify_trigger_armed(core)
        print(
            f"applied: {applied} rows in batches of {args.batch_size} "
            f"(guard {MUTATION_TRIGGER} re-armed and verified)"
        )
    else:
        print("dry run: no rows written (pass --apply to record the attributions)")

    report = {
        "decisions_missing_attribution": plan.counted["missing"],
        "decisions_with_events": plan.counted["with_events"],
        "decisions_without_events": len(plan.no_event),
        "payloads_unparseable": len(plan.unparseable),
        "actors_derived": actors,
        "actors_ineligible": len(plan.ineligible),
        "actors_malformed": len(plan.malformed),
        "events_stating_no_actor": plan.no_actor,
        "evidence_grades_derived": grades,
        "evidence_grades_unknown": len(plan.unknown_grades),
        "updates": len(plan.updates),
        "applied": applied,
    }
    if args.report:
        with Path(args.report).open("w") as f:
            json.dump(report, f, indent=2)
        print(f"report: {args.report}")
    if args.review:
        write_review(args.review, plan)
        entries = (
            len(plan.ineligible)
            + len(plan.malformed)
            + len(plan.unparseable)
            + len(plan.unknown_grades)
            + len(plan.no_event)
        )
        if entries:
            print(f"review list: {args.review}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
