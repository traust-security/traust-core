#!/usr/bin/env python3
"""Backfill traust.finding.kind: the migrated non-advisory findings default to weakness.

The estate migration left kind NULL on 99.5% of the findings (52,307 of 52,589
on integration): the legacy lane had no kind column, and only the newest
recordings state one (the intake path carries a report's `findings[].kind`
onto the finding row; the harness contract emitting it is the companion fix on
the worker side). The console renders the Kind column from finding.kind — its
tooltip already documents "Hardening is the display label for kind=weakness" —
so every migrated row reads empty.

What it does
------------
1. Reads core's findings with a NULL kind, split by the advisory class: a
   finding with advisory_id set is an advisory match, and its kind is not this
   backfill's to default (the advisory lane owns that class).
2. Applies kind='weakness' to the non-advisory NULL rows in batched
   transactions. traust.finding is mutable — the finding_touch trigger keeps
   updated_at, and no append-only guard stands on the table — so a plain
   UPDATE per batch is the sanctioned repair. Idempotent: only rows still NULL
   are touched, so a re-run converges and never overwrites a kind a report
   stated.
3. Writes a JSON report.

The database is reached only through the psql command given on the command
line, so no credentials live in this script or its output. Reads use
COPY ... TO STDOUT (FORMAT csv); writes pipe a SQL script with inline CSV COPY
data, so every value is quoted by the CSV layer, never by hand.

Examples
--------
Dry run (the default) against an environment through the migration-label
query pod:

    python3 scripts/backfill_finding_kind.py \
      --psql-core "oc -n sci exec -i dbq -- psql -X -v ON_ERROR_STOP=1 -d traust_core" \
      --report /tmp/kind-backfill-report.json

Apply:

    ... --apply --batch-size 2000
"""

from __future__ import annotations

import argparse
import csv
import io
import json
import shlex
import subprocess
import sys
from dataclasses import dataclass, field
from pathlib import Path

DEFAULT_KIND = "weakness"


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
class Kindless:
    """One finding waiting for its kind."""

    finding_id: str
    advisory: bool


@dataclass
class Plan:
    """The backfill's computed plan and its diagnostics."""

    updates: list[str] = field(default_factory=list)
    advisory_null: list[str] = field(default_factory=list)  # advisory matches: not ours to default
    already_kind: int = 0


# The findings waiting for a default, with the advisory flag that splits them.
KINDLESS_SQL = """
COPY (
  SELECT id::text, (advisory_id IS NOT NULL)
  FROM traust.finding
  WHERE kind IS NULL
  ORDER BY id
) TO STDOUT (FORMAT csv)
"""

KINDED_COUNT_SQL = (
    "COPY (SELECT count(*) FROM traust.finding WHERE kind IS NOT NULL) TO STDOUT (FORMAT csv)"
)


def load_plan(core: Psql) -> Plan:
    plan = Plan()
    for row in core.read_csv(KINDLESS_SQL):
        if len(row) < 2 or not row[0]:
            continue
        kindless = Kindless(row[0], row[1] == "t")
        if kindless.advisory:
            plan.advisory_null.append(kindless.finding_id)
        else:
            plan.updates.append(kindless.finding_id)
    for row in core.read_csv(KINDED_COUNT_SQL):
        plan.already_kind = int(row[0]) if row and row[0].isdigit() else 0
    return plan


def csv_block(rows: list[str]) -> str:
    out = io.StringIO()
    w = csv.writer(out, lineterminator="\n")
    for row in rows:
        w.writerow([row])
    return out.getvalue()


def apply_updates(core: Psql, updates: list[str], kind: str, batch_size: int) -> int:
    """Record the default kind in batched transactions.

    traust.finding is mutable (finding_touch keeps updated_at; there is no
    append-only guard to lift), so each batch is one plain UPDATE. Idempotent:
    only rows still NULL are touched, so a re-run converges and never
    overwrites a kind a report stated.
    """
    total = 0
    for start in range(0, len(updates), batch_size):
        batch = updates[start : start + batch_size]
        sql = (
            "BEGIN;\n"
            "CREATE TEMP TABLE kind_backfill (finding_id uuid) ON COMMIT DROP;\n"
            "COPY kind_backfill (finding_id) FROM STDIN (FORMAT csv);\n"
            f"{csv_block(batch)}\\.\n"
            f"UPDATE traust.finding f SET kind = '{kind}' "
            "FROM kind_backfill b "
            "WHERE f.id = b.finding_id AND f.kind IS NULL AND f.advisory_id IS NULL;\n"
            "COMMIT;\n"
        )
        core.script(sql)
        total += len(batch)
    return total


def main() -> int:
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
        help="record the default kind (default: dry run, report only)",
    )
    ap.add_argument(
        "--kind", default=DEFAULT_KIND, help=f"the default to record (default {DEFAULT_KIND})"
    )
    ap.add_argument(
        "--batch-size", type=int, default=2000, help="rows per UPDATE transaction (default 2000)"
    )
    ap.add_argument("--report", help="write the JSON report here")
    args = ap.parse_args()

    core = Psql(args.psql_core)
    plan = load_plan(core)
    total_null = len(plan.updates) + len(plan.advisory_null)
    print(f"core holds {plan.already_kind} findings that state a kind, {total_null} that do not")
    print(f"  non-advisory  {len(plan.updates):>6}  gain kind='{args.kind}'")
    print(
        f"  advisory      {len(plan.advisory_null):>6}  stay NULL by design "
        "(the advisory lane owns that class)"
    )

    applied = 0
    if args.apply:
        applied = apply_updates(core, plan.updates, args.kind, args.batch_size)
        print(
            f"applied: {applied} rows in batches of {args.batch_size} "
            f"(idempotent: only still-NULL rows are updated)"
        )
    else:
        print("dry run: no rows written (pass --apply to record the default)")

    report = {
        "kind": args.kind,
        "findings_already_kind": plan.already_kind,
        "findings_kind_null": total_null,
        "findings_gaining_kind": len(plan.updates),
        "advisory_findings_left_null": len(plan.advisory_null),
        "applied": applied,
    }
    if args.report:
        with Path(args.report).open("w") as f:
            json.dump(report, f, indent=2)
        print(f"report: {args.report}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
