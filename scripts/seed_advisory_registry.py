#!/usr/bin/env python3
"""Seed traust.advisory from the impact analyses' CVEs.

The advisory registry is empty (0 rows on every environment) while 917 impact
assessments recorded 1,342 impact-analysis artifacts — each analysis names the
CVE it analysed (its document's metadata.cve). Every exposure read joins
analyses to the registry, so the whole section fails on the first analysis
("an impact analysis names CVE-…, never kept"), which is why the executive
summary's fleet-wide report never rendered.

The advisory table wants the identifiers with whatever metadata's derivable:
an impact analysis states its advisory's identifier (the field is named
metadata.cve; the estate's analyses name CVEs, the fixture names a GHSA) and
its own times, never the advisory's publication, so the seed writes the
identifier alone — published_at stays NULL until the advisory source sweep
fills it. The registry row is the join key the exposure section needs, not
the advisory's full record.

What it does
------------
1. Reads core's impact-analysis artifact rows (id, uri, digest). The bytes
   live in the object store, reached through a caller-supplied objects root
   (a local mount or copy of the store; the uri is the object key, the layout
   artifacts/<schema>/<sha256>.json), so no credentials live in this script.
2. Reads each artifact, verifies it against the digest its row recorded, and
   takes the advisory identifier its metadata names. An identifier that fails
   the advisory-id shape (the CVE/GHSA/MAL/... family the registry keys on),
   an artifact whose bytes fail its digest, and one naming no identifier go
   to the review list — the seed never guesses.
3. Applies the distinct new identifiers in batched transactions
   (INSERT ... ON CONFLICT (identifier) DO NOTHING). traust.advisory is
   mutable (advisory_touch keeps updated_at; no append-only guard), and the
   conflict target makes the seed idempotent: a re-run converges and never
   duplicates or overwrites.
4. Writes a JSON report and a CSV review list.

The database is reached only through the psql command given on the command
line. Reads use COPY ... TO STDOUT (FORMAT csv); writes pipe a SQL script with
inline CSV COPY data, so every value is quoted by the CSV layer, never by
hand.

Examples
--------
Dry run (the default) against an environment through the migration-label
query pod (the objects volume copied or mounted locally first):

    python3 scripts/seed_advisory_registry.py \
      --psql-core "oc -n sci exec -i dbq -- psql -X -v ON_ERROR_STOP=1 -d traust_core" \
      --objects-root /var/lib/traust/artifacts \
      --report /tmp/advisory-seed-report.json --review /tmp/advisory-seed-review.csv

Apply:

    ... --apply --batch-size 1000
"""

from __future__ import annotations

import argparse
import csv
import hashlib
import io
import json
import re
import shlex
import subprocess
import sys
from dataclasses import dataclass, field
from pathlib import Path

CVE = re.compile(r"(?:CVE|GHSA|MAL|PYSEC|GO|RUSTSEC|OSV)-[A-Za-z0-9][A-Za-z0-9-]{0,63}")


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
class ArtifactRow:
    """One impact-analysis artifact row, as the registry's source."""

    artifact_id: str
    uri: str
    digest: str


@dataclass
class Seed:
    """The seed's computed plan and its diagnostics."""

    inserts: list[str] = field(default_factory=list)
    already_present: list[str] = field(default_factory=list)
    rejected: list[dict] = field(default_factory=list)  # review list entries
    artifacts_read: int = 0


# Every impact-analysis artifact row, with the object key and digest its bytes
# verify against.
ARTIFACTS_SQL = """
COPY (
  SELECT id::text, uri, digest
  FROM traust.artifact
  WHERE kind = 'impact-analysis'
  ORDER BY id
) TO STDOUT (FORMAT csv)
"""

REGISTRY_SQL = "COPY (SELECT identifier FROM traust.advisory) TO STDOUT (FORMAT csv)"


def load_rows(core: Psql) -> list[ArtifactRow]:
    rows = []
    for row in core.read_csv(ARTIFACTS_SQL):
        if len(row) < 3 or not row[0] or not row[1]:
            continue
        rows.append(ArtifactRow(row[0], row[1], row[2]))
    return rows


def cve_of(row: ArtifactRow, root: Path) -> tuple[str | None, str]:
    """The advisory identifier one artifact names, or (None, why not) for the review list."""
    path = root / row.uri
    try:
        payload = path.read_bytes()
    except OSError as e:
        return None, f"unreadable: {type(e).__name__}"
    if hashlib.sha256(payload).hexdigest() != row.digest:
        return None, "digest mismatch"
    try:
        named = json.loads(payload)["metadata"]["cve"]
    except (ValueError, KeyError, TypeError):
        return None, "no metadata.cve"
    if not isinstance(named, str) or CVE.fullmatch(named) is None:
        return None, f"not an advisory id: {named!r}"
    return named, ""


def load_seed(core: Psql, root: Path) -> tuple[Seed, dict[str, int]]:
    """The identifiers to insert, and the counts per source artifact."""
    seed = Seed()
    counts: dict[str, int] = {"named": 0, "rejected": 0}
    named: set[str] = set()
    for row in load_rows(core):
        seed.artifacts_read += 1
        cve, why = cve_of(row, root)
        if cve is None:
            counts["rejected"] += 1
            seed.rejected.append({"artifact_id": row.artifact_id, "uri": row.uri, "why": why})
            continue
        counts["named"] += 1
        named.add(cve)
    kept = {row[0] for row in core.read_csv(REGISTRY_SQL) if row and row[0]}
    seed.already_present = sorted(kept & named)
    seed.inserts = sorted(named - kept)
    return seed, counts


def csv_block(rows: list[str]) -> str:
    out = io.StringIO()
    w = csv.writer(out, lineterminator="\n")
    for row in rows:
        w.writerow([row])
    return out.getvalue()


def apply_inserts(core: Psql, inserts: list[str], batch_size: int) -> int:
    """Record the advisories in batched transactions.

    traust.advisory is mutable (advisory_touch keeps updated_at; there is no
    append-only guard to lift), and the identifier's unique constraint is the
    idempotency key: ON CONFLICT DO NOTHING, so a re-run converges and never
    duplicates or overwrites.
    """
    total = 0
    for start in range(0, len(inserts), batch_size):
        batch = inserts[start : start + batch_size]
        sql = (
            "BEGIN;\n"
            "CREATE TEMP TABLE advisory_seed (identifier text) ON COMMIT DROP;\n"
            "COPY advisory_seed (identifier) FROM STDIN (FORMAT csv);\n"
            f"{csv_block(batch)}\\.\n"
            "INSERT INTO traust.advisory (identifier) "
            "SELECT identifier FROM advisory_seed "
            "ON CONFLICT (identifier) DO NOTHING;\n"
            "COMMIT;\n"
        )
        core.script(sql)
        total += len(batch)
    return total


def write_review(path: str, rejected: list[dict]) -> None:
    with Path(path).open("w", newline="") as f:
        w = csv.writer(f)
        w.writerow(["artifact_id", "uri", "why"])
        for r in rejected:
            w.writerow([r["artifact_id"], r["uri"], r["why"]])


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument(
        "--psql-core",
        required=True,
        help="psql command prefix reaching the traust_core database "
        '(e.g. "oc -n sci exec -i dbq -- psql -X -d traust_core")',
    )
    ap.add_argument(
        "--objects-root",
        required=True,
        type=Path,
        help="the artifact store's root (a mount or copy of the objects "
        "volume; artifact uri values are keys under it)",
    )
    ap.add_argument(
        "--apply", action="store_true", help="record the advisories (default: dry run, report only)"
    )
    ap.add_argument(
        "--batch-size", type=int, default=1000, help="rows per INSERT transaction (default 1000)"
    )
    ap.add_argument("--report", help="write the JSON report here")
    ap.add_argument("--review", help="write the review-list CSV here")
    args = ap.parse_args()

    core = Psql(args.psql_core)
    seed, counts = load_seed(core, args.objects_root)
    print(
        f"read {seed.artifacts_read} impact-analysis artifacts "
        f"({counts['named']} name an advisory, {counts['rejected']} rejected to the "
        "review list)"
    )
    print(
        f"distinct identifiers named: {len(seed.inserts) + len(seed.already_present)} "
        f"({len(seed.already_present)} already in the registry, {len(seed.inserts)} to seed)"
    )

    applied = 0
    if args.apply:
        applied = apply_inserts(core, seed.inserts, args.batch_size)
        print(
            f"applied: {applied} rows in batches of {args.batch_size} "
            "(idempotent: ON CONFLICT (identifier) DO NOTHING)"
        )
    else:
        print("dry run: no rows written (pass --apply to record the advisories)")

    report = {
        "impact_artifacts": seed.artifacts_read,
        "artifacts_naming_an_advisory": counts["named"],
        "artifacts_rejected": counts["rejected"],
        "distinct_identifiers_named": len(seed.inserts) + len(seed.already_present),
        "advisories_already_present": len(seed.already_present),
        "advisories_to_seed": len(seed.inserts),
        "applied": applied,
    }
    if args.report:
        with Path(args.report).open("w") as f:
            json.dump(report, f, indent=2)
        print(f"report: {args.report}")
    if args.review:
        write_review(args.review, seed.rejected)
        if seed.rejected:
            print(f"review list: {args.review}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
