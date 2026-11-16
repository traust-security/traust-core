#!/usr/bin/env python3
"""Unit tests for backfill_finding_kind.py (stdlib unittest, no deps).

Run: python3 scripts/test_backfill_finding_kind.py
"""

from __future__ import annotations

import importlib.util
import sys
import unittest
from pathlib import Path

_spec = importlib.util.spec_from_file_location(
    "backfill", Path(__file__).with_name("backfill_finding_kind.py")
)
backfill = importlib.util.module_from_spec(_spec)
sys.modules["backfill"] = backfill
_spec.loader.exec_module(backfill)


class FakePsql:
    """A psql prefix answering canned COPY results, capturing written scripts."""

    def __init__(self, results: dict[str, list[list[str]]]) -> None:
        self.results = results
        self.scripts: list[str] = []

    def read_csv(self, sql: str) -> list[list[str]]:
        for needle, rows in self.results.items():
            if needle in sql:
                return rows
        return []

    def script(self, sql: str) -> None:
        self.scripts.append(sql)


F1, F2, F3 = "f" * 8 + "-0001", "f" * 8 + "-0002", "f" * 8 + "-0003"


class LoadPlanTests(unittest.TestCase):
    def test_null_kind_findings_split_by_advisory_class(self):
        core = FakePsql(
            {
                "WHERE kind IS NULL": [[F1, "f"], [F2, "t"], [F3, "f"]],
                "WHERE kind IS NOT NULL": [["411"]],
            }
        )
        plan = backfill.load_plan(core)
        self.assertEqual(plan.updates, [F1, F3])
        self.assertEqual(plan.advisory_null, [F2])
        self.assertEqual(plan.already_kind, 411)

    def test_short_or_empty_rows_are_skipped(self):
        core = FakePsql({"WHERE kind IS NULL": [[""], [F1], [F1, "f"]]})
        plan = backfill.load_plan(core)
        self.assertEqual(plan.updates, [F1])
        self.assertEqual(plan.advisory_null, [])


class ApplyTests(unittest.TestCase):
    def test_updates_only_still_null_non_advisory_rows_in_batches(self):
        core = FakePsql({})
        applied = backfill.apply_updates(core, [F1, F2, F3], "weakness", 2)
        self.assertEqual(applied, 3)
        self.assertEqual(len(core.scripts), 2)
        first, second = core.scripts
        self.assertIn("SET kind = 'weakness'", first)
        self.assertIn("f.kind IS NULL AND f.advisory_id IS NULL", first)
        self.assertIn("BEGIN;", first)
        self.assertIn("COMMIT;", first)
        self.assertIn(F1, first)
        self.assertIn(F2, first)
        self.assertNotIn(F3, first)
        self.assertIn(F3, second)

    def test_rows_are_quoted_by_the_csv_layer(self):
        core = FakePsql({})
        backfill.apply_updates(core, ["has,comma", 'has"quote'], "weakness", 10)
        self.assertIn('"has,comma"', core.scripts[0])
        self.assertIn('"has""quote"', core.scripts[0])

    def test_no_updates_write_nothing(self):
        core = FakePsql({})
        self.assertEqual(backfill.apply_updates(core, [], "weakness", 10), 0)
        self.assertEqual(core.scripts, [])


if __name__ == "__main__":
    unittest.main()
