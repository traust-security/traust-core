#!/usr/bin/env python3
"""Unit tests for backfill_decision_attribution.py (stdlib unittest, no deps).

Run: python3 scripts/test_backfill_decision_attribution.py
"""

from __future__ import annotations

import importlib.util
import json
import sys
import unittest
from pathlib import Path

_spec = importlib.util.spec_from_file_location(
    "backfill", Path(__file__).with_name("backfill_decision_attribution.py")
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


def hexed(payload: dict | None) -> str:
    """The event_payload column as psql prints it (\\x-hex, '' for no event)."""
    if payload is None:
        return ""
    return "\\x" + json.dumps(payload, sort_keys=True, separators=(",", ":")).encode().hex()


D1, D2, D3, D4 = "d" * 8 + "-0001", "d" * 8 + "-0002", "d" * 8 + "-0003", "d" * 8 + "-0004"
LEGACY = {"source": {"type": "mr_comment", "actor": {"kind": "human", "identity": "a@x.com"}}}
DUMP = {"actor": "human:b@x.com", "evidence_grade": None}


class ParsePayloadTests(unittest.TestCase):
    def test_hex_json_parses_and_the_rest_does_not(self):
        self.assertEqual(backfill.parse_payload(hexed(DUMP)), DUMP)
        self.assertIsNone(backfill.parse_payload(""))
        self.assertIsNone(backfill.parse_payload("\\xzznotjson"))
        self.assertIsNone(backfill.parse_payload("\\x5b5d"))  # a JSON array, not an object

    def test_legacy_layer_event_actor_folds_to_core_spelling(self):
        self.assertEqual(backfill.actor_of(LEGACY), "human:a@x.com")

    def test_decision_dump_actor_string_passes_through(self):
        self.assertEqual(backfill.actor_of(DUMP), "human:b@x.com")

    def test_payloads_without_actors_state_none(self):
        self.assertIsNone(backfill.actor_of({"evidence_grade": "E1"}))
        self.assertIsNone(backfill.actor_of({"source": {"actor": {"kind": "human"}}}))
        self.assertIsNone(backfill.actor_of({}))

    def test_grades_accept_only_the_known_set(self):
        for grade in ("E0", "E1", "E2", "E3"):
            self.assertEqual(backfill.grade_of({"evidence_grade": grade}), (grade, False))
        self.assertEqual(backfill.grade_of({"evidence_grade": "E4"}), (None, True))
        self.assertEqual(backfill.grade_of({"evidence_grade": None}), (None, False))
        self.assertEqual(backfill.grade_of({}), (None, False))


class LoadPlanTests(unittest.TestCase):
    def row(self, decision_id, by_assessment, payload, has_actor="f", has_grade="f"):
        return [decision_id, by_assessment, has_actor, has_grade, hexed(payload)]

    def test_actors_and_grades_derive_and_updates_collect(self):
        core = FakePsql(
            {
                "FROM traust.decision": [
                    self.row(D1, "f", {**LEGACY, "evidence_grade": "E2"}),
                    self.row(D2, "f", {"actor": "machine:triage", "evidence_grade": None}),
                    self.row(D3, "t", {"actor": "human:c@x.com"}),  # an assessment decided
                ]
            }
        )
        plan = backfill.load_plan(core)
        self.assertEqual(
            plan.updates,
            [
                backfill.Attribution(D1, "human:a@x.com", "E2"),
                backfill.Attribution(D2, "machine:triage", None),
            ],
        )
        self.assertEqual(plan.ineligible, [{"decision_id": D3, "actor": "human:c@x.com"}])

    def test_rows_already_carrying_a_derived_value_are_not_re_touched(self):
        core = FakePsql(
            {
                "FROM traust.decision": [
                    # the actor already written, the grade derivable: only the grade updates
                    self.row(
                        D1,
                        "f",
                        {"actor": "human:a@x.com", "evidence_grade": "E1"},
                        has_actor="t",
                        has_grade="f",
                    ),
                    # both already written: no update at all (a re-run converges to zero)
                    self.row(
                        D2,
                        "f",
                        {"actor": "human:a@x.com", "evidence_grade": "E1"},
                        has_actor="t",
                        has_grade="t",
                    ),
                ]
            }
        )
        plan = backfill.load_plan(core)
        self.assertEqual(plan.updates, [backfill.Attribution(D1, "human:a@x.com", "E1")])

    def test_no_event_unparseable_and_unknown_grades_go_to_the_review_list(self):
        core = FakePsql(
            {
                "FROM traust.decision": [
                    self.row(D1, "f", None),
                    [D2, "f", "f", "f", "\\xzznotjson"],
                    self.row(D3, "f", {"evidence_grade": "strong"}),
                    self.row(D4, "f", {"rationale": "no attribution stated"}),
                ]
            }
        )
        plan = backfill.load_plan(core)
        self.assertEqual(plan.updates, [])
        self.assertEqual(plan.no_event, [D1])
        self.assertEqual(plan.unparseable, [{"decision_id": D2}])
        self.assertEqual(plan.unknown_grades, [{"decision_id": D3, "grade": repr("strong")}])
        self.assertEqual(plan.no_actor, 2)  # the unknown-grade and the bare events
        self.assertEqual(plan.counted["missing"], 4)
        self.assertEqual(plan.counted["with_events"], 2)  # the unparseable one does not count


class ApplyTests(unittest.TestCase):
    def test_lifts_and_restores_the_guard_inside_one_transaction(self):
        core = FakePsql({})
        updates = [backfill.Attribution(D1, "human:a@x.com", "E2")]
        applied = backfill.apply_updates(core, updates, 10)
        self.assertEqual(applied, 1)
        sql = core.scripts[0]
        self.assertTrue(sql.startswith("BEGIN;\n"))
        self.assertIn(
            f"ALTER TABLE traust.decision DISABLE TRIGGER {backfill.MUTATION_TRIGGER};", sql
        )
        self.assertIn(
            f"ALTER TABLE traust.decision ENABLE TRIGGER {backfill.MUTATION_TRIGGER};", sql
        )
        self.assertLess(sql.index("DISABLE TRIGGER"), sql.index("UPDATE traust.decision"))
        self.assertLess(sql.index("UPDATE traust.decision"), sql.index("ENABLE TRIGGER"))
        self.assertLess(sql.index("ENABLE TRIGGER"), sql.index("COMMIT;"))
        self.assertIn("actor = COALESCE(d.actor, b.actor)", sql)
        self.assertIn("(b.actor IS NULL OR d.assessment_id IS NULL)", sql)

    def test_batches_and_quotes(self):
        core = FakePsql({})
        updates = [
            backfill.Attribution(D1, 'has"quote', None),
            backfill.Attribution(D2, None, "E1"),
            backfill.Attribution(D3, "human:a@x.com", None),
        ]
        backfill.apply_updates(core, updates, 2)
        self.assertEqual(len(core.scripts), 2)
        self.assertIn('"has""quote"', core.scripts[0])
        self.assertIn(D3, core.scripts[1])

    def test_no_updates_write_nothing(self):
        core = FakePsql({})
        self.assertEqual(backfill.apply_updates(core, [], 10), 0)
        self.assertEqual(core.scripts, [])


class TriggerStateTests(unittest.TestCase):
    def armed(self, disabled: str, found: str) -> FakePsql:
        return FakePsql({"pg_trigger": [[disabled, found]]})

    def test_armed_trigger_passes(self):
        backfill.verify_trigger_armed(self.armed("0", "1"))

    def test_disabled_trigger_raises(self):
        with self.assertRaises(RuntimeError):
            backfill.verify_trigger_armed(self.armed("1", "1"))

    def test_missing_or_unreadable_trigger_raises(self):
        with self.assertRaises(RuntimeError):
            backfill.verify_trigger_armed(self.armed("0", "0"))
        with self.assertRaises(RuntimeError):
            backfill.verify_trigger_armed(FakePsql({"pg_trigger": []}))


if __name__ == "__main__":
    unittest.main()
