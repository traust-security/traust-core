#!/usr/bin/env python3
"""Unit tests for seed_advisory_registry.py (stdlib unittest, no deps).

Run: python3 scripts/test_seed_advisory_registry.py
"""

from __future__ import annotations

import argparse
import hashlib
import importlib.util
import json
import sys
import unittest
from pathlib import Path
from tempfile import TemporaryDirectory

_spec = importlib.util.spec_from_file_location(
    "seed", Path(__file__).with_name("seed_advisory_registry.py")
)
seed_script = importlib.util.module_from_spec(_spec)
sys.modules["seed"] = seed_script
_spec.loader.exec_module(seed_script)


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


def artifact(root: Path, cve: str | None, name: str = "a.json") -> tuple[str, str, str]:
    """Write one impact-analysis document under root; its (id, uri, digest) row."""
    document = {"metadata": {"cve": cve}} if cve is not None else {"metadata": {}}
    payload = json.dumps(document).encode()
    uri = f"artifacts/impact-analysis/{name}"
    (root / uri).parent.mkdir(parents=True, exist_ok=True)
    (root / uri).write_bytes(payload)
    return name.removesuffix(".json"), uri, hashlib.sha256(payload).hexdigest()


class LoadSeedTests(unittest.TestCase):
    def test_cves_are_collected_and_split_against_the_registry(self):
        with TemporaryDirectory() as tmp:
            root = Path(tmp)
            one = artifact(root, "CVE-2026-22778", "one.json")
            two = artifact(root, "CVE-2026-22778", "two.json")  # same CVE, another analysis
            three = artifact(root, "CVE-2025-10001", "three.json")
            core = FakePsql(
                {
                    "kind = 'impact-analysis'": [
                        ["a1", one[1], one[2]],
                        ["a2", two[1], two[2]],
                        ["a3", three[1], three[2]],
                    ],
                    "FROM traust.advisory": [["CVE-2025-10001"]],
                }
            )
            seed, counts = seed_script.load_seed(core, root)
            self.assertEqual(seed.inserts, ["CVE-2026-22778"])
            self.assertEqual(seed.already_present, ["CVE-2025-10001"])
            self.assertEqual((counts["named"], counts["rejected"]), (3, 0))
            self.assertEqual(seed.artifacts_read, 3)

    def test_bad_digest_missing_cve_and_malformed_ids_go_to_the_review_list(self):
        with TemporaryDirectory() as tmp:
            root = Path(tmp)
            good = artifact(root, "CVE-2026-22778", "good.json")
            mismatch = artifact(root, "CVE-2026-00002", "mismatch.json")
            nocve = artifact(root, None, "nocve.json")
            malformed = artifact(root, "not-an-advisory", "malformed.json")
            core = FakePsql(
                {
                    "kind = 'impact-analysis'": [
                        ["a1", good[1], good[2]],
                        ["a2", mismatch[1], "0" * 64],
                        ["a3", nocve[1], nocve[2]],
                        ["a4", malformed[1], malformed[2]],
                    ],
                    "FROM traust.advisory": [],
                }
            )
            seed, counts = seed_script.load_seed(core, root)
            self.assertEqual(seed.inserts, ["CVE-2026-22778"])
            self.assertEqual(counts["rejected"], 3)
            self.assertEqual(
                [r["why"] for r in seed.rejected],
                ["digest mismatch", "no metadata.cve", "not an advisory id: 'not-an-advisory'"],
            )

    def test_an_unreadable_artifact_is_rejected_not_fatal(self):
        core = FakePsql(
            {
                "kind = 'impact-analysis'": [
                    ["a1", "artifacts/impact-analysis/gone.json", "d" * 64]
                ],
                "FROM traust.advisory": [],
            }
        )
        seed, counts = seed_script.load_seed(core, Path("/nowhere"))
        self.assertEqual(seed.inserts, [])
        self.assertEqual(counts["rejected"], 1)
        self.assertEqual(seed.rejected[0]["why"], "unreadable: FileNotFoundError")


class ApplyTests(unittest.TestCase):
    def test_inserts_are_conflict_doing_nothing_in_batches(self):
        core = FakePsql({})
        applied = seed_script.apply_inserts(core, ["CVE-1", "CVE-2", "CVE-3"], 2)
        self.assertEqual(applied, 3)
        self.assertEqual(len(core.scripts), 2)
        first = core.scripts[0]
        self.assertIn("INSERT INTO traust.advisory (identifier)", first)
        self.assertIn("ON CONFLICT (identifier) DO NOTHING", first)
        self.assertIn("CVE-1", first)
        self.assertIn("CVE-2", first)
        self.assertNotIn("CVE-3", first)
        self.assertIn("CVE-3", core.scripts[1])

    def test_rows_are_quoted_by_the_csv_layer(self):
        core = FakePsql({})
        seed_script.apply_inserts(core, ["has,comma"], 10)
        self.assertIn('"has,comma"', core.scripts[0])

    def test_nothing_to_insert_writes_nothing(self):
        core = FakePsql({})
        self.assertEqual(seed_script.apply_inserts(core, [], 10), 0)
        self.assertEqual(core.scripts, [])


class BatchSizeTests(unittest.TestCase):
    def test_nonpositive_batch_sizes_are_refused_at_parse_time(self):
        for bad in ("0", "-5"):
            with self.assertRaises(argparse.ArgumentTypeError):
                seed_script.positive_int(bad)
        self.assertEqual(seed_script.positive_int("1000"), 1000)

    def test_main_refuses_a_nonpositive_batch_size_before_any_work(self):
        for bad in ("0", "-5"):
            with self.assertRaises(SystemExit) as refused:
                seed_script.main(
                    ["--psql-core", "psql", "--objects-root", "/nowhere", "--batch-size", bad]
                )
            self.assertEqual(refused.exception.code, 2)


if __name__ == "__main__":
    unittest.main()
