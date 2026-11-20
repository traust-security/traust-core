"""Native quality responses for adapter transport tests; real-engine tests live separately."""

from __future__ import annotations

import json
from collections.abc import Sequence
from pathlib import Path

import yaml

from traust_core.v1.models.rule_mining import example_lines


def write_fixture(config: Path) -> None:
    document = yaml.safe_load(config.read_text())
    lines = []
    for rule in document.get("rules", []):
        lines += [
            f"# ruleid: {rule['id']}",
            "dangerous(value)",
            f"# ok: {rule['id']}",
            "safe(value)",
        ]
    config.with_suffix(".py").write_text("\n".join(lines) + "\n")


def write_rule(root: Path, rule_id: str = "example-rule", *, name: str = "rules") -> Path:
    root.mkdir(parents=True, exist_ok=True)
    config = root / f"{name}.yaml"
    config.write_text(
        yaml.safe_dump(
            {
                "rules": [
                    {
                        "id": rule_id,
                        "languages": ["python"],
                        "severity": "ERROR",
                        "message": "Unsafe call",
                        "metadata": {"cwe": ["CWE-78"]},
                        "pattern": "dangerous($X)",
                    }
                ]
            },
            sort_keys=False,
        )
    )
    write_fixture(config)
    return config


def native_output(argv: Sequence[str]) -> bytes | None:
    if len(argv) < 2:
        return None
    if argv[1] == "validate":
        return b"Configuration is valid - found 0 fatal errors, 0 skippable error(s)."
    if argv[1] != "test":
        return None
    root = Path(argv[-1])
    results = {}
    for config in sorted(root.rglob("*.yaml")):
        if ".test." in config.name:
            continue
        document = yaml.safe_load(config.read_text())
        if not isinstance(document, dict) or not isinstance(document.get("rules"), list):
            continue
        checks = {}
        for rule in document["rules"]:
            matches = {}
            for fixture in sorted(config.parent.glob(config.stem + ".*")):
                if fixture == config or not fixture.is_file():
                    continue
                fire, _ = example_lines(rule["id"], fixture.read_text())
                matches[str(fixture)] = {
                    "expected_lines": sorted(fire),
                    "reported_lines": sorted(fire),
                }
            checks[rule["id"]] = {"passed": True, "matches": matches, "errors": []}
        results[str(config)] = {"checks": checks}
    return json.dumps(
        {
            "results": results,
            "config_missing_tests": [],
            "config_missing_fixtests": [],
            "config_with_errors": [],
            "fixtest_results": {},
        }
    ).encode()
