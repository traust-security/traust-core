"""Offline fixture scanner: report print calls with enclosing symbols and exact file hash claims."""

import argparse
import ast
import hashlib
import json
from pathlib import Path

parser = argparse.ArgumentParser()
parser.add_argument("source", type=Path)
parser.add_argument("--repository", required=True)
parser.add_argument("--sha", required=True)
parser.add_argument("--path", required=True)
args = parser.parse_args()
raw = args.source.read_bytes()
results = [
    {
        "ruleId": "fixture/log-input",
        "message": {"text": "Input written to a log."},
        "locations": [
            {
                "physicalLocation": {
                    "artifactLocation": {"index": 0},
                    "region": {"startLine": call.lineno},
                },
                "logicalLocations": [{"kind": "function", "fullyQualifiedName": f"api.{fn.name}"}],
            }
        ],
    }
    for fn in ast.walk(ast.parse(raw))
    if isinstance(fn, ast.FunctionDef)
    for call in ast.walk(fn)
    if isinstance(call, ast.Call) and isinstance(call.func, ast.Name) and call.func.id == "print"
]
print(
    json.dumps(
        {
            "version": "2.1.0",
            "runs": [
                {
                    "tool": {
                        "driver": {
                            "name": "fixture-scanner",
                            "version": "1",
                            "rules": [
                                {"id": "fixture/log-input", "properties": {"tags": ["CWE-117"]}}
                            ],
                        }
                    },
                    "versionControlProvenance": [
                        {"repositoryUri": args.repository, "revisionId": args.sha}
                    ],
                    "artifacts": [
                        {
                            "location": {"uri": args.path},
                            "hashes": {"sha-256": hashlib.sha256(raw).hexdigest()},
                        }
                    ],
                    "results": results,
                }
            ],
        }
    )
)
