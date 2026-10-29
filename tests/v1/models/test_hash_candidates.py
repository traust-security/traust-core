from __future__ import annotations

import copy
import json
from collections.abc import Iterator
from pathlib import Path
from uuid import uuid4

import pytest

from traust_core.v1.errors import ValidationError
from traust_core.v1.models import candidate_formats
from traust_core.v1.models.common import FILE_BYTES_SHA256, CodeHash
from traust_core.v1.models.findings import CandidateFormat, FindingCandidate

FIXTURE = Path(__file__).parents[2] / "fixtures/findings/scanners/codeql-symbols.sarif"
REPO = "https://github.com/example/current"
SHA = "a" * 40


def document() -> dict:
    doc = json.loads(FIXTURE.read_bytes())
    run = doc["runs"][0]
    location = run["results"][0]["locations"][0]["physicalLocation"]["artifactLocation"]
    run["artifacts"] = [{"location": copy.deepcopy(location), "hashes": {"sha-256": "A" * 64}}]
    run["versionControlProvenance"] = [{"repositoryUri": REPO, "revisionId": SHA}]
    return doc


def parse(doc: dict, *, bound: bool = True) -> FindingCandidate:
    return FindingCandidate.parse_many(
        json.dumps(doc).encode(),
        CandidateFormat.SARIF,
        uuid4(),
        repository_url=REPO if bound else None,
        sha=SHA if bound else None,
    )[0]


@pytest.mark.parametrize("indexed", [False, True])
def test_sarif_imports_only_the_selected_bound_artifact_claim(indexed: bool) -> None:
    doc = document()
    run = doc["runs"][0]
    if indexed:
        run["results"][0]["locations"][0]["physicalLocation"]["artifactLocation"] = {"index": 0}
    run["artifacts"].append({"location": {"uri": "unrelated.go"}, "hashes": {"sha-256": "b" * 64}})
    [span] = parse(doc).locations
    assert span.symbol == "api.Handle"
    assert span.hashes == (CodeHash(algorithm=FILE_BYTES_SHA256, digest="a" * 64),)


@pytest.mark.parametrize("fault", ["absent", "other-repo", "other-commit", "ambiguous", "caller"])
def test_unavailable_producer_binding_does_not_promote_a_claim(fault: str) -> None:
    doc = document()
    vcs = doc["runs"][0]["versionControlProvenance"]
    if fault == "absent":
        vcs.clear()
    elif fault == "other-repo":
        vcs[0]["repositoryUri"] = "https://github.com/example/other"
    elif fault == "other-commit":
        vcs[0]["revisionId"] = "b" * 40
    elif fault == "ambiguous":
        vcs.append({"repositoryUri": REPO, "revisionId": "b" * 40})
    assert parse(doc, bound=fault != "caller").locations[0].hashes == ()


@pytest.mark.parametrize(
    "fault", ["index", "bool-index", "uri-conflict", "duplicate-uri", "digest", "hashes"]
)
def test_malformed_or_ambiguous_artifact_claim_is_a_typed_error(fault: str) -> None:
    doc = document()
    run = doc["runs"][0]
    reference = run["results"][0]["locations"][0]["physicalLocation"]["artifactLocation"]
    if fault == "index":
        reference["index"] = 5
    elif fault == "bool-index":
        reference["index"] = True
    elif fault == "uri-conflict":
        reference.update(index=0, uri="other.go")
    elif fault == "duplicate-uri":
        run["artifacts"].append(copy.deepcopy(run["artifacts"][0]))
    elif fault == "digest":
        run["artifacts"][0]["hashes"]["sha-256"] = "a" * 64 + "\x00suffix"
    else:
        run["artifacts"][0]["hashes"] = []
    with pytest.raises(ValidationError, match="sarif:"):
        parse(doc)


def test_uri_artifact_resolution_does_not_rescan_artifacts_per_result() -> None:
    class Counted(list):
        passes = 0

        def __iter__(self) -> Iterator[dict]:
            self.passes += 1
            return super().__iter__()

    run = document()["runs"][0]
    artifacts = Counted(
        [
            *run["artifacts"],
            *({"location": {"uri": f"unrelated-{n}.go"}} for n in range(1000)),
        ]
    )
    run["artifacts"] = artifacts
    run["results"] *= 1000
    parsed = list(candidate_formats._sarif_run(run, repository_url=REPO, sha=SHA))
    assert len(parsed) == 1000
    assert all(row["hashes"] for row in parsed)
    assert artifacts.passes <= 2
