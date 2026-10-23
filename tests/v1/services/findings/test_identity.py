"""Finding identity, ported from traust-ledger's identity tests and vectors at d1b589a."""

from __future__ import annotations

import hashlib
import json
from pathlib import Path
from typing import Any

import pytest

from traust_core.v1.errors import ValidationError
from traust_core.v1.models.integrity import Fingerprint, FingerprintInput
from traust_core.v1.services.findings.identity import (
    ALGO_LADDER,
    ALGO_VERSION,
    IdentityPolicy,
    ascii_lower,
    ascii_upper,
    canon_path,
    canon_repo,
    primary_cwe,
)

FIXTURES = Path(__file__).parents[3] / "fixtures" / "findings"
RECIPE = json.loads((FIXTURES / "identity-recipe-vectors.json").read_text(encoding="utf-8"))
CONFORMANCE = json.loads((FIXTURES / "finding-identity-vectors.json").read_text(encoding="utf-8"))
REPO = "https://github.com/org/repo"
POLICY = IdentityPolicy()


def fp(finding: dict[str, Any], repo: str | None = REPO, *, strict: bool = False) -> str:
    return POLICY.match_key(FingerprintInput.from_report(finding, repo), strict=strict).value


def attribute(finding: dict[str, Any], stamp: str, repos: list[str | None]) -> str | None:
    return POLICY.attribute(FingerprintInput.from_report(finding, None), stamp, repos)


def cwe(finding: dict[str, Any]) -> str:
    return primary_cwe(FingerprintInput.from_report(finding, None))


def digest(repo: str, paths: list[str], cwe_part: str) -> str:
    payload = "|".join([canon_repo(repo), ";".join(paths), cwe_part])
    return hashlib.sha256(payload.encode()).hexdigest()


def code(paths: list[str], cwes: tuple[str, ...] = ("CWE-79",)) -> dict[str, Any]:
    return {"locations": [{"path": p} for p in paths], "cwes": list(cwes)}


def cloud(resources: list[str], cwe_id: str | None = None, files: list[str] | None = None) -> dict:
    locs = [
        {"resource": r, "file_line_range": [1, 5], **({"file_path": files[i]} if files else {})}
        for i, r in enumerate(resources)
    ]
    return {"locations": locs, **({"cwe": cwe_id} if cwe_id else {})}


def test_match_key_stamps_the_current_version() -> None:
    key = POLICY.match_key(FingerprintInput.from_report(code(["a.go"]), REPO))
    assert key == Fingerprint("v3", digest(REPO, ["a.go"], "CWE-79"))
    assert ALGO_VERSION == "v3"


def test_a_fingerprint_is_a_version_and_a_hex_digest() -> None:
    with pytest.raises(ValidationError):
        Fingerprint("v3", "not-hex")
    with pytest.raises(ValidationError):
        Fingerprint("", "a" * 64)


# The recipe vectors (12 cases from the retired contracts golden suite) and conformance vectors
def test_recipe_vectors_are_pinned_to_this_version_and_not_shrinking() -> None:
    assert RECIPE["algo_version"] == ALGO_VERSION
    names = [v["name"] for v in RECIPE["vectors"]]
    assert len(names) >= 12
    assert len(set(names)) == len(names)


@pytest.mark.parametrize("vector", RECIPE["vectors"], ids=[v["name"] for v in RECIPE["vectors"]])
def test_recipe_vector(vector: dict[str, Any]) -> None:
    given, norm = vector["input"], vector.get("normalized") or {}
    assert fp(given["finding"], given["repo_url"]) == vector["expected_fingerprint"]
    if "canon_repo" in norm:
        assert canon_repo(given["repo_url"]) == norm["canon_repo"]
    if "primary_cwe" in norm:
        assert cwe(given["finding"]) == norm["primary_cwe"]


def test_v3_moved_only_the_multi_cwe_vector() -> None:
    moved = [v["name"] for v in RECIPE["vectors"] if v.get("moved_in_v3")]
    assert moved == ["multiple_cwes_lowest_number_upper_trim"]
    for v in RECIPE["vectors"]:
        if not v.get("moved_in_v3"):
            assert v["expected_fingerprint"] == v["v1_expected_fingerprint"]


def test_strict_refuses_the_empty_pathset_vector_the_lenient_recipe_hashes() -> None:
    vector = next(v for v in RECIPE["vectors"] if v["name"] == "no_locations_empty_pathset")
    given = vector["input"]
    assert fp(given["finding"], given["repo_url"]) == vector["expected_fingerprint"]
    with pytest.raises(ValidationError):
        fp(given["finding"], given["repo_url"], strict=True)


@pytest.mark.parametrize("case", CONFORMANCE["canon_repo"])
def test_canon_repo_conformance(case: dict[str, str]) -> None:
    assert canon_repo(case["input"]) == case["expected"]


@pytest.mark.parametrize("case", CONFORMANCE["canon_path"])
def test_canon_path_conformance(case: dict[str, str]) -> None:
    assert canon_path(case["input"]) == case["expected"]


@pytest.mark.parametrize("case", CONFORMANCE["fingerprint"], ids=lambda c: c["name"])
def test_fingerprint_conformance(case: dict[str, Any]) -> None:
    assert fp(case["finding"], case["repo_url"]) == case["expected"]


def test_conformance_keeps_the_hard_cases() -> None:
    names = " ".join(c["name"] for c in CONFORMANCE["fingerprint"])
    for marker in ("dedupe", "CWE-0", "no locations", "subgroup", "broken metadata"):
        assert marker in names


# Case folding, blank CWE, empty paths (divergences measured against the Go SDK)
@pytest.mark.parametrize("ch", ["\u0130", "\u0131", "\u00df", "\u1e9e", "\u212a", "\u017f"])
def test_case_folding_is_ascii_only(ch: str) -> None:
    assert ascii_lower("ABZ") == "abz"
    assert ascii_upper("abz") == "ABZ"
    assert ascii_lower(ch) == ch
    assert ascii_upper(ch) == ch


def test_canon_repo_does_not_fold_non_ascii() -> None:
    assert (
        canon_repo("https://github.com/ORG/\u0130stanbul") == "https://github.com/org/\u0130stanbul"
    )


@pytest.mark.parametrize("cwes", [[], [""], ["   "], None])
def test_absent_or_blank_cwe_is_cwe_0(cwes: list[str] | None) -> None:
    assert cwe({"cwes": cwes}) == "CWE-0"
    assert cwe({}) == "CWE-0"


@pytest.mark.parametrize(
    ("cwes", "expected"),
    [
        (["CWE-937", "CWE-1104"], "CWE-937"),
        (["CWE-1104", "CWE-937"], "CWE-937"),
        (["CWE-89", "CWE-79", "CWE-352"], "CWE-79"),
        (["  cwe-79  "], "CWE-79"),
        (["CWE-xx", "CWE-79"], "CWE-79"),
        (["CWE-xx"], "CWE-XX"),
    ],
)
def test_primary_cwe_is_the_lowest_number_not_lexicographic(cwes: list[str], expected: str) -> None:
    assert cwe({"cwes": cwes}) == expected


def test_identity_does_not_depend_on_cwe_order() -> None:
    assert fp(code(["cmd/main.go"], ("CWE-89", "CWE-79"))) == fp(
        code(["cmd/main.go"], ("CWE-79", "CWE-89"))
    )
    assert fp(code(["cmd/main.go"], ("CWE-937", "CWE-1104"))) == fp(
        code(["cmd/main.go"], ("CWE-937",))
    )


@pytest.mark.parametrize("marker", [".", "/", "./", "/./"])
def test_repo_root_markers_drop_out_of_the_path_set(marker: str) -> None:
    assert canon_path(marker) == ""
    assert fp(code([marker, "src/a.go"])) == fp(code(["src/a.go"]))
    assert fp(code([marker])) == fp(code([]))


@pytest.mark.parametrize("marker", [".", "/", "./", "/./"])
def test_strict_refuses_no_usable_location_and_names_the_escape_hatch(marker: str) -> None:
    with pytest.raises(ValidationError, match=r"repo-scope-path\.json"):
        fp(code([marker]), strict=True)
    with pytest.raises(ValidationError):
        fp(code([]), strict=True)


def test_strict_changes_no_accepted_hash_and_takes_pseudo_paths() -> None:
    for paths in (["src/a.go"], ["src/a.go", "b.go"], [".", "src/a.go"], ["repo:maintenance"]):
        assert fp(code(paths)) == fp(code(paths), strict=True)
    assert fp(code(["repo:maintenance"]), strict=True) != fp(
        code(["repo:scorecard-onboarding"]), strict=True
    )


def test_lenient_is_the_default_until_the_corpus_is_migrated() -> None:
    assert fp(code(["."]))


# Cloud-config shape and the policy check
def test_resource_anchors_identity_when_path_is_absent() -> None:
    assert fp(cloud(["RoleBinding.ns.name"], "CWE-284")) == digest(
        REPO, ["RoleBinding.ns.name"], "CWE-284"
    )


def test_resource_beats_file_path_and_path_beats_resource() -> None:
    moved = cloud(["RoleBinding.ns.name"], "CWE-284", ["/deploy/a.yaml"])
    renamed = cloud(["RoleBinding.ns.name"], "CWE-284", ["/deploy_pko/B.yaml"])
    assert fp(moved) == fp(renamed)
    both = {"locations": [{"path": "a/b.go", "resource": "Ignored.me"}], "cwes": ["CWE-79"]}
    assert fp(both) == digest(REPO, ["a/b.go"], "CWE-79")


def test_widening_to_resources_moves_no_existing_hash() -> None:
    assert fp(code(["a/b.go"], ("CWE-276", "CWE-250"))) == digest(REPO, ["a/b.go"], "CWE-250")
    assert fp({"locations": [{"path": "a/b.go"}]}) == digest(REPO, ["a/b.go"], "CWE-0")


def test_the_check_separates_findings_on_one_resource_only_when_present() -> None:
    base = cloud(["Pod.default.app"], "CWE-250")
    assert fp({**base, "check_id": "CKV_K8S_11"}) != fp({**base, "check_id": "CKV_K8S_12"})
    assert fp({**base, "check_id": "CKV_K8S_11"}) == fp({**base, "check_id": "ckv_k8s_11"})
    plain = code(["a/b.go"])
    for empty in ("", None):
        assert fp({**plain, "check_id": empty}) == digest(REPO, ["a/b.go"], "CWE-79")
    assert fp({**plain, "check_id": "CKV_1"}) == digest(REPO, ["a/b.go"], "CWE-79|CKV_1")


def test_one_check_on_one_resource_split_across_files_is_one_identity() -> None:
    a = cloud(["Spec.api.types"], "CWE-20", ["/api/v1/types.json"])
    b = cloud(["Spec.api.types"], "CWE-20", ["/tooling/openapi.yaml"])
    a["check_id"] = b["check_id"] = "CKV_OPENAPI_21"
    assert fp(a) == fp(b)


# Attribution: which historical recipe minted an unversioned stamp
def test_the_ladder_is_newest_first() -> None:
    assert [v for v, _, _ in ALGO_LADDER] == ["v3", "v2", "v1"]


def test_attribution_recognises_each_rung() -> None:
    current = code(["a/b.go"])
    assert attribute(current, fp(current), [REPO]) == "v3"
    reordered = code(["a/b.go"], ("CWE-276", "CWE-250"))
    assert attribute(reordered, digest(REPO, ["a/b.go"], "CWE-276"), [REPO]) == "v2"
    rooted = code([".", "src/a.go"])
    assert attribute(rooted, digest(REPO, ["", "src/a.go"], "CWE-79"), [REPO]) == "v1"


def test_an_unnormalized_repository_string_is_a_candidate_not_a_rung() -> None:
    finding = code(["a/b.go"])
    wrapped = f"<{REPO}>"
    stamp = digest(wrapped, ["a/b.go"], "CWE-79")
    assert attribute(finding, stamp, [REPO]) is None
    assert attribute(finding, stamp, [REPO, wrapped]) == "v3"


def test_unknown_stamps_attribute_to_nothing_and_candidates_may_repeat() -> None:
    finding = code(["a/b.go"])
    assert attribute(finding, "f" * 64, [REPO]) is None
    assert attribute(finding, "", [REPO]) is None
    assert attribute(finding, fp(finding), [None, REPO, REPO, None]) == "v3"


@pytest.mark.parametrize(
    "finding",
    [
        code(["a/b.go"]),
        cloud(["RoleBinding.ns.name"], "CWE-284"),
        cloud(["A.b.c", "D.e.f"], "CWE-732"),
        {"locations": [{"path": "x.go"}, {"resource": "R.s.t"}], "cwes": ["CWE-1", "CWE-2"]},
        {**cloud(["Pod.default.app"], "CWE-250"), "check_id": "CKV_K8S_11"},
    ],
)
def test_the_newest_rung_tracks_the_live_recipe(finding: dict[str, Any]) -> None:
    assert attribute(finding, fp(finding), [REPO]) == ALGO_VERSION


def test_frozen_rungs_see_only_what_their_recipe_read() -> None:
    rungs = {version: (paths_of, cwe_of) for version, paths_of, cwe_of in ALGO_LADDER}
    resource_only = FingerprintInput.from_report(cloud(["RoleBinding.ns.name"], "CWE-284"), REPO)
    checked = FingerprintInput.from_report({**code(["a/b.go"]), "check_id": "CKV_1"}, REPO)
    for frozen in ("v2", "v1"):
        paths_of, cwe_of = rungs[frozen]
        assert paths_of(resource_only) in ([], [""])
        assert cwe_of(resource_only) == "CWE-0"
        assert cwe_of(checked) == "CWE-79"
    paths_of, cwe_of = rungs["v3"]
    assert paths_of(resource_only) == ["RoleBinding.ns.name"]
    assert cwe_of(resource_only) == "CWE-284"
    assert cwe_of(checked) == "CWE-79|CKV_1"
