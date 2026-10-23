"""Checkov output as facts: the normalizer and gap register tests ported from traust
test_cloud_config_audit.py, test_run_checkov_coverage.py and test_run_checkov_bicep_fallback.py."""

from __future__ import annotations

import json
from pathlib import Path, PurePosixPath
from typing import Any
from uuid import uuid4

import pytest

from traust_core.v1.errors import ConfigError
from traust_core.v1.models.artifacts import CloudConfigAuditArtifact
from traust_core.v1.models.cloud_config import (
    CheckovScan,
    CloudConfigFacts,
    IacInventory,
    audit_candidates,
    audit_judgments,
    provider_of,
    require_checkov,
)

FIXTURES = Path(__file__).parents[2] / "fixtures" / "cloud_config"
SOURCE = FIXTURES / "source"
LEGACY_SNAPSHOT = "68045f8c22717898437d7e35ce61990aa0685350b9fd118fab27fecdc85f0dea"


def block(
    check_type: str = "terraform",
    failed: list[dict[str, Any]] | None = None,
    passed: int = 1,
    parsing_errors: int = 0,
) -> dict[str, Any]:
    failed = (
        failed
        if failed is not None
        else [
            {
                "check_id": "CKV_AWS_20",
                "check_name": "S3 Bucket has an ACL defined which allows public READ access",
                "file_path": "/main.tf",
                "repo_file_path": "/iac/main.tf",
                "file_line_range": [1, 12],
                "resource": "aws_s3_bucket.data",
                "guideline": "https://docs.example/ckv_aws_20",
                "severity": None,
            }
        ]
    )
    return {
        "check_type": check_type,
        "results": {"failed_checks": failed},
        "summary": {
            "passed": passed,
            "failed": len(failed),
            "skipped": 0,
            "parsing_errors": parsing_errors,
        },
    }


def facts(*outputs: Any, **scan: Any) -> CloudConfigFacts:
    raw = tuple(o if isinstance(o, bytes) else json.dumps(o).encode() for o in outputs)
    return CloudConfigFacts.of(CheckovScan(target="myrepo", version="3.3.6", outputs=raw, **scan))


def tree(root: Path, files: dict[str, str]) -> IacInventory:
    for name, text in files.items():
        (root / name).parent.mkdir(parents=True, exist_ok=True)
        (root / name).write_text(text)
    return inventory(root)


def inventory(root: Path) -> IacInventory:
    paths = [PurePosixPath(p.relative_to(root).as_posix()) for p in root.rglob("*") if p.is_file()]
    return IacInventory.count(paths, lambda p: (root / p).read_text())


def test_recorded_checkov_output_matches_the_legacy_runner_byte_for_byte() -> None:
    raw = (FIXTURES / "checkov-3.3.6.json").read_bytes()
    got = facts(raw, roots=("/work/clone-a/myrepo",), inventory=inventory(SOURCE))
    assert (len(got.facts), got.counts.failed, got.counts.passed) == (33, 33, 96)
    assert got.counts.frameworks == ("dockerfile", "kubernetes", "terraform")
    assert [g.split(" file(s)")[0] for g in got.gaps] == [
        "myrepo: 1 .tekton/ PipelineRun",
        "myrepo: 1 OpenShift Template",
    ]
    assert got.snapshot_id == LEGACY_SNAPSHOT
    assert [f.fact_id for f in got.facts] == sorted(f.fact_id for f in got.facts)


def test_a_single_block_and_a_list_of_blocks_normalize_alike() -> None:
    one = facts(block())
    many = facts([block(), block(check_type="kubernetes", failed=[])])
    assert (len(one.facts), one.counts.failed) == (1, 1)
    assert (len(many.facts), many.counts.passed) == (1, 2)
    assert many.counts.frameworks == ("kubernetes", "terraform")


def test_a_fact_carries_the_check_and_is_unrated_without_a_scanner_severity() -> None:
    [f] = facts(block()).facts
    assert f.fact_id.startswith("cca-") and len(f.fact_id) == 16
    assert (f.provider, f.framework, f.scanner_severity) == ("aws", "terraform", "unrated")
    assert (f.file_path, f.resource, f.file_line_range) == (
        "/iac/main.tf",
        "aws_s3_bucket.data",
        (1, 12),
    )


@pytest.mark.parametrize(
    ("reported", "expected"),
    [("HIGH", "high"), ("informational", "informational"), ("x", "unrated")],
)
def test_a_reported_severity_is_kept_only_when_it_is_one_of_ours(
    reported: str, expected: str
) -> None:
    b = block()
    b["results"]["failed_checks"][0]["severity"] = reported
    assert facts(b).facts[0].scanner_severity == expected


def test_fact_ids_are_deterministic_and_independent_of_the_clone_location() -> None:
    a, b = block(), block()
    a["results"]["failed_checks"][0]["repo_file_path"] = "/tmp/clone-a/myrepo/iac/main.tf"
    b["results"]["failed_checks"][0]["repo_file_path"] = "/home/x/myrepo/iac/main.tf"
    fa = facts(a, roots=("/tmp/clone-a/myrepo",)).facts[0]
    fb = facts(b, roots=("", "/home/x/myrepo")).facts[0]
    assert fa.fact_id == fb.fact_id == facts(block()).facts[0].fact_id
    assert fa.file_path == "/iac/main.tf"


@pytest.mark.parametrize(
    ("check_id", "provider"),
    [
        ("CKV_AWS_1", "aws"),
        ("CKV2_AWS_1", "aws"),
        ("CKV2_AZURE_2", "azure"),
        ("CKV_GCP_3", "gcp"),
        ("CKV2_GCP_18", "gcp"),
        ("CKV_K8S_4", "kubernetes"),
        ("CKV_DOCKER_5", "docker"),
        ("CKV2_DOCKER_5", "other"),
        ("CKV_LIN_6", "other"),
    ],
)
def test_checks_roll_up_by_provider_prefix(check_id: str, provider: str) -> None:
    assert provider_of(check_id) == provider


def test_a_containerfile_alias_cites_the_real_path_and_keeps_the_native_fact_id() -> None:
    def dockerfile(path: str, resource: str) -> dict[str, Any]:
        check = {
            "check_id": "CKV_DOCKER_8",
            "check_name": "Ensure the last USER is not root",
            "file_path": path,
            "repo_file_path": path,
            "file_line_range": [2, 2],
            "resource": resource,
        }
        return block("dockerfile", [check], passed=0)

    aliases = {"/vllm-bootc/Dockerfile": "/vllm-bootc/Containerfile"}
    [aliased] = facts(
        dockerfile("/vllm-bootc/Dockerfile", "/vllm-bootc/Dockerfile.USER"), aliases=aliases
    ).facts
    [direct] = facts(
        dockerfile("/vllm-bootc/Containerfile", "/vllm-bootc/Containerfile.USER")
    ).facts
    assert (aliased.file_path, aliased.resource) == (
        "/vllm-bootc/Containerfile",
        "/vllm-bootc/Containerfile.USER",
    )
    assert aliased.fact_id == direct.fact_id


def test_a_repeated_fact_identity_collapses_to_one_row_and_counts_keep_the_raw_total() -> None:
    check = {
        "check_id": "CKV_AZURE_111",
        "check_name": "soft delete",
        "file_path": "/t/kv.bicep",
        "resource": "Microsoft.KeyVault/vaults.[p('kv')]",
    }
    repeated = [{**check, "file_line_range": [n, n + 5]} for n in (1, 100, 200)]
    got = facts(block("arm", repeated, passed=0))
    assert (len(got.facts), got.counts.failed) == (1, 3)
    assert got.facts[0].file_line_range == (1, 6)


def test_a_scan_error_is_the_only_gap_and_no_facts() -> None:
    got = CloudConfigFacts.of(
        CheckovScan(
            target="myrepo",
            version="3.3.6",
            error="timeout after 1800s",
            inventory=IacInventory(terraform=3),
        )
    )
    assert (got.facts, got.counts.passed, got.gaps) == ((), 0, ("myrepo: timeout after 1800s",))


def test_zero_evaluated_checks_is_a_gap_never_a_clean_target() -> None:
    got = facts([])
    assert got.gaps == (
        "myrepo: scan evaluated zero checks — no IaC frameworks detected or scan failed; "
        "treating as not assessed, not clean",
    )


@pytest.mark.parametrize(
    ("recovered", "suffix"),
    [(0, "not assessed"), (2, "not assessed (2 .bicep of them transpile-recovered")],
)
def test_parse_errors_are_a_gap_naming_any_bicep_recovered(recovered: int, suffix: str) -> None:
    got = facts(block(parsing_errors=3), bicep_recovered=recovered)
    [gap] = got.gaps
    assert gap.startswith(f"myrepo: 3 file(s) failed to parse — those files are {suffix}")


def test_unparseable_output_is_a_gap_and_the_rest_still_counts() -> None:
    got = facts(block(), b"{not json", b"")
    assert len(got.facts) == 1
    assert got.gaps == ("myrepo: unparseable checkov JSON output",)


def test_workaround_notes_and_the_target_head_are_carried() -> None:
    notes = {"hidden_path_workaround": "scanned via a non-hidden temp path"}
    got = facts(block(), notes=notes, target_head="abc123")
    assert (got.notes, got.target_head, got.checkov_version) == (notes, "abc123", "3.3.6")


@pytest.mark.parametrize("reported", ["checkov 3.3.5", "", "3.4.0"])
def test_any_checkov_but_the_pinned_one_is_refused(reported: str) -> None:
    with pytest.raises(ConfigError, match=r"pinned 3\.3\.6"):
        require_checkov(reported)
    with pytest.raises(ConfigError):
        CloudConfigFacts.of(CheckovScan(target="t", version=reported))


def test_the_pinned_checkov_is_accepted() -> None:
    assert require_checkov("3.3.6\n") == "3.3.6"


def test_terraform_with_zero_terraform_checks_is_a_gap(tmp_path: Path) -> None:
    inv = tree(tmp_path, {"kafka.tf": 'resource "rhoas_kafka" "k" {}\n'})
    [gap] = inv.gaps([], "repo")
    assert "terraform framework evaluated zero checks" in gap
    assert "rhoas" in gap and "NOT ASSESSED" in gap
    assert inv.gaps(["terraform"], "repo") == []


def test_bicep_with_zero_bicep_checks_is_a_gap(tmp_path: Path) -> None:
    inv = tree(tmp_path, {"infra.bicep": "param location string\n"})
    [gap] = inv.gaps(["terraform"], "repo")
    assert "Bicep" in gap and "NOT ASSESSED" in gap
    assert inv.gaps(["bicep"], "repo") == []


def test_templates_and_tekton_pipelineruns_always_gap() -> None:
    gaps = inventory(SOURCE).gaps(["terraform", "bicep", "dockerfile", "kubernetes"], "myrepo")
    joined = "\n".join(gaps)
    assert "1 OpenShift Template file(s)" in joined
    assert "1 .tekton/ PipelineRun file(s)" in joined
    assert len(gaps) == 2


def test_plain_kubernetes_yaml_and_tekton_outside_dot_tekton_are_not_gaps(tmp_path: Path) -> None:
    inv = tree(
        tmp_path,
        {
            "deploy.yaml": "apiVersion: apps/v1\nkind: Deployment\n",
            "ci/run.yml": "kind: PipelineRun\n",
            ".tekton/task.yaml": "kind: Task\n",
        },
    )
    assert inv == IacInventory()


def test_third_party_and_hidden_dirs_are_not_first_party(tmp_path: Path) -> None:
    inv = tree(
        tmp_path,
        {
            "vendor/m.tf": "{}\n",
            "node_modules/x/main.bicep": "\n",
            ".cache/t.yaml": "kind: Template\n",
            ".tekton/.old/run.yaml": "kind: PipelineRun\n",
        },
    )
    assert inv == IacInventory()


def test_an_empty_checkout_has_no_inventory() -> None:
    assert IacInventory.count([], lambda p: "") == IacInventory()


def test_every_finding_is_a_policy_candidate_anchored_on_its_resource() -> None:
    doc = CloudConfigAuditArtifact.parse((FIXTURES / "myrepo-cloud-config-audit.json").read_bytes())
    repository_id = uuid4()
    candidates = audit_candidates(doc, repository_id)
    assert [c.label for c in candidates] == [f"CCA-myrepo-00{n}" for n in range(1, 7)]
    first = candidates[0]
    assert (first.repository_id, first.rule, first.policy, first.cwes) == (
        repository_id,
        "CKV_AWS_20",
        True,
        ("CWE-732",),
    )
    assert (first.reported_severity, first.title, first.description) == (
        "unrated",
        "S3 bucket ACL allows public READ",
        "",
    )
    assert first.resources == ("aws_s3_bucket.data",)
    [span] = first.locations
    assert (span.path, span.line, span.symbol) == ("iac/main.tf", 1, "aws_s3_bucket.data")
    assert first.origin is None
    assert candidates[4].cwes == ()


def test_the_occurrence_keeps_checkovs_severity_not_the_audits() -> None:
    raw = json.loads((FIXTURES / "myrepo-cloud-config-audit.json").read_text())
    raw["findings"][5].update(scanner_severity="low", severity="medium")
    doc = CloudConfigAuditArtifact.parse(json.dumps(raw).encode())
    assert audit_candidates(doc, uuid4())[5].reported_severity == "low"


def test_every_named_resource_is_identity_even_one_with_no_file() -> None:
    raw = json.loads((FIXTURES / "myrepo-cloud-config-audit.json").read_text())
    raw["findings"][0]["locations"].append({"resource": "aws_s3_bucket.logs"})
    doc = CloudConfigAuditArtifact.parse(json.dumps(raw).encode())
    first = audit_candidates(doc, uuid4())[0]
    assert first.resources == ("aws_s3_bucket.data", "aws_s3_bucket.logs")
    assert [span.symbol for span in first.locations] == ["aws_s3_bucket.data"]


def test_each_status_maps_to_a_validity_and_only_needs_review_asks_a_person() -> None:
    doc = CloudConfigAuditArtifact.parse((FIXTURES / "myrepo-cloud-config-audit.json").read_bytes())
    judged = audit_judgments(doc)
    assert [(label, j.validity, j.review) for label, j in judged] == [
        ("CCA-myrepo-001", "confirmed", None),
        ("CCA-myrepo-002", "confirmed", None),
        ("CCA-myrepo-003", "confirmed", None),
        ("CCA-myrepo-004", "not_verified", "undetermined_finding"),
        ("CCA-myrepo-005", "false_positive", None),
        ("CCA-myrepo-006", "confirmed", None),
    ]
    suppressed = judged[4][1].rationale
    assert suppressed is not None and suppressed.startswith(
        "(facts: cca-d4266ab73726) R5 hygiene: the namespace is set at deploy time"
    )
    assert (
        judged[0][1].rationale
        == "R1 exposure: acl = public-read on the data bucket (iac/main.tf:3)."
    )


@pytest.mark.parametrize(
    ("status", "scanner", "severity"),
    [
        ("confirmed", "low", "medium"),
        ("confirmed", "medium", None),
        ("confirmed", "unrated", "medium"),
        ("needs_review", "low", None),
        ("suppressed", "low", None),
    ],
)
def test_a_confirmed_finding_states_only_a_re_rating(
    status: str, scanner: str, severity: str | None
) -> None:
    raw = json.loads((FIXTURES / "myrepo-cloud-config-audit.json").read_text())
    raw["findings"][5].update(status=status, scanner_severity=scanner)
    doc = CloudConfigAuditArtifact.parse(json.dumps(raw).encode())
    assert audit_judgments(doc)[5][1].severity == severity
