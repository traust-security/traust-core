"""REST regression tests for server-resolved component PURL lease admission and recording."""

from __future__ import annotations

import json
from collections.abc import Iterator
from pathlib import Path
from typing import Any
from uuid import UUID

import pytest
from fastapi.testclient import TestClient
from sqlalchemy.engine import Engine

from tests.fixtures.component_purl.builder import PinnedFixture, build_spring_fixture
from tests.v1.conftest import SQL_BACKENDS, contract_db
from tests.v1.repositories.tables.conftest import T0, Seed
from traust_core.v1.context import Config, Context
from traust_core.v1.context.config import ProcessConfig, RecordingConfig
from traust_core.v1.models.assessment import AssessmentKind
from traust_core.v1.models.common import PageRequest
from traust_core.v1.models.operations import AssetName, OrderFilter, RecordingStartScope
from traust_core.v1.models.values import GitSha, LocalRepoUrl
from traust_core.v1.providers.clock import FixedClock
from traust_core.v1.providers.local import LocalCheckout
from traust_core.v1.providers.process import ProcessRunner
from traust_core.v1.providers.sources import CheckoutRequest, Workspace
from traust_core.v1.repositories.contract import SqlTraustUnitOfWork
from traust_core.v1.rest.app import create_app
from traust_core.v1.services.identity import IdentityConfig


class _MappedLocalCheckouts:
    """Serves a fixture repo URL from a local pinned git checkout without touching the network."""

    def __init__(self, repo_url: str, local_path: Path) -> None:
        self._repo_url = repo_url
        self._origin = LocalRepoUrl.parse(local_path.as_uri())
        self._local = LocalCheckout(ProcessRunner(allowed=("git",)), FixedClock(T0))

    def checkout(self, request: CheckoutRequest) -> Any:
        assert str(request.repo) == self._repo_url
        mapped = CheckoutRequest(
            repo=self._origin,
            ref=GitSha.parse(str(request.ref)),
            shared=request.shared,
            writable=request.writable,
        )
        return self._local.checkout(mapped)

    def release(self, workspace: Workspace) -> None:
        self._local.release(workspace)


@pytest.fixture(params=SQL_BACKENDS)
def engine(request: pytest.FixtureRequest, tmp_path: Path) -> Iterator[Engine]:
    with contract_db(request.param, tmp_path) as database:
        yield database


def _auth(token: str) -> dict[str, str]:
    return {"Authorization": f"Bearer {token}"}


def _setup(
    engine: Engine, tmp_path: Path
) -> tuple[Context, TestClient, PinnedFixture, str, str, str, str]:
    spring = build_spring_fixture(tmp_path)
    with SqlTraustUnitOfWork(engine) as uow:
        seed = Seed(uow)
        repo = seed.repository(url=spring.repo_url)
        seed.repository_ref(
            repository_id=repo.id, name="main", kind="branch", is_default=True, sha=spring.commit
        )
        ref = seed.repository_ref(
            repository_id=repo.id, name="v7.1.0", kind="tag", sha=spring.commit
        )
        uow.commit()
    assert repo.id is not None and ref.id is not None
    context = Context(
        Config(
            home=tmp_path / "home",
            identity=IdentityConfig(trust_local=True),
            process=ProcessConfig(allowed_binaries=("git",)),
            recording=RecordingConfig(
                assessment=(AssetName("sci_scan"),),
                start=(
                    RecordingStartScope(
                        principal="machine:runner-7",
                        assets=(AssetName("sci_scan"),),
                        repository_ids=(repo.id,),
                    ),
                ),
            ),
        ),
    )
    context.__dict__["database"] = engine
    context.__dict__["checkouts"] = _MappedLocalCheckouts(spring.repo_url, spring.path)
    assert context.identity is not None
    runner_tok = context.local_issuer.mint("runner-7", machine=True).token.get_secret_value()
    person_tok = context.local_issuer.mint(
        "alice@example.com", machine=False
    ).token.get_secret_value()
    return (
        context,
        TestClient(create_app(context)),
        spring,
        str(repo.id),
        str(ref.id),
        runner_tok,
        person_tok,
    )


def _report_json(repo_url: str, commit: str, purl: str, module_path: str, title: str) -> str:
    return json.dumps(
        {
            "title": title,
            "metadata": {
                "date": "2026-11-22",
                "scope": f"Component PURL audit of {purl} ({module_path})",
                "repository": repo_url,
                "commit": commit,
                "audit_profile": "code",
                "target": {
                    "purl": purl,
                    "repository": repo_url,
                    "commit": commit,
                    "module_path": module_path,
                    "release_ref": "v7.1.0",
                    "verification": {
                        "strategy": "shared_release",
                        "manifest_paths": [
                            "pom.xml",
                            f"{module_path}/pom.xml",
                        ],
                    },
                },
            },
            "executive_summary": {
                "prose": "Fresh initial source audit of pinned component target in monorepo.",
                "severity_counts": {
                    "critical": 0,
                    "high": 0,
                    "medium": 0,
                    "low": 0,
                    "informational": 0,
                },
            },
            "severity_criteria": [
                {"level": "critical", "definition": "Remote compromise without authentication."},
                {"level": "high", "definition": "High-impact cross-tenant exposure or bypass."},
                {"level": "medium", "definition": "Scoped weakness under extra preconditions."},
                {"level": "low", "definition": "Defense-in-depth hardening gap."},
            ],
            "findings": [],
            "findings_summary": [
                {"severity": sev, "count": 0, "finding_ids": []}
                for sev in ("critical", "high", "medium", "low")
            ],
            "remediation_roadmap": [
                {
                    "priority": "p3",
                    "addresses": ["NONE"],
                    "action": "No remediation required for clean fixture report.",
                    "effort": "xs",
                }
            ],
        }
    )


def test_mismatched_purl_and_module_path_cannot_obtain_a_lease_or_queue(
    engine: Engine, tmp_path: Path
) -> None:
    context, client, spring, repo_id, ref_id, runner_tok, person_tok = _setup(engine, tmp_path)

    # 1. Mismatched (PURL, module_path) on POST /v1/orders/start -> 422, no lease created.
    bad_start = client.post(
        "/v1/orders/start",
        headers=_auth(runner_tok),
        json={
            "order": {
                "asset": "sci_scan",
                "priority": 1,
                "repository_id": repo_id,
                "target_purl": "pkg:maven/org.springframework/spring-beans@7.1.0",
                "target_sha": spring.commit,
                "target_module_path": "spring-context",
            },
            "lease_seconds": 300,
        },
    )
    assert bad_start.status_code == 422, bad_start.text
    assert "supplied_path_conflict" in bad_start.text

    # 2. Mismatched (PURL, module_path) on POST /v1/orders -> 422, nothing queued.
    bad_submit = client.post(
        "/v1/orders",
        headers=_auth(person_tok),
        json={
            "order": {
                "asset": "sci_scan",
                "priority": 1,
                "repository_id": repo_id,
                "target_purl": "pkg:maven/org.springframework/spring-beans@7.1.0",
                "target_sha": spring.commit,
                "target_module_path": "spring-context",
            }
        },
    )
    assert bad_submit.status_code == 422, bad_submit.text
    assert "supplied_path_conflict" in bad_submit.text

    # 3. Unverified version -> 422, no lease created.
    bad_ver = client.post(
        "/v1/orders/start",
        headers=_auth(runner_tok),
        json={
            "order": {
                "asset": "sci_scan",
                "priority": 1,
                "repository_id": repo_id,
                "target_purl": "pkg:maven/org.springframework/spring-beans@9.9.9",
                "target_sha": spring.commit,
            },
            "lease_seconds": 300,
        },
    )
    assert bad_ver.status_code == 422, bad_ver.text
    assert "version_mismatch" in bad_ver.text

    # Confirm ZERO orders were persisted by any refused request.
    listed = context.services().ops.list(
        OrderFilter(asset=AssetName("sci_scan"), repository_id=UUID(repo_id)), PageRequest()
    )
    assert listed.items == ()

    # 4. Valid PURL with omitted target_module_path -> server resolves "spring-beans" and leases.
    started = client.post(
        "/v1/orders/start",
        headers=_auth(runner_tok),
        json={
            "order": {
                "asset": "sci_scan",
                "priority": 1,
                "repository_id": repo_id,
                "target_purl": "pkg:maven/org.springframework/spring-beans@7.1.0",
                "target_sha": spring.commit,
            },
            "lease_seconds": 300,
        },
    )
    assert started.status_code == 200, started.text
    order = started.json()
    assert order["target_purl"] == "pkg:maven/org.springframework/spring-beans@7.1.0"
    assert order["target_sha"] == spring.commit
    assert order["target_module_path"] == "spring-beans"

    # 4b. GET /v1/orders/{id}/manifest exposes the full authoritative component_target
    # (including release_ref and verification.strategy / manifest_paths) for worker staging.
    manifest_resp = client.get(f"/v1/orders/{order['id']}/manifest", headers=_auth(runner_tok))
    assert manifest_resp.status_code == 200, manifest_resp.text
    manifest_target = manifest_resp.json()["component_target"]
    assert manifest_target["purl"] == "pkg:maven/org.springframework/spring-beans@7.1.0"
    assert manifest_target["release_ref"] == "v7.1.0"
    assert manifest_target["verification"]["strategy"] == "shared_release"
    assert manifest_target["verification"]["manifest_paths"] == ["pom.xml", "spring-beans/pom.xml"]

    # 4c. Tampering verification.strategy (reconstructed/altered target) is refused (403).
    tampered_doc = json.loads(
        _report_json(
            spring.repo_url,
            spring.commit,
            "pkg:maven/org.springframework/spring-beans@7.1.0",
            "spring-beans",
            "Spring Beans Security Audit",
        )
    )
    tampered_doc["metadata"]["target"]["verification"]["strategy"] = "package_release"
    tampered = client.post(
        "/v1/assessment-records",
        headers=_auth(runner_tok),
        json={
            "run_order_id": order["id"],
            "lease_generation": order["lease_generation"],
            "repository_ref_id": ref_id,
            "assessor_version": "1.0.0",
            "provenance": {
                "run_id": order["id"],
                "source": "vuln_scan_report",
                "occurred_at": T0.isoformat(),
            },
            "payload": json.dumps(tampered_doc),
        },
    )
    assert tampered.status_code == 403, tampered.text

    # 5. Sibling-B report at the same (repo, SHA) is refused on sibling-A's lease (403).
    swapped = client.post(
        "/v1/assessment-records",
        headers=_auth(runner_tok),
        json={
            "run_order_id": order["id"],
            "lease_generation": order["lease_generation"],
            "repository_ref_id": ref_id,
            "assessor_version": "1.0.0",
            "provenance": {
                "run_id": order["id"],
                "source": "vuln_scan_report",
                "occurred_at": T0.isoformat(),
            },
            "payload": _report_json(
                spring.repo_url,
                spring.commit,
                "pkg:maven/org.springframework/spring-context@7.1.0",
                "spring-context",
                "Spring Context Security Audit",
            ),
        },
    )
    assert swapped.status_code == 403, swapped.text

    # 6. Matching sibling-A report succeeds and stamps target_purl.
    ok = client.post(
        "/v1/assessment-records",
        headers=_auth(runner_tok),
        json={
            "run_order_id": order["id"],
            "lease_generation": order["lease_generation"],
            "repository_ref_id": ref_id,
            "assessor_version": "1.0.0",
            "provenance": {
                "run_id": order["id"],
                "source": "vuln_scan_report",
                "occurred_at": T0.isoformat(),
            },
            "payload": _report_json(
                spring.repo_url,
                spring.commit,
                "pkg:maven/org.springframework/spring-beans@7.1.0",
                "spring-beans",
                "Spring Beans Security Audit",
            ),
        },
    )
    assert ok.status_code == 200, ok.text
    latest = context.services().assessment.latest_recorded(
        UUID(repo_id),
        AssessmentKind.SECURE_CODE_CANONICAL,
        target_purl="pkg:maven/org.springframework/spring-beans@7.1.0",
    )
    assert latest.target_purl == "pkg:maven/org.springframework/spring-beans@7.1.0"

    # 7. Repository-set listing filters by target_purl (including equivalent PURL spelling).
    listed_beans = client.get(
        "/v1/assessments",
        headers=_auth(person_tok),
        params={
            "repository_ids": [repo_id],
            # an informational qualifier is the same target; an identity one (classifier) isn't
            "target_purl": (
                "pkg:maven/org.springframework/spring-beans@7.1.0"
                "?repository_url=https://repo.example.invalid"
            ),
        },
    )
    assert listed_beans.status_code == 200, listed_beans.text
    assert len(listed_beans.json()["items"]) == 1
    assert (
        listed_beans.json()["items"][0]["target_purl"]
        == "pkg:maven/org.springframework/spring-beans@7.1.0"
    )

    listed_other = client.get(
        "/v1/assessments",
        headers=_auth(person_tok),
        params={
            "repository_ids": [repo_id],
            "target_purl": "pkg:maven/org.springframework/spring-context@7.1.0",
        },
    )
    assert listed_other.status_code == 200, listed_other.text
    assert listed_other.json()["items"] == []

    # 8. OpsService.plan resolves component targets, rejects unverified hints, and deduplicates.
    from traust_core.v1.errors import UnresolvedTargetError
    from traust_core.v1.models.identity import Principal
    from traust_core.v1.models.operations import OrderRequest
    from traust_core.v1.models.vocabulary import ActorKind

    planner = Principal(
        identity="engine", display="Engine", kind=ActorKind.MACHINE, verified_by="oidc"
    )
    with pytest.raises(UnresolvedTargetError):
        context.services().ops.plan(
            OrderRequest(
                asset=AssetName("sci_scan"),
                priority=1,
                repository_id=UUID(repo_id),
                target_purl="pkg:maven/org.springframework/spring-beans@7.1.0",
                target_sha=spring.commit,
                target_module_path="spring-context",
            ),
            planner,
        )
    planned_1 = context.services().ops.plan(
        OrderRequest(
            asset=AssetName("sci_scan"),
            priority=1,
            repository_id=UUID(repo_id),
            target_purl="pkg:maven/org.springframework/spring-context@7.1.0",
            target_sha=spring.commit,
        ),
        planner,
    )
    assert planned_1.target_module_path == "spring-context"
    assert planned_1.artifact_id is not None
    assert context.services().ops.manifest(planned_1.id).component_target is not None
    planned_2 = context.services().ops.plan(
        OrderRequest(
            asset=AssetName("sci_scan"),
            priority=1,
            repository_id=UUID(repo_id),
            target_purl="pkg:maven/org.springframework/spring-context@7.1.0",
            target_sha=spring.commit,
        ),
        planner,
    )
    assert planned_2.id == planned_1.id


def test_open_order_dedup_keys_by_purl_and_sha_and_verifies_external_provenance(
    engine: Engine, tmp_path: Path
) -> None:
    import base64
    import hashlib

    from cryptography.hazmat.primitives import serialization
    from cryptography.hazmat.primitives.asymmetric import ed25519

    from tests.fixtures.component_purl.builder import _fixture_git
    from traust_core.v1.models.identity import Principal
    from traust_core.v1.models.operations import OrderRequest
    from traust_core.v1.models.vocabulary import ActorKind
    from traust_core.v1.providers.provenance import (
        DsseProvenanceVerifier,
        ProvenanceTrustPolicy,
        TrustedProvenanceKey,
        dsse_pae,
    )

    context, client, spring, repo_id, _ref_id, runner_tok, person_tok = _setup(engine, tmp_path)
    # Create a second pinned commit in the same fixture repo with the same manifest version
    # (e.g. a second tagged/rebuilt commit for the same PURL) plus a release tag.
    readme = spring.path / "spring-beans" / "NOTES.txt"
    readme.write_text("second pinned commit\n", encoding="utf-8")
    _fixture_git(spring.path, "add", "-A")
    _fixture_git(spring.path, "commit", "-q", "-m", "second commit")
    sha_2 = _fixture_git(spring.path, "rev-parse", "HEAD")
    _fixture_git(spring.path, "tag", "release-7.1.0")
    assert sha_2 != spring.commit

    with SqlTraustUnitOfWork(engine) as uow:
        seed = Seed(uow)
        ref_2 = seed.repository_ref(
            repository_id=UUID(repo_id), name="release-7.1.0", kind="tag", sha=sha_2
        )
        uow.commit()
    assert ref_2.id is not None

    planner = Principal(
        identity="engine", display="Engine", kind=ActorKind.MACHINE, verified_by="oidc"
    )
    purl = "pkg:maven/org.springframework/spring-beans@7.1.0"

    # 1. Same PURL at sha_1 and sha_2 creates two PLANNED orders; repeating sha_1 deduplicates.
    p_sha1 = context.services().ops.plan(
        OrderRequest(
            asset=AssetName("sci_scan"),
            priority=1,
            repository_id=UUID(repo_id),
            target_purl=purl,
            target_sha=spring.commit,
        ),
        planner,
    )
    p_sha2 = context.services().ops.plan(
        OrderRequest(
            asset=AssetName("sci_scan"),
            priority=1,
            repository_id=UUID(repo_id),
            target_purl=purl,
            target_sha=sha_2,
        ),
        planner,
    )
    assert p_sha1.id != p_sha2.id
    assert (
        context.services()
        .ops.plan(
            OrderRequest(
                asset=AssetName("sci_scan"),
                priority=1,
                repository_id=UUID(repo_id),
                target_purl=purl,
                target_sha=spring.commit,
            ),
            planner,
        )
        .id
        == p_sha1.id
    )

    # The start door takes over only an admitted (queued) order (traust-core c129551d): the
    # engine's admission queues these planned orders first.
    context.services().ops.admit(p_sha1.id)
    context.services().ops.admit(p_sha2.id)

    # 2. Leasing sha_1 does NOT collide with leasing sha_2 via POST /v1/orders/start.
    lease_1 = client.post(
        "/v1/orders/start",
        headers=_auth(runner_tok),
        json={
            "order": {
                "asset": "sci_scan",
                "priority": 1,
                "repository_id": repo_id,
                "target_purl": purl,
                "target_sha": spring.commit,
            },
            "lease_seconds": 300,
        },
    )
    assert lease_1.status_code == 200, lease_1.text
    assert lease_1.json()["id"] == str(p_sha1.id)

    lease_2 = client.post(
        "/v1/orders/start",
        headers=_auth(runner_tok),
        json={
            "order": {
                "asset": "sci_scan",
                "priority": 1,
                "repository_id": repo_id,
                "target_purl": purl,
                "target_sha": sha_2,
            },
            "lease_seconds": 300,
        },
    )
    assert lease_2.status_code == 200, lease_2.text
    assert lease_2.json()["id"] == str(p_sha2.id)

    # 3. Unconfigured verifier rejects target_provenance on POST /v1/orders/start (422).
    priv = ed25519.Ed25519PrivateKey.generate()
    pub_pem = (
        priv.public_key()
        .public_bytes(serialization.Encoding.PEM, serialization.PublicFormat.SubjectPublicKeyInfo)
        .decode("utf-8")
    )
    ext_purl = "pkg:maven/org.springframework/spring-beans@7.1.0.rebuild-2"
    stmt = {
        "_type": "https://in-toto.io/Statement/v1",
        "subject": [{"uri": ext_purl}],
        "predicateType": "https://slsa.dev/provenance/v1",
        "predicate": {
            "repository": spring.repo_url,
            "commit": sha_2,
            "ref": "release-7.1.0",
            "manifest_version": "7.1.0",
        },
    }
    payload_bytes = json.dumps(stmt, sort_keys=True).encode("utf-8")
    payload_digest = f"sha256:{hashlib.sha256(payload_bytes).hexdigest()}"
    sig = priv.sign(dsse_pae("application/vnd.in-toto+json", payload_bytes))
    dsse_env = {
        "payloadType": "application/vnd.in-toto+json",
        "payload": base64.b64encode(payload_bytes).decode("ascii"),
        "signatures": [{"keyid": "k1", "sig": base64.b64encode(sig).decode("ascii")}],
    }

    unverified = client.post(
        "/v1/orders/start",
        headers=_auth(runner_tok),
        json={
            "order": {
                "asset": "sci_scan",
                "priority": 1,
                "repository_id": repo_id,
                "target_purl": ext_purl,
                "target_sha": sha_2,
                "target_provenance": dsse_env,
            },
            "lease_seconds": 300,
        },
    )
    assert unverified.status_code == 422, unverified.text
    assert "provenance_unverified" in unverified.text

    # 4. Configured verifier authenticates target_provenance and binds assessment recording.
    context._provenance_verifier = DsseProvenanceVerifier(
        ProvenanceTrustPolicy(
            trusted_keys=(TrustedProvenanceKey(key_id="k1", public_key_pem=pub_pem),),
            allowed_sources=("https://slsa.dev/provenance/v1",),
        )
    )
    context.__dict__.pop("component_targets", None)  # the resolver holds the verifier
    ext_client = TestClient(create_app(context))
    ext_lease = ext_client.post(
        "/v1/orders/start",
        headers=_auth(runner_tok),
        json={
            "order": {
                "asset": "sci_scan",
                "priority": 1,
                "repository_id": repo_id,
                "target_purl": ext_purl,
                "target_sha": sha_2,
                "target_release_ref": "release-7.1.0",
                "target_provenance": dsse_env,
            },
            "lease_seconds": 300,
        },
    )
    assert ext_lease.status_code == 200, ext_lease.text
    ext_order = ext_lease.json()
    manifest_target = ext_client.get(
        f"/v1/orders/{ext_order['id']}/manifest", headers=_auth(runner_tok)
    ).json()["component_target"]
    assert manifest_target["verification"]["strategy"] == "external_provenance"
    assert manifest_target["verification"]["provenance"] == {
        "source": "https://slsa.dev/provenance/v1",
        "ref": "release-7.1.0",
        "digest": payload_digest,
        "manifest_version": "7.1.0",
    }

    ext_report = json.loads(
        _report_json(spring.repo_url, sha_2, ext_purl, "spring-beans", "Spring Beans Rebuild Audit")
    )
    ext_report["metadata"]["target"] = manifest_target
    recorded = ext_client.post(
        "/v1/assessment-records",
        headers=_auth(runner_tok),
        json={
            "run_order_id": ext_order["id"],
            "lease_generation": ext_order["lease_generation"],
            "repository_ref_id": str(ref_2.id),
            "assessor_version": "1.0.0",
            "provenance": {
                "run_id": ext_order["id"],
                "source": "vuln_scan_report",
                "occurred_at": T0.isoformat(),
            },
            "payload": json.dumps(ext_report),
        },
    )
    assert recorded.status_code == 200, recorded.text

    # 5. Submit external_provenance-only target via POST /v1/orders, then take over the queued
    #    order via POST /v1/orders/start WITHOUT re-sending the raw provenance envelope (matching
    #    SCI AgenticCadence.start). Raw envelope is never persisted, and ad-hoc/forged starts
    #    still fail closed.
    ext_purl_queued = "pkg:maven/org.springframework/spring-beans@7.1.0.rebuild-3"
    stmt_q = {
        "_type": "https://in-toto.io/Statement/v1",
        "subject": [{"uri": ext_purl_queued}],
        "predicateType": "https://slsa.dev/provenance/v1",
        "predicate": {
            "repository": spring.repo_url,
            "commit": sha_2,
            "ref": "release-7.1.0",
            "manifest_version": "7.1.0",
        },
    }
    payload_q = json.dumps(stmt_q, sort_keys=True).encode("utf-8")
    digest_q = f"sha256:{hashlib.sha256(payload_q).hexdigest()}"
    sig_q = priv.sign(dsse_pae("application/vnd.in-toto+json", payload_q))
    dsse_env_q = {
        "payloadType": "application/vnd.in-toto+json",
        "payload": base64.b64encode(payload_q).decode("ascii"),
        "signatures": [{"keyid": "k1", "sig": base64.b64encode(sig_q).decode("ascii")}],
    }

    # 5a. Ad-hoc start WITHOUT queued order and WITHOUT envelope fails closed (422).
    adhoc_no_env = ext_client.post(
        "/v1/orders/start",
        headers=_auth(runner_tok),
        json={
            "order": {
                "asset": "sci_scan",
                "priority": 1,
                "repository_id": repo_id,
                "target_purl": ext_purl_queued,
                "target_sha": sha_2,
                "target_module_path": "spring-beans",
            },
            "lease_seconds": 300,
        },
    )
    assert adhoc_no_env.status_code == 422, adhoc_no_env.text

    # 5b. Submit via POST /v1/orders with valid envelope -> planned (the engine's admission
    # queues it, traust-core c129551d), no raw envelope on order.
    queued_resp = ext_client.post(
        "/v1/orders",
        headers=_auth(person_tok),
        json={
            "order": {
                "asset": "sci_scan",
                "priority": 1,
                "repository_id": repo_id,
                "target_purl": ext_purl_queued,
                "target_sha": sha_2,
                "target_release_ref": "release-7.1.0",
                "target_provenance": dsse_env_q,
            }
        },
    )
    assert queued_resp.status_code == 200, queued_resp.text
    queued_order = queued_resp.json()
    assert queued_order["state"] == "planned"
    assert "target_provenance" not in queued_order

    # 5c. Forged target_provenance on start STILL fails closed (422) even with queued order.
    forged_start = ext_client.post(
        "/v1/orders/start",
        headers=_auth(runner_tok),
        json={
            "order": {
                "asset": "sci_scan",
                "priority": 1,
                "repository_id": repo_id,
                "target_purl": ext_purl_queued,
                "target_sha": sha_2,
                "target_module_path": "spring-beans",
                "target_provenance": {**dsse_env_q, "signatures": [{"keyid": "k1", "sig": "AAAA"}]},
            },
            "lease_seconds": 300,
        },
    )
    assert forged_start.status_code == 422, forged_start.text
    assert "provenance_unverified" in forged_start.text

    # 5d. Conflicting target_module_path on takeover fails closed (409).
    wrong_mod_start = ext_client.post(
        "/v1/orders/start",
        headers=_auth(runner_tok),
        json={
            "order": {
                "asset": "sci_scan",
                "priority": 1,
                "repository_id": repo_id,
                "target_purl": ext_purl_queued,
                "target_sha": sha_2,
                "target_module_path": "spring-context",
            },
            "lease_seconds": 300,
        },
    )
    assert wrong_mod_start.status_code == 409, wrong_mod_start.text

    # 5e. Exact queued takeover WITHOUT envelope leases the same order and keeps verified manifest.
    # Only an admitted (queued) order can be taken over (traust-core c129551d).
    context.services().ops.admit(UUID(queued_order["id"]))
    takeover = ext_client.post(
        "/v1/orders/start",
        headers=_auth(runner_tok),
        json={
            "order": {
                "asset": "sci_scan",
                "priority": 1,
                "repository_id": repo_id,
                "target_purl": ext_purl_queued,
                "target_sha": sha_2,
                "target_module_path": "spring-beans",
            },
            "lease_seconds": 300,
        },
    )
    assert takeover.status_code == 200, takeover.text
    taken_order = takeover.json()
    assert taken_order["id"] == queued_order["id"]
    assert taken_order["state"] == "leased"
    taken_manifest = ext_client.get(
        f"/v1/orders/{taken_order['id']}/manifest", headers=_auth(runner_tok)
    ).json()["component_target"]
    assert taken_manifest["verification"]["strategy"] == "external_provenance"
    assert taken_manifest["verification"]["provenance"] == {
        "source": "https://slsa.dev/provenance/v1",
        "ref": "release-7.1.0",
        "digest": digest_q,
        "manifest_version": "7.1.0",
    }

    # 5f. Recording an assessment bound to the taken-over order succeeds with verified manifest.
    taken_report = json.loads(
        _report_json(
            spring.repo_url,
            sha_2,
            ext_purl_queued,
            "spring-beans",
            "Spring Beans Queued Rebuild Audit",
        )
    )
    taken_report["metadata"]["target"] = taken_manifest
    recorded_q = ext_client.post(
        "/v1/assessment-records",
        headers=_auth(runner_tok),
        json={
            "run_order_id": taken_order["id"],
            "lease_generation": taken_order["lease_generation"],
            "repository_ref_id": str(ref_2.id),
            "assessor_version": "1.0.0",
            "provenance": {
                "run_id": taken_order["id"],
                "source": "vuln_scan_report",
                "occurred_at": T0.isoformat(),
            },
            "payload": json.dumps(taken_report),
        },
    )
    assert recorded_q.status_code == 200, recorded_q.text


def test_a_takeover_naming_another_release_tag_is_refused_not_leased(
    engine: Engine, tmp_path: Path
) -> None:
    # Recording binds the whole verified target, release tag included: a lease on another tag
    # of the same commit could never record, only hold the order until its lease ran out.
    from tests.fixtures.component_purl.builder import _fixture_git
    from traust_core.v1.models.identity import Principal
    from traust_core.v1.models.operations import OrderRequest
    from traust_core.v1.models.vocabulary import ActorKind

    context, client, spring, repo_id, _ref_id, runner_tok, _person = _setup(engine, tmp_path)
    _fixture_git(spring.path, "tag", "release-7.1.0")  # a second release tag at the same commit
    purl = "pkg:maven/org.springframework/spring-beans@7.1.0"
    planner = Principal(
        identity="engine", display="Engine", kind=ActorKind.MACHINE, verified_by="oidc"
    )
    planned = context.services().ops.plan(
        OrderRequest(
            asset=AssetName("sci_scan"),
            priority=1,
            repository_id=UUID(repo_id),
            target_purl=purl,
            target_sha=spring.commit,
            target_release_ref=spring.tag,
        ),
        planner,
    )
    context.services().ops.admit(planned.id)

    def start(release_ref: str) -> Any:
        return client.post(
            "/v1/orders/start",
            headers=_auth(runner_tok),
            json={
                "order": {
                    "asset": "sci_scan",
                    "priority": 1,
                    "repository_id": repo_id,
                    "target_purl": purl,
                    "target_sha": spring.commit,
                    "target_module_path": "spring-beans",
                    "target_release_ref": release_ref,
                },
                "lease_seconds": 300,
            },
        )

    other = start("release-7.1.0")
    assert other.status_code == 409, other.text
    assert context.services().ops.get(planned.id).state == "queued"  # not held by a dead lease
    same = start(spring.tag)
    assert same.status_code == 200, same.text
    assert same.json()["id"] == str(planned.id)
