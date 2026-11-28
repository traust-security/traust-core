"""Unit tests for deterministic component PURL resolution (Spring, LangChain, Pi, negatives)."""

from __future__ import annotations

import base64
import hashlib
import json
from pathlib import Path
from typing import Any

import pytest
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ed25519
from pydantic import ValidationError as PydanticValidationError

from traust_core.v1.context.documents import yaml_documents
from traust_core.v1.errors import ConfigError, UnresolvedTargetError
from traust_core.v1.models.component_target import (
    ComponentTarget,
    ComponentTargetRequest,
    ComponentTargetStrategy,
    ComponentTargetVerification,
    UnresolvedTargetReason,
    canonical_component_purl,
    normalize_module_path,
)
from traust_core.v1.providers.checkout import GitCheckout
from traust_core.v1.providers.package_manifests import PackageManifestScanner
from traust_core.v1.providers.process import ProcessRunner
from traust_core.v1.providers.provenance import (
    DsseProvenanceVerifier,
    ProvenanceTrustPolicy,
    TrustedProvenanceKey,
    dsse_pae,
)
from traust_core.v1.services.component_target import ComponentTargetResolver

_GIT = ProcessRunner(("git",))
# The runtime's seam: its keep-list env means a git hook's GIT_DIR never reaches fixture git.
_FIXTURE_ENV = {
    "GIT_CONFIG_GLOBAL": "/dev/null",
    "GIT_CONFIG_SYSTEM": "/dev/null",
    "GIT_AUTHOR_NAME": "Fixture",
    "GIT_AUTHOR_EMAIL": "fixture@example.invalid",
    "GIT_COMMITTER_NAME": "Fixture",
    "GIT_COMMITTER_EMAIL": "fixture@example.invalid",
}


def _git(repo: Path, *args: str) -> str:
    return _GIT.run(["git", "-C", str(repo), *args], env=_FIXTURE_ENV).stdout.decode().strip()


def _init_repo(
    root: Path,
    files: dict[str, str],
    tags: tuple[str, ...] = (),
    *,
    sha256: bool = False,
) -> str:
    root.mkdir(parents=True, exist_ok=True)
    init_args = ["init", "--quiet", "-b", "main"]
    if sha256:
        init_args.append("--object-format=sha256")
    _git(root, *init_args)
    for rel, content in files.items():
        path = root / rel
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(content, encoding="utf-8")
    _git(root, "add", ".")
    _git(root, "commit", "--quiet", "-m", "fixture commit")
    sha = _git(root, "rev-parse", "HEAD")
    for tag in tags:
        _git(root, "tag", tag)
    return sha


def _resolver(verifier: DsseProvenanceVerifier | None = None) -> ComponentTargetResolver:
    return ComponentTargetResolver(
        GitCheckout(ProcessRunner(allowed=("git",))),
        PackageManifestScanner(yaml_documents),
        provenance_verifier=verifier,
    )


def _sign_dsse(
    private_key: ed25519.Ed25519PrivateKey,
    key_id: str,
    statement: dict[str, Any],
    payload_type: str = "application/vnd.in-toto+json",
) -> tuple[dict[str, Any], str]:
    payload_bytes = json.dumps(statement, sort_keys=True).encode("utf-8")
    sig = private_key.sign(dsse_pae(payload_type, payload_bytes))
    digest = f"sha256:{hashlib.sha256(payload_bytes).hexdigest()}"
    envelope = {
        "payloadType": payload_type,
        "payload": base64.b64encode(payload_bytes).decode("ascii"),
        "signatures": [
            {
                "keyid": key_id,
                "sig": base64.b64encode(sig).decode("ascii"),
            }
        ],
    }
    return envelope, digest


def test_shared_release_maven_multi_module_resolves_sibling_modules(tmp_path: Path) -> None:
    repo = tmp_path / "spring-framework"
    sha = _init_repo(
        repo,
        {
            "pom.xml": (
                "<project><modelVersion>4.0.0</modelVersion>"
                "<groupId>org.springframework</groupId>"
                "<artifactId>spring-framework-parent</artifactId>"
                "<version>7.1.0</version><packaging>pom</packaging>"
                "<modules><module>spring-core</module><module>spring-beans</module>"
                "<module>spring-context</module></modules></project>\n"
            ),
            "spring-core/pom.xml": (
                "<project><parent><groupId>org.springframework</groupId>"
                "<artifactId>spring-framework-parent</artifactId>"
                "<version>7.1.0</version></parent>"
                "<artifactId>spring-core</artifactId></project>\n"
            ),
            "spring-beans/pom.xml": (
                "<project><parent><groupId>org.springframework</groupId>"
                "<artifactId>spring-framework-parent</artifactId>"
                "<version>7.1.0</version></parent>"
                "<artifactId>spring-beans</artifactId></project>\n"
            ),
            "spring-context/pom.xml": (
                "<project><parent><groupId>org.springframework</groupId>"
                "<artifactId>spring-framework-parent</artifactId>"
                "<version>7.1.0</version></parent>"
                "<artifactId>spring-context</artifactId></project>\n"
            ),
        },
        tags=("v7.1.0",),
    )
    resolver = _resolver()

    beans = resolver.resolve(
        ComponentTargetRequest(
            purl="pkg:maven/org.springframework/spring-beans@7.1.0",
            repository="https://github.com/spring-projects/spring-framework",
            commit=sha,
        ),
        repo,
    )
    context = resolver.resolve(
        ComponentTargetRequest(
            purl="pkg:maven/org.springframework/spring-context@7.1.0",
            repository="https://github.com/spring-projects/spring-framework",
            commit=sha,
        ),
        repo,
    )

    assert beans.module_path == "spring-beans"
    assert beans.release_ref == "v7.1.0"
    assert beans.verification.strategy is ComponentTargetStrategy.SHARED_RELEASE
    assert beans.verification.manifest_paths == ("pom.xml", "spring-beans/pom.xml")
    assert context.module_path == "spring-context"
    assert context.commit == beans.commit == sha


def test_langchain_style_package_release_tag_resolves(tmp_path: Path) -> None:
    repo = tmp_path / "langchain"
    sha = _init_repo(
        repo,
        {
            "libs/core/pyproject.toml": ('[project]\nname = "langchain-core"\nversion = "1.8.4"\n'),
            "libs/langchain/pyproject.toml": ('[project]\nname = "langchain"\nversion = "1.2.0"\n'),
        },
        tags=("langchain-core==1.8.4",),
    )
    resolved = _resolver().resolve(
        ComponentTargetRequest(
            purl="pkg:pypi/langchain-core@1.8.4",
            repository="https://github.com/langchain-ai/langchain",
            release_ref="langchain-core==1.8.4",
        ),
        repo,
    )
    assert resolved.commit == sha
    assert resolved.module_path == "libs/core"
    assert resolved.release_ref == "langchain-core==1.8.4"
    assert resolved.verification.strategy is ComponentTargetStrategy.PACKAGE_RELEASE
    assert resolved.verification.manifest_paths == ("libs/core/pyproject.toml",)


def test_pi_style_public_workspace_ignores_private_root_version(tmp_path: Path) -> None:
    repo = tmp_path / "pi"
    sha = _init_repo(
        repo,
        {
            "package.json": json.dumps(
                {
                    "name": "pi-monorepo",
                    "private": True,
                    "version": "0.0.1-private",
                    "workspaces": ["packages/*"],
                }
            ),
            "packages/ai/package.json": json.dumps(
                {"name": "@earendil-works/pi-ai", "version": "1.6.0"}
            ),
            "packages/coding-agent/package.json": json.dumps(
                {"name": "@earendil-works/pi-coding-agent", "version": "1.6.0"}
            ),
        },
        tags=("v1.6.0",),
    )
    resolved = _resolver().resolve(
        ComponentTargetRequest(
            purl="pkg:npm/%40earendil-works/pi-ai@1.6.0",
            repository="https://github.com/earendil-works/pi",
            commit=sha,
        ),
        repo,
    )
    assert resolved.module_path == "packages/ai"
    assert resolved.verification.strategy is ComponentTargetStrategy.WORKSPACE_PACKAGE
    assert "packages/ai/package.json" in resolved.verification.manifest_paths

    # Matching only the private root version must be rejected.
    with pytest.raises(UnresolvedTargetError) as exc:
        _resolver().resolve(
            ComponentTargetRequest(
                purl="pkg:npm/%40earendil-works/pi-ai@0.0.1-private",
                repository="https://github.com/earendil-works/pi",
                commit=sha,
            ),
            repo,
        )
    assert exc.value.reason == UnresolvedTargetReason.VERSION_MISMATCH

    with pytest.raises(UnresolvedTargetError) as root_exc:
        _resolver().resolve(
            ComponentTargetRequest(
                purl="pkg:npm/pi-monorepo@0.0.1-private",
                repository="https://github.com/earendil-works/pi",
                commit=sha,
            ),
            repo,
        )
    assert root_exc.value.reason == UnresolvedTargetReason.PRIVATE_ROOT_ONLY


def test_unresolved_rejects_dir_name_only_default_branch_and_conflicts(tmp_path: Path) -> None:
    repo = tmp_path / "monorepo"
    sha = _init_repo(
        repo,
        {
            # Directory name matches "spring-beans" but there is no manifest declaring it.
            "spring-beans/Cache.java": "class Cache {}\n",
            "libs/core/pyproject.toml": '[project]\nname = "demo-core"\nversion = "2.0.0"\n',
        },
        tags=("demo-core==2.0.0",),
    )
    resolver = _resolver()

    with pytest.raises(UnresolvedTargetError) as dir_only:
        resolver.resolve(
            ComponentTargetRequest(
                purl="pkg:maven/org.springframework/spring-beans@7.1.0",
                repository="https://github.com/example/monorepo",
                commit=sha,
            ),
            repo,
        )
    assert dir_only.value.reason == UnresolvedTargetReason.NO_MANIFEST_MATCH

    with pytest.raises(UnresolvedTargetError) as default_branch:
        resolver.resolve(
            ComponentTargetRequest(
                purl="pkg:pypi/demo-core@2.0.0",
                repository="https://github.com/example/monorepo",
                ref_kind="default",
            ),
            repo,
        )
    assert default_branch.value.reason == UnresolvedTargetReason.DEFAULT_BRANCH_DISALLOWED

    with pytest.raises(UnresolvedTargetError) as unversioned:
        resolver.resolve(
            ComponentTargetRequest(
                purl="pkg:pypi/demo-core",
                repository="https://github.com/example/monorepo",
                commit=sha,
            ),
            repo,
        )
    assert unversioned.value.reason == UnresolvedTargetReason.MISSING_VERSION

    with pytest.raises(UnresolvedTargetError) as path_conflict:
        resolver.resolve(
            ComponentTargetRequest(
                purl="pkg:pypi/demo-core@2.0.0",
                repository="https://github.com/example/monorepo",
                commit=sha,
                module_path="libs/wrong",
            ),
            repo,
        )
    assert path_conflict.value.reason == UnresolvedTargetReason.SUPPLIED_PATH_CONFLICT

    with pytest.raises(UnresolvedTargetError) as tag_conflict:
        resolver.resolve(
            ComponentTargetRequest(
                purl="pkg:pypi/demo-core@2.0.0",
                repository="https://github.com/example/monorepo",
                commit="0" * 40,
                release_ref="demo-core==2.0.0",
            ),
            repo,
        )
    assert tag_conflict.value.reason == UnresolvedTargetReason.TAG_COMMIT_MISMATCH


def test_declarative_gradle_groovy_and_kotlin_dsl_resolve(tmp_path: Path) -> None:
    groovy_repo = tmp_path / "gradle-groovy"
    sha_groovy = _init_repo(
        groovy_repo,
        {
            "gradle.properties": "version=7.1.0\ngroup=org.springframework\n",
            "settings.gradle": (
                'rootProject.name = "spring"\n'
                'include "spring-core", "spring-beans", "spring-context"\n'
            ),
            "spring-beans/spring-beans.gradle": 'description = "Spring Beans"\n',
            "spring-context/spring-context.gradle": 'description = "Spring Context"\n',
        },
        tags=("v7.1.0",),
    )
    beans = _resolver().resolve(
        ComponentTargetRequest(
            purl="pkg:maven/org.springframework/spring-beans@7.1.0",
            repository="https://github.com/spring-projects/spring-framework",
            commit=sha_groovy,
        ),
        groovy_repo,
    )
    assert beans.module_path == "spring-beans"
    assert beans.verification.strategy is ComponentTargetStrategy.SHARED_RELEASE
    assert beans.verification.manifest_paths == (
        "gradle.properties",
        "settings.gradle",
        "spring-beans/spring-beans.gradle",
    )

    kts_repo = tmp_path / "gradle-kts"
    sha_kts = _init_repo(
        kts_repo,
        {
            "gradle.properties": "version=2.4.0\ngroup=io.example\n",
            "settings.gradle.kts": (
                'rootProject.name = "platform"\n'
                'include(\n    ":core-api",\n    ":custom-mod",\n)\n'
                'project(":custom-mod").projectDir = file("modules/custom")\n'
            ),
            "modules/custom/build.gradle.kts": 'artifactId = "custom-artifact"\n',
        },
        tags=("platform-2.4.0",),
    )
    custom = _resolver().resolve(
        ComponentTargetRequest(
            purl="pkg:maven/io.example/custom-artifact@2.4.0",
            repository="https://github.com/example/platform",
            commit=sha_kts,
        ),
        kts_repo,
    )
    assert custom.module_path == "modules/custom"
    assert custom.release_ref == "platform-2.4.0"
    assert custom.verification.strategy is ComponentTargetStrategy.SHARED_RELEASE
    assert custom.verification.manifest_paths == (
        "gradle.properties",
        "modules/custom/build.gradle.kts",
        "settings.gradle.kts",
    )


def test_dynamic_or_incomplete_gradle_builds_fail_closed(tmp_path: Path) -> None:
    dyn_repo = tmp_path / "gradle-dyn"
    sha_dyn = _init_repo(
        dyn_repo,
        {
            "gradle.properties": "group=org.example\n",
            "settings.gradle.kts": 'include(":mod-a", ":undeclared-only")\n',
            "mod-a/build.gradle.kts": "version = computeVersion()\n",
            "orphan/build.gradle.kts": 'group = "org.example"\nversion = "1.0.0"\n',
        },
        tags=("v1.0.0",),
    )
    with pytest.raises(UnresolvedTargetError) as dyn_exc:
        _resolver().resolve(
            ComponentTargetRequest(
                purl="pkg:maven/org.example/mod-a@1.0.0",
                repository="https://github.com/example/gradle-dyn",
                commit=sha_dyn,
            ),
            dyn_repo,
        )
    assert dyn_exc.value.reason == UnresolvedTargetReason.VERSION_MISMATCH

    with pytest.raises(UnresolvedTargetError) as orphan_exc:
        _resolver().resolve(
            ComponentTargetRequest(
                purl="pkg:maven/org.example/orphan@1.0.0",
                repository="https://github.com/example/gradle-dyn",
                commit=sha_dyn,
            ),
            dyn_repo,
        )
    assert orphan_exc.value.reason == UnresolvedTargetReason.NO_MANIFEST_MATCH

    no_group = tmp_path / "gradle-no-group"
    sha_ng = _init_repo(
        no_group,
        {
            "gradle.properties": "version=1.0.0\n",
            "settings.gradle": 'include "mod-a"\n',
            "mod-a/build.gradle": 'description = "missing group"\n',
        },
        tags=("v1.0.0",),
    )
    with pytest.raises(UnresolvedTargetError) as ng_exc:
        _resolver().resolve(
            ComponentTargetRequest(
                purl="pkg:maven/org.example/mod-a@1.0.0",
                repository="https://github.com/example/gradle-no-group",
                commit=sha_ng,
            ),
            no_group,
        )
    assert ng_exc.value.reason == UnresolvedTargetReason.NO_MANIFEST_MATCH


def test_pnpm_workspace_yaml_resolves_via_injected_yaml_loader(tmp_path: Path) -> None:
    repo = tmp_path / "pnpm-mono"
    sha = _init_repo(
        repo,
        {
            "package.json": json.dumps({"name": "root", "private": True, "version": "0.0.0"}),
            "pnpm-workspace.yaml": "packages:\n  - 'packages/*'\n  - '!packages/ignored'\n",
            "packages/sdk/package.json": json.dumps({"name": "@acme/sdk", "version": "3.2.1"}),
            "packages/ignored/package.json": json.dumps(
                {"name": "@acme/ignored", "version": "3.2.1"}
            ),
        },
        tags=("v3.2.1",),
    )
    resolved = _resolver().resolve(
        ComponentTargetRequest(
            purl="pkg:npm/%40acme/sdk@3.2.1",
            repository="https://github.com/acme/pnpm-mono",
            commit=sha,
        ),
        repo,
    )
    assert resolved.module_path == "packages/sdk"
    assert resolved.verification.strategy is ComponentTargetStrategy.WORKSPACE_PACKAGE
    assert "pnpm-workspace.yaml" in resolved.verification.manifest_paths


def test_maven_parent_requires_all_three_coordinates_and_respects_empty_relative_path(
    tmp_path: Path,
) -> None:
    repo = tmp_path / "maven-parent-guards"
    sha = _init_repo(
        repo,
        {
            "pom.xml": (
                "<project><modelVersion>4.0.0</modelVersion>"
                "<groupId>org.example</groupId><artifactId>parent</artifactId>"
                "<version>2.0.0</version><packaging>pom</packaging>"
                "<properties><release.version>2.0.0</release.version></properties>"
                "</project>\n"
            ),
            # Parent version mismatch (1.0.0 != 2.0.0): must NOT borrow root ${release.version}.
            "bad-ver/pom.xml": (
                "<project><parent><groupId>org.example</groupId><artifactId>parent</artifactId>"
                "<version>1.0.0</version></parent>"
                "<artifactId>bad-ver</artifactId>"
                "<version>${release.version}</version></project>\n"
            ),
            # Empty <relativePath/> disables local parent lookup even when coordinates match.
            "no-local/pom.xml": (
                "<project><parent><groupId>org.example</groupId><artifactId>parent</artifactId>"
                "<version>2.0.0</version><relativePath/></parent>"
                "<artifactId>no-local</artifactId>"
                "<version>${release.version}</version></project>\n"
            ),
            # Nested module with explicit <relativePath> and matching 3 coordinates resolves.
            "services/good/pom.xml": (
                "<project><parent><groupId>org.example</groupId><artifactId>parent</artifactId>"
                "<version>2.0.0</version><relativePath>../../pom.xml</relativePath></parent>"
                "<artifactId>good</artifactId></project>\n"
            ),
        },
        tags=("v2.0.0",),
    )
    resolver = _resolver()

    with pytest.raises(UnresolvedTargetError) as bad_ver:
        resolver.resolve(
            ComponentTargetRequest(
                purl="pkg:maven/org.example/bad-ver@2.0.0",
                repository="https://github.com/example/maven-parent-guards",
                commit=sha,
            ),
            repo,
        )
    assert bad_ver.value.reason == UnresolvedTargetReason.VERSION_MISMATCH

    with pytest.raises(UnresolvedTargetError) as no_local:
        resolver.resolve(
            ComponentTargetRequest(
                purl="pkg:maven/org.example/no-local@2.0.0",
                repository="https://github.com/example/maven-parent-guards",
                commit=sha,
            ),
            repo,
        )
    assert no_local.value.reason == UnresolvedTargetReason.VERSION_MISMATCH

    good = resolver.resolve(
        ComponentTargetRequest(
            purl="pkg:maven/org.example/good@2.0.0",
            repository="https://github.com/example/maven-parent-guards",
            commit=sha,
        ),
        repo,
    )
    assert good.module_path == "services/good"
    assert good.verification.strategy is ComponentTargetStrategy.SHARED_RELEASE
    assert good.verification.manifest_paths == ("pom.xml", "services/good/pom.xml")


def test_npm_workspace_single_star_does_not_match_nested_fixture_package(tmp_path: Path) -> None:
    repo = tmp_path / "npm-glob"
    sha = _init_repo(
        repo,
        {
            "package.json": json.dumps(
                {
                    "name": "root",
                    "private": True,
                    "version": "0.0.0",
                    "workspaces": ["packages/*", "deep/**"],
                }
            ),
            "packages/ai/package.json": json.dumps({"name": "@acme/ai", "version": "1.0.0"}),
            # Nested under packages/ai/examples — must NOT match single-segment `packages/*`.
            "packages/ai/nested/demo/package.json": json.dumps(
                {"name": "@acme/demo", "version": "1.0.0"}
            ),
            # Nested under deep/** — MUST match multi-segment `**`.
            "deep/a/b/package.json": json.dumps({"name": "@acme/deep-pkg", "version": "1.0.0"}),
        },
        tags=("v1.0.0",),
    )
    resolver = _resolver()
    with pytest.raises(UnresolvedTargetError) as nested:
        resolver.resolve(
            ComponentTargetRequest(
                purl="pkg:npm/%40acme/demo@1.0.0",
                repository="https://github.com/acme/npm-glob",
                commit=sha,
            ),
            repo,
        )
    assert nested.value.reason == UnresolvedTargetReason.NO_MANIFEST_MATCH

    deep = resolver.resolve(
        ComponentTargetRequest(
            purl="pkg:npm/%40acme/deep-pkg@1.0.0",
            repository="https://github.com/acme/npm-glob",
            commit=sha,
        ),
        repo,
    )
    assert deep.module_path == "deep/a/b"
    assert deep.verification.strategy is ComponentTargetStrategy.WORKSPACE_PACKAGE


def test_untagged_workspace_commit_fails_closed(tmp_path: Path) -> None:
    repo = tmp_path / "npm-untagged"
    sha = _init_repo(
        repo,
        {
            "package.json": json.dumps(
                {"name": "root", "private": True, "workspaces": ["packages/*"]}
            ),
            "packages/pkg-a/package.json": json.dumps({"name": "@acme/pkg-a", "version": "1.0.0"}),
        },
        tags=("unrelated-branch-tag",),
    )
    with pytest.raises(UnresolvedTargetError) as exc:
        _resolver().resolve(
            ComponentTargetRequest(
                purl="pkg:npm/%40acme/pkg-a@1.0.0",
                repository="https://github.com/acme/npm-untagged",
                commit=sha,
                release_ref="unrelated-branch-tag",
            ),
            repo,
        )
    assert exc.value.reason == UnresolvedTargetReason.NO_MANIFEST_MATCH


def test_component_commit_accepts_40_and_64_hex_and_rejects_invalid_lengths(tmp_path: Path) -> None:
    repo40 = tmp_path / "sha1-pin"
    sha40 = _init_repo(
        repo40,
        {"libs/core/pyproject.toml": '[project]\nname = "demo-core"\nversion = "1.0.0"\n'},
        tags=("demo-core==1.0.0",),
    )
    repo64 = tmp_path / "sha256-pin"
    sha64 = _init_repo(
        repo64,
        {"libs/core/pyproject.toml": '[project]\nname = "demo-core"\nversion = "1.0.0"\n'},
        tags=("demo-core==1.0.0",),
        sha256=True,
    )
    assert len(sha64) == 64
    resolver = _resolver()

    res64 = resolver.resolve(
        ComponentTargetRequest(
            purl="pkg:pypi/demo-core@1.0.0",
            repository="https://github.com/example/sha256-pin",
            commit=f"  {sha64.upper()}  ",
        ),
        repo64,
    )
    assert res64.commit == sha64

    for bad_commit in ("a" * 39, "a" * 41, "a" * 63, "a" * 65, "xyz"):
        with pytest.raises(UnresolvedTargetError) as bad_exc:
            resolver.resolve(
                ComponentTargetRequest(
                    purl="pkg:pypi/demo-core@1.0.0",
                    repository="https://github.com/example/sha1-pin",
                    commit=bad_commit,
                ),
                repo40,
            )
        assert bad_exc.value.reason == UnresolvedTargetReason.MISSING_PIN
        with pytest.raises(PydanticValidationError):
            ComponentTarget(
                purl="pkg:pypi/demo-core@1.0.0",
                repository="https://github.com/example/sha1-pin",
                commit=bad_commit,
                module_path="libs/core",
                verification=ComponentTargetVerification(
                    strategy=ComponentTargetStrategy.PACKAGE_RELEASE,
                    manifest_paths=("libs/core/pyproject.toml",),
                ),
            )

    upper40 = resolver.resolve(
        ComponentTargetRequest(
            purl="pkg:pypi/demo-core@1.0.0",
            repository="https://github.com/example/sha1-pin",
            commit=f"  {sha40.upper()}  ",
        ),
        repo40,
    )
    assert upper40.commit == sha40


def test_maven_child_pom_resolves_root_defined_revision_in_parent_version(tmp_path: Path) -> None:
    repo = tmp_path / "maven-revision"
    sha = _init_repo(
        repo,
        {
            "pom.xml": (
                "<project>\n"
                "  <groupId>org.example</groupId>\n"
                "  <artifactId>parent-bom</artifactId>\n"
                "  <version>${revision}</version>\n"
                "  <properties><revision>3.4.5</revision></properties>\n"
                "</project>\n"
            ),
            "child-mod/pom.xml": (
                "<project>\n"
                "  <parent>\n"
                "    <groupId>org.example</groupId>\n"
                "    <artifactId>parent-bom</artifactId>\n"
                "    <version>${revision}</version>\n"
                "  </parent>\n"
                "  <artifactId>child-mod</artifactId>\n"
                "</project>\n"
            ),
        },
        tags=("v3.4.5",),
    )
    target = _resolver().resolve(
        ComponentTargetRequest(
            purl="pkg:maven/org.example/child-mod@3.4.5",
            repository="https://github.com/example/maven-revision",
            commit=sha,
        ),
        repo,
    )
    assert target.module_path == "child-mod"
    assert target.verification.strategy is ComponentTargetStrategy.SHARED_RELEASE
    assert target.verification.manifest_paths == ("child-mod/pom.xml", "pom.xml")


def test_equivalent_purl_spellings_canonicalize_to_same_key(tmp_path: Path) -> None:
    repo = tmp_path / "canon-purls"
    sha = _init_repo(
        repo,
        {
            "package.json": '{"name": "root", "private": true, "workspaces": ["packages/*"]}',
            "packages/cache/package.json": '{"name": "@acme/cache-lib", "version": "1.2.0"}',
            "libs/core/pyproject.toml": '[project]\nname = "LangChain_Core"\nversion = "1.8.4"\n',
        },
        tags=("v1.2.0", "langchain-core==1.8.4"),
    )
    resolver = _resolver()
    npm_literal = resolver.resolve(
        ComponentTargetRequest(
            purl="pkg:npm/@acme/cache-lib@1.2.0",
            repository="https://github.com/example/canon-purls",
            commit=sha,
        ),
        repo,
    )
    npm_encoded = resolver.resolve(
        ComponentTargetRequest(
            purl="pkg:npm/%40acme/cache-lib@1.2.0?vcs_url=git+https://example.com",
            repository="https://github.com/example/canon-purls",
            commit=sha,
        ),
        repo,
    )
    assert npm_literal.purl == npm_encoded.purl == "pkg:npm/%40acme/cache-lib@1.2.0"

    py_mixed = resolver.resolve(
        ComponentTargetRequest(
            # an informational qualifier (where it was fetched) is no part of the identity
            purl="pkg:PyPI/LangChain_Core@1.8.4?repository_url=https://pypi.example.invalid",
            repository="https://github.com/example/canon-purls",
            commit=sha,
        ),
        repo,
    )
    py_canon = resolver.resolve(
        ComponentTargetRequest(
            purl="pkg:pypi/langchain-core@1.8.4",
            repository="https://github.com/example/canon-purls",
            commit=sha,
        ),
        repo,
    )
    assert py_mixed.purl == py_canon.purl == "pkg:pypi/langchain-core@1.8.4"


@pytest.mark.parametrize(
    ("repo_url", "tag", "version"),
    [
        ("https://github.com/apache/cxf", "cxf-3.6.9", "3.6.9"),
        ("https://github.com/netty/netty.git", "netty-4.1.100.Final", "4.1.100.Final"),
        ("https://github.com/apache/zookeeper", "zookeeper-3.8.3", "3.8.3"),
    ],
)
def test_project_prefixed_shared_release_tags_resolve(
    tmp_path: Path, repo_url: str, tag: str, version: str
) -> None:
    repo = tmp_path / tag
    sha = _init_repo(
        repo,
        {
            "pom.xml": (
                "<project><groupId>org.example</groupId><artifactId>reactor-parent</artifactId>"
                f"<version>{version}</version><packaging>pom</packaging>"
                "<modules><module>core</module></modules></project>\n"
            ),
            "core/pom.xml": (
                "<project><parent><groupId>org.example</groupId>"
                f"<artifactId>reactor-parent</artifactId><version>{version}</version></parent>"
                "<artifactId>core</artifactId></project>\n"
            ),
        },
        tags=(tag,),
    )
    resolved = _resolver().resolve(
        ComponentTargetRequest(
            purl=f"pkg:maven/org.example/core@{version}",
            repository=repo_url,
            commit=sha,
        ),
        repo,
    )
    assert resolved.module_path == "core"
    assert resolved.release_ref == tag
    assert resolved.verification.strategy is ComponentTargetStrategy.SHARED_RELEASE


def test_maven_multi_hop_parent_chain_and_skipped_fixture_poms(tmp_path: Path) -> None:
    repo = tmp_path / "maven-3hop"
    sha = _init_repo(
        repo,
        {
            "pom.xml": (
                "<project><groupId>org.example</groupId><artifactId>root-pom</artifactId>"
                "<version>${revision}</version><packaging>pom</packaging>"
                "<properties><revision>4.2.0</revision></properties>"
                "<profiles><profile><id>all</id><modules><module>bom</module>"
                "<module>services</module></modules></profile></profiles></project>\n"
            ),
            "bom/pom.xml": (
                "<project><parent><groupId>org.example</groupId><artifactId>root-pom</artifactId>"
                "<version>${revision}</version></parent><artifactId>bom</artifactId>"
                "<packaging>pom</packaging></project>\n"
            ),
            "services/pom.xml": (
                "<project><parent><groupId>org.example</groupId><artifactId>bom</artifactId>"
                "<version>${revision}</version><relativePath>../bom/pom.xml</relativePath>"
                "</parent><artifactId>services-parent</artifactId><packaging>pom</packaging>"
                "<modules><module>auth</module></modules></project>\n"
            ),
            "services/auth/pom.xml": (
                "<project><parent><groupId>org.example</groupId>"
                "<artifactId>services-parent</artifactId><version>${revision}</version></parent>"
                "<artifactId>auth-service</artifactId></project>\n"
            ),
            # IT/test fixture POM with same artifact coordinate must be skipped.
            "it/fixtures/auth/pom.xml": (
                "<project><groupId>org.example</groupId><artifactId>auth-service</artifactId>"
                "<version>4.2.0</version></project>\n"
            ),
        },
        tags=("v4.2.0",),
    )
    resolved = _resolver().resolve(
        ComponentTargetRequest(
            purl="pkg:maven/org.example/auth-service@4.2.0",
            repository="https://github.com/example/maven-3hop",
            commit=sha,
        ),
        repo,
    )
    assert resolved.module_path == "services/auth"
    assert resolved.verification.strategy is ComponentTargetStrategy.SHARED_RELEASE
    assert resolved.verification.manifest_paths == (
        "bom/pom.xml",
        "pom.xml",
        "services/auth/pom.xml",
        "services/pom.xml",
    )


def test_root_published_package_and_python_setup_cfg_and_dynamic_version(tmp_path: Path) -> None:
    assert normalize_module_path(".") == "."
    assert normalize_module_path("./") == "."
    for bad in ("", "   ", "..", "../x", "/abs", "./.."):
        with pytest.raises(UnresolvedTargetError):
            normalize_module_path(bad)

    # Root-published package via setup.cfg static version
    setup_repo = tmp_path / "setup-cfg-root"
    sha_setup = _init_repo(
        setup_repo,
        {"setup.cfg": "[metadata]\nname = legacy-pkg\nversion = 2.1.0\n"},
        tags=("v2.1.0",),
    )
    root_res = _resolver().resolve(
        ComponentTargetRequest(
            purl="pkg:pypi/legacy-pkg@2.1.0",
            repository="https://github.com/example/legacy-pkg",
            commit=sha_setup,
            module_path=".",
        ),
        setup_repo,
    )
    assert root_res.module_path == "."
    assert root_res.verification.strategy is ComponentTargetStrategy.SHARED_RELEASE
    assert root_res.verification.manifest_paths == ("setup.cfg",)

    # Dynamic version via pyproject.toml + uv workspace + release tag
    dyn_repo = tmp_path / "py-dyn"
    sha_dyn = _init_repo(
        dyn_repo,
        {
            "pyproject.toml": '[tool.uv.workspace]\nmembers = ["packages/*"]\n',
            "packages/alpha/pyproject.toml": (
                '[project]\nname = "alpha-lib"\ndynamic = ["version"]\n'
            ),
            "packages/beta/setup.cfg": (
                "[metadata]\nname = beta-lib\nversion = attr: beta.__version__\n"
            ),
        },
        tags=("v3.0.0", "beta-lib==1.4.0"),
    )
    alpha = _resolver().resolve(
        ComponentTargetRequest(
            purl="pkg:pypi/alpha-lib@3.0.0",
            repository="https://github.com/example/py-dyn",
            commit=sha_dyn,
        ),
        dyn_repo,
    )
    assert alpha.module_path == "packages/alpha"
    assert alpha.verification.strategy is ComponentTargetStrategy.SHARED_RELEASE
    assert alpha.verification.manifest_paths == (
        "packages/alpha/pyproject.toml",
        "pyproject.toml",
    )

    beta = _resolver().resolve(
        ComponentTargetRequest(
            purl="pkg:pypi/beta-lib@1.4.0",
            repository="https://github.com/example/py-dyn",
            commit=sha_dyn,
        ),
        dyn_repo,
    )
    assert beta.module_path == "packages/beta"
    assert beta.verification.strategy is ComponentTargetStrategy.PACKAGE_RELEASE
    assert beta.verification.manifest_paths == ("packages/beta/setup.cfg", "pyproject.toml")

    # Dynamic version without matching tag fails closed
    untagged_dyn = tmp_path / "py-dyn-untagged"
    sha_untagged = _init_repo(
        untagged_dyn,
        {"pyproject.toml": '[project]\nname = "dyn-root"\ndynamic = ["version"]\n'},
    )
    with pytest.raises(UnresolvedTargetError) as untagged_exc:
        _resolver().resolve(
            ComponentTargetRequest(
                purl="pkg:pypi/dyn-root@1.0.0",
                repository="https://github.com/example/py-dyn-untagged",
                commit=sha_untagged,
            ),
            untagged_dyn,
        )
    assert untagged_exc.value.reason == UnresolvedTargetReason.NO_MANIFEST_MATCH


def test_external_provenance_verification_and_mandatory_negatives(tmp_path: Path) -> None:
    repo = tmp_path / "rebuilt-reactor"
    repo_url = "https://github.com/example/rebuilt-reactor"
    sha = _init_repo(
        repo,
        {
            "pom.xml": (
                "<project><groupId>org.example</groupId><artifactId>reactor</artifactId>"
                "<version>7.1.0</version><packaging>pom</packaging>"
                "<modules><module>beans</module></modules></project>\n"
            ),
            "beans/pom.xml": (
                "<project><parent><groupId>org.example</groupId><artifactId>reactor</artifactId>"
                "<version>7.1.0</version></parent><artifactId>beans</artifactId></project>\n"
            ),
        },
        tags=("build-ref/7.1.0-rebuild-1",),
    )
    trusted_priv = ed25519.Ed25519PrivateKey.generate()
    trusted_pem = (
        trusted_priv.public_key()
        .public_bytes(serialization.Encoding.PEM, serialization.PublicFormat.SubjectPublicKeyInfo)
        .decode("utf-8")
    )
    untrusted_priv = ed25519.Ed25519PrivateKey.generate()
    verifier = DsseProvenanceVerifier(
        ProvenanceTrustPolicy(
            trusted_keys=(
                TrustedProvenanceKey(
                    key_id="builder-key-1",
                    public_key_pem=trusted_pem,
                    issuer="https://attestor.example",
                ),
            ),
            allowed_sources=("https://slsa.dev/provenance/v1",),
            allowed_issuers=("https://attestor.example",),
        )
    )
    rebuilt_purl = "pkg:maven/org.example/beans@7.1.0.rebuild-1"
    valid_stmt = {
        "_type": "https://in-toto.io/Statement/v1",
        "subject": [{"uri": rebuilt_purl}],
        "predicateType": "https://slsa.dev/provenance/v1",
        "predicate": {
            "repository": repo_url,
            "commit": sha,
            "ref": "build-ref/7.1.0-rebuild-1",
            "manifest_version": "7.1.0",
        },
    }
    valid_env, expected_digest = _sign_dsse(trusted_priv, "builder-key-1", valid_stmt)

    # 1. Bare nonstandard --release-ref without provenance fails closed (NO_MANIFEST_MATCH).
    with pytest.raises(UnresolvedTargetError) as bare_ref:
        _resolver(verifier).resolve(
            ComponentTargetRequest(
                purl="pkg:maven/org.example/beans@7.1.0",
                repository=repo_url,
                commit=sha,
                release_ref="build-ref/7.1.0-rebuild-1",
            ),
            repo,
        )
    assert bare_ref.value.reason == UnresolvedTargetReason.NO_MANIFEST_MATCH

    # 2. Unconfigured verifier (provenance_verifier=None) rejects provenance_record.
    with pytest.raises(UnresolvedTargetError) as unconfigured:
        _resolver(None).resolve(
            ComponentTargetRequest(
                purl=rebuilt_purl,
                repository=repo_url,
                commit=sha,
                provenance_record=valid_env,
            ),
            repo,
        )
    assert unconfigured.value.reason == UnresolvedTargetReason.PROVENANCE_UNVERIFIED

    # 3. Forged/tampered payload fails closed.
    tampered_env = dict(valid_env)
    tampered_stmt = {
        **valid_stmt,
        "predicate": {**valid_stmt["predicate"], "commit": "0" * 40},
    }
    tampered_env["payload"] = base64.b64encode(json.dumps(tampered_stmt).encode()).decode()
    with pytest.raises(UnresolvedTargetError) as forged:
        _resolver(verifier).resolve(
            ComponentTargetRequest(
                purl=rebuilt_purl,
                repository=repo_url,
                commit=sha,
                provenance_record=tampered_env,
            ),
            repo,
        )
    assert forged.value.reason == UnresolvedTargetReason.PROVENANCE_UNVERIFIED

    # 4. Untrusted key / untrusted source fails closed.
    untrusted_env, _ = _sign_dsse(untrusted_priv, "builder-key-1", valid_stmt)
    with pytest.raises(UnresolvedTargetError) as bad_key:
        _resolver(verifier).resolve(
            ComponentTargetRequest(
                purl=rebuilt_purl,
                repository=repo_url,
                commit=sha,
                provenance_record=untrusted_env,
            ),
            repo,
        )
    assert bad_key.value.reason == UnresolvedTargetReason.PROVENANCE_UNVERIFIED

    bad_source_env, _ = _sign_dsse(
        trusted_priv,
        "builder-key-1",
        {**valid_stmt, "predicateType": "https://untrusted.example/v1"},
    )
    with pytest.raises(UnresolvedTargetError) as bad_src:
        _resolver(verifier).resolve(
            ComponentTargetRequest(
                purl=rebuilt_purl,
                repository=repo_url,
                commit=sha,
                provenance_record=bad_source_env,
            ),
            repo,
        )
    assert bad_src.value.reason == UnresolvedTargetReason.PROVENANCE_UNVERIFIED

    # 5. Valid signature bound to wrong PURL, repository, commit, or manifest_version -> MISMATCH.
    for bad_pred_patch, bad_subj in (
        ({}, [{"uri": "pkg:maven/org.example/other@7.1.0"}]),
        ({"repository": "https://github.com/other/repo"}, None),
        ({"commit": "1" * 40}, None),
        ({"manifest_version": "9.9.9"}, None),
    ):
        stmt = {
            **valid_stmt,
            "subject": bad_subj or valid_stmt["subject"],
            "predicate": {**valid_stmt["predicate"], **bad_pred_patch},
        }
        env, _ = _sign_dsse(trusted_priv, "builder-key-1", stmt)
        with pytest.raises(UnresolvedTargetError) as mismatch:
            _resolver(verifier).resolve(
                ComponentTargetRequest(
                    purl=rebuilt_purl,
                    repository=repo_url,
                    commit=sha,
                    provenance_record=env,
                ),
                repo,
            )
        assert mismatch.value.reason == UnresolvedTargetReason.PROVENANCE_MISMATCH

    # 6. cand.version != purl.version with missing manifest_version fails closed.
    pred_no_mv = {k: v for k, v in valid_stmt["predicate"].items() if k != "manifest_version"}
    no_mv_env, _ = _sign_dsse(
        trusted_priv, "builder-key-1", {**valid_stmt, "predicate": pred_no_mv}
    )
    with pytest.raises(UnresolvedTargetError) as no_mv:
        _resolver(verifier).resolve(
            ComponentTargetRequest(
                purl=rebuilt_purl,
                repository=repo_url,
                commit=sha,
                provenance_record=no_mv_env,
            ),
            repo,
        )
    assert no_mv.value.reason == UnresolvedTargetReason.PROVENANCE_MISMATCH

    # 7. Valid authenticated record succeeds with EXTERNAL_PROVENANCE and verifier-derived digest.
    resolved = _resolver(verifier).resolve(
        ComponentTargetRequest(
            purl=rebuilt_purl,
            repository=repo_url,
            commit=sha,
            release_ref="build-ref/7.1.0-rebuild-1",
            provenance_record=valid_env,
        ),
        repo,
    )
    assert resolved.purl == rebuilt_purl
    assert resolved.module_path == "beans"
    assert resolved.release_ref == "build-ref/7.1.0-rebuild-1"
    assert resolved.verification.strategy is ComponentTargetStrategy.EXTERNAL_PROVENANCE
    assert resolved.verification.manifest_paths == ("beans/pom.xml", "pom.xml")
    assert resolved.verification.provenance is not None
    assert resolved.verification.provenance.source == "https://slsa.dev/provenance/v1"
    assert resolved.verification.provenance.ref == "build-ref/7.1.0-rebuild-1"
    assert resolved.verification.provenance.digest == expected_digest
    assert resolved.verification.provenance.manifest_version == "7.1.0"


def _signed_policy() -> tuple[ed25519.Ed25519PrivateKey, DsseProvenanceVerifier]:
    priv = ed25519.Ed25519PrivateKey.generate()
    pem = (
        priv.public_key()
        .public_bytes(serialization.Encoding.PEM, serialization.PublicFormat.SubjectPublicKeyInfo)
        .decode("utf-8")
    )
    return priv, DsseProvenanceVerifier(
        ProvenanceTrustPolicy(trusted_keys=(TrustedProvenanceKey(key_id="k", public_key_pem=pem),))
    )


def _rebuilt_reactor(tmp_path: Path) -> tuple[Path, str, str]:
    repo = tmp_path / "reactor"
    sha = _init_repo(
        repo,
        {
            "pom.xml": (
                "<project><groupId>org.example</groupId><artifactId>reactor</artifactId>"
                "<version>7.1.0</version><packaging>pom</packaging>"
                "<modules><module>beans</module></modules></project>\n"
            ),
            "beans/pom.xml": (
                "<project><parent><groupId>org.example</groupId><artifactId>reactor</artifactId>"
                "<version>7.1.0</version></parent><artifactId>beans</artifactId></project>\n"
            ),
        },
        tags=("v7.1.0", "build-7.1.0-r1", "build-7.1.0-r2"),
    )
    return repo, "https://github.com/example/reactor", sha


def _statement(purl: str, repo_url: str, sha: str, ref: str) -> dict[str, Any]:
    return {
        "_type": "https://in-toto.io/Statement/v1",
        "subject": [{"uri": purl}],
        "predicateType": "https://slsa.dev/provenance/v1",
        "predicate": {
            "repository": repo_url,
            "commit": sha,
            "ref": ref,
            "manifest_version": "7.1.0",
        },
    }


REBUILT = "pkg:maven/org.example/beans@7.1.0.r1"


def test_a_trusted_signature_over_another_payload_type_is_not_provenance(tmp_path: Path) -> None:
    repo, repo_url, sha = _rebuilt_reactor(tmp_path)
    priv, verifier = _signed_policy()
    statement = _statement(REBUILT, repo_url, sha, "build-7.1.0-r1")
    env, _ = _sign_dsse(priv, "k", statement, payload_type="application/json")
    with pytest.raises(UnresolvedTargetError) as exc:
        _resolver(verifier).resolve(
            ComponentTargetRequest(
                purl=REBUILT, repository=repo_url, commit=sha, provenance_record=env
            ),
            repo,
        )
    assert exc.value.reason == UnresolvedTargetReason.PROVENANCE_UNVERIFIED


def test_a_signed_json_document_that_is_no_in_toto_statement_is_not_provenance(
    tmp_path: Path,
) -> None:
    repo, repo_url, sha = _rebuilt_reactor(tmp_path)
    priv, verifier = _signed_policy()
    flat = {"purl": REBUILT, "repository": repo_url, "commit": sha, "source": "s", "ref": "r"}
    env, _ = _sign_dsse(priv, "k", flat)
    with pytest.raises(UnresolvedTargetError) as exc:
        _resolver(verifier).resolve(
            ComponentTargetRequest(
                purl=REBUILT, repository=repo_url, commit=sha, provenance_record=env
            ),
            repo,
        )
    assert exc.value.reason == UnresolvedTargetReason.PROVENANCE_UNVERIFIED


def test_signed_provenance_for_another_release_ref_is_a_mismatch(tmp_path: Path) -> None:
    repo, repo_url, sha = _rebuilt_reactor(tmp_path)
    priv, verifier = _signed_policy()
    env, _ = _sign_dsse(priv, "k", _statement(REBUILT, repo_url, sha, "build-7.1.0-r2"))
    with pytest.raises(UnresolvedTargetError) as exc:
        _resolver(verifier).resolve(
            ComponentTargetRequest(
                purl=REBUILT,
                repository=repo_url,
                commit=sha,
                release_ref="build-7.1.0-r1",
                provenance_record=env,
            ),
            repo,
        )
    assert exc.value.reason == UnresolvedTargetReason.PROVENANCE_MISMATCH


def test_the_trust_policy_is_read_on_first_use_only(tmp_path: Path) -> None:
    # a broken policy fails the orders that carry provenance, never resolution without it
    repo, repo_url, sha = _rebuilt_reactor(tmp_path)
    broken = tmp_path / "trust.json"
    broken.write_text("{not json", encoding="utf-8")
    resolver = ComponentTargetResolver(
        GitCheckout(ProcessRunner(allowed=("git",))),
        PackageManifestScanner(yaml_documents),
        trust_policy=broken,
    )
    resolved = resolver.resolve(
        ComponentTargetRequest(
            purl="pkg:maven/org.example/beans@7.1.0", repository=repo_url, commit=sha
        ),
        repo,
    )
    assert resolved.module_path == "beans"
    priv, _ = _signed_policy()
    env, _ = _sign_dsse(priv, "k", _statement(REBUILT, repo_url, sha, "build-7.1.0-r1"))
    with pytest.raises(ConfigError):
        resolver.resolve(
            ComponentTargetRequest(
                purl=REBUILT, repository=repo_url, commit=sha, provenance_record=env
            ),
            repo,
        )


def test_a_hyphenated_tag_for_another_version_conflicts(tmp_path: Path) -> None:
    repo = tmp_path / "ws"
    sha = _init_repo(
        repo,
        {
            "package.json": json.dumps(
                {"name": "root", "private": True, "workspaces": ["packages/*"]}
            ),
            "packages/pkg/package.json": json.dumps({"name": "@acme/pkg", "version": "1.0.0"}),
        },
        tags=("v1.0.0", "@acme/pkg-2.0.0"),
    )
    with pytest.raises(UnresolvedTargetError) as exc:
        _resolver().resolve(
            ComponentTargetRequest(
                purl="pkg:npm/%40acme/pkg@1.0.0",
                repository="https://github.com/acme/ws",
                commit=sha,
            ),
            repo,
        )
    assert exc.value.reason == UnresolvedTargetReason.VERSION_MISMATCH


def test_a_hyphenated_tag_for_another_package_is_no_conflict(tmp_path: Path) -> None:
    repo = tmp_path / "ws"
    sha = _init_repo(
        repo,
        {
            "package.json": json.dumps(
                {"name": "root", "private": True, "workspaces": ["packages/*"]}
            ),
            "packages/pkg/package.json": json.dumps({"name": "@acme/pkg", "version": "1.0.0"}),
        },
        tags=("v1.0.0", "@acme/pkg-extra-2.0.0", "@acme/pkg-v1.0.0"),
    )
    resolved = _resolver().resolve(
        ComponentTargetRequest(
            purl="pkg:npm/%40acme/pkg@1.0.0", repository="https://github.com/acme/ws", commit=sha
        ),
        repo,
    )
    assert resolved.module_path == "packages/pkg"


@pytest.mark.parametrize(
    "child_version", ["${project.parent.version}", "${revision}"], ids=["builtin", "chained"]
)
def test_maven_versions_through_model_and_chained_properties_resolve(
    tmp_path: Path, child_version: str
) -> None:
    repo = tmp_path / "reactor"
    sha = _init_repo(
        repo,
        {
            "pom.xml": (
                "<project><groupId>org.example</groupId><artifactId>reactor</artifactId>"
                "<version>7.1.0</version><packaging>pom</packaging>"
                "<properties><release.version>7.1.0</release.version>"
                "<revision>${release.version}</revision></properties>"
                "<modules><module>beans</module></modules></project>\n"
            ),
            "beans/pom.xml": (
                "<project><parent><groupId>org.example</groupId><artifactId>reactor</artifactId>"
                "<version>7.1.0</version></parent><artifactId>beans</artifactId>"
                f"<version>{child_version}</version></project>\n"
            ),
        },
        tags=("v7.1.0",),
    )
    resolved = _resolver().resolve(
        ComponentTargetRequest(
            purl="pkg:maven/org.example/beans@7.1.0",
            repository="https://github.com/example/reactor",
            commit=sha,
        ),
        repo,
    )
    assert resolved.module_path == "beans"


def test_component_purls_parse_into_the_one_purl_value_type() -> None:
    from traust_core.v1.models.component_target import parse_component_purl
    from traust_core.v1.models.purl import Purl

    parsed = parse_component_purl("pkg:maven/org.example/beans@7.1.0#beans")
    assert isinstance(parsed, Purl)
    assert parsed == Purl.parse("pkg:maven/org.example/beans@7.1.0#beans")
    assert Purl.try_parse("not a purl") is None


@pytest.mark.parametrize(
    ("field", "value"), [("ref_kind", "Branch"), ("ref_kind", "trunk")], ids=["case", "unknown"]
)
def test_a_target_request_refuses_an_unknown_ref_kind(field: str, value: str) -> None:
    with pytest.raises(PydanticValidationError):
        ComponentTargetRequest(purl="pkg:npm/a@1.0.0", repository="r", **{field: value})


def test_a_manifest_candidate_refuses_an_unknown_ecosystem() -> None:
    from traust_core.v1.models.component_target import PackageManifestCandidate

    with pytest.raises(PydanticValidationError):
        PackageManifestCandidate(
            ecosystem="pypy", package_id="a", module_path=".", manifest_paths=("setup.py",)
        )


def test_a_target_request_refuses_a_provenance_record_that_is_no_dsse_envelope() -> None:
    with pytest.raises(PydanticValidationError):
        ComponentTargetRequest(
            purl="pkg:npm/a@1.0.0", repository="r", provenance_record={"purl": "pkg:npm/a@1.0.0"}
        )


def test_provenance_has_one_verifier_and_no_single_implementation_protocol() -> None:
    import traust_core.v1.providers.provenance as provenance

    assert not hasattr(provenance, "ProvenanceVerifier")


def test_fixture_git_runs_through_the_runtime_process_seam(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    from tests.fixtures.component_purl import builder

    calls: list[tuple[str, ...]] = []
    real_run = ProcessRunner.run

    def spy(self: ProcessRunner, argv: Any, **kwargs: Any) -> Any:
        calls.append(tuple(argv))
        return real_run(self, argv, **kwargs)

    monkeypatch.setattr(ProcessRunner, "run", spy)
    builder.build_spring_fixture(tmp_path)
    assert calls and all(argv[0] == "git" for argv in calls)
    assert any("commit" in argv for argv in calls)


def test_a_qualified_target_keeps_its_identity() -> None:
    sources = canonical_component_purl("pkg:maven/org.example/beans@7.1.0?classifier=sources")
    assert sources != canonical_component_purl("pkg:maven/org.example/beans@7.1.0")
    assert "classifier=sources" in sources


def test_signed_provenance_for_the_unqualified_artifact_does_not_verify_a_qualified_one(
    tmp_path: Path,
) -> None:
    repo, repo_url, sha = _rebuilt_reactor(tmp_path)
    priv, verifier = _signed_policy()
    env, _ = _sign_dsse(priv, "k", _statement(REBUILT, repo_url, sha, "build-7.1.0-r1"))
    with pytest.raises(UnresolvedTargetError) as exc:
        _resolver(verifier).resolve(
            ComponentTargetRequest(
                purl=f"{REBUILT}?classifier=sources",
                repository=repo_url,
                commit=sha,
                provenance_record=env,
            ),
            repo,
        )
    assert exc.value.reason == UnresolvedTargetReason.PROVENANCE_MISMATCH


@pytest.mark.parametrize(
    ("field", "value"),
    [
        ("_type", "https://in-toto.io/Statement/v0.9-draft"),
        ("predicateType", "https://in-toto.io/attestation/test-result/v0.1"),
    ],
    ids=["statement-type", "predicate-type"],
)
def test_only_an_in_toto_v1_slsa_provenance_statement_verifies_a_release(
    tmp_path: Path, field: str, value: str
) -> None:
    repo, repo_url, sha = _rebuilt_reactor(tmp_path)
    priv, verifier = _signed_policy()
    statement = {**_statement(REBUILT, repo_url, sha, "build-7.1.0-r1"), field: value}
    env, _ = _sign_dsse(priv, "k", statement)
    with pytest.raises(UnresolvedTargetError) as exc:
        _resolver(verifier).resolve(
            ComponentTargetRequest(
                purl=REBUILT, repository=repo_url, commit=sha, provenance_record=env
            ),
            repo,
        )
    assert exc.value.reason == UnresolvedTargetReason.PROVENANCE_UNVERIFIED


def _reactor_with(tmp_path: Path, tags: tuple[str, ...], child: str = "") -> tuple[Path, str]:
    repo = tmp_path / "reactor"
    sha = _init_repo(
        repo,
        {
            "pom.xml": (
                "<project><groupId>org.example</groupId><artifactId>reactor</artifactId>"
                "<version>1.0.0</version><packaging>pom</packaging>"
                "<modules><module>foo</module></modules></project>\n"
            ),
            "foo/pom.xml": child
            or (
                "<project><parent><groupId>org.example</groupId><artifactId>reactor</artifactId>"
                "<version>1.0.0</version></parent><artifactId>foo</artifactId></project>\n"
            ),
        },
        tags=tags,
    )
    return repo, sha


def _resolve_foo(repo: Path, sha: str, version: str = "1.0.0") -> ComponentTarget:
    return _resolver().resolve(
        ComponentTargetRequest(
            purl=f"pkg:maven/org.example/foo@{version}",
            repository="https://github.com/example/reactor",
            commit=sha,
        ),
        repo,
    )


def test_a_final_release_tagged_on_its_rc_commit_resolves(tmp_path: Path) -> None:
    repo, sha = _reactor_with(tmp_path, ("foo-1.0.0-rc.2", "foo-1.0.0"))
    assert _resolve_foo(repo, sha).module_path == "foo"


def test_a_label_version_tag_for_the_package_conflicts(tmp_path: Path) -> None:
    repo, sha = _reactor_with(tmp_path, ("v1.0.0", "foo-RC1"))
    with pytest.raises(UnresolvedTargetError) as exc:
        _resolve_foo(repo, sha)
    assert exc.value.reason == UnresolvedTargetReason.VERSION_MISMATCH


def test_a_sibling_package_tag_does_not_block_this_package(tmp_path: Path) -> None:
    repo = tmp_path / "ws"
    sha = _init_repo(
        repo,
        {
            "package.json": json.dumps(
                {"name": "root", "private": True, "workspaces": ["packages/*"]}
            ),
            "packages/client/package.json": json.dumps({"name": "client", "version": "1.0.0"}),
            "packages/client-v2/package.json": json.dumps(
                {"name": "client-v2", "version": "1.0.0"}
            ),
            "packages/foo/package.json": json.dumps({"name": "foo", "version": "1.0.0"}),
            "packages/foo-3d/package.json": json.dumps({"name": "foo-3d", "version": "2.0.0"}),
        },
        tags=("client@1.0.0", "client-v2@1.0.0", "foo@1.0.0", "foo-3d-2.0.0"),
    )
    for name in ("client", "foo"):
        resolved = _resolver().resolve(
            ComponentTargetRequest(
                purl=f"pkg:npm/{name}@1.0.0", repository="https://github.com/acme/ws", commit=sha
            ),
            repo,
        )
        assert resolved.module_path == f"packages/{name}"


def test_a_child_artifact_through_the_parent_artifact_id_resolves(tmp_path: Path) -> None:
    child = (
        "<project><parent><groupId>org.example</groupId><artifactId>reactor</artifactId>"
        "<version>1.0.0</version></parent>"
        "<artifactId>${project.parent.artifactId}-foo</artifactId></project>\n"
    )
    repo, sha = _reactor_with(tmp_path, ("v1.0.0",), child)
    resolved = _resolver().resolve(
        ComponentTargetRequest(
            purl="pkg:maven/org.example/reactor-foo@1.0.0",
            repository="https://github.com/example/reactor",
            commit=sha,
        ),
        repo,
    )
    assert resolved.module_path == "foo"


def test_a_stated_groupid_that_cannot_resolve_does_not_borrow_the_parents(tmp_path: Path) -> None:
    child = (
        "<project><parent><groupId>org.example</groupId><artifactId>reactor</artifactId>"
        "<version>1.0.0</version></parent><groupId>${elsewhere.group}</groupId>"
        "<artifactId>foo</artifactId></project>\n"
    )
    repo, sha = _reactor_with(tmp_path, ("v1.0.0",), child)
    with pytest.raises(UnresolvedTargetError) as exc:
        _resolve_foo(repo, sha)
    assert exc.value.reason == UnresolvedTargetReason.NO_MANIFEST_MATCH


def test_a_multiplying_property_chain_is_bounded(tmp_path: Path) -> None:
    levels = (
        "".join(f"<p{i}>" + f"${{p{i + 1}}}" * 50 + f"</p{i}>" for i in range(8)) + "<p8>x</p8>"
    )
    child = (
        "<project><parent><groupId>org.example</groupId><artifactId>reactor</artifactId>"
        f"<version>1.0.0</version></parent><properties>{levels}</properties>"
        "<artifactId>foo</artifactId><version>${p0}</version></project>\n"
    )
    repo, sha = _reactor_with(tmp_path, ("v1.0.0",), child)
    with pytest.raises(UnresolvedTargetError) as exc:
        _resolve_foo(repo, sha)  # fails closed in bounded memory, never expands 50^8 copies
    assert exc.value.reason == UnresolvedTargetReason.VERSION_MISMATCH


def test_the_takeover_binding_compares_typed_targets() -> None:
    from traust_core.v1.services.operations import _binding_form

    target = ComponentTarget(
        purl="pkg:maven/org.example/beans@7.1.0",
        repository="https://github.com/example/reactor",
        commit="a" * 40,
        module_path="beans",
        release_ref="v7.1.0",
        verification=ComponentTargetVerification(
            strategy=ComponentTargetStrategy.SHARED_RELEASE, manifest_paths=("beans/pom.xml",)
        ),
    )
    bound = _binding_form(target)
    assert isinstance(bound, ComponentTarget)
    assert bound != _binding_form(target.model_copy(update={"release_ref": "release-7.1.0"}))
