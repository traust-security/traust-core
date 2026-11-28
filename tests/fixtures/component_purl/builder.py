"""Deterministic local git fixture builders for component PURL monorepo audits.

Sanitized, synthetic monorepos derived from real ecosystem packaging patterns:
- Spring-style shared-version Maven multi-module POMs (v7.1.0)
- LangChain package-specific Python release tags (langchain-core==1.8.4)
- Pi public npm workspace members with an unrelated private root version (v1.6.0)
- Cross-module tenant-cache fixture (vulnerable shared cache vs safe per-tenant cache)
"""

from __future__ import annotations

import json
from dataclasses import dataclass
from pathlib import Path

from traust_core.v1.providers.process import ProcessRunner


@dataclass(frozen=True, slots=True)
class PinnedFixture:
    path: Path
    repo_url: str
    commit: str
    tag: str


# Through the runtime's own seam: the allowlist applies, and the child env is its keep-list, so
# a git hook's GIT_DIR / GIT_INDEX_FILE never reach the fixture's git.
_GIT = ProcessRunner(("git",))
_FIXTURE_ENV = {"GIT_CONFIG_GLOBAL": "/dev/null", "GIT_CONFIG_SYSTEM": "/dev/null"}


def _fixture_git(root: Path, *args: str) -> str:
    return (
        _GIT.run(
            ["git", "-C", str(root), "-c", "user.email=t@example.com", "-c", "user.name=T", *args],
            env=_FIXTURE_ENV,
        )
        .stdout.decode()
        .strip()
    )


def _build_git_repo(root: Path, repo_url: str, files: dict[str, str], tag: str) -> PinnedFixture:
    root.mkdir(parents=True, exist_ok=True)
    _fixture_git(root, "init", "-q", "-b", "main")
    for rel, content in files.items():
        target = root / rel
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_text(content, encoding="utf-8")
    _fixture_git(root, "add", "-A")
    _fixture_git(root, "commit", "-q", "-m", f"fixture {tag}")
    sha = _fixture_git(root, "rev-parse", "HEAD")
    _fixture_git(root, "tag", tag)
    return PinnedFixture(path=root, repo_url=repo_url, commit=sha, tag=tag)


def _maven_parent_pom(
    group_id: str, artifact_id: str, version: str, modules: tuple[str, ...]
) -> str:
    mods = "".join(f"<module>{m}</module>" for m in modules)
    return (
        '<project xmlns="http://maven.apache.org/POM/4.0.0">\n'
        "  <modelVersion>4.0.0</modelVersion>\n"
        f"  <groupId>{group_id}</groupId>\n"
        f"  <artifactId>{artifact_id}</artifactId>\n"
        f"  <version>{version}</version>\n"
        "  <packaging>pom</packaging>\n"
        f"  <modules>{mods}</modules>\n"
        "</project>\n"
    )


def _maven_child_pom(group_id: str, parent_id: str, version: str, artifact_id: str) -> str:
    return (
        '<project xmlns="http://maven.apache.org/POM/4.0.0">\n'
        "  <modelVersion>4.0.0</modelVersion>\n"
        "  <parent>\n"
        f"    <groupId>{group_id}</groupId>\n"
        f"    <artifactId>{parent_id}</artifactId>\n"
        f"    <version>{version}</version>\n"
        "  </parent>\n"
        f"  <artifactId>{artifact_id}</artifactId>\n"
        "</project>\n"
    )


def build_spring_fixture(tmp_path: Path) -> PinnedFixture:
    return _build_git_repo(
        tmp_path / "spring-framework",
        "https://github.com/example-spring/spring-framework",
        {
            "pom.xml": _maven_parent_pom(
                "org.springframework",
                "spring-framework-parent",
                "7.1.0",
                ("spring-core", "spring-beans", "spring-context"),
            ),
            "spring-core/pom.xml": _maven_child_pom(
                "org.springframework", "spring-framework-parent", "7.1.0", "spring-core"
            ),
            "spring-core/src/main/java/org/example/CoreId.java": (
                "package org.example;\n"
                'public class CoreId { public String raw() { return "1"; } }\n'
            ),
            "spring-beans/pom.xml": _maven_child_pom(
                "org.springframework", "spring-framework-parent", "7.1.0", "spring-beans"
            ),
            "spring-beans/src/main/java/org/example/BeanCache.java": (
                "package org.example;\n"
                "public class BeanCache { public Object get(String k) { return null; } }\n"
            ),
            "spring-context/pom.xml": _maven_child_pom(
                "org.springframework", "spring-framework-parent", "7.1.0", "spring-context"
            ),
            "spring-context/src/main/java/org/example/AppContext.java": (
                "package org.example;\n"
                "public class AppContext { public BeanCache cache() { return new BeanCache(); } }\n"
            ),
        },
        tag="v7.1.0",
    )


def build_langchain_fixture(tmp_path: Path) -> PinnedFixture:
    return _build_git_repo(
        tmp_path / "langchain",
        "https://github.com/example-langchain/langchain",
        {
            "libs/core/pyproject.toml": ('[project]\nname = "langchain-core"\nversion = "1.8.4"\n'),
            "libs/core/langchain_core/runnable.py": "def invoke(x: str) -> str:\n    return x\n",
            "libs/langchain/pyproject.toml": ('[project]\nname = "langchain"\nversion = "1.2.0"\n'),
            "libs/langchain/langchain/chain.py": "def run_chain(x: str) -> str:\n    return x\n",
        },
        tag="langchain-core==1.8.4",
    )


def build_pi_fixture(tmp_path: Path) -> PinnedFixture:
    return _build_git_repo(
        tmp_path / "pi",
        "https://github.com/example-pi/pi",
        {
            "package.json": json.dumps(
                {
                    "name": "pi-monorepo",
                    "private": True,
                    "version": "0.0.1-private",
                    "workspaces": ["packages/*"],
                },
                indent=2,
            ),
            "packages/ai/package.json": json.dumps(
                {"name": "@earendil-works/pi-ai", "version": "1.6.0"}, indent=2
            ),
            "packages/ai/src/client.ts": (
                "export function callModel(prompt: string) { return prompt; }\n"
            ),
            "packages/coding-agent/package.json": json.dumps(
                {"name": "@earendil-works/pi-coding-agent", "version": "1.6.0"}, indent=2
            ),
            "packages/coding-agent/src/agent.ts": "export function runAgent() { return true; }\n",
        },
        tag="v1.6.0",
    )


def build_tenant_cache_fixture(tmp_path: Path, *, shared_cache: bool) -> PinnedFixture:
    """Target package keys a cache by bare ID; sibling defines IDs as tenant-local; app either
    shares one cache across tenants (vulnerable) or isolates caches per tenant (safe); unrelated
    sibling carries an isolated SQL injection not reachable from target."""
    variant = "shared" if shared_cache else "isolated"
    app_server = (
        'import { ItemCache } from "@acme/cache-lib";\n'
        'import { nextTenantItemId } from "@acme/tenant-ids";\n'
        "const GLOBAL_CACHE = new ItemCache();\n"
        "export function handleRequest(tenantId: string, payload: string) {\n"
        "  const id = nextTenantItemId(tenantId);\n"
        "  GLOBAL_CACHE.put(id, payload);\n"
        "  return GLOBAL_CACHE.get(id);\n"
        "}\n"
        if shared_cache
        else 'import { ItemCache } from "@acme/cache-lib";\n'
        'import { nextTenantItemId } from "@acme/tenant-ids";\n'
        "const CACHES_BY_TENANT = new Map<string, ItemCache>();\n"
        "export function handleRequest(tenantId: string, payload: string) {\n"
        "  let cache = CACHES_BY_TENANT.get(tenantId);\n"
        "  if (!cache) { cache = new ItemCache(); CACHES_BY_TENANT.set(tenantId, cache); }\n"
        "  const id = nextTenantItemId(tenantId);\n"
        "  cache.put(id, payload);\n"
        "  return cache.get(id);\n"
        "}\n"
    )
    return _build_git_repo(
        tmp_path / f"tenant-cache-{variant}",
        f"https://github.com/example-acme/tenant-cache-{variant}",
        {
            "package.json": json.dumps(
                {
                    "name": "acme-workspace",
                    "private": True,
                    "version": "0.0.0",
                    "workspaces": ["packages/*", "apps/*"],
                },
                indent=2,
            ),
            "packages/cache-lib/package.json": json.dumps(
                {"name": "@acme/cache-lib", "version": "1.2.0"}, indent=2
            ),
            "packages/cache-lib/src/cache.ts": (
                "export class ItemCache {\n"
                "  private readonly entries = new Map<string, string>();\n"
                "  put(id: string, value: string): void { this.entries.set(id, value); }\n"
                "  get(id: string): string | undefined { return this.entries.get(id); }\n"
                "}\n"
            ),
            "packages/tenant-ids/package.json": json.dumps(
                {"name": "@acme/tenant-ids", "version": "1.2.0"}, indent=2
            ),
            "packages/tenant-ids/src/id.ts": (
                "// IDs are sequential per tenant and collide across distinct tenants.\n"
                "const seqByTenant = new Map<string, number>();\n"
                "export function nextTenantItemId(tenantId: string): string {\n"
                "  const n = (seqByTenant.get(tenantId) ?? 0) + 1;\n"
                "  seqByTenant.set(tenantId, n);\n"
                "  return `item-${n}`;\n"
                "}\n"
            ),
            "packages/billing-helper/package.json": json.dumps(
                {"name": "@acme/billing-helper", "version": "1.2.0"}, indent=2
            ),
            "packages/billing-helper/src/query.ts": (
                "export function buildInvoiceSql(rawFilter: string): string {\n"
                '  return "SELECT * FROM invoices WHERE code = \'" + rawFilter + "\'";\n'
                "}\n"
            ),
            "apps/api-server/package.json": json.dumps(
                {"name": "@acme/api-server", "private": True, "version": "1.2.0"}, indent=2
            ),
            "apps/api-server/src/server.ts": app_server,
        },
        tag="v1.2.0",
    )
