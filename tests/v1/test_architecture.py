"""Where code may live. Each test names the rule it holds (AGENTS.md "Design rules")."""

from __future__ import annotations

import ast
import importlib
import inspect
import pkgutil
from pathlib import Path

import pytest

import traust_core.v1.models as models
from traust_core.v1.models.base import AppendOnly, Entity
from traust_core.v1.repositories.tables import SqlTableRepository

SRC = Path(__file__).resolve().parents[2] / "src" / "traust_core" / "v1"
REPOSITORIES = SRC / "repositories"
SERVICES = SRC / "services"

# The section each service writes. A service imports only its own section's unit of work.
SERVICE_SECTION = {
    "portfolio": "traust.inventory",
    "onboarding": "traust.inventory",
    "assessment": "traust.assessments",
    "artifact_publishing": "traust.assessments",
    "code_facts": "traust.assessments",
    "pqc": "traust.assessments",
    "compliance": "traust.assessments",
    "detection_quality": "traust.assessments",
    "attestation": "traust.findings",
    "operations": "traust_ops",
    "provider_catalog": "traust_ops",
    "ledger": "traust_ledger",
}
# Use cases that write several sections in one transaction declare TraustUnitOfWork.
SPANS_SECTIONS = {"findings", "exposure", "validation", "remediation", "insight"}

REPOSITORY_PACKAGES = {"traust", "traust_ops", "traust_ledger", "objects"}
REPOSITORY_MODULES = {"__init__", "contract", "memory", "sql", "tables", "unit_of_work"}
IN_MEMORY_ALLOWED = {"InMemoryUnitOfWork", "InMemoryObjectStore"}
FILE_ACCESS = {"open", "read_text", "read_bytes", "write_text", "write_bytes"}


def _tree(path: Path) -> ast.Module:
    return ast.parse(path.read_text())


def _imported_modules(path: Path) -> set[str]:
    found: set[str] = set()
    for node in ast.walk(_tree(path)):
        if isinstance(node, ast.ImportFrom) and node.module:
            found |= {f"{node.module}.{alias.name}" for alias in node.names} | {node.module}
        elif isinstance(node, ast.Import):
            found |= {alias.name for alias in node.names}
    return found


def _service_key(path: Path) -> str:
    rel = path.relative_to(SERVICES)
    return rel.parts[0] if len(rel.parts) > 1 else rel.stem


def _sql_table_repositories() -> set[type]:
    import traust_core.v1.repositories as repositories

    found: set[type] = set()
    for info in pkgutil.walk_packages(repositories.__path__, "traust_core.v1.repositories."):
        module = importlib.import_module(info.name)
        for _, cls in inspect.getmembers(module, inspect.isclass):
            if issubclass(cls, SqlTableRepository) and getattr(cls, "spec", None) is not None:
                found.add(cls)
    return found


def _row_models() -> set[type]:
    found: set[type] = set()
    for info in pkgutil.walk_packages(models.__path__, "traust_core.v1.models."):
        module = importlib.import_module(info.name)
        for _, cls in inspect.getmembers(module, inspect.isclass):
            own = cls.__module__ == module.__name__ and cls not in (Entity, AppendOnly)
            if own and issubclass(cls, Entity | AppendOnly):
                found.add(cls)
    return found


def test_every_row_model_is_a_contract_table() -> None:
    """Entity/AppendOnly mean "a row of a contract table"; anything else is a plain Model."""
    tables = {cls.record for cls in _sql_table_repositories()}
    orphans = sorted(cls.__qualname__ for cls in _row_models() - tables)
    assert not orphans, (
        f"row models with no contract table (use Model, or raise a model gap): {orphans}"
    )


def test_repositories_hold_only_contract_tables_and_object_storage() -> None:
    """No side repositories: tables live under traust*/, bytes under objects/."""
    extra = sorted(
        p.name
        for p in REPOSITORIES.iterdir()
        if p.name != "__pycache__"
        and (
            (p.is_dir() and p.name not in REPOSITORY_PACKAGES)
            or (p.suffix == ".py" and p.stem not in REPOSITORY_MODULES)
        )
    )
    assert not extra, f"unexpected modules under repositories/: {extra}"


@pytest.mark.parametrize(
    "path", sorted(SERVICES.rglob("*.py")), ids=lambda p: str(p.relative_to(SRC))
)
def test_service_uses_its_own_section(path: Path) -> None:
    """A service reaches another domain through that domain's service, never its repositories."""
    key = _service_key(path)
    allowed = {"traust_core.v1.repositories.objects", "traust_core.v1.repositories.unit_of_work"}
    if key in SERVICE_SECTION:
        allowed.add(f"traust_core.v1.repositories.{SERVICE_SECTION[key]}")
    if key in SPANS_SECTIONS:
        allowed.add("traust_core.v1.repositories.contract.TraustUnitOfWork")
    bad = sorted(
        name
        for name in _imported_modules(path)
        if name.startswith("traust_core.v1.repositories")
        and name != "traust_core.v1.repositories.contract"
        and not any(name == a or name.startswith(a + ".") for a in allowed)
    )
    assert not bad, f"{key} may not import {bad}"


@pytest.mark.parametrize(
    "path",
    sorted(
        [
            *SERVICES.rglob("*.py"),
            *(REPOSITORIES / "traust").rglob("*.py"),
            *(REPOSITORIES / "traust_ops").rglob("*.py"),
            *(REPOSITORIES / "traust_ledger").rglob("*.py"),
        ]
    ),
    ids=lambda p: str(p.relative_to(SRC)),
)
def test_no_file_or_sqlite_access_outside_object_storage(path: Path) -> None:
    """Services and table repositories read contract tables only; bytes go via ObjectStore."""
    hits = []
    for node in ast.walk(_tree(path)):
        if isinstance(node, ast.Import | ast.ImportFrom):
            names = {a.name for a in node.names} | {getattr(node, "module", None) or ""}
            if "sqlite3" in names:
                hits.append("import sqlite3")
        elif isinstance(node, ast.Call):
            fn = node.func
            name = fn.attr if isinstance(fn, ast.Attribute) else getattr(fn, "id", "")
            if name in FILE_ACCESS and not (isinstance(fn, ast.Attribute) and name == "open"):
                hits.append(f"{name}()")
            if isinstance(fn, ast.Name) and fn.id == "open":
                hits.append("open()")
    assert not hits, f"{path.relative_to(SRC)}: {sorted(set(hits))}"


def test_in_memory_doubles_live_in_tests() -> None:
    """In-memory stand-ins hide missing persistence; only the shared doubles stay in src."""
    found = sorted(
        f"{p.relative_to(SRC)}:{node.name}"
        for p in SRC.rglob("*.py")
        for node in ast.walk(_tree(p))
        if isinstance(node, ast.ClassDef)
        and node.name.startswith("InMemory")
        and node.name not in IN_MEMORY_ALLOWED
    )
    assert not found, f"move in-memory doubles to tests/: {found}"


def test_context_opens_only_the_configured_database() -> None:
    """Context builds one engine from config; it never opens another database."""
    engines, connects = [], []
    for path in (SRC / "context").rglob("*.py"):
        for node in ast.walk(_tree(path)):
            if isinstance(node, ast.Call):
                fn = node.func
                name = fn.attr if isinstance(fn, ast.Attribute) else getattr(fn, "id", "")
                where = f"{path.relative_to(SRC)}:{node.lineno}"
                if name in {"create_database_engine", "create_engine"}:
                    engines.append(where)
                if name == "connect":
                    connects.append(where)
    assert len(engines) <= 1, f"Context creates more than one engine: {engines}"
    assert not connects, f"Context opens connections itself (use a unit of work): {connects}"


def test_only_the_ledger_service_imports_traust_ledger() -> None:
    """traust-ledger is the one traust code dependency (AGENTS.md); one module holds it."""
    importers = sorted(
        str(path.relative_to(SRC))
        for path in SRC.rglob("*.py")
        if any(name.split(".")[0] == "traust_ledger" for name in _imported_modules(path))
    )
    assert importers == ["services/ledger.py"]


def test_only_the_identity_provider_imports_jwt_or_cryptography() -> None:
    """Tokens and their keys have one home: the identity provider."""
    importers = sorted(
        str(path.relative_to(SRC))
        for path in SRC.rglob("*.py")
        if any(name.split(".")[0] in {"jwt", "cryptography"} for name in _imported_modules(path))
    )
    assert importers == ["providers/identity.py"]


REST = SRC / "rest"
REST_DOMAINS = sorted(
    p.name
    for p in REST.iterdir()
    if p.is_dir() and (p / "__init__.py").is_file() and p.name != "common"
)


@pytest.mark.parametrize("domain", REST_DOMAINS)
def test_a_rest_domain_reaches_others_only_through_core(domain: str) -> None:
    """Routes compose across domains in the services, never by importing another domain's routes."""
    others = {f"traust_core.v1.rest.{d}" for d in REST_DOMAINS if d != domain}
    bad = sorted(
        f"{path.relative_to(SRC)}: {name}"
        for path in (REST / domain).rglob("*.py")
        for name in _imported_modules(path)
        if any(name == o or name.startswith(o + ".") for o in others)
    )
    assert not bad, bad


def test_every_rest_domain_is_served() -> None:
    """A domain package under rest/ exposes `router` and is listed in rest.domains.DOMAINS."""
    from traust_core.v1.rest.domains import DOMAINS

    assert sorted(m.__name__.rsplit(".", 1)[-1] for m in DOMAINS) == REST_DOMAINS
    assert all(hasattr(m, "router") for m in DOMAINS)
