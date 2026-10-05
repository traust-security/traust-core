import ast
import sys
from pathlib import Path

import pytest

SRC = Path(__file__).resolve().parents[2] / "src" / "traust_core" / "v1"

ORDER = [
    "domain",
    "contracts",
    "artifacts",
    "interfaces",
    "repositories",
    "rendering",
    "services",
    "security",
    "clients",
    "context",
]
THIRD_PARTY = {
    "domain": {"pydantic"},
    "contracts": {"jsonschema", "referencing"},
    "artifacts": set(),
    "interfaces": {"pydantic"},
    "rendering": {"pydantic"},
    "repositories": {"sqlalchemy", "psycopg", "pydantic"},
    "services": {"pydantic"},
    "security": {"pydantic", "sqlalchemy"},
    "clients": {"pydantic"},
    "context": {"pydantic", "yaml", "sqlalchemy"},
}


def _imports(path: Path) -> set[str]:
    names: set[str] = set()
    for node in ast.walk(ast.parse(path.read_text())):
        if isinstance(node, ast.Import):
            names |= {a.name for a in node.names}
        elif isinstance(node, ast.ImportFrom) and node.module and node.level == 0:
            names |= {f"{node.module}.{a.name}" for a in node.names}
    return names


@pytest.mark.parametrize("package", ORDER)
def test_package_imports(package: str) -> None:
    allowed = {f"traust_core.v1.{p}" for p in ORDER[: ORDER.index(package) + 1]}
    violations = []
    module = SRC / f"{package}.py"
    paths = [module] if module.is_file() else (SRC / package).rglob("*.py")
    for path in paths:
        for name in _imports(path):
            top = name.split(".")[0]
            if top == "__future__" or top in sys.stdlib_module_names:
                continue
            if top == "traust_core":
                ok = any(name == a or name.startswith(a + ".") for a in allowed)
            else:
                ok = top in THIRD_PARTY[package]
            if not ok:
                violations.append(f"{path.relative_to(SRC)}: {name}")
    assert not violations, "dependency rule violations:\n" + "\n".join(violations)
