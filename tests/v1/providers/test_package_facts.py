from __future__ import annotations

from pathlib import Path

from traust_core.v1.context.documents import yaml_documents_with_lines
from traust_core.v1.models.common import ToolRequest
from traust_core.v1.providers.package_facts import PackageIndex


def test_python_package_imports_and_explicit_export_aliases_use_ast(tmp_path: Path) -> None:
    package = tmp_path / "src" / "sample"
    package.mkdir(parents=True)
    (tmp_path / "pyproject.toml").write_text('[project]\nname = "sample-dist"\n')
    (package / "__init__.py").write_text("""from .impl import Internal as Public
__all__ = ["Public"]
# import misleading.package
""")
    (package / "impl.py").write_text("""import outside.client as client
class Internal:
    def method(self):
        pass
def _private():
    pass
""")
    facts = PackageIndex(yaml_documents_with_lines).packages(ToolRequest(workspace=tmp_path))
    assert [(m.ecosystem, m.name) for m in facts.modules] == [("pypi", "sample-dist")]
    assert {(i.package, str(i.location.path)) for i in facts.imports} == {
        ("sample.impl", "src/sample/__init__.py"),
        ("outside.client", "src/sample/impl.py"),
    }
    assert {(e.package, e.name) for e in facts.exports} == {
        ("sample", "Public"),
        ("sample.impl", "Internal"),
    }
    assert facts.gaps == ()


def test_go_nested_modules_import_blocks_and_export_visibility(tmp_path: Path) -> None:
    (tmp_path / "go.mod").write_text("module example.test/root\n")
    nested = tmp_path / "nested"
    nested.mkdir()
    (nested / "go.mod").write_text("module example.test/child\n")
    (nested / "api.go").write_text("""package child
/* import "misleading/package" */
import (
  alias "example.test/shared/api"
  _ "example.test/sideeffect"
)
func Public() {}
func private() {}
""")
    vendor = tmp_path / "vendor"
    vendor.mkdir()
    (vendor / "ignored.go").write_text('package ignored\nimport "ignored/package"\n')
    facts = PackageIndex(yaml_documents_with_lines).packages(ToolRequest(workspace=tmp_path))
    assert {m.name for m in facts.modules} == {"example.test/root", "example.test/child"}
    assert {i.package for i in facts.imports} == {
        "example.test/shared/api",
        "example.test/sideeffect",
    }
    assert [(e.package, e.name) for e in facts.exports] == [("example.test/child", "Public")]


def test_typescript_imports_reexports_and_named_exports_ignore_comment_text(tmp_path: Path) -> None:
    (tmp_path / "package.json").write_text('{"name": "@sample/client"}')
    (tmp_path / "index.ts").write_text("""import { Client } from "@sample/api";
export { Client as PublicClient } from "@sample/api";
export const Create = () => new Client();
const Extra = require("@sample/extra");
// import { Fake } from "misleading";
""")
    facts = PackageIndex(yaml_documents_with_lines).packages(ToolRequest(workspace=tmp_path))
    assert {i.package for i in facts.imports} == {"@sample/api", "@sample/extra"}
    assert {(e.package, e.name) for e in facts.exports} == {
        ("@sample/client", "PublicClient"),
        ("@sample/client", "Create"),
    }
    assert facts.gaps == ()


def test_syntax_failure_is_an_explicit_coverage_gap_not_empty_clean_facts(tmp_path: Path) -> None:
    (tmp_path / "broken.py").write_text("def incomplete(\n")
    facts = PackageIndex(yaml_documents_with_lines).packages(ToolRequest(workspace=tmp_path))
    assert facts.exports == facts.imports == ()
    assert [(g.system, str(g.path)) for g in facts.gaps] == [("Python", "broken.py")]


def test_source_and_manifest_symlinks_are_not_scanned(tmp_path: Path) -> None:
    checkout = tmp_path / "checkout"
    checkout.mkdir()
    outside = tmp_path / "outside.py"
    outside.write_text("import secret.package\n")
    (checkout / "linked.py").symlink_to(outside)
    facts = PackageIndex(yaml_documents_with_lines).packages(ToolRequest(workspace=checkout))
    assert facts.imports == facts.exports == ()
