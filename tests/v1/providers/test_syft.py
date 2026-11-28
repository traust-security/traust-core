"""SyftSbom as a tool provider: the argv digest on its result, and its own version and database."""

from __future__ import annotations

import hashlib
import json
from datetime import UTC, datetime
from enum import StrEnum
from pathlib import Path

import pytest

from traust_core.v1.errors import ConfigError, ServiceError, ValidationError
from traust_core.v1.providers.base import argv_digest
from traust_core.v1.providers.clock import FixedClock
from traust_core.v1.providers.process import ProcessResult, ProcessRunner
from traust_core.v1.providers.syft import SyftSbom, unresolved_manifests
from traust_core.v1.providers.tools import NoDatabase, ToolProvider, ToolRequest
from traust_core.v1.providers.tree import MAX_FILE_BYTES

AT = datetime(2026, 10, 26, tzinfo=UTC)
CDX = json.dumps({"metadata": {"tools": {"components": [{"name": "syft", "version": "1.51.1"}]}}})


class Runner:
    def __init__(self, stdout: str) -> None:
        self.stdout = stdout.encode()
        self.argv: list[str] = []
        self.env: dict[str, str] | None = None

    def run(
        self, argv: list[str], *, check: bool = True, env: dict[str, str] | None = None
    ) -> ProcessResult:
        self.argv, self.env = argv, env
        return ProcessResult(tuple(argv), 0, self.stdout, b"", 0.1)


def syft(stdout: str) -> SyftSbom:
    return SyftSbom(Runner(stdout), FixedClock(AT))  # type: ignore[arg-type]


def test_argv_digest_is_the_sha256_of_the_argv_as_a_json_array() -> None:
    expected = hashlib.sha256(b'["syft", "dir:a b"]').hexdigest()
    assert argv_digest(["syft", "dir:a b"]) == expected
    assert argv_digest(["syft", "dir:a", "b"]) != expected


def test_the_sbom_carries_the_digest_of_the_argv_it_ran(tmp_path: Path) -> None:
    tool = syft(CDX)
    found = tool.acquire(ToolRequest(workspace=tmp_path)).acquisition
    assert found.argv_sha256 == argv_digest(tool._process.argv)  # type: ignore[attr-defined]
    assert (found.version, found.db_built_at) == ("1.51.1", None)


def test_npm_dev_dependencies_are_in_the_sbom(tmp_path: Path) -> None:
    tool = syft(CDX)
    tool.acquire(ToolRequest(workspace=tmp_path))
    assert tool._process.env == {"SYFT_JAVASCRIPT_INCLUDE_DEV_DEPENDENCIES": "true"}  # type: ignore[attr-defined]


def test_syft_reports_its_version_and_keeps_no_database() -> None:
    tool = syft(json.dumps({"application": "syft", "version": "1.51.1"}))
    assert isinstance(tool, ToolProvider)
    assert (tool.version(), tool.database()) == ("1.51.1", None)
    assert tool._process.argv == ["syft", "version", "-o", "json"]  # type: ignore[attr-defined]
    with pytest.raises(NoDatabase, match="syft keeps no database"):
        tool.update_database()


def test_an_unreadable_version_is_a_service_error() -> None:
    with pytest.raises(ServiceError, match="syft version wrote no version"):
        syft("{}").version()


@pytest.mark.parametrize(("allowed", "ready"), [(["syft"], True), (["git"], False)])
def test_syft_is_ready_only_when_the_allowlist_grants_it(
    monkeypatch: pytest.MonkeyPatch, allowed: list[str], ready: bool
) -> None:
    monkeypatch.setattr("shutil.which", lambda _: "/bin/syft")
    assert SyftSbom(ProcessRunner(allowed), FixedClock(AT)).check().ready is ready


def _tree(root: Path, files: dict[str, str]) -> Path:
    for rel, text in files.items():
        (root / rel).parent.mkdir(parents=True, exist_ok=True)
        (root / rel).write_text(text)
    return root


PEP621 = '[project]\nname = "app"\ndependencies = ["requests>=2"]\n'
PACKAGE = json.dumps({"dependencies": {"lodash": "^4"}})
CSPROJ = '<Project><ItemGroup><PackageReference Include="X" Version="1" /></ItemGroup></Project>'


CARGO = '[dependencies]\nserde = "1"\n'


@pytest.mark.parametrize(
    ("files", "expected"),
    [
        ({}, []),
        ({"pyproject.toml": PEP621}, [("pypi", "pyproject.toml")]),
        ({"pyproject.toml": PEP621, "uv.lock": "version = 1\n"}, []),
        ({"pyproject.toml": PEP621, "uv.lock": ""}, [("pypi", "pyproject.toml")]),  # empty lock
        # a requirements file pins only itself, never the pyproject beside it
        (
            {"pyproject.toml": PEP621, "requirements.txt": "flask==3.0.0\n"},
            [("pypi", "pyproject.toml")],
        ),
        ({"pyproject.toml": '[project]\nname = "app"\n'}, []),  # declares nothing
        ({"pyproject.toml": "not = = toml"}, [("pypi", "pyproject.toml")]),  # unreadable
        ({"pyproject.toml": "project = []\n"}, []),  # valid TOML, wrong shape
        (
            {"pyproject.toml": '[project.optional-dependencies]\ndev = ["pytest"]\n'},
            [("pypi", "pyproject.toml")],
        ),
        (
            {"pyproject.toml": '[tool.poetry.group.dev.dependencies]\nruff = "*"\n'},
            [("pypi", "pyproject.toml")],
        ),
        (
            {"pyproject.toml": '[dependency-groups]\ntest = ["pytest"]\n'},
            [("pypi", "pyproject.toml")],
        ),
        ({"requirements.txt": "requests==2.32.0\nflask==3.0.0 --hash=sha256:ab\n"}, []),
        ({"requirements.txt": "requests==2.32.0\npyjwt\n"}, [("pypi", "requirements.txt")]),
        (
            {"dev-requirements.txt": "ruff>=0.5\n-r requirements.txt\n"},
            [("pypi", "dev-requirements.txt")],
        ),
        ({"Pipfile": "[packages]\nrequests = '*'\n"}, [("pypi", "Pipfile")]),
        ({"Pipfile": "[requires]\npython_version = '3.11'\n"}, []),
        ({"Pipfile": "[packages]\nrequests = '*'\n", "Pipfile.lock": '{"default": {}}'}, []),
        ({"ui/package.json": PACKAGE}, [("npm", "ui/package.json")]),
        ({"ui/package.json": PACKAGE, "yarn.lock": "lodash@^4:\n"}, []),  # a workspace lock above
        ({"ui/package.json": PACKAGE, "ui/package-lock.json": "{}"}, [("npm", "ui/package.json")]),
        ({"ui/package.json": json.dumps({"name": "tool"})}, []),
        ({"ui/package.json": "[]"}, []),
        ({"vendor/x/package.json": PACKAGE, "node_modules/y/package.json": PACKAGE}, []),
        ({"crates/a/Cargo.toml": CARGO}, [("cargo", "crates/a/Cargo.toml")]),
        ({"crates/a/Cargo.toml": CARGO, "Cargo.lock": "version = 3\n"}, []),
        (
            {"Cargo.toml": "[target.'cfg(windows)'.dependencies]\nwinapi = '0.3'\n"},
            [("cargo", "Cargo.toml")],
        ),
        ({"Cargo.toml": "workspace = []\n"}, []),
        ({"Gemfile": "gem 'rails'\n"}, [("ruby", "Gemfile")]),
        ({"Gemfile": "source 'https://rubygems.org'\n"}, []),
        # a nested Gemfile locks beside itself, never at the root
        ({"app/Gemfile": "gem 'rails'\n", "Gemfile.lock": "GEM\n"}, [("ruby", "app/Gemfile")]),
        # a Pipfile.lock pins the Pipfile, not a pyproject beside it
        (
            {"pyproject.toml": PEP621, "Pipfile.lock": '{"default": {}}'},
            [("pypi", "pyproject.toml")],
        ),
        ({"src/App/App.csproj": CSPROJ}, [("nuget", "src/App/App.csproj")]),
        ({"src/App/App.fsproj": CSPROJ}, [("nuget", "src/App/App.fsproj")]),
        # a project file's lock sits beside it, never above
        (
            {"src/App/App.csproj": CSPROJ, "packages.lock.json": '{"version": 1}'},
            [("nuget", "src/App/App.csproj")],
        ),
        ({"src/App/App.csproj": CSPROJ, "src/App/packages.lock.json": '{"version": 1}'}, []),
        ({"src/App/App.csproj": "<Project />"}, []),
    ],
)
def test_manifests_with_nothing_to_pin_them_are_unresolved(
    tmp_path: Path, files: dict[str, str], expected: list[tuple[str, str]]
) -> None:
    found = unresolved_manifests(_tree(tmp_path, files))
    assert [(m.ecosystem, m.path) for m in found] == expected
    assert all(
        m.reason == ("unpinned" if "requirements" in m.path else "no-lockfile") for m in found
    )


@pytest.mark.parametrize(
    ("contents", "has_external_base"),
    [
        ("FROM base:1.2.3\n", True),
        ("\ufeffFROM base:1.2.3\n", True),
        ("# escape=\\\nFROM base:1.2.3\n", True),
        ("from --platform=$PLATFORM \\\n  base@sha256:" + "a" * 64 + "\n", True),
        ("FROM ${BASE}\n", True),
        ("FROM scratch AS empty\nFROM empty\n", False),
        ("# FROM base:1.2.3\nFROM scratch\n", False),
        ("FROM scratch\nCOPY --from=registry.example/base:1 /tool /\n", True),
        ('FROM scratch\nCOPY --link --chown=7 --from="${BASE}" ["/bin", "/"]\n', True),
        ("FROM scratch\nCOPY --fr\\\n# middle of flag\nom=base:1 /tool /\n", True),
        ("FROM scratch AS BuIlD\nFROM scratch\nCOPY --from=build /tool /\n", False),
        ("FROM scratch\nFROM scratch\nCOPY --link --from=0 /tool /\n", False),
        ("FROM scratch\nCOPY --from=42 /tool /\n", True),
        ("FROM scratch\nCOPY ./assets --from=not-a-flag /dst/\n", False),
        ("FROM scratch\nRUN echo \\\n# not an instruction\n\n  FROM literal\n", False),
        ("# escape=`\nFROM scratch\nRUN echo `\nCOPY --from=literal / /\n", False),
        ("# escape=`\nFROM scratch\nCO`\nPY --from=external / /\n", True),
        ("# escape=`\nFROM scratch\nCOPY --fr`om=external / /\n", True),
        ("FROM scratch\nCOPY -- --from=literal /\n", False),
        ("FROM scratch\nRUN <<'EOF'\nFROM literal\nCOPY --from=literal / /\nEOF\n", False),
        ('FROM scratch\nCOPY <<A <<-"B" /\nFROM literal\nA\nCOPY --from=x / /\n\tB\n', False),
        (
            'FROM scratch\nRUN cat <<FIRST <<-"SECOND"\n'
            "FROM external/one\nFIRST\nCOPY --from=external/two / /\n\tSECOND\n",
            False,
        ),
        ("FROM scratch\nRUN echo 'cat<<EOF'\n", False),
        ('FROM scratch\nRUN echo "cat<<EOF"\n', False),
        ("FROM scratch\nRUN echo cat\\<<EOF\n", False),
        ("FROM scratch\nRUN cat<<EOF\nFROM external/image\nEOF\n", True),
        ("FROM scratch\nRUN cat 0<<'EOF'\nFROM external/image\nEOF\n", False),
        ('FROM scratch\nRUN cat<<"END OF FILE"\nCOPY --from=external / /\nEND OF FILE\n', True),
        (
            'FROM scratch\nRUN cat<<FIRST<<-"SECOND"\n'
            "FROM external/one\nFIRST\nCOPY --from=external/two / /\n\tSECOND\n",
            True,
        ),
        ("FROM scratch\nRUN cat<<EOF; echo done\nFROM external/image\nEOF\n", True),
        ("FROM scratch\nRUN cat<<EOF\nFROM literal\nEOF\nFROM external/image\n", True),
        ("FROM scratch\nRUN cat<<EOF\nignored\nEOF\nCOPY --from=external / /\n", True),
        ("FROM scratch\nRUN echo 'cat<<EOF'\nFROM external/image\n", True),
        ('FROM scratch\nRUN echo "cat<<EOF"\nFROM external/image\n', True),
        ("FROM scratch\nRUN echo 'cat<<\"RUN true\"'\nFROM external/image\nRUN true\n", True),
        ('FROM scratch\nCOPY file<<"RUN true" /dest\nFROM external/image\nRUN true\n', True),
        ("FROM scratch\nRUN echo cat\\<<EOF\nFROM external/image\n", True),
        ("FROM scratch\nRUN echo ok # cat<<EOF\nFROM external/image\n", True),
        ("FROM scratch\nRUN cat<<<EOF\nFROM external/image\n", True),
        ("FROM scratch\nRUN echo $((1<<2))\n", True),  # ambiguous, never clean
        ("FROM scratch\nRUN cat<<EOF\nignored\n", True),  # compact but unterminated
        ("FROM scratch\nRUN <<EOF\nignored\nEOF\nCOPY --from=base:1 /tool /\n", True),
        ("FROM scratch\nRUN <<EOF\nignored\n", True),  # ambiguous boundary, never clean
        ("FROM scratch\nRUN echo '<<EOF'\nCOPY --from=base:1 /tool /\n", True),
        ("FROM scratch\nONBUILD COPY --from=base:1 /tool /\n", True),
        ("FROM scratch\nRUN [ -f /tmp/x ] && cat <<EOF\nFROM literal\nEOF\n", False),
    ],
)
def test_containerfile_external_images_have_unresolved_coverage(
    tmp_path: Path, contents: str, has_external_base: bool
) -> None:
    found = unresolved_manifests(_tree(tmp_path, {"nested/Dockerfile.build": contents}))
    expected = [("docker", "nested/Dockerfile.build", "unsupported-manifest")]
    assert [(m.ecosystem, m.path, m.reason) for m in found] == (
        expected if has_external_base else []
    )


@pytest.mark.parametrize(
    "contents",
    [
        "FROM external/image\n",
        "FROM scratch\nRUN cat<<EOF\nFROM literal\nEOF\n",
    ],
)
def test_docker_coverage_fails_closed_when_contract_reason_is_unavailable(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, contents: str
) -> None:
    class LegacyReason(StrEnum):
        NO_LOCKFILE = "no-lockfile"
        UNPINNED = "unpinned"

    monkeypatch.setattr("traust_core.v1.providers.syft.ManifestCoverageReason", LegacyReason)
    workspace = _tree(tmp_path, {"package.json": PACKAGE, "Dockerfile": contents})
    with pytest.raises(ConfigError, match="installed manifest coverage contract lacks reason"):
        unresolved_manifests(workspace)


def test_an_oversized_manifest_is_unresolved_without_reading_it(tmp_path: Path) -> None:
    (tmp_path / "package.json").write_text(" " * (MAX_FILE_BYTES + 1))
    assert [m.path for m in unresolved_manifests(tmp_path)] == ["package.json"]


def test_a_missing_workspace_is_refused(tmp_path: Path) -> None:
    with pytest.raises(ValidationError):
        unresolved_manifests(tmp_path / "missing")


@pytest.mark.parametrize(
    ("name", "text", "locked", "reason"),
    [
        ("setup.py", "setup(install_requires=['requests>=2'])\n", False, "unpinned"),
        ("setup.py", "setup(install_requires=REQS)\n", False, "unpinned"),  # built at run time
        ("setup.py", "setup(extras_require={'x': ['idna']})\n", False, "unpinned"),
        ("setup.py", "setup(install_requires=['requests==2.32.3'])\n", False, None),  # read
        ("setup.py", "setup(install_requires=['requests>=2'])\n", True, None),  # lock pins it
        ("setup.py", "setup(name='x')\n", False, None),  # declares nothing
        # syft's reader takes a one-word name only (syft 1.48.0 parse_setup.go pinnedDependency)
        ("setup.py", "setup(install_requires=['python-dateutil==2.8.2'])\n", False, "unpinned"),
        ("setup.py", "setup(install_requires=['zope.interface==5.0'])\n", False, "unpinned"),
        ("setup.py", "setup(install_requires=['requests[security]==2.31.0'])\n", False,
         "unpinned"),
        ("setup.py", "setup(install_requires=['pkg==1.0+local'])\n", False, "unpinned"),
        # only setup() declares requirements
        ("setup.py", "validate(install_requires=['foo>=1'])\nsetup(name='x')\n", False, None),
        ("setup.py", "import setuptools\nsetuptools.setup(install_requires=['a>=1'])\n", False,
         "unpinned"),
        # `**` expansion: a literal dict is read through, anything else is unknown
        ("setup.py", "setup(**{'install_requires': ['requests>=2']})\n", False, "unpinned"),
        ("setup.py", "setup(**{'install_requires': ['requests==2.32.3']})\n", False, None),
        ("setup.py", "setup(**meta)\n", False, "unpinned"),
        ("setup.cfg", "[options]\ninstall_requires =\n    requests==2.32.3\n", False,
         "unsupported-manifest"),  # syft catalogs setup.cfg not at all
        ("setup.cfg", "[metadata]\nname = x\n", False, None),
    ],
    ids=["range", "dynamic", "extras", "exact pins", "locked", "no requirements",
         "hyphenated name", "dotted name", "extras name", "local version",
         "unrelated call", "module setup", "literal dict expansion", "pinned dict expansion",
         "opaque expansion",
         "setup.cfg requirements", "setup.cfg metadata only"],
)  # fmt: skip
def test_setup_py_and_setup_cfg_requirements_syft_cant_read_are_unresolved(
    tmp_path: Path, name: str, text: str, locked: bool, reason: str | None
) -> None:
    (tmp_path / name).write_text(text)
    if locked:
        (tmp_path / "uv.lock").write_text("version = 1\n")
    found = unresolved_manifests(tmp_path)
    assert [(m.path, m.reason) for m in found] == ([(name, reason)] if reason else [])
