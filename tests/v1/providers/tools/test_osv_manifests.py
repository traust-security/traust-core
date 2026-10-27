"""The osv scanner's manifest readers: one realistic fixture per reader, the ecosystem edge
cases, and malformed input read as (None, []). Ported from traust-engine's portfolio parsers."""

from __future__ import annotations

import json

import pytest

from traust_core.v1.providers.tools import osv_manifests as M


def _deps(parsed: M.Parsed) -> list[M.Dep]:
    return sorted(parsed[1])


# ------------------------------------------------------------------- npm
PACKAGE_LOCK = """\
{
  "name": "my-app",
  "lockfileVersion": 3,
  "packages": {
    "": {
      "name": "my-app",
      "version": "1.0.0",
      "dependencies": {"lodash": "^4.17.20"},
      "devDependencies": {"@scope/pkg": "^2.0.0"}
    },
    "node_modules/lodash": {"version": "4.17.21"},
    "node_modules/@scope/pkg": {"version": "2.1.0"},
    "node_modules/transitive-dep": {"version": "0.5.0"}
  }
}
"""

PACKAGE_JSON = """\
{
  "name": "web-ui",
  "dependencies": {"@backstage/core": "^1.2.3", "react": "18.2.0"},
  "devDependencies": {"jest": "~29.0.0"}
}
"""


def test_package_lock_v3_root_and_node_modules() -> None:
    declared, _ = M.parse_package_lock(PACKAGE_LOCK)
    assert declared == "my-app"
    assert _deps(M.parse_package_lock(PACKAGE_LOCK)) == sorted(
        [
            ("@scope/pkg", "2.1.0", False),  # scoped, root devDep -> direct
            ("lodash", "4.17.21", False),  # root dep -> direct
            ("transitive-dep", "0.5.0", True),  # only in node_modules
        ]
    )


def test_package_json_scoped_and_range_strip() -> None:
    declared, _ = M.parse_package_json(PACKAGE_JSON)
    assert declared == "web-ui"
    assert _deps(M.parse_package_json(PACKAGE_JSON)) == sorted(
        [
            ("@backstage/core", "1.2.3", False),
            ("react", "18.2.0", False),
            ("jest", "29.0.0", False),
        ]
    )


def test_package_lock_malformed() -> None:
    assert M.parse_package_lock("{not json") == (None, [])


def test_npm_alias_resolved_in_package_lock() -> None:
    # Regression: an npm alias (`"legacy-swc-helpers":
    # "npm:@swc/helpers@=0.4.14"`) must resolve to the REAL package
    # (@swc/helpers), never the alias name — the alias name-matched a
    # malicious-package advisory (MAL-2024-7969) and produced a false
    # positive (2026-08-05). npm records the real name in `name`.
    lock = json.dumps(
        {
            "name": "aliased-app",
            "packages": {
                "": {
                    "name": "aliased-app",
                    "dependencies": {"legacy-swc-helpers": "npm:@swc/helpers@=0.4.14"},
                },
                "node_modules/legacy-swc-helpers": {
                    "name": "@swc/helpers",
                    "version": "0.4.14",
                },
            },
        }
    )
    _declared, deps = M.parse_package_lock(lock)
    names = [d[0] for d in deps]
    assert "@swc/helpers" in names
    assert "legacy-swc-helpers" not in names
    # resolved as a direct dep (the alias key is a root dependency)
    assert ("@swc/helpers", "0.4.14", False) in deps


def test_npm_alias_resolved_in_package_json() -> None:
    pj = json.dumps(
        {
            "name": "aliased-app",
            "dependencies": {
                "legacy-swc-helpers": "npm:@swc/helpers@=0.4.14",
                "react": "^18.2.0",
            },
        }
    )
    deps = _deps(M.parse_package_json(pj))
    assert deps == sorted(
        [
            ("@swc/helpers", "0.4.14", False),  # alias -> real package
            ("react", "18.2.0", False),
        ]
    )


def test_resolve_npm_alias_helper() -> None:
    assert M._resolve_npm_alias("npm:@swc/helpers@=0.4.14") == ("@swc/helpers", "0.4.14")
    assert M._resolve_npm_alias("npm:left-pad@^1.3.0") == ("left-pad", "1.3.0")
    assert M._resolve_npm_alias("npm:some-pkg") == ("some-pkg", "")
    assert M._resolve_npm_alias("^1.2.3") is None
    assert M._resolve_npm_alias("2.5.3") is None


PNPM_LOCK = """\
lockfileVersion: '6.0'

dependencies:
  lodash:
    specifier: ^4.17.21
    version: 4.17.21
  '@scope/util':
    specifier: ^1.0.0
    version: 1.0.5

devDependencies:
  typescript:
    specifier: ^5.0.0
    version: 5.1.6

packages:

  /lodash@4.17.21:
    resolution: {integrity: sha512-xxx}
    dev: false

  /@scope/util@1.0.5:
    resolution: {integrity: sha512-yyy}
    dev: false

  /@babel/core@7.22.0(supports-color@8.1.1):
    resolution: {integrity: sha512-zzz}
    dependencies:
      lodash: 4.17.21
    dev: true

  /typescript@5.1.6:
    resolution: {integrity: sha512-www}
    dev: true
"""

# npm-shrinkwrap.json is byte-for-byte the package-lock schema
NPM_SHRINKWRAP = PACKAGE_LOCK


def test_pnpm_direct_vs_transitive() -> None:
    declared, deps = M.parse_pnpm_lock(PNPM_LOCK)
    assert declared is None
    assert _deps((declared, deps)) == sorted(
        [
            ("lodash", "4.17.21", False),  # under dependencies:
            ("@scope/util", "1.0.5", False),  # scoped direct
            ("typescript", "5.1.6", False),  # under devDependencies:
            ("@babel/core", "7.22.0", True),  # only in packages: -> tr.
        ]
    )


def test_npm_shrinkwrap_delegates_to_package_lock() -> None:
    assert M.parse_npm_shrinkwrap(NPM_SHRINKWRAP) == M.parse_package_lock(NPM_SHRINKWRAP)


# ------------------------------------------------------------------- PyPI
REQUIREMENTS = """\
# top-level comment
-r base.txt
-e .
Foo.Bar_Baz==1.2.3
requests>=2.20.0  # inline comment
urllib3==1.26.5 ; python_version < "3.9"
"""

PYPROJECT_621 = """\
[project]
name = "my-pkg"
dependencies = ["requests>=2.20", "PyYAML"]

[project.optional-dependencies]
dev = ["pytest>=7.0"]
"""

PYPROJECT_POETRY = """\
[tool.poetry]
name = "poetry-pkg"

[tool.poetry.dependencies]
python = "^3.10"
requests = "^2.28.0"
click = {version = "8.1.3", optional = false}

[tool.poetry.group.dev.dependencies]
pytest = "^7.2"
"""

POETRY_LOCK = """\
[[package]]
name = "requests"
version = "2.28.1"

[[package]]
name = "urllib3"
version = "1.26.12"
"""

PIPFILE_LOCK = """\
{
  "default": {"cryptography": {"version": "==41.0.3"}},
  "develop": {"pytest": {"version": "==7.4.0"}}
}
"""


def test_requirements_markers_includes_normalization() -> None:
    declared, _ = M.parse_requirements_txt(REQUIREMENTS)
    assert declared is None
    assert _deps(M.parse_requirements_txt(REQUIREMENTS)) == sorted(
        [
            ("foo-bar-baz", "1.2.3", False),  # PEP 503 normalized
            ("requests", "2.20.0", False),  # inline comment stripped
            ("urllib3", "1.26.5", False),  # env marker ignored
        ]
    )


def test_pyproject_pep621() -> None:
    declared, _ = M.parse_pyproject_deps(PYPROJECT_621)
    assert declared == "my-pkg"
    assert _deps(M.parse_pyproject_deps(PYPROJECT_621)) == sorted(
        [
            ("requests", ">=2.20", False),
            ("pyyaml", "", False),
            ("pytest", ">=7.0", False),
        ]
    )


def test_pyproject_poetry() -> None:
    declared, deps = M.parse_pyproject_deps(PYPROJECT_POETRY)
    assert declared == "poetry-pkg"
    names = {d[0] for d in deps}
    assert "python" not in names  # poetry python pin excluded
    assert _deps((declared, deps)) == sorted(
        [
            ("requests", "^2.28.0", False),
            ("click", "8.1.3", False),
            ("pytest", "^7.2", False),
        ]
    )


def test_poetry_lock_all_indirect() -> None:
    declared, deps = M.parse_poetry_lock(POETRY_LOCK)
    assert declared is None
    assert all(d[2] for d in deps)
    assert _deps((declared, deps)) == sorted(
        [
            ("requests", "2.28.1", True),
            ("urllib3", "1.26.12", True),
        ]
    )


def test_pipfile_lock_strip_eq() -> None:
    assert _deps(M.parse_pipfile_lock(PIPFILE_LOCK)) == sorted(
        [
            ("cryptography", "41.0.3", True),
            ("pytest", "7.4.0", True),
        ]
    )


SETUP_PY = """\
from setuptools import setup, find_packages

setup(
    name="my-tool",
    version="0.1.0",
    packages=find_packages(),
    install_requires=[
    "requests>=2.20",
    "PyYAML",
    "click==8.1.3",
    ],
)
"""

CONSTRAINTS = """\
requests==2.28.1
urllib3==1.26.5
"""

ENVIRONMENT_YML = """\
name: myenv
channels:
  - conda-forge
dependencies:
  - python=3.10
  - numpy=1.24.0
  - pandas==2.0.0
  - pip
  - pip:
    - requests>=2.28
    - flask
"""


def test_setup_py_install_requires() -> None:
    declared, deps = M.parse_setup_py(SETUP_PY)
    assert declared == "my-tool"
    assert _deps((declared, deps)) == sorted(
        [
            ("requests", ">=2.20", False),
            ("pyyaml", "", False),  # PEP 503 normalized, no version
            ("click", "==8.1.3", False),
        ]
    )


def test_constraints_delegates_to_requirements() -> None:
    assert M.parse_constraints_txt(CONSTRAINTS) == M.parse_requirements_txt(CONSTRAINTS)
    assert _deps(M.parse_constraints_txt(CONSTRAINTS)) == sorted(
        [
            ("requests", "2.28.1", False),
            ("urllib3", "1.26.5", False),
        ]
    )


def test_environment_yml_conda_and_pip() -> None:
    declared, deps = M.parse_environment_yml(ENVIRONMENT_YML)
    assert declared is None
    assert _deps((declared, deps)) == sorted(
        [
            ("python", "3.10", False),  # conda name=version
            ("numpy", "1.24.0", False),  # conda name=version
            ("pandas", "2.0.0", False),  # conda name==version
            ("pip", "", False),  # bare conda pip package
            ("requests", ">=2.28", False),  # nested pip: list (PEP 508)
            ("flask", "", False),  # nested pip: list
        ]
    )


# ------------------------------------------------------------------- Maven
POM = """\
<project>
  <groupId>com.example</groupId>
  <artifactId>my-service</artifactId>
  <version>3.1.0</version>
  <properties>
    <jackson.version>2.15.2</jackson.version>
  </properties>
  <dependencies>
    <dependency>
      <groupId>com.fasterxml.jackson.core</groupId>
      <artifactId>jackson-databind</artifactId>
      <version>${jackson.version}</version>
    </dependency>
    <dependency>
      <groupId>com.example</groupId>
      <artifactId>sibling</artifactId>
      <version>${project.version}</version>
    </dependency>
    <dependency>
      <groupId>org.managed</groupId>
      <artifactId>no-version-here</artifactId>
    </dependency>
  </dependencies>
</project>
"""

POM_NS = """\
<project xmlns="http://maven.apache.org/POM/4.0.0">
  <groupId>org.ns</groupId>
  <artifactId>ns-app</artifactId>
  <version>1.0.0</version>
  <dependencies>
    <dependency>
      <groupId>org.slf4j</groupId>
      <artifactId>slf4j-api</artifactId>
      <version>1.7.36</version>
    </dependency>
  </dependencies>
</project>
"""

POM_DEPMGMT = """\
<project>
  <groupId>com.example</groupId>
  <artifactId>parent</artifactId>
  <version>1.0.0</version>
  <properties>
    <spring.version>5.3.20</spring.version>
  </properties>
  <dependencyManagement>
    <dependencies>
      <dependency>
    <groupId>org.springframework</groupId>
    <artifactId>spring-core</artifactId>
    <version>${spring.version}</version>
      </dependency>
    </dependencies>
  </dependencyManagement>
</project>
"""

POM_AGGREGATOR = """\
<project>
  <groupId>com.example</groupId>
  <artifactId>aggregator</artifactId>
  <version>1.0.0</version>
  <modules>
    <module>core</module>
    <module>api</module>
  </modules>
</project>
"""

GRADLE_LOCKFILE = """\
# This is a Gradle generated file for dependency locking.
com.google.guava:guava:31.1-jre=compileClasspath,runtimeClasspath
org.slf4j:slf4j-api:1.7.36=runtimeClasspath
empty=annotationProcessor
"""

BUILD_GRADLE = """\
dependencies {
    implementation 'org.apache.commons:commons-lang3:3.12.0'
    api "com.google.guava:guava:31.1-jre"
    testImplementation 'junit:junit:4.13.2'
}
"""


def test_pom_property_projectversion_and_omitted() -> None:
    declared, deps = M.parse_pom_xml(POM)
    assert declared == "com.example:my-service"
    names = {d[0] for d in deps}
    # the version-less dependency is omitted, not emitted with a bogus
    # or empty version
    assert "org.managed:no-version-here" not in names
    assert _deps((declared, deps)) == sorted(
        [
            ("com.fasterxml.jackson.core:jackson-databind", "2.15.2", False),
            ("com.example:sibling", "3.1.0", False),  # ${project.version}
        ]
    )


def test_pom_default_namespace() -> None:
    declared, deps = M.parse_pom_xml(POM_NS)
    assert declared == "org.ns:ns-app"
    assert deps == [("org.slf4j:slf4j-api", "1.7.36", False)]


def test_gradle_lockfile() -> None:
    declared, deps = M.parse_gradle_lockfile(GRADLE_LOCKFILE)
    assert declared is None
    assert all(d[2] for d in deps)  # lockfile -> indirect
    assert _deps((declared, deps)) == sorted(
        [
            ("com.google.guava:guava", "31.1-jre", True),
            ("org.slf4j:slf4j-api", "1.7.36", True),
        ]
    )


def test_build_gradle() -> None:
    assert _deps(M.parse_build_gradle(BUILD_GRADLE)) == sorted(
        [
            ("org.apache.commons:commons-lang3", "3.12.0", False),
            ("com.google.guava:guava", "31.1-jre", False),
            ("junit:junit", "4.13.2", False),
        ]
    )


def test_pom_dependency_management_read() -> None:
    declared, deps = M.parse_pom_xml(POM_DEPMGMT)
    assert declared == "com.example:parent"
    # version pinned only under <dependencyManagement> is now read
    assert _deps((declared, deps)) == sorted(
        [
            ("org.springframework:spring-core", "5.3.20", False),
        ]
    )


def test_pom_aggregator_modules_only_is_legit_empty() -> None:
    # root/aggregator pom with only <modules> -> (declared, []) is
    # correct, not an error
    declared, deps = M.parse_pom_xml(POM_AGGREGATOR)
    assert declared == "com.example:aggregator"
    assert deps == []


def test_pom_malformed() -> None:
    assert M.parse_pom_xml("<project><oops") == (None, [])


# ------------------------------------------------------------------- Cargo
CARGO_LOCK = """\
[[package]]
name = "serde"
version = "1.0.152"

[[package]]
name = "libc"
version = "0.2.139"
"""

CARGO_TOML = """\
[package]
name = "my-crate"
version = "0.3.0"

[dependencies]
serde = "1.0"
tokio = {version = "1.25", features = ["full"]}

[dev-dependencies]
criterion = "0.4"
"""


def test_cargo_lock_all_indirect() -> None:
    declared, deps = M.parse_cargo_lock(CARGO_LOCK)
    assert declared is None
    assert _deps((declared, deps)) == sorted(
        [
            ("serde", "1.0.152", True),
            ("libc", "0.2.139", True),
        ]
    )


def test_cargo_toml_string_and_table() -> None:
    declared, deps = M.parse_cargo_toml(CARGO_TOML)
    assert declared == "my-crate"
    assert _deps((declared, deps)) == sorted(
        [
            ("serde", "1.0", False),
            ("tokio", "1.25", False),  # table form
            ("criterion", "0.4", False),
        ]
    )


# ----------------------------------------------------------------- RubyGems
GEMFILE_LOCK = """\
GEM
  remote: https://rubygems.org/
  specs:
    actionpack (6.1.4)
      actionview (= 6.1.4)
      rack (~> 2.0)
    rack (2.2.3)

PLATFORMS
  ruby

DEPENDENCIES
  rails
"""

GEMSPEC = """\
Gem::Specification.new do |spec|
  spec.name = "my-gem"
  spec.version = "1.0.0"
  spec.add_dependency "activesupport", ">= 6.0"
  spec.add_runtime_dependency("nokogiri", "~> 1.13")
  spec.add_development_dependency "rspec", "~> 3.12"
end
"""

GEMFILE = """\
source "https://rubygems.org"
gem "rails", "~> 6.1.4"
gem "puma", "~> 5.0"
gem "bootsnap", require: false
"""


def test_gemfile_lock_spec_vs_subdep() -> None:
    declared, deps = M.parse_gemfile_lock(GEMFILE_LOCK)
    assert declared is None
    # 4-space specs kept with pinned versions; deeper sub-deps
    # (actionview/rack constraints) skipped
    assert _deps((declared, deps)) == sorted(
        [
            ("actionpack", "6.1.4", True),
            ("rack", "2.2.3", True),
        ]
    )


def test_gemspec() -> None:
    declared, deps = M.parse_gemspec(GEMSPEC)
    assert declared == "my-gem"
    assert _deps((declared, deps)) == sorted(
        [
            ("activesupport", ">= 6.0", False),
            ("nokogiri", "~> 1.13", False),
            ("rspec", "~> 3.12", False),
        ]
    )


def test_gemfile() -> None:
    declared, deps = M.parse_gemfile(GEMFILE)
    assert declared is None
    assert _deps((declared, deps)) == sorted(
        [
            ("rails", "~> 6.1.4", False),
            ("puma", "~> 5.0", False),
            ("bootsnap", "", False),  # no version arg
        ]
    )


# ------------------------------------------------------------------- NuGet
PACKAGES_LOCK = """\
{
  "version": 1,
  "dependencies": {
    "net6.0": {
      "Newtonsoft.Json": {"type": "Direct", "resolved": "13.0.1"},
      "System.Text.Json": {"type": "Transitive", "resolved": "6.0.0"},
      "MyProject.Lib": {"type": "Project"}
    }
  }
}
"""

CSPROJ = """\
<Project Sdk="Microsoft.NET.Sdk">
  <ItemGroup>
    <PackageReference Include="Serilog" Version="2.12.0" />
    <PackageReference Include="Dapper" Version="2.0.123" />
  </ItemGroup>
</Project>
"""


def test_packages_lock_direct_vs_transitive() -> None:
    declared, deps = M.parse_packages_lock_json(PACKAGES_LOCK)
    assert declared is None
    # Project-type entry has no "resolved" -> skipped
    assert _deps((declared, deps)) == sorted(
        [
            ("newtonsoft.json", "13.0.1", False),  # Direct
            ("system.text.json", "6.0.0", True),  # Transitive
        ]
    )


def test_csproj() -> None:
    declared, deps = M.parse_csproj(CSPROJ)
    assert declared is None
    assert _deps((declared, deps)) == sorted(
        [
            ("Serilog", "2.12.0", False),
            ("Dapper", "2.0.123", False),
        ]
    )


# ------------------------------------------------------- GitHub Actions
WORKFLOW = """\
name: CI
on: [push]
jobs:
  build:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - name: Setup
    uses: actions/setup-node@v3.8.1
      - uses: ./.github/actions/local-setup
      - uses: docker://alpine:3.18
      - uses: aws-actions/configure-aws-credentials@v2
      - uses: monorepo/tools/sub-action@abc123def
"""


def test_workflow_uses_extraction() -> None:
    declared, deps = M.parse_github_workflow(WORKFLOW)
    assert declared is None
    # local ./ and docker:// skipped; owner/repo canonicalized (subdir
    # dropped for monorepo/tools/sub-action)
    assert _deps((declared, deps)) == sorted(
        [
            ("actions/checkout", "v4", False),
            ("actions/setup-node", "v3.8.1", False),
            ("aws-actions/configure-aws-credentials", "v2", False),
            ("monorepo/tools", "abc123def", False),
        ]
    )


def test_workflow_malformed() -> None:
    assert M.parse_github_workflow("not: a: workflow: [") == (None, [])


# --------------------------------------------------------------- dispatch
def test_parser_for_exact_and_globs() -> None:
    assert M.parser_for("package-lock.json")[0] == "npm"
    assert M.parser_for("deep/dir/pom.xml")[1] is M.parse_pom_xml
    assert M.parser_for("my-gem.gemspec") == ("ruby", M.parse_gemspec)
    assert M.parser_for("Foo.csproj") == ("nuget", M.parse_csproj)
    assert M.parser_for("requirements-dev.txt") == ("pypi", M.parse_requirements_txt)
    assert M.parser_for("unknown.file") is None


def test_parser_for_more_filenames() -> None:
    assert M.parser_for("pnpm-lock.yaml") == ("npm", M.parse_pnpm_lock)
    assert M.parser_for("npm-shrinkwrap.json") == ("npm", M.parse_npm_shrinkwrap)
    assert M.parser_for("setup.py") == ("pypi", M.parse_setup_py)
    assert M.parser_for("constraints.txt") == ("pypi", M.parse_constraints_txt)
    assert M.parser_for("environment.yml") == ("pypi", M.parse_environment_yml)
    # Dockerfiles and Helm charts have no OSV ecosystem: the osv scan reads none of them
    for name in ("Chart.yaml", "requirements.yaml", "Dockerfile", "Dockerfile.dev"):
        assert M.parser_for(name) is None


def test_parser_for_path_workflow_routing() -> None:
    assert M.parser_for_path(".github/workflows/ci.yml") == ("actions", M.parse_github_workflow)
    assert M.parser_for_path("repo/.github/workflows/release.yaml") == (
        "actions",
        M.parse_github_workflow,
    )
    assert M.is_workflow_path(".github/workflows/ci.yml")
    assert M.parser_for_path("deep/dir/pnpm-lock.yaml") == ("npm", M.parse_pnpm_lock)
    # a Chart.yaml is not a workflow even though it is yaml
    assert not M.is_workflow_path("charts/foo/Chart.yaml")


def test_garbage_returns_empty() -> None:
    assert M.parse_package_json("\x00not{json") == (None, [])
    assert M.parse_cargo_toml("this is = not [valid toml") == (None, [])
    assert M.parse_pyproject_deps("[[[broken") == (None, [])
    assert M.parse_packages_lock_json("<xml/>") == (None, [])
    assert M.parse_pnpm_lock("\x00: :[") == (None, [])
    assert M.parse_environment_yml("\x00garbage") == (None, [])
    assert M.parse_setup_py("nonsense without a call") == (None, [])
    assert M.parse_github_workflow("not: a: workflow") == (None, [])
    # empty input across every parser -> clean (None|declared, [])
    for fn in (
        M.parse_package_lock,
        M.parse_package_json,
        M.parse_npm_shrinkwrap,
        M.parse_pnpm_lock,
        M.parse_requirements_txt,
        M.parse_pyproject_deps,
        M.parse_poetry_lock,
        M.parse_pipfile_lock,
        M.parse_pom_xml,
        M.parse_setup_py,
        M.parse_constraints_txt,
        M.parse_environment_yml,
        M.parse_gradle_lockfile,
        M.parse_build_gradle,
        M.parse_cargo_lock,
        M.parse_cargo_toml,
        M.parse_gemfile_lock,
        M.parse_gemspec,
        M.parse_gemfile,
        M.parse_packages_lock_json,
        M.parse_csproj,
        M.parse_github_workflow,
    ):
        _declared, deps = fn("")
        assert deps == [], fn.__name__


def test_requirements_extras_are_parsed() -> None:
    _, deps = M.parse_requirements_txt("aiohttp[speedups]==3.14.1\nx[a,b] >= 2\n")
    assert ("aiohttp", "3.14.1", False) in deps
    assert ("x", "2", False) in deps


YARN_V1 = """# yarn lockfile v1


"@algolia/autocomplete-core@1.5.2", "@algolia/autocomplete-core@^1.5.0":
  version "1.5.2"
  dependencies:
    "@algolia/autocomplete-shared" "1.5.2"

lodash@^4.17.0:
  version "4.17.15"
"""

YARN_BERRY = """__metadata:
  version: 8

"@aashutoshrathi/word-wrap@npm:^1.2.3":
  version: 1.2.6
  resolution: "@aashutoshrathi/word-wrap@npm:1.2.6"

"my-app@workspace:.":
  version: 0.0.0-use.local

"string-width-cjs@npm:string-width@^4.2.0":
  version: 4.2.3

"@material-ui/pickers@patch:@material-ui/pickers@npm%3A3.3.11#./x.patch::locator=root":
  version: 3.3.11
"""


def test_yarn_classic() -> None:
    _, deps = M.parse_yarn_lock(YARN_V1)
    assert deps == [("@algolia/autocomplete-core", "1.5.2", True), ("lodash", "4.17.15", True)]


def test_yarn_berry_skips_workspaces_and_resolves_aliases() -> None:
    _, deps = M.parse_yarn_lock(YARN_BERRY)
    assert ("@aashutoshrathi/word-wrap", "1.2.6", True) in deps
    assert ("string-width", "4.2.3", True) in deps
    assert ("@material-ui/pickers", "3.3.11", True) in deps
    assert not any(name == "my-app" for name, _, _ in deps)


def test_uv_lock_skips_workspace_members() -> None:
    text = """version = 1

[[package]]
name = "absl-py"
version = "2.4.0"
source = { registry = "https://pypi.org/simple" }

[[package]]
name = "MLflow"
version = "3.0.0.dev0"
source = { editable = "." }

[[package]]
name = "Some_Pkg"
version = "1.2.3"
source = { git = "https://github.com/x/y?rev=abc" }
"""
    _, deps = M.parse_uv_lock(text)
    assert deps == [("absl-py", "2.4.0", True), ("some-pkg", "1.2.3", True)]
    assert M.parse_uv_lock("[[[broken") == (None, [])


@pytest.mark.parametrize(
    "name",
    [
        "requirements.txt",
        "requirements-dev.txt",
        "dev-requirements.txt",
        "py3.10-ci-requirements.txt",
    ],
)
def test_requirements_files_are_found_by_any_name(name: str) -> None:
    hit = M.parser_for(f"sdk/{name}")
    assert hit is not None and hit[0] == "pypi"


GOMOD = """\
module github.com/org/repo-a

go 1.22

require (
\tgithub.com/org/lib-b v1.2.3
\tgolang.org/x/net v0.17.0
\tk8s.io/client-go v0.29.1 // indirect
)

require sigs.k8s.io/yaml v1.4.0
"""


def test_gomod_module_requires_and_indirect() -> None:
    module, requires = M.parse_gomod(GOMOD)
    assert module == "github.com/org/repo-a"
    assert len(requires) == 4
    as_dict = {p: (v, ind) for p, v, ind in requires}
    assert as_dict["github.com/org/lib-b"] == ("v1.2.3", False)
    assert as_dict["k8s.io/client-go"] == ("v0.29.1", True)
    assert as_dict["sigs.k8s.io/yaml"] == ("v1.4.0", False)


def test_gomod_of_non_go_text_is_empty() -> None:
    assert M.parse_gomod("# just a readme\n") == (None, [])
