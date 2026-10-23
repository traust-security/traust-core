from __future__ import annotations

import json
import textwrap
from datetime import UTC, datetime
from pathlib import Path

import pytest

from traust_core.v1.errors import ServiceError, ValidationError
from traust_core.v1.models.code_facts import CryptoDirective, CryptoFact, CryptoProbeId
from traust_core.v1.providers.clock import FixedClock
from traust_core.v1.providers.crypto import CryptoProbe, sbom_facts
from traust_core.v1.providers.tools import ToolRequest

FIXTURE = Path(__file__).parents[2] / "fixtures/code_facts/crypto"
AT = datetime(2026, 10, 24, tzinfo=UTC)
P = CryptoProbeId


def probe(root: Path, sbom: Path | None = None) -> list[CryptoFact]:
    result = CryptoProbe(FixedClock(AT)).enumerate(ToolRequest(workspace=root, sbom=sbom))
    assert result.acquisition.provider == "crypto-probe"
    assert result.acquisition.acquired_at == AT
    assert all(isinstance(f, CryptoFact) for f in result.data)
    return result.data  # type: ignore[return-value]


def write(root: Path, files: dict[str, str]) -> Path:
    for rel, content in files.items():
        path = root / rel
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(textwrap.dedent(content))
    return root


def legacy_shape(fact: CryptoFact) -> dict[str, object]:
    extra: dict[str, object] = {}
    path = fact.location.path if fact.location else f"sbom:{fact.package}"
    if fact.probe_id == P.GO_FIPS_BACKEND:
        extra["crypto_backend_swap"] = True
        if path.endswith("go.mod"):
            extra["note"] = "Go stdlib crypto replaced by OpenSSL via CGo"
    if fact.directive:
        extra |= {"directive_type": fact.directive.value, "key": fact.key, "value": fact.value}
    if fact.probe_id == P.FIPS140_GODEBUG:
        extra["fips_mode"] = fact.value
    if fact.package and fact.probe_id != P.SBOM_COMPONENT:
        extra["gem" if fact.probe_id == P.RUBY_CRYPTO_GEM else "package"] = fact.package
    return {
        "probe_id": fact.probe_id.value,
        "file": path,
        "line": fact.location.line if fact.location else 0,
        "detail": fact.detail,
        "provider": fact.provider,
        "version": fact.version,
        "extra": extra,
    }


def test_matches_the_legacy_source_tier_fact_for_fact() -> None:
    facts = probe(FIXTURE / "repo", FIXTURE / "sbom.cdx.json")
    legacy = json.loads((FIXTURE / "legacy-crypto-probe.json").read_text())
    assert [legacy_shape(f) for f in facts] == legacy


def test_reruns_give_the_same_facts() -> None:
    assert probe(FIXTURE / "repo") == probe(FIXTURE / "repo")


def test_an_empty_checkout_has_no_facts(tmp_path: Path) -> None:
    assert probe(tmp_path) == []


@pytest.mark.parametrize(
    ("files", "expected"),
    [
        pytest.param(
            {"go.mod": "module example.com/foo\ngo 1.24\nrequire golang.org/x/crypto v0.32.0\n"},
            [(P.GO_TOOLCHAIN, "go", "1.24")],
            id="go-mod-version",
        ),
        pytest.param(
            {"go.mod": "module x\ngo 1.22\nrequire github.com/golang-fips/openssl v0.0.0\n"},
            [(P.GO_TOOLCHAIN, "go", "1.22"), (P.GO_FIPS_BACKEND, "go-fips", None)],
            id="golang-fips-backend",
        ),
        pytest.param({".nvmrc": "v22.4.0\n"}, [(P.NODE_VERSION, "node", "22.4.0")], id="nvmrc"),
        pytest.param(
            {"package.json": json.dumps({"engines": {"node": ">=18.0.0"}})},
            [(P.NODE_VERSION, "node", "18.0.0")],
            id="engines-semver",
        ),
        pytest.param(
            {"package.json": json.dumps({"engines": {"node": "^20"}})},
            [(P.NODE_VERSION, "node", "20")],
            id="engines-caret",
        ),
        pytest.param(
            {".python-version": "3.12.1\n"},
            [(P.PYTHON_VERSION, "python", "3.12.1")],
            id="python-version-file",
        ),
        pytest.param(
            {"pyproject.toml": '[project]\nname = "myapp"\nrequires-python = ">=3.10"\n'},
            [(P.PYTHON_VERSION, "python", "3.10")],
            id="pyproject-requires-python",
        ),
        pytest.param(
            {"pom.xml": "<project><properties><java.version>21</java.version></properties>"},
            [(P.JDK_VERSION, "jdk", "21")],
            id="pom",
        ),
        pytest.param(
            {"build.gradle": "java {\n    sourceCompatibility = 17\n}\n"},
            [(P.JDK_VERSION, "jdk", "17")],
            id="gradle",
        ),
        pytest.param(
            {"Cargo.toml": '[dependencies]\nring = "0.17.8"\naws-lc-rs = {version = "1.8.0"}\n'},
            [(P.RUST_TLS_BACKEND, "aws-lc-rs", "1.8.0"), (P.RUST_TLS_BACKEND, "ring", "0.17.8")],
            id="ring-and-aws-lc",
        ),
        pytest.param(
            {"global.json": json.dumps({"sdk": {"version": "9.0.100"}})},
            [(P.DOTNET_SDK, "dotnet", "9.0.100")],
            id="global-json",
        ),
        pytest.param(
            {".ruby-version": "3.3.0\n"}, [(P.RUBY_VERSION, "ruby", "3.3.0")], id="ruby-version"
        ),
        pytest.param(
            {"CMakeLists.txt": "find_package(OpenSSL REQUIRED)\nfind_package(GnuTLS)\n"},
            [(P.C_TLS_LIBRARY, "openssl", None), (P.C_TLS_LIBRARY, "gnutls", None)],
            id="cmake-find-package",
        ),
        pytest.param(
            {"configure.ac": "AC_CHECK_LIB([mbedtls], [mbedtls_ssl_init])\n"},
            [(P.C_TLS_LIBRARY, "mbedtls", None)],
            id="autoconf",
        ),
        pytest.param(
            {"run.sh": "GODEBUG=tlsmlkem=0 ./myapp\n"},
            [(P.GODEBUG_TLS_KILLSWITCH, "go", None)],
            id="godebug-killswitch",
        ),
        pytest.param(
            {"entrypoint.sh": "#!/bin/bash\nupdate-crypto-policies --set FIPS\n"},
            [(P.POLICY_SET, "crypto-policies", None)],
            id="crypto-policy",
        ),
        pytest.param(
            {"Makefile": "build:\n\tGOEXPERIMENT=opensslcrypto go build -o app .\n"},
            [(P.DOCKERFILE_DIRECTIVE, "container-build", None)],
            id="goexperiment-in-makefile",
        ),
        pytest.param(
            {"app.properties": "jdk.tls.namedGroups=x25519\n"},
            [(P.JVM_SECURITY_PROPERTY, "jdk", None)],
            id="jvm-property-in-properties-file",
        ),
    ],
)
def test_each_probe_reports_the_stack_it_finds(
    tmp_path: Path,
    files: dict[str, str],
    expected: list[tuple[CryptoProbeId, str, str | None]],
) -> None:
    facts = probe(write(tmp_path, files))
    assert sorted((f.probe_id, f.provider, f.version) for f in facts) == sorted(expected)


def test_dockerfile_reports_raw_base_images_installs_and_crypto_directives(
    tmp_path: Path,
) -> None:
    facts = probe(
        write(
            tmp_path,
            {
                "Dockerfile": """\
                FROM registry.example.com/custom-go-toolset:1.21 AS builder
                ENV GOEXPERIMENT=boringcrypto
                ARG OPENSSL_FORCE_FIPS_MODE=1
                ENV APP_PORT=8080
                RUN apt-get install -y libssl-dev
                FROM builder
                FROM scratch
                FROM alpine:3.19
                RUN apk add openssl-dev
                LABEL description="golang-fips-container"
                """
            },
        )
    )
    images = [f.detail for f in facts if f.probe_id == P.BASE_IMAGE]
    assert images == ["registry.example.com/custom-go-toolset:1.21", "alpine:3.19"]
    assert [f.location.line for f in facts if f.probe_id == P.OPENSSL_INSTALL] == [5, 9]  # type: ignore[union-attr]
    directives = [
        (f.directive, f.key, f.value) for f in facts if f.probe_id == P.DOCKERFILE_DIRECTIVE
    ]
    assert directives == [
        (CryptoDirective.ENV, "GOEXPERIMENT", "boringcrypto"),
        (CryptoDirective.ENV, "OPENSSL_FORCE_FIPS_MODE", "1"),
        (CryptoDirective.LABEL, "description", "golang-fips-container"),
        (CryptoDirective.ENV, "GOEXPERIMENT", "boringcrypto"),  # the policy scan sees it too
    ]


def test_dependency_pins_name_their_package(tmp_path: Path) -> None:
    facts = probe(
        write(
            tmp_path,
            {
                "requirements.txt": "flask==2.3.0\ncryptography==42.0.5\npyopenssl>=23.3.0\n",
                "Gemfile": "gem 'openssl', '~> 3.2'\ngem 'bcrypt'\n",
                "App.csproj": '<PackageReference Include="NSec.Cryptography" Version="24.4.0" />',
            },
        )
    )
    assert sorted((f.probe_id, f.package, f.version) for f in facts) == sorted(
        [
            (P.PYTHON_CRYPTO_DEP, "cryptography", "42.0.5"),
            (P.PYTHON_CRYPTO_DEP, "pyopenssl", "23.3.0"),
            (P.RUBY_CRYPTO_GEM, "openssl", "3.2"),
            (P.RUBY_CRYPTO_GEM, "bcrypt", None),
            (P.DOTNET_CRYPTO_PKG, "NSec.Cryptography", "24.4.0"),
        ]
    )


def test_vendored_trees_are_skipped_but_vendored_rpm_locks_are_not(tmp_path: Path) -> None:
    facts = probe(
        write(
            tmp_path,
            {
                "vendor/submod/go.mod": "module x\ngo 1.22\n",
                "node_modules/pkg/run.sh": "GODEBUG=tlsmlkem=0\n",
                "third_party/rpms.lock.yaml": "openssl-libs 3.2.2\nopenssl-libs 3.2.2\n",
            },
        )
    )
    assert [(f.probe_id, f.detail) for f in facts] == [(P.RPM_NEVRA, "openssl-libs 3.2.2")]


def test_symlinks_never_lead_out_of_the_checkout(tmp_path: Path) -> None:
    outside = write(
        tmp_path / "outside", {"go.mod": "go 1.24\n", "deep/run.sh": "GODEBUG=tlskyber=0\n"}
    )
    checkout = tmp_path / "checkout"
    checkout.mkdir()
    (checkout / "go.mod").symlink_to(outside / "go.mod")
    (checkout / "linked").symlink_to(outside / "deep", target_is_directory=True)
    assert probe(checkout) == []


def test_malformed_manifests_carry_no_version(tmp_path: Path) -> None:
    files = {"package.json": "{not json", "global.json": "[1, 2]", "web/package.json": "[]"}
    assert probe(write(tmp_path, files)) == []


def test_files_over_the_scan_limit_are_not_scanned_for_policy(tmp_path: Path) -> None:
    write(tmp_path, {"big.sh": "GODEBUG=tlsmlkem=0\n" + "#" * 1_000_000})
    assert probe(tmp_path) == []


def test_a_missing_workspace_is_refused(tmp_path: Path) -> None:
    with pytest.raises(ValidationError, match="not a directory"):
        probe(tmp_path / "missing")


def test_an_unreadable_file_is_an_error_not_a_silent_skip(tmp_path: Path) -> None:
    write(tmp_path, {"go.mod": "go 1.24\n"}).joinpath("go.mod").chmod(0)
    try:
        with pytest.raises(ServiceError, match=r"cannot read go\.mod"):
            probe(tmp_path)
    finally:
        (tmp_path / "go.mod").chmod(0o644)


def test_sbom_components_keep_unknown_versions_unknown(tmp_path: Path) -> None:
    sbom = tmp_path / "sbom.json"
    sbom.write_text(
        json.dumps(
            {
                "components": [
                    {"name": "nss-softokn"},
                    {"name": "BouncyCastle-Provider", "version": "1.78"},
                    {"name": "python-cryptography", "version": "42.0.0"},
                    {"name": "zlib", "version": "1.3"},
                ]
            }
        )
    )
    assert [(f.provider, f.version, f.package, f.location) for f in sbom_facts(sbom)] == [
        ("nss", None, "nss-softokn", None),
        ("bouncycastle", "1.78", "bouncycastle-provider", None),
        ("python-openssl", "42.0.0", "python-cryptography", None),
    ]


@pytest.mark.parametrize("content", ['{"components": null}', "{}"])
def test_an_sbom_without_components_has_no_facts(tmp_path: Path, content: str) -> None:
    (sbom := tmp_path / "sbom.json").write_text(content)
    assert sbom_facts(sbom) == []


@pytest.mark.parametrize("content", ["not json", '{"components": {"name": "openssl"}}'])
def test_a_malformed_sbom_is_refused(tmp_path: Path, content: str) -> None:
    (sbom := tmp_path / "sbom.json").write_text(content)
    with pytest.raises(ValidationError, match="CycloneDX"):
        sbom_facts(sbom)


def test_a_missing_sbom_is_an_error(tmp_path: Path) -> None:
    with pytest.raises(ServiceError, match="cannot read SBOM"):
        sbom_facts(tmp_path / "missing.json")


def test_the_probe_is_always_ready() -> None:
    assert CryptoProbe(FixedClock(AT)).check().ready
