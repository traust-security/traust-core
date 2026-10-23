from __future__ import annotations

import json
import os
import re
from collections.abc import Callable, Iterator
from dataclasses import dataclass
from fnmatch import fnmatchcase
from functools import cached_property
from pathlib import Path

from traust_core.v1.errors import ServiceError, ValidationError
from traust_core.v1.models.code_facts import (
    CodeFactDetail,
    CodeFactKind,
    CryptoDirective,
    CryptoFact,
    CryptoProbeId,
)
from traust_core.v1.models.common import CodeSpan, RepoPath
from traust_core.v1.providers.base import Acquisition, Readiness, Result
from traust_core.v1.providers.clock import Clock
from traust_core.v1.providers.tools import ToolRequest

_VENDOR = re.compile(
    r"(^|/)(vendor|node_modules|third_party|_vendor|3rdparty|third-party|"
    r"bundled|external|site-packages|\.gomodcache)(/|$)"
)
_GO_DIRECTIVE = re.compile(r"(?m)^go\s+(\d+)\.(\d+)")
_GOLANG_FIPS = re.compile(
    r"(?m)(golang\.org/x/crypto/internal/boring|github\.com/golang-fips/"
    r"|go-toolset-.*-openssl-fips|openssl-fips-provider)"
)
_FROM = re.compile(r"(?mi)^\s*FROM\s+(\S+)")
_FROM_ALIAS = re.compile(r"(?mi)^\s*FROM\s+\S+\s+AS\s+(\S+)")
_PKG_INSTALL_OPENSSL = re.compile(
    r"(?mi)\b(dnf|yum|microdnf|apt-get|apt|apk)\b[^\n]*"
    r"(?:install|add)[^\n]*\b(openssl\S*|libssl\S*|gnutls\S*|libnss\S*)"
)
_DOCKERFILE_ARG_ENV = re.compile(r"(?mi)^\s*(?:ARG|ENV)\s+(\w+)\s*=\s*(\S+)")
_DOCKERFILE_LABEL = re.compile(r'(?mi)^\s*LABEL\s+(\S+)\s*=\s*"?([^"\n]+)')
_CRYPTO_KEYWORDS = (
    "fips", "crypto", "openssl", "gnutls", "nss", "tls", "ssl", "boringcrypto", "opensslcrypto",
    "cngcrypto", "boring", "goexperiment", "cgo_enabled", "golang-fips",
)  # fmt: skip
_LEADING_VERSION = re.compile(r"(\d+(?:\.\d+)*)")
_MIN_SEMVER = re.compile(r"[>=^~]*\s*(\d+(?:\.\d+)*)")
_POM_JAVA = re.compile(r"<(?:maven\.compiler\.(?:release|source)|java\.version)>\s*(\d+)")
_GRADLE_JAVA = re.compile(
    r"(?:sourceCompatibility|targetCompatibility|toolchain\s*\{[^}]*"
    r"languageVersion\.set\(JavaLanguageVersion\.of\()\s*[=( ]*(\d+)"
)
_JVM_TLS_PROPS = re.compile(
    r"(?m)^(jdk\.tls\.namedGroups|jdk\.tls\.disabledAlgorithms|"
    r"jdk\.tls\.ephemeralDHKeySize)\s*=\s*(.+)"
)
_REQUIRES_PYTHON = re.compile(r'requires-python\s*=\s*"([^"]+)"')
_PIPFILE_PYTHON = re.compile(r'python_version\s*=\s*"([^"]+)"')
_RUST_VERSION = re.compile(r'(?m)^rust-version\s*=\s*"([^"]+)"')
_CMAKE_PKG_CHECK = re.compile(r"pkg_check_modules\([^)]*\b(openssl|gnutls|mbedtls|wolfssl)\b", re.I)
_CSPROJ_TFM = re.compile(r"<TargetFramework>net(\d+)\.(\d+)")
_NEVRA_CRYPTO = re.compile(
    r"(?m)(openssl(?:-libs|-fips-provider)?|crypto-policies|gnutls|nss)"
    r"[^\n]{0,40}?(\d+[.:][\w.\-]+)"
)
_GODEBUG_TLS = re.compile(r"GODEBUG\s*[=:].{0,80}?tls(mlkem|kyber)=0")
_GODEBUG_FIPS = re.compile(r"GODEBUG\s*[=:].{0,80}?fips140\s*=\s*(on|only)")
_GOEXPERIMENT = re.compile(
    r"(?mi)GOEXPERIMENT\s*[=:]\s*(\S*(?:boringcrypto|opensslcrypto|cngcrypto)\S*)"
)
_CRYPTO_POLICY = re.compile(
    r"update-crypto-policies\s+--set\s+(\S+)|\bFIPS[:=\s]*(mode|true|enabled)", re.I
)
_TEXT_SUFFIXES = frozenset(
    {".go", ".py", ".sh", ".yaml", ".yml", ".env", ".conf", ".md", ".just", ".properties",
     ".toml", ".cfg", ".rb", ".cs", ".csproj", ".json", ""}
)  # fmt: skip
_MAX_SCANNED_BYTES = 1_000_000


@dataclass(frozen=True)
class _File:
    rel: str
    path: Path

    @property
    def vendored(self) -> bool:
        return bool(_VENDOR.search(self.rel))

    @cached_property
    def text(self) -> str:
        try:
            return self.path.read_text(errors="replace")
        except OSError as e:
            raise ServiceError(f"crypto probe: cannot read {self.rel}: {e}") from e

    def fact(
        self, probe_id: CryptoProbeId, detail: str, line: int = 1, **kw: str | None
    ) -> CryptoFact:
        return CryptoFact(
            probe_id=probe_id,
            detail=detail,
            location=CodeSpan(path=RepoPath(self.rel), line=line),
            **kw,  # type: ignore[arg-type]
        )

    def line_at(self, offset: int) -> int:
        return self.text.count("\n", 0, offset) + 1


class CryptoProbe:
    """Source-tier census: the crypto stacks, versions and policies a checkout configures.
    Crypto packages come from the commit's dependency rows (`models.crypto_catalog`)."""

    kind = CodeFactKind.CRYPTO
    name = "crypto-probe"

    def __init__(self, clock: Clock) -> None:
        self._clock = clock

    def check(self) -> Readiness:
        return Readiness(ready=True)

    def enumerate(self, request: ToolRequest) -> Result[list[CodeFactDetail]]:
        if not request.workspace.is_dir():
            raise ValidationError(
                f"crypto probe: workspace is not a directory: {request.workspace}"
            )
        files = _walk(request.workspace)
        facts: list[CodeFactDetail] = [f for probe in _PROBES for f in probe(files)]
        return Result(facts, Acquisition(provider=self.name, acquired_at=self._clock.now()))


def _walk(root: Path) -> list[_File]:
    # Never follow symlinks out of an untrusted checkout: excerpts flow into the facts.
    files = [
        _File(path.relative_to(root).as_posix(), path)
        for top, dirs, names in os.walk(root, followlinks=False)
        for path in (Path(top) / n for n in names)
        if not path.is_symlink() and path.is_file()
    ]
    return sorted(files, key=lambda f: f.rel)


def _named(files: list[_File], *patterns: str, vendored: bool = False) -> Iterator[_File]:
    return (
        f
        for f in files
        if any(fnmatchcase(f.path.name, p) for p in patterns) and (vendored or not f.vendored)
    )


def _min_semver(constraint: str) -> str | None:
    return m.group(1) if (m := _MIN_SEMVER.search(constraint)) else None


def _go(files: list[_File]) -> Iterator[CryptoFact]:
    for f in _named(files, "go.mod"):
        if m := _GO_DIRECTIVE.search(f.text):
            version = f"{int(m.group(1))}.{int(m.group(2))}"
            yield f.fact(
                CryptoProbeId.GO_TOOLCHAIN, f"go {version}", provider="go", version=version
            )
        if _GOLANG_FIPS.search(f.text):
            yield f.fact(
                CryptoProbeId.GO_FIPS_BACKEND,
                "golang-fips or boring crypto dependency in go.mod",
                provider="go-fips",
            )
    for f in _named(files, "go.sum"):
        if _GOLANG_FIPS.search(f.text):
            yield f.fact(
                CryptoProbeId.GO_FIPS_BACKEND,
                "golang-fips or boring crypto dependency in go.sum",
                provider="go-fips",
            )


def _dockerfiles(files: list[_File]) -> Iterator[CryptoFact]:
    for f in _named(files, "Dockerfile*", "Containerfile*"):
        aliases = {a.lower() for a in _FROM_ALIAS.findall(f.text)}
        for m in _FROM.finditer(f.text):
            if m.group(1).lower() not in aliases | {"scratch"}:
                yield f.fact(
                    CryptoProbeId.BASE_IMAGE,
                    m.group(1),
                    f.line_at(m.start()),
                    provider="base-image",
                )
        for m in _PKG_INSTALL_OPENSSL.finditer(f.text):
            yield f.fact(
                CryptoProbeId.OPENSSL_INSTALL,
                m.group(0)[:200],
                f.line_at(m.start()),
                provider="openssl",
            )
        for directive, pattern in (
            (CryptoDirective.ENV, _DOCKERFILE_ARG_ENV),
            (CryptoDirective.LABEL, _DOCKERFILE_LABEL),
        ):
            for m in pattern.finditer(f.text):
                key, value = m.group(1), m.group(2).strip()
                if any(k in f"{key}={value}".lower() for k in _CRYPTO_KEYWORDS):
                    yield f.fact(
                        CryptoProbeId.DOCKERFILE_DIRECTIVE,
                        f"{key}={value}"[:200],
                        f.line_at(m.start()),
                        provider="container-build",
                        directive=directive,
                        key=key,
                        value=value,
                    )


def _node(files: list[_File]) -> Iterator[CryptoFact]:
    for f in _named(files, ".nvmrc"):
        raw = f.text.strip().lstrip("v")
        if m := _LEADING_VERSION.match(raw):
            yield f.fact(
                CryptoProbeId.NODE_VERSION, f"node {raw}", provider="node", version=m.group(1)
            )
    for f in _named(files, "package.json"):
        engine = _json_path(f.text, "engines", "node")
        if engine and (version := _min_semver(str(engine))):
            yield f.fact(
                CryptoProbeId.NODE_VERSION,
                f"engines.node {engine}",
                provider="node",
                version=version,
            )


def _json_path(text: str, *keys: str) -> object:
    # A malformed manifest in an untrusted checkout carries no version; legacy skipped it too.
    try:
        value: object = json.loads(text)
    except json.JSONDecodeError:
        return None
    for key in keys:
        if not isinstance(value, dict):
            return None
        value = value.get(key)
    return value


def _jdk(files: list[_File]) -> Iterator[CryptoFact]:
    for f, pattern in (
        *((f, _POM_JAVA) for f in _named(files, "pom.xml")),
        *((f, _GRADLE_JAVA) for f in _named(files, "build.gradle*")),
    ):
        if m := pattern.search(f.text):
            yield f.fact(
                CryptoProbeId.JDK_VERSION,
                f"jdk {m.group(1)}",
                provider="jdk",
                version=m.group(1),
            )
    for f in _named(files, "java.security"):
        yield from _jvm_properties(f)


def _jvm_properties(f: _File) -> Iterator[CryptoFact]:
    for m in _JVM_TLS_PROPS.finditer(f.text):
        yield f.fact(
            CryptoProbeId.JVM_SECURITY_PROPERTY,
            f"{m.group(1)}={m.group(2)[:150]}",
            f.line_at(m.start()),
            provider="jdk",
        )


def _python(files: list[_File]) -> Iterator[CryptoFact]:
    for f in _named(files, ".python-version"):
        raw = f.text.strip()
        if m := _LEADING_VERSION.match(raw):
            yield f.fact(
                CryptoProbeId.PYTHON_VERSION,
                f"python {raw}",
                provider="python",
                version=m.group(1),
            )
    for f in _named(files, "pyproject.toml"):
        if (m := _REQUIRES_PYTHON.search(f.text)) and (version := _min_semver(m.group(1))):
            yield f.fact(
                CryptoProbeId.PYTHON_VERSION,
                f"requires-python {m.group(1)}",
                f.line_at(m.start()),
                provider="python",
                version=version,
            )
    for f in _named(files, "Pipfile"):
        if m := _PIPFILE_PYTHON.search(f.text):
            yield f.fact(
                CryptoProbeId.PYTHON_VERSION,
                f"python_version {m.group(1)}",
                f.line_at(m.start()),
                provider="python",
                version=m.group(1),
            )


def _rust(files: list[_File]) -> Iterator[CryptoFact]:
    for f in _named(files, "Cargo.toml"):
        if m := _RUST_VERSION.search(f.text):
            yield f.fact(
                CryptoProbeId.RUST_VERSION,
                f"rust {m.group(1)}",
                provider="rust",
                version=m.group(1),
            )


def _c(files: list[_File]) -> Iterator[CryptoFact]:
    for f in _named(files, "CMakeLists.txt"):
        for lib in ("OpenSSL", "GnuTLS", "MbedTLS", "wolfSSL"):
            if re.search(rf"find_package\(\s*{lib}", f.text, re.I):
                yield f.fact(
                    CryptoProbeId.C_TLS_LIBRARY, f"find_package({lib})", provider=lib.lower()
                )
        for m in _CMAKE_PKG_CHECK.finditer(f.text):
            yield f.fact(
                CryptoProbeId.C_TLS_LIBRARY,
                f"pkg_check_modules {m.group(1)}",
                f.line_at(m.start()),
                provider=m.group(1).lower(),
            )
    for f in _named(files, "configure.ac"):
        for lib in ("openssl", "gnutls", "mbedtls"):
            if re.search(rf"AC_CHECK_LIB\(\[?{lib}", f.text, re.I):
                yield f.fact(CryptoProbeId.C_TLS_LIBRARY, f"AC_CHECK_LIB({lib})", provider=lib)


def _dotnet(files: list[_File]) -> Iterator[CryptoFact]:
    for f in _named(files, "global.json"):
        if version := _json_path(f.text, "sdk", "version"):
            yield f.fact(
                CryptoProbeId.DOTNET_SDK,
                f"dotnet sdk {version}",
                provider="dotnet",
                version=str(version),
            )
    for f in _named(files, "*.csproj"):
        if m := _CSPROJ_TFM.search(f.text):
            version = f"{m.group(1)}.{m.group(2)}"
            yield f.fact(
                CryptoProbeId.DOTNET_TFM, f"net{version}", provider="dotnet", version=version
            )


def _ruby(files: list[_File]) -> Iterator[CryptoFact]:
    for f in _named(files, ".ruby-version"):
        raw = f.text.strip()
        if m := _LEADING_VERSION.match(raw):
            yield f.fact(
                CryptoProbeId.RUBY_VERSION, f"ruby {raw}", provider="ruby", version=m.group(1)
            )


def _rpm_locks(files: list[_File]) -> Iterator[CryptoFact]:
    # Read here, not from dependency rows: syft has no rpms.lock.yaml cataloger (1.51.1).
    for f in _named(files, "rpms.lock.yaml", vendored=True):
        for name, version in dict.fromkeys(_NEVRA_CRYPTO.findall(f.text)):
            yield f.fact(
                CryptoProbeId.RPM_NEVRA, f"{name} {version}", provider=name, version=version
            )


def _env_and_policy(files: list[_File]) -> Iterator[CryptoFact]:
    for f in files:
        if (
            f.path.suffix not in _TEXT_SUFFIXES
            or f.vendored
            or f.path.stat().st_size > _MAX_SCANNED_BYTES
        ):
            continue
        for m in _GODEBUG_TLS.finditer(f.text):
            yield f.fact(
                CryptoProbeId.GODEBUG_TLS_KILLSWITCH,
                m.group(0)[:200],
                f.line_at(m.start()),
                provider="go",
            )
        for m in _GODEBUG_FIPS.finditer(f.text):
            yield f.fact(
                CryptoProbeId.FIPS140_GODEBUG,
                f"GODEBUG fips140={m.group(1)}",
                f.line_at(m.start()),
                provider="go",
                value=m.group(1),
            )
        for m in _GOEXPERIMENT.finditer(f.text):
            yield f.fact(
                CryptoProbeId.DOCKERFILE_DIRECTIVE,
                f"GOEXPERIMENT={m.group(1)}",
                f.line_at(m.start()),
                provider="container-build",
                directive=CryptoDirective.ENV,
                key="GOEXPERIMENT",
                value=m.group(1),
            )
        for m in _CRYPTO_POLICY.finditer(f.text):
            yield f.fact(
                CryptoProbeId.POLICY_SET,
                m.group(0)[:200],
                f.line_at(m.start()),
                provider="crypto-policies",
            )
        if f.path.name == "java.security" or f.path.suffix == ".properties":
            yield from _jvm_properties(f)


_PROBES: tuple[Callable[[list[_File]], Iterator[CryptoFact]], ...] = (
    _go, _dockerfiles, _node, _jdk, _python, _rust, _c, _dotnet, _ruby, _rpm_locks,
    _env_and_policy,
)  # fmt: skip
