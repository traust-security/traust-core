from __future__ import annotations

import io
import tarfile
from collections.abc import Sequence
from datetime import UTC, datetime
from pathlib import Path, PurePosixPath
from typing import Any

import pytest

from tests.v1.models.test_elf_formats import elf
from traust_core.v1.errors import ConfigError
from traust_core.v1.models.code_facts import CryptoDirective, CryptoFact, CryptoProbeId
from traust_core.v1.providers.clock import FixedClock
from traust_core.v1.providers.crypto_image import ImageCryptoProbe
from traust_core.v1.providers.process import ProcessError, ProcessResult

P = CryptoProbeId
CLOCK = FixedClock(datetime(2026, 10, 23, tzinfo=UTC))
NAME, DIGEST = "registry.example.com/app", "sha256:" + "a" * 64
INSPECT = (
    (Path(__file__).parents[2] / "fixtures" / "code_facts" / "crypto" / "image")
    .joinpath("podman-image-inspect.json")
    .read_bytes()
)
BINARY = elf(("libssl.so.3", "libcrypto.so.3", "libc.so.6")) + b"\x00" * 10_000
Link = tuple[str, str]


class FakeRuntime:
    """podman as far as the image tier uses it, over an in-memory rootfs."""

    def __init__(self, rootfs: dict[str, bytes | Link], **failures: bytes) -> None:
        self.rootfs = rootfs
        self.failures = failures
        self.calls: list[tuple[list[str], float | None]] = []

    def run(
        self,
        argv: Sequence[str],
        *,
        check: bool = True,
        timeout_seconds: float | None = None,
        **_: Any,
    ) -> ProcessResult:
        self.calls.append((list(argv), timeout_seconds))
        verb = argv[1]
        if verb in self.failures:
            result = ProcessResult(tuple(argv), 125, b"", self.failures[verb], 0)
            raise ProcessError(result)
        out = {"image": INSPECT, "create": b"c" * 64 + b"\n"}.get(verb, b"")
        if verb == "cp":
            return self._cp(argv, argv[2].split(":", 1)[1])
        return ProcessResult(tuple(argv), 0, out, b"", 0)

    def _cp(self, argv: Sequence[str], source: str) -> ProcessResult:
        contents = source.endswith("/.")
        root = PurePosixPath(source.removesuffix("/."))
        found = {p: v for p, v in self.rootfs.items() if PurePosixPath(p).is_relative_to(root)}
        if not found:
            err = f'Error: "{source}" could not be found on container c: no such file'.encode()
            return ProcessResult(tuple(argv), 125, b"", err, 0)
        buffer = io.BytesIO()
        with tarfile.open(fileobj=buffer, mode="w") as tar:
            for path, value in found.items():
                relative = PurePosixPath(path).relative_to(root if contents else root.parent)
                info = tarfile.TarInfo(str(relative))
                if isinstance(value, tuple):
                    info.type, info.linkname = tarfile.SYMTYPE, value[1]
                    tar.addfile(info)
                else:
                    info.size = len(value)
                    tar.addfile(info, io.BytesIO(value))
        return ProcessResult(tuple(argv), 0, buffer.getvalue(), b"", 0)


ROOTFS: dict[str, bytes | Link] = {
    "/usr/bin/openssl": BINARY,
    "/usr/bin/tiny": elf(),
    "/usr/bin/script": b"#!/bin/sh\n" + b"x" * 20_000,
    "/usr/bin/ssl": ("link", "openssl"),
    "/usr/bin/host-escape": ("link", "/etc/alternatives/java"),
    "/usr/sbin/sub/tool": BINARY,
    "/etc/pki/tls/certs/ca-bundle.crt": b"-----BEGIN CERTIFICATE-----",
    "/etc/pki/tls/private/server.KEY": b"k",
    "/etc/pki/README": b"not a cert",
    "/etc/ssl/certs/ca-bundle.crt": ("link", "/etc/pki/tls/certs/ca-bundle.crt"),
    "/etc/crypto-policies/state/current": b"FIPS\n",
    "/etc/system-fips": b"",
    "/usr/lib/ossl-modules/fips.so": b"\x7fELF",
}


def probe(runtime: FakeRuntime) -> ImageCryptoProbe:
    return ImageCryptoProbe(runtime, CLOCK, runtime="podman")  # type: ignore[arg-type]


def test_an_image_reports_what_it_ships_without_running_it() -> None:
    runtime = FakeRuntime(ROOTFS)
    result = probe(runtime).collect(NAME, DIGEST, pull=True)
    census = result.data
    assert (census.digest, census.architecture, census.os, census.entrypoint) == (
        DIGEST,
        "arm64",
        "linux",
        (),
    )
    by_id: dict[CryptoProbeId, list[CryptoFact]] = {}
    for fact in census.facts:
        by_id.setdefault(fact.probe_id, []).append(fact)
    libs = ("libssl.so.3", "libcrypto.so.3", "libc.so.6")
    assert [(f.path, f.libraries, f.detail) for f in by_id[P.IMAGE_LINKED_LIBS]] == [
        ("/usr/bin/openssl", libs, "libssl.so.3, libcrypto.so.3, libc.so.6"),
        ("/usr/bin/ssl", libs, "libssl.so.3, libcrypto.so.3, libc.so.6"),
        ("/usr/sbin/sub/tool", libs, "libssl.so.3, libcrypto.so.3, libc.so.6"),
    ]
    assert [(f.path, f.size) for f in by_id[P.IMAGE_CERT_FILES]] == [
        ("/etc/pki/tls/certs/ca-bundle.crt", 27),
        ("/etc/pki/tls/private/server.KEY", 1),
    ]
    [policy] = by_id[P.IMAGE_CRYPTO_POLICY]
    assert (policy.detail, policy.value, policy.path) == (
        "FIPS",
        "FIPS",
        "/etc/crypto-policies/state/current",
    )
    assert [f.detail for f in by_id[P.IMAGE_FIPS_MARKER]] == ["/etc/system-fips present"]
    assert [f.path for f in by_id[P.IMAGE_FIPS_MODULE]] == ["/usr/lib/ossl-modules/fips.so"]
    env = by_id[P.IMAGE_ENV]
    assert (env[1].directive, env[1].key, env[1].value) == (CryptoDirective.ENV, "container", "oci")
    label = next(f for f in by_id[P.IMAGE_LABEL] if f.key == "name")
    assert (label.directive, label.detail) == (CryptoDirective.LABEL, "name=ubi9/ubi-minimal")
    assert census.gaps == ()
    assert result.acquisition.provider == "crypto-image"
    verbs = [argv[1] for argv, _ in runtime.calls]
    assert "run" not in verbs and verbs[:3] == ["pull", "image", "create"] and verbs[-1] == "rm"
    assert runtime.calls[0] == (["podman", "pull", "--", f"{NAME}@{DIGEST}"], 300)


def test_no_pull_uses_the_local_store_and_absent_files_are_no_facts() -> None:
    runtime = FakeRuntime({"/usr/bin/openssl": BINARY})
    census = probe(runtime).collect(NAME, DIGEST, pull=False).data
    assert {f.probe_id for f in census.facts} == {P.IMAGE_LINKED_LIBS, P.IMAGE_ENV, P.IMAGE_LABEL}
    assert census.gaps == ()
    assert all(argv[1] != "pull" for argv, _ in runtime.calls)


def test_an_empty_policy_file_is_no_fact() -> None:
    census = probe(FakeRuntime({"/etc/crypto-policies/state/current": b" \n"})).collect(
        NAME, DIGEST, pull=False
    )
    assert P.IMAGE_CRYPTO_POLICY not in {f.probe_id for f in census.data.facts}


def test_a_cp_failure_that_is_not_absence_is_a_gap() -> None:
    class Broken(FakeRuntime):
        def _cp(self, argv: Sequence[str], source: str) -> ProcessResult:
            if source == "/etc/pki":
                return ProcessResult(tuple(argv), 125, b"", b"Error: permission denied", 0)
            return super()._cp(argv, source)

    census = probe(Broken(ROOTFS)).collect(NAME, DIGEST, pull=False).data
    assert census.gaps == ("cp /etc/pki: Error: permission denied",)
    assert [f.path for f in census.facts if f.probe_id == P.IMAGE_CERT_FILES] == []


def test_the_container_is_removed_when_reading_it_fails() -> None:
    class Exploding(FakeRuntime):
        def _cp(self, argv: Sequence[str], source: str) -> ProcessResult:
            raise ProcessError(ProcessResult(tuple(argv), 1, b"", b"boom", 0))

    runtime = Exploding(ROOTFS)
    with pytest.raises(ProcessError):
        probe(runtime).collect(NAME, DIGEST, pull=False)
    assert runtime.calls[-1] == (["podman", "rm", "-f", "c" * 64], 30)


@pytest.mark.parametrize("verb", ["pull", "image", "create"])
def test_a_runtime_failure_before_reading_raises(verb: str) -> None:
    runtime = FakeRuntime(ROOTFS, **{verb: b"manifest unknown"})
    with pytest.raises(ProcessError, match="manifest unknown"):
        probe(runtime).collect(NAME, DIGEST, pull=True)
    assert all(argv[1] != "rm" for argv, _ in runtime.calls)


def test_without_a_runtime_the_probe_is_not_ready(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr("shutil.which", lambda _: None)
    image = ImageCryptoProbe(FakeRuntime({}), CLOCK)  # type: ignore[arg-type]
    assert not image.check().ready
    with pytest.raises(ConfigError, match="neither podman nor docker"):
        image.collect(NAME, DIGEST, pull=False)


def test_podman_is_preferred_over_docker(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr("shutil.which", lambda name: f"/usr/bin/{name}")
    runtime = FakeRuntime({})
    ImageCryptoProbe(runtime, CLOCK).collect(NAME, DIGEST, pull=False)  # type: ignore[arg-type]
    assert runtime.calls[0][0][0] == "podman"
    assert ImageCryptoProbe(runtime, CLOCK).check().ready  # type: ignore[arg-type]
