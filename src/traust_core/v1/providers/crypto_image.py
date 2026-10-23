from __future__ import annotations

import io
import logging
import re
import shutil
import tarfile
from collections.abc import Iterator
from pathlib import PurePosixPath

from traust_core.v1.errors import ConfigError
from traust_core.v1.models.code_facts import (
    CryptoDirective,
    CryptoFact,
    CryptoProbeId,
    ImageCensus,
)
from traust_core.v1.models.crypto_formats import ImageInspect
from traust_core.v1.models.elf_formats import is_elf, linked_libraries
from traust_core.v1.providers.base import Acquisition, Readiness, Result
from traust_core.v1.providers.clock import Clock
from traust_core.v1.providers.process import ProcessRunner

log = logging.getLogger(__name__)

P = CryptoProbeId
_RUNTIMES = ("podman", "docker")
_BIN_DIRS = ("usr/bin", "usr/sbin", "usr/local/bin", "bin", "sbin")
_CERT_DIRS = ("/etc/pki", "/etc/ssl/certs")
_CERT_SUFFIXES = frozenset({".pem", ".crt", ".cert", ".key"})
_FIPS_MODULES = ("/usr/lib64/ossl-modules/fips.so", "/usr/lib/ossl-modules/fips.so")
_MIN_BINARY = 10_000
_MAX_DETAIL = 200
_ABSENT = re.compile(r"could not be found|could not find|no such", re.I)


class ImageCryptoProbe:
    """The crypto image tier (traust-engine `crypto_audit.run_image`): what an image ships, read
    through the container runtime's inspect, create and cp. The image is never run, and files
    are read from the archive `cp` streams, so no image symlink resolves on the host."""

    name = "crypto-image"

    def __init__(self, process: ProcessRunner, clock: Clock, runtime: str | None = None) -> None:
        self._process = process
        self._clock = clock
        self._runtime = runtime or next((r for r in _RUNTIMES if shutil.which(r)), None)

    def check(self) -> Readiness:
        if self._runtime is None:
            return Readiness(ready=False, detail="neither podman nor docker found in PATH")
        return Readiness(ready=True)

    def collect(self, name: str, digest: str, *, pull: bool) -> Result[ImageCensus]:
        if self._runtime is None:
            raise ConfigError("neither podman nor docker found in PATH")
        reference = f"{name}@{digest}"
        if pull:
            self._run("pull", "--", reference, timeout=300)
        inspect = ImageInspect.parse(self._run("image", "inspect", "--", reference))
        container = self._run("create", "--", reference, "/bin/true").decode().strip()[:64]
        gaps: list[str] = []
        try:
            facts = [
                *_metadata(inspect),
                *self._linked_libraries(container, gaps),
                *self._certificates(container, gaps),
                *self._crypto_files(container, gaps),
            ]
        finally:
            self._run("rm", "-f", container, timeout=30)
        log.info("image %s: %d crypto facts, %d gaps", reference, len(facts), len(gaps))
        census = ImageCensus(
            digest=digest,
            architecture=inspect.architecture,
            os=inspect.os,
            entrypoint=inspect.config.entrypoint,
            facts=tuple(facts),
            gaps=tuple(gaps),
        )
        return Result(census, Acquisition(provider=self.name, acquired_at=self._clock.now()))

    def _run(self, *args: str, timeout: float = 120) -> bytes:
        assert self._runtime is not None
        return self._process.run([self._runtime, *args], timeout_seconds=timeout).stdout

    def _archive(self, container: str, source: str, gaps: list[str]) -> tarfile.TarFile | None:
        """`source` from the container as the tar `cp` streams; None when it isn't there."""
        assert self._runtime is not None
        run = self._process.run(
            [self._runtime, "cp", f"{container}:{source}", "-"], check=False, timeout_seconds=120
        )
        if run.returncode != 0:
            stderr = run.stderr.decode(errors="replace").strip()
            if not _ABSENT.search(stderr):
                gaps.append(f"cp {source}: {stderr[-_MAX_DETAIL:]}")
            return None
        return tarfile.open(fileobj=io.BytesIO(run.stdout))

    def _linked_libraries(self, container: str, gaps: list[str]) -> list[CryptoFact]:
        linked: dict[str, tuple[str, ...]] = {}
        for directory in _BIN_DIRS:
            if archive := self._archive(container, f"/{directory}/.", gaps):
                with archive:
                    linked |= {
                        f"/{directory}/{name}": libraries
                        for name, data in _files(archive)
                        if len(data) >= _MIN_BINARY and is_elf(data)
                        if (libraries := linked_libraries(data))
                    }
        return [
            CryptoFact(
                probe_id=P.IMAGE_LINKED_LIBS,
                provider="elf",
                detail=", ".join(libraries)[:_MAX_DETAIL],
                path=path,
                libraries=libraries,
            )
            for path, libraries in sorted(linked.items())
        ]

    def _certificates(self, container: str, gaps: list[str]) -> list[CryptoFact]:
        found: dict[str, int] = {}
        for source in _CERT_DIRS:
            if archive := self._archive(container, source, gaps):
                parent = PurePosixPath(source).parent
                with archive:
                    found |= {
                        str(parent / n): len(d)
                        for n, d in _files(archive)
                        if PurePosixPath(n).suffix.lower() in _CERT_SUFFIXES
                    }
        return [
            CryptoFact(
                probe_id=P.IMAGE_CERT_FILES,
                provider="filesystem",
                detail=path,
                path=path,
                size=size,
            )
            for path, size in sorted(found.items())
        ]

    def _crypto_files(self, container: str, gaps: list[str]) -> list[CryptoFact]:
        facts = []
        policy_path = "/etc/crypto-policies/state/current"
        if archive := self._archive(container, policy_path, gaps):
            with archive:
                policy = b"".join(d for _, d in _files(archive)).decode(errors="replace").strip()
            if policy:
                facts.append(
                    CryptoFact(
                        probe_id=P.IMAGE_CRYPTO_POLICY,
                        provider="crypto-policies",
                        detail=policy,
                        path=policy_path,
                        value=policy,
                    )
                )
        if self._archive(container, "/etc/system-fips", gaps):
            facts.append(
                CryptoFact(
                    probe_id=P.IMAGE_FIPS_MARKER,
                    provider="fips",
                    detail="/etc/system-fips present",
                    path="/etc/system-fips",
                )
            )
        module = next((m for m in _FIPS_MODULES if self._archive(container, m, gaps)), None)
        if module is not None:
            facts.append(
                CryptoFact(
                    probe_id=P.IMAGE_FIPS_MODULE,
                    provider="openssl-fips",
                    detail=f"FIPS module at {module}",
                    path=module,
                )
            )
        return facts


def _metadata(inspect: ImageInspect) -> list[CryptoFact]:
    env = [
        CryptoFact(
            probe_id=P.IMAGE_ENV,
            provider="image-metadata",
            detail=entry[:_MAX_DETAIL],
            directive=CryptoDirective.ENV,
            key=entry.partition("=")[0],
            value=entry.partition("=")[2],
        )
        for entry in inspect.config.env
    ]
    labels = [
        CryptoFact(
            probe_id=P.IMAGE_LABEL,
            provider="image-metadata",
            detail=f"{key}={value}"[:_MAX_DETAIL],
            directive=CryptoDirective.LABEL,
            key=key,
            value=value,
        )
        for key, value in inspect.config.labels.items()
    ]
    return env + labels


def _files(archive: tarfile.TarFile) -> Iterator[tuple[str, bytes]]:
    """Each file's path (relative to the copied root) and bytes; a link counts only when its
    target is inside the same archive."""
    for member in archive.getmembers():
        if not (member.isfile() or member.issym() or member.islnk()):
            continue
        try:
            handle = archive.extractfile(member)
        except KeyError:
            continue
        if handle is not None:
            yield member.name.removeprefix("./"), handle.read()
