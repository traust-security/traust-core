"""The crypto image and cluster doors: an image's shipped crypto plus its SBOM's crypto packages
(parity with the legacy image SBOM probe), and the cluster tier behind the k8s exec scope gate
(legacy traust-engine tests/test_crypto_audit_scope.py)."""

from __future__ import annotations

import json
import logging
from collections.abc import Iterator, Sequence
from datetime import UTC, date, datetime
from pathlib import Path
from typing import Any

import pytest
from sqlalchemy.engine import Engine

from tests.v1.conftest import SQL_BACKENDS, contract_db
from tests.v1.providers.test_crypto_cluster import APISERVER, TLS13, FakeOc
from tests.v1.providers.test_crypto_image import DIGEST, NAME, ROOTFS, FakeRuntime
from tests.v1.services.test_crypto_census import services
from tests.v1.services.test_exposure_image_sbom import FIXTURE, IMAGE_SBOM
from traust_core.v1.errors import ConfigError
from traust_core.v1.models.code_facts import (
    ClusterRequest,
    CryptoProbeId,
    ImageRequest,
    NamespaceScope,
)
from traust_core.v1.models.dependencies import NoImageSbomError
from traust_core.v1.models.validation import ClusterScope, ScopeDecision, ValidationScope
from traust_core.v1.models.vocabulary import ScopeBindingMode
from traust_core.v1.providers.base import Readiness
from traust_core.v1.providers.clock import FixedClock
from traust_core.v1.providers.crypto_cluster import ClusterCryptoProbe
from traust_core.v1.providers.crypto_image import ImageCryptoProbe
from traust_core.v1.services.code_facts import CodeFactsService
from traust_core.v1.services.exposure import ExposureService

P = CryptoProbeId
CLOCK = FixedClock(datetime(2026, 10, 23, tzinfo=UTC))
LEGACY_IMAGE_SBOM = json.loads((FIXTURE / "legacy-image-sbom-probe.json").read_text())
# parse_sbom keeps the purl's version, which carries no rpm epoch (as X5: resolved, not raw).
NO_EPOCH = {"openssl-libs 1:3.5.8-2.el9_8": "openssl-libs 3.5.8-2.el9_8"}


@pytest.fixture(params=SQL_BACKENDS)
def engine(request: pytest.FixtureRequest, tmp_path: Path) -> Iterator[Engine]:
    with contract_db(request.param, tmp_path) as eng:
        yield eng


def wired(
    exposure: ExposureService | None,
    *,
    image: ImageCryptoProbe | None = None,
    cluster: ClusterCryptoProbe | None = None,
) -> CodeFactsService:
    return CodeFactsService(
        None,  # type: ignore[arg-type]
        None,  # type: ignore[arg-type]
        (),
        exposure,
        image=image,
        cluster=cluster,
        clock=CLOCK,
    )


def image_probe(runtime: FakeRuntime) -> ImageCryptoProbe:
    return ImageCryptoProbe(runtime, CLOCK, runtime="podman")  # type: ignore[arg-type]


def test_an_image_census_is_what_it_ships_plus_its_sbom_crypto_packages(engine: Engine) -> None:
    exposure, _ = services(engine)
    exposure.ingest_image_sbom(IMAGE_SBOM, DIGEST)
    runtime = FakeRuntime(ROOTFS)
    census = wired(exposure, image=image_probe(runtime)).image_crypto(
        DIGEST, ImageRequest(name=NAME)
    )
    shipped = {f.probe_id for f in census.facts if f.probe_id.value.startswith("IMG_")}
    assert P.IMAGE_LINKED_LIBS in shipped and P.IMAGE_FIPS_MODULE in shipped
    packages = [
        (f.probe_id.value, f.provider, f.detail, f.package)
        for f in census.facts
        if f.probe_id == P.SBOM_COMPONENT
    ]
    legacy = [
        (
            f["probe_id"],
            f["provider"],
            NO_EPOCH.get(f["detail"], f["detail"]),
            f["detail"].split()[0],
        )
        for f in LEGACY_IMAGE_SBOM
    ]
    assert sorted(packages) == sorted(legacy)
    assert all(f.direct is False for f in census.facts if f.probe_id == P.SBOM_COMPONENT)


def test_an_image_without_an_sbom_fails_before_the_image_is_touched(engine: Engine) -> None:
    exposure, _ = services(engine)
    runtime = FakeRuntime(ROOTFS)
    with pytest.raises(NoImageSbomError):
        wired(exposure, image=image_probe(runtime)).image_crypto(DIGEST, ImageRequest(name=NAME))
    assert runtime.calls == []


def test_the_image_door_needs_its_collaborators(
    engine: Engine, monkeypatch: pytest.MonkeyPatch
) -> None:
    exposure, _ = services(engine)
    with pytest.raises(ConfigError):
        wired(exposure).image_crypto(DIGEST, ImageRequest(name=NAME))
    exposure.ingest_image_sbom(IMAGE_SBOM, DIGEST)
    monkeypatch.setattr("shutil.which", lambda _: None)
    unready = ImageCryptoProbe(FakeRuntime(ROOTFS), CLOCK)  # type: ignore[arg-type]
    with pytest.raises(ConfigError, match="crypto-image is not ready"):
        wired(exposure, image=unready).image_crypto(DIGEST, ImageRequest(name=NAME))


def scope(namespaces: Sequence[str], *, context: str = "lab") -> ValidationScope:
    """A mode-1 targets.yaml listing `namespaces` for `context` (listing is explicit)."""
    return ValidationScope(
        modes=frozenset({ScopeBindingMode.EXPLICIT}),
        clusters=(
            ClusterScope(
                context=context,
                namespaces=tuple(namespaces),
                explicit_namespaces=frozenset(namespaces),
            ),
        ),
    )


class Recording(ClusterCryptoProbe):
    def __init__(self, oc: FakeOc) -> None:
        super().__init__(oc, CLOCK)  # type: ignore[arg-type]
        self.asked: list[list[str]] = []

    def check(self) -> Readiness:
        return Readiness(ready=True)

    def collect(self, request: ClusterRequest, namespaces: Sequence[str], gate: Any) -> Any:
        self.asked.append(list(namespaces))
        return super().collect(request, namespaces, gate)


def test_denied_namespaces_are_skipped_logged_and_returned(
    caplog: pytest.LogCaptureFixture,
) -> None:
    probe = Recording(FakeOc({"app-ns": ["web-0"], **APISERVER}))
    request = ClusterRequest(context="lab", namespaces=("app-ns", "openshift-kube-apiserver"))
    with caplog.at_level(logging.INFO, logger="traust_core.v1.services.code_facts"):
        census = wired(None, cluster=probe).cluster_crypto(request, scope(["app-ns"]))
    assert probe.asked == [["app-ns"]]
    denied = ScopeDecision(
        allowed=False,
        reason="control-plane namespace 'openshift-kube-apiserver' not explicitly authorized in "
        "targets.yaml",
    )
    assert census.scope == (
        NamespaceScope(namespace="app-ns", decision=ScopeDecision(allowed=True, reason="ok")),
        NamespaceScope(namespace="openshift-kube-apiserver", decision=denied),
    )
    assert census.gaps[-1] == f"scope denied: openshift-kube-apiserver — {denied.reason}"
    assert any("TLS not probed" in g for g in census.gaps)
    lines = {(r.levelname, r.getMessage()) for r in caplog.records}
    assert (
        "WARNING",
        "scope k8s/exec context=lab namespace=openshift-kube-apiserver allowed=False reason="
        + denied.reason,
    ) in lines
    assert ("INFO", "scope k8s/exec context=lab namespace=app-ns allowed=True reason=ok") in lines


def test_a_control_plane_namespace_is_probeable_only_when_listed() -> None:
    probe = Recording(FakeOc({**APISERVER}, tls={"kubernetes.default.svc": TLS13}))
    request = ClusterRequest(context="lab", namespaces=("openshift-kube-apiserver",))
    census = wired(None, cluster=probe).cluster_crypto(request, scope(["openshift-kube-apiserver"]))
    assert probe.asked == [["openshift-kube-apiserver"]]
    assert census.scope[0].decision.allowed
    assert any(f.probe_id == P.CLUSTER_TLS_NEGOTIATION for f in census.facts)


def test_nothing_in_scope_fails_closed_without_probing(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr("shutil.which", lambda _: None)  # oc missing doesn't matter: never reached
    oc = FakeOc({"app-ns": ["web-0"]})
    request = ClusterRequest(context="OTHER-ctx", namespaces=("app-ns",))
    census = wired(None, cluster=ClusterCryptoProbe(oc, CLOCK)).cluster_crypto(  # type: ignore[arg-type]
        request, scope(["app-ns"])
    )
    assert oc.calls == []
    assert census.facts == () and census.discovery == ()
    assert census.gaps == ("scope denied: app-ns — context 'OTHER-ctx' not in scope",)


def test_an_expired_engagement_denies_every_namespace() -> None:
    expired = scope(["app-ns"]).model_copy(update={"expires": date(2026, 10, 1)})
    census = wired(None, cluster=Recording(FakeOc({}))).cluster_crypto(
        ClusterRequest(context="lab", namespaces=("app-ns",)), expired
    )
    assert census.gaps == ("scope denied: app-ns — engagement expired 2026-10-01",)


def test_the_cluster_door_needs_its_probe_and_oc(monkeypatch: pytest.MonkeyPatch) -> None:
    request = ClusterRequest(context="lab", namespaces=("app-ns",))
    with pytest.raises(ConfigError):
        wired(None).cluster_crypto(request, scope(["app-ns"]))
    monkeypatch.setattr("shutil.which", lambda _: None)
    probe = ClusterCryptoProbe(FakeOc({}), CLOCK)  # type: ignore[arg-type]
    with pytest.raises(ConfigError, match="oc not found"):
        wired(None, cluster=probe).cluster_crypto(request, scope(["app-ns"]))
