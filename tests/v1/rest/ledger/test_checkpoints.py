from __future__ import annotations

from pathlib import Path
from uuid import uuid4

from fastapi.testclient import TestClient

from tests.v1.rest.conftest import bearer
from tests.v1.rest.ledger.conftest import Ledgered, deployment, tamper
from traust_core.v1.context import Config, Context
from traust_core.v1.rest.app import create_app


def checkpoint_url(ledgered: Ledgered) -> str:
    return f"/v1/repositories/{ledgered.repository_id}/ledger/checkpoint"


def test_an_admin_checkpoints_the_repository_layer(ledgered: Ledgered) -> None:
    response = ledgered.client.post(checkpoint_url(ledgered), headers=ledgered.admin)
    assert response.status_code == 200
    body = response.json()
    assert (body["layer"]["id"], body["signing"]) == (str(ledgered.layer_id), "unconfigured")
    assert body["layer"]["merkle_size"] == 3


def test_a_checkpoint_without_the_admin_role_is_a_403(ledgered: Ledgered) -> None:
    response = ledgered.client.post(checkpoint_url(ledgered), headers=ledgered.reader)
    assert response.status_code == 403
    assert response.headers["content-type"] == "application/problem+json"
    assert ledgered.client.post(checkpoint_url(ledgered)).status_code == 401


def test_a_checkpoint_without_a_layer_is_a_404(ledgered: Ledgered) -> None:
    url = f"/v1/repositories/{uuid4()}/ledger/checkpoint"
    response = ledgered.client.post(url, headers=ledgered.admin)
    assert response.status_code == 404
    assert response.headers["content-type"] == "application/problem+json"


def test_required_signing_that_fails_writes_nothing(ledgered: Ledgered, tmp_path: Path) -> None:
    before = ledgered.client.get(
        f"/v1/ledger/layers/{ledgered.layer_id}", headers=ledgered.reader
    ).json()
    strict = deployment(tmp_path, required=True, key_path=str(tmp_path / "missing.key"))
    with TestClient(create_app(strict), raise_server_exceptions=False) as client:
        response = client.post(checkpoint_url(ledgered), headers=bearer(strict))
    assert response.status_code == 500
    assert response.headers["content-type"] == "application/problem+json"
    assert "not signed" in response.json()["detail"]
    after = ledgered.client.get(
        f"/v1/ledger/layers/{ledgered.layer_id}", headers=ledgered.reader
    ).json()
    assert after == before


def test_a_deployment_without_a_ledger_has_no_ledger_resources(tmp_path: Path) -> None:
    context = Context(Config(home=tmp_path, identity=deployment(tmp_path).config.identity))
    with TestClient(create_app(context)) as client:
        response = client.get(f"/v1/ledger/layers/{uuid4()}", headers=bearer(context))
    assert response.status_code == 404
    assert "keeps no ledger" in response.json()["detail"]


def test_a_layer_that_does_not_verify_is_not_re_signed(ledgered: Ledgered) -> None:
    tamper(ledgered.context, ledgered.layer_id)
    response = ledgered.client.post(checkpoint_url(ledgered), headers=ledgered.admin)
    assert response.status_code == 409
    assert response.headers["content-type"] == "application/problem+json"
    assert "won't be re-signed" in response.json()["detail"]
