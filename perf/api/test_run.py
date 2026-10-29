import json

from perf.api import run


def _summary(latency: float = 100.0, rps: float = 200.0) -> dict[str, float]:
    return {
        "claim_p95_ms": latency,
        "list_p95_ms": latency,
        "feed_p95_ms": latency,
        "claim_rps": rps,
        "list_rps": rps,
        "feed_rps": rps,
        "http_reqs_rate": rps * 2,
    }


def _baseline(path, latency: float = 100.0, rps: float = 200.0, rate_keys: bool = True) -> None:
    body = {
        "claim_p95_ms": latency,
        "list_p95_ms": latency,
        "feed_p95_ms": latency,
    }
    if rate_keys:
        body |= {
            "claim_rps": rps,
            "list_rps": rps,
            "feed_rps": rps,
            "http_reqs_rate": rps * 2,
        }
    path.write_text(json.dumps(body))


def test_gate_passes_within_the_margin(tmp_path, monkeypatch):
    monkeypatch.setattr(run, "BASELINE", tmp_path / "baseline.json")
    _baseline(tmp_path / "baseline.json")
    assert run.gate(_summary(latency=119.0, rps=169.0), update=False) == 0


def test_gate_fails_on_latency_regression(tmp_path, monkeypatch):
    monkeypatch.setattr(run, "BASELINE", tmp_path / "baseline.json")
    _baseline(tmp_path / "baseline.json")
    assert run.gate(_summary(latency=121.0), update=False) == 1


def test_gate_fails_on_throughput_regression(tmp_path, monkeypatch):
    monkeypatch.setattr(run, "BASELINE", tmp_path / "baseline.json")
    _baseline(tmp_path / "baseline.json")
    assert run.gate(_summary(rps=166.0), update=False) == 1


def test_gate_passes_on_a_baseline_predating_the_rate_keys(tmp_path, monkeypatch, capsys):
    monkeypatch.setattr(run, "BASELINE", tmp_path / "baseline.json")
    _baseline(tmp_path / "baseline.json", rate_keys=False)
    assert run.gate(_summary(rps=1.0), update=False) == 0
    assert "refresh it with --update-baseline" in capsys.readouterr().out


def test_update_baseline_writes_every_gate_key(tmp_path, monkeypatch):
    monkeypatch.setattr(run, "BASELINE", tmp_path / "baseline.json")
    assert run.gate(_summary(), update=True) == 0
    assert set(json.loads((tmp_path / "baseline.json").read_text())) == set(run.GATE_KEYS)
