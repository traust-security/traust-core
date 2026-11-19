import json

from perf.api import run


def _summary(
    latency: float = 100.0, rps: float = 200.0, personas: tuple[str, ...] = ()
) -> dict[str, float]:
    body = {
        key: rps * 2 if key == "http_reqs_rate" else rps if key.endswith("_rps") else latency
        for key in run.GATE_KEYS
    }
    for name in personas:
        body[f"persona_{name}_p95_ms"] = latency
        body[f"persona_{name}_rps"] = rps
    return body


def _baseline(path, latency: float = 100.0, rps: float = 200.0, rate_keys: bool = True) -> None:
    body = {
        key: rps * 2 if key == "http_reqs_rate" else rps if key.endswith("_rps") else latency
        for key in run.GATE_KEYS
        if rate_keys or not (key.endswith("_rps") or key == "http_reqs_rate")
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


def test_gate_passes_on_a_baseline_predating_the_persona_rows(tmp_path, monkeypatch, capsys):
    monkeypatch.setattr(run, "BASELINE", tmp_path / "baseline.json")
    _baseline(tmp_path / "baseline.json")
    assert run.gate(_summary(personas=("small-measure-tab",)), update=False) == 0
    assert "persona_small-measure-tab_p95_ms" in capsys.readouterr().out


def test_gate_fails_on_a_persona_latency_regression(tmp_path, monkeypatch):
    monkeypatch.setattr(run, "BASELINE", tmp_path / "baseline.json")
    _baseline(tmp_path / "baseline.json")
    assert run.gate(_summary(personas=("small-measure-tab",)), update=True) == 0
    slower = _summary(latency=119.0, personas=("small-measure-tab",))
    slower["persona_small-measure-tab_p95_ms"] = 121.0
    assert run.gate(slower, update=False) == 1


def test_gate_fails_on_a_persona_throughput_regression(tmp_path, monkeypatch):
    monkeypatch.setattr(run, "BASELINE", tmp_path / "baseline.json")
    _baseline(tmp_path / "baseline.json")
    assert run.gate(_summary(personas=("estate-top-tab",)), update=True) == 0
    quieter = _summary(rps=169.0, personas=("estate-top-tab",))
    quieter["persona_estate-top-tab_rps"] = 166.0
    assert run.gate(quieter, update=False) == 1


def test_update_baseline_writes_the_persona_rows(tmp_path, monkeypatch):
    monkeypatch.setattr(run, "BASELINE", tmp_path / "baseline.json")
    assert run.gate(_summary(personas=("estate-top-tab",)), update=True) == 0
    baseline = json.loads((tmp_path / "baseline.json").read_text())
    assert baseline["persona_estate-top-tab_p95_ms"] == 100.0
    assert baseline["persona_estate-top-tab_rps"] == 200.0


def test_persona_rows_skip_a_persona_the_run_never_reached():
    reached = {"persona_a_p95_ms": 5.0, "persona_a_rps": 0.1, "persona_b_rps": None}
    assert run.persona_rows(reached) == ("persona_a_p95_ms", "persona_a_rps")
