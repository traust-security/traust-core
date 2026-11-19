"""The dashboard presets: named, code-defined queries that resolve to the
query body the query route takes, run over the caller's grant, and the
refusal of any id the registry does not define."""

from __future__ import annotations

import pytest

from tests.v1.conftest import SQL_BACKENDS, contract_db
from tests.v1.services.test_dashboards import _seed, _service
from traust_core.v1.errors import ValidationError
from traust_core.v1.models.dashboard import DashboardPresetQuery
from traust_core.v1.services.dashboards import presets as registry


def test_preset_ids_are_the_stable_names_cards_reference() -> None:
    assert [preset.id for preset in registry.PRESETS] == [
        "findings-count",
        "open-findings-by-severity",
        "findings-by-category",
        "top-repositories-by-findings",
        "open-critical-high-by-severity",
    ]


def test_the_registry_covers_the_query_shapes_and_bakes_in_no_grant() -> None:
    queries = {preset.id: preset.query for preset in registry.PRESETS}
    assert not queries["findings-count"].group_by  # one card: a single measure
    assert (
        queries["top-repositories-by-findings"].limit < queries["findings-count"].limit
    )  # a top-N, not the default page
    assert set(queries["open-critical-high-by-severity"].where) >= {"state", "severity"}
    for query in queries.values():
        assert (query.repository_ids, query.product_ids, query.team_ids) == ((), (), ())


@pytest.mark.parametrize("backend", SQL_BACKENDS)
def test_every_preset_runs_over_the_seeded_estate(backend: str, tmp_path) -> None:
    with contract_db(backend, tmp_path) as engine:
        _seed(engine)
        service = _service(engine)

        assert service.presets() == registry.PRESETS
        for preset in service.presets():
            results = service.query_preset(preset.id, DashboardPresetQuery())
            assert results.subject == "findings"
            assert len(results.rows) <= preset.query.limit


@pytest.mark.parametrize("backend", SQL_BACKENDS)
def test_a_preset_takes_the_callers_grant(backend: str, tmp_path) -> None:
    with contract_db(backend, tmp_path) as engine:
        seeded = _seed(engine)
        service = _service(engine)

        whole = service.query_preset("findings-count", DashboardPresetQuery())
        granted = service.query_preset(
            "findings-count", DashboardPresetQuery(repository_ids=(seeded["repo"],))
        )

        assert whole.rows[0].measures["findings"] == 6.0
        assert granted.rows[0].measures["findings"] == 5.0


@pytest.mark.parametrize("backend", SQL_BACKENDS)
def test_the_filtered_cut_reads_state_and_severity(backend: str, tmp_path) -> None:
    with contract_db(backend, tmp_path) as engine:
        _seed(engine)
        service = _service(engine)

        results = service.query_preset("open-critical-high-by-severity", DashboardPresetQuery())

        assert {row.groups["severity"]: row.measures["findings"] for row in results.rows} == {
            "critical": 2.0,
            "high": 1.0,
        }  # the resolved high and the medium and low cuts are not open critical/high


@pytest.mark.parametrize("backend", SQL_BACKENDS)
def test_counts_by_category_carry_the_unlabelled(backend: str, tmp_path) -> None:
    with contract_db(backend, tmp_path) as engine:
        _seed(engine)
        service = _service(engine)

        results = service.query_preset("findings-by-category", DashboardPresetQuery())

        assert {row.groups["category"]: row.measures["findings"] for row in results.rows} == {
            "xss": 1.0,
            None: 5.0,
        }  # only the labelled finding has a category; null is a group, not an absence


@pytest.mark.parametrize("backend", SQL_BACKENDS)
def test_the_top_n_orders_by_the_measure(backend: str, tmp_path) -> None:
    with contract_db(backend, tmp_path) as engine:
        seeded = _seed(engine)
        service = _service(engine)

        results = service.query_preset("top-repositories-by-findings", DashboardPresetQuery())

        counts = [row.measures["findings"] for row in results.rows]
        assert counts == sorted(counts, reverse=True)
        assert results.rows[0].groups["repository"] == str(seeded["repo"])


@pytest.mark.parametrize("backend", SQL_BACKENDS)
def test_an_unknown_preset_refuses(backend: str, tmp_path) -> None:
    with contract_db(backend, tmp_path) as engine:
        service = _service(engine)

        with pytest.raises(ValidationError, match="unknown dashboard preset"):
            service.query_preset("no-such-preset", DashboardPresetQuery())
