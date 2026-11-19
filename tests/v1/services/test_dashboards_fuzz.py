"""Injection fuzzing: an injection payload in every request field ends as a
refusal (the model's ValidationError, what the REST layer maps to a 422 problem
response) or as a correctly bound literal — never an error, never a changed
result shape."""

from __future__ import annotations

from collections.abc import Iterator
from pathlib import Path

import pytest
from fastapi.testclient import TestClient
from hypothesis import HealthCheck, given, settings
from hypothesis import strategies as st
from pydantic import ValidationError as Refusal

from tests.v1.conftest import SQL_BACKENDS, contract_db
from tests.v1.rest.conftest import bearer
from tests.v1.services.test_dashboards import _seed, _service
from traust_core.v1.context import Config, Context
from traust_core.v1.models.dashboard import DashboardQuery, Measure, Subject
from traust_core.v1.rest.app import create_app
from traust_core.v1.services.identity import IdentityConfig

# The payload vocabulary: quote breaks, comment markers, UNION and stacked
# statements, tautologies, unicode look-alikes and control characters,
# format-string and template markers, and (via the pad) oversized strings.
FRAGMENTS: tuple[str, ...] = (
    "'",
    '"',
    "\\'",
    "''",
    "`",
    "--",
    "/*",
    "*/",
    "#",
    ";",
    "' OR '1'='1",
    "' OR 1=1--",
    "') OR ('1'='1",
    "' UNION SELECT id FROM decision--",
    "'; DROP TABLE finding;--",
    "1; DELETE FROM occurrence;--",
    "' AND (SELECT count(*) FROM finding) > 0--",
    "\u0430",  # a cyrillic look-alike of the letter a
    "\u200b",
    "\U0001f6a9",
    "\U0001d54f",  # a mathematical double-struck X
    "%s",
    "%(name)s",
    "{{7*7}}",
    "${jndi:ldap://x}",
    "$(id)",
    "\x00",
)

# NUL is refused by the postgres driver rather than by us, so it stays out of
# value payloads (noted with the plan's typed-per-dimension values).
VALUE_FRAGMENTS = tuple(fragment for fragment in FRAGMENTS if "\x00" not in fragment)

_IDENTIFIER_FIELDS = ("subject", "measure", "group_by", "where_key", "order_by")
_ID_FIELDS = ("repository_ids", "product_ids", "team_ids")


# The REST fixtures live with tests/v1/rest; these mirror them so the HTTP
# cases stay beside their service-level twins.
@pytest.fixture
def context(tmp_path: Path) -> Context:
    return Context(Config(home=tmp_path, identity=IdentityConfig(trust_local=True)))


@pytest.fixture
def client(context: Context) -> Iterator[TestClient]:
    with TestClient(create_app(context), raise_server_exceptions=False) as c:
        yield c


def payloads(fragments: tuple[str, ...] = FRAGMENTS) -> st.SearchStrategy[str]:
    """A marker fragment wrapped in arbitrary text, sometimes padded oversized."""
    return st.builds(
        lambda fragment, wrap, pad: f"{wrap[0]}{fragment}{wrap[1]}{'A' * pad}",
        st.sampled_from(fragments),
        st.tuples(st.text(max_size=6), st.text(max_size=6)),
        st.sampled_from((0, 0, 0, 10_000)),
    )


def _body(field: str, payload: str) -> dict[str, object]:
    """A valid query with the payload placed in one field."""
    body: dict[str, object] = {"subject": "findings", "measures": ["findings"]}
    if field == "subject":
        body["subject"] = payload
    elif field == "measure":
        body["measures"] = [payload]
    elif field == "group_by":
        body["group_by"] = [payload]
    elif field == "where_key":
        body["where"] = {payload: ["open"]}
    elif field == "order_by":
        body["order"] = [{"by": payload}]
    elif field == "where_value":
        body["where"] = {"category": [payload]}
    else:
        body[field] = [payload]
    return body


@settings(suppress_health_check=[HealthCheck.function_scoped_fixture])
@given(payload=payloads(), field=st.sampled_from(_IDENTIFIER_FIELDS))
def test_a_payload_in_an_identifier_field_is_refused_before_any_sql(
    payload: str, field: str
) -> None:
    with pytest.raises(Refusal):
        DashboardQuery.model_validate(_body(field, payload))


@settings(suppress_health_check=[HealthCheck.function_scoped_fixture])
@given(payload=payloads(), field=st.sampled_from(_ID_FIELDS))
def test_a_payload_in_an_id_field_is_refused(payload: str, field: str) -> None:
    with pytest.raises(Refusal):
        DashboardQuery.model_validate(_body(field, payload))


@settings(suppress_health_check=[HealthCheck.function_scoped_fixture])
@given(payload=payloads())
def test_a_payload_in_a_scalar_field_is_refused(payload: str) -> None:
    with pytest.raises(Refusal):
        DashboardQuery.model_validate(
            {"subject": "findings", "measures": ["findings"], "limit": payload}
        )
    with pytest.raises(Refusal):
        DashboardQuery.model_validate(
            {"subject": "findings", "measures": ["findings"], "order": [{"desc": payload}]}
        )


@pytest.mark.parametrize("backend", SQL_BACKENDS)
@settings(
    suppress_health_check=[HealthCheck.function_scoped_fixture],
    deadline=None,
    max_examples=50,
)
@given(
    payload=payloads(VALUE_FRAGMENTS),
    dimension=st.sampled_from(("category", "state", "severity")),
)
def test_a_payload_as_a_where_value_is_a_bound_literal(
    backend: str, tmp_path: Path, payload: str, dimension: str
) -> None:
    with contract_db(backend, tmp_path) as engine:
        seeded = _seed(engine)
        service = _service(engine)

        results = service.query(
            DashboardQuery(
                subject="findings",
                repository_ids=(seeded["repo"],),
                measures=("findings",),
                where={dimension: (payload,)},
            )
        )

        assert results.subject == Subject.FINDINGS
        for row in results.rows:  # the shape never changes: groups and measures as asked
            assert set(row.groups) == set()
            assert set(row.measures) == {Measure.FINDINGS}
            assert row.measures[Measure.FINDINGS] is None or isinstance(
                row.measures[Measure.FINDINGS], float
            )
        # the payload matched exactly what it literally equals; an OR tautology would return more
        matched = sum(row.measures[Measure.FINDINGS] or 0.0 for row in results.rows)
        expected = 1.0 if dimension == "category" and payload == "xss" else 0.0
        assert matched == expected


@settings(
    suppress_health_check=[HealthCheck.function_scoped_fixture], deadline=None, max_examples=40
)
@given(
    payload=payloads(VALUE_FRAGMENTS),
    field=st.sampled_from((*_IDENTIFIER_FIELDS, *_ID_FIELDS, "where_value")),
)
def test_a_payload_request_over_http_is_a_refusal_or_a_bound_literal(
    context: Context, client: TestClient, payload: str, field: str
) -> None:
    response = client.post(
        "/v1/dashboards:query", json=_body(field, payload), headers=bearer(context)
    )

    assert response.status_code in (200, 422)  # never a 5xx
    if response.status_code == 422:
        assert response.headers["content-type"] == "application/problem+json"
    else:  # a bound literal: the answer keeps its shape
        answer = response.json()
        assert answer["subject"] == "findings"
        assert isinstance(answer["rows"], list)
