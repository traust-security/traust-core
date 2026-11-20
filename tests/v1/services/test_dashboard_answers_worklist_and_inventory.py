"""The dashboard query answers what the worklist pager and the inventory rows need: the
filtered count under SCI's findings list (formerly GET /v1/findings/count) and each
repository's findings by state with its open findings by severity (formerly GET
/v1/findings/summaries). The oracle is the seeded table below, each finding's state and
severity stated by the agreed fact definitions, never derived from the code under test.

The state follows the workflow (identified -> verify -> remediate | accept risk | false
positive) and the contracts: kind alone never decides, so an unjudged weakness is
identified (open) and a verified one is hardening. Severity follows the most recent report.
Deliberate departures from the removed endpoints (their vocabulary was assembled, not
agreed): `not_affected` is false_positive, not open; "closed" is the caller's
`state in [resolved, accepted]`; a never-reported finding counts."""

from __future__ import annotations

from collections import Counter
from collections.abc import Iterator
from dataclasses import dataclass
from datetime import timedelta
from pathlib import Path
from uuid import UUID

import pytest
from sqlalchemy.engine import Engine

from tests.v1.conftest import SQL_BACKENDS, contract_db
from tests.v1.repositories.tables.conftest import Seed
from tests.v1.services.test_dashboards import HUMAN, T0, _service
from traust_core.v1.models.dashboard import DashboardQuery
from traust_core.v1.repositories.contract import SqlTraustUnitOfWork


@dataclass(frozen=True)
class Case:
    repo: str
    title: str
    severity: str | None  # the occurrence's band; None: never reported
    decision: dict[str, str] | None
    state: str  # expected, by the agreed definitions
    effective: str | None  # expected severity fact
    kind: str | None = None
    later: str | None = None  # a newer report's band, after the decision


CASES = (
    Case("svc", "undecided critical", "critical", None, "open", "critical"),
    Case("svc", "undecided high", "high", None, "open", "high"),
    Case("svc", "confirmed, unresolved", "high", {"validity": "confirmed"}, "open", "high"),
    Case(
        "svc",
        "explicit open resolution",
        "medium",
        {"validity": "confirmed", "resolution": "open"},
        "open",
        "medium",
    ),
    Case(
        "svc",
        "remediated",
        "high",
        {"validity": "confirmed", "resolution": "resolved"},
        "resolved",
        "high",
    ),
    Case(
        "svc",
        "risk accepted",
        "medium",
        {"validity": "confirmed", "resolution": "risk_accepted"},
        "accepted",
        "medium",
    ),
    Case("svc", "false positive", "low", {"validity": "false_positive"}, "false_positive", "low"),
    Case("svc", "not affected", "high", {"validity": "not_affected"}, "false_positive", "high"),
    Case("svc", "hardening debt", "low", {"validity": "hardening"}, "hardening", "low"),
    Case("svc", "undecided weakness", "medium", None, "open", "medium", kind="weakness"),
    Case(
        "svc",
        "verified weakness",
        "low",
        {"validity": "true_positive"},
        "hardening",
        "low",
        kind="weakness",
    ),
    Case(
        "svc",
        "re-reported after a decision",
        "medium",
        {"validity": "confirmed"},
        "open",
        "critical",
        later="critical",
    ),
    Case("svc", "unrated", "unrated", None, "open", None),
    Case("svc", "never reported", None, None, "open", None),
    Case("lib", "lib critical", "critical", None, "open", "critical"),
    Case(
        "lib",
        "lib remediated",
        "low",
        {"validity": "confirmed", "resolution": "resolved"},
        "resolved",
        "low",
    ),
    Case("outside", "outside the grant", "critical", None, "open", "critical"),
)


def _seed(engine: Engine) -> dict[str, UUID]:
    with SqlTraustUnitOfWork(engine) as uow:
        s = Seed(uow)
        repos = {
            name: s.repository(url=f"https://github.com/example-org/{name}")
            for name in ("svc", "lib", "outside")
        }
        refs = {name: s.repository_ref(r) for name, r in repos.items()}
        audits = {name: s.assessment(ref, occurred_at=T0) for name, ref in refs.items()}
        later = {
            name: s.assessment(ref, occurred_at=T0 + timedelta(days=1))
            for name, ref in refs.items()
        }
        for case in CASES:
            finding = s.finding(repos[case.repo], title=case.title, kind=case.kind)
            if case.severity is not None:
                s.occurrence(finding, audits[case.repo], severity=case.severity)
            if case.decision is not None:
                s.decision(finding, actor=HUMAN, **case.decision)
            if case.later is not None:
                s.occurrence(finding, later[case.repo], severity=case.later)
        uow.commit()
        return {name: r.id for name, r in repos.items()}


@pytest.fixture(params=SQL_BACKENDS)
def seeded(
    request: pytest.FixtureRequest, tmp_path: Path
) -> Iterator[tuple[Engine, dict[str, UUID]]]:
    with contract_db(request.param, tmp_path) as engine:
        yield engine, _seed(engine)


GRANT = ("svc", "lib")

# The cuts SCI's worklist pager asks for: an exposure-like state set and a severity set.
PAGER_CUTS = (
    ((), ()),
    (("open",), ()),
    (("open",), ("critical", "high")),
    (("resolved", "accepted"), ()),
    (("false_positive",), ()),
    (("hardening",), ("low", "medium")),
)


@pytest.mark.parametrize(("states", "severities"), PAGER_CUTS)
def test_the_pager_count_is_one_filtered_query(seeded, states, severities) -> None:
    engine, repos = seeded
    where = {
        **({"state": states} if states else {}),
        **({"severity": severities} if severities else {}),
    }

    results = _service(engine).query(
        DashboardQuery(
            subject="findings",
            repository_ids=tuple(repos[name] for name in GRANT),
            measures=("findings",),
            where=where,
        )
    )

    expected = sum(
        1
        for c in CASES
        if c.repo in GRANT
        and (not states or c.state in states)
        and (not severities or c.effective in severities)
    )
    assert [row.measures["findings"] for row in results.rows] == [float(expected)]


def test_each_inventory_row_is_its_findings_by_state(seeded) -> None:
    engine, repos = seeded

    results = _service(engine).query(
        DashboardQuery(
            subject="findings",
            repository_ids=tuple(repos[name] for name in GRANT),
            measures=("findings",),
            group_by=("repository", "state"),
        )
    )

    got = {
        (row.groups["repository"], row.groups["state"]): row.measures["findings"]
        for row in results.rows
    }
    expected = Counter((str(repos[c.repo]), c.state) for c in CASES if c.repo in GRANT)
    assert got == {key: float(n) for key, n in expected.items()}


def test_each_inventory_row_has_its_open_findings_by_severity(seeded) -> None:
    engine, repos = seeded

    results = _service(engine).query(
        DashboardQuery(
            subject="findings",
            repository_ids=tuple(repos[name] for name in GRANT),
            measures=("findings",),
            group_by=("repository", "severity"),
            where={"state": ("open",)},
        )
    )

    got = {
        (row.groups["repository"], row.groups["severity"]): row.measures["findings"]
        for row in results.rows
    }
    expected = Counter(
        (str(repos[c.repo]), c.effective) for c in CASES if c.repo in GRANT and c.state == "open"
    )
    assert got == {key: float(n) for key, n in expected.items()}  # unrated is its own (null) row


def test_nothing_outside_the_grant_contributes(seeded) -> None:
    engine, repos = seeded

    results = _service(engine).query(
        DashboardQuery(
            subject="findings",
            repository_ids=tuple(repos[name] for name in GRANT),
            measures=("findings",),
            group_by=("repository",),
        )
    )

    assert {row.groups["repository"] for row in results.rows} == {str(repos[n]) for n in GRANT}
