from perf.harness import Explained


def test_only_executed_sequential_scans_are_reported() -> None:
    executed = "Seq Scan on finding (actual time=0.010..0.011 rows=0 loops=1)"
    plan = Explained(
        sql="SELECT count(*) FROM finding",
        plan=(
            "Aggregate (actual time=0.020..0.021 rows=1 loops=1)",
            "  -> Seq Scan on repository_ref (cost=0.00..7000.00 rows=1) (never executed)",
            f"  -> {executed}",
            "  -> Index Scan using decision_pkey on decision (actual rows=1 loops=1)",
            "Execution Time: 0.030 ms",
        ),
    )

    scans = plan.seq_scans()
    assert len(scans) == 1
    assert "Seq Scan on finding " in scans[0]
