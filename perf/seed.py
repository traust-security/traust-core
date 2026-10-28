"""A Postgres contracts database seeded at production volume, built once and reused.

The database name carries a digest of the DDL and this seed, so a schema or seed change
rebuilds it and an unchanged one is reused across runs.
"""

from __future__ import annotations

import hashlib
import inspect
import json
from itertools import groupby

import sqlalchemy as sa
from sqlalchemy.engine import Engine
from traust_ledger.integrity import (
    LEAF_FORMAT_CURRENT,
    canonical_event_bytes,
    compute_frontier,
    stamp_merkle_metadata,
)

from traust_core.v1 import contracts
from traust_core.v1.repositories import apply_schema, create_database_engine
from traust_core.v1.repositories.sql import Dialect

# 1% of leases have lapsed; the rest never expire, so a reused database keeps that shape.
# Past a year of continuous ops on a ~10k-repository estate; retention prunes finished orders
# long before this, so queries that hold here hold in production.
REPOSITORIES = 10_000
RUN_BATCHES = 52
RUN_ORDERS = 2_000_000
OPEN_ORDERS = 20_000
# ~1.5 model calls per order over the same year; 1 in 10 claims no order (unattributed).
SPEND_EVENTS = 3_000_000

# A year of decisions (Appendix D: ~250k), each proved by one ledger event in its repository's
# layer. Every 25th lands on HOT_REPOSITORY, a monorepo-sized layer of 10k events; the rest
# average ~24 per layer. UNLEDGERED more decisions per repository wait to be appended.
DECISIONS = 250_000
HOT_REPOSITORY = "https://forge.example/org/r1"
TYPICAL_REPOSITORY = "https://forge.example/org/r2"
UNLEDGERED = 50
PRODUCTS = 1_000
TEAMS = 1_000
REVISIONS_PER_REPOSITORY = 12
RELEASES_PER_PRODUCT = 12
OWNERSHIP_PERIODS = 10
FINDINGS = 100_000
# A year of scans (Appendix D: ~250k occurrences): every seeded finding reported once, ten per
# assessment; half the locations name a line range (with its enclosing function), half a file.
FINDINGS_PER_ASSESSMENT = 10
ARTIFACTS_PER_ASSESSMENT = 10
PACKAGES = 100_000
ADVISORIES = 50_000
SBOMS = 20_000
DEPENDENCIES_PER_SBOM = 150
BASE_IMAGES = 200
INTERNAL_LIBRARIES = 500
IMAGES = 100_000  # a few platforms of a few releases per repository
HOT_PACKAGE = "pkg-1"  # in every 10th SBOM: a blast radius of thousands of commits
HOT_ADVISORY = "GHSA-perf-hot"

ROUTED = ("full-audit", "diff-scan", "diff-scan-quarterly", "threat-model-review", "deps-lane")
UNROUTED = ("feeds_cache", "repo_state", "dashboards")

SEED = (
    f"""INSERT INTO traust.repository (url, public)
    SELECT 'https://forge.example/org/r' || g, true FROM generate_series(1, {REPOSITORIES}) g""",
    f"""INSERT INTO traust_ops.run_batch (kind, period)
    SELECT 'drain_tranche', '2026-W' || lpad(g::text, 2, '0')
    FROM generate_series(1, {RUN_BATCHES}) g""",
    f"""INSERT INTO traust_ops.run_order (run_batch_id, repository_id, asset, lane, state,
        priority, requested_by, lease_holder, lease_expires_at, started_at, finished_at, created_at,
        updated_at)
    SELECT b.id, CASE WHEN o.lane IS NULL AND o.asset <> 'repo_state' THEN NULL ELSE r.id END,
        o.asset, o.lane, o.state, mod(o.g, 100), 'machine:engine',
        CASE WHEN o.state = 'leased' THEN 'worker-' || mod(o.g, 50) END,
        CASE WHEN o.state = 'leased' AND mod(o.g, 100) = 2 THEN o.at + interval '5 minutes'
            WHEN o.state = 'leased' THEN now() + interval '100 years' END,
        CASE WHEN o.state IN ('leased', 'succeeded', 'degraded', 'refused', 'failed') THEN o.at END,
        CASE WHEN o.g > {OPEN_ORDERS} AND o.state <> 'withheld'
            THEN o.at + interval '10 minutes' END,
        o.at,
        CASE WHEN o.g > {OPEN_ORDERS} AND o.state <> 'withheld'
            THEN o.at + interval '10 minutes' ELSE o.at END
    FROM (
        SELECT g, now() - make_interval(secs => g * 15) AS at,
            CASE WHEN mod(g, 8) < 5 THEN replace(replace(w.lane, '-quarterly', ''), '-', '_')
                ELSE w.asset END AS asset,
            CASE WHEN mod(g, 8) < 5 THEN w.lane END AS lane,
            CASE WHEN g <= {OPEN_ORDERS}
                THEN (ARRAY['planned', 'queued', 'leased', 'awaiting_approval'])[1 + mod(g, 4)]
                ELSE (ARRAY['succeeded', 'succeeded', 'succeeded', 'degraded', 'failed',
                    'refused', 'withheld'])[1 + mod(g, 7)] END AS state
        FROM generate_series(1, {RUN_ORDERS}) g,
        LATERAL (SELECT (ARRAY{list(ROUTED)})[1 + mod(g, {len(ROUTED)})] AS lane,
                        (ARRAY{list(UNROUTED)})[1 + mod(g, {len(UNROUTED)})] AS asset) w
    ) o
    JOIN (SELECT row_number() OVER (ORDER BY id) AS n, id FROM traust.repository) r
        ON r.n = 1 + mod(o.g, {REPOSITORIES})
    LEFT JOIN (SELECT row_number() OVER (ORDER BY id) AS n, id FROM traust_ops.run_batch) b
        ON mod(o.g, 10) = 0 AND b.n = 1 + mod(o.g / 10, {RUN_BATCHES})""",
    f"""INSERT INTO traust.finding (repository_id, fingerprint_algo, fingerprint, title)
    SELECT r.id, 'v2', 'fp-' || f.g, 'finding ' || f.g
    FROM (
        SELECT g, CASE WHEN mod(g, 25) = 0 THEN '{HOT_REPOSITORY}'
            ELSE 'https://forge.example/org/r' || (1 + mod(g, {REPOSITORIES})) END AS url
        FROM generate_series(1, {DECISIONS}) g
        UNION ALL
        SELECT {DECISIONS} + g, CASE WHEN g <= {UNLEDGERED} THEN '{HOT_REPOSITORY}'
            ELSE '{TYPICAL_REPOSITORY}' END
        FROM generate_series(1, {2 * UNLEDGERED}) g
    ) f
    JOIN traust.repository r ON r.url = f.url""",
    """INSERT INTO traust.decision (finding_id, statement_key, validity, evidence_grade, rationale,
        source_channel, actor, occurred_at)
    SELECT id, 'sk-' || fingerprint, 'false_positive', 'E1', repeat('rationale ', 20),
        'interactive', 'human:perf@example.com',
        now() - make_interval(mins => mod(abs(hashtext(fingerprint)), 525600))
    FROM traust.finding""",
    """INSERT INTO traust.decision_approver (decision_id, approver)
    SELECT id, 'human:approver@example.com' FROM traust.decision
    WHERE mod(abs(hashtext(statement_key)), 100) = 0""",
    """INSERT INTO traust.finding_external_ref (finding_id, system, ref)
    SELECT id, 'forge', 'https://forge.example/org/mr/' || fingerprint || '#note_1'
    FROM traust.finding""",
    """INSERT INTO traust.review_item (finding_id, reason, status)
    SELECT id, 'ambiguous_statement', 'pending' FROM traust.finding
    WHERE mod(abs(hashtext(fingerprint)), 20) = 0""",
    """INSERT INTO traust_ledger.layers (repository_id, merkle_signing_method)
    SELECT id, 'keypair' FROM traust.repository""",
    f"""INSERT INTO traust_ledger.events (layer_id, decision_id, seq, event_payload)
    SELECT l.id, d.id, row_number() OVER (PARTITION BY l.id ORDER BY d.id) - 1,
        convert_to(jsonb_build_object('id', d.id, 'finding_id', d.finding_id,
            'statement_key', d.statement_key, 'validity', d.validity, 'resolution', d.resolution,
            'evidence_grade', d.evidence_grade, 'reason', d.reason, 'actor', d.actor,
            'source_channel', d.source_channel, 'occurred_at', d.occurred_at,
            'created_at', d.created_at)::text, 'UTF8')
    FROM traust.decision d
    JOIN traust.finding f ON f.id = d.finding_id
    JOIN traust_ledger.layers l ON l.repository_id = f.repository_id
    WHERE substr(f.fingerprint, 4)::int <= {DECISIONS}""",
    f"""INSERT INTO traust_ops.spend_event (run_order_id, lane, provider, model, skill, tokens_in,
        tokens_out, cost_usd, occurred_at)
    SELECT CASE WHEN mod(s.g, 10) <> 0 THEN o.id END,
        CASE WHEN mod(s.g, 10) <> 0 THEN o.lane END, 'anthropic',
        (ARRAY['opus', 'sonnet', 'haiku'])[1 + mod(s.g, 3)],
        (ARRAY['secure-code-audit', 'triage', NULL])[1 + mod(s.g, 3)],
        1000 + mod(s.g, 50000), 100 + mod(s.g, 5000), round(mod(s.g, 2000) / 100.0, 2),
        now() - make_interval(secs => s.g * 10)
    FROM generate_series(1, {SPEND_EVENTS}) s(g)
    JOIN (SELECT row_number() OVER (ORDER BY id) AS n, id, lane FROM traust_ops.run_order) o
        ON o.n = 1 + mod(s.g, {RUN_ORDERS})""",
    f"""INSERT INTO traust.product (slug, name)
    SELECT 'product-' || g, 'Product ' || g FROM generate_series(1, {PRODUCTS}) g""",
    f"""INSERT INTO traust.release (product_id, version)
    SELECT p.id, 'v' || g FROM traust.product p
    CROSS JOIN generate_series(1, {RELEASES_PER_PRODUCT}) g""",
    f"""INSERT INTO traust.repository_ref (repository_id, name, kind, sha, is_default)
    SELECT r.id, CASE WHEN named THEN 'main' END, CASE WHEN named THEN 'branch' END,
        lpad(g::text, 40, '0'), named
    FROM traust.repository r CROSS JOIN generate_series(1, {REVISIONS_PER_REPOSITORY}) g
    CROSS JOIN (VALUES (true), (false)) variant(named)""",
    f"""INSERT INTO traust.component (release_id, repository_ref_id)
    SELECT release.id, ref.id
    FROM (SELECT id, row_number() OVER (ORDER BY id) n FROM traust.repository_ref
        WHERE name IS NOT NULL) ref
    JOIN (SELECT id, row_number() OVER (ORDER BY id) n FROM traust.release) release
        ON release.n = 1 + mod(ref.n - 1, {PRODUCTS * RELEASES_PER_PRODUCT})""",
    f"""INSERT INTO traust.team (name)
    SELECT 'team-' || g FROM generate_series(1, {TEAMS}) g""",
    f"""INSERT INTO traust.ownership (repository_id, team_id, valid_from, valid_to)
    SELECT r.id, t.id, timestamptz '2020-01-01' + g * interval '1 year',
        CASE WHEN g < {OWNERSHIP_PERIODS - 1}
            THEN timestamptz '2020-01-01' + (g + 1) * interval '1 year' END
    FROM (SELECT id, row_number() OVER (ORDER BY id) n FROM traust.repository) r
    JOIN (SELECT id, row_number() OVER (ORDER BY id) n FROM traust.team) t
        ON t.n = 1 + mod(r.n - 1, {TEAMS})
    CROSS JOIN generate_series(0, {OWNERSHIP_PERIODS - 1}) g""",
    f"""INSERT INTO traust.assessment (repository_ref_id, kind, status, assessor, assessor_version,
        occurred_at, created_at)
    SELECT ref.id, 'vuln-scan', 'complete', 'vuln-scan', '1', now() - make_interval(hours => g),
        now() - make_interval(hours => g)
    FROM generate_series(1, {DECISIONS // FINDINGS_PER_ASSESSMENT}) g
    JOIN (SELECT id, row_number() OVER (ORDER BY id) n FROM traust.repository_ref) ref
        ON ref.n = g""",
    f"""INSERT INTO traust.artifact (assessment_id, digest, kind, uri)
    SELECT a.id, repeat(md5(a.id::text || ':' || g), 2),
        CASE WHEN g = 1 THEN 'code-facts' ELSE 'report' END,
        'artifacts/' || repeat(md5(a.id::text || ':' || g), 2) || '.json'
    FROM traust.assessment a CROSS JOIN generate_series(1, {ARTIFACTS_PER_ASSESSMENT}) g""",
    """INSERT INTO traust.artifact (digest, kind, uri)
    SELECT digest, kind, uri FROM traust.artifact WHERE assessment_id IS NOT NULL""",
    f"""INSERT INTO traust.occurrence (finding_id, assessment_id, severity, rule)
    SELECT f.id, a.id, 'high', 'rule-' || mod(f.n, 50)
    FROM (SELECT id, row_number() OVER (ORDER BY id) n FROM traust.finding) f
    JOIN (SELECT id, row_number() OVER (ORDER BY id) n FROM traust.assessment) a
        ON a.n = 1 + (f.n - 1) / {FINDINGS_PER_ASSESSMENT}""",
    """INSERT INTO traust.cwe (identifier, abstraction)
    SELECT 'CWE-' || g, 'base' FROM generate_series(1, 1000) g""",
    """INSERT INTO traust.finding_cwe (finding_id, cwe_id)
    SELECT f.id, c.id
    FROM (SELECT id, 1 + mod(row_number() OVER (ORDER BY id), 1000) n FROM traust.finding) f
    JOIN (SELECT id, row_number() OVER (ORDER BY id) n FROM traust.cwe) c ON c.n = f.n""",
    """INSERT INTO traust.location (occurrence_id, path, line_start, line_end, symbol)
    SELECT o.id, 'pkg/file' || g || '.go', CASE WHEN g = 1 THEN 10 END, CASE WHEN g = 1 THEN 12 END,
        CASE WHEN g = 1 THEN 'fn' || mod(abs(hashtext(o.id::text)), 50000) END
    FROM traust.occurrence o CROSS JOIN generate_series(1, 2) g
    WHERE g = 1 OR mod(abs(hashtext(o.id::text)), 2) = 0""",
    f"""INSERT INTO traust.finding
        (repository_id, fingerprint_algo, fingerprint, kind, title)
    SELECT r.id, 'v3', 'perf-' || g, 'vulnerability', 'Performance finding'
    FROM generate_series(1, {FINDINGS}) g
    JOIN traust.repository r
        ON r.url = 'https://forge.example/org/r' || (1 + mod(g, {REPOSITORIES}))""",
    """INSERT INTO traust.decision
        (finding_id, statement_key, validity, evidence_grade, actor, occurred_at)
    SELECT id, fingerprint, 'confirmed', 'E0', 'human:perf@example.com', now()
    FROM traust.finding WHERE fingerprint_algo = 'v3'""",
    """INSERT INTO traust.review_item (finding_id, decision_id, reason, status)
    SELECT d.finding_id, d.id, 'needs_manual_test',
        CASE WHEN mod(row_number() OVER (ORDER BY d.id), 100) = 0
            THEN 'pending' ELSE 'accepted' END
    FROM traust.decision d
    JOIN traust.finding f ON f.id = d.finding_id
    WHERE f.fingerprint_algo = 'v3'""",
    f"""INSERT INTO traust.package (ecosystem, name)
    SELECT (ARRAY['go', 'npm', 'pypi', 'maven'])[1 + mod(g, 4)], 'pkg-' || g
    FROM generate_series(1, {PACKAGES}) g""",
    f"""INSERT INTO traust.sbom (digest)
    SELECT 'sbom-' || g FROM generate_series(1, {SBOMS}) g""",
    f"""INSERT INTO traust.dependency (sbom_id, package_id, version, direct)
    SELECT s.id, p.id, '1.' || mod(s.n + k, 30) || '.0', k < 20
    FROM (SELECT id, row_number() OVER (ORDER BY digest) n FROM traust.sbom) s
    CROSS JOIN generate_series(0, {DEPENDENCIES_PER_SBOM - 1}) k
    JOIN (SELECT id, row_number() OVER (ORDER BY id) n FROM traust.package
        WHERE name <> '{HOT_PACKAGE}') p
        ON p.n = 1 + mod(s.n * 31 + k * 7919, {PACKAGES - 1})""",
    f"""INSERT INTO traust.dependency (sbom_id, package_id, version, direct)
    SELECT s.id, p.id, '2.0.0', true
    FROM (SELECT id, row_number() OVER (ORDER BY digest) n FROM traust.sbom) s,
        traust.package p
    WHERE p.name = '{HOT_PACKAGE}' AND mod(s.n, 10) = 0""",
    f"""UPDATE traust.package p SET sbom_id = s.id
    FROM (SELECT id, row_number() OVER (ORDER BY digest) n FROM traust.sbom) s,
        (SELECT id, row_number() OVER (ORDER BY id) n FROM traust.package
            WHERE ecosystem = 'npm') b
    WHERE p.id = b.id AND s.n = b.n AND b.n <= {BASE_IMAGES}""",
    f"""UPDATE traust.package p SET source_repository_id = r.id
    FROM (SELECT id, row_number() OVER (ORDER BY id) n FROM traust.repository) r,
        (SELECT id, row_number() OVER (ORDER BY id) n FROM traust.package
            WHERE ecosystem = 'go') l
    WHERE p.id = l.id AND r.n = l.n AND l.n <= {INTERNAL_LIBRARIES}""",
    f"""UPDATE traust.repository_ref ref SET manifest_sbom_id = s.id
    FROM (SELECT id, row_number() OVER (ORDER BY id) n FROM traust.repository_ref
            WHERE name IS NOT NULL) r,
        (SELECT id, row_number() OVER (ORDER BY digest) n FROM traust.sbom) s
    WHERE ref.id = r.id AND s.n = 1 + mod(r.n, {SBOMS})""",
    f"""INSERT INTO traust.image (digest, platform, repository_ref_id, sbom_id)
    SELECT 'sha256:image-' || g, 'linux/amd64', CASE WHEN mod(g, 4) > 0 THEN r.id END, s.id
    FROM generate_series(1, {IMAGES}) g
    JOIN (SELECT id, row_number() OVER (ORDER BY id) n FROM traust.repository_ref
        WHERE name IS NULL) r ON r.n = 1 + mod(g, {REPOSITORIES * REVISIONS_PER_REPOSITORY})
    JOIN (SELECT id, row_number() OVER (ORDER BY digest) n FROM traust.sbom) s
        ON s.n = 1 + mod(g * 7, {SBOMS})""",
    f"""INSERT INTO traust.advisory (identifier, published_at)
    SELECT 'CVE-2026-' || g, now() - make_interval(days => mod(g, 1000))
    FROM generate_series(1, {ADVISORIES}) g""",
    """INSERT INTO traust.advisory (alias_of_id, identifier)
    SELECT id, 'GHSA-' || substr(identifier, 10) FROM traust.advisory
    WHERE mod(abs(hashtext(identifier)), 2) = 0""",
    f"""INSERT INTO traust.advisory_package (advisory_id, package_id)
    SELECT a.id, p.id
    FROM (SELECT id, row_number() OVER (ORDER BY id) n FROM traust.advisory
        WHERE alias_of_id IS NULL) a
    CROSS JOIN generate_series(0, 1) k
    JOIN (SELECT id, row_number() OVER (ORDER BY id) n FROM traust.package) p
        ON p.n = 1 + mod(a.n * 7 + k, {PACKAGES})""",
    f"""INSERT INTO traust.advisory (identifier) VALUES ('{HOT_ADVISORY}')""",
    f"""INSERT INTO traust.advisory_package (advisory_id, package_id)
    SELECT a.id, p.id FROM traust.advisory a, traust.package p
    WHERE a.identifier = '{HOT_ADVISORY}' AND p.name = '{HOT_PACKAGE}'""",
    """INSERT INTO traust.assessment (repository_ref_id, kind, status, assessor, assessor_version,
        occurred_at)
    SELECT id, 'repo-state', 'completed', 'forge', '1',
        now() - interval '1 year' + right(sha, 2)::int * interval '1 day'
    FROM traust.repository_ref WHERE is_default""",
)


def _stamp_layers(engine: Engine) -> None:
    """Stamp each layer's root and frontier from its events, as appends keep them."""
    events = sa.text(
        "SELECT layer_id, event_payload FROM traust_ledger.events ORDER BY layer_id, seq"
    )
    stamp = sa.text(
        "UPDATE traust_ledger.layers SET merkle_root = :merkle_root, "
        "merkle_epoch = :merkle_epoch, merkle_size = :merkle_size, "
        "merkle_frontier = :merkle_frontier WHERE id = :id"
    )
    with engine.begin() as conn:
        rows = conn.execute(events)
        stamped = []
        for layer_id, group in groupby(rows, key=lambda r: r[0]):
            document = {
                "events": [json.loads(bytes(r[1])) for r in group],
                "metadata": {"leaf_format": LEAF_FORMAT_CURRENT},
            }
            stamp_merkle_metadata(document)
            meta = document["metadata"]
            frontier = compute_frontier([canonical_event_bytes(e) for e in document["events"]])
            row = {k: meta[k] for k in STAMPED}
            stamped.append(
                {"id": layer_id, **row, "merkle_frontier": ",".join(h.hex() for h in frontier)}
            )
        conn.execute(stamp, stamped)


STAMPED = ("merkle_root", "merkle_epoch", "merkle_size")


ANALYZED = (
    "traust_ops.run_order",
    "traust_ops.spend_event",
    "traust.decision",
    "traust.finding_external_ref",
    "traust.review_item",
    "traust.decision_approver",
    "traust_ledger.events",
    "traust.repository",
    "traust.product",
    "traust.release",
    "traust.repository_ref",
    "traust.component",
    "traust.team",
    "traust.ownership",
    "traust.finding",
    "traust.assessment",
    "traust.artifact",
    "traust.occurrence",
    "traust.location",
    "traust.finding_cwe",
    "traust.package",
    "traust.sbom",
    "traust.dependency",
    "traust.image",
    "traust.advisory",
    "traust.advisory_package",
)


def _name() -> str:
    ddl = contracts.database_ddl(Dialect.POSTGRES)
    steps = [*ddl, *SEED, *ANALYZED, inspect.getsource(_stamp_layers)]
    digest = hashlib.sha256("\n".join(steps).encode()).hexdigest()[:12]
    return f"traust_perf_{digest}"


def seeded_database(url: str) -> Engine:
    name = _name()
    admin = sa.create_engine(url, isolation_level="AUTOCOMMIT")
    with admin.connect() as conn:
        existing = set(
            conn.exec_driver_sql(
                "SELECT datname FROM pg_database WHERE starts_with(datname, 'traust_perf_')"
            ).scalars()
        )
        for stale in existing - {name}:
            conn.exec_driver_sql(f"DROP DATABASE {stale} WITH (FORCE)")
        fresh = name not in existing
        if fresh:
            conn.exec_driver_sql(f"CREATE DATABASE {name}")
    admin.dispose()
    engine = create_database_engine(sa.make_url(url).set(database=name))
    if fresh:
        try:
            apply_schema(engine, contracts.database_ddl(Dialect.POSTGRES))
            apply_schema(engine, SEED)
            _stamp_layers(engine)
            with engine.connect().execution_options(isolation_level="AUTOCOMMIT") as conn:
                for table in ANALYZED:
                    conn.exec_driver_sql(f"VACUUM (ANALYZE) {table}")
        except BaseException:
            engine.dispose()
            _drop(url, name)  # never leave a half-seeded database to be reused
            raise
    return engine


def _drop(url: str, name: str) -> None:
    admin = sa.create_engine(url, isolation_level="AUTOCOMMIT")
    with admin.connect() as conn:
        conn.exec_driver_sql(f"DROP DATABASE IF EXISTS {name} WITH (FORCE)")
    admin.dispose()
