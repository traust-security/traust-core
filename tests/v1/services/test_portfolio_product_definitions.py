"""`PortfolioService.resolve_products`: traust-engine's `registry/products.py` ownership resolver
(`traust registry products`), its `test_product_definitions.py` scenarios on core."""

from __future__ import annotations

import json
import shutil
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

import pytest

from traust_core.v1.context import Config, Context
from traust_core.v1.models.product_definitions import IDENTITY, norm_repo_url
from traust_core.v1.providers.clock import FixedClock

FIXTURE = Path(__file__).parents[2] / "fixtures" / "inventory" / "product-definitions"
NOW = datetime(2026, 10, 5, tzinfo=UTC)
FORBIDDEN_KEYS = {
    "bts",
    "cpe",
    "errata_product_tags",
    "team",
    "business_unit",
    "public_description",
    "brew_tags",
    "components",
}


@pytest.fixture
def cache(tmp_path: Path) -> Path:
    return Path(shutil.copytree(FIXTURE, tmp_path / "feeds"))


@pytest.fixture
def ctx(tmp_path: Path) -> Context:
    return Context(Config(home=tmp_path / "home"), clock=FixedClock(NOW))


def resolve(
    ctx: Context, cache: Path, mapfile: Path | None = None, **queries: list[str]
) -> dict[str, Any]:
    result = ctx.services().portfolio.resolve_products(
        ctx.product_definitions(cache).read(), ctx.product_mappings(mapfile), **queries
    )
    return result.model_dump(mode="json", exclude_unset=True)


def only(doc: dict[str, Any]) -> dict[str, Any]:
    assert len(doc["results"]) == 1
    return doc["results"][0]


def test_a_repo_url_joins_stream_to_module_to_contacts(ctx: Context, cache: Path) -> None:
    doc = resolve(ctx, cache, repo_urls=["https://github.com/acme/widget-api"])
    r = only(doc)
    assert doc["source_status"] == "ok"
    assert (r["match_tier"], r["ps_modules"], r["ps_products"]) == (
        "repo-url",
        ["widget-1"],
        ["widget"],
    )
    assert r["evidence"] == {
        "repo_url": "https://github.com/acme/widget-api",
        "ps_update_streams": ["widget-1-default"],
        "components": ["widget-api"],
    }
    assert r["query"] == {"kind": "repo-url", "value": "https://github.com/acme/widget-api"}


@pytest.mark.parametrize(
    "variant",
    [
        "https://github.com/acme/widget-api.git",
        "https://github.com/acme/widget-api/",
        "HTTPS://GitHub.com/ACME/Widget-API",
        "git@github.com:acme/widget-api.git",
    ],
)
def test_repo_urls_join_whatever_their_spelling(ctx: Context, cache: Path, variant: str) -> None:
    assert only(resolve(ctx, cache, repo_urls=[variant]))["match_tier"] == "repo-url"
    assert norm_repo_url(variant) == "github.com/acme/widget-api"


def test_an_unknown_repo_is_no_match_not_an_error(ctx: Context, cache: Path) -> None:
    r = only(resolve(ctx, cache, repo_urls=["https://github.com/acme/nope"]))
    assert r["match_tier"] == "none"
    assert r["evidence"] == {"repo_url": "https://github.com/acme/nope"}


def test_a_mapped_repo_outranks_its_url_match(ctx: Context, cache: Path, tmp_path: Path) -> None:
    mapfile = tmp_path / "map.yaml"
    mapfile.write_text("mappings:\n  repos:\n    github.com/acme/widget-api: relic\n")
    r = only(resolve(ctx, cache, mapfile, repo_urls=["https://github.com/acme/widget-api"]))
    assert (r["match_tier"], r["ps_products"]) == ("mapped", ["relic"])


def test_the_contact_ladder_tags_tiers_and_embargo(ctx: Context, cache: Path) -> None:
    r = only(resolve(ctx, cache, product_ids=["widget"]))
    assert r["contacts"] == [
        {
            "kerberos_id": "embargoperson",
            "field": "private_tracker_cc",
            "tier": 1,
            "embargo_cleared": True,
            "ps_module": "widget-1",
        },
        {
            "kerberos_id": "componentperson",
            "field": "component_cc",
            "tier": 2,
            "embargo_cleared": False,
            "ps_module": "widget-1",
            "component": "widget-core",
        },
        {
            "kerberos_id": "publicperson",
            "field": "default_cc",
            "tier": 3,
            "embargo_cleared": False,
            "ps_module": "widget-1",
        },
    ]
    assert r["embargo_cc"] == "present"


def test_default_cc_is_never_embargo_cleared(ctx: Context, cache: Path) -> None:
    r = only(resolve(ctx, cache, product_ids=["gizmo"]))
    assert [c["embargo_cleared"] for c in r["contacts"]] == [False]
    assert r["embargo_cc"] == "absent"


def test_an_unexpanded_alias_is_dropped_and_recorded(ctx: Context, cache: Path) -> None:
    r = only(resolve(ctx, cache, product_ids=["widget"]))
    assert r["dropped_contacts"] == [
        {
            "value": "+unexpanded",
            "field": "private_tracker_cc",
            "ps_module": "widget-1",
            "reason": "unexpanded_alias",
        }
    ]


def test_an_email_contact_keeps_its_local_part(ctx: Context, cache: Path) -> None:
    r = only(resolve(ctx, cache, product_ids=["gizmo"]))
    assert [c["kerberos_id"] for c in r["contacts"]] == ["gizmoperson"]


def test_a_high_drop_rate_warns_that_alias_expansion_regressed(ctx: Context, cache: Path) -> None:
    path = cache / "product_definitions.json"
    doc = json.loads(path.read_text())
    doc["ps_modules"]["gizmo-1"]["default_cc"] += ["+a", "Not Kerberos"]
    path.write_text(json.dumps(doc))
    out = resolve(ctx, cache, product_ids=["gizmo"])
    assert [d["reason"] for d in only(out)["dropped_contacts"]] == [
        "unexpanded_alias",
        "not_kerberos_shaped",
    ]
    assert out["warnings"] == [
        "2 of 3 contact values failed the kerberos-id shape gate. Upstream publishes with "
        "--expand-aliases, so a high rate suggests that regressed — check the compile before "
        "trusting an empty contact list."
    ]


def test_no_tracker_field_or_free_text_leaves_the_registry(ctx: Context, cache: Path) -> None:
    out = resolve(ctx, cache, product_ids=["widget"])

    def keys(node: object) -> set[str]:
        if isinstance(node, dict):
            return set(node) | {k for v in node.values() for k in keys(v)}
        return {k for v in node for k in keys(v)} if isinstance(node, list) else set()

    assert not FORBIDDEN_KEYS & keys(out)
    assert "SECRET FREE TEXT MARKER" not in json.dumps(out)


@pytest.mark.parametrize(
    ("product", "lifecycle"),
    [
        ("relic", ["2024-07-27", "2026-09-05", "eol"]),
        ("future-thing", ["2027-11-09", None, "unreleased"]),
        ("widget", ["2026-09-05", None, "supported"]),
    ],
)
def test_the_lifecycle_state_is_judged_on_the_clocks_day(
    ctx: Context, cache: Path, product: str, lifecycle: list[str | None]
) -> None:
    r = only(resolve(ctx, cache, product_ids=[product]))
    assert list(r["lifecycle"].values()) == lifecycle


def test_a_slug_match_is_flagged_advisory(ctx: Context, cache: Path) -> None:
    r = only(resolve(ctx, cache, packages=["widget"]))
    assert r["match_tier"] == "slug"
    assert r["evidence"]["slug"] == "widget"
    assert "advisory" in r["evidence"]["advisory_only"]


def test_a_product_name_slugs_too(ctx: Context, cache: Path) -> None:
    assert only(resolve(ctx, cache, packages=["example-gizmo"]))["ps_products"] == ["gizmo"]


def test_a_mapped_package_wins_over_its_slug(ctx: Context, cache: Path, tmp_path: Path) -> None:
    mapfile = tmp_path / "map.yaml"
    mapfile.write_text("mappings:\n  packages:\n    widget: gizmo\n  repos: {}\n")
    r = only(resolve(ctx, cache, mapfile, packages=["widget-findings"]))
    assert (r["match_tier"], r["ps_products"]) == ("mapped", ["gizmo"])
    assert r["evidence"] == {"ps_product": "gizmo", "mapped_from": "widget"}


def test_a_package_mapped_to_an_unknown_product_says_so(
    ctx: Context, cache: Path, tmp_path: Path
) -> None:
    mapfile = tmp_path / "map.yaml"
    mapfile.write_text("mappings:\n  packages:\n    widget: retired\n")
    r = only(resolve(ctx, cache, mapfile, packages=["widget"]))
    assert r["match_tier"] == "none"
    assert r["evidence"] == {"error": "mapped id 'retired' not in registry"}


def test_the_findings_suffix_is_optional(ctx: Context, cache: Path) -> None:
    assert only(resolve(ctx, cache, packages=["widget-findings"]))["ps_products"] == ["widget"]


def test_an_unknown_package_or_product_is_no_match(ctx: Context, cache: Path) -> None:
    out = resolve(ctx, cache, packages=["no-such-pkg"], product_ids=["no-such-id"])
    assert out["source_status"] == "ok"
    assert [(r["match_tier"], r["evidence"]) for r in out["results"]] == [
        ("none", {"package": "no-such-pkg"}),
        ("none", {"error": "'no-such-id' not in registry"}),
    ]
    assert "warnings" not in out


def test_results_follow_query_kind_order(ctx: Context, cache: Path) -> None:
    out = resolve(
        ctx,
        cache,
        product_ids=["gizmo"],
        repo_urls=["https://github.com/acme/widget-api"],
        packages=["relic"],
    )
    assert [r["query"]["kind"] for r in out["results"]] == ["package", "repo-url", "product"]


def test_a_missing_cache_is_unavailable_not_no_match(ctx: Context, tmp_path: Path) -> None:
    (tmp_path / "empty").mkdir()
    out = resolve(ctx, tmp_path / "empty", product_ids=["widget"])
    assert (out["source_status"], out["results"]) == ("unavailable", [])
    assert "No such file" in out["source"]["detail"]
    assert out["warnings"] == [
        "product-definitions cache unavailable — this source is optional; continue with the "
        "other ownership sources when the feed cache is unreachable."
    ]


def test_with_no_feeds_cache_configured_the_source_is_unavailable(ctx: Context) -> None:
    out = resolve(ctx, None, product_ids=["widget"])  # type: ignore[arg-type]
    assert out["source"] == {"detail": "feeds cache not configured"}


def test_a_malformed_cache_is_unavailable_not_an_empty_result(ctx: Context, tmp_path: Path) -> None:
    bad = tmp_path / "bad"
    bad.mkdir()
    (bad / "product_definitions.json").write_text('{"ps_products": {}, "ps_update_streams": {}}')
    out = resolve(ctx, bad, product_ids=["widget"])
    assert out["source"] == {
        "detail": "product-definitions cache is missing/malformed top-level key(s): ps_modules"
    }


@pytest.mark.parametrize("text", ["[]", "{not json"], ids=["not-an-object", "not-json"])
def test_an_unreadable_cache_document_is_unavailable(
    ctx: Context, tmp_path: Path, text: str
) -> None:
    bad = tmp_path / "bad"
    bad.mkdir()
    (bad / "product_definitions.json").write_text(text)
    assert resolve(ctx, bad, product_ids=["widget"])["source_status"] == "unavailable"


@pytest.mark.parametrize(
    ("retrieved_at", "status", "age"),
    [
        ("2026-10-04T12:00:00Z", "ok", 12.0),
        ("2026-09-01T00:00:00Z", "stale", 816.0),
        ("not a time", "stale", None),
    ],
)
def test_freshness_comes_from_the_feeds_meta(
    ctx: Context, cache: Path, retrieved_at: str, status: str, age: float | None
) -> None:
    (cache / "feeds-meta.json").write_text(
        json.dumps({"product-definitions": {"retrieved_at": retrieved_at}})
    )
    out = resolve(ctx, cache, product_ids=["gizmo"])
    assert out["source_status"] == status
    assert out["source"] == {
        "retrieved_at": retrieved_at,
        "age_hours": age,
        "max_age_hours": 720.0,
        "url": "https://example.com/product-definitions/products.json",
    }
    if status == "stale":
        assert out["warnings"] == [
            f"cache is {age}h old (threshold 720.0h) — refresh with traust feeds fetch-products"
        ]


def test_without_feeds_meta_the_cache_is_stale(ctx: Context, cache: Path) -> None:
    (cache / "feeds-meta.json").unlink()
    out = resolve(ctx, cache, product_ids=["widget"])
    assert (out["source_status"], out["source"]["retrieved_at"]) == ("stale", None)


def test_the_feeds_cache_defaults_to_locations(tmp_path: Path, cache: Path) -> None:
    home = tmp_path / "home"
    home.mkdir()
    (home / "traust.yaml").write_text(f"home: {home}\nlocations:\n  feeds_cache: {cache}\n")
    ctx = Context(Config.from_file(home / "traust.yaml"), clock=FixedClock(NOW))
    assert ctx.product_definitions().read().status == "ok"


def test_an_unparseable_map_is_ignored_with_a_warning(
    ctx: Context, cache: Path, tmp_path: Path
) -> None:
    mapfile = tmp_path / "map.yaml"
    mapfile.write_text("mappings: [\n")
    out = resolve(ctx, cache, mapfile, packages=["widget"])
    assert only(out)["match_tier"] == "slug"
    assert out["warnings"][0].startswith(f"{mapfile} unparseable (")
    assert out["warnings"][0].endswith(") — ignoring")


def test_an_absent_map_means_no_mappings(ctx: Context, tmp_path: Path) -> None:
    mappings = ctx.product_mappings(tmp_path / "absent.yaml")
    assert (mappings.packages, mappings.repos, mappings.warnings) == ({}, {}, ())


@pytest.mark.parametrize(
    ("value", "ok"),
    [
        ("adinn", True),
        ("eric.wittmann", True),
        ("+alias", False),
        ("Has Space", False),
        ("UPPER", False),
        ("x" * 64, True),
        ("x" * 65, False),
    ],
)
def test_the_identity_shape_gate(value: str, ok: bool) -> None:
    assert bool(IDENTITY.match(value)) is ok


def _core_yaml(home: Path) -> Path:
    path = home / "core.yaml"
    path.write_text(f"home: {home}\n")
    return path


def test_ctx_product_lookup_never_opens_the_record_store(
    ctx: Context, cache: Path, tmp_path: Path
) -> None:
    snapshot, mappings = ctx.product_definitions(cache).read(), ctx.product_mappings(None)
    queries = {"repo_urls": ["https://github.com/acme/widget-api"], "packages": ["nope"]}
    looked_up = ctx.product_lookup.resolve_products(snapshot, mappings, **queries)
    assert "database" not in ctx.__dict__
    assert not (tmp_path / "home").exists()
    assert {r.match_tier for r in looked_up.results} == {"repo-url", "none"}
    assert looked_up == ctx.services().portfolio.resolve_products(snapshot, mappings, **queries)
