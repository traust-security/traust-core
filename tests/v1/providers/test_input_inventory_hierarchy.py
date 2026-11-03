from __future__ import annotations

from pathlib import Path

from traust_core.v1.context.documents import yaml_documents
from traust_core.v1.providers.input_segments import InputSegments


def _file(root: Path, path: str, text: str) -> None:
    target = root / path
    target.parent.mkdir(parents=True, exist_ok=True)
    target.write_text(text)


def test_declared_kinds_preserve_release_catalog_and_service_hierarchy(tmp_path: Path) -> None:
    _file(
        tmp_path,
        "inventory.yaml",
        "segments:\n  platform: {kind: release-payload, label: Platform}\n"
        "  catalog: catalog\n  services: services\n",
    )
    _file(
        tmp_path,
        "platform/platform-4.20-payload-repos.csv",
        "GitHub URL,Category,Source Branch\nhttps://github.com/o/shared,network,release-4.20\n",
    )
    _file(
        tmp_path,
        "catalog/operator/2.0/bundle-payload-repos.csv",
        "URL,Category,Branch\nhttps://github.com/o/shared,operator,release-2.0\n",
    )
    _file(
        tmp_path,
        "services/control/api-repos.csv",
        "URL,App/Sub-Service,Resource Type\nhttps://github.com/o/api,control-api,first-party\n",
    )
    inventory = InputSegments(tmp_path, yaml_documents).read()
    assert [s.name for s in inventory.segments] == ["platform", "catalog", "services"]
    release, catalog, service = inventory.hierarchy
    assert (
        release.segment_label,
        release.product,
        release.release,
        release.category,
        release.branch,
    ) == ("Platform", None, "4.20", "network", "release-4.20")
    assert (catalog.product, catalog.version, catalog.category, catalog.branch) == (
        "operator",
        "2.0",
        "operator",
        "release-2.0",
    )
    assert (
        service.product,
        service.version,
        service.category,
        service.sub_service,
        service.resource_type,
    ) == ("control", None, None, "control-api", "first-party")
    assert service.source == "services/control/api-repos.csv"
    assert inventory.segments[0].repository_urls == inventory.segments[1].repository_urls


def test_distinct_branches_remain_distinct_without_multiplying_segment_population(
    tmp_path: Path,
) -> None:
    _file(tmp_path, "inventory.yaml", "segments:\n  catalog: catalog\n")
    for version in ("1.0", "2.0"):
        _file(
            tmp_path,
            f"catalog/operator/{version}/bundle-payload-repos.csv",
            f"URL,Source Branch\nhttps://github.com/o/shared,release-{version}\nhttps://github.com/o/shared,release-{version}\n",
        )
    inventory = InputSegments(tmp_path, yaml_documents).read()
    assert inventory.segments[0].repository_urls == ("https://github.com/o/shared",)
    assert {(r.version, r.branch) for r in inventory.hierarchy} == {
        ("1.0", "release-1.0"),
        ("2.0", "release-2.0"),
    }
    assert len(inventory.hierarchy) == 2
