from pathlib import Path

import pytest

from traust_core.v1.context.documents import yaml_documents, yaml_text
from traust_core.v1.errors import ValidationError
from traust_core.v1.models.inventory_reference import RepositoryDeclaration
from traust_core.v1.providers.inventory_reference import InventoryReferenceFile

HOSTS = {"github.com": "github"}
URL = "https://github.com/example-org/api"


def test_reference_round_trip_merges_only_supplied_fields(tmp_path: Path) -> None:
    path = tmp_path / "declared.yaml"
    provider = InventoryReferenceFile(path, HOSTS, yaml_documents, yaml_text)
    provider.merge(
        (
            RepositoryDeclaration(
                repo_url=URL + ".git/",
                service="Payments",
                individual_owners=("alice",),
                ownership_source="reviewed OWNERS",
                manager="morgan",
                jira_project="PAY",
                jira_component="Gateway",
                escalation_contact="oncall@example.com",
            ),
        )
    )
    InventoryReferenceFile(path, HOSTS, yaml_documents, yaml_text).merge(
        (
            RepositoryDeclaration(
                repo_url=URL,
                service="Gateway",
            ),
        )
    )
    (stored,) = InventoryReferenceFile(path, HOSTS, yaml_documents, yaml_text).read().repositories
    assert stored.repo_url == URL
    assert stored.service == "Gateway"
    assert stored.individual_owners == ("alice",)
    assert stored.ownership_source == "reviewed OWNERS"
    assert (stored.manager, stored.jira_project, stored.jira_component) == (
        "morgan",
        "PAY",
        "Gateway",
    )
    assert stored.escalation_contact == "oncall@example.com"
    provider.merge((RepositoryDeclaration(repo_url=URL, jira_component=None),))
    assert provider.read().repositories[0].jira_component is None


def test_intake_accumulates_versions_but_authoritative_import_can_clear_them(
    tmp_path: Path,
) -> None:
    provider = InventoryReferenceFile(tmp_path / "reference.yaml", HOSTS, yaml_documents, yaml_text)
    provider.merge((RepositoryDeclaration(repo_url=URL, operator_versions=("1.0",)),))
    provider.merge(
        (
            RepositoryDeclaration(
                repo_url=URL,
                operator_versions=("1.0", "2.0"),
                payload_versions=("4.0",),
            ),
        ),
        append_versions=True,
    )
    (stored,) = provider.read().repositories
    assert stored.operator_versions == ("1.0", "2.0")
    assert stored.payload_versions == ("4.0",)
    provider.merge((RepositoryDeclaration(repo_url=URL, operator_versions=()),))
    assert provider.read().repositories[0].operator_versions == ()
    assert provider.read().repositories[0].payload_versions == ("4.0",)


@pytest.mark.parametrize(
    "document",
    [
        "version: 2\nrepositories: []\n",
        "repositories:\n- repo_url: https://github.com/example-org/api\n"
        "- repo_url: https://github.com/example-org/api.git\n",
        "repositories:\n- repo_url: http://github.com/example-org/api\n",
        "repositories: [invalid\n",
        "repositories: []\n---\nrepositories: []\n",
    ],
)
def test_invalid_reference_is_refused_without_overwriting_it(tmp_path: Path, document: str) -> None:
    path = tmp_path / "declared.yaml"
    path.write_text(document)
    with pytest.raises(ValidationError):
        InventoryReferenceFile(path, HOSTS, yaml_documents, yaml_text).merge(
            (RepositoryDeclaration(repo_url=URL),)
        )
    assert path.read_text() == document
