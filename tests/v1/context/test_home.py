"""The deployment config home resolves, looks files up and audits exactly as traust-contracts'
`deployment_config_dir`, `config_path`, `optional_config_path` and `config_completeness_audit`."""

from __future__ import annotations

import shutil
from pathlib import Path

import pytest

from traust_core.v1 import contracts
from traust_core.v1.context import (
    TRAUST_CONFIG_HOME_ENV,
    config_completeness_audit,
    config_path,
    optional_config_path,
    resolve_config_home,
    schema_dir,
    schema_path,
)
from traust_core.v1.context import home as config_home
from traust_core.v1.errors import ConfigError, DeploymentConfigMissing

FIXTURES = Path(__file__).parents[2] / "fixtures"
SEEDED_HOME = FIXTURES / "context" / "config-home"
REGISTRY = FIXTURES / "operations" / "model-registry.yaml"
LOCATIONS = "workspace: ws\nanalysis_results: ar\nprogress_tracker: pt\n"
TREES = (
    "version: 1\n"
    "trees:\n"
    "  findings: {ownership: owned, label: example, business_unit: Example BU}\n"
)


@pytest.fixture(autouse=True)
def no_operator_home(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> Path:
    default = tmp_path / "default-home"
    monkeypatch.delenv(TRAUST_CONFIG_HOME_ENV, raising=False)
    monkeypatch.setattr(config_home, "TRAUST_CONFIG_HOME_DEFAULT", default)
    return default


@pytest.fixture
def seeded(tmp_path: Path) -> Path:
    """A home as install_traust seeds it: every required file, no trees, nothing optional."""
    home = tmp_path / "config"
    shutil.copytree(SEEDED_HOME, home)
    shutil.copy(REGISTRY, home / "model-registry.yaml")
    return home


def test_an_explicit_home_wins_over_the_environment(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    monkeypatch.setenv(TRAUST_CONFIG_HOME_ENV, str(tmp_path / "env"))
    assert resolve_config_home(tmp_path / "given") == tmp_path / "given"


def test_the_environment_names_the_home_with_user_expanded(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    monkeypatch.setenv("HOME", str(tmp_path))
    monkeypatch.setenv(TRAUST_CONFIG_HOME_ENV, "~/conf")
    assert resolve_config_home() == tmp_path / "conf"


def test_an_empty_environment_variable_is_unset(
    monkeypatch: pytest.MonkeyPatch, no_operator_home: Path
) -> None:
    monkeypatch.setenv(TRAUST_CONFIG_HOME_ENV, "")
    assert resolve_config_home() is None


def test_the_default_home_counts_only_when_it_exists(no_operator_home: Path) -> None:
    assert resolve_config_home() is None
    no_operator_home.mkdir()
    assert resolve_config_home() == no_operator_home


def test_a_present_file_resolves_in_the_home(monkeypatch: pytest.MonkeyPatch, seeded: Path) -> None:
    monkeypatch.setenv(TRAUST_CONFIG_HOME_ENV, str(seeded))
    assert optional_config_path("feeds.yaml") == seeded / "feeds.yaml"
    assert config_path("feeds.yaml") == seeded / "feeds.yaml"


def test_an_absent_optional_file_is_none(monkeypatch: pytest.MonkeyPatch, seeded: Path) -> None:
    monkeypatch.setenv(TRAUST_CONFIG_HOME_ENV, str(seeded))
    (seeded / "budget-policy.yaml").mkdir()
    assert optional_config_path("budget-policy.yaml") is None
    assert optional_config_path("sla-policy.yaml") is None


def test_with_no_home_every_optional_file_is_none() -> None:
    assert optional_config_path("feeds.yaml") is None


def test_an_absent_required_file_names_the_home_and_its_template(
    monkeypatch: pytest.MonkeyPatch, seeded: Path
) -> None:
    monkeypatch.setenv(TRAUST_CONFIG_HOME_ENV, str(seeded))
    with pytest.raises(DeploymentConfigMissing) as caught:
        config_path("org-parameters.yaml")
    assert str(caught.value) == (
        f"required config file 'org-parameters.yaml' not found in {seeded}. Copy "
        "config/org-parameters.example.yaml there as 'org-parameters.yaml' and fill it in, "
        "or run scripts/install_traust."
    )


def test_a_required_file_with_no_home_says_why(no_operator_home: Path) -> None:
    with pytest.raises(DeploymentConfigMissing, match=r"ledger-signing-key\.example") as caught:
        config_path("ledger-signing-key")
    assert f"<${TRAUST_CONFIG_HOME_ENV} unset and {no_operator_home} absent>" in str(caught.value)


def test_a_missing_deployment_file_is_a_config_error_and_a_missing_file() -> None:
    with pytest.raises(ConfigError):
        config_path("feeds.yaml")
    with pytest.raises(FileNotFoundError):
        config_path("feeds.yaml")


def test_the_audit_without_a_home_is_one_error(no_operator_home: Path) -> None:
    assert config_completeness_audit() == (
        [
            f"no config home: set ${TRAUST_CONFIG_HOME_ENV} or run scripts/install_traust "
            f"(default {no_operator_home})."
        ],
        [],
    )


def test_the_audit_of_an_empty_home_names_the_first_required_file(tmp_path: Path) -> None:
    errors, warnings = config_completeness_audit(config_home=tmp_path)
    assert errors == [
        f"required config file 'model-registry.yaml' not found in {tmp_path}. Copy "
        "config/model-registry.example.yaml there as 'model-registry.yaml' and fill it in, "
        "or run scripts/install_traust."
    ]
    assert warnings == []


def test_the_audit_of_a_seeded_home_reports_what_the_operator_still_owes(seeded: Path) -> None:
    errors, warnings = config_completeness_audit(config_home=seeded)
    assert errors == []
    assert [w.split(":")[0] for w in warnings] == ["internal-vocabulary.yaml"]


def test_the_audit_reads_the_home_from_the_environment(
    monkeypatch: pytest.MonkeyPatch, seeded: Path
) -> None:
    monkeypatch.setenv(TRAUST_CONFIG_HOME_ENV, str(seeded))
    assert config_completeness_audit() == config_completeness_audit(config_home=seeded)


def test_the_audit_of_a_complete_home_is_clean(seeded: Path) -> None:
    (seeded / "corpus-config.yaml").write_text(TREES)
    (seeded / "locations.yaml").write_text(LOCATIONS)
    (seeded / "product-definitions-map.yaml").write_text("mappings:\n  repos: {a: product-a}\n")
    (seeded / "internal-vocabulary.yaml").write_text("rules: []\n")
    (seeded / "ledger-signing-key.pub").write_text("key\n")
    assert config_completeness_audit(config_home=seeded) == ([], [])


@pytest.mark.parametrize(
    ("name", "text"),
    [
        ("model-registry.yaml", "version: 1\ntiers: {}\n"),
        ("model-registry.yaml", "version: [1\n"),
        ("hardening-risk-weights.json", "{not json"),
    ],
    ids=["schema", "yaml", "json"],
)
def test_a_malformed_file_fails_the_audit_as_a_config_error(
    seeded: Path, name: str, text: str
) -> None:
    (seeded / name).write_text(text)
    with pytest.raises(ConfigError, match=f"cannot audit config home {seeded}"):
        config_completeness_audit(config_home=seeded)


def test_schema_files_resolve_in_the_pinned_contracts() -> None:
    assert schema_path("report") == schema_dir() / "report.schema.json"
    assert schema_path("report").is_file()
    assert "report" in contracts.schema_names()
