"""The config matrix: effective deployed defaults as (key, default, sink) triples. Ported from
traust tests/test_expand_config_matrix.py."""

from __future__ import annotations

import json
from datetime import UTC, datetime
from pathlib import Path

import pytest

from traust_core.v1.context.context import yaml_documents
from traust_core.v1.errors import ValidationError
from traust_core.v1.models.code_facts import ConfigFact
from traust_core.v1.providers.clock import FixedClock
from traust_core.v1.providers.config_matrix import (
    MAX_TRIPLES,
    ConfigMatrix,
    _credential_name,
    config_matrix,
)
from traust_core.v1.providers.tools import ToolRequest


def _expand(repo: Path, max_triples: int = MAX_TRIPLES) -> dict:
    return config_matrix(repo, yaml_documents, max_triples).model_dump(
        mode="json", by_alias=True, exclude_none=True
    )


def _by_key(result: dict, key: str) -> list:
    return [t for t in result["triples"] if t["key"] == key or t["key"].endswith("." + key)]


# --------------------------------------------------------------------------
# helm values chain (the trustee-shape miss)
# --------------------------------------------------------------------------


@pytest.fixture
def helm_repo(tmp_path):
    chart = tmp_path / "deploy" / "chart"
    (chart / "templates").mkdir(parents=True)
    (chart / "Chart.yaml").write_text("name: svc\nversion: 1.0.0\n")
    (chart / "values.yaml").write_text(
        "database:\n"
        "  host: db.svc\n"
        "  sslmode: disable\n"
        "replicas: 2\n"
        "auth:\n"
        "  anonymousAccess: true\n"
    )
    (chart / "templates" / "deploy.yaml").write_text(
        "env:\n"
        "  - name: DB_DSN\n"
        "    value: postgres://u@{{ .Values.database.host }}/app"
        "?sslmode={{ .Values.database.sslmode }}\n"
    )
    return tmp_path


def test_helm_values_default_becomes_triple(helm_repo):
    result = _expand(helm_repo)
    [t] = _by_key(result, "database.sslmode")
    assert t["effective_default"] == "disable"
    assert t["source"]["system"] == "helm"
    assert t["source"]["path"].endswith("values.yaml")
    assert t["class"] == "dsn"
    assert t["judgement_required"] is True
    assert t["weak_default"] is True


def test_helm_sink_resolves_to_template_usage(helm_repo):
    result = _expand(helm_repo)
    [t] = _by_key(result, "database.sslmode")
    assert t["sink"]["status"] == "template"
    assert t["sink"]["path"].endswith("templates/deploy.yaml")
    assert "sslmode" in t["sink"]["expr"]


def test_helm_auth_default_classified(helm_repo):
    result = _expand(helm_repo)
    [t] = _by_key(result, "auth.anonymousAccess")
    assert t["class"] == "auth"
    assert t["judgement_required"] is True


def test_irrelevant_key_not_judged(helm_repo):
    result = _expand(helm_repo)
    [t] = _by_key(result, "replicas")
    assert t["judgement_required"] is False
    assert t["class"] == "other"


def test_chart_without_values_is_coverage_gap(tmp_path):
    chart = tmp_path / "chart"
    chart.mkdir()
    (chart / "Chart.yaml").write_text("name: rendered-only\n")
    result = _expand(tmp_path)
    gaps = [g for g in result["coverage_gaps"] if g["system"] == "helm"]
    assert gaps and "render time" in gaps[0]["reason"]


# --------------------------------------------------------------------------
# code-side fallback chains (the config-assembled DSN shape)
# --------------------------------------------------------------------------


def test_go_getenv_if_empty_fallback(tmp_path):
    (tmp_path / "db.go").write_text(
        "package config\n\n"
        "func dsn() string {\n"
        '\tmode := os.Getenv("DB_SSLMODE")\n'
        '\tif mode == "" {\n'
        '\t\tmode = "disable"\n'
        "\t}\n"
        "\treturn mode\n"
        "}\n"
    )
    result = _expand(tmp_path)
    [t] = _by_key(result, "DB_SSLMODE")
    assert t["effective_default"] == "disable"
    assert t["source"]["system"] == "env-chain-go"
    assert t["sink"]["status"] == "code"
    assert t["judgement_required"] is True


def test_go_viper_and_cmp_or(tmp_path):
    (tmp_path / "cfg.go").write_text(
        "package cfg\n"
        "func init() {\n"
        '\tviper.SetDefault("server.tls.enabled", false)\n'
        '\taddr := cmp.Or(os.Getenv("BIND_ADDR"), "0.0.0.0:8080")\n'
        "\t_ = addr\n"
        "}\n"
    )
    result = _expand(tmp_path)
    [tls] = _by_key(result, "server.tls.enabled")
    assert tls["effective_default"] == "false"
    assert tls["class"] == "tls"
    [bind] = _by_key(result, "BIND_ADDR")
    assert bind["effective_default"] == "0.0.0.0:8080"
    assert bind["class"] == "listener"


def test_python_environ_get_default(tmp_path):
    (tmp_path / "settings.py").write_text(
        'VERIFY_TLS = os.environ.get("VERIFY_TLS", "false")\n'
        'PAGE_SIZE = os.getenv("PAGE_SIZE", 50)\n'
    )
    result = _expand(tmp_path)
    [t] = _by_key(result, "VERIFY_TLS")
    assert t["effective_default"] == "false"
    assert t["judgement_required"] is True
    [p] = _by_key(result, "PAGE_SIZE")
    assert p["judgement_required"] is False


def test_js_process_env_fallback(tmp_path):
    (tmp_path / "server.js").write_text("const debug = process.env.DEBUG_MODE || 'true';\n")
    result = _expand(tmp_path)
    [t] = _by_key(result, "DEBUG_MODE")
    assert t["effective_default"] == "true"
    assert t["class"] == "debug"


def test_test_files_excluded(tmp_path):
    (tmp_path / "db_test.go").write_text(
        'func t() { m := os.Getenv("X_MODE")\nif m == "" { m = "disable" } }\n'
    )
    result = _expand(tmp_path)
    assert _by_key(result, "X_MODE") == []


# --------------------------------------------------------------------------
# compose + k8s env literals + kustomize
# --------------------------------------------------------------------------


def test_compose_environment(tmp_path):
    (tmp_path / "docker-compose.yml").write_text(
        "services:\n"
        "  api:\n"
        "    environment:\n"
        "      DATABASE_URL: postgres://u:p@db/app?sslmode=disable\n"
        "      LOG_LEVEL: info\n"
    )
    result = _expand(tmp_path)
    [t] = _by_key(result, "DATABASE_URL")
    assert t["class"] == "dsn"
    assert t["sink"] == {"status": "service", "service": "api"}


def test_k8s_deployment_env_and_configmap(tmp_path):
    (tmp_path / "manifests").mkdir()
    (tmp_path / "manifests" / "deploy.yaml").write_text(
        "apiVersion: apps/v1\n"
        "kind: Deployment\n"
        "spec:\n"
        "  template:\n"
        "    spec:\n"
        "      containers:\n"
        "        - name: app\n"
        "          env:\n"
        "            - name: INSECURE_SKIP_VERIFY\n"
        '              value: "true"\n'
        "---\n"
        "apiVersion: v1\n"
        "kind: ConfigMap\n"
        "metadata: {name: cfg}\n"
        "data:\n"
        '  auth.anonymous: "enabled"\n'
    )
    result = _expand(tmp_path)
    [skip] = _by_key(result, "INSECURE_SKIP_VERIFY")
    assert skip["class"] == "tls"
    assert skip["sink"]["container"] == "app"
    [anon] = _by_key(result, "auth.anonymous")
    assert anon["source"]["system"] == "k8s-configmap"


def test_kustomize_literals(tmp_path):
    (tmp_path / "kustomization.yaml").write_text(
        "configMapGenerator:\n  - name: cfg\n    literals:\n      - DB_SSLMODE=prefer\n"
    )
    result = _expand(tmp_path)
    [t] = _by_key(result, "DB_SSLMODE")
    assert t["effective_default"] == "prefer"
    assert t["weak_default"] is True


# --------------------------------------------------------------------------
# scope + coverage-gap + output contracts
# --------------------------------------------------------------------------


def test_no_override_cross_product(tmp_path):
    """Plan D3 risk (c): one triple per (key, default, source), never the
    override combination space — two values files yield two triples for
    the same key, not a matrix of joint states."""
    chart = tmp_path / "chart"
    (chart / "templates").mkdir(parents=True)
    (chart / "Chart.yaml").write_text("name: svc\n")
    (chart / "values.yaml").write_text("tlsVerify: false\n")
    (chart / "values-prod.yaml").write_text("tlsVerify: true\n")
    result = _expand(tmp_path)
    assert len(_by_key(result, "tlsVerify")) == 2


def test_toml_ini_emit_coverage_gap(tmp_path):
    (tmp_path / "app.toml").write_text("[db]\nsslmode = 'disable'\n")
    (tmp_path / "legacy.ini").write_text("[auth]\nanonymous = yes\n")
    result = _expand(tmp_path)
    [gap] = [g for g in result["coverage_gaps"] if g["system"] == "config-file"]
    assert gap["count"] == 2
    assert not _by_key(result, "db.sslmode")


def test_vendor_and_dotgit_skipped(tmp_path):
    v = tmp_path / "vendor" / "lib"
    v.mkdir(parents=True)
    (v / "compose.yaml").write_text(
        "services:\n  x:\n    environment:\n      SECRET_KEY: hunter2\n"
    )
    result = _expand(tmp_path)
    assert result["triples"] == []


def test_triple_cap_records_gap_and_keeps_judged_first(tmp_path):
    lines = "\n".join(f'K{i} = os.environ.get("PLAIN_{i}", "v")' for i in range(30))
    (tmp_path / "big.py").write_text(lines + '\nS = os.environ.get("DB_PASSWORD", "changeme")\n')
    result = _expand(tmp_path, max_triples=5)
    assert len(result["triples"]) == 5
    assert result["triples"][0]["key"] == "DB_PASSWORD"  # judged kept first
    [gap] = [g for g in result["coverage_gaps"] if g["system"] == "expander"]
    assert gap["count"] == 26


def test_dedupe_on_key_default_and_source(helm_repo):
    result = _expand(helm_repo)
    assert sum(t["judgement_required"] for t in result["triples"]) >= 3
    sigs = {
        (t["key"], t["effective_default"], t["source"]["path"], t["source"]["line"])
        for t in result["triples"]
    }
    assert len(sigs) == len(result["triples"])


# --------------------------------------------------------------------------
# python settings: modules and settings classes (parsed, never imported)
# --------------------------------------------------------------------------

# Credential-shaped fixture values are built at runtime, so no literal that
# looks like a secret is committed.
FAKE_KEY = "k" * 24
FAKE_PW = "p" * 12


@pytest.fixture
def settings_repo(tmp_path):
    app = tmp_path / "app"
    app.mkdir()
    (app / "config.py").write_text(
        "import os\n"
        "class Config:\n"
        "    DEBUG = False\n"
        f"    SECRET_KEY = '{FAKE_KEY}'\n"
        "    WTF_CSRF_ENABLED = True\n"
        "    SESSION_COOKIE_NAME = 'session'\n"
        "class TestingConfig(Config):\n"
        "    TESTING = True\n"
        "    WTF_CSRF_ENABLED = False\n"
        "class ProductionConfig(Config):\n"
        "    API_TOKEN = os.environ.get('API_TOKEN')\n"
    )
    (app / "settings.py").write_text(
        "DEBUG = True\n"
        "ALLOWED_HOSTS = '*'\n"
        f"DATABASE_URL = 'postgres://app:{FAKE_PW}@db/app'\n"
        "_PRIVATE = 1\n"
        "lower_case = 'ignored'\n"
    )
    (app / "models.py").write_text(
        "from pydantic_settings import BaseSettings\n"
        "class AppSettings(BaseSettings):\n"
        "    verify_signature: bool = False\n"
        "    region: str = 'us-east-1'\n"
        "class Widget:\n"
        "    DEBUG = True\n"
    )
    (app / "views.py").write_text(
        "from flask import current_app\n"
        "def index():\n"
        "    if current_app.config['DEBUG']:\n"
        "        return 'debug'\n"
        "    return config.get('WTF_CSRF_ENABLED')\n"
    )
    return tmp_path


def _settings(result):
    return [t for t in result["triples"] if t["source"]["system"] == "python-settings"]


def test_settings_classes_and_modules_become_triples(settings_repo):
    keys = {t["key"] for t in _settings(_expand(settings_repo))}
    assert {
        "Config.DEBUG",
        "Config.SECRET_KEY",
        "TestingConfig.TESTING",
        "TestingConfig.WTF_CSRF_ENABLED",
        "DEBUG",
        "DATABASE_URL",
        "AppSettings.verify_signature",
    } <= keys
    # not settings: a non-settings class, private and lower-case module names
    assert "Widget.DEBUG" not in keys
    assert "_PRIVATE" not in keys and "lower_case" not in keys
    # an env read is left to the env-chain tier
    assert "ProductionConfig.API_TOKEN" not in keys


def test_security_toggles_are_judged(settings_repo):
    by = {t["key"]: t for t in _settings(_expand(settings_repo))}
    for key in ("TestingConfig.TESTING", "TestingConfig.WTF_CSRF_ENABLED", "DEBUG"):
        assert by[key]["judgement_required"], key
    assert by["TestingConfig.WTF_CSRF_ENABLED"].get("weak_default")  # False
    assert by["AppSettings.verify_signature"]["judgement_required"]
    assert not by["AppSettings.region"]["judgement_required"]


def test_hardcoded_secrets_are_weak_defaults_and_never_copied(settings_repo):
    result = _expand(settings_repo)
    by = {t["key"]: t for t in _settings(result)}
    key = by["Config.SECRET_KEY"]
    assert key["literal_redacted"] and key["weak_default"] and key["judgement_required"]
    assert key["effective_default"] == f"<hardcoded literal, {len(FAKE_KEY)} chars>"
    dsn = by["DATABASE_URL"]
    assert (
        dsn["literal_redacted"] and dsn["effective_default"] == "postgres://app:<redacted>@db/app"
    )
    blob = json.dumps(result)
    assert FAKE_KEY not in blob and FAKE_PW not in blob


def test_sinks_list_the_readers(settings_repo):
    by = {t["key"]: t for t in _settings(_expand(settings_repo))}
    sink = by["DEBUG"]["sink"]
    assert sink["status"] == "readers" and sink["count"] >= 1
    assert {"path": "app/views.py", "line": 3} in sink["sites"]
    assert by["TestingConfig.WTF_CSRF_ENABLED"]["sink"]["status"] == "readers"
    assert by["Config.SESSION_COOKIE_NAME"]["sink"]["status"] == "unresolved"


def test_settings_files_are_parsed_not_imported(tmp_path):
    marker = tmp_path / "imported"
    (tmp_path / "settings.py").write_text(f"open({str(marker)!r}, 'w').write('x')\nDEBUG = True\n")
    result = _expand(tmp_path)
    assert not marker.exists()
    assert any(t["key"] == "DEBUG" for t in _settings(result))


def test_unparseable_settings_module_is_a_coverage_gap(tmp_path):
    (tmp_path / "settings.py").write_text("DEBUG = (\n")
    gaps = _expand(tmp_path)["coverage_gaps"]
    assert any(g["system"] == "python-settings" and "settings.py" in g["paths"] for g in gaps)


def test_settings_in_test_files_are_skipped(tmp_path):
    (tmp_path / "test_settings.py").write_text("DEBUG = True\n")
    (tmp_path / "conftest.py").write_text("class TestConfig:\n    DEBUG = True\n")
    (tmp_path / "tests").mkdir()
    (tmp_path / "tests" / "config.py").write_text("class Config:\n    DEBUG = True\n")
    assert _settings(_expand(tmp_path)) == []


def test_settings_are_classified_by_name_not_by_a_module_path_value(tmp_path):
    (tmp_path / "settings.py").write_text(
        "ROOT_URLCONF = 'rbac.urls'\nDEBUG = False\nDEBUG_TOOLBAR = True\n"
        "CACHE_URL = 'redis://cache:6379/0'\n"
        "METRICS_EXPORT_ADDRESS = '0.0.0.0'\n"
    )
    by = {t["key"]: t for t in _settings(_expand(tmp_path))}
    assert not by["ROOT_URLCONF"]["judgement_required"]
    assert by["DEBUG"]["judgement_required"] and not by["DEBUG"].get("weak_default")
    assert by["DEBUG_TOOLBAR"].get("weak_default")  # a debug toggle ON is weak
    assert by["CACHE_URL"]["class"] == "dsn"
    bind = by["METRICS_EXPORT_ADDRESS"]
    assert bind["class"] == "listener" and bind.get("weak_default")


# --------------------------------------------------------------------------
# credentials are redacted in every tier, under any credential-shaped name
# --------------------------------------------------------------------------


def test_a_signing_key_and_a_verification_toggle_in_a_settings_class(tmp_path):
    (tmp_path / "config.py").write_text(
        "class Config:\n"
        f"    TOKEN_SIGNING_KEY = '{FAKE_KEY}'  # gitleaks:allow\n"
        "    VERIFY_WEBHOOK_SIGNATURES = False\n"
    )
    result = _expand(tmp_path)
    by = {t["key"]: t for t in _settings(result)}
    key = by["Config.TOKEN_SIGNING_KEY"]
    assert key["literal_redacted"] and key["weak_default"] and key["judgement_required"]
    flag = by["Config.VERIFY_WEBHOOK_SIGNATURES"]
    assert flag["judgement_required"] and flag.get("weak_default")
    assert FAKE_KEY not in json.dumps(result)


def test_env_chain_defaults_are_redacted_too(tmp_path):
    (tmp_path / "app.py").write_text(
        f"import os\nTOKEN = os.environ.get('API_TOKEN', '{FAKE_KEY}')\n"
    )
    result = _expand(tmp_path)
    (t,) = [t for t in result["triples"] if t["key"] == "API_TOKEN"]
    assert t["literal_redacted"] and t["effective_default"].startswith("<hardcoded literal")
    assert FAKE_KEY not in json.dumps(result)


def test_helm_values_credentials_are_redacted(tmp_path):
    chart = tmp_path / "chart"
    (chart / "templates").mkdir(parents=True)
    (chart / "Chart.yaml").write_text("name: c\nversion: 0.1.0\n")
    (chart / "values.yaml").write_text(f"auth:\n  apiKey: {FAKE_KEY}\n  publicKey: abcdefgh\n")
    result = _expand(tmp_path)
    by = {t["key"]: t for t in result["triples"]}
    assert by["auth.apiKey"]["literal_redacted"]
    assert not by["auth.publicKey"]["literal_redacted"]
    assert FAKE_KEY not in json.dumps(result)


@pytest.mark.parametrize(
    ("name", "credential"),
    [
        ("SIGNING_KEY", True),
        ("apiToken", True),
        ("session-secret", True),
        ("PASSWORD_SALT", True),
        ("KEY", True),
        ("PUBLIC_KEY", False),
        ("primary_key", False),
        ("monkey", False),
        ("MAX_TOKENS", False),
        ("ACCESS_TOKEN_MINUTES", False),
    ],
)
def test_credential_shaped_names(name, credential):
    assert _credential_name(name) is credential


def test_templated_values_are_not_literals(tmp_path):
    (tmp_path / "settings.py").write_text("API_TOKEN = '${API_TOKEN}'\n")
    (t,) = _settings(_expand(tmp_path))
    assert not t["literal_redacted"] and t["effective_default"] == "${API_TOKEN}"


def test_enumerator_returns_one_matrix(helm_repo):
    at = datetime(2026, 10, 25, tzinfo=UTC)
    result = ConfigMatrix(FixedClock(at), yaml_documents).enumerate(
        ToolRequest(workspace=helm_repo)
    )
    [matrix] = result.data
    assert isinstance(matrix, ConfigFact) and matrix.triples
    assert result.acquisition.provider == "config-matrix"
    assert result.acquisition.acquired_at == at


def test_empty_tree_is_an_empty_matrix(tmp_path):
    assert config_matrix(tmp_path, yaml_documents) == ConfigFact()


def test_missing_workspace_is_refused(tmp_path):
    with pytest.raises(ValidationError, match="not a directory"):
        config_matrix(tmp_path / "absent", yaml_documents)


def test_malformed_yaml_and_shapes_are_skipped(tmp_path):
    (tmp_path / "docker-compose.yml").write_text("services: [a, b]\n")
    (tmp_path / "cm.yaml").write_text("kind: ConfigMap\ndata: [x]\n")
    (tmp_path / "bad.yaml").write_text("kind: Deployment\n  : : bad\n")
    assert _expand(tmp_path)["triples"] == []


def test_class_serializes_under_its_legacy_name(helm_repo):
    triple = config_matrix(helm_repo, yaml_documents).triples[0]
    assert triple.model_dump(by_alias=True)["class"] == triple.config_class
