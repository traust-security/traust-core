"""`Context.preflight`: every unmet requirement of the enabled assets at once, each with its
fix; the same door the engine's start gate and `traust doctor` call."""

from __future__ import annotations

import shutil
import subprocess
from pathlib import Path

import pydantic
import pytest
import yaml
from traust_core.v1.context import Config, Context
from traust_core.v1.context.home import TRAUST_CONFIG_HOME_ENV
from traust_core.v1.errors import PreflightError
from traust_core.v1.models.artifacts import SlaPolicyArtifact
from traust_core.v1.models.operations import Requirement
from traust_core.v1.providers.base import Readiness
from traust_core.v1.repositories.contract import SqlTraustUnitOfWork
from traust_core.v1.services.artifact_publishing import (
    ArtifactPublisher,
    PublishSpec,
    PublishSpecs,
)

FIXTURES = Path(__file__).parents[2] / "fixtures"
MODEL_REGISTRY = FIXTURES / "operations" / "model-registry.yaml"
SLA_POLICY = FIXTURES / "insight" / "sla-policy.yaml"
TRIAGE_REQUIREMENT = Requirement(config=("identity", "ledger", "review"))
SBOM_REQUIREMENT = Requirement(tools=("syft",))

TOOLS = """
tools:
  - name: not-a-real-tool
    expected: "9.9.9"
    version_cmd: [not-a-real-tool, --version]
"""

FEEDS = """
version: 1
sources:
  deps_dev:
    tier: live
    url_template: https://dd.test/v3/systems/{ident}
"""

# Every key the completeness audit warns about is set; `home` keeps the database in tmp_path.
COMPLETE = """
home: {store}
locations:
  workspace: ws
  analysis_results: results
  progress_tracker: tracker
ledger:
  public_key_path: /keys/ledger.pub
"""


def context(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    *,
    traust_yaml: str | None = COMPLETE,
    tools: bool = True,
    feeds: bool = True,
    model_registry: bool = True,
) -> Context:
    home = tmp_path / "home"
    home.mkdir(exist_ok=True)
    if traust_yaml is not None:
        (home / "traust.yaml").write_text(traust_yaml.replace("{store}", str(tmp_path / "store")))
    if model_registry:
        (home / "model-registry.yaml").write_bytes(MODEL_REGISTRY.read_bytes())
    monkeypatch.setenv(TRAUST_CONFIG_HOME_ENV, str(home))
    ctx = Context(Config.from_home(home))
    if tools:
        ctx.register_toolchain(
            _write(tmp_path, "external-tools.yaml", TOOLS),
            _write(tmp_path, "safe-exec-profiles.yaml", "profiles: {}\n"),
        )
    if feeds:
        ctx.register_feeds(_write(tmp_path, "feeds.yaml", FEEDS))
    if model_registry:
        ctx.register_model_catalog(home / "model-registry.yaml")
    return ctx


def _write(tmp_path: Path, name: str, text: str) -> Path:
    path = tmp_path / name
    path.write_text(text)
    return path


def gaps(error: PreflightError) -> list[str]:
    return str(error).splitlines()[1:]


def test_a_complete_home_with_every_requirement_met_passes(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    ctx = context(tmp_path, monkeypatch)
    monkeypatch.setenv("NVD_API_KEY", "synthetic-only")
    record_sla_policy(ctx)
    ctx.preflight(
        [
            Requirement(config=("ledger",), facts=("sla-policy",), feeds=("deps_dev",)),
            Requirement(config=("model-registry",), secrets=("NVD_API_KEY",)),
        ]
    )
    ctx.preflight([])


def test_every_gap_is_listed_at_once(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    ctx = context(tmp_path, monkeypatch, traust_yaml=COMPLETE.replace("  workspace: ws\n", ""))
    monkeypatch.delenv("NVD_API_KEY", raising=False)
    with pytest.raises(PreflightError) as caught:
        ctx.preflight(
            [
                Requirement(tools=("not-a-real-tool",), config=("review",)),
                Requirement(facts=("sla-policy",), feeds=("osv",)),
                Requirement(secrets=("NVD_API_KEY",)),
            ]
        )
    lines = gaps(caught.value)
    assert lines == [
        "- not-a-real-tool: not found on PATH "
        "(install it at the external-tools.yaml pin, not-a-real-tool >= 9.9.9)",
        "- config: `review` is not set -- set it in traust.yaml (copy traust.example.yaml "
        "to start)",
        "- facts: sla-policy is not recorded -- record one (InsightService.record_sla_policy)",
        "- feeds: osv is not an enabled source -- enable it in the feeds registry "
        "(Context.register_feeds)",
        "- secrets: $NVD_API_KEY is not set",
        "- traust.yaml: locations.workspace unset",
    ]


def test_requirements_of_several_assets_are_checked_once(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    ctx = context(tmp_path, monkeypatch)
    with pytest.raises(PreflightError) as caught:
        ctx.preflight(
            [
                Requirement(tools=("not-a-real-tool",), config=("review",)),
                Requirement(tools=("not-a-real-tool",), config=("review", "campaign")),
            ]
        )
    assert gaps(caught.value) == [
        "- not-a-real-tool: not found on PATH "
        "(install it at the external-tools.yaml pin, not-a-real-tool >= 9.9.9)",
        "- config: `campaign` is not set -- set it in traust.yaml (copy traust.example.yaml "
        "to start)",
        "- config: `review` is not set -- set it in traust.yaml (copy traust.example.yaml "
        "to start)",
    ]


def test_a_config_requirement_names_the_unset_traust_yaml_key(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    ctx = context(tmp_path, monkeypatch)
    with pytest.raises(PreflightError, match="`review` is not set"):
        ctx.preflight([Requirement(config=("review",))])
    ctx.preflight([Requirement(config=("ledger",))])


def test_a_model_registry_requirement_names_the_register_door(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    ctx = context(tmp_path, monkeypatch, model_registry=False)
    with pytest.raises(PreflightError, match="model-registry is not registered"):
        ctx.preflight([Requirement(config=("model-registry",))])


def test_a_fact_requirement_names_the_record_door(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    ctx = context(tmp_path, monkeypatch)
    with pytest.raises(PreflightError, match="sla-policy is not recorded"):
        ctx.preflight([Requirement(facts=("sla-policy",))])
    record_sla_policy(ctx)
    ctx.preflight([Requirement(facts=("sla-policy",))])


def record_sla_policy(ctx: Context) -> None:
    publisher = ArtifactPublisher(
        PublishSpecs(PublishSpec(SlaPolicyArtifact)),
        ctx.object_store,
        SqlTraustUnitOfWork(ctx.database),
    )
    publisher.publish_artifact(
        SlaPolicyArtifact.from_document(yaml.safe_load(SLA_POLICY.read_text()))
    )


def test_a_feed_requirement_names_the_source_and_its_reachability(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    ctx = context(tmp_path, monkeypatch)
    with pytest.raises(PreflightError, match="osv is not an enabled source"):
        ctx.preflight([Requirement(feeds=("osv",))])
    monkeypatch.setattr(
        ctx.feed_sources.get("deps_dev"),
        "check",
        lambda: Readiness(ready=False, detail="could not reach dd.test"),
    )
    with pytest.raises(PreflightError, match="deps_dev is not reachable -- could not reach"):
        ctx.preflight([Requirement(feeds=("deps_dev",))])


def test_a_secret_requirement_names_the_environment_variable(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    ctx = context(tmp_path, monkeypatch)
    monkeypatch.delenv("NVD_API_KEY", raising=False)
    with pytest.raises(PreflightError, match=r"\$NVD_API_KEY is not set"):
        ctx.preflight([Requirement(secrets=("NVD_API_KEY",))])


def test_the_home_audit_is_part_of_preflight(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    ctx = context(tmp_path, monkeypatch, traust_yaml=None, model_registry=False)
    with pytest.raises(PreflightError, match=r"model-registry\.yaml"):
        ctx.preflight([])
    ctx = context(
        tmp_path,
        monkeypatch,
        traust_yaml=COMPLETE.replace("ledger:\n  public_key_path: /keys/ledger.pub\n", ""),
    )
    with pytest.raises(PreflightError, match=r"ledger\.public_key_path unset"):
        ctx.preflight([])


def _config_home(tmp_path: Path, name: str, traust_yaml: str | None) -> Path:
    home = tmp_path / name
    home.mkdir()
    if traust_yaml is not None:
        (home / "traust.yaml").write_text(traust_yaml.format(store=tmp_path / "store"))
    (home / "model-registry.yaml").write_bytes(MODEL_REGISTRY.read_bytes())
    return home


def test_the_home_audit_examines_the_home_the_config_was_loaded_from(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    complete = _config_home(tmp_path, "complete", COMPLETE)
    gapped = _config_home(tmp_path, "gapped", COMPLETE.replace("  workspace: ws\n", ""))
    monkeypatch.setenv(TRAUST_CONFIG_HOME_ENV, str(gapped))
    Context(Config.from_file(complete / "traust.yaml")).preflight([])
    monkeypatch.setenv(TRAUST_CONFIG_HOME_ENV, str(complete))
    with pytest.raises(PreflightError, match=r"locations\.workspace unset"):
        Context(Config.from_file(gapped / "traust.yaml")).preflight([])


def test_a_missing_toolchain_is_one_more_gap_not_an_abort(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.delenv("NVD_API_KEY", raising=False)
    ctx = context(tmp_path, monkeypatch, tools=False)
    with pytest.raises(PreflightError) as caught:
        ctx.preflight([Requirement(tools=("not-a-real-tool",), config=("review",), feeds=("osv",))])
    assert gaps(caught.value) == [
        "- tools: no toolchain config: Context.register_toolchain()",
        "- config: `review` is not set -- set it in traust.yaml (copy traust.example.yaml "
        "to start)",
        "- feeds: osv is not an enabled source -- enable it in the feeds registry "
        "(Context.register_feeds)",
    ]


@pytest.mark.parametrize(
    "source",
    [
        "  osv:\n    tier: live\n    url_template: https://osv.test/v1/query\n"
        "    access: disabled\n",
        "  osv:\n    tier: cached\n    mode: file\n    url: https://osv.test/feed.json\n"
        "    file: osv.json\n    access: disabled\n",
    ],
    ids=["live source", "cached feed"],
)
def test_a_requirement_on_a_disabled_feed_source_fails_naming_the_registry(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, source: str
) -> None:
    ctx = context(tmp_path, monkeypatch, feeds=False)
    ctx.register_feeds(_write(tmp_path, "disabled-feeds.yaml", f"version: 1\nsources:\n{source}"))
    with pytest.raises(PreflightError, match="osv is not an enabled source"):
        ctx.preflight([Requirement(feeds=("osv",))])


@pytest.mark.parametrize(
    "fields",
    [
        {"config": ("storage",)},
        {"facts": ("org-chart",)},
        {"tools": ("gitleaks", "gitleaks")},
        {"secrets": ("",)},
        {"tool": ("gitleaks",)},
        {"secret": ("NVD_API_KEY",)},
    ],
    ids=[
        "unknown config key",
        "unknown fact",
        "duplicate tool",
        "empty secret",
        "typo'd kind tool",
        "typo'd kind secret",
    ],
)
def test_an_unknown_or_empty_requirement_is_rejected(fields: dict[str, tuple[str, ...]]) -> None:
    with pytest.raises(pydantic.ValidationError):
        Requirement(**fields)


def test_a_typoed_requirement_kind_names_the_valid_ones() -> None:
    with pytest.raises(pydantic.ValidationError) as caught:
        Requirement(tools=("gitleaks",), feed=("osv",))
    message = str(caught.value)
    assert "unknown requirement kind(s) ['feed']" in message
    assert "valid kinds: ['config', 'facts', 'feeds', 'secrets', 'tools']" in message


@pytest.fixture
def triage_home(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> dict[str, object]:
    prefix = tmp_path / "ledger"
    monkeypatch.setenv("TEST_VALVE_SALT", "synthetic-test-salt")
    ctx = context(tmp_path, monkeypatch)
    ctx.local_issuer.mint("runner", machine=True)
    return {
        **yaml.safe_load(COMPLETE.replace("{store}", str(tmp_path / "store"))),
        "identity": {"trust_local": True},
        "review": {"valve_salt_env": "TEST_VALVE_SALT"},
        "ledger": {
            "key_path": str(prefix.with_suffix(".key")),
            "public_key_path": str(prefix.with_suffix(".pub")),
            "required": True,
        },
    }


@pytest.fixture
def signing_home(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, triage_home: dict[str, object]
) -> dict[str, object]:
    if not shutil.which("cosign"):
        pytest.skip("cosign is needed for a real signing readiness probe")
    monkeypatch.setenv("COSIGN_PASSWORD", "synthetic-ledger-password")
    subprocess.run(
        ["cosign", "generate-key-pair", "--output-key-prefix", str(tmp_path / "ledger")],
        check=True,
        capture_output=True,
        timeout=30,
    )
    return triage_home


def _load_triage(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, triage_home: dict[str, object]
) -> Context:
    return context(tmp_path, monkeypatch, traust_yaml=yaml.safe_dump(triage_home))


def test_decision_writing_readiness_accepts_a_verified_local_issuer_and_signing_pair(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, signing_home: dict[str, object]
) -> None:
    ctx = _load_triage(tmp_path, monkeypatch, signing_home)
    ctx.preflight([TRIAGE_REQUIREMENT])
    assert not (ctx.config.home / "traust.db").exists()


@pytest.mark.parametrize(
    ("section", "replacement", "message"),
    [
        ("identity", None, "`identity` is not set"),
        ("identity", {}, "identity: no verified issuer"),
        ("ledger", {}, "ledger: set ledger.key_path"),
        ("ledger", {"key_path": "/nonexistent/key"}, "ledger: set ledger.key_path"),
        ("review", {}, "audit-valve salt is missing or blank"),
    ],
)
def test_decision_writing_refuses_each_unready_section(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    triage_home: dict[str, object],
    section: str,
    replacement: dict[str, object] | None,
    message: str,
) -> None:
    if replacement is None:
        del triage_home[section]
    else:
        triage_home[section] = replacement
    with pytest.raises(PreflightError, match=message):
        _load_triage(tmp_path, monkeypatch, triage_home).preflight([TRIAGE_REQUIREMENT])


@pytest.mark.parametrize(
    ("problem", "message"),
    [
        ("no-local-keys", "no usable local JWKS"),
        ("malformed-local-keys", "no usable local JWKS"),
        ("no-salt", "names unset variable TEST_VALVE_SALT"),
        ("empty-salt", "is set but empty"),
        ("blank-salt", "audit-valve salt is missing or blank"),
    ],
)
def test_present_config_does_not_mask_runtime_prerequisite_failures(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    triage_home: dict[str, object],
    problem: str,
    message: str,
) -> None:
    ctx = _load_triage(tmp_path, monkeypatch, triage_home)
    if problem == "no-local-keys":
        ctx.local_jwks.unlink()
    elif problem == "malformed-local-keys":
        ctx.local_jwks.write_text('{"keys": []}')
    elif problem == "no-salt":
        monkeypatch.delenv("TEST_VALVE_SALT")
    elif problem in ("empty-salt", "blank-salt"):
        monkeypatch.setenv("TEST_VALVE_SALT", "" if problem == "empty-salt" else " \t")
    with pytest.raises(PreflightError, match=message):
        ctx.preflight([TRIAGE_REQUIREMENT])


def test_missing_cosign_needs_no_installed_signer(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, triage_home: dict[str, object]
) -> None:
    (tmp_path / "ledger.key").touch()
    (tmp_path / "ledger.pub").touch()
    monkeypatch.setenv("PATH", str(tmp_path))
    with pytest.raises(PreflightError, match="cosign not found on PATH"):
        _load_triage(tmp_path, monkeypatch, triage_home).preflight([TRIAGE_REQUIREMENT])


@pytest.mark.parametrize(
    ("problem", "message"),
    [("bad-password", "cosign could not sign"), ("bad-public-key", "cosign could not verify")],
)
def test_signing_probe_reports_a_bad_password_or_public_key(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    signing_home: dict[str, object],
    problem: str,
    message: str,
) -> None:
    ctx = _load_triage(tmp_path, monkeypatch, signing_home)
    if problem == "bad-password":
        monkeypatch.setenv("COSIGN_PASSWORD", "wrong-test-password")
    elif problem == "bad-public-key":
        (tmp_path / "ledger.pub").write_text("not a public key")
    with pytest.raises(PreflightError, match=message) as exc:
        ctx.preflight([TRIAGE_REQUIREMENT])
    assert "synthetic-ledger-password" not in str(exc.value)
    assert "wrong-test-password" not in str(exc.value)


def test_unusable_identity_does_not_hide_other_decision_writing_gaps(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, triage_home: dict[str, object]
) -> None:
    program = tmp_path / "lookup"
    program.touch(mode=0o600)
    triage_home["identity"] = {
        "issuers": [{"issuer": "example", "jwks_url": "invalid"}],
        "directory_command": [str(program)],
    }
    monkeypatch.delenv("TEST_VALVE_SALT")
    ctx = _load_triage(tmp_path, monkeypatch, triage_home)
    with pytest.raises(PreflightError) as exc:
        ctx.preflight([TRIAGE_REQUIREMENT])
    details = str(exc.value)
    assert "identity.issuers[0]" in details and "jwks_url" in details
    assert "identity.directory_command is not executable" in details
    assert "ledger:" in details and "TEST_VALVE_SALT" in details


def test_nonwriting_requirements_do_not_combine_into_decision_writing_readiness(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    ctx = context(tmp_path, monkeypatch, traust_yaml=COMPLETE + "identity: {}\nreview: {}\n")
    ctx.preflight(Requirement(config=(key,)) for key in TRIAGE_REQUIREMENT.config)


@pytest.mark.parametrize(
    ("installed", "allowed", "message"),
    [
        (False, True, "syft: not found on PATH"),
        (True, False, "add syft to process.allowed_binaries"),
        (True, True, None),
    ],
)
def test_manifest_sbom_requires_syft_installed_and_allowed(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    installed: bool,
    allowed: bool,
    message: str | None,
) -> None:
    traust_yaml = COMPLETE + ("process:\n  allowed_binaries: [syft]\n" if allowed else "")
    ctx = context(tmp_path, monkeypatch, tools=False, traust_yaml=traust_yaml)
    ctx.register_toolchain()
    monkeypatch.setenv("PATH", str(tmp_path))
    if installed:
        pin = ctx.toolchain.pins["syft"]
        syft = _write(tmp_path, "syft", f"#!/bin/sh\nprintf 'syft {pin.expected}\\n'\n")
        syft.chmod(0o755)
    if message is None:
        ctx.preflight([SBOM_REQUIREMENT])
    else:
        with pytest.raises(PreflightError, match=message):
            ctx.preflight([SBOM_REQUIREMENT])
