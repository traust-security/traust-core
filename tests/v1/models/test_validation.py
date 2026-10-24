from datetime import UTC, date, datetime, timedelta
from pathlib import Path
from uuid import UUID

import pytest
from pydantic import ValidationError as ModelValidationError

from traust_core.v1.errors import ValidationError
from traust_core.v1.models.validation import (
    BrowserTarget,
    ClusterScope,
    OffLimit,
    ValidationAction,
    ValidationActionKind,
    ValidationAttempt,
    ValidationPlan,
    ValidationProbe,
    ValidationScope,
    ValidationTarget,
)
from traust_core.v1.models.vocabulary import (
    ScopeBindingMode,
    ValidationAdapterKind,
    ValidationApprovalMode,
    ValidationTechnique,
    ValidationVerdict,
)

AS_OF = date(2026, 10, 22)
NOW = datetime(2026, 10, 22, tzinfo=UTC)
FINDING_ID = UUID("00000000-0000-4000-8000-000000000001")
PLAN_ID = UUID("00000000-0000-4000-8000-000000000002")
ARTIFACT_ID = UUID("00000000-0000-4000-8000-000000000003")
OTHER_ARTIFACT_ID = UUID("00000000-0000-4000-8000-000000000004")
FIXTURES = Path(__file__).resolve().parents[2] / "fixtures" / "validation"
FORBIDDEN = (FIXTURES / "validator-forbidden.txt").read_text().strip()
RBAC_EMPTY = (FIXTURES / "rbac-empty.txt").read_text().strip()
RBAC_CONCRETE = (FIXTURES / "rbac-concrete.txt").read_text().strip()
K8S = ValidationAction(kind=ValidationActionKind.K8S, verb="get")
TARGET = ValidationTarget(context="lab", namespace="tenant-a")
BROWSER = BrowserTarget(
    victim_origin="https://victim.example",
    attacker_origins=("https://attacker.example",),
    allowed_verbs=frozenset({"navigate", "screenshot"}),
)


@pytest.fixture
def scope() -> ValidationScope:
    return ValidationScope(
        modes=frozenset({ScopeBindingMode.EXPLICIT}),
        clusters=(
            ClusterScope(
                context="lab",
                namespaces=("tenant-*", "openshift-app-*"),
                explicit_namespaces=frozenset({"tenant-*", "openshift-app-*"}),
            ),
        ),
        containers=("app-*",),
        wasm_artifact_ids=frozenset({ARTIFACT_ID}),
    )


def _attempt(
    probes: tuple[ValidationProbe, ...] = (),
    *,
    verdict: ValidationVerdict = ValidationVerdict.REFUTED,
    flag: str | None = None,
    observed_impact: str | None = None,
    install_failed: bool | None = None,
    controls_required: bool = False,
    differential_required: bool = False,
) -> ValidationAttempt:
    return ValidationAttempt(
        plan_id=PLAN_ID,
        verdict=verdict,
        started_at=NOW,
        finished_at=NOW,
        probes=probes,
        soundness_flag=flag,
        observed_impact=observed_impact,
        install_failed=install_failed,
        controls_required=controls_required,
        differential_required=differential_required,
    )


@pytest.mark.parametrize(
    "target,allowed",
    [
        (TARGET, True),
        (ValidationTarget(context="lab", namespace="tenant-b"), True),
        (ValidationTarget(context="lab", namespace="openshift-app-web"), True),
        (ValidationTarget(context="lab", namespace="other"), False),
        (ValidationTarget(context="unknown", namespace="tenant-a"), False),
        (ValidationTarget(context="lab"), False),
    ],
)
def test_kubernetes_context_and_namespace_grants(
    scope: ValidationScope, target: ValidationTarget, allowed: bool
) -> None:
    assert scope.permits(K8S, target, as_of=AS_OF) is allowed


def test_current_context_binding_remains_available() -> None:
    scope = ValidationScope(clusters=(ClusterScope(context="__current__", namespaces=("app",)),))
    assert scope.permits(K8S, ValidationTarget(namespace="app"), as_of=AS_OF)


def test_exact_context_precedes_current_context_binding() -> None:
    scope = ValidationScope(
        clusters=(
            ClusterScope(context="__current__", namespaces=("*",)),
            ClusterScope(context="lab", namespaces=("tenant-b",)),
        )
    )
    assert not scope.permits(K8S, TARGET, as_of=AS_OF)


@pytest.mark.parametrize(
    "namespaces,allowed", [((), False), (("tenant-*",), False), (("*",), True)]
)
def test_cluster_wide_reads_require_a_star(namespaces: tuple[str, ...], allowed: bool) -> None:
    scope = ValidationScope(clusters=(ClusterScope(context="lab", namespaces=namespaces),))
    assert scope.permits(K8S, ValidationTarget(context="lab"), as_of=AS_OF) is allowed


@pytest.mark.parametrize(
    "namespace",
    [
        "kube-system",
        "kube-public",
        "kube-node-lease",
        "default",
        "openshift",
        "openshift-etcd",
        "openshift-config",
        "openshift-ingress",
        "openshift-monitoring",
    ],
)
@pytest.mark.parametrize("mode", [ScopeBindingMode.INLINE, ScopeBindingMode.INFERRED])
def test_control_plane_namespaces_need_explicit_grants(
    namespace: str, mode: ScopeBindingMode
) -> None:
    scope = ValidationScope(
        modes=frozenset({mode}),
        clusters=(ClusterScope(context="lab", namespaces=("*",)),),
    )
    assert not scope.permits(K8S, ValidationTarget(context="lab", namespace=namespace), as_of=AS_OF)


def test_inferred_namespace_cannot_expand_an_explicit_control_plane_grant() -> None:
    scope = ValidationScope(
        modes=frozenset({ScopeBindingMode.EXPLICIT, ScopeBindingMode.INFERRED}),
        clusters=(
            ClusterScope(
                context="lab",
                namespaces=("tenant-a", "openshift-etcd"),
                explicit_namespaces=frozenset({"tenant-a"}),
            ),
        ),
    )
    assert not scope.permits(
        K8S, ValidationTarget(context="lab", namespace="openshift-etcd"), as_of=AS_OF
    )


@pytest.mark.parametrize("verb", ["get", "delete"])
def test_explicit_grant_unlocks_a_control_plane_namespace(verb: str) -> None:
    scope = ValidationScope(
        clusters=(
            ClusterScope(
                context="lab",
                namespaces=("openshift-*",),
                explicit_namespaces=frozenset({"openshift-*"}),
            ),
        )
    )
    assert scope.permits(
        ValidationAction(kind=ValidationActionKind.K8S, verb=verb),
        ValidationTarget(context="lab", namespace="openshift-config"),
        as_of=AS_OF,
    )


@pytest.mark.parametrize("resource", ["nodes", "clusterroles", "crds", "machineconfigpool"])
@pytest.mark.parametrize(
    "verb,explicit,allowed",
    [
        ("get", False, True),
        ("delete", False, False),
        ("delete", True, True),
    ],
)
def test_cluster_control_plane_writes_need_an_explicit_star(
    resource: str, verb: str, explicit: bool, allowed: bool
) -> None:
    scope = ValidationScope(
        clusters=(
            ClusterScope(
                context="lab",
                namespaces=("*",),
                explicit_namespaces=frozenset({"*"}) if explicit else frozenset(),
            ),
        )
    )
    assert (
        scope.permits(
            ValidationAction(kind=ValidationActionKind.K8S, verb=verb),
            ValidationTarget(context="lab", resource=resource),
            as_of=AS_OF,
        )
        is allowed
    )


def test_denied_verb_wins_over_an_explicit_star() -> None:
    scope = ValidationScope(
        clusters=(
            ClusterScope(
                context="lab",
                namespaces=("*",),
                explicit_namespaces=frozenset({"*"}),
                verbs_denied=frozenset({"delete"}),
            ),
        )
    )
    assert not scope.permits(
        ValidationAction(kind=ValidationActionKind.K8S, verb="delete"), TARGET, as_of=AS_OF
    )


@pytest.mark.parametrize(
    "rule",
    [
        OffLimit(namespace="tenant-*"),
        OffLimit(context="lab", verb="get"),
        OffLimit(resource="secrets"),
        OffLimit(name="private-*"),
        OffLimit(image="private/*"),
    ],
)
def test_off_limits_wins_including_unknown_target_fields(
    scope: ValidationScope, rule: OffLimit
) -> None:
    restricted = scope.model_copy(update={"off_limits": (rule,)})
    assert not restricted.permits(K8S, TARGET, as_of=AS_OF)


def test_nonmatching_off_limit_does_not_deny(scope: ValidationScope) -> None:
    restricted = scope.model_copy(update={"off_limits": (OffLimit(namespace="private-*"),)})
    assert restricted.permits(K8S, TARGET, as_of=AS_OF)


@pytest.mark.parametrize("offset,allowed", [(-1, False), (0, True), (1, True)])
def test_expiry_is_inclusive_and_uses_the_supplied_date(
    scope: ValidationScope, offset: int, allowed: bool
) -> None:
    dated = scope.model_copy(update={"expires": AS_OF + timedelta(days=offset)})
    assert dated.permits(K8S, TARGET, as_of=AS_OF) is allowed
    assert dated.expires == AS_OF + timedelta(days=offset)


@pytest.mark.parametrize("expired", [True, False])
def test_expiry_and_off_limits_preempt_browser_matching_errors(expired: bool) -> None:
    scope = ValidationScope(
        browser=(BROWSER,),
        expires=AS_OF - timedelta(days=1) if expired else None,
        off_limits=() if expired else (OffLimit(verb="navigate"),),
    )
    assert not scope.permits(
        ValidationAction(kind=ValidationActionKind.BROWSER, verb="navigate"),
        ValidationTarget(url="https://[invalid"),
        as_of=AS_OF,
    )


@pytest.mark.parametrize("kind", list(ValidationActionKind))
def test_empty_scope_denies_every_operation(kind: ValidationActionKind) -> None:
    assert not ValidationScope().permits(
        ValidationAction(kind=kind, verb="get"), TARGET, as_of=AS_OF
    )


@pytest.mark.parametrize("kind", [ValidationActionKind.K8S, ValidationActionKind.CONTAINER])
@pytest.mark.parametrize(
    "image,allowed",
    [(None, True), ("registry.example/app:v1", True), ("registry.example/other:v1", False)],
)
def test_image_restrictions_apply_to_cluster_and_container_targets(
    scope: ValidationScope, kind: ValidationActionKind, image: str | None, allowed: bool
) -> None:
    restricted = scope.model_copy(update={"images": ("registry.example/app:*",)})
    target = TARGET.model_copy(update={"name": "app-worker", "image": image})
    assert (
        restricted.permits(ValidationAction(kind=kind, verb="get"), target, as_of=AS_OF) is allowed
    )


@pytest.mark.parametrize("name,allowed", [("app-worker", True), ("other", False), (None, True)])
def test_container_name_grants(scope: ValidationScope, name: str | None, allowed: bool) -> None:
    assert (
        scope.permits(
            ValidationAction(kind=ValidationActionKind.CONTAINER, verb="exec"),
            ValidationTarget(name=name),
            as_of=AS_OF,
        )
        is allowed
    )


@pytest.mark.parametrize(
    "artifact_id,allowed", [(ARTIFACT_ID, True), (OTHER_ARTIFACT_ID, False), (None, False)]
)
def test_wasm_scope_uses_resolved_artifact_identity(
    scope: ValidationScope, artifact_id: UUID | None, allowed: bool
) -> None:
    assert (
        scope.permits(
            ValidationAction(kind=ValidationActionKind.WASM, verb="invoke-export"),
            ValidationTarget(artifact_id=artifact_id),
            as_of=AS_OF,
        )
        is allowed
    )


@pytest.mark.parametrize(
    "url,verb,allowed",
    [
        ("https://victim.example/app", "navigate", True),
        ("HTTPS://VICTIM.EXAMPLE/app", "navigate", True),
        ("https://attacker.example/poc", "navigate", True),
        ("https://victim.example.evil.example/app", "navigate", False),
        ("http://victim.example/app", "navigate", False),
        ("https://victim.example:8443/app", "navigate", False),
        ("https://victim.example/app", "xss-inject", False),
        ("not-a-url", "navigate", False),
        (None, "navigate", False),
    ],
)
def test_browser_scope_binds_verbs_to_exact_origins(
    url: str | None, verb: str, allowed: bool
) -> None:
    assert (
        ValidationScope(browser=(BROWSER,)).permits(
            ValidationAction(kind=ValidationActionKind.BROWSER, verb=verb),
            ValidationTarget(url=url),
            as_of=AS_OF,
        )
        is allowed
    )


def test_browser_port_is_part_of_the_origin() -> None:
    browser = BrowserTarget(victim_origin="https://victim.example:8443", allowed_verbs={"navigate"})
    assert browser.matches_url("https://victim.example:8443/path")
    assert not browser.matches_url("https://victim.example/path")


def test_empty_browser_verb_grants_deny_every_action() -> None:
    browser = BrowserTarget(victim_origin="https://victim.example")
    assert not ValidationScope(browser=(browser,)).permits(
        ValidationAction(kind=ValidationActionKind.BROWSER, verb="navigate"),
        ValidationTarget(url="https://victim.example"),
        as_of=AS_OF,
    )


def test_browser_verb_comes_from_the_first_matched_target() -> None:
    denied = BROWSER.model_copy(update={"allowed_verbs": frozenset()})
    assert not ValidationScope(browser=(denied, BROWSER)).permits(
        ValidationAction(kind=ValidationActionKind.BROWSER, verb="navigate"),
        ValidationTarget(url="https://victim.example"),
        as_of=AS_OF,
    )


def test_invalid_browser_grant_does_not_match() -> None:
    assert not BrowserTarget(victim_origin="invalid").matches_url("https://victim.example")


def test_malformed_browser_url_raises_a_contextual_error() -> None:
    with pytest.raises(ValidationError, match="browser validation target URL") as error:
        BROWSER.matches_url("https://[invalid")
    assert isinstance(error.value.__cause__, ValueError)


@pytest.mark.parametrize(
    "mode",
    [
        ScopeBindingMode.INLINE,
        ScopeBindingMode.INFERRED,
        ScopeBindingMode.MIXED,
        ScopeBindingMode.NONE,
    ],
)
@pytest.mark.parametrize(
    "kind,verb,target",
    [
        (ValidationActionKind.CREDENTIAL, "introspect", ValidationTarget(resource="github")),
        (
            ValidationActionKind.INVENTORY,
            "enumerate",
            ValidationTarget(resource="aws_profile", name="stage"),
        ),
    ],
)
def test_credential_and_inventory_grants_require_explicit_binding(
    mode: ScopeBindingMode, kind: ValidationActionKind, verb: str, target: ValidationTarget
) -> None:
    scope = ValidationScope(
        modes=frozenset({mode}),
        credential_probe_classes=frozenset({"github"}),
        inventory_aws_profiles=frozenset({"stage"}),
    )
    assert not scope.permits(ValidationAction(kind=kind, verb=verb), target, as_of=AS_OF)


@pytest.mark.parametrize(
    "verb,resource,allowed",
    [
        ("introspect", "github", True),
        ("introspect", "aws", False),
        ("rotate", "github", False),
        ("introspect", None, False),
    ],
)
def test_credential_scope_checks_class_and_read_only_verb(
    verb: str, resource: str | None, allowed: bool
) -> None:
    scope = ValidationScope(
        modes=frozenset({ScopeBindingMode.EXPLICIT, ScopeBindingMode.INLINE}),
        credential_probe_classes=frozenset({"github"}),
    )
    assert (
        scope.permits(
            ValidationAction(kind=ValidationActionKind.CREDENTIAL, verb=verb),
            ValidationTarget(resource=resource),
            as_of=AS_OF,
        )
        is allowed
    )


@pytest.mark.parametrize(
    "verb,resource,name,allowed",
    [
        ("enumerate", "aws_profile", "stage", True),
        ("enumerate", "aws_profile", "prod", False),
        ("delete", "aws_profile", "stage", False),
        ("enumerate", "cluster_context", "lab", True),
        ("enumerate", "cluster_context", "other", False),
        ("enumerate", "unknown", "stage", False),
        ("enumerate", "aws_profile", None, False),
    ],
)
def test_inventory_scope_checks_resource_name_and_read_only_verb(
    verb: str, resource: str, name: str | None, allowed: bool
) -> None:
    scope = ValidationScope(
        modes=frozenset({ScopeBindingMode.EXPLICIT}),
        inventory_aws_profiles=frozenset({"stage"}),
        inventory_cluster_contexts=frozenset({"lab"}),
    )
    assert (
        scope.permits(
            ValidationAction(kind=ValidationActionKind.INVENTORY, verb=verb),
            ValidationTarget(resource=resource, name=name),
            as_of=AS_OF,
        )
        is allowed
    )


def test_invalid_operation_is_rejected_at_the_boundary() -> None:
    with pytest.raises(ModelValidationError):
        ValidationAction(kind="unknown", verb="get")
    with pytest.raises(ModelValidationError):
        ValidationAction(kind=ValidationActionKind.BROWSER, verb="")


@pytest.mark.parametrize(
    "mode,required",
    [
        (ValidationApprovalMode.INTERACTIVE, True),
        (ValidationApprovalMode.AUTO, False),
        (ValidationApprovalMode.DRY_RUN, False),
    ],
)
def test_approval_requirement_depends_only_on_mode(
    mode: ValidationApprovalMode, required: bool
) -> None:
    plan = ValidationPlan(
        finding_id=FINDING_ID,
        target=TARGET,
        technique=ValidationTechnique.REPLAY,
        adapter=ValidationAdapterKind.K8S,
        approval_mode=mode,
    )
    assert plan.requires_approval() is required


@pytest.mark.parametrize(
    "observed,name",
    [
        (FORBIDDEN, "forbidden"),
        ('secrets is forbidden: User "probe-sa" cannot get resource "secrets"', "forbidden"),
        ('Forbidden: probe User "probe-sa" cannot patch pods', "forbidden"),
        ('User "probe-sa" cannot impersonate subjects', "forbidden"),
        ("Error from server (Unauthorized): Unauthorized", "authentication-failed"),
        (
            "error: You must be logged in to the server (Unauthorized)",
            "authentication-failed",
        ),
        ("the server has asked for the client to provide credentials", "authentication-failed"),
        (
            "Unable to authenticate the request due to an invalid bearer token",
            "authentication-failed",
        ),
        ("bash: openssl: command not found", "command-not-found"),
        ("executable file not found", "command-not-found"),
        ("tool not found in $PATH", "command-not-found"),
        ("error executing jsonpath: unrecognized identifier", "jsonpath-error"),
        ("error parsing jsonpath", "jsonpath-error"),
        ('Error from server (NotFound): deployments.apps "app" not found', "not-found"),
        ("the server doesn't have a resource type", "not-found"),
        ('namespace "tenant-a" does not exist', "does-not-exist"),
        ("curl: (7) Could not connect to server", "could-not-connect"),
        ("Unable to connect to the server", "could-not-connect"),
        ("could not resolve host", "could-not-connect"),
        ("no route to host", "could-not-connect"),
        ("system:serviceaccount:{ns}:{sa}", "unsubstituted-template"),
        ("--as=subject:{identity}", "unsubstituted-template"),
    ],
)
def test_probe_errors_prevent_refutation(observed: str, name: str) -> None:
    probe = ValidationProbe(verdict=ValidationVerdict.REFUTED, verb="raw", observed=observed)
    attempt = _attempt((probe,))
    result = attempt.soundness()
    assert result.verdict == ValidationVerdict.INCONCLUSIVE
    assert result.flag == f"error-signature:{name}"
    assert attempt.verdict == ValidationVerdict.REFUTED


@pytest.mark.parametrize(
    "observed",
    [
        "yes",
        "no",
        "pod/test created",
        '{"paths": ["/apis"]}',
        "HTTP/1.1 200 OK\nvf-http-status:200",
        "vf-http-status:403",
        "403 Forbidden for subject under test",
        "HTTP/1.1 401 Unauthorized",
        "HTTP/1.1 403 Forbidden",
        "401 Unauthorized for subject under test",
        RBAC_CONCRETE,
    ],
)
def test_target_denials_are_not_validator_failures(observed: str) -> None:
    probe = ValidationProbe(verdict=ValidationVerdict.REFUTED, verb="rbac-can-i", observed=observed)
    result = _attempt((probe,)).soundness()
    assert result.verdict == ValidationVerdict.REFUTED
    assert result.flag is None


@pytest.mark.parametrize("verb", ["raw", "rbac-can-i"])
def test_rbac_markers_with_no_concrete_subjects_prevent_refutation(verb: str) -> None:
    probe = ValidationProbe(verdict=ValidationVerdict.REFUTED, verb=verb, observed=RBAC_EMPTY)
    assert _attempt((probe,)).soundness().flag == "rbac-zero-subjects"


def test_error_signature_precedes_rbac_empty_subject_flag() -> None:
    probe = ValidationProbe(
        verdict=ValidationVerdict.REFUTED,
        verb="rbac-can-i",
        observed=FORBIDDEN + "\n" + RBAC_EMPTY,
    )
    assert _attempt((probe,)).soundness().flag == "error-signature:forbidden"


@pytest.mark.parametrize(
    "verdict",
    [
        ValidationVerdict.CONFIRMED,
        ValidationVerdict.INCONCLUSIVE,
        ValidationVerdict.BLOCKED_BY_SCOPE,
        ValidationVerdict.NOT_ATTEMPTED,
    ],
)
def test_other_verdicts_are_not_refutation_gated(verdict: ValidationVerdict) -> None:
    probe = ValidationProbe(verdict=verdict, verb="raw", observed=FORBIDDEN)
    result = _attempt(
        (probe,),
        verdict=verdict,
        install_failed=True,
        controls_required=True,
        differential_required=True,
    ).soundness()
    assert result.verdict == verdict
    assert result.flag is None
    assert probe.refutation_flag() is None


@pytest.mark.parametrize(
    "verdict",
    [ValidationVerdict.REFUTED, ValidationVerdict.INCONCLUSIVE, ValidationVerdict.CONFIRMED],
)
def test_explicit_flags_are_preserved_before_rechecking(verdict: ValidationVerdict) -> None:
    result = _attempt(
        verdict=verdict, flag="producer-specific-flag", install_failed=True
    ).soundness()
    assert result.flag == "producer-specific-flag"
    assert result.verdict == (
        ValidationVerdict.INCONCLUSIVE if verdict == ValidationVerdict.REFUTED else verdict
    )


def test_deployment_failure_precedes_controls_and_transcripts() -> None:
    probe = ValidationProbe(
        verdict=ValidationVerdict.REFUTED,
        verb="raw",
        observed=FORBIDDEN,
        positive_controls=(False,),
    )
    assert _attempt((probe,), install_failed=True).soundness().flag == "target-not-deployed"


@pytest.mark.parametrize(
    "controls,required,flag",
    [
        ((False,), False, "failed-positive-control"),
        ((True, False), True, "failed-positive-control"),
        ((), True, "missing-positive-control"),
        ((), False, None),
        ((True,), True, None),
    ],
)
def test_positive_controls_keep_historical_requirement_semantics(
    controls: tuple[bool, ...], required: bool, flag: str | None
) -> None:
    probe = ValidationProbe(
        verdict=ValidationVerdict.REFUTED,
        verb="raw",
        observed="no",
        positive_controls=controls,
    )
    result = _attempt((probe,), controls_required=required).soundness()
    assert result.flag == flag
    assert result.verdict == (ValidationVerdict.INCONCLUSIVE if flag else ValidationVerdict.REFUTED)


@pytest.mark.parametrize(
    "discriminated,required,verb,flag",
    [
        (False, False, "raw", "non-discriminating-oracle"),
        (False, True, "rbac-can-i", "non-discriminating-oracle"),
        (True, True, "rbac-can-i", None),
        (None, True, "rbac-can-i", "missing-differential-probe"),
        (None, False, "rbac-can-i", None),
        (None, True, "raw", None),
    ],
)
def test_differential_probes_keep_historical_requirement_semantics(
    discriminated: bool | None, required: bool, verb: str, flag: str | None
) -> None:
    probe = ValidationProbe(
        verdict=ValidationVerdict.REFUTED,
        verb=verb,
        observed="no",
        differential_discriminated=discriminated,
    )
    assert _attempt((probe,), differential_required=required).soundness().flag == flag


def test_rbac_transcript_markers_also_require_a_differential() -> None:
    probe = ValidationProbe(verdict=ValidationVerdict.REFUTED, verb="raw", observed=RBAC_CONCRETE)
    assert (
        _attempt((probe,), differential_required=True).soundness().flag
        == "missing-differential-probe"
    )


def test_controls_precede_differential_and_transcript_failures() -> None:
    probe = ValidationProbe(
        verdict=ValidationVerdict.REFUTED,
        verb="raw",
        observed=FORBIDDEN,
        positive_controls=(False,),
        differential_discriminated=False,
    )
    assert _attempt((probe,)).soundness().flag == "failed-positive-control"


def test_differential_failure_precedes_transcript_failure() -> None:
    probe = ValidationProbe(
        verdict=ValidationVerdict.REFUTED,
        verb="raw",
        observed=FORBIDDEN,
        differential_discriminated=False,
    )
    assert _attempt((probe,)).soundness().flag == "non-discriminating-oracle"


def test_checks_consider_only_refuted_probes() -> None:
    probe = ValidationProbe(
        verdict=ValidationVerdict.CONFIRMED,
        verb="raw",
        observed=FORBIDDEN,
        positive_controls=(False,),
        differential_discriminated=False,
    )
    assert _attempt((probe,)).soundness().flag is None


@pytest.mark.parametrize(
    "second_observed,flag", [(RBAC_CONCRETE, None), (RBAC_EMPTY, "error-signature:forbidden")]
)
def test_mixed_and_all_unsound_probe_rollups_preserve_legacy_behavior(
    second_observed: str, flag: str | None
) -> None:
    probes = (
        ValidationProbe(verdict=ValidationVerdict.REFUTED, verb="raw", observed=FORBIDDEN),
        ValidationProbe(
            verdict=ValidationVerdict.REFUTED, verb="rbac-can-i", observed=second_observed
        ),
    )
    assert _attempt(probes).soundness().flag == flag


def test_one_failed_differential_invalidates_other_discriminating_probes() -> None:
    probes = tuple(
        ValidationProbe(
            verdict=ValidationVerdict.REFUTED,
            verb="raw",
            observed="no",
            differential_discriminated=discriminated,
        )
        for discriminated in (True, False)
    )
    assert _attempt(probes).soundness().flag == "non-discriminating-oracle"


def test_controls_and_differentials_are_aggregated_across_refuted_probes() -> None:
    probes = (
        ValidationProbe(
            verdict=ValidationVerdict.REFUTED, verb="rbac-can-i", observed=RBAC_CONCRETE
        ),
        ValidationProbe(
            verdict=ValidationVerdict.REFUTED,
            verb="raw",
            observed="no",
            positive_controls=(True,),
            differential_discriminated=True,
        ),
    )
    assert (
        _attempt(probes, controls_required=True, differential_required=True).soundness().flag
        is None
    )


def test_historical_observed_impact_is_checked_without_probe_records() -> None:
    assert _attempt(observed_impact=FORBIDDEN).soundness().flag == "error-signature:forbidden"


def test_observed_impact_does_not_replace_recorded_probe_evidence() -> None:
    probe = ValidationProbe(verdict=ValidationVerdict.REFUTED, verb="raw", observed="no")
    assert _attempt((probe,), observed_impact=FORBIDDEN).soundness().flag is None


def test_missing_historical_observations_do_not_invent_a_failure() -> None:
    result = _attempt().soundness()
    assert result.verdict == ValidationVerdict.REFUTED
    assert result.flag is None


LEGACY_SCOPE = ValidationScope(
    expires=date(2026, 12, 31),
    modes=frozenset({ScopeBindingMode.EXPLICIT}),
    clusters=(
        ClusterScope(
            context="lab",
            namespaces=("app-*", "openshift-etcd"),
            verbs_denied=frozenset({"delete"}),
            explicit_namespaces=frozenset({"openshift-etcd"}),
        ),
    ),
    off_limits=(OffLimit(namespace="app-secrets", verb="exec"),),
    containers=("web-*",),
    images=("registry.example.com/*",),
    wasm_artifact_ids=frozenset({ARTIFACT_ID}),
    credential_probe_classes=frozenset({"oidc"}),
    inventory_aws_profiles=frozenset({"audit"}),
    inventory_cluster_contexts=frozenset({"lab"}),
)
EXEC = ValidationAction(kind=ValidationActionKind.K8S, verb="exec")


def _action(kind: ValidationActionKind, verb: str) -> ValidationAction:
    return ValidationAction(kind=kind, verb=verb)


# Reasons are traust-engine 60d2e7e validation/scope.py `is_in_scope` texts; the browser ones are
# core's own (legacy had no browser adapter).
@pytest.mark.parametrize(
    "action,target,reason",
    [
        (EXEC, ValidationTarget(context="lab", namespace="app-a"), "ok"),
        (
            EXEC,
            ValidationTarget(context="lab", namespace="app-secrets"),
            "off_limits: OffLimit(context=None, namespace='app-secrets', resource=None, "
            "verb='exec', name=None, image=None)",
        ),
        (
            EXEC,
            ValidationTarget(context="lab", namespace="openshift-kube-apiserver"),
            "control-plane namespace 'openshift-kube-apiserver' not explicitly authorized "
            "in targets.yaml",
        ),
        (
            EXEC,
            ValidationTarget(context="other", namespace="openshift-etcd"),
            "control-plane namespace 'openshift-etcd' not explicitly authorized in targets.yaml",
        ),
        (EXEC, ValidationTarget(context="lab", namespace="openshift-etcd"), "ok"),
        (
            _action(ValidationActionKind.K8S, "delete"),
            ValidationTarget(context="lab", resource="nodes"),
            "cluster-scoped control-plane resource 'nodes' (verb 'delete') not explicitly "
            "authorized in targets.yaml",
        ),
        (
            EXEC,
            ValidationTarget(context="other", namespace="app-a"),
            "context 'other' not in scope",
        ),
        (
            _action(ValidationActionKind.K8S, "delete"),
            ValidationTarget(context="lab", namespace="app-a"),
            "verb 'delete' denied for context 'lab'",
        ),
        (
            EXEC,
            ValidationTarget(context="lab", namespace="tenant"),
            "namespace 'tenant' not in scope for context 'lab'",
        ),
        (
            EXEC,
            ValidationTarget(context="lab", namespace="app-a", image="quay.io/x"),
            "image 'quay.io/x' not in scope",
        ),
        (
            _action(ValidationActionKind.CONTAINER, "run"),
            ValidationTarget(name="db"),
            "container 'db' not in scope",
        ),
        (
            _action(ValidationActionKind.WASM, "run"),
            ValidationTarget(artifact_id=OTHER_ARTIFACT_ID),
            f"wasm artifact '{OTHER_ARTIFACT_ID}' not in scope",
        ),
        (
            _action(ValidationActionKind.CREDENTIAL, "use"),
            ValidationTarget(resource="oidc"),
            "credential verb 'use' denied — probes are read-only introspection only",
        ),
        (
            _action(ValidationActionKind.CREDENTIAL, "introspect"),
            ValidationTarget(resource="saml"),
            "credential class 'saml' not in targets.yaml credential_probes.classes",
        ),
        (
            _action(ValidationActionKind.INVENTORY, "write"),
            ValidationTarget(resource="aws_profile", name="audit"),
            "inventory verb 'write' denied — read-only enumeration only",
        ),
        (
            _action(ValidationActionKind.INVENTORY, "enumerate"),
            ValidationTarget(resource="aws_profile", name="prod"),
            "aws profile 'prod' not in targets.yaml cloud_inventory.aws_profiles",
        ),
        (
            _action(ValidationActionKind.INVENTORY, "enumerate"),
            ValidationTarget(resource="cluster_context", name="prod"),
            "context 'prod' not in targets.yaml cloud_inventory.cluster_contexts",
        ),
        (
            _action(ValidationActionKind.INVENTORY, "enumerate"),
            ValidationTarget(resource="gcp_project", name="x"),
            "unknown inventory resource 'gcp_project'",
        ),
        (
            _action(ValidationActionKind.BROWSER, "navigate"),
            ValidationTarget(),
            "browser target has no url",
        ),
    ],
)
def test_a_scope_decision_names_the_rule_that_denied_it(
    action: ValidationAction, target: ValidationTarget, reason: str
) -> None:
    decision = LEGACY_SCOPE.decide(action, target, as_of=AS_OF)
    assert decision.reason == reason
    assert decision.allowed is (reason == "ok")
    assert LEGACY_SCOPE.permits(action, target, as_of=AS_OF) is decision.allowed


@pytest.mark.parametrize(
    "scope,action,target,reason",
    [
        (
            LEGACY_SCOPE,
            EXEC,
            ValidationTarget(context="lab", namespace="app-a"),
            "engagement expired 2026-12-31",
        ),
        (
            ValidationScope(),
            _action(ValidationActionKind.CONTAINER, "run"),
            ValidationTarget(name="web-1"),
            "no containers in scope",
        ),
        (
            ValidationScope(),
            _action(ValidationActionKind.WASM, "run"),
            ValidationTarget(artifact_id=ARTIFACT_ID),
            "no wasm artifacts in scope",
        ),
        (
            ValidationScope(credential_probe_classes=frozenset({"oidc"})),
            _action(ValidationActionKind.CREDENTIAL, "introspect"),
            ValidationTarget(resource="oidc"),
            "credential probes require a mode-1 targets.yaml (explicit scope) — inline/inferred "
            "scope cannot unlock them",
        ),
        (
            ValidationScope(inventory_aws_profiles=frozenset({"audit"})),
            _action(ValidationActionKind.INVENTORY, "enumerate"),
            ValidationTarget(resource="aws_profile", name="audit"),
            "cloud inventory requires a mode-1 targets.yaml (explicit scope)",
        ),
        (
            ValidationScope(browser=(BROWSER,)),
            _action(ValidationActionKind.BROWSER, "navigate"),
            ValidationTarget(url="https://elsewhere.example/x"),
            "origin of 'https://elsewhere.example/x' not in scope",
        ),
        (
            ValidationScope(browser=(BROWSER,)),
            _action(ValidationActionKind.BROWSER, "submit"),
            ValidationTarget(url="https://victim.example/login"),
            "browser verb 'submit' not allowed for 'https://victim.example'",
        ),
    ],
)
def test_scope_denials_outside_the_cluster_rules(
    scope: ValidationScope, action: ValidationAction, target: ValidationTarget, reason: str
) -> None:
    as_of = date(2027, 1, 1) if scope.expires else AS_OF
    assert scope.decide(action, target, as_of=as_of).reason == reason
    assert not scope.permits(action, target, as_of=as_of)
