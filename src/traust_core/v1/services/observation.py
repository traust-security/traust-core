"""Forge measurement: observe a repository, classify what changed.

Pure machinery behind PortfolioService.record_forge_facts - no persistence here.
"""

from __future__ import annotations

import hashlib
import logging
import re
from collections.abc import Callable, Mapping, Sequence
from datetime import date, datetime
from typing import Any, TypeVar

from traust_core.v1.errors import ConfigError, IntegrityError, TraustError, ValidationError
from traust_core.v1.models.artifacts import AdapterResultArtifact
from traust_core.v1.models.assessment import ToolName
from traust_core.v1.models.observation import (
    SENSITIVE_RX,
    ChangeMetrics,
    ComparisonStatus,
    ForgeFacts,
    ObservationTarget,
    SeenHead,
    is_deps_manifest,
    is_first_party,
)
from traust_core.v1.models.values import GitSha, HttpsRepoUrl
from traust_core.v1.providers.base import ProviderRegistry, Result
from traust_core.v1.providers.sources import (
    ChangedFile,
    Comparison,
    Quota,
    RepoInfo,
    RepoTree,
    SourceError,
    SourceProvider,
)
from traust_core.v1.providers.tools import ToolProvider, acquire_over_text

log = logging.getLogger(__name__)

T = TypeVar("T")


TM_SURFACE_RX = re.compile(
    r"(^|/)(cmd|api|apis|handler|handlers|route|routes|controller|"
    r"controllers|webhook|webhooks|middleware|admission|server|"
    r"endpoints?)(/|$)"
    r"|(^|/)main\.(go|py|rs|java|ts|js)$"
    r"|(^|/)(openapi|swagger)[^/]*\.(ya?ml|json)$"
    r"|\.proto$",
    re.I,
)

BAN_STREAK_THRESHOLD = 50
# The tree is counted (one more forge call) only when this many first-party files changed: the
# legacy router saw a diff refused at 5 of 10 files, so the floor sits low.
PREROUTE_MIN_FILES = 3
# The router's tripwire scans the change's patch with the secret scanner registered by this name,
# and fetches a GitHub patch only while this many forge calls stay in reserve.
GITLEAKS = ToolName("gitleaks")
TRIPWIRE_QUOTA_RESERVE = 100
# A never-audited repository is observed too (its head feeds the manifest SBOM sweep); it has
# nothing to compare against, so its status stays never-audited.
OBSERVED = frozenset({ComparisonStatus.OK, ComparisonStatus.NEVER_AUDITED})

IAC_RX = re.compile(
    r"\.tf$|\.tfvars$|\.tf\.json$"
    r"|(^|/)(cloudformation|cfn)/[^ ]*\.(ya?ml|json)$"
    r"|\.bicep$|(^|/)azuredeploy[^/]*\.json$"
)


class BanBreaker:
    def __init__(self, threshold: int = BAN_STREAK_THRESHOLD) -> None:
        self.threshold, self.streak, self.tripped = threshold, 0, False

    def record(self, ok: bool) -> None:
        self.streak = 0 if ok else self.streak + 1
        if self.streak >= self.threshold:
            self.tripped = True


def change_metrics(files: Sequence[ChangedFile]) -> ChangeMetrics:
    changed, sensitive_lines, first_party, iac, threat = 0, 0, 0, 0, 0
    sensitive, deps_only = False, bool(files)
    for file in files:
        path = file.filename
        if not is_deps_manifest(path):
            deps_only = False
        if not is_first_party(path):
            continue
        changed += file.changes
        first_party += 1
        if SENSITIVE_RX.search(path):
            sensitive = True
            sensitive_lines += file.changes
        iac += bool(IAC_RX.search(path))
        threat += bool(TM_SURFACE_RX.search(path))
    return ChangeMetrics(
        changed_lines=changed,
        sensitive_changed=sensitive,
        sensitive_lines=sensitive_lines,
        deps_only=deps_only,
        first_party_files=first_party,
        iac_files=iac,
        threat_model_files=threat,
    )


def observation_url(raw: str | None, hosts: Mapping[str, str]) -> HttpsRepoUrl | None:
    if raw is None:
        return None
    try:
        typed = HttpsRepoUrl.parse(raw, hosts)
    except ValueError:
        return None
    if hosts[typed.host] == "github":
        return HttpsRepoUrl(typed.host, "/".join(typed.path.split("/")[:2]).lower())
    return typed


T = TypeVar("T")


def _fetch(fetch: Callable[[], Result[T]], expected: type[T]) -> T:
    try:
        data = fetch().data
        if not isinstance(data, expected):
            raise TypeError("unexpected forge result type")
        return data
    except SourceError:
        raise
    except OSError as exc:
        raise SourceError(str(exc), ComparisonStatus.UNREACHABLE) from exc
    except (AttributeError, KeyError, TypeError, ValueError) as exc:
        raise SourceError(
            f"malformed forge response ({type(exc).__name__})", ComparisonStatus.ERROR
        ) from exc


def observe_forge_facts(
    target: ObservationTarget,
    sources: SourceProvider | None,
    now: datetime,
    *,
    hosts: Mapping[str, str],
    network: bool = True,
    breaker: BanBreaker | None = None,
    quota_deferred: bool | None = None,
    seen: SeenHead | None = None,
    tools: ProviderRegistry[ToolProvider[Any]] | None = None,
) -> ForgeFacts:
    """`seen` spares the head lookup when the forge reports no push since it."""
    if now.tzinfo is None or now.utcoffset() is None:
        raise ValidationError("observation time must include a timezone")
    repo = observation_url(target.repo_url, hosts)
    status = ComparisonStatus.OK
    if target.repo_url is None:
        status = ComparisonStatus.NO_REPO_URL
    elif repo is None:
        status = ComparisonStatus.UNSUPPORTED_HOST
    elif not target.has_audit:
        status = ComparisonStatus.NEVER_AUDITED
    elif not network:
        status = ComparisonStatus.NETWORK_SKIPPED
    facts = ForgeFacts(
        repository_id=target.repository_id,
        repo=repo,
        repo_url=target.repo_url,
        audited_sha=target.pinned_sha,
        audit_date=target.audit_date,
        has_audit=target.has_audit,
        status=status,
        observed_at=now,
    )
    if status not in OBSERVED or not network:
        return facts
    if sources is None or repo is None:
        raise ConfigError("repository observation requires a source provider")
    github = hosts[repo.host] == "github"
    breaker = breaker if breaker is not None else BanBreaker()
    if github and breaker.tripped:
        return facts.model_copy(
            update={
                "status": ComparisonStatus.BAN_SUSPECTED,
                "error": "skipped: consecutive-error streak suggests a GitHub secondary ban",
            }
        )
    try:
        info = _fetch(lambda: sources.info(repo), RepoInfo)
        if info.repo != repo:
            raise SourceError(
                "forge response identifies a different repository", ComparisonStatus.ERROR
            )
        branch = info.default_branch
        head = None
        if seen is not None and (seen.branch, seen.pushed_at) == (branch, info.pushed_at):
            head = seen.head
        elif branch:
            head = str(_fetch(lambda: sources.head(repo, branch), GitSha))
    except SourceError as exc:
        if github:
            breaker.record(False)
        return facts.model_copy(update={"status": exc.observation_status, "error": str(exc)})
    if github:
        breaker.record(True)
    facts = facts.model_copy(
        update={
            key: getattr(info, key)
            for key in ("pushed_at", "archived", "default_branch", "visibility", "fork", "parent")
        }
        | {"head": head}
    )
    pushed, audited = parse_audit_date(info.pushed_at), parse_audit_date(target.audit_date)
    if status == ComparisonStatus.NEVER_AUDITED or not (pushed and audited and pushed >= audited):
        return facts
    if not target.pinned_sha:
        return facts.model_copy(update={"status": ComparisonStatus.NO_PINNED_SHA})
    remaining = None
    try:
        deferred = quota_deferred
        if deferred is None:
            quota = _fetch(lambda: sources.quota(repo), Quota) if github else Quota(remaining=None)
            remaining = quota.remaining
            deferred = remaining is not None and remaining <= 0
        if deferred:
            return facts.model_copy(update={"status": ComparisonStatus.QUOTA_DEFERRED})
        compared = _fetch(
            lambda: sources.compare(repo, target.pinned_sha, info.default_branch or "HEAD"),
            Comparison,
        )
    except SourceError as exc:
        return facts.model_copy(update={"status": exc.observation_status, "error": str(exc)})
    metrics = change_metrics(compared.files)
    tree_files = None
    if github and not compared.truncated and metrics.first_party_files >= PREROUTE_MIN_FILES:
        tree_files = _first_party_tree(sources, repo, head or info.default_branch or "HEAD")
    hits = None
    if metrics.changed_lines:
        baseline = target.pinned_sha
        hits = _secret_hits(
            repo,
            tools,
            lambda: _patch(sources, repo, baseline, remaining) if github else compared.patch,
        )
    return facts.model_copy(
        update=dict(
            ahead_by=compared.ahead_by,
            compare_truncated=compared.truncated,
            **metrics.model_dump(),
            tree_first_party_files=tree_files,
            secret_hits=hits,
        )
    )


def _patch(
    sources: SourceProvider, repo: HttpsRepoUrl, baseline: str, remaining: int | None
) -> str:
    # The compare already spent one of the calls the quota read counted.
    if remaining is not None and remaining - 1 <= TRIPWIRE_QUOTA_RESERVE:
        raise SourceError(
            f"{remaining - 1} forge calls left, inside the reserve of {TRIPWIRE_QUOTA_RESERVE}",
            ComparisonStatus.QUOTA_DEFERRED,
        )
    return _fetch(lambda: sources.compare_patch(repo, baseline), str)


def _secret_hits(
    repo: HttpsRepoUrl,
    tools: ProviderRegistry[ToolProvider[Any]] | None,
    patch: Callable[[], str | None],
) -> int | None:
    """Secret-scanner hits in the change's patch; None, with the reason logged, when it wasn't
    scanned, which never escalates (as the legacy tripwire)."""
    stage = "registration"
    try:
        if tools is None or GITLEAKS not in tools.names():
            raise ConfigError(f"no {GITLEAKS} tool registered")
        scanner = tools.get(GITLEAKS)
        stage = "readiness"
        if not (ready := scanner.check()).ready:
            raise ConfigError(f"{GITLEAKS} not ready: {ready.detail}")
        stage = "patch"
        if not (text := patch()):
            raise ValidationError("the forge returned no patch")
        stage = "scan"
        return _findings(acquire_over_text(scanner, "change.patch", text).data)
    except (TraustError, OSError) as exc:
        log.warning(
            "secrets not scanned repo_hash=%s stage=%s error_type=%s",
            _repo_hash(repo),
            stage,
            type(exc).__name__,
        )
        return None


def _findings(data: object) -> int:
    if not isinstance(data, AdapterResultArtifact):
        # traust-engine's scanners return traust-contracts' AdapterResult model.
        to_dict = getattr(data, "to_dict", None)
        if not callable(to_dict):
            raise IntegrityError(f"{GITLEAKS} returned {type(data).__name__}, not adapter results")
        data = AdapterResultArtifact.from_document(to_dict())
    return len(data.findings)


def _first_party_tree(sources: SourceProvider, repo: HttpsRepoUrl, ref: str) -> int | None:
    """First-party files in the tree; None when the forge truncated it or the listing failed,
    since the pre-route only steers and the diff resolver still refuses at dispatch."""
    try:
        tree = _fetch(lambda: sources.tree(repo, ref), RepoTree)
    except SourceError as exc:
        log.warning(
            "tree not counted repo_hash=%s error_type=%s", _repo_hash(repo), type(exc).__name__
        )
        return None
    return None if tree.truncated else sum(map(is_first_party, tree.paths))


def _repo_hash(repo: HttpsRepoUrl) -> str:
    return hashlib.sha256(str(repo).encode()).hexdigest()[:16]


def parse_audit_date(value: str | None) -> date | None:
    if not value:
        return None
    try:
        return date.fromisoformat(value.strip()[:10])
    except ValueError:
        return None
