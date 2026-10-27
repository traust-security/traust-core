"""Checkov output as declared-layer facts: the deterministic half of a cloud-config audit.

The Checkov tool provider (`providers.tools.cloud_config`) runs the scan; every rule about its
output lives here.
"""

from __future__ import annotations

import json
import re
from collections import Counter
from collections.abc import Callable, Iterable, Mapping
from pathlib import PurePosixPath
from typing import Any
from uuid import UUID

from pydantic import Field

from traust_core.v1.errors import ConfigError, ValidationError
from traust_core.v1.models.artifacts import CloudConfigAuditArtifact
from traust_core.v1.models.assessment import ToolName
from traust_core.v1.models.base import Model
from traust_core.v1.models.common import CodeSpan, RepoPath
from traust_core.v1.models.findings import AssessedJudgment, CweId, FindingCandidate, Label
from traust_core.v1.models.integrity import canonical_json, sha256_hex
from traust_core.v1.models.vocabulary import (
    CloudProvider,
    ReviewReason,
    ScannerSeverity,
    Severity,
    Validity,
)

CHECKOV = ToolName("checkov")
# Bump only deliberately: re-verify the license row, then re-baseline one known IaC tree.
CHECKOV_VERSION = "3.3.6"
# checkov 3.3.6's `--framework` choices (checkov_runners + "all"); `secrets` is valid but never
# scanned (gitleaks owns secrets), so restricting to it evaluates nothing.
CHECKOV_FRAMEWORKS = frozenset(
    {
        "ansible",
        "argo_workflows",
        "arm",
        "azure_pipelines",
        "bicep",
        "bitbucket_pipelines",
        "cdk",
        "circleci_pipelines",
        "cloudformation",
        "dockerfile",
        "github_configuration",
        "github_actions",
        "gitlab_configuration",
        "gitlab_ci",
        "bitbucket_configuration",
        "helm",
        "json",
        "yaml",
        "kubernetes",
        "kustomize",
        "openapi",
        "sca_package",
        "sca_image",
        "secrets",
        "serverless",
        "terraform",
        "terraform_json",
        "terraform_plan",
        "sast",
        "sast_python",
        "sast_java",
        "sast_javascript",
        "sast_typescript",
        "sast_golang",
        "3d_policy",
        "all",
    }
)

_PROVIDERS = {
    "CKV_AWS": "aws",
    "CKV2_AWS": "aws",
    "CKV_AZURE": "azure",
    "CKV2_AZURE": "azure",
    "CKV_GCP": "gcp",
    "CKV2_GCP": "gcp",
    "CKV_K8S": "kubernetes",
    "CKV2_K8S": "kubernetes",
    "CKV_DOCKER": "docker",
}
_SEVERITIES = frozenset(s.value for s in ScannerSeverity)
_SKIP_DIRS = frozenset({"vendor", "node_modules", "third_party"})
_KIND_TEMPLATE = re.compile(r'^\s*kind:\s*["\']?Template["\']?\s*$', re.MULTILINE)
_KIND_PIPELINERUN = re.compile(r'^\s*kind:\s*["\']?PipelineRun["\']?\s*$', re.MULTILINE)


def require_checkov(reported: str) -> str:
    """The pinned version, when `checkov --version` reports it; anything else is a hard failure."""
    if CHECKOV_VERSION not in reported:
        found = reported.strip()[:120]
        raise ConfigError(f"checkov version mismatch: pinned {CHECKOV_VERSION}, found: {found}")
    return CHECKOV_VERSION


def provider_of(check_id: str) -> CloudProvider:
    """The roll-up bucket a check belongs to, by its id prefix."""
    return CloudProvider(
        next((p for k, p in _PROVIDERS.items() if check_id.startswith(k)), "other")
    )


class IacInventory(Model):
    """First-party IaC files of the kinds Checkov can leave unassessed without saying so."""

    terraform: int = 0
    bicep: int = 0
    templates: int = 0
    tekton: int = 0

    @classmethod
    def count(
        cls, files: Iterable[PurePosixPath], read: Callable[[PurePosixPath], str]
    ) -> IacInventory:
        """Tally checkout-relative files; `read` is asked only for YAML."""
        tally: Counter[str] = Counter()
        for path in files:
            dirs = path.parts[:-1]
            if any(d in _SKIP_DIRS or (d.startswith(".") and d != ".tekton") for d in dirs):
                continue
            if path.suffix == ".tf":
                tally["terraform"] += 1
            elif path.suffix == ".bicep":
                tally["bicep"] += 1
            elif path.suffix in (".yaml", ".yml"):
                text = read(path)
                if ".tekton" in dirs and _KIND_PIPELINERUN.search(text):
                    tally["tekton"] += 1
                elif _KIND_TEMPLATE.search(text):
                    tally["templates"] += 1
        return cls(**tally)

    def gaps(self, evaluated: Iterable[str], target: str) -> list[str]:
        """IaC present that no framework evaluated: NOT ASSESSED, never clean."""
        frameworks = set(evaluated)
        gaps = []
        if self.terraform and "terraform" not in frameworks:
            gaps.append(
                f"{target}: {self.terraform} Terraform file(s) (*.tf) present but the "
                "terraform framework evaluated zero checks — likely cause: no Checkov policies "
                "for the provider(s) in use (observed classes: rhoas, Cloudflare, IBM Cloud); "
                "these files are NOT ASSESSED, never clean"
            )
        if self.bicep and "bicep" not in frameworks:
            gaps.append(
                f"{target}: {self.bicep} Bicep file(s) present but the bicep framework "
                f"evaluated zero checks — likely cause: weak Bicep parsing in checkov "
                f"{CHECKOV_VERSION} (see SKILL.md known limitations); these files are "
                "NOT ASSESSED, never clean"
            )
        if self.templates:
            gaps.append(
                f"{target}: {self.templates} OpenShift Template file(s) (yaml kind: Template) "
                "present — objects inside templates are not assessed by any Checkov framework "
                "(template unwrapping deliberately not attempted); NOT ASSESSED, never clean"
            )
        if self.tekton:
            gaps.append(
                f"{target}: {self.tekton} .tekton/ PipelineRun file(s) present — not assessed "
                "by any Checkov framework; NOT ASSESSED, never clean"
            )
        return gaps


class CheckovFact(Model):
    """One failed check; `fact_id` is stable across clones and scan-tree workarounds."""

    fact_id: str
    target: str
    framework: str
    provider: CloudProvider
    check_id: str
    title: str | None = None
    scanner_severity: ScannerSeverity
    file_path: str
    file_line_range: tuple[int, ...] | None = None
    resource: str | None = None
    guideline: str | None = None


class CheckovCounts(Model):
    passed: int = 0
    failed: int = 0
    skipped: int = 0
    parsing_errors: int = 0
    frameworks: tuple[str, ...] = ()


class CheckovScan(Model):
    """What the provider observed: Checkov's JSON output and how the scan tree was laid out."""

    target: str
    version: str
    # The scan's stdout first, then the bicep fallback's arm re-scans.
    outputs: tuple[bytes, ...] = ()
    error: str | None = None
    roots: tuple[str, ...] = ()
    aliases: Mapping[str, str] = {}
    notes: Mapping[str, str] = {}
    bicep_recovered: int = 0
    inventory: IacInventory = IacInventory()
    target_head: str | None = None

    def restrict(self, frameworks: frozenset[str]) -> CheckovScan:
        """The scan a `--framework` run makes: only those frameworks' blocks, and the bicep
        fallback only when bicep is in (legacy skipped it otherwise)."""
        if self.error is not None or not self.outputs:
            return self
        main, *fallback = self.outputs
        if (blocks := _blocks(main)) is not None:
            main = json.dumps([b for b in blocks if _framework(b) in frameworks]).encode()
        if "bicep" in frameworks:
            return self.model_copy(update={"outputs": (main, *fallback)})
        notes = {k: v for k, v in self.notes.items() if k != "bicep_transpile_fallback"}
        return self.model_copy(update={"outputs": (main,), "notes": notes, "bicep_recovered": 0})


class CloudConfigFacts(Model):
    """The facts a cloud-config audit cites; a target with gaps is not assessed, never clean."""

    target: str
    checkov_version: str
    target_head: str | None = None
    notes: Mapping[str, str] = {}
    facts: tuple[CheckovFact, ...] = ()
    counts: CheckovCounts = CheckovCounts()
    gaps: tuple[str, ...] = ()
    snapshot_id: str
    scan: CheckovScan | None = Field(default=None, exclude=True, repr=False)

    @classmethod
    def of(cls, scan: CheckovScan) -> CloudConfigFacts:
        version, target = require_checkov(scan.version), scan.target
        if scan.error is not None:
            facts, counts, gaps = [], CheckovCounts(), [f"{target}: {scan.error}"]
        else:
            facts, counts, gaps = _normalize(scan)
            if counts.passed + counts.failed == 0:
                gaps.append(
                    f"{target}: scan evaluated zero checks — no IaC frameworks detected or scan "
                    "failed; treating as not assessed, not clean"
                )
            if counts.parsing_errors:
                recovered = (
                    f" ({scan.bicep_recovered} .bicep of them transpile-recovered via the arm "
                    "framework — see metadata.bicep_transpile_fallback)"
                    if scan.bicep_recovered
                    else ""
                )
                gaps.append(
                    f"{target}: {counts.parsing_errors} file(s) failed to parse — those files "
                    f"are not assessed{recovered}"
                )
            gaps += scan.inventory.gaps(counts.frameworks, target)
        facts.sort(key=lambda f: f.fact_id)
        gaps.sort()
        body = {
            "facts": [f.model_dump(mode="json") for f in facts],
            "counts": counts.model_dump(mode="json"),
            "gaps": gaps,
        }
        return cls(
            target=target,
            checkov_version=version,
            target_head=scan.target_head,
            notes=scan.notes,
            facts=tuple(facts),
            counts=counts,
            gaps=tuple(gaps),
            snapshot_id=sha256_hex(canonical_json(body)),
            scan=scan,
        )

    def restrict(self, frameworks: Iterable[str]) -> CloudConfigFacts:
        """The facts legacy's `--framework` run produced: only those frameworks' facts, counts
        and parse errors, with every gap re-derived (IaC of an excluded framework is a gap)."""
        names = frozenset(frameworks)
        if not names:
            raise ValidationError("a framework filter names at least one checkov framework")
        if unknown := sorted(names - CHECKOV_FRAMEWORKS):
            raise ValidationError(f"unknown checkov framework(s): {', '.join(unknown)}")
        if self.scan is None:
            raise ValidationError(f"{self.target}: these facts carry no scan to restrict")
        return self if "all" in names else CloudConfigFacts.of(self.scan.restrict(names))


def _normalize(scan: CheckovScan) -> tuple[list[CheckovFact], CheckovCounts, list[str]]:
    gaps: list[str] = []
    blocks: list[dict[str, Any]] = []
    for raw in scan.outputs:
        if (parsed := _blocks(raw)) is None:
            gaps.append(f"{scan.target}: unparseable checkov JSON output")
            continue
        blocks += parsed
    totals: Counter[str] = Counter()
    frameworks: set[str] = set()
    facts: dict[str, CheckovFact] = {}
    for block in blocks:
        framework = _framework(block)
        summary = block.get("summary") or {}
        for key in ("passed", "failed", "skipped", "parsing_errors"):
            totals[key] += int(summary.get(key) or 0)
        if summary.get("passed") or summary.get("failed"):
            frameworks.add(framework)
        for check in (block.get("results") or {}).get("failed_checks") or []:
            fact = _fact(scan, framework, check)
            # A module instantiated N times repeats one identity: the first stands, counts keep N.
            facts.setdefault(fact.fact_id, fact)
    counts = CheckovCounts(**totals, frameworks=tuple(sorted(frameworks)))
    return list(facts.values()), counts, gaps


def _blocks(raw: bytes) -> list[dict[str, Any]] | None:
    """One Checkov output's framework blocks (an object or a list of them); None if not JSON."""
    try:
        parsed = json.loads(raw) if raw.strip() else []
    except json.JSONDecodeError:
        return None
    return [b for b in (parsed if isinstance(parsed, list) else [parsed]) if isinstance(b, dict)]


def _framework(block: Mapping[str, Any]) -> str:
    return str(block.get("check_type") or "unknown")


def _fact(scan: CheckovScan, framework: str, check: Mapping[str, Any]) -> CheckovFact:
    check_id = str(check.get("check_id") or "unknown-check")
    path = str(check.get("repo_file_path") or check.get("file_path") or "")
    if root := next((r for r in scan.roots if r and path.startswith(r)), None):
        path = "/" + path[len(root) :].lstrip("/")
    path = scan.aliases.get(path, path)
    resource = str(check.get("resource") or "")
    if alias := next((a for a in scan.aliases if resource.startswith(a)), None):
        resource = scan.aliases[alias] + resource[len(alias) :]
    severity = str(check.get("severity") or "").strip().lower()
    identity = f"{framework}|{check_id}|{path}|{resource}".encode()
    return CheckovFact(
        fact_id="cca-" + sha256_hex(identity)[:12],
        target=scan.target,
        framework=framework,
        provider=provider_of(check_id),
        check_id=check_id,
        title=check.get("check_name"),
        scanner_severity=ScannerSeverity(severity if severity in _SEVERITIES else "unrated"),
        file_path=path,
        file_line_range=check.get("file_line_range"),
        resource=resource or None,
        guideline=check.get("guideline"),
    )


_VALIDITY = {
    "confirmed": Validity.CONFIRMED,
    "suppressed": Validity.FALSE_POSITIVE,
    "needs_review": None,
}


# NEED(contracts: label-taxonomy): control_refs become finding_label rows once contracts closes
# the label taxonomy; until then they stay in the report.
def audit_candidates(doc: CloudConfigAuditArtifact, repository_id: UUID) -> list[FindingCandidate]:
    """Every finding the report states, for intake: a policy check on its resources, with the
    severity Checkov reported (OSS Checkov rates none: `unrated`)."""
    return [
        FindingCandidate(
            label=Label(f.id),
            repository_id=repository_id,
            title=f.title,
            rule=f.check_id,
            policy=True,
            resources=tuple(dict.fromkeys(loc.resource for loc in f.locations if loc.resource)),
            cwes=(CweId(f.cwe),) if f.cwe else (),
            locations=tuple(
                CodeSpan(
                    path=RepoPath(loc.file_path.lstrip("/")),
                    line=loc.file_line_range[0] if loc.file_line_range else None,
                    symbol=loc.resource or None,
                )
                for loc in f.locations
                if loc.file_path
            ),
            reported_severity=ScannerSeverity(f.scanner_severity or "unrated"),
        )
        for f in doc.findings
    ]


def audit_judgments(doc: CloudConfigAuditArtifact) -> list[tuple[Label, AssessedJudgment]]:
    """The report's disposition on each finding it states (by report id): a confirmed finding
    carries the audit's rubric severity only when it re-rates Checkov's, a suppression cites its
    facts, a needs-review asks a person."""
    return [
        (
            Label(f.id),
            AssessedJudgment(
                validity=_VALIDITY[f.status],
                rationale=" ".join(
                    p
                    for p in (
                        f"(facts: {', '.join(f.fact_ids)})" if f.status == "suppressed" else "",
                        (f.rationale or "").strip(),
                    )
                    if p
                )
                or None,
                severity=Severity(f.severity)
                if f.status == "confirmed" and f.severity != (f.scanner_severity or "unrated")
                else None,
                review=ReviewReason.UNDETERMINED_FINDING if f.status == "needs_review" else None,
            ),
        )
        for f in doc.findings
    ]
