"""Below-range applicability: installed versions an advisory's stated ranges leave out, and the
facts a reviewer needs to judge them (the fix patch, the installed source, hunk presence).

Facts only: nothing here decides whether a version is affected; review of the packet does.
"""

from __future__ import annotations

import email.utils
import re
import urllib.parse
from collections.abc import Sequence
from datetime import UTC, datetime
from enum import StrEnum
from uuid import UUID

from traust_core.v1.models.base import Model
from traust_core.v1.models.dependencies import (
    AdvisoryIdentifier,
    AdvisoryRecord,
    AffectedPackage,
    Version,
    version_key,
)
from traust_core.v1.models.vocabulary import Ecosystem

MAX_PATCHES = 6  # a fix often has one commit per release branch
MAX_DETAILS = 6000
_TEST_PATH = re.compile(
    r"(^|/)(tests?|__tests__|spec|testdata|fixtures?)/|_test\.go$|(^|/)test_[^/]*\.py$|"
    r"[^/]*_test\.py$|\.test\.|\.spec\.|Test\.java$"
)
_COMMIT_OR_PR = re.compile(r"/(?:-/)?commit/[0-9a-f]{7,40}|/pull/\d+|/merge_requests/\d+")
# A release or version-bump subject, after an optional "[branch] " tag and an optional
# conventional-commit type ("chore:", "build!:"). "Release" and "bump" count only when a version
# (or the word "version") follows at most two words later, so "Release the lock" and "bump lodash
# from 4.17.20 to 4.17.21" are not releases. A `(release)` scope always is.
_RELEASE_SUBJECT = re.compile(
    r"^(?:\[[^\]]*\]\s*)?"
    r"(?:[a-z]+\(release\)!?:|(?:[a-z]+(?:\([^)]*\))?!?:\s*)?"
    r"(?:bump(?:ed|s)?\s+(?:the\s+)?version\b|bump(?:ed|s)?\s+(?:to\s+|for\s+)?v?\d"
    r"|(?:prepare|preparing|cut|cutting)?\s*(?:for\s+)?(?:the\s+)?release[sd]?"
    r"(?:\s+(?:of\s+|for\s+)?(?:[a-z][\w.-]*\s+){0,2}v?\d|\s*$)"
    # "Version Packages" is the changesets release bot's subject.
    r"|version\s+bump|version\s+packages(?:\s+\(#\d+\))?\s*$|v?\d+\.\d+(?:\.\d+)*(?:\s|$)))",
    re.IGNORECASE,
)
# Version, packaging, changelog and docs files; not Gemfile.lock or .csproj, which a
# dependency-bump fix changes alone.
_RELEASE_FILES = re.compile(
    r"(^|/)(__init__\.py|_version\.py|version\.py|setup\.(py|cfg)|pyproject\.toml|package\.json|"
    r"go\.mod|go\.sum|VERSION|CHANGE(LOG|S)[^/]*|HISTORY[^/]*|NEWS[^/]*|[^/]*\.md|[^/]*\.rst|"
    r"version\.rb|[^/]*\.gemspec|[^/]*\.nuspec)$"
    r"|(^|/)docs?/",
    re.IGNORECASE,
)


class CandidateKind(StrEnum):
    BELOW_RANGE = "below_range"  # under every span's explicit start
    GAP = "gap"  # after a span left without a fix, before the next span's start


class GapReason(StrEnum):
    NUGET_ID_UNRESOLVED = "nuget_id_unresolved"
    OSV_UNANSWERED = "osv_unanswered"
    ADVISORY_UNREADABLE = "advisory_unreadable"
    OVER_MAX_CANDIDATES = "over_max_candidates"
    SOURCE_UNAVAILABLE = "source_unavailable"
    NO_USABLE_FIX_PATCH = "no_usable_fix_patch"


class StatedGap(Model):
    """Where an installed version sits outside an advisory's stated spans."""

    kind: CandidateKind
    stated_start: Version  # the lowest explicit `introduced`, or the next span's start for a gap
    major_distance: int | None


class Candidate(Model):
    """One (installed version, advisory) pair the stated ranges leave out."""

    ecosystem: Ecosystem
    package: str
    version: Version
    advisory: AdvisoryIdentifier
    kind: CandidateKind
    stated_start: Version
    major_distance: int | None
    aliases: tuple[AdvisoryIdentifier, ...] = ()

    @property
    def case(self) -> str:
        raw = f"{self.package}@{self.version}--{self.advisory}"
        return re.sub(r"[^A-Za-z0-9._@-]+", "_", raw)[:180]


class Hunk(Model):
    removed: tuple[str, ...] = ()
    added: tuple[str, ...] = ()


class FileChange(Model):
    path: str
    hunks: tuple[Hunk, ...] = ()


class PatchCommit(Model):
    sha: str
    subject: str
    message: str
    files: tuple[FileChange, ...] = ()

    @property
    def authored_at(self) -> datetime | None:
        """The author date from the format-patch `Date:` header."""
        m = re.search(r"(?m)^Date: (.+)$", self.message)
        if not m:
            return None
        try:
            d = email.utils.parsedate_to_datetime(m.group(1).strip())
        except (TypeError, ValueError):
            return None
        return d if d.tzinfo else d.replace(tzinfo=UTC)


class CommitRef(Model):
    sha: str
    subject: str


class FixAttempt(Model):
    """One linked patch and how it scored; `error` when it couldn't be read."""

    url: str
    rank: int
    error: str | None = None
    commits: tuple[CommitRef, ...] = ()
    files: int | None = None
    files_in_installed_tree: int | None = None
    names_advisory: bool | None = None
    only_adds_code: bool | None = None
    release_commit: bool | None = None
    commit_date: str | None = None


class FixedRelease(Model):
    version: Version
    published: str | None  # None: the registry doesn't publish it, or didn't answer


class FixChoice(Model):
    chosen: FixAttempt
    alternatives: tuple[FixAttempt, ...]
    fixed_releases: tuple[FixedRelease, ...]


class DeclaredSource(Model):
    """The repository and commit a NuGet nuspec says the package was built from: its claim."""

    nuspec: str
    repository: str
    commit: str


class InstalledSource(Model):
    url: str
    sha256: str
    files: int
    root: str  # relative to the working directory
    declared_by: DeclaredSource | None = None


class HunkPresence(Model):
    removed_lines: int
    removed_present: int
    added_lines: int
    added_present: int


class FilePresence(Model):
    patch_path: str
    installed_path: str | None
    hunks: tuple[HunkPresence, ...] = ()


class DependencySource(Model):
    """A direct dependency a file the fix touches imports, and where its source was read."""

    package: str
    version: Version
    imported_by: tuple[str, ...]
    url: str
    sha256: str
    files: int
    root: str


class DependencyGap(Model):
    reason: str
    package: str | None = None
    version: Version | None = None


class AdvisoryExcerpt(Model):
    identifier: AdvisoryIdentifier
    aliases: tuple[AdvisoryIdentifier, ...]
    summary: str
    details: str
    affected: AffectedPackage


class Packet(Model):
    """The facts for one candidate; `patch` is the chosen fix's text."""

    case: str
    candidate: Candidate
    advisory: AdvisoryExcerpt
    fix: FixChoice
    installed_source: InstalledSource
    hunk_presence: tuple[FilePresence, ...]
    dependency_sources: tuple[DependencySource, ...] = ()
    dependency_gaps: tuple[DependencyGap, ...] = ()
    patch: str


class CoverageGap(Model):
    """A candidate (or a lookup) that couldn't be checked, and why: never clean."""

    reason: GapReason
    case: str | None = None
    ecosystem: Ecosystem | None = None
    package: str | None = None
    version: Version | None = None
    detail: str | None = None
    tried: tuple[FixAttempt, ...] = ()


class BelowRangeStatus(StrEnum):
    COMPLETE = "complete"
    DEGRADED = "degraded"  # some packages unanswered or some advisories unreadable


class BelowRangeInput(Model):
    """One commit's below-range packets and coverage gaps: every candidate is one or the other."""

    repository_ref_id: UUID
    installed_exact: int
    skipped_installs: dict[str, int]
    candidates: int
    packets: tuple[Packet, ...]
    coverage_gaps: tuple[CoverageGap, ...]
    status: BelowRangeStatus


class BelowRangeVerdict(StrEnum):
    APPLICABLE = "applicable"
    NOT_APPLICABLE = "not_applicable"
    UNDETERMINED = "undetermined"


class BelowRangeScan(Model):
    """The recorded packets of one commit, and the impact assessment holding them."""

    assessment_id: UUID
    artifact_id: UUID
    packets: BelowRangeInput


class BelowRangeOutcome(Model):
    """A recorded review: each `applicable` case's finding; the rest stay in the document."""

    assessment_id: UUID
    artifact_id: UUID
    packets_assessment_id: UUID
    findings: dict[str, UUID]
    not_applicable: tuple[str, ...]
    undetermined: tuple[str, ...]
    coverage_gaps: int


def stated_gap(affected: AffectedPackage, version: Version) -> StatedGap | None:
    """Where `version` sits outside the stated spans, or None: affected as stated (a span or the
    `versions` list), above every fix, no spans, or a version or bound that can't be ordered."""
    eco = affected.ecosystem
    have = version_key(version, eco)
    if version in affected.versions or not affected.spans or have is None:
        return None
    if any(s.contains(have, eco) for s in affected.spans):
        return None
    starts = []
    for s in affected.spans:
        k = () if s.introduced == "0" else version_key(s.introduced, eco)
        if k is None:
            return None
        starts.append((k, s))
    lowest_key, lowest = min(starts, key=lambda t: t[0])
    if lowest.introduced != "0" and have < lowest_key:
        return StatedGap(
            kind=CandidateKind.BELOW_RANGE,
            stated_start=lowest.introduced,
            major_distance=lowest_key[0] - have[0] if lowest_key and have else None,
        )
    # A gap counts only after a span ending at `last_affected`: that line was left without a known
    # fix, so a later version below the next span's start may still carry the code.
    open_ends = [
        k
        for s in affected.spans
        if s.last_affected and not s.fixed and (k := version_key(s.last_affected, eco)) is not None
    ]
    fixed_ends = [
        k for s in affected.spans if s.fixed and (k := version_key(s.fixed, eco)) is not None
    ]
    for k, s in sorted(starts, key=lambda t: t[0]):
        if k <= have:
            continue
        below = [e for e in open_ends + fixed_ends if e <= have]
        if below and max(below) in open_ends and max(below) not in fixed_ends:
            return StatedGap(
                kind=CandidateKind.GAP,
                stated_start=s.introduced,
                major_distance=k[0] - have[0] if k and have else None,
            )
        break
    return None


def fix_links(
    record: AdvisoryRecord, aliases: Sequence[AdvisoryRecord], forges: frozenset[str]
) -> list[tuple[int, str]]:
    """(rank, url) of every linked fix on an allow-listed forge, best first: a GIT range's `fixed`
    commit, then `FIX` references, then other commit or pull-request links. Alias records count:
    a GHSA often links no commit while its CVE record carries them as GIT ranges."""
    found: list[tuple[int, str]] = []
    for rec in (record, *aliases):
        found += [(0, u) for u in rec.fixed_commits]
        found += [(1, u) for u in rec.fix_references]
        found += [(2, u) for u in rec.references if _COMMIT_OR_PR.search(u)]
    seen: set[str] = set()
    ranked = []
    for rank, url in sorted(found, key=lambda t: t[0]):
        url = url.split("#")[0].split("?")[0]
        if (urllib.parse.urlsplit(url).hostname or "") in forges and url not in seen:
            seen.add(url)
            ranked.append((rank, url))
    return ranked


def patch_url(url: str) -> str | None:
    """The `.patch` endpoint of a GitHub/GitLab commit, pull or merge request link."""
    m = re.match(r"(https://github\.com/[^/]+/[^/]+/(?:commit/[0-9a-f]{7,40}|pull/\d+))", url)
    if m:
        return m.group(1) + ".patch"
    m = re.match(r"(https://gitlab\.com/.+?/-/(?:commit/[0-9a-f]{7,40}|merge_requests/\d+))", url)
    return m.group(1) + ".patch" if m else None


def parse_mbox(text: str) -> list[PatchCommit]:
    """A git format-patch stream as commits with their non-test file changes."""
    chunks = re.split(r"(?m)^From ([0-9a-f]{40}) ", text)
    pairs = list(zip(chunks[1::2], chunks[2::2], strict=False)) or [("", text)]
    commits = []
    for sha, body in pairs:
        head, _, diff = body.partition("\ndiff --git ")
        subj = re.search(r"(?m)^Subject: (?:\[PATCH[^\]]*\] )?(.*(?:\n [^\n]+)*)", head)
        subject = re.sub(r"\s+", " ", subj.group(1)).strip() if subj else ""
        files = _files("diff --git " + diff) if diff else ()
        commits.append(PatchCommit(sha=sha, subject=subject, message=head, files=files))
    return commits


def _files(diff: str) -> tuple[FileChange, ...]:
    files: list[tuple[str, list[tuple[list[str], list[str]]]]] = []
    hunks: list[tuple[list[str], list[str]]] | None = None
    hunk: tuple[list[str], list[str]] | None = None
    for line in diff.splitlines():
        if line.startswith("diff --git "):
            hunks, hunk = None, None
        elif line.startswith("+++ "):
            path = line[4:].strip().removeprefix("b/")
            hunks, hunk = (None, None) if path == "/dev/null" else ([], None)
            if hunks is not None:
                files.append((path, hunks))
        elif line.startswith("@@") and hunks is not None:
            hunk = ([], [])
            hunks.append(hunk)
        elif hunk is not None:
            if line.startswith("-") and not line.startswith("---"):
                hunk[0].append(line[1:])
            elif line.startswith("+") and not line.startswith("+++"):
                hunk[1].append(line[1:])
    return tuple(
        FileChange(path=p, hunks=tuple(Hunk(removed=tuple(r), added=tuple(a)) for r, a in hs))
        for p, hs in files
        if hs and not _TEST_PATH.search(p)
    )


def advisory_ids(record: AdvisoryRecord) -> set[str]:
    return {record.identifier, *record.aliases}


def narrow(commits: list[PatchCommit], ids: set[str]) -> list[PatchCommit]:
    """The commits of a bundle that name the advisory, or all of them if none do."""
    return [c for c in commits if any(i in c.message for i in ids)] or commits


def release_like(commits: Sequence[PatchCommit], files: Sequence[FileChange]) -> bool:
    """A release or version-bump commit: a release subject, or only version, packaging,
    changelog or docs files changed."""
    if commits and all(_RELEASE_SUBJECT.search(c.subject) for c in commits):
        return True
    return bool(files) and all(_RELEASE_FILES.search(f.path) for f in files)


def only_adds(files: Sequence[FileChange]) -> bool:
    """The change removes nothing: the shape of a feature introduction."""
    return bool(files) and all(not h.removed for f in files for h in f.hunks)


def latest_authored(commits: Sequence[PatchCommit]) -> str | None:
    dates = [d for c in commits if (d := c.authored_at) is not None]
    return max(dates).isoformat() if dates else None
