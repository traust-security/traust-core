"""The finding identity recipe (moved from traust-ledger). A change that moves a stamped value
bumps ALGO_VERSION; stamps record their version, so the ladder can attribute older ones."""

from __future__ import annotations

import difflib
import hashlib
import re
from collections.abc import Callable, Sequence
from uuid import UUID

from traust_core.v1.errors import ValidationError
from traust_core.v1.models.findings import (
    ExposureKey,
    FindingCandidate,
    FindingView,
    IdentityMove,
    Label,
)
from traust_core.v1.models.integrity import Fingerprint, FingerprintInput, FingerprintLocation
from traust_core.v1.models.vocabulary import AliasMatchedBy

ALGO_VERSION = "v3"
EXPOSURE_ALGO = "exposure-v1"

# ASCII-only folding: Unicode case mappings differ across runtimes (U+0130), the recipe must not.
_ASCII_LOWER = str.maketrans("ABCDEFGHIJKLMNOPQRSTUVWXYZ", "abcdefghijklmnopqrstuvwxyz")
_ASCII_UPPER = str.maketrans("abcdefghijklmnopqrstuvwxyz", "ABCDEFGHIJKLMNOPQRSTUVWXYZ")
_CWE_NUMBER = re.compile(r"(\d+)")
_CWE_NO_NUMBER = 10**9


def ascii_lower(s: str) -> str:
    return s.translate(_ASCII_LOWER)


def ascii_upper(s: str) -> str:
    return s.translate(_ASCII_UPPER)


def canon_repo(url: str | None) -> str:
    """https, lowercase, no .git or trailing slash; a non-URL passes through lowercased."""
    s = ascii_lower((url or "").strip())
    s = re.sub(r"^git@([^:]+):", r"https://\1/", s)
    s = re.sub(r"^(https?|ssh|git)://", "https://", s)
    return re.sub(r"\.git$", "", s).rstrip("/")


def canon_path(p: str | None) -> str:
    s = (p or "").strip().replace("\\", "/")
    s = re.sub(r"/{2,}", "/", s)
    return s.lstrip("./").rstrip("/")


def title_similarity(a: str | None, b: str | None) -> float:
    """Max of character-sequence and token-set similarity: re-audits reorder and reword titles."""
    a, b = (a or "").lower(), (b or "").lower()
    tokens_a = {t for t in re.split(r"[^a-z0-9]+", a) if len(t) > 2}
    tokens_b = {t for t in re.split(r"[^a-z0-9]+", b) if len(t) > 2}
    union = tokens_a | tokens_b
    jaccard = len(tokens_a & tokens_b) / len(union) if union else 0.0
    return max(difflib.SequenceMatcher(None, a, b).ratio(), jaccard)


def location_anchor(location: FingerprintLocation) -> str:
    """`path`, else `resource`: an IaC resource name survives its file moving."""
    return canon_path(location.path) or canon_path(location.resource)


def primary_cwe(finding: FingerprintInput) -> str:
    """The lowest CWE by number (not lexicographic, not first listed); 'CWE-0' when absent."""
    listed = finding.cwes or ((finding.cwe,) if finding.cwe else ())
    cwes = [c for c in listed if c.strip()]
    if not cwes:
        return "CWE-0"

    def rank(cwe: str) -> tuple[int, str]:
        text = ascii_upper(cwe.strip()).strip()
        digits = _CWE_NUMBER.search(text)
        return (int(digits.group(1)) if digits else _CWE_NO_NUMBER, text)

    return ascii_upper(min(cwes, key=rank).strip()).strip() or "CWE-0"


def policy_check(finding: FingerprintInput) -> str:
    """A policy finding's check id, appended only when present so no code finding's stamp moves."""
    return ascii_upper(finding.check_id.strip()) if finding.check_id else ""


def _paths_v3(finding: FingerprintInput) -> list[str]:
    return sorted({anchor for loc in finding.locations if (anchor := location_anchor(loc))})


def _cwe_v3(finding: FingerprintInput) -> str:
    cwe = primary_cwe(finding)
    return f"{cwe}|{check}" if (check := policy_check(finding)) else cwe


# Frozen rungs reproduce history exactly: they read only what their recipe could see.
def _paths_v2(finding: FingerprintInput) -> list[str]:
    return sorted({canon for loc in finding.locations if (canon := canon_path(loc.path))})


def _paths_v1(finding: FingerprintInput) -> list[str]:
    return sorted({canon_path(loc.path) for loc in finding.locations})


def _cwe_first(finding: FingerprintInput) -> str:
    values = [c for c in finding.cwes if c]
    return ascii_upper(values[0].strip()) if values else "CWE-0"


Rung = tuple[str, Callable[[FingerprintInput], list[str]], Callable[[FingerprintInput], str]]

ALGO_LADDER: tuple[Rung, ...] = (
    ("v3", _paths_v3, _cwe_v3),
    ("v2", _paths_v2, _cwe_first),
    ("v1", _paths_v1, _cwe_first),
)


def _digest(repo: str | None, paths: list[str], cwe: str) -> str:
    payload = "|".join([canon_repo(repo), ";".join(paths), cwe])
    return hashlib.sha256(payload.encode("utf-8")).hexdigest()


class IdentityPolicy:
    def match_key(self, finding: FingerprintInput, *, strict: bool = False) -> Fingerprint:
        """The current recipe. strict refuses a finding with no usable location."""
        paths = _paths_v3(finding)
        if strict and not paths:
            raise ValidationError(
                "refusing to fingerprint a finding with no usable location: every path in "
                f"{[loc.path for loc in finding.locations]!r} canonicalizes to empty. Name the "
                "artifact the finding concerns, or use a controlled pseudo-path from "
                "traust-contracts enums/v1/repo-scope-path.json"
            )
        return Fingerprint(ALGO_VERSION, _digest(finding.repo, paths, _cwe_v3(finding)))

    def exposure_key(self, repo: str, key: ExposureKey) -> Fingerprint:
        """A dependency finding: the same advisory reaching the same package is one finding,
        whatever the manifest or line it was seen at."""
        payload = "|".join([canon_repo(repo), key.advisory, key.ecosystem, key.package])
        return Fingerprint(EXPOSURE_ALGO, hashlib.sha256(payload.encode("utf-8")).hexdigest())

    def attribute(
        self, finding: FingerprintInput, stamp: str, repo_candidates: Sequence[str | None]
    ) -> str | None:
        """Which recipe minted an unversioned stamp; each repo spelling is an input, not a rung."""
        for repo in dict.fromkeys(repo_candidates):
            for version, paths_of, cwe_of in ALGO_LADDER:
                if _digest(repo, paths_of(finding), cwe_of(finding)) == stamp:
                    return version
        return None

    def moves(
        self,
        previous: Sequence[FindingView],
        candidates: Sequence[FindingCandidate],
        keys: Sequence[Fingerprint],
    ) -> list[IdentityMove]:
        """The rebaseline ladder: candidates whose fingerprint (`keys`) is a recorded finding's
        need no move; the rest are proposed by equal path set and primary CWE, then overlapping
        paths (Jaccard >= 0.5), then title similarity (>= 0.6). Every proposal needs a person."""
        known = {(v.finding.fingerprint_algo, v.finding.fingerprint) for v in previous}
        reported = {(k.algo, k.value) for k in keys}
        open_ = {
            c.label: (c, k)
            for c, k in zip(candidates, keys, strict=True)
            if (k.algo, k.value) not in known
        }
        olds = [
            v
            for v in previous
            if (v.finding.fingerprint_algo, v.finding.fingerprint) not in reported
        ]
        moves: list[IdentityMove] = []

        def claim(view: FindingView, label: Label, tier: str, **scores: float) -> None:
            _, key = open_.pop(label)
            moves.append(
                IdentityMove(
                    finding_id=view.finding.id,  # type: ignore[arg-type]
                    label=label,
                    fingerprint_algo=key.algo,
                    fingerprint=key.value,
                    matched_by=AliasMatchedBy(tier),
                    **{k: round(v, 3) for k, v in scores.items()},
                )
            )

        for view in [v for v in olds if _view_paths(v)]:
            same = [
                lb
                for lb, (c, _) in open_.items()
                if _candidate_paths(c) == _view_paths(view)
                and _primary(c.cwes) == _primary(view.cwes)
            ]
            if len(same) == 1:
                claim(view, same[0], "path_cwe")
        for view in [v for v in olds if _view_paths(v) and v.finding.id not in _moved(moves)]:
            scored = [
                (lb, overlap, title_similarity(view.finding.title, c.title))
                for lb, (c, _) in open_.items()
                if (overlap := _jaccard(_view_paths(view), _candidate_paths(c))) >= 0.5
            ]
            if scored:
                lb, overlap, sim = max(scored, key=lambda t: (t[1], t[2]))
                claim(view, lb, "path_set", similarity=sim, path_overlap=overlap)
        for view in [v for v in olds if v.finding.id not in _moved(moves)]:
            scored = [
                (lb, title_similarity(view.finding.title, c.title)) for lb, (c, _) in open_.items()
            ]
            if scored and (best := max(scored, key=lambda t: t[1]))[1] >= 0.6:
                claim(view, best[0], "title", similarity=best[1])
        return moves


def _view_paths(view: FindingView) -> frozenset[str]:
    return frozenset(p for loc in view.locations if (p := canon_path(loc.path)))


def _candidate_paths(candidate: FindingCandidate) -> frozenset[str]:
    return frozenset(p for span in candidate.locations if (p := canon_path(span.path)))


def _primary(cwes: Sequence[str]) -> str:
    return primary_cwe(FingerprintInput(cwes=tuple(cwes)))


def _jaccard(a: frozenset[str], b: frozenset[str]) -> float:
    return len(a & b) / len(a | b) if a | b else 0.0


def _moved(moves: Sequence[IdentityMove]) -> set[UUID]:
    return {m.finding_id for m in moves}
