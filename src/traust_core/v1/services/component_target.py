"""Deterministic resolution and verification of component PURL targets against pinned checkouts.

Owns `deterministic-rules-placement`: neither CLI glue nor skills guess module paths or release
associations. Every resolution is verified from build/workspace metadata and git pin evidence.
"""

from __future__ import annotations

import re
import threading
from collections.abc import Sequence
from pathlib import Path
from urllib.parse import urlsplit

from traust_core.v1.errors import UnresolvedTargetError, ValidationError
from traust_core.v1.models.component_target import (
    ComponentTarget,
    ComponentTargetProvenance,
    ComponentTargetRequest,
    ComponentTargetStrategy,
    ComponentTargetVerification,
    PackageManifestCandidate,
    UnresolvedTargetReason,
    canonical_component_purl,
    normalize_component_commit,
    normalize_module_path,
    parse_component_purl,
)
from traust_core.v1.models.purl import Purl
from traust_core.v1.models.vocabulary import RefKind
from traust_core.v1.providers.checkout import GitCheckout
from traust_core.v1.providers.package_manifests import PackageManifestScanner
from traust_core.v1.providers.provenance import DsseProvenanceVerifier

_PKG_TAG_SEPARATORS = ("==", "@", "-v", "-", "/v", "/")
# what follows a package-tag separator when the tag names a release: a digit-led version
# (`1.0.0`, `v2`, `1.0.0-rc.2`) or a bare label-and-number one (`RC1`, `M2`). A hyphenated
# word before the digits names another package (`pkg-extra-2.0.0`), and so does any further
# name or separator (`client-v2@1.0.0` releases `client-v2`).
_VERSION_TOKEN = re.compile(r"v?\d[0-9A-Za-z.+_-]*|[A-Za-z]+\d+[0-9A-Za-z.+_]*")
# a pre-release label after the version: the RC commit promoted to the final release keeps
# both tags (`foo-1.0.0-rc.2` and `foo-1.0.0`), which is one release, not a conflict
_PRERELEASE = re.compile(
    r"[-.+_]?(?:rc|alpha|beta|pre|preview|dev|milestone|m|cr|a|b)[.-]?\d*", re.IGNORECASE
)
_PROJECT_TAG_SEPARATORS = ("-", "_", "/")


def _repo_slug(repository: str) -> str | None:
    cleaned = repository.strip().rstrip("/")
    if cleaned.endswith(".git"):
        cleaned = cleaned[:-4]
    path = urlsplit(cleaned).path if "://" in cleaned else cleaned
    slug = path.rsplit("/", 1)[-1].strip()
    return slug or None


def _project_prefixes(
    repository: str, candidates: Sequence[PackageManifestCandidate]
) -> tuple[str, ...]:
    names: list[str] = []
    if slug := _repo_slug(repository):
        names.append(slug)
    for cand in candidates:
        if cand.project_name:
            names.append(cand.project_name)
    return tuple(dict.fromkeys(n for n in names if n))


def _is_shared_release_tag(tag: str, version: str, project_names: Sequence[str] = ()) -> bool:
    if tag in (version, f"v{version}", f"release-{version}", f"rel/{version}"):
        return True
    for proj in project_names:
        for sep in _PROJECT_TAG_SEPARATORS:
            if tag in (f"{proj}{sep}{version}", f"{proj}{sep}v{version}"):
                return True
    return False


def _package_tag_names(purl: Purl) -> tuple[str, ...]:
    names = [purl.name]
    if purl.type == "pypi":
        names.extend([purl.package_id, purl.name.replace("_", "-"), purl.name.replace("-", "_")])
    elif purl.namespace:
        names.append(f"{purl.namespace}/{purl.name}")
    return tuple(dict.fromkeys(names))


def _is_package_release_tag(tag: str, purl: Purl) -> bool:
    for pkg in _package_tag_names(purl):
        for sep in _PKG_TAG_SEPARATORS:
            if tag == f"{pkg}{sep}{purl.version}":
                return True
    return False


def _released_version(tag: str, names: Sequence[str]) -> str | None:
    """The version `tag` releases for one of `names`, or None when it names no such release."""
    for pkg in names:
        for sep in _PKG_TAG_SEPARATORS:
            prefix = f"{pkg}{sep}"
            if tag.startswith(prefix):
                rest = tag[len(prefix) :]
                if _VERSION_TOKEN.fullmatch(rest):
                    return rest.removeprefix("v") if sep in ("-", "/") else rest
    return None


def _candidate_tag_names(candidate: PackageManifestCandidate) -> tuple[str, ...]:
    """The names a sibling package's release tags carry (its own name, and its scoped or
    grouped form)."""
    package_id = candidate.package_id
    name = package_id.rsplit(":", 1)[-1].rsplit("/", 1)[-1]
    return tuple(dict.fromkeys((package_id, name, package_id.replace(":", "/"))))


def _conflicting_package_tag(
    tags: Sequence[str],
    purl: Purl,
    siblings: Sequence[PackageManifestCandidate] = (),
) -> str | None:
    """A tag at the pinned commit that releases this package at another version, under any
    separator `_is_package_release_tag` accepts. Not a conflict: a release tag of this
    version, a pre-release of it (an RC commit promoted to the final release), or a tag
    that releases a sibling package whose name extends this one's (`foo-3d-1.0.0`)."""
    names = _package_tag_names(purl)
    sibling_names = tuple(
        dict.fromkeys(
            n
            for c in siblings
            if c.package_id != purl.package_id
            for n in _candidate_tag_names(c)
            if n not in names
        )
    )
    for tag in tags:
        if _is_package_release_tag(tag, purl):
            continue
        version = _released_version(tag, names)
        if version is None or version == purl.version:
            continue
        if purl.version and version.startswith(purl.version):
            label = version[len(purl.version) :]
            if _PRERELEASE.fullmatch(label):
                continue
        if _released_version(tag, sibling_names) is not None:
            continue
        return tag
    return None


def _classify_candidate(
    candidate: PackageManifestCandidate,
    purl: Purl,
    tags: Sequence[str],
    requested_release_ref: str | None,
    project_names: Sequence[str] = (),
) -> tuple[ComponentTargetStrategy, str | None] | None:
    """Determine which verified release strategy applies, or None when evidence is insufficient."""
    if candidate.is_private:
        return None

    pkg_tag = next((t for t in tags if _is_package_release_tag(t, purl)), None)
    shared_tag = next(
        (t for t in tags if _is_shared_release_tag(t, purl.version, project_names)), None
    )

    if candidate.is_dynamic_version and candidate.version is None:
        if pkg_tag is not None:
            return ComponentTargetStrategy.PACKAGE_RELEASE, requested_release_ref or pkg_tag
        if shared_tag is not None and (
            candidate.is_workspace_root or candidate.is_workspace_member
        ):
            return ComponentTargetStrategy.SHARED_RELEASE, requested_release_ref or shared_tag
        return None

    if candidate.version != purl.version:
        return None

    if pkg_tag is not None:
        return ComponentTargetStrategy.PACKAGE_RELEASE, requested_release_ref or pkg_tag

    if shared_tag is None:
        return None

    if (
        candidate.is_workspace_member
        and not candidate.inherits_root_version
        and candidate.ecosystem == "npm"
    ):
        return ComponentTargetStrategy.WORKSPACE_PACKAGE, requested_release_ref or shared_tag

    if (
        candidate.is_workspace_root
        or candidate.is_workspace_member
        or candidate.inherits_root_version
    ):
        return ComponentTargetStrategy.SHARED_RELEASE, requested_release_ref or shared_tag

    return None


class ComponentTargetResolver:
    """Verifies that a versioned PURL maps deterministically to one module in a pinned tree."""

    def __init__(
        self,
        git: GitCheckout,
        scanner: PackageManifestScanner | None = None,
        provenance_verifier: DsseProvenanceVerifier | None = None,
        *,
        trust_policy: Path | None = None,
    ) -> None:
        """`trust_policy` is read once, on the first order that carries provenance: a missing
        or broken policy fails those orders only, never every request."""
        self._git = git
        self._scanner = scanner or PackageManifestScanner()
        self._provenance_verifier = provenance_verifier
        self._trust_policy = trust_policy
        self._verifier_lock = threading.Lock()

    def _verifier(self) -> DsseProvenanceVerifier | None:
        if self._provenance_verifier is None and self._trust_policy is not None:
            with self._verifier_lock:
                if self._provenance_verifier is None:
                    self._provenance_verifier = DsseProvenanceVerifier.from_file(self._trust_policy)
        return self._provenance_verifier

    def resolve(self, request: ComponentTargetRequest, checkout: Path) -> ComponentTarget:
        purl = parse_component_purl(request.purl)

        if request.ref_kind in (RefKind.DEFAULT, RefKind.BRANCH) and not request.commit:
            raise UnresolvedTargetError(
                UnresolvedTargetReason.DEFAULT_BRANCH_DISALLOWED,
                f"mutable ref kind {request.ref_kind!r} without an immutable commit pin",
            )

        commit: str | None = None
        if request.commit:
            try:
                commit = normalize_component_commit(request.commit)
            except ValidationError as exc:
                raise UnresolvedTargetError(
                    UnresolvedTargetReason.MISSING_PIN,
                    f"commit must be a 40- or 64-char SHA, got {request.commit!r}",
                ) from exc
        release_ref = request.release_ref.strip() if request.release_ref else None
        if release_ref:
            tag_sha = self._git.resolve_tag(checkout, release_ref)
            if tag_sha is None:
                raise UnresolvedTargetError(
                    UnresolvedTargetReason.TAG_COMMIT_MISMATCH,
                    f"release tag {release_ref!r} not found in pinned checkout",
                )
            if commit is not None and commit != tag_sha:
                raise UnresolvedTargetError(
                    UnresolvedTargetReason.TAG_COMMIT_MISMATCH,
                    f"release tag {release_ref!r} points to {tag_sha}, not {commit}",
                )
            commit = tag_sha

        if commit is None:
            raise UnresolvedTargetError(
                UnresolvedTargetReason.MISSING_PIN,
                "an immutable 40- or 64-char commit SHA or verified release tag is required",
            )

        head = self._git.head(checkout).lower()
        if head != commit:
            raise UnresolvedTargetError(
                UnresolvedTargetReason.TAG_COMMIT_MISMATCH,
                f"checkout HEAD {head} does not match pinned commit {commit}",
            )

        supplied_path: str | None = None
        if request.module_path is not None:
            supplied_path = normalize_module_path(request.module_path)
        elif purl.subpath is not None:
            supplied_path = purl.subpath

        candidates = self._scanner.scan(checkout)
        same_eco = [c for c in candidates if c.ecosystem == purl.ecosystem]
        matched_name = [c for c in same_eco if c.package_id == purl.package_id]

        if not matched_name:
            private_root_version_match = [
                c
                for c in same_eco
                if c.is_workspace_root and c.is_private and c.version == purl.version
            ]
            if private_root_version_match:
                raise UnresolvedTargetError(
                    UnresolvedTargetReason.PRIVATE_ROOT_ONLY,
                    f"only private workspace root matches version {purl.version} for {purl.raw}",
                )
            raise UnresolvedTargetError(
                UnresolvedTargetReason.NO_MANIFEST_MATCH,
                f"no manifest declares {purl.package_id!r} ({purl.type}) at {commit}",
            )

        if all(c.is_private for c in matched_name):
            raise UnresolvedTargetError(
                UnresolvedTargetReason.PRIVATE_ROOT_ONLY,
                f"{purl.raw} matches only a private manifest",
            )

        if request.provenance_record is not None:
            return self._resolve_external_provenance(
                request=request,
                purl=purl,
                commit=commit,
                release_ref=release_ref,
                supplied_path=supplied_path,
                matched_name=matched_name,
            )

        tags = self._git.tags_at(checkout, commit)
        if conflict_tag := _conflicting_package_tag(tags, purl, same_eco):
            raise UnresolvedTargetError(
                UnresolvedTargetReason.VERSION_MISMATCH,
                f"commit {commit} carries conflicting tag {conflict_tag!r} for {purl.raw}",
            )

        project_names = _project_prefixes(request.repository, candidates)
        verified: list[tuple[PackageManifestCandidate, ComponentTargetStrategy, str | None]] = []
        version_mismatch = False
        for cand in matched_name:
            if cand.is_private:
                continue
            if cand.version is not None and cand.version != purl.version:
                version_mismatch = True
                continue
            if cand.version is None and not cand.is_dynamic_version:
                version_mismatch = True
                continue
            classified = _classify_candidate(cand, purl, tags, release_ref, project_names)
            if classified is not None:
                verified.append((cand, classified[0], classified[1]))

        if not verified:
            if version_mismatch:
                raise UnresolvedTargetError(
                    UnresolvedTargetReason.VERSION_MISMATCH,
                    f"manifest version for {purl.package_id!r} != {purl.version!r} at {commit}",
                )
            raise UnresolvedTargetError(
                UnresolvedTargetReason.NO_MANIFEST_MATCH,
                f"release/build metadata at {commit} does not verify {purl.raw}",
            )

        if supplied_path is not None:
            narrowed = [item for item in verified if item[0].module_path == supplied_path]
            if not narrowed:
                found_paths = ", ".join(sorted(item[0].module_path for item in verified))
                raise UnresolvedTargetError(
                    UnresolvedTargetReason.SUPPLIED_PATH_CONFLICT,
                    f"supplied module_path {supplied_path!r} conflicts with {found_paths}",
                )
            verified = narrowed

        if len(verified) > 1:
            found_paths = ", ".join(sorted(item[0].module_path for item in verified))
            raise UnresolvedTargetError(
                UnresolvedTargetReason.AMBIGUOUS_MODULE_MATCH,
                f"{purl.raw} matched multiple modules at {commit}: {found_paths}",
            )

        cand, strategy, matched_ref = verified[0]
        return ComponentTarget(
            purl=purl.canonical,
            repository=request.repository,
            commit=commit,
            module_path=cand.module_path,
            release_ref=matched_ref,
            verification=ComponentTargetVerification(
                strategy=strategy,
                manifest_paths=cand.manifest_paths,
            ),
        )

    def _resolve_external_provenance(
        self,
        *,
        request: ComponentTargetRequest,
        purl: Purl,
        commit: str,
        release_ref: str | None,
        supplied_path: str | None,
        matched_name: Sequence[PackageManifestCandidate],
    ) -> ComponentTarget:
        assert request.provenance_record is not None
        verifier = self._verifier()
        if verifier is None:
            raise UnresolvedTargetError(
                UnresolvedTargetReason.PROVENANCE_UNVERIFIED,
                "no provenance verifier or trust policy configured",
            )
        claim = verifier.verify(request.provenance_record)
        try:
            claim_purl = canonical_component_purl(claim.purl)
            claim_commit = normalize_component_commit(claim.commit)
        except (UnresolvedTargetError, ValidationError) as exc:
            raise UnresolvedTargetError(
                UnresolvedTargetReason.PROVENANCE_MISMATCH,
                f"verified provenance carries invalid purl or commit: {exc}",
            ) from exc
        if claim_purl != purl.canonical:
            raise UnresolvedTargetError(
                UnresolvedTargetReason.PROVENANCE_MISMATCH,
                f"provenance PURL {claim_purl!r} does not match requested {purl.canonical!r}",
            )
        if claim.repository.strip().rstrip("/") != request.repository.strip().rstrip("/"):
            raise UnresolvedTargetError(
                UnresolvedTargetReason.PROVENANCE_MISMATCH,
                f"provenance repository {claim.repository!r} does not match {request.repository!r}",
            )
        if claim_commit != commit:
            raise UnresolvedTargetError(
                UnresolvedTargetReason.PROVENANCE_MISMATCH,
                f"provenance commit {claim_commit} does not match pinned commit {commit}",
            )
        if release_ref is not None and claim.ref != release_ref:
            # the stored provenance and the verified tag must describe the same release
            raise UnresolvedTargetError(
                UnresolvedTargetReason.PROVENANCE_MISMATCH,
                f"provenance ref {claim.ref!r} does not match release tag {release_ref!r}",
            )

        non_private = [c for c in matched_name if not c.is_private]
        if supplied_path is not None:
            narrowed = [c for c in non_private if c.module_path == supplied_path]
            if not narrowed:
                found_paths = ", ".join(sorted(c.module_path for c in non_private))
                raise UnresolvedTargetError(
                    UnresolvedTargetReason.SUPPLIED_PATH_CONFLICT,
                    f"supplied module_path {supplied_path!r} conflicts with {found_paths}",
                )
            non_private = narrowed
        if len(non_private) > 1:
            found_paths = ", ".join(sorted(c.module_path for c in non_private))
            raise UnresolvedTargetError(
                UnresolvedTargetReason.AMBIGUOUS_MODULE_MATCH,
                f"{purl.raw} matched multiple modules at {commit}: {found_paths}",
            )
        cand = non_private[0]
        if cand.version == purl.version:
            if claim.manifest_version is not None and claim.manifest_version != cand.version:
                raise UnresolvedTargetError(
                    UnresolvedTargetReason.PROVENANCE_MISMATCH,
                    f"provenance manifest_version {claim.manifest_version!r} != {cand.version!r}",
                )
        else:
            if cand.version is None or claim.manifest_version != cand.version:
                raise UnresolvedTargetError(
                    UnresolvedTargetReason.PROVENANCE_MISMATCH,
                    f"manifest declares {cand.version!r} (!= {purl.version!r}), requiring "
                    f"matching provenance manifest_version (got {claim.manifest_version!r})",
                )
        return ComponentTarget(
            purl=purl.canonical,
            repository=request.repository,
            commit=commit,
            module_path=cand.module_path,
            release_ref=release_ref,
            verification=ComponentTargetVerification(
                strategy=ComponentTargetStrategy.EXTERNAL_PROVENANCE,
                manifest_paths=cand.manifest_paths,
                provenance=ComponentTargetProvenance(
                    source=claim.source,
                    ref=claim.ref,
                    digest=claim.digest,
                    manifest_version=claim.manifest_version,
                ),
            ),
        )
