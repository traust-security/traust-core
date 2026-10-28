"""The product-definitions registry (`ps_products`, `ps_modules`, `ps_update_streams`) read for
ownership context: candidate contacts and a lifecycle window, never an owner.

Only the ownership slice leaves here: contacts tagged by the field they came from, and the
lifecycle. Tracker keys, CPEs, errata tags, legacy teams and free text are never emitted.
"""

from __future__ import annotations

import re
from collections.abc import Iterable, Mapping
from datetime import date
from enum import StrEnum
from typing import Any

from pydantic import Field

from traust_core.v1.models.base import Dto

DEFINITION_KEYS = ("ps_products", "ps_modules", "ps_update_streams")
# These values may be passed to an employee verification tool.
IDENTITY = re.compile(r"^[a-z0-9._-]{1,64}$")
# (field, tier, embargo-cleared), highest confidence first. Only tier 1 receives embargoed
# trackers; CC'ing default_cc on an embargoed finding would be a disclosure event.
CONTACT_FIELDS = (
    ("private_tracker_cc", 1, True),
    ("private_tracker_cc_component_override", 1, True),
    ("component_cc", 2, False),
    ("default_cc", 3, False),
)
# Upstream publishes with --expand-aliases, so many dropped values mean that regressed.
DROP_RATE_WARN = 0.20
SLUG_ADVISORY = (
    "slug match is advisory — confirm it in the product-definitions-map setting before "
    "relying on it"
)


class ProductMatchTier(StrEnum):
    MAPPED = "mapped"  # reviewed config
    REPO_URL = "repo-url"  # exact managed_service_components[].git_repo_url
    SLUG = "slug"  # advisory only, always human-confirmed
    NONE = "none"


class ProductSourceStatus(StrEnum):
    OK = "ok"
    STALE = "stale"
    UNAVAILABLE = "unavailable"  # not "none": the cache is missing, not the match


class ProductQueryKind(StrEnum):
    PACKAGE = "package"
    REPO_URL = "repo-url"
    PRODUCT = "product"


class ProductContact(Dto):
    kerberos_id: str
    field: str
    tier: int
    embargo_cleared: bool
    ps_module: str
    component: str | None = None


class DroppedContact(Dto):
    value: str
    field: str
    ps_module: str
    reason: str


class ProductLifecycle(Dto):
    supported_from: str | None
    supported_until: str | None
    state: str


class ProductEvidence(Dto):
    repo_url: str | None = None
    ps_update_streams: tuple[str, ...] | None = None
    components: tuple[str, ...] | None = None
    ps_product: str | None = None
    mapped_from: str | None = None
    slug: str | None = None
    advisory_only: str | None = None
    package: str | None = None
    error: str | None = None


class ProductQuery(Dto):
    kind: ProductQueryKind
    value: str


class ProductMatch(Dto):
    """One query's ownership context. Serialise with `exclude_unset=True`: evidence carries
    only what its tier found."""

    match_tier: ProductMatchTier
    ps_products: tuple[str, ...]
    ps_modules: tuple[str, ...]
    lifecycle: ProductLifecycle
    contacts: tuple[ProductContact, ...]
    embargo_cc: str
    dropped_contacts: tuple[DroppedContact, ...]
    evidence: ProductEvidence
    query: ProductQuery | None = None


class ProductSource(Dto):
    detail: str | None = None
    retrieved_at: str | None = None
    age_hours: float | None = None
    max_age_hours: float | None = None
    url: str | None = None


class ProductDefinitionsSnapshot(Dto):
    """The cached registry as it stands: its freshness and, unless unavailable, the document."""

    status: ProductSourceStatus
    source: ProductSource
    document: dict[str, Any] | None = None


class ProductMappings(Dto):
    """Reviewed package -> product and repo URL -> product pairs (product-definitions-map)."""

    packages: dict[str, str] = Field(default_factory=dict)
    repos: dict[str, str] = Field(default_factory=dict)
    warnings: tuple[str, ...] = ()


class ProductResolution(Dto):
    source_status: ProductSourceStatus
    source: ProductSource
    results: tuple[ProductMatch, ...] = ()
    warnings: tuple[str, ...] | None = None


def norm_repo_url(url: str) -> str:
    """Join key for repo URLs: lowercased, no scheme or `.git`, scp-style folded to host/path."""
    u = re.sub(r"\.git$", "", (url or "").strip().rstrip("/").lower())
    if u.startswith("git@"):
        return u[4:].replace(":", "/", 1)
    return re.sub(r"^[a-z][a-z0-9+.-]*://", "", u)


def _slug(text: str | None) -> str:
    return re.sub(r"[^a-z0-9]", "", (text or "").lower())


class ProductDefinitions:
    """The registry document indexed for lookups by product id, package name and repo URL."""

    def __init__(self, document: Mapping[str, Any], today: date) -> None:
        self._products: dict[str, Any] = document.get("ps_products") or {}
        self._modules: dict[str, Any] = document.get("ps_modules") or {}
        self._today = today
        self._module_products: dict[str, list[str]] = {}
        for pid, product in self._products.items():
            for mid in product.get("ps_modules") or []:
                self._module_products.setdefault(mid, []).append(pid)
        self._stream_modules: dict[str, list[str]] = {}
        for mid, module in self._modules.items():
            for sid in module.get("ps_update_streams") or []:
                self._stream_modules.setdefault(sid, []).append(mid)
        self._repo_streams: dict[str, list[str]] = {}
        self._repo_components: dict[str, set[str]] = {}
        for sid, stream in (document.get("ps_update_streams") or {}).items():
            for component in stream.get("managed_service_components") or []:
                if url := component.get("git_repo_url"):
                    key = norm_repo_url(url)
                    self._repo_streams.setdefault(key, []).append(sid)
                    self._repo_components.setdefault(key, set()).add(component.get("name"))
        self._slugs: dict[str, str] = {}
        for pid, product in self._products.items():
            for candidate in (pid, product.get("name")):
                if s := _slug(candidate):
                    self._slugs.setdefault(s, pid)

    def resolve(
        self,
        mappings: ProductMappings,
        packages: Iterable[str] = (),
        repo_urls: Iterable[str] = (),
        product_ids: Iterable[str] = (),
    ) -> tuple[ProductMatch, ...]:
        """Each query's match, in query order: packages, then repo URLs, then product ids."""
        results = [
            self._package(name, mappings).model_copy(
                update={"query": ProductQuery(kind=ProductQueryKind.PACKAGE, value=name)}
            )
            for name in packages
        ]
        for url in repo_urls:
            mapped = mappings.repos.get(url) or mappings.repos.get(norm_repo_url(url))
            match = (
                (self.product(mapped) if mapped else None)
                or self.repo_url(url)
                or self._none(ProductEvidence(repo_url=url))
            )
            query = ProductQuery(kind=ProductQueryKind.REPO_URL, value=url)
            results.append(match.model_copy(update={"query": query}))
        for pid in product_ids:
            match = self.product(pid) or self._none(
                ProductEvidence(error=f"{pid!r} not in registry")
            )
            query = ProductQuery(kind=ProductQueryKind.PRODUCT, value=pid)
            results.append(match.model_copy(update={"query": query}))
        return tuple(results)

    def product(
        self, pid: str, tier: ProductMatchTier = ProductMatchTier.MAPPED
    ) -> ProductMatch | None:
        if pid not in self._products:
            return None
        modules = self._products[pid].get("ps_modules") or []
        return self._match(tier, [pid], modules, ProductEvidence(ps_product=pid))

    def repo_url(self, url: str) -> ProductMatch | None:
        key = norm_repo_url(url)
        if not (streams := self._repo_streams.get(key)):
            return None
        modules = [mid for sid in streams for mid in self._stream_modules.get(sid, [])]
        products = [pid for mid in modules for pid in self._module_products.get(mid, [])]
        evidence = ProductEvidence(
            repo_url=url,
            ps_update_streams=tuple(sorted(set(streams))),
            components=tuple(sorted(c for c in self._repo_components.get(key, ()) if c)),
        )
        return self._match(ProductMatchTier.REPO_URL, products, modules, evidence)

    def _package(self, name: str, mappings: ProductMappings) -> ProductMatch:
        base = re.sub(r"-findings$", "", name)
        if mapped := mappings.packages.get(base) or mappings.packages.get(name):
            if match := self.product(mapped):
                return _with_evidence(match, mapped_from=base)
            return self._none(ProductEvidence(error=f"mapped id {mapped!r} not in registry"))
        if pid := self._slugs.get(_slug(base)):
            match = self._product(pid, ProductMatchTier.SLUG)
            return _with_evidence(match, slug=_slug(base), advisory_only=SLUG_ADVISORY)
        return self._none(ProductEvidence(package=base))

    def _product(self, pid: str, tier: ProductMatchTier) -> ProductMatch:
        modules = self._products[pid].get("ps_modules") or []
        return self._match(tier, [pid], modules, ProductEvidence(ps_product=pid))

    def _match(
        self,
        tier: ProductMatchTier,
        product_ids: Iterable[str],
        module_ids: Iterable[str],
        evidence: ProductEvidence,
    ) -> ProductMatch:
        modules = sorted(set(module_ids))
        contacts, dropped = self._contacts(modules)
        return ProductMatch(
            match_tier=tier,
            ps_products=tuple(sorted(set(product_ids))),
            ps_modules=tuple(modules),
            lifecycle=self._lifecycle(modules),
            contacts=contacts,
            embargo_cc="present" if any(c.embargo_cleared for c in contacts) else "absent",
            dropped_contacts=dropped,
            evidence=evidence,
        )

    def _none(self, evidence: ProductEvidence) -> ProductMatch:
        return self._match(ProductMatchTier.NONE, [], [], evidence)

    def _contacts(
        self, module_ids: Iterable[str]
    ) -> tuple[tuple[ProductContact, ...], tuple[DroppedContact, ...]]:
        """Ladder-ordered contacts, each id at its best tier (an embargo contact also in
        default_cc is never demoted), plus every value that failed the identity shape."""
        best: dict[str, ProductContact] = {}
        dropped = []
        for mid in module_ids:
            module = self._modules.get(mid) or {}
            for field, tier, embargo in CONTACT_FIELDS:
                for value, component in _values(module.get(field)):
                    if not isinstance(value, str):
                        continue
                    ident = value.split("@")[0].strip()
                    if not IDENTITY.match(ident):
                        reason = (
                            "unexpanded_alias" if value.startswith("+") else "not_kerberos_shaped"
                        )
                        dropped.append(
                            DroppedContact(value=value, field=field, ps_module=mid, reason=reason)
                        )
                        continue
                    if ident not in best or tier < best[ident].tier:
                        best[ident] = ProductContact(
                            kerberos_id=ident,
                            field=field,
                            tier=tier,
                            embargo_cleared=embargo,
                            ps_module=mid,
                            **({"component": component} if component else {}),
                        )
        contacts = sorted(best.values(), key=lambda c: (c.tier, c.kerberos_id))
        return tuple(contacts), tuple(dropped)

    def _lifecycle(self, module_ids: Iterable[str]) -> ProductLifecycle:
        """The widest supported window across the modules; no end date on any means none."""
        froms, untils, open_ended = [], [], False
        for mid in module_ids:
            lc = (self._modules.get(mid) or {}).get("lifecycle") or {}
            if lc.get("supported_from"):
                froms.append(lc["supported_from"])
            if lc.get("supported_until"):
                untils.append(lc["supported_until"])
            else:
                open_ended = True
        start = min(froms) if froms else None
        end = None if open_ended else (max(untils) if untils else None)
        today = self._today.isoformat()
        if start and start > today:
            state = "unreleased"
        elif end and end < today:
            state = "eol"
        elif froms or untils or open_ended:
            state = "supported"
        else:
            state = "unknown"
        return ProductLifecycle(supported_from=start, supported_until=end, state=state)


def drop_rate_warning(results: Iterable[ProductMatch]) -> str | None:
    """A warning when more contact values failed the identity shape than upstream ever drops."""
    matched = list(results)
    kept = sum(len(r.contacts) for r in matched)
    lost = sum(len(r.dropped_contacts) for r in matched)
    if not lost or lost / (kept + lost) <= DROP_RATE_WARN:
        return None
    return (
        f"{lost} of {kept + lost} contact values failed the kerberos-id "
        f"shape gate. Upstream publishes with --expand-aliases, so a "
        f"high rate suggests that regressed — check the compile before "
        f"trusting an empty contact list."
    )


def _values(value: object) -> list[tuple[object, str | None]]:
    """One contact field as (value, component) pairs: a list, or a component -> members map."""
    if isinstance(value, list):
        return [(v, None) for v in value]
    if isinstance(value, dict):
        return [(v, component) for component, members in value.items() for v in members or []]
    return []


def _with_evidence(match: ProductMatch, **evidence: str) -> ProductMatch:
    return match.model_copy(update={"evidence": match.evidence.model_copy(update=evidence)})
