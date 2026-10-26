"""The x/crypto usage tracker (the OCP "x/crypto usage tracking" workbook): per repository x
package, the best evidence (callgraph-reachable, then import, then vendored presence in the
pqc-facts) and a suggested Status the team owns."""

from __future__ import annotations

import re
from collections.abc import Callable, Sequence
from dataclasses import dataclass, field
from urllib.parse import urlsplit

from traust_core.v1.models.code_facts import XcryptoUsageFact
from traust_core.v1.models.pqc import PqcFact, XcryptoRow, XcryptoStatus, XcryptoTier
from traust_core.v1.models.vocabulary import PqcPathClass
from traust_core.v1.providers.xcrypto import XCRYPTO
from traust_core.v1.rendering.markdown import Table
from traust_core.v1.services.pqc.facts import path_class

U, A = XcryptoStatus.UNACCEPTABLE, XcryptoStatus.ACCEPTABLE
# Unacceptable?: classically broken or upstream-deprecated primitives (openpgp is deprecated
# upstream, pkcs12 carries RC2/SHA-1, ssh ships classical KEX incl. dh-group1-sha1). Acceptable?:
# sound classical crypto, IR 8547-acceptable now but on the 2035 clock where public-key.
STATUS = {
    "openpgp": U, "pkcs12": U, "otr": U, "cast5": U, "blowfish": U, "twofish": U, "tea": U,
    "xtea": U, "md4": U, "ripemd160": U, "ssh": U,
    "curve25519": A, "ed25519": A, "nacl": A, "chacha20": A, "chacha20poly1305": A, "salsa20": A,
    "poly1305": A, "hkdf": A, "pbkdf2": A, "scrypt": A, "argon2": A, "bcrypt": A, "acme": A,
    "ocsp": A, "cryptobyte": A, "sha3": A, "blake2b": A, "blake2s": A, "x509roots": A,
}  # fmt: skip
_NOTE = {
    U: "contains classically-broken/upstream-deprecated primitives",
    A: "sound classical crypto; IR 8547 2035 clock where public-key",
    XcryptoStatus.UNKNOWN: "no per-package suggestion table entry — needs team review",
}
_IN_FACT = re.compile(r"(?:golang\.org/)?x/crypto/([a-zA-Z0-9_]+)")
COLUMNS = (
    "product_org",
    "repository",
    "entrypoint",
    "crypto_module_used",
    "status_suggested",
    "comment",
    "dependency_graph",
    "evidence_tier",
)


def status(package: str) -> XcryptoStatus:
    base = package.removeprefix(XCRYPTO + "/").split("/")[0]
    return STATUS.get(base, XcryptoStatus.UNKNOWN)


@dataclass
class _Evidence:
    tier: XcryptoTier
    evidence: str = ""
    entrypoint: str | None = None
    functions: list[str] = field(default_factory=list)
    witness: tuple[str, ...] = ()


def _usage(usage: XcryptoUsageFact) -> dict[str, _Evidence]:
    found: dict[str, _Evidence] = {}
    for entry in usage.callgraph or ():
        for r in entry.reachable:
            e = found.get(r.package)
            if e is None or e.tier is not XcryptoTier.CALLGRAPH:
                e = found[r.package] = _Evidence(XcryptoTier.CALLGRAPH, entrypoint=entry.entrypoint)
            e.functions.append(r.function)
            e.witness = e.witness or r.witness
    for site in usage.imports:
        where = path_class(site.location.path)
        if where is PqcPathClass.VENDOR:
            continue
        tier = (
            XcryptoTier.FIRST_PARTY_IMPORT
            if where is PqcPathClass.FIRST_PARTY
            else XcryptoTier.TEST_DOCS_IMPORT
        )
        e = found.get(site.package)
        if e is None or (
            e.tier is XcryptoTier.TEST_DOCS_IMPORT and tier is XcryptoTier.FIRST_PARTY_IMPORT
        ):
            found[site.package] = _Evidence(tier, f"{site.location.path}:{site.location.line}")
    return found


def _presence(facts: Sequence[PqcFact]) -> dict[str, _Evidence]:
    found: dict[str, _Evidence] = {}
    for fact in facts:
        for m in _IN_FACT.finditer(f"{fact.file} {fact.detail}"):
            found.setdefault(
                f"{XCRYPTO}/{m.group(1)}",
                _Evidence(XcryptoTier.DEPENDENCY_PRESENCE, f"{fact.file}:{fact.line}"),
            )
    return found


def tracker(
    repository: str, usage: XcryptoUsageFact, facts: Callable[[], Sequence[PqcFact]]
) -> list[XcryptoRow]:
    """The repository's tracker rows, one per package; `facts` (its recorded pqc-facts) is read
    only when the checkout shows no x/crypto import, reachability or go.mod require."""
    modules = tuple(f"{m.path} {','.join(m.require)}" for m in usage.modules if m.require)
    found = _usage(usage)
    if not found and not modules:
        found = _presence(facts())
    org = urlsplit(repository).path.strip("/").split("/")[0]
    return [
        XcryptoRow(
            product_org=org,
            repository=repository,
            package=package,
            evidence_tier=e.tier,
            status_suggested=status(package),
            evidence=e.evidence,
            entrypoint=e.entrypoint,
            functions=tuple(sorted(set(e.functions))),
            witness=e.witness,
            modules=tuple(sorted(modules)),
        )
        for package, e in sorted(found.items())
    ]


def table(rows: Sequence[XcryptoRow]) -> Table:
    """The rows in the workbook's column order, as the legacy CSV wrote them."""

    def cells(r: XcryptoRow) -> tuple[str, ...]:
        reached = r.evidence_tier is XcryptoTier.CALLGRAPH
        evidence = "callgraph-reachable" if reached else r.evidence
        versions = f"; go.mod: {'; '.join(r.modules)}" if r.modules else ""
        return (
            r.product_org,
            r.repository,
            (r.entrypoint or "") if reached else "n/a — static scan",
            "; ".join(r.functions[:5]) if reached else r.package,
            r.status_suggested.value,
            f"{r.evidence_tier.value}: {evidence} — {_NOTE[r.status_suggested]}{versions}",
            (" -> ".join(r.witness) or "no path") if reached else "not computed (no callgraph)",
            r.evidence_tier.value,
        )

    return Table(columns=COLUMNS, rows=tuple(cells(r) for r in rows))
