"""Ownership of the object a Spring or JAX-RS id route acts on, read from its handler."""

from __future__ import annotations

import pytest

from traust_core.v1.providers.route_guards import route_guards
from traust_core.v1.providers.tree import tree_files

POM = "<project><dependency>spring-boot-starter-security</dependency></project>\n"
METHOD_SECURITY = (
    "import org.springframework.security.config.annotation.method.configuration.*;\n"
    "@EnableMethodSecurity class MethodSecurity {}\n"
)
ENTITIES = (
    "import jakarta.persistence.*;\n"
    "@Entity class Invoice { @Id Long id; String ownerId; long cents; }\n"
    "@Entity class Currency { @Id String code; String symbol; }\n"
    "interface InvoiceRepository extends JpaRepository<Invoice, Long> {\n"
    "  Optional<Invoice> findByIdAndOwnerId(Long id, String ownerId);\n}\n"
)
SERVICE = (
    "class InvoiceService {\n"
    "  private InvoiceRepository invoices;\n"
    "  private AuditTrail trail;\n"
    "  long total(Long invoiceId) { return invoices.findById(invoiceId).get().cents; }\n"
    "  void audit(Long invoiceId) { trail.record(invoiceId); }\n"
    "  Invoice checkInvoiceId(Long invoiceId) { return checkOwned(invoiceId); }\n"
    "  Invoice checkOwned(Long ref) {\n"
    "    Invoice inv = invoices.findById(ref).orElseThrow();\n"
    "    String me = SecurityContextHolder.getContext().getAuthentication().getName();\n"
    "    if (!inv.ownerId.equals(me)) {\n"
    "      throw new IllegalStateException();\n    }\n"
    "    trail.record(ref);\n"
    "    return inv;\n  }\n"
    "  Invoice loadInvoice(Long invoiceId) { return fetchDeep(invoiceId); }\n"
    "  Invoice fetchDeep(Long ref) { return invoices.findById(ref).orElseThrow(); }\n}\n"
    "class AuditTrail { void record(Long id) {} }\n"
)
CONTROLLER = (
    "import org.springframework.web.bind.annotation.*;\n"
    "import org.springframework.security.core.Authentication;\n"
    "import java.security.Principal;\n"
    '@RestController @RequestMapping("/api")\n'
    "class Billing {\n"
    "  private EntityManager em;\n"
    "  private InvoiceRepository invoices;\n"
    "  private InvoiceService service;\n"
    '  @GetMapping("/invoices/{id}") Invoice get(@PathVariable Long id) {\n'
    "    return em.find(Invoice.class, id);\n  }\n"
    '  @GetMapping("/mine/{id}") Invoice mine(@PathVariable Long id, Principal me) {\n'
    "    return invoices.findByIdAndOwnerId(id, me.getName()).orElseThrow();\n  }\n"
    '  @GetMapping("/filtered/{id}") Invoice filtered(@PathVariable Long id, Principal me) {\n'
    "    return invoices.findById(id).filter(i -> i.ownerId.equals(me.getName())).orElseThrow();\n"
    "  }\n"
    '  @DeleteMapping("/invoices/{id}") void remove(@PathVariable Long id, Authentication auth) {\n'
    "    Invoice inv = invoices.findById(id).orElseThrow();\n"
    "    if (!inv.ownerId.equals(auth.getName())) { throw new IllegalStateException(); }\n"
    "    invoices.deleteById(id);\n  }\n"
    '  @PreAuthorize("@access.canEdit(#id, authentication)")\n'
    '  @PutMapping("/invoices/{id}") void edit(@PathVariable Long id) {\n'
    "    invoices.findById(id);\n  }\n"
    '  @GetMapping("/currencies/{code}") Currency currency(@PathVariable String code) {\n'
    "    return em.find(Currency.class, code);\n  }\n"
    '  @GetMapping("/invoices/{id}/total") long total(@PathVariable("id") Long invoiceId) {\n'
    "    return service.total(invoiceId);\n  }\n"
    '  @GetMapping("/invoices/{id}/audit") void audit(@PathVariable Long id) {\n'
    "    service.audit(id);\n  }\n"
    '  @GetMapping("/checked/{id}") Invoice checkedTwice(@PathVariable Long id) {\n'
    "    return service.checkInvoiceId(id);\n  }\n"
    '  @GetMapping("/deep/{id}") Invoice deep(@PathVariable Long id) {\n'
    "    return service.loadInvoice(id);\n  }\n"
    '  @GetMapping("/raw/{id}") Invoice raw(@PathVariable Long id, Principal me) {\n'
    "    System.out.println(me.getName());\n"
    "    return em.find(Invoice.class, id);\n  }\n"
    "  @PreAuthorize(\"hasRole('ADMIN')\")\n"
    '  @DeleteMapping("/admin/invoices/{id}") void purge(@PathVariable Long id) {\n'
    "    invoices.deleteById(id);\n  }\n"
    "  @PreAuthorize(\"hasAnyRole('ADMIN', 'CLERK')\")\n"
    '  @GetMapping("/clerk/invoices/{id}") Invoice clerk(@PathVariable Long id) {\n'
    "    return em.find(Invoice.class, id);\n  }\n"
    '  @GetMapping("/invoices") Object list() { return null; }\n'
    '  @GetMapping("/owned/{id}") Invoice owned(@PathVariable Long id) {\n'
    "    return invoices.findByIdAndOwnerId(id, currentOwner()).orElseThrow();\n  }\n"
    '  @GetMapping("/keyed/{raw}") Invoice keyed(@PathVariable String raw) {\n'
    "    Long key = Long.valueOf(raw);\n"
    "    return em.find(Invoice.class, key);\n  }\n"
    '  @GetMapping("/logged/{id}") Invoice logged(@PathVariable Long id, Principal me) {\n'
    "    log.info(id, me.getName());\n"
    "    return this.invoices.findById(id).orElseThrow();\n  }\n"
    '  @GetMapping("/permitted/{id}") Invoice permitted(@PathVariable Long id) {\n'
    "    access.checkPermission(currentOwner(), id);\n"
    "    return invoices.findById(id).orElseThrow();\n  }\n"
    '  @GetMapping("/self/{id}") long self(@PathVariable Long id) { return this.sum(id); }\n'
    "  long sum(Long ref) { return invoices.findById(ref).get().cents; }\n"
    "  String currentOwner() { return principal().getName(); }\n"
    "  Authentication principal() {\n"
    "    return SecurityContextHolder.getContext().getAuthentication();\n  }\n"
    "}\n"
)
RESOURCE = (
    "import jakarta.ws.rs.*;\n"
    "import jakarta.annotation.security.RolesAllowed;\n"
    '@Path("/docs") @RolesAllowed("reader")\n'
    "class Docs {\n"
    "  @Inject SecurityIdentity identity;\n"
    "  private DocStore store;\n"
    '  @GET @Path("/{id}") Doc get(@PathParam("id") String id) {\n'
    "    return store.owned(id, identity.getPrincipal().getName());\n  }\n"
    '  @DELETE @Path("/{id}") void delete(@PathParam("id") String id) {}\n'
    '  @GET @Path("/{id}/peek") Doc peek(@PathParam("id") String id) {\n'
    "    return store.find(id);\n  }\n"
    '  @GET @Path("/{id}/careless") Doc careless(@PathParam("id") String id) {\n'
    "    return store.careless(id, identity.getPrincipal().getName());\n  }\n"
    "}\n"
    "class Doc { String id; String owner; }\n"
    "class DocStore {\n"
    "  private Map<String, Doc> byId;\n"
    "  Doc find(String id) { return byId.get(id); }\n"
    "  Doc owned(String id, String owner) {\n"
    "    Doc d = byId.get(id);\n"
    "    return d != null && d.owner.equals(owner) ? d : null;\n  }\n"
    "  Doc careless(String id, String owner) { return byId.get(id); }\n}\n"
)


@pytest.fixture(scope="module")
def result(tmp_path_factory: pytest.TempPathFactory) -> dict:
    root = tmp_path_factory.mktemp("billing")
    for rel, text in {
        "pom.xml": POM,
        "src/main/java/billing/MethodSecurity.java": METHOD_SECURITY,
        "src/main/java/billing/Model.java": ENTITIES,
        "src/main/java/billing/InvoiceService.java": SERVICE,
        "src/main/java/billing/Billing.java": CONTROLLER,
        "src/main/java/docs/Docs.java": RESOURCE,
    }.items():
        path = root / rel
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(text)
    return route_guards(tree_files(root)).model_dump(mode="json")


def _row(result: dict, method: str, pattern: str) -> dict:
    [row] = [r for r in result["routes"] if r["method"] == method and r["pattern"] == pattern]
    return row


@pytest.mark.parametrize(
    ("method", "pattern", "ownership", "judged"),
    [
        ("GET", "/api/invoices/{id}", "caller-blind", True),
        ("GET", "/api/mine/{id}", "scoped", False),
        ("GET", "/api/filtered/{id}", "unchecked", True),  # a filter lambda: not an allowed shape
        ("DELETE", "/api/invoices/{id}", "checked", False),
        ("PUT", "/api/invoices/{id}", "checked", False),
        ("GET", "/api/currencies/{code}", "none", False),
        ("GET", "/api/invoices/{id}/total", "caller-blind", True),
        ("GET", "/api/invoices/{id}/audit", "unknown", False),
        ("GET", "/api/checked/{id}", "checked", False),
        ("GET", "/api/deep/{id}", "unknown", False),
        ("GET", "/api/raw/{id}", "unchecked", True),
        ("DELETE", "/api/admin/invoices/{id}", "n/a", False),
        ("GET", "/api/clerk/invoices/{id}", "caller-blind", True),
        ("GET", "/api/invoices", "n/a", False),
        ("GET", "/docs/{id}", "checked", False),  # returned only when owned (shape 5)
        ("DELETE", "/docs/{id}", "caller-blind", True),
        ("GET", "/api/owned/{id}", "scoped", False),
        ("GET", "/api/keyed/{raw}", "caller-blind", True),
        ("GET", "/api/logged/{id}", "unchecked", True),
        ("GET", "/api/permitted/{id}", "unchecked", True),  # a check-shaped name proves nothing
        ("GET", "/api/self/{id}", "caller-blind", True),
        ("GET", "/docs/{id}/peek", "caller-blind", True),
        ("GET", "/docs/{id}/careless", "unchecked", True),
    ],
)
def test_ownership_of_each_route(
    result: dict, method: str, pattern: str, ownership: str, judged: bool
) -> None:
    row = _row(result, method, pattern)
    assert row["ownership"] == ownership
    assert row["judgement_required"] is judged


def test_an_owner_bearing_entity_names_its_owner_field(result: dict) -> None:
    evidence = _row(result, "GET", "/api/invoices/{id}")["ownership_evidence"]
    assert (evidence["record_type"], evidence["owner_field"]) == ("Invoice", "ownerId")
    assert evidence["lookup"]["line"] == 10 and evidence["caller"] is None


def test_a_hop_lookup_carries_its_repository_entity_and_the_call_site(result: dict) -> None:
    evidence = _row(result, "GET", "/api/invoices/{id}/total")["ownership_evidence"]
    assert (evidence["record_type"], evidence["owner_field"]) == ("Invoice", "ownerId")
    assert evidence["hop"]["path"] == "src/main/java/billing/Billing.java"
    assert evidence["lookup"]["path"] == "src/main/java/billing/InvoiceService.java"


def test_a_store_lookup_takes_the_record_type_its_method_returns(result: dict) -> None:
    evidence = _row(result, "GET", "/docs/{id}/peek")["ownership_evidence"]
    assert (evidence["record_type"], evidence["owner_field"]) == ("Doc", "owner")


def test_method_security_naming_the_id_is_the_check(result: dict) -> None:
    evidence = _row(result, "PUT", "/api/invoices/{id}")["ownership_evidence"]
    assert evidence["check"]["path"] == "src/main/java/billing/Billing.java"


def test_owner_bearing_judged_rows_sort_ahead_of_unresolved_ones(result: dict) -> None:
    judged = [r for r in result["routes"] if r["ownership"] in ("caller-blind", "unchecked")]
    owners = [bool(r["ownership_evidence"]["owner_field"]) for r in judged]
    assert owners == sorted(owners, reverse=True)


# Code that looks protected but isn't: each must stay judged beside a correct twin.
LEDGER = (
    "import org.springframework.web.bind.annotation.*;\n"
    "import java.security.Principal;\n"
    "interface LedgerApi {\n"
    '  @GetMapping("/ledger/{id}") Entry byInterface(@PathVariable("id") Long id);\n}\n'
    "class Entry { Long id; String ownerId; long cents; }\n"
    "class OwnedRecord { String ownerId; }\n"
    "class Document extends OwnedRecord { Long id; String body; }\n"
    "class Memo extends ExternalBase { Long id; String body; }\n"
    "interface EntryRepository extends JpaRepository<Entry, Long> {\n"
    "  Optional<Entry> findByIdAndOwnerId(Long id, String ownerId);\n}\n"
    '@RestController @RequestMapping("/v")\n'
    "class Ledger implements LedgerApi {\n"
    "  private EntryRepository entries;\n"
    "  private EntityManager em;\n"
    "  private Access access;\n"
    "  public Entry byInterface(Long id) { return entries.findById(id).orElseThrow(); }\n"
    '  @GetMapping("/logs/{id}") Entry logs(@PathVariable Long id, Principal me) {\n'
    "    Entry e = entries.findById(id).orElseThrow();\n"
    '    if (e.ownerId.equals(me.getName())) { System.out.println("owner"); }\n'
    "    return e;\n  }\n"
    '  @GetMapping("/unrelated/{id}") Entry unrelated(@PathVariable Long id, Principal me) {\n'
    "    Entry e = entries.findById(id).orElseThrow();\n"
    "    if (e.cents > 0 && me != null) { throw new IllegalStateException(); }\n"
    "    return e;\n  }\n"
    '  @GetMapping("/positive/{id}") Entry positive(@PathVariable Long id, Principal me) {\n'
    "    Entry e = entries.findById(id).orElseThrow();\n"
    "    if (e.ownerId.equals(me.getName())) { return e; }\n"
    "    throw new IllegalStateException();\n  }\n"
    '  @GetMapping("/advisory/{id}") Entry advisory(@PathVariable Long id, Principal me) {\n'
    '    if (access.canRead(me.getName(), id)) { System.out.println("ok"); }\n'
    "    return entries.findById(id).orElseThrow();\n  }\n"
    '  @GetMapping("/enforced/{id}") Entry enforced(@PathVariable Long id, Principal me) {\n'
    "    if (!access.canRead(me.getName(), id)) { throw new IllegalStateException(); }\n"
    "    return entries.findById(id).orElseThrow();\n  }\n"
    '  @GetMapping("/mapped/{id}") Object mapped(@PathVariable Long id, Principal me) {\n'
    "    return entries.findById(id).map(e -> new Object[] {e, me.getName()}).orElseThrow();\n"
    "  }\n"
    '  @DeleteMapping("/late/{id}") void late(@PathVariable Long id, Principal me) {\n'
    "    entries.deleteById(id);\n"
    "    access.checkPermission(me.getName(), id);\n  }\n"
    '  @GetMapping("/branch/{id}") Entry branch(@PathVariable Long id, Principal me, boolean f) {\n'
    "    if (f) { entries.findByIdAndOwnerId(id, me.getName()); }\n"
    "    return entries.findById(id).orElseThrow();\n  }\n"
    "  @PreAuthorize(\"#format == 'pdf'\")\n"
    '  @GetMapping("/format/{id}")\n'
    "  Entry format(@PathVariable Long id, @RequestParam String format) {\n"
    "    return entries.findById(id).orElseThrow();\n  }\n"
    "  @PreAuthorize(\"#id.equals('demo')\")\n"
    '  @GetMapping("/demo/{id}") Entry demo(@PathVariable String id) {\n'
    "    return entries.findById(Long.valueOf(id)).orElseThrow();\n  }\n"
    '  @PostAuthorize("returnObject.ownerId == authentication.name")\n'
    '  @GetMapping("/returned/{id}") Entry returned(@PathVariable Long id) {\n'
    "    return entries.findById(id).orElseThrow();\n  }\n"
    '  @GetMapping("/documents/{id}") Document document(@PathVariable Long id) {\n'
    "    return em.find(Document.class, id);\n  }\n"
    '  @GetMapping("/memos/{id}") Memo memo(@PathVariable Long id) {\n'
    "    return em.find(Memo.class, id);\n  }\n"
    "}\n"
    '@RestController @RequestMapping("/guarded")\n'
    '@PreAuthorize("@access.canRead(#id, authentication)")\n'
    "class Guarded {\n"
    "  private EntryRepository entries;\n"
    '  @GetMapping("/{id}") Entry get(@PathVariable Long id) {\n'
    "    return entries.findById(id).orElseThrow();\n  }\n"
    "}\n"
)


@pytest.fixture(scope="module")
def ledger(tmp_path_factory: pytest.TempPathFactory) -> dict:
    root = tmp_path_factory.mktemp("ledger")
    for rel, text in {
        "pom.xml": POM,
        "src/main/java/ledger/MethodSecurity.java": METHOD_SECURITY,
        "src/main/java/ledger/Ledger.java": LEDGER,
    }.items():
        path = root / rel
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(text)
    return route_guards(tree_files(root)).model_dump(mode="json")


@pytest.mark.parametrize(
    ("method", "pattern", "ownership"),
    [
        ("GET", "/v/logs/{id}", "unchecked"),  # the condition doesn't deny
        ("GET", "/v/unrelated/{id}", "unchecked"),  # compares nothing with the caller
        ("GET", "/v/positive/{id}", "unchecked"),  # equal → returns: not an allowed shape
        ("GET", "/v/advisory/{id}", "unchecked"),  # an authorization result left unused
        ("GET", "/v/enforced/{id}", "unchecked"),  # a helper we can't follow, credited by name
        ("GET", "/v/mapped/{id}", "unchecked"),  # the caller added to output, not a filter
        ("DELETE", "/v/late/{id}", "unchecked"),  # the delete runs before the check
        ("GET", "/v/branch/{id}", "unchecked"),  # the scoped lookup sits in an optional branch
        ("GET", "/v/format/{id}", "caller-blind"),  # method security on another parameter
        ("GET", "/v/demo/{id}", "caller-blind"),  # names the id, compares it with a constant
        ("GET", "/v/returned/{id}", "caller-blind"),  # @PostAuthorize runs after the handler
        ("GET", "/v/ledger/{id}", "caller-blind"),  # @PathVariable on the interface
        ("GET", "/v/documents/{id}", "caller-blind"),  # owner field inherited
        ("GET", "/v/memos/{id}", "caller-blind"),  # superclass outside the checkout: not ownerless
        ("GET", "/guarded/{id}", "checked"),  # class-level object security
    ],
)
def test_protection_has_to_be_enforced_to_count(
    ledger: dict, method: str, pattern: str, ownership: str
) -> None:
    row = _row(ledger, method, pattern)
    assert row["ownership"] == ownership
    assert row["judgement_required"] is (ownership in ("caller-blind", "unchecked"))


def test_an_inherited_owner_field_is_named(ledger: dict) -> None:
    evidence = _row(ledger, "GET", "/v/documents/{id}")["ownership_evidence"]
    assert (evidence["record_type"], evidence["owner_field"]) == ("Document", "ownerId")


# Shapes an independent review found credited without protection; each must stay judged.
PROBE = (
    "package probe;\n"
    "import org.springframework.web.bind.annotation.*;\n"
    "import java.security.Principal;\n"
    "class Card { Long id; String ownerEmail; long cents; }\n"
    "class Task { Long id; Long projectId; }\n"
    "interface CardRepository extends JpaRepository<Card, Long> {\n"
    "  Optional<Card> findByIdAndOwnerEmail(Long id, String ownerEmail);\n"
    "  Optional<Card> findByIdOrOwnerEmail(Long id, String ownerEmail);\n"
    "  boolean existsByIdAndOwnerEmail(Long id, String ownerEmail);\n}\n"
    "interface CardFinder { Card find(Long id, String owner); }\n"
    "class LooseFinder implements CardFinder {\n"
    "  private CardRepository cards;\n"
    "  public Card find(Long id, String owner) { return cards.findById(id).orElseThrow(); }\n}\n"
    "class Base { protected CardFinder finder; }\n"
    '@RestController @RequestMapping("/p")\n'
    "class Probe extends Base {\n"
    "  private CardRepository cards;\n"
    "  private Access access;\n"
    "  private EntityManager em;\n"
    "  private JdbcTemplate jdbc;\n"
    '  @GetMapping("/try/{id}") Card tried(@PathVariable Long id, Principal me) {\n'
    "    Card c = cards.findById(id).orElseThrow();\n"
    "    try { if (!c.ownerEmail.equals(me.getName())) throw new IllegalStateException(); }\n"
    "    catch (RuntimeException ex) { }\n"
    "    return c;\n  }\n"
    '  @GetMapping("/lambda/{id}") Card lambda(@PathVariable Long id, Principal me) {\n'
    "    Card c = cards.findById(id).orElseThrow();\n"
    "    Runnable r = () -> { if (!c.ownerEmail.equals(me.getName())) throw new"
    " IllegalStateException(); };\n"
    "    return c;\n  }\n"
    '  @GetMapping("/nested/{id}") Card nested(@PathVariable Long id, Principal me, boolean s) {\n'
    "    Card c = cards.findById(id).orElseThrow();\n"
    "    if (s) { if (!c.ownerEmail.equals(me.getName())) throw new IllegalStateException(); }\n"
    "    return c;\n  }\n"
    '  @GetMapping("/early/{id}") Card early(@PathVariable Long id, Principal me) {\n'
    "    Card c = cards.findById(id).orElseThrow();\n"
    "    if (c.cents == 0) return c;\n"
    "    if (!c.ownerEmail.equals(me.getName())) throw new IllegalStateException();\n"
    "    return c;\n  }\n"
    '  @PutMapping("/mutated/{id}") void mutated(@PathVariable Long id, Principal me) {\n'
    "    Card c = cards.findById(id).orElseThrow();\n"
    "    c.cents = 0;\n"
    "    cards.save(c);\n"
    "    if (!c.ownerEmail.equals(me.getName())) throw new IllegalStateException();\n  }\n"
    '  @GetMapping("/unrelated-deny/{id}") Card unrelatedDeny(@PathVariable Long id, Principal me)'
    " {\n"
    "    Card c = cards.findById(id).orElseThrow();\n"
    '    if (c.ownerEmail.equals(me.getName())) { System.out.println("owner"); }\n'
    "    if (c.cents < 0) { throw new IllegalStateException(); }\n"
    "    return c;\n  }\n"
    '  @GetMapping("/worded/{id}") Card worded(@PathVariable Long id, Principal me) {\n'
    "    Card c = cards.findById(id).orElseThrow();\n"
    '    if (!c.ownerEmail.equals(me.getName())) System.out.println("forbidden access");\n'
    "    return c;\n  }\n"
    '  @DeleteMapping("/can/{id}") void can(@PathVariable Long id, Principal me) {\n'
    "    access.canDelete(me.getName(), id);\n"
    "    cards.deleteById(id);\n  }\n"
    '  @DeleteMapping("/swallowed/{id}") void swallowed(@PathVariable Long id, Principal me) {\n'
    "    try { access.checkOwner(me.getName(), id); } catch (Exception ex) { }\n"
    "    cards.deleteById(id);\n  }\n"
    '  @DeleteMapping("/ignored/{id}") void ignored(@PathVariable Long id, Principal me) {\n'
    "    Optional<Card> mine = cards.findByIdAndOwnerEmail(id, me.getName());\n"
    "    cards.deleteById(id);\n  }\n"
    '  @DeleteMapping("/unchecked-exists/{id}") void uncheckedExists(@PathVariable Long id,'
    " Principal me) {\n"
    '    if (!cards.existsByIdAndOwnerEmail(id, me.getName())) { System.out.println("x"); }\n'
    "    cards.deleteById(id);\n  }\n"
    '  @DeleteMapping("/enforced-exists/{id}") void enforcedExists(@PathVariable Long id,'
    " Principal me) {\n"
    "    if (!cards.existsByIdAndOwnerEmail(id, me.getName())) { throw new"
    " IllegalStateException(); }\n"
    "    cards.deleteById(id);\n  }\n"
    '  @DeleteMapping("/thrown/{id}") void thrown(@PathVariable Long id, Principal me) {\n'
    "    cards.findByIdAndOwnerEmail(id, me.getName()).orElseThrow();\n"
    "    cards.deleteById(id);\n  }\n"
    '  @PreAuthorize("@access.canReadProject(#pid, authentication)")\n'
    '  @GetMapping("/projects/{pid}/cards/{cid}") Card two(@PathVariable Long pid, @PathVariable'
    " Long cid) {\n"
    "    return cards.findById(cid).orElseThrow();\n  }\n"
    '  @PreAuthorize("@rateLimiter.allow(#id)")\n'
    '  @GetMapping("/limited/{id}") Card limited(@PathVariable Long id) {\n'
    "    return cards.findById(id).orElseThrow();\n  }\n"
    '  @PostAuthorize("returnObject.ownerEmail == authentication.name")\n'
    '  @DeleteMapping("/after/{id}") Card after(@PathVariable Long id) {\n'
    "    Card c = cards.findById(id).orElseThrow();\n"
    "    cards.deleteById(id);\n"
    "    return c;\n  }\n"
    '  @GetMapping("/as/{id}") Card as(@PathVariable Long id, @RequestParam String as, Principal'
    " me) {\n"
    "    String owner = as != null ? as : me.getName();\n"
    "    return cards.findByIdAndOwnerEmail(id, owner).orElseThrow();\n  }\n"
    '  @GetMapping("/nonnull/{id}") Card nonnull(@PathVariable Long id, Principal me) {\n'
    "    return cards.findById(id).filter(c -> me != null).orElseThrow();\n  }\n"
    '  @GetMapping("/or/{id}") Card or(@PathVariable Long id, Principal me) {\n'
    "    return cards.findByIdOrOwnerEmail(id, me.getName()).orElseThrow();\n  }\n"
    '  @GetMapping("/iface/{id}") Card iface(@PathVariable Long id, Principal me) {\n'
    "    return finder.find(id, me.getName());\n  }\n"
    '  @GetMapping("/created/{id}") Card created(@PathVariable Long id, Principal me) {\n'
    "    return new LooseFinder().find(id, me.getName());\n  }\n"
    '  @GetMapping("/jpql/{id}") Object jpql(@PathVariable Long id) {\n'
    '    return em.createQuery("from Card c where c.id = :id").setParameter("id",'
    " id).getSingleResult();\n"
    "  }\n"
    '  @GetMapping("/jdbc/{id}") Object jdbc(@PathVariable Long id) {\n'
    '    return jdbc.queryForObject("select * from card where id = ?", Object.class, id);\n  }\n'
    '  @GetMapping("/trim/{id}") Card trim(@PathVariable String id) {\n'
    "    String key = id.trim();\n"
    "    return cards.findById(Long.valueOf(key)).orElseThrow();\n  }\n"
    '  @GetMapping("/map/{id}") Card map(@PathVariable Map<String, String> vars) {\n'
    '    return cards.findById(Long.valueOf(vars.get("id"))).orElseThrow();\n  }\n'
    '  @GetMapping("/form/{id}") Card form(CardForm form) {\n'
    "    return cards.findById(form.id).orElseThrow();\n  }\n"
    '  @GetMapping("/tasks/{id}") Task task(@PathVariable Long id) {\n'
    "    return em.find(Task.class, id);\n  }\n"
    '  @GetMapping("/emails/{id}") Card email(@PathVariable Long id) {\n'
    "    return em.find(Card.class, id);\n  }\n"
    "  @RolesAllowed({Roles.ADMIN, Roles.USER})\n"
    '  @GetMapping("/roles/{id}") Card roles(@PathVariable Long id) {\n'
    "    return cards.findById(id).orElseThrow();\n  }\n"
    '  @GetMapping("/doubled/{id}") Card doubled(@PathVariable Long id, Principal me) {\n'
    "    Card c = cards.findById(id).orElseThrow();\n"
    "    if (!c.ownerEmail.equals(me.getName()) == false) throw new IllegalStateException();\n"
    "    return c;\n  }\n"
    '  @GetMapping("/inline-as/{id}") Card inlineAs(@PathVariable Long id, @RequestParam String'
    " as, Principal me) {\n"
    "    return cards.findByIdAndOwnerEmail(id, as != null ? as : me.getName()).orElseThrow();\n "
    " }\n"
    '  @GetMapping("/finder/{id}") Card viaFinder(@PathVariable Long id, Principal me) {\n'
    "    return load(id, me, cards::findByIdAndOwnerEmail);\n  }\n"
    "  Card load(Long id, Principal me, java.util.function.BiFunction<Long, String, Card> finder)"
    " {\n"
    "    Card c = finder.apply(id, me.getName());\n"
    "    return c;\n  }\n"
    '  @GetMapping("/finder-request/{id}") Card viaFinderRequest(@PathVariable Long id,'
    " @RequestParam String who) {\n"
    "    return loadFor(id, who, cards::findByIdAndOwnerEmail);\n  }\n"
    "  Card loadFor(Long id, String who, java.util.function.BiFunction<Long, String, Card> finder)"
    " {\n"
    "    Card c = finder.apply(id, who);\n"
    "    return c;\n  }\n"
    '  @DeleteMapping("/reassigned/{id}") void reassigned(@PathVariable Long id, Principal me,'
    " Long other) {\n"
    "    cards.findByIdAndOwnerEmail(id, me.getName()).orElseThrow();\n"
    "    id = other;\n"
    "    cards.deleteById(id);\n  }\n"
    "}\n"
)


@pytest.fixture(scope="module")
def probe(tmp_path_factory: pytest.TempPathFactory) -> dict:
    root = tmp_path_factory.mktemp("probe")
    for rel, text in {
        "pom.xml": POM,
        "src/main/java/probe/MethodSecurity.java": METHOD_SECURITY,
        "src/main/java/probe/Probe.java": PROBE,
    }.items():
        path = root / rel
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(text)
    return route_guards(tree_files(root)).model_dump(mode="json")


@pytest.mark.parametrize(
    ("method", "pattern", "ownership"),
    [
        ("GET", "/p/try/{id}", "unchecked"),  # the check is in a try that swallows it
        ("GET", "/p/lambda/{id}", "unchecked"),  # the check never runs
        ("GET", "/p/nested/{id}", "unchecked"),  # only under another condition
        ("GET", "/p/early/{id}", "unchecked"),  # returned before the check
        ("PUT", "/p/mutated/{id}", "unchecked"),  # saved before the check
        ("GET", "/p/unrelated-deny/{id}", "unchecked"),  # the denial belongs to another test
        ("GET", "/p/worded/{id}", "unchecked"),  # "forbidden" in a log line isn't a denial
        ("DELETE", "/p/can/{id}", "unchecked"),  # a boolean authorization thrown away
        ("DELETE", "/p/swallowed/{id}", "unchecked"),  # the check's exception is caught
        ("DELETE", "/p/ignored/{id}", "unchecked"),  # a scoped lookup whose result is ignored
        ("DELETE", "/p/unchecked-exists/{id}", "unchecked"),  # nothing refused when absent
        ("DELETE", "/p/enforced-exists/{id}", "checked"),  # refused when absent: the id is verified
        ("DELETE", "/p/thrown/{id}", "checked"),  # orElseThrow: verified
        ("GET", "/p/projects/{pid}/cards/{cid}", "caller-blind"),  # security names the other id
        ("GET", "/p/limited/{id}", "caller-blind"),  # a bean call without the caller
        ("DELETE", "/p/after/{id}", "caller-blind"),  # PostAuthorize runs after the delete
        ("GET", "/p/as/{id}", "unchecked"),  # a request value can stand in for the caller
        ("GET", "/p/nonnull/{id}", "unchecked"),  # the filter compares nothing with the record
        ("GET", "/p/or/{id}", "unchecked"),  # an Or-query doesn't narrow to the caller
        ("GET", "/p/iface/{id}", "unchecked"),  # through an inherited interface field
        ("GET", "/p/created/{id}", "unchecked"),  # through `new Impl()`
        ("GET", "/p/jpql/{id}", "caller-blind"),  # a JPQL parameter is a lookup
        ("GET", "/p/jdbc/{id}", "caller-blind"),  # JdbcTemplate by id
        ("GET", "/p/trim/{id}", "caller-blind"),  # a trimmed id is the id
        ("GET", "/p/map/{id}", "caller-blind"),  # @PathVariable Map
        ("GET", "/p/form/{id}", "unknown"),  # a command object: the id isn't followed
        ("GET", "/p/tasks/{id}", "caller-blind"),  # projectId: indirect tenancy
        ("GET", "/p/emails/{id}", "caller-blind"),  # ownerEmail is an owner field
        ("GET", "/p/roles/{id}", "caller-blind"),  # Roles.USER admits ordinary users
        ("GET", "/p/doubled/{id}", "unchecked"),  # `!owner == false` denies the owner
        ("DELETE", "/p/reassigned/{id}", "unchecked"),  # the id changed after the check
        ("GET", "/p/inline-as/{id}", "unchecked"),  # a mixed value inline isn't the caller
        (
            "GET",
            "/p/finder/{id}",
            "scoped",
        ),  # a load handed a caller value: trusted
        ("GET", "/p/finder-request/{id}", "caller-blind"),  # handed request data, not the caller
    ],
)
def test_protection_that_doesnt_hold_stays_judged(
    probe: dict, method: str, pattern: str, ownership: str
) -> None:
    row = _row(probe, method, pattern)
    assert row["ownership"] == ownership
    assert row["judgement_required"] is (ownership in ("caller-blind", "unchecked"))


# Shapes without protection, each beside a correct twin that the allow-list credits.
REVIEW = (
    "package review;\n"
    "import org.springframework.web.bind.annotation.*;\n"
    "import java.security.Principal;\n"
    "class Card { Long id; String ownerEmail; long cents; }\n"
    "class Note { Long id; String username; }\n"
    "class Patient { Long id; String ownerId; }\n"
    "class Visit { Long id; Patient patient; }\n"
    "class Result<T> { T value; }\n"
    "interface CardRepository extends JpaRepository<Card, Long> {\n"
    "  Optional<Card> findByIdAndOwnerEmail(Long id, String ownerEmail);\n}\n"
    "class CardGuard {\n"
    "  private CardRepository cards;\n"
    "  void checkCard(Long id, String me) {\n"
    "    Card c = cards.findById(id).orElseThrow();\n"
    "    if (!c.ownerEmail.equals(me)) throw new IllegalStateException();\n  }\n"
    "  void checkPair(Long pid, Long cid, String me) {\n"
    "    Card c = cards.findById(cid).orElseThrow();\n"
    "    if (!c.ownerEmail.equals(me)) throw new IllegalStateException();\n  }\n}\n"
    "class Guards { static void verifyOwner(Long id, String me) {} }\n"
    "class Session {\n"
    "  String owner() {\n"
    "    return SecurityContextHolder.getContext().getAuthentication().getName();\n  }\n}\n"
    "class Reader {\n"
    "  private JdbcTemplate jdbc;\n"
    "  Result<Card> fetch(Long id) {\n"
    '    return new Result<>(jdbc.queryForObject("select * from card where id = ?",'
    " Card.class, id));\n"
    "  }\n}\n"
    '@RestController @RequestMapping("/r")\n'
    "class Review {\n"
    "  private CardRepository cards;\n"
    "  private CardGuard guard;\n"
    "  private Reader reader;\n"
    "  private EntityManager em;\n"
    "  private Orders orders;\n"
    "  private String lastSeen;\n"
    '  @GetMapping("/and/{id}") Card and(@PathVariable Long id, Principal me) {\n'
    "    Card c = cards.findById(id).orElseThrow();\n"
    "    if (!c.ownerEmail.equals(me.getName()) && c.cents > 0)"
    " throw new IllegalStateException();\n"
    "    return c;\n  }\n"
    '  @GetMapping("/null-or/{id}") Card nullOr(@PathVariable Long id, Principal me) {\n'
    "    Card c = cards.findById(id).orElse(null);\n"
    "    if (c == null || !c.ownerEmail.equals(me.getName()))"
    " throw new IllegalStateException();\n"
    "    return c;\n  }\n"
    '  @GetMapping("/objects/{id}") Card objects(@PathVariable Long id, Principal me) {\n'
    "    Card c = cards.findById(id).orElseThrow();\n"
    "    if (!Objects.equals(c.ownerEmail, me.getName()))"
    " { throw new IllegalStateException(); }\n"
    "    return c;\n  }\n"
    '  @GetMapping("/getter/{id}") Card getter(@PathVariable Long id, Principal me) {\n'
    "    Card c = cards.findById(id).orElseThrow();\n"
    "    if (!me.getName().equals(c.getOwnerEmail())) throw new IllegalStateException();\n"
    "    return c;\n  }\n"
    '  @GetMapping("/forbidden/{id}") Object forbidden(@PathVariable Long id, Principal me) {\n'
    "    Card c = cards.findById(id).orElseThrow();\n"
    "    if (!c.ownerEmail.equals(me.getName()))"
    " return ResponseEntity.status(FORBIDDEN).body(c);\n"
    "    return c;\n  }\n"
    '  @GetMapping("/later/{id}") Card later(@PathVariable Long id, Principal me) {\n'
    "    Card c = cards.findById(id).orElseThrow();\n"
    "    orders.touch(c);\n"
    "    if (!c.ownerEmail.equals(me.getName())) throw new IllegalStateException();\n"
    "    return c;\n  }\n"
    '  @GetMapping("/checkout/{id}") Card checkout(@PathVariable Long id) {\n'
    "    orders.checkout(id);\n"
    "    return cards.findById(id).orElseThrow();\n  }\n"
    '  @GetMapping("/static/{id}") Card viaStatic(@PathVariable Long id, Principal me) {\n'
    "    Guards.verifyOwner(id, me.getName());\n"
    "    return cards.findById(id).orElseThrow();\n  }\n"
    '  @GetMapping("/guarded/{id}") Card guarded(@PathVariable Long id, Principal me) {\n'
    "    guard.checkCard(id, me.getName());\n"
    "    return cards.findById(id).orElseThrow();\n  }\n"
    '  @GetMapping("/projects/{pid}/cards/{cid}")\n'
    "  Card other(@PathVariable Long pid, @PathVariable Long cid, Principal me) {\n"
    "    guard.checkCard(cid, me.getName());\n"
    "    return cards.findById(pid).orElseThrow();\n  }\n"
    '  @GetMapping("/pairs/{pid}/{cid}")\n'
    "  Card pair(@PathVariable Long pid, @PathVariable Long cid, Principal me) {\n"
    "    guard.checkPair(pid, cid, me.getName());\n"
    "    return cards.findById(pid).orElseThrow();\n  }\n"
    '  @GetMapping("/result/{id}") Result<Card> result(@PathVariable Long id) {\n'
    "    return reader.fetch(id);\n  }\n"
    '  @GetMapping("/notes/{id}") Note note(@PathVariable Long id) {\n'
    "    return em.find(Note.class, id);\n  }\n"
    '  @GetMapping("/visits/{id}") Visit visit(@PathVariable Long id) {\n'
    "    return em.find(Visit.class, id);\n  }\n"
    '  @GetMapping("/ternary/{id}") Card ternary(@PathVariable Long id, boolean f) {\n'
    "    Long key = f ? id : 0L;\n"
    "    return cards.findById(key).orElseThrow();\n  }\n"
    '  @GetMapping("/formatted/{id}") Card formatted(@PathVariable Long id) {\n'
    '    String key = "" + id;\n'
    "    return cards.findById(Long.valueOf(key)).orElseThrow();\n  }\n"
    '  @GetMapping("/swapped/{id}")\n'
    "  Card swapped(@PathVariable Long id, Principal p, @RequestParam String who) {\n"
    "    String me = p.getName();\n"
    "    me = who;\n"
    "    return cards.findByIdAndOwnerEmail(id, me).orElseThrow();\n  }\n"
    '  @GetMapping("/named/{id}") Card named(@PathVariable Long id) {\n'
    "    return cards.findByIdAndOwnerEmail(id, owner()).orElseThrow();\n  }\n"
    "  String owner() { return lastSeen; }\n"
    '  @PreAuthorize("@access.canRead(#id, authentication) or true")\n'
    '  @GetMapping("/spel-or/{id}") Card spelOr(@PathVariable Long id) {\n'
    "    return cards.findById(id).orElseThrow();\n  }\n"
    '  @PreAuthorize("!@access.canRead(#id, authentication)")\n'
    '  @GetMapping("/spel-not/{id}") Card spelNot(@PathVariable Long id) {\n'
    "    return cards.findById(id).orElseThrow();\n  }\n"
    '  @PostAuthorize("returnObject.ownerEmail == authentication.name")\n'
    '  @GetMapping("/touched/{id}") Card touched(@PathVariable Long id) {\n'
    "    Card c = cards.findById(id).orElseThrow();\n"
    "    cards.save(c);\n"
    "    return c;\n  }\n"
    '  @PreAuthorize("hasRole(@roles.admin())")\n'
    '  @GetMapping("/bean-role/{id}") Card beanRole(@PathVariable Long id) {\n'
    "    return cards.findById(id).orElseThrow();\n  }\n"
    "}\n"
    '@RestController @RequestMapping("/admin")\n'
    "@PreAuthorize(\"hasRole('ADMIN')\")\n"
    "class Admin {\n"
    "  private CardRepository cards;\n"
    '  @GetMapping("/cards/{id}") Card card(@PathVariable Long id) {\n'
    "    return cards.findById(id).orElseThrow();\n  }\n"
    '  @PreAuthorize("isAuthenticated()")\n'
    '  @GetMapping("/open/{id}") Card open(@PathVariable Long id) {\n'
    "    return cards.findById(id).orElseThrow();\n  }\n"
    "}\n"
)


@pytest.fixture(scope="module")
def review(tmp_path_factory: pytest.TempPathFactory) -> dict:
    root = tmp_path_factory.mktemp("review")
    for rel, text in {
        "pom.xml": POM,
        "src/main/java/review/MethodSecurity.java": METHOD_SECURITY,
        "src/main/java/review/Review.java": REVIEW,
    }.items():
        path = root / rel
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(text)
    return route_guards(tree_files(root)).model_dump(mode="json")


@pytest.mark.parametrize(
    ("method", "pattern", "ownership"),
    [
        ("GET", "/r/and/{id}", "unchecked"),  # `&&`: the owner passes only when cents > 0
        ("GET", "/r/null-or/{id}", "checked"),
        ("GET", "/r/objects/{id}", "checked"),
        ("GET", "/r/getter/{id}", "checked"),
        ("GET", "/r/forbidden/{id}", "unchecked"),  # returns the record in a 403 body
        ("GET", "/r/later/{id}", "unchecked"),  # handed on before the check
        ("GET", "/r/checkout/{id}", "caller-blind"),  # `checkout` isn't a check
        ("GET", "/r/static/{id}", "unchecked"),  # a static helper that verifies nothing
        ("GET", "/r/guarded/{id}", "checked"),  # a helper that refuses a foreign record
        ("GET", "/r/projects/{pid}/cards/{cid}", "unchecked"),  # verified the other id
        ("GET", "/r/pairs/{pid}/{cid}", "unchecked"),  # handed both ids, verified one
        ("GET", "/r/result/{id}", "caller-blind"),  # a wrapper return type isn't ownerless
        ("GET", "/r/notes/{id}", "caller-blind"),  # username is an owner field
        ("GET", "/r/visits/{id}", "caller-blind"),  # owned through its patient: not ownerless
        ("GET", "/r/ternary/{id}", "caller-blind"),  # a ternary of the id is the id
        ("GET", "/r/formatted/{id}", "caller-blind"),  # a string built from the id is the id
        ("GET", "/r/swapped/{id}", "unchecked"),  # the caller local was overwritten
        ("GET", "/r/named/{id}", "caller-blind"),  # a same-named caller helper in another class
        ("GET", "/r/spel-or/{id}", "caller-blind"),
        ("GET", "/r/spel-not/{id}", "caller-blind"),
        ("GET", "/r/touched/{id}", "caller-blind"),  # @PostAuthorize after a save
        ("GET", "/r/bean-role/{id}", "caller-blind"),  # a role we can't read isn't privileged
        ("GET", "/admin/cards/{id}", "n/a"),  # privileged only
        ("GET", "/admin/open/{id}", "caller-blind"),  # the method's own rule overrides the class's
    ],
)
def test_only_the_allowed_shapes_count_as_protection(
    review: dict, method: str, pattern: str, ownership: str
) -> None:
    row = _row(review, method, pattern)
    assert row["ownership"] == ownership
    assert row["judgement_required"] is (ownership in ("caller-blind", "unchecked"))


def test_under_a_deploy_time_chain_only_the_routes_own_rules_decide(tmp_path) -> None:
    chain = (
        '@ConditionalOnProperty(name = "app.security", havingValue = "{cond}")\n'
        "class {name} {{\n"
        "  @Bean SecurityFilterChain f(HttpSecurity http) throws Exception {{\n"
        "    http.authorizeHttpRequests(a -> a.anyRequest().{rule}());\n"
        "    return http.build();\n  }}\n}}\n"
    )
    files = {
        "pom.xml": POM,
        "src/main/java/app/MethodSecurity.java": METHOD_SECURITY,
        "src/main/java/app/Off.java": chain.format(cond="false", name="Off", rule="permitAll"),
        "src/main/java/app/On.java": chain.format(cond="true", name="On", rule="authenticated"),
        "src/main/java/app/Api.java": (
            "import org.springframework.web.bind.annotation.*;\n"
            "import jakarta.annotation.security.PermitAll;\n"
            "class Card { Long id; String ownerEmail; }\n"
            "@RestController class Api {\n"
            "  private EntityManager em;\n"
            '  @PreAuthorize("isAuthenticated()")\n'
            '  @GetMapping("/signed/{id}") Card signed(@PathVariable Long id) {\n'
            "    return em.find(Card.class, id);\n  }\n"
            '  @GetMapping("/bare/{id}") Card bare(@PathVariable Long id) {\n'
            "    return em.find(Card.class, id);\n  }\n"
            "  @PermitAll\n"
            '  @GetMapping("/open/{id}") Card open(@PathVariable Long id) {\n'
            "    return em.find(Card.class, id);\n  }\n}\n"
        ),
    }
    for rel, text in files.items():
        path = tmp_path / rel
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(text)
    result = route_guards(tree_files(tmp_path)).model_dump(mode="json")
    # a candidate chain's permitAll doesn't open a route that authenticates itself
    assert _row(result, "GET", "/signed/{id}")["ownership"] == "caller-blind"
    assert _row(result, "GET", "/bare/{id}")["ownership"] == "n/a"
    assert _row(result, "GET", "/open/{id}")["ownership"] == "n/a"


# Protection that still lets a caller reach another user's object, and the fifth allowed shape.
AUDIT = (
    "package audit;\n"
    "import org.springframework.web.bind.annotation.*;\n"
    "import java.security.Principal;\n"
    "class Card { Long id; String ownerEmail; String accountType; long cents; }\n"
    "class UserDetails { String username; }\n"
    "class AppUser { String accountType; }\n"
    "class Prescription { Long id; Long patientId; String drug; }\n"
    "class Message { Long id; String recipient; String body; }\n"
    "class Statement { Long id; long amount; }\n"
    "class Account { Long id; String ownerId; List<Statement> statements; }\n"
    "class Payment { Long id; long cents; }\n"
    "class CardPayment extends Payment { String ownerEmail; }\n"
    "@Entity class Status { Long id; String label; }\n"
    "interface StatusRepository extends JpaRepository<Status, Long> {\n"
    "  Status findByLabel(String label);\n}\n"
    "interface CardRepository extends JpaRepository<Card, Long> {\n"
    "  Optional<Card> findByIdAndOwnerEmail(Long id, String ownerEmail);\n"
    "  Optional<Card> findByIdAndOwnerEmailNot(Long id, String ownerEmail);\n"
    "  Optional<Card> findByIdAndOwnerEmailContaining(Long id, String ownerEmail);\n"
    '  @Query("select c from Card c where c.id = ?1")\n'
    "  Optional<Card> findByIdAndOwnerEmailIs(Long id, String ownerEmail);\n"
    "  default Optional<Card> findByIdAndOwnerEmailEquals(Long id, String e) {\n"
    "    return findById(id);\n  }\n}\n"
    "class Orders {\n"
    "  private JdbcTemplate jdbc;\n"
    "  private StatusRepository statuses;\n"
    "  private CardRepository cards;\n"
    "  Status cancel(Long orderId) {\n"
    "    jdbc.update(\"update orders set status = 'CANCELLED' where id = ?\", orderId);\n"
    '    return statuses.findByLabel("CANCELLED");\n  }\n'
    "  Card archive(Long id) {\n"
    '    jdbc.update("update card set archived = true where id = ?", id);\n'
    "    return cards.findById(id).orElseThrow();\n  }\n}\n"
    "abstract class CardStore { abstract void purge(Long id); }\n"
    "class NoteStore {\n"
    "  private Map<Long, Card> byId;\n"
    "  Card owned(Long id, String owner) {\n"
    "    Card c = byId.get(id);\n"
    "    return c != null && c.ownerEmail.equals(owner) ? c : null;\n  }\n"
    "  Card either(Long id, String owner) {\n"
    "    Card c = byId.get(id);\n"
    "    return c != null || c.ownerEmail.equals(owner) ? c : null;\n  }\n"
    "  Card fallback(Long id, String owner) {\n"
    "    Card c = byId.get(id);\n"
    "    return c != null && c.ownerEmail.equals(owner) ? c : byId.get(0L);\n  }\n}\n"
    '@RestController @RequestMapping("/a")\n'
    "class Audit {\n"
    "  @Autowired private HttpServletRequest request;\n"
    "  private CardRepository cards;\n"
    "  private EntityManager em;\n"
    "  private Orders orders;\n"
    "  private CardStore store;\n"
    "  private NoteStore notes;\n"
    "  private Gateway gateway;\n"
    "  private Workflow workflow;\n"
    "  private AuditLog auditLog;\n"
    "  private Access access;\n"
    '  @GetMapping("/not/{id}") Card not(@PathVariable Long id, Principal me) {\n'
    "    return cards.findByIdAndOwnerEmailNot(id, me.getName()).orElseThrow();\n  }\n"
    '  @GetMapping("/containing/{id}") Card containing(@PathVariable Long id, Principal me) {\n'
    "    return cards.findByIdAndOwnerEmailContaining(id, me.getName()).orElseThrow();\n  }\n"
    '  @GetMapping("/declared/{id}") Card declared(@PathVariable Long id, Principal me) {\n'
    "    return cards.findByIdAndOwnerEmailIs(id, me.getName()).orElseThrow();\n  }\n"
    '  @GetMapping("/default/{id}") Card byDefault(@PathVariable Long id, Principal me) {\n'
    "    return cards.findByIdAndOwnerEmailEquals(id, me.getName()).orElseThrow();\n  }\n"
    '  @GetMapping("/derived/{id}") Card derived(@PathVariable Long id, Principal me) {\n'
    "    return cards.findByIdAndOwnerEmail(id, me.getName()).orElseThrow();\n  }\n"
    '  @GetMapping("/onbehalf/{id}") Card onBehalf(@PathVariable Long id, Principal me) {\n'
    '    String owner = Optional.ofNullable(request.getHeader("X-On-Behalf-Of"))'
    ".orElse(me.getName());\n"
    "    return cards.findByIdAndOwnerEmail(id, owner).orElseThrow();\n  }\n"
    '  @GetMapping("/dto/{id}") Card dto(@PathVariable Long id, @RequestBody UserDetails body) {\n'
    "    return cards.findByIdAndOwnerEmail(id, body.getUsername()).orElseThrow();\n  }\n"
    '  @GetMapping("/shadow/{id}")\n'
    "  Card shadow(@PathVariable Long id, Principal p, @RequestParam String who) {\n"
    "    if (who == null) { String me = p.getName(); System.out.println(me); }\n"
    "    String me = who;\n"
    "    return cards.findByIdAndOwnerEmail(id, me).orElseThrow();\n  }\n"
    '  @GetMapping("/act-as/{id}")\n'
    "  Card actAs(@PathVariable Long id, Authentication auth, @RequestParam String as) {\n"
    "    if (as != null) auth = new UsernamePasswordAuthenticationToken(as, null);\n"
    "    return cards.findByIdAndOwnerEmail(id, auth.getName()).orElseThrow();\n  }\n"
    '  @GetMapping("/acting/{id}") Card acting(@PathVariable Long id) {\n'
    "    return cards.findByIdAndOwnerEmail(id, actingUser()).orElseThrow();\n  }\n"
    "  String actingUser() {\n"
    '    String as = request.getParameter("as");\n'
    "    if (as != null) return as;\n"
    "    return SecurityContextHolder.getContext().getAuthentication().getName();\n  }\n"
    "  String owner(String fallback) { return fallback; }\n"
    "  String owner() {\n"
    "    return SecurityContextHolder.getContext().getAuthentication().getName();\n  }\n"
    '  @GetMapping("/overload/{id}") Card overload(@PathVariable Long id) {\n'
    '    return cards.findByIdAndOwnerEmail(id, owner("x")).orElseThrow();\n  }\n'
    '  @GetMapping("/helper/{id}") Card helper(@PathVariable Long id) {\n'
    "    return cards.findByIdAndOwnerEmail(id, owner()).orElseThrow();\n  }\n"
    '  @DeleteMapping("/probe-1/{id}")\n'
    "  void probe1(@PathVariable Long id, @RequestParam Long probe, Principal me) {\n"
    "    cards.findByIdAndOwnerEmail(probe != null ? probe : id, me.getName()).orElseThrow();\n"
    "    cards.deleteById(id);\n  }\n"
    '  @DeleteMapping("/probe-2/{id}")\n'
    "  void probe2(@PathVariable Long id, @RequestParam Long probe, Principal me) {\n"
    "    Card c = cards.findById(probe != null ? probe : id).orElseThrow();\n"
    "    if (!c.ownerEmail.equals(me.getName())) throw new IllegalStateException();\n"
    "    cards.deleteById(id);\n  }\n"
    '  @DeleteMapping("/verified/{id}") void verified(@PathVariable Long id, Principal me) {\n'
    "    Card c = cards.findById(id).orElseThrow();\n"
    "    if (!c.ownerEmail.equals(me.getName())) throw new IllegalStateException();\n"
    "    cards.deleteById(id);\n  }\n"
    '  @PreAuthorize("@access.canEdit(#id, authentication)")\n'
    '  @DeleteMapping("/s3-moved/{id}")\n'
    "  void moved(@PathVariable Long id, @RequestParam Long also) {\n"
    "    if (also != null) id = also;\n"
    "    cards.deleteById(id);\n  }\n"
    '  @GetMapping("/archived/{id}") Card archived(@PathVariable Long id, Principal me) {\n'
    "    Card c = orders.archive(id);\n"
    "    if (!c.ownerEmail.equals(me.getName())) throw new IllegalStateException();\n"
    "    return c;\n  }\n"
    '  @GetMapping("/saved/{id}") Card saved(@PathVariable Long id, Principal me) {\n'
    "    Card c = cards.save(cards.findById(id).orElseThrow());\n"
    "    if (!c.ownerEmail.equals(me.getName())) throw new IllegalStateException();\n"
    "    return c;\n  }\n"
    '  @GetMapping("/kind/{id}")\n'
    "  Card kind(@PathVariable Long id, @AuthenticationPrincipal AppUser me) {\n"
    "    Card c = cards.findById(id).orElseThrow();\n"
    "    if (!c.accountType.equals(me.getAccountType())) throw new IllegalStateException();\n"
    "    return c;\n  }\n"
    '  @GetMapping("/prescriptions/{id}") Prescription rx(@PathVariable Long id) {\n'
    "    return em.find(Prescription.class, id);\n  }\n"
    '  @GetMapping("/messages/{id}") Message message(@PathVariable Long id) {\n'
    "    return em.find(Message.class, id);\n  }\n"
    '  @GetMapping("/statements/{id}") Statement statement(@PathVariable Long id) {\n'
    "    return em.find(Statement.class, id);\n  }\n"
    '  @GetMapping("/payments/{id}") Payment payment(@PathVariable Long id) {\n'
    "    return em.find(Payment.class, id);\n  }\n"
    '  @PostMapping("/orders/{id}/cancel") Status cancel(@PathVariable Long id) {\n'
    "    return orders.cancel(id);\n  }\n"
    '  @PostMapping("/submit/{id}") Card submit(@PathVariable Long id, Principal me) {\n'
    "    workflow.validateAndSubmit(id);\n"
    "    return cards.findByIdAndOwnerEmail(id, me.getName()).orElseThrow();\n  }\n"
    '  @GetMapping("/require/{id}") Card require(@PathVariable Long id) {\n'
    "    return gateway.requireCard(id);\n  }\n"
    '  @GetMapping("/view/{id}") Object view(@PathVariable Long id) {\n'
    "    return gateway.toView(id);\n  }\n"
    '  @DeleteMapping("/abstract/{id}") Card purge(@PathVariable Long id, Principal me) {\n'
    "    store.purge(id);\n"
    "    return cards.findByIdAndOwnerEmail(id, me.getName()).orElseThrow();\n  }\n"
    '  @DeleteMapping("/ctor/{id}") Card ctor(@PathVariable Long id, Principal me) {\n'
    "    new PurgeCommand(id).execute();\n"
    "    return cards.findByIdAndOwnerEmail(id, me.getName()).orElseThrow();\n  }\n"
    '  @DeleteMapping("/ref/{id}") Card ref(@PathVariable Long id, Principal me) {\n'
    "    Optional.of(id).ifPresent(cards::deleteById);\n"
    "    return cards.findByIdAndOwnerEmail(id, me.getName()).orElseThrow();\n  }\n"
    '  @GetMapping("/logged/{id}") Card logged(@PathVariable Long id) {\n'
    "    auditLog.logAdminView(id);\n"
    "    return em.find(Card.class, id);\n  }\n"
    '  @RolesAllowed("ADMIN")\n'
    '  @GetMapping("/jsr250/{id}") Card jsr250(@PathVariable Long id) {\n'
    "    return em.find(Card.class, id);\n  }\n"
    '  @Secured("ROLE_ADMIN")\n'
    '  @GetMapping("/secured/{id}") Card secured(@PathVariable Long id) {\n'
    "    return em.find(Card.class, id);\n  }\n"
    "  @PostAuthorize(\"hasRole('ADMIN')\")\n"
    '  @DeleteMapping("/post/{id}") void post(@PathVariable Long id) {\n'
    "    cards.deleteById(id);\n  }\n"
    "  @GetMapping(Routes.CARD_BY_ID) Card constant(@PathVariable Long id) {\n"
    "    return em.find(Card.class, id);\n  }\n"
    '  @GetMapping("/owned/{id}") Card owned(@PathVariable Long id, Principal me) {\n'
    "    Card c = notes.owned(id, me.getName());\n"
    "    if (c == null) throw new IllegalStateException();\n"
    "    return c;\n  }\n"
    '  @DeleteMapping("/owned-deleted/{id}")\n'
    "  void ownedDeleted(@PathVariable Long id, Principal me) {\n"
    "    Card c = notes.owned(id, me.getName());\n"
    "    if (c == null) throw new IllegalStateException();\n"
    "    cards.deleteById(id);\n  }\n"
    '  @DeleteMapping("/owned-unrefused/{id}")\n'
    "  void ownedUnrefused(@PathVariable Long id, Principal me) {\n"
    "    Card c = notes.owned(id, me.getName());\n"
    "    cards.deleteById(id);\n  }\n"
    '  @GetMapping("/either/{id}") Card either(@PathVariable Long id, Principal me) {\n'
    "    return notes.either(id, me.getName());\n  }\n"
    '  @GetMapping("/fallback/{id}") Card fallback(@PathVariable Long id, Principal me) {\n'
    "    return notes.fallback(id, me.getName());\n  }\n"
    "}\n"
)


@pytest.fixture(scope="module")
def audit(tmp_path_factory: pytest.TempPathFactory) -> dict:
    root = tmp_path_factory.mktemp("audit")
    for rel, text in {
        "pom.xml": POM,
        "src/main/java/audit/MethodSecurity.java": METHOD_SECURITY,
        "src/main/java/audit/Audit.java": AUDIT,
    }.items():
        path = root / rel
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(text)
    return route_guards(tree_files(root)).model_dump(mode="json")


@pytest.mark.parametrize(
    ("method", "pattern", "ownership"),
    [
        ("GET", "/a/not/{id}", "unchecked"),  # `…Not`: other users' cards
        ("GET", "/a/containing/{id}", "unchecked"),
        ("GET", "/a/declared/{id}", "unchecked"),  # an @Query decides, not the name
        ("GET", "/a/default/{id}", "unchecked"),  # a default body decides, not the name
        ("GET", "/a/derived/{id}", "scoped"),
        ("GET", "/a/onbehalf/{id}", "unchecked"),  # a request header can stand in
        ("GET", "/a/dto/{id}", "caller-blind"),  # a request body named UserDetails
        ("GET", "/a/shadow/{id}", "unchecked"),  # `me` declared again from the request
        ("GET", "/a/act-as/{id}", "caller-blind"),  # the caller parameter reassigned
        ("GET", "/a/acting/{id}", "caller-blind"),  # a helper that may return a parameter
        ("GET", "/a/overload/{id}", "caller-blind"),  # the one-argument overload
        ("GET", "/a/helper/{id}", "scoped"),
        ("DELETE", "/a/probe-1/{id}", "unchecked"),  # verified another value than the id
        ("DELETE", "/a/probe-2/{id}", "unchecked"),
        ("DELETE", "/a/verified/{id}", "checked"),
        ("DELETE", "/a/s3-moved/{id}", "caller-blind"),  # the id reassigned after the check
        ("GET", "/a/archived/{id}", "unchecked"),  # updated before the load is checked
        ("GET", "/a/saved/{id}", "unchecked"),  # saved before the check
        ("GET", "/a/kind/{id}", "unchecked"),  # accountType is no owner
        ("GET", "/a/prescriptions/{id}", "caller-blind"),  # patientId: owned through it
        ("GET", "/a/messages/{id}", "caller-blind"),  # a recipient
        ("GET", "/a/statements/{id}", "caller-blind"),  # held by an owned account
        ("GET", "/a/payments/{id}", "caller-blind"),  # a subclass names an owner
        ("POST", "/a/orders/{id}/cancel", "caller-blind"),  # an entity return type isn't the load
        ("POST", "/a/submit/{id}", "unknown"),  # `validateAndSubmit` isn't a validator
        ("GET", "/a/require/{id}", "unknown"),
        ("GET", "/a/view/{id}", "unknown"),  # a conversion on an object we don't follow
        ("DELETE", "/a/abstract/{id}", "unknown"),  # no implementation to read
        ("DELETE", "/a/ctor/{id}", "unknown"),  # the id handed to a constructor
        ("DELETE", "/a/ref/{id}", "unknown"),  # the id handed to a method reference
        ("GET", "/a/logged/{id}", "caller-blind"),  # a call's name doesn't make it admin-only
        ("GET", "/a/jsr250/{id}", "caller-blind"),  # jsr250 isn't enabled
        ("GET", "/a/secured/{id}", "caller-blind"),  # @Secured isn't enabled
        ("DELETE", "/a/post/{id}", "caller-blind"),  # @PostAuthorize runs after the delete
        ("GET", "/a/Routes.CARD_BY_ID", "unknown"),  # an unresolved pattern with a path id
        ("GET", "/a/owned/{id}", "checked"),  # shape 5, refused when null
        ("DELETE", "/a/owned-deleted/{id}", "checked"),
        ("DELETE", "/a/owned-unrefused/{id}", "unchecked"),  # deletes whatever owned returned
        ("GET", "/a/either/{id}", "unchecked"),  # `||`: returned when not null
        ("GET", "/a/fallback/{id}", "unchecked"),  # returns another record when not owned
    ],
)
def test_only_the_allowed_shapes_count_after_a_third_review(
    audit: dict, method: str, pattern: str, ownership: str
) -> None:
    row = _row(audit, method, pattern)
    assert row["ownership"] == ownership
    assert row["judgement_required"] is (ownership in ("caller-blind", "unchecked"))


def _tree(root, files: dict[str, str]) -> dict:
    for rel, text in files.items():
        path = root / rel
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(text)
    return route_guards(tree_files(root)).model_dump(mode="json")


CARD_API = (
    "import org.springframework.web.bind.annotation.*;\n"
    "class Card { Long id; String ownerEmail; }\n"
    "@RestController class Api {\n"
    "  private EntityManager em;\n"
    '  @PreAuthorize("@access.canRead(#id, authentication)")\n'
    '  @GetMapping("/bean/{id}") Card bean(@PathVariable Long id) {\n'
    "    return em.find(Card.class, id);\n  }\n"
    '  @PreAuthorize("isAuthenticated()")\n'
    '  @GetMapping("/signed/{id}") Card signed(@PathVariable Long id) {\n'
    "    return em.find(Card.class, id);\n  }\n}\n"
)


def test_method_security_counts_only_for_the_families_enabled(tmp_path) -> None:
    result = _tree(
        tmp_path,
        {
            "pom.xml": POM,
            "src/main/java/app/Sec.java": (
                "@EnableGlobalMethodSecurity(securedEnabled = true) class Sec {}\n"
            ),
            "src/main/java/app/Api.java": CARD_API,
        },
    )
    assert _row(result, "GET", "/bean/{id}")["ownership"] == "caller-blind"


def test_an_open_filter_chain_doesnt_open_a_route_its_method_authenticates(tmp_path) -> None:
    chain = (
        "class Web {\n"
        "  @Bean SecurityFilterChain f(HttpSecurity http) throws Exception {\n"
        "    http.authorizeHttpRequests(a -> a.anyRequest().permitAll());\n"
        "    return http.build();\n  }\n}\n"
    )
    result = _tree(
        tmp_path,
        {
            "pom.xml": POM,
            "src/main/java/app/MethodSecurity.java": METHOD_SECURITY,
            "src/main/java/app/Web.java": chain,
            "src/main/java/app/Api.java": CARD_API,
        },
    )
    assert _row(result, "GET", "/signed/{id}")["ownership"] == "caller-blind"


def test_a_jaxrs_methods_own_roles_override_its_classs_permit_all(tmp_path) -> None:
    resource = (
        "import jakarta.ws.rs.*;\n"
        "import jakarta.annotation.security.*;\n"
        "class Card { Long id; String ownerEmail; }\n"
        '@Path("/f") @PermitAll class F {\n'
        "  private EntityManager em;\n"
        '  @GET @Path("/{id}") @RolesAllowed("user") Card get(@PathParam("id") Long id) {\n'
        "    return em.find(Card.class, id);\n  }\n}\n"
    )
    result = _tree(tmp_path, {"src/main/java/app/F.java": resource})
    assert _row(result, "GET", "/f/{id}")["ownership"] == "caller-blind"


def test_long_conditions_and_many_declarations_neither_crash_nor_crawl(tmp_path) -> None:
    terms = " || ".join(f"c.cents == {k}" for k in range(1500))
    declarations = "".join(f"    String m{k} = me.getName();\n" for k in range(400))
    api = (
        "import org.springframework.web.bind.annotation.*;\n"
        "import java.security.Principal;\n"
        "class Card { Long id; String ownerEmail; long cents; }\n"
        "interface CardRepository extends JpaRepository<Card, Long> {}\n"
        "@RestController class Api {\n"
        "  private CardRepository cards;\n"
        '  @GetMapping("/long/{id}") Card long(@PathVariable Long id) {\n'
        "    Card c = cards.findById(id).orElseThrow();\n"
        f"    if ({terms}) throw new IllegalStateException();\n"
        "    return c;\n  }\n"
        '  @GetMapping("/many/{id}") Card many(@PathVariable Long id, Principal me) {\n'
        "    Card c = cards.findById(id).orElseThrow();\n"
        f"{declarations}"
        "    if (!c.ownerEmail.equals(me.getName())) throw new IllegalStateException();\n"
        "    return c;\n  }\n}\n"
    )
    result = _tree(tmp_path, {"pom.xml": POM, "src/main/java/app/Api.java": api})
    assert _row(result, "GET", "/long/{id}")["ownership"] == "caller-blind"
    assert _row(result, "GET", "/many/{id}")["ownership"] == "checked"


# A fourth independent review: more ways a caller still reaches another user's object.
ITEMS = (
    "import org.springframework.web.bind.annotation.*;\n"
    "import java.security.Principal;\n"
    "@Entity class Item { Long id; String ownerId; String title; }\n"
    "@Entity class Board { Long id; String ownerId; }\n"
    "@Entity class Order { Long id; String ownerId; }\n"
    "@Entity class CatalogItem { Long id; String name; }\n"
    "@Entity class Doc { Long id; String body; }\n"
    "@Entity class DocShare { Long id; Long docId; String userId; }\n"
    '@NamedQuery(name = "Board.findByIdAndOwnerId",'
    ' query = "select b from Board b where b.id = ?1")\n'
    "class BoardQueries {}\n"
    "interface ItemRepository extends JpaRepository<Item, Long> {\n"
    "  Optional<Item> findByIdAndOwnerId(Long id, String ownerId);\n"
    "  @Procedure Item findByIdAndTitle(Long id, String title);\n"
    "  @Modifying @Query(\"update Item i set i.title = 'x' where i.id = ?1\")\n"
    "  Optional<Item> findLocked(Long id);\n}\n"
    "interface BoardRepository extends JpaRepository<Board, Long> {\n"
    "  Optional<Board> findByIdAndOwnerId(Long id, String ownerId);\n}\n"
    "@NoRepositoryBean interface BaseRepo<T> extends JpaRepository<T, Long> {}\n"
    "interface OrderRepository extends BaseRepo<Order> {\n"
    '  @Query("select o from Order o where o.id = ?1")\n'
    "  Order findByIdAndOwnerId(Long id, String ownerId);\n}\n"
    "interface CatalogRepository extends JpaRepository<CatalogItem, Long> {\n"
    '  @Query("select o from Order o where o.id = ?1") Order findOrder(Long id);\n}\n'
    "interface DocRepository extends JpaRepository<Doc, Long> {}\n"
    "class ItemService {\n"
    "  ItemRepository items;\n"
    "  Item load(Long id, String owner) {\n"
    "    return items.findByIdAndOwnerId(id, owner).orElseThrow();\n  }\n"
    "  Item find(Long id, String owner) {\n"
    "    return items.findByIdAndOwnerId(id, owner).orElseThrow();\n  }\n"
    "  Item open(Long id) {\n"
    "    Item r = items.findById(id).orElseThrow();\n"
    '    r.title = "opened";\n'
    "    items.save(r);\n"
    "    return r;\n  }\n"
    "  Item read(Long id) {\n"
    "    Item r = items.findById(id).orElseThrow();\n"
    "    return r;\n  }\n"
    "  Board board(Long boardId, Long cardId) {\n"
    "    return boards.findById(boardId).orElseThrow();\n  }\n"
    "  BoardRepository boards;\n"
    "  Map<String, Item> drafts;\n"
    "  Item owned(Long id, String me) {\n"
    "    if (drafts.containsKey(me)) return drafts.get(me);\n"
    "    Item r = items.findById(id).orElse(null);\n"
    "    return r != null && r.ownerId.equals(me) ? r : null;\n  }\n}\n"
    "@Primary class FastService extends ItemService {\n"
    "  Item load(Long id, String owner) {\n"
    "    return items.findById(id).orElseThrow();\n  }\n}\n"
    "class Overloaded {\n"
    "  ItemRepository items;\n"
    "  Item get(Long id, String owner) {\n"
    "    return items.findByIdAndOwnerId(id, owner).orElseThrow();\n  }\n"
    "  Item get(Long id, Long other) {\n"
    "    return items.findById(id).orElseThrow();\n  }\n}\n"
    "class BaseController {\n"
    "  ItemRepository items;\n"
    "  Item find(Long id, String owner) {\n"
    "    return items.findById(id).orElseThrow();\n  }\n}\n"
    "class ItemRef { Long itemId; }\n"
    '@RestController @RequestMapping("/f")\n'
    "class Fourth extends BaseController {\n"
    "  private ItemRepository items;\n"
    "  private BoardRepository boards;\n"
    "  private OrderRepository orders;\n"
    "  private CatalogRepository catalog;\n"
    "  private DocRepository docs;\n"
    "  private ItemService service;\n"
    "  private Overloaded overloaded;\n"
    "  private Directory directory;\n"
    '  @GetMapping("/try/{raw}") Item tried(@PathVariable String raw) {\n'
    "    long id;\n"
    "    try { id = Long.parseLong(raw); } catch (NumberFormatException e) {\n"
    "      throw new IllegalArgumentException();\n    }\n"
    "    return items.findById(id).orElseThrow();\n  }\n"
    '  @DeleteMapping("/each/{ids}") void each(@PathVariable List<Long> ids) {\n'
    "    for (Long id : ids) { items.deleteById(id); }\n  }\n"
    '  @GetMapping("/bound/{id}") Item bound(@PathVariable("id") Item item) {\n'
    "    return item;\n  }\n"
    '  @DeleteMapping("/boards/{boardId}/cards/{raw}")\n'
    "  void card(@PathVariable Long boardId, @PathVariable String raw, Principal me) {\n"
    "    boards.findByIdAndOwnerId(boardId, me.getName()).orElseThrow();\n"
    "    Long cid;\n"
    "    cid = Long.valueOf(raw);\n"
    "    items.deleteById(cid);\n  }\n"
    '  @DeleteMapping("/siblings/{a}/{b}")\n'
    "  void siblings(@PathVariable Long a, @PathVariable Long b, Principal me, boolean flag) {\n"
    "    items.findByIdAndOwnerId(b, me.getName()).orElseThrow();\n"
    "    if (flag) { Long key = a; items.deleteById(key); }\n"
    "    else { Long key = b; items.deleteById(key); }\n  }\n"
    '  @GetMapping("/overloaded/{id}") Item viaOverload(@PathVariable Long id, Principal me) {\n'
    "    return overloaded.get(id, me.getName());\n  }\n"
    '  @GetMapping("/primary/{id}") Item primary(@PathVariable Long id, Principal me) {\n'
    "    return service.load(id, me.getName());\n  }\n"
    "  Item find(Long id, String owner) {\n"
    "    return items.findByIdAndOwnerId(id, owner).orElseThrow();\n  }\n"
    '  @GetMapping("/super/{id}") Item viaSuper(@PathVariable Long id, Principal me) {\n'
    "    return super.find(id, me.getName());\n  }\n"
    '  @GetMapping("/opened/{id}") Item opened(@PathVariable Long id, Principal me) {\n'
    "    Item r = service.open(id);\n"
    "    if (!r.ownerId.equals(me.getName())) throw new IllegalStateException();\n"
    "    return r;\n  }\n"
    '  @DeleteMapping("/read/{id}") void read(@PathVariable Long id, Principal me) {\n'
    "    Item r = service.read(id);\n"
    "    if (!r.ownerId.equals(me.getName())) throw new IllegalStateException();\n"
    "    items.deleteById(id);\n  }\n"
    '  @DeleteMapping("/board/{boardId}/{cardId}")\n'
    "  void board(@PathVariable Long boardId, @PathVariable Long cardId, Principal me) {\n"
    "    Board b = service.board(boardId, cardId);\n"
    "    if (!b.ownerId.equals(me.getName())) throw new IllegalStateException();\n"
    "    items.deleteById(cardId);\n  }\n"
    '  @DeleteMapping("/owned/{id}") void owned(@PathVariable Long id, Principal me) {\n'
    "    Item r = service.owned(id, me.getName());\n"
    "    if (r == null) throw new IllegalStateException();\n"
    "    items.deleteById(id);\n  }\n"
    '  @GetMapping("/orders/{id}") Order order(@PathVariable Long id, Principal me) {\n'
    "    Order o = orders.findByIdAndOwnerId(id, me.getName());\n"
    "    return o;\n  }\n"
    '  @GetMapping("/named/{id}") Board named(@PathVariable Long id, Principal me) {\n'
    "    return boards.findByIdAndOwnerId(id, me.getName()).orElseThrow();\n  }\n"
    '  @GetMapping("/procedure/{id}") Item procedure(@PathVariable Long id, Principal me) {\n'
    "    return items.findByIdAndTitle(id, me.getName());\n  }\n"
    '  @GetMapping("/catalog/{id}") Order catalogOrder(@PathVariable Long id) {\n'
    "    return catalog.findOrder(id);\n  }\n"
    '  @GetMapping("/principal/{id}")\n'
    "  Item principal(@PathVariable Long id, @RequestParam String u) {\n"
    "    String owner = directory.getUserPrincipal(u).getName();\n"
    "    return items.findByIdAndOwnerId(id, owner).orElseThrow();\n"
    "  }\n"
    '  @GetMapping("/mutated/{id}")\n'
    "  Item mutated(@PathVariable Long id, @AuthenticationPrincipal AppUser me, String as) {\n"
    "    me.setName(as);\n"
    "    return items.findByIdAndOwnerId(id, me.getName()).orElseThrow();\n  }\n"
    '  @GetMapping("/act-as/{id}")\n'
    "  Item actAs(@PathVariable Long id, Principal me, @RequestParam Map<String, String> as) {\n"
    "    return items.findByIdAndOwnerId(id, as.getOrDefault(me.getName(), me.getName()))"
    ".orElseThrow();\n  }\n"
    '  @DeleteMapping("/boards/{id}/items/{itemId}")\n'
    "  void command(@PathVariable Long id, ItemRef ref, Principal me) {\n"
    "    items.findByIdAndOwnerId(id, me.getName()).orElseThrow();\n"
    "    items.deleteById(ref.itemId);\n  }\n"
    '  @GetMapping("/converted/{id}") Item converted(@PathVariable String id, Principal me) {\n'
    "    Long key = Long.valueOf(id);\n"
    "    return items.findByIdAndOwnerId(key, me.getName()).orElseThrow();\n  }\n"
    '  @GetMapping("/docs/{id}") Doc doc(@PathVariable Long id) {\n'
    "    return docs.findById(id).orElseThrow();\n  }\n"
    '  @GetMapping("/locked/{id}") Item locked(@PathVariable Long id, Principal me) {\n'
    "    Item r = items.findLocked(id).orElseThrow();\n"
    "    if (!r.ownerId.equals(me.getName())) throw new IllegalStateException();\n"
    "    return r;\n  }\n"
    '  @PreAuthorize("permitAll()")\n'
    '  @GetMapping("/open/{id}") Item open(@PathVariable Long id) {\n'
    "    return items.findById(id).orElseThrow();\n  }\n"
    '  @GetMapping("/long/{id}") Item longValue(@PathVariable Long id) {\n'
    "    return items.findById(id).orElseThrow();\n  }\n"
    "  String label() {\n"
    "    return " + " + ".join(['"x"'] * 600) + ";\n  }\n"
    "}\n"
)


@pytest.fixture(scope="module")
def fourth(tmp_path_factory: pytest.TempPathFactory) -> dict:
    root = tmp_path_factory.mktemp("fourth")
    return _tree(
        root,
        {
            "pom.xml": POM,
            "src/main/java/fourth/MethodSecurity.java": METHOD_SECURITY,
            "src/main/java/fourth/Fourth.java": ITEMS,
        },
    )


@pytest.mark.parametrize(
    ("method", "pattern", "ownership"),
    [
        ("GET", "/f/try/{raw}", "caller-blind"),  # the id assigned in a try
        ("DELETE", "/f/each/{ids}", "caller-blind"),  # each id of a path list
        ("GET", "/f/bound/{id}", "caller-blind"),  # Spring loads the entity by the path id
        ("DELETE", "/f/boards/{boardId}/cards/{raw}", "unchecked"),  # the card id assigned later
        ("DELETE", "/f/siblings/{a}/{b}", "unchecked"),  # `key` is `a` in one branch
        ("GET", "/f/overloaded/{id}", "unknown"),  # which overload runs is the types'
        ("GET", "/f/primary/{id}", "unchecked"),  # an overriding subclass may run
        ("GET", "/f/super/{id}", "unchecked"),  # `super.find` is the superclass's
        ("GET", "/f/opened/{id}", "unchecked"),  # the hop writes before the refusal
        ("DELETE", "/f/read/{id}", "checked"),  # the hop only reads
        ("DELETE", "/f/board/{boardId}/{cardId}", "unchecked"),  # verified the board only
        ("DELETE", "/f/owned/{id}", "unchecked"),  # returns something else first
        ("GET", "/f/orders/{id}", "unchecked"),  # an @Query behind a custom base repository
        ("GET", "/f/named/{id}", "unchecked"),  # a JPA named query wins over the name
        ("GET", "/f/procedure/{id}", "unchecked"),  # a stored procedure
        ("GET", "/f/catalog/{id}", "caller-blind"),  # the query loads an Order
        ("GET", "/f/principal/{id}", "caller-blind"),  # another user's principal
        ("GET", "/f/mutated/{id}", "caller-blind"),  # the caller object rewritten
        ("GET", "/f/act-as/{id}", "unchecked"),  # a request map picks the owner
        ("DELETE", "/f/boards/{id}/items/{itemId}", "unknown"),  # a path id in a command object
        ("GET", "/f/converted/{id}", "scoped"),  # a converted id is the id
        ("GET", "/f/docs/{id}", "caller-blind"),  # shared through DocShare.docId
        ("GET", "/f/locked/{id}", "unchecked"),  # a @Modifying query isn't a read
        ("GET", "/f/open/{id}", "caller-blind"),  # permitAll() leaves the chain's guard
    ],
)
def test_only_the_allowed_shapes_count_after_a_fourth_review(
    fourth: dict, method: str, pattern: str, ownership: str
) -> None:
    row = _row(fourth, method, pattern)
    assert row["ownership"] == ownership
    assert row["judgement_required"] is (ownership in ("caller-blind", "unchecked"))


def test_method_security_in_tests_doesnt_enable_it_for_the_application(tmp_path) -> None:
    api = (
        "import org.springframework.web.bind.annotation.*;\n"
        "@Entity class Item { Long id; String ownerId; }\n"
        "@RestController class Api {\n"
        "  private EntityManager em;\n"
        "  @PreAuthorize(\"hasRole('ADMIN')\")\n"
        '  @GetMapping("/admin/{id}") Item admin(@PathVariable Long id) {\n'
        "    return em.find(Item.class, id);\n  }\n}\n"
    )
    result = _tree(
        tmp_path,
        {
            "pom.xml": POM,
            "src/test/java/app/TestSecurity.java": METHOD_SECURITY,
            "src/main/java/app/Comment.java": "// @EnableMethodSecurity\nclass Comment {}\n",
            "src/main/java/app/Api.java": api,
        },
    )
    assert _row(result, "GET", "/admin/{id}")["ownership"] == "caller-blind"


def test_the_implementations_own_pre_authorize_wins(tmp_path) -> None:
    api = (
        "import org.springframework.web.bind.annotation.*;\n"
        "@Entity class Item { Long id; String ownerId; }\n"
        "interface ItemApi {\n"
        '  @PreAuthorize("@access.canRead(#id, authentication)")\n'
        '  @GetMapping("/items/{id}") Item get(@PathVariable("id") Long id);\n}\n'
        "@RestController class Api implements ItemApi {\n"
        "  private EntityManager em;\n"
        "  @PreAuthorize(\"hasRole('USER')\")\n"
        "  public Item get(Long id) { return em.find(Item.class, id); }\n}\n"
    )
    result = _tree(
        tmp_path,
        {
            "pom.xml": POM,
            "src/main/java/app/MethodSecurity.java": METHOD_SECURITY,
            "src/main/java/app/Api.java": api,
        },
    )
    assert _row(result, "GET", "/items/{id}")["ownership"] == "caller-blind"


def test_same_named_repositories_in_two_modules_are_never_ownerless(tmp_path) -> None:
    def module(name: str, entity: str, owner: str) -> str:
        return (
            f"package {name};\n"
            "import org.springframework.web.bind.annotation.*;\n"
            f"@Entity class {entity} {{ Long id; {owner} }}\n"
            f"interface ItemRepository extends JpaRepository<{entity}, Long> {{}}\n"
            f'@RestController @RequestMapping("/{name}") class Api {{\n'
            "  private ItemRepository items;\n"
            '  @GetMapping("/{id}") Object get(@PathVariable Long id) {\n'
            "    return items.findById(id).orElseThrow();\n  }\n}\n"
        )

    result = _tree(
        tmp_path,
        {
            "pom.xml": POM,
            "a/src/main/java/a/Api.java": module("a", "Item", "String ownerId;"),
            "b/src/main/java/b/Api.java": module("b", "Tag", "String label;"),
        },
    )
    assert _row(result, "GET", "/a/{id}")["ownership"] == "caller-blind"
    assert _row(result, "GET", "/b/{id}")["ownership"] == "caller-blind"


def test_a_tenant_finder_behind_overloaded_helpers_stays_scoped(tmp_path) -> None:
    base = (
        "import org.springframework.web.bind.annotation.*;\n"
        "class Device { Long id; String tenantId; }\n"
        "class User { String getTenantId() { return null; } }\n"
        "interface Finder<T, I, E> { E apply(T tenant, I id); }\n"
        "class Base {\n"
        "  User getCurrentUser() {\n"
        "    return (User) SecurityContextHolder.getContext().getAuthentication().getPrincipal();\n"
        "  }\n"
        "  <T> T checkNotNull(T value) { return value; }\n"
        "  <T> T checkNotNull(T value, String message) { return value; }\n"
        "  <T> T checkNotNull(Optional<T> value, String message) { return value.get(); }\n"
        "  <E, I> E checkEntityId(I id, Finder<String, I, E> finder, String op) {\n"
        "    User user = getCurrentUser();\n"
        "    E entity = finder.apply(user.getTenantId(), id);\n"
        '    checkNotNull(entity, "missing " + id);\n'
        "    return entity;\n  }\n"
        "  <E, I> E checkEntityId(I id, Finder<String, I, E> finder, String op, String... more) {\n"
        "    return null;\n  }\n"
        "  Device checkDeviceId(Long id, String op) {\n"
        "    return checkEntityId(id, devices::findByTenantAndId, op);\n  }\n"
        "  DeviceService devices;\n}\n"
        '@RestController @RequestMapping("/api") class Api extends Base {\n'
        '  @GetMapping("/devices/{id}") Device get(@PathVariable Long id) {\n'
        '    return checkDeviceId(id, "read");\n  }\n}\n'
    )
    result = _tree(tmp_path, {"pom.xml": POM, "src/main/java/app/Api.java": base})
    assert _row(result, "GET", "/api/devices/{id}")["ownership"] == "scoped"


# Qodo's review of the allow-list: request data passing as the caller, and real protection or
# real method security going unseen.
QODO = (
    "package qodo;\n"
    "import org.springframework.web.bind.annotation.*;\n"
    "import java.security.Principal;\n"
    "@Entity class Card { Long id; String ownerEmail; }\n"
    "@Entity class Note { Long id; String ownerEmail; }\n"
    "class Dto { String getRemoteUser() { return null; } }\n"
    "interface CustomizedCardRepository { void touch(Card c); }\n"
    "interface CardRepository extends JpaRepository<Card, Long>, CustomizedCardRepository {\n"
    "  Optional<Card> findByIdAndOwnerEmail(Long id, String ownerEmail);\n}\n"
    "interface NoteRepository extends JpaRepository<Note, Long> {\n"
    "  Optional<Note> findByIdAndOwnerEmail(Long id, String ownerEmail);\n}\n"
    "class NoteRepositoryImpl {\n"
    "  Optional<Note> findByIdAndOwnerEmail(Long id, String e) { return Optional.empty(); }\n}\n"
    "class OtherRepositoryImpl {\n"
    "  Optional<Card> findByIdAndOwnerEmail(Long id, String e) { return Optional.empty(); }\n}\n"
    '@RestController @RequestMapping("/q")\n'
    "class Qodo {\n"
    "  private CardRepository cards;\n"
    "  private NoteRepository notes;\n"
    "  private Registry registry;\n"
    "  @Autowired private Owners owners;\n"
    '  @GetMapping("/selected/{id}")\n'
    "  Card selected(@PathVariable Long id, @RequestParam String tenant, Principal me) {\n"
    "    Resolver resolver = registry.forTenant(tenant);\n"
    "    return cards.findByIdAndOwnerEmail(id, resolver.resolve(me.getName())).orElseThrow();\n"
    "  }\n"
    '  @GetMapping("/injected/{id}") Card injected(@PathVariable Long id, Principal me) {\n'
    "    return cards.findByIdAndOwnerEmail(id, owners.resolve(me.getName())).orElseThrow();\n"
    "  }\n"
    '  @GetMapping("/fragment/{id}") Card fragment(@PathVariable Long id, Principal me) {\n'
    "    return cards.findByIdAndOwnerEmail(id, me.getName()).orElseThrow();\n  }\n"
    '  @GetMapping("/custom/{id}") Note custom(@PathVariable Long id, Principal me) {\n'
    "    return notes.findByIdAndOwnerEmail(id, me.getName()).orElseThrow();\n  }\n"
    '  @GetMapping("/body/{id}") Card body(@PathVariable Long id, @RequestBody Dto body) {\n'
    "    return cards.findByIdAndOwnerEmail(id, body.getRemoteUser()).orElseThrow();\n  }\n"
    '  @GetMapping("/request/{id}")\n'
    "  Card request(@PathVariable Long id, HttpServletRequest request) {\n"
    "    return cards.findByIdAndOwnerEmail(id, request.getRemoteUser()).orElseThrow();\n  }\n"
    "}\n"
)


@pytest.fixture(scope="module")
def qodo(tmp_path_factory: pytest.TempPathFactory) -> dict:
    root = tmp_path_factory.mktemp("qodo")
    return _tree(
        root,
        {
            "pom.xml": POM,
            "src/main/java/qodo/MethodSecurity.java": METHOD_SECURITY,
            "src/main/java/qodo/Qodo.java": QODO,
        },
    )


@pytest.mark.parametrize(
    ("method", "pattern", "ownership"),
    [
        ("GET", "/q/selected/{id}", "unchecked"),  # a resolver the request chose
        ("GET", "/q/injected/{id}", "scoped"),  # an injected resolver handed only the caller
        ("GET", "/q/fragment/{id}", "scoped"),  # a fragment interface beside the entity's base
        ("GET", "/q/custom/{id}", "unchecked"),  # this repository's own `…Impl` implements it
        ("GET", "/q/body/{id}", "caller-blind"),  # a request body's getter isn't the caller
        ("GET", "/q/request/{id}", "scoped"),  # the servlet request's authenticated user
    ],
)
def test_the_caller_and_the_query_come_from_where_qodo_said(
    qodo: dict, method: str, pattern: str, ownership: str
) -> None:
    row = _row(qodo, method, pattern)
    assert row["ownership"] == ownership
    assert row["judgement_required"] is (ownership in ("caller-blind", "unchecked"))


BEAN_CHECKED = (
    "import org.springframework.web.bind.annotation.*;\n"
    "@Entity class Card { Long id; String ownerEmail; }\n"
    "@RestController class Api {\n"
    "  private EntityManager em;\n"
    '  @PreAuthorize("@access.canRead(#id, authentication)")\n'
    '  @GetMapping("/cards/{id}") Card get(@PathVariable Long id) {\n'
    "    return em.find(Card.class, id);\n  }\n}\n"
)


@pytest.mark.parametrize(
    ("rel", "config"),
    [
        # a production package named `test` is no test source
        ("src/main/java/com/test/SecurityConfig.java", METHOD_SECURITY),
        # enabled through an annotation of the application's own
        (
            "src/main/java/app/SecurityConfig.java",
            "import org.springframework.security.config.annotation.method.configuration.*;\n"
            "@EnableMethodSecurity @interface EnableSecurity {}\n"
            "@EnableSecurity class SecurityConfig {}\n",
        ),
    ],
)
def test_method_security_enabled_in_the_application_is_seen(
    tmp_path, rel: str, config: str
) -> None:
    result = _tree(
        tmp_path, {"pom.xml": POM, rel: config, "src/main/java/app/Api.java": BEAN_CHECKED}
    )
    assert _row(result, "GET", "/cards/{id}")["ownership"] == "checked"


@pytest.mark.parametrize(
    ("field", "constructor", "mutation", "receiver", "protected"),
    [
        ("private Owners owners;", "", "", "owners", False),
        ("@Autowired private Owners owners;", "", "", "owners", True),
        ("@Inject private Owners owners;", "", "", "owners", True),
        ("@Resource private Owners owners;", "", "", "this.owners", True),
        (
            "@Autowired private Owners owners;",
            "",
            "owners = registry.forTenant(tenant);",
            "owners",
            False,
        ),
        (
            "@Autowired private Owners owners;",
            "",
            "this.owners = registry.forTenant(tenant);",
            "owners",
            False,
        ),
        (
            "@Autowired private Owners owners;",
            "",
            "owners.tenant = tenant;",
            "owners",
            False,
        ),
        (
            "@Autowired private Owners owners;",
            "",
            "this.owners.setTenant(tenant);",
            "this.owners",
            False,
        ),
        (
            "private final Owners owners;",
            "Api(Owners owners) { this.owners = owners; }",
            "",
            "owners",
            True,
        ),
        (
            "private Owners owners;",
            "Api(Owners supplied) { this.owners = supplied; }",
            "this.owners = registry.forTenant(tenant);",
            "owners",
            False,
        ),
        (
            "private Owners owners;",
            "Api(String tenant) { this.owners = registry.forTenant(tenant); }",
            "",
            "owners",
            False,
        ),
        (
            "@Autowired private Owners owners = new Owners();",
            "",
            "",
            "owners",
            False,
        ),
        (
            "@Autowired private Owners owners;",
            "",
            "Owners owners = registry.forTenant(tenant); owners = new Owners();",
            "owners",
            True,
        ),
        (
            "@Autowired private Owners owners;",
            "",
            "owners = registry.forTenant(tenant); { Owners owners = null; }",
            "owners",
            False,
        ),
        (
            "@Autowired private Owners Owners;",
            "",
            "Owners = registry.forTenant(tenant);",
            "Owners",
            False,
        ),
        (
            "private final Owners owners;",
            "Api(Owners owners) { this.owners = owners; this.owners = owners; }",
            "",
            "owners",
            False,
        ),
    ],
)
def test_resolver_field_needs_injection_and_checkout_wide_stability(
    tmp_path, field, constructor, mutation, receiver, protected
) -> None:
    source = (
        "package provenance;\n"
        "import org.springframework.web.bind.annotation.*;\n"
        "import java.security.Principal;\n"
        "class Card { Long id; String ownerEmail; }\n"
        "class Owners { String tenant; String resolve(String caller) { return tenant; }"
        " void setTenant(String tenant) { this.tenant = tenant; } }\n"
        "class Registry { Owners forTenant(String tenant) { return null; } }\n"
        "interface CardRepository extends JpaRepository<Card, Long> {\n"
        " Optional<Card> findByIdAndOwnerEmail(Long id, String ownerEmail);\n}\n"
        "@RestController class Api {\n"
        " private CardRepository cards;\n"
        " private Registry registry;\n"
        f" {field}\n {constructor}\n"
        ' @PostMapping("/select") void select(@RequestParam String tenant) {\n'
        f"  {mutation}\n }}\n"
        ' @GetMapping("/cards/{id}") Card get(@PathVariable Long id, Principal me) {\n'
        f"  return cards.findByIdAndOwnerEmail(id, {receiver}.resolve(me.getName()))"
        ".orElseThrow();\n }\n}\n"
    )
    result = _tree(
        tmp_path,
        {
            "pom.xml": POM,
            "src/main/java/provenance/Api.java": source,
            "src/main/java/provenance/Security.java": METHOD_SECURITY,
        },
    )
    row = _row(result, "GET", "/cards/{id}")
    if protected:
        assert row["ownership"] == "scoped"
        assert row["judgement_required"] is False
    else:
        assert row["ownership"] in {"caller-blind", "unchecked"}
        assert row["judgement_required"] is True


@pytest.mark.parametrize(
    ("kind", "imports", "declaration", "extra", "protected"),
    [
        (
            "HttpServletRequest",
            "",
            "class HttpServletRequest { String getRemoteUser() { return null; } }",
            {},
            False,
        ),
        (
            "provenance.HttpServletRequest",
            "",
            "class HttpServletRequest { String getRemoteUser() { return null; } }",
            {},
            False,
        ),
        (
            "Bodies.HttpServletRequest",
            "",
            "class Bodies { static class HttpServletRequest {"
            " String getRemoteUser() { return null; } } }",
            {},
            False,
        ),
        (
            "HttpServletRequest",
            "",
            "record HttpServletRequest(String owner) {"
            " public String getRemoteUser() { return owner; } }",
            {},
            False,
        ),
        (
            "HttpServletRequest",
            "",
            'enum HttpServletRequest { OTHER; public String getRemoteUser() { return "other"; } }',
            {},
            False,
        ),
        (
            "HttpServletRequest",
            "import other.HttpServletRequest;\n",
            "",
            {
                "src/main/java/other/HttpServletRequest.java": "package other;"
                " public class HttpServletRequest {"
                " public String getRemoteUser() { return null; } }"
            },
            False,
        ),
        (
            "jakarta.servlet.http.HttpServletRequest",
            "",
            "class HttpServletRequest { String getRemoteUser() { return null; } }",
            {},
            True,
        ),
        (
            "HttpServletRequest",
            "import jakarta.servlet.http.HttpServletRequest;\n",
            "",
            {
                "src/main/java/other/HttpServletRequest.java": "package other;"
                " public class HttpServletRequest {"
                " public String getRemoteUser() { return null; } }"
            },
            True,
        ),
        (
            "jakarta.servlet.http.HttpServletRequest",
            "",
            "",
            {
                "src/main/java/jakarta/servlet/http/HttpServletRequest.java": (
                    "package jakarta.servlet.http; public class HttpServletRequest {"
                    " public String getRemoteUser() { return null; } }"
                )
            },
            False,
        ),
    ],
)
def test_request_getter_identity_excludes_checkout_lookalikes(
    tmp_path, kind, imports, declaration, extra, protected
) -> None:
    binding = "" if protected else "@RequestBody "
    source = (
        "package provenance;\n"
        "import org.springframework.web.bind.annotation.*;\n"
        f"{imports}{declaration}\n"
        "class Card { Long id; String ownerEmail; }\n"
        "interface CardRepository extends JpaRepository<Card, Long> {\n"
        " Optional<Card> findByIdAndOwnerEmail(Long id, String ownerEmail);\n}\n"
        "@RestController class Api {\n private CardRepository cards;\n"
        ' @GetMapping("/requests/{id}") Card get(@PathVariable Long id,'
        f" {binding}{kind} body) {{\n"
        "  return cards.findByIdAndOwnerEmail(id, body.getRemoteUser()).orElseThrow();\n"
        " }\n}\n"
    )
    result = _tree(
        tmp_path,
        {
            "pom.xml": POM,
            "src/main/java/provenance/Api.java": source,
            "src/main/java/provenance/Security.java": METHOD_SECURITY,
            **extra,
        },
    )
    row = _row(result, "GET", "/requests/{id}")
    if protected:
        assert row["ownership"] == "scoped"
        assert row["judgement_required"] is False
    else:
        assert row["ownership"] in {"caller-blind", "unchecked"}
        assert row["judgement_required"] is True


@pytest.mark.parametrize(
    ("mutation", "receiver"),
    [
        ("Owners alias = owners; alias.setTenant(tenant);", "this.owners"),
        ("Owners alias = this.owners; alias.setTenant(tenant);", "owners"),
        ("Owners alias = owners; alias = registry.forTenant(tenant);", "owners"),
        ("Owners alias = owners; use(alias);", "owners"),
        ("use(owners);", "owners"),
        ("use(this.owners);", "owners"),
        ("Owners alias = owners::resolve;", "owners"),
        ("return owners;", "owners"),
        ("return this.owners;", "owners"),
    ],
)
def test_an_aliased_resolver_field_is_not_trusted(tmp_path, mutation: str, receiver: str) -> None:
    """Once the field value escapes under another name, its provenance is unproven: a request
    parameter may reach a setter through the alias, so `this.owners.resolve(...)` stays judged."""
    source = (
        "package provenance;\n"
        "import org.springframework.web.bind.annotation.*;\n"
        "import java.security.Principal;\n"
        "class Card { Long id; String ownerEmail; }\n"
        "class Owners { String tenant; String resolve(String caller) { return tenant; }"
        " void setTenant(String tenant) { this.tenant = tenant; } }\n"
        "class Registry { Owners forTenant(String tenant) { return null; } }\n"
        "interface CardRepository extends JpaRepository<Card, Long> {\n"
        " Optional<Card> findByIdAndOwnerEmail(Long id, String ownerEmail);\n}\n"
        "@RestController class Api {\n"
        " private CardRepository cards;\n"
        " private Registry registry;\n"
        " @Autowired private Owners owners;\n"
        " void use(Object o) {}\n"
        ' @PostMapping("/select") void select(@RequestParam String tenant) {\n'
        f"  {mutation}\n"
        " }\n"
        ' @GetMapping("/cards/{id}") Card get(@PathVariable Long id, Principal me) {\n'
        f"  return cards.findByIdAndOwnerEmail(id, {receiver}.resolve(me.getName()))"
        ".orElseThrow();\n }\n}\n"
    )
    result = _tree(
        tmp_path,
        {
            "pom.xml": POM,
            "src/main/java/provenance/Api.java": source,
            "src/main/java/provenance/Security.java": METHOD_SECURITY,
        },
    )
    row = _row(result, "GET", "/cards/{id}")
    assert row["ownership"] in {"caller-blind", "unchecked"}
    assert row["judgement_required"] is True


@pytest.mark.parametrize(
    ("kind", "outer_import", "outer_rel", "outer_src"),
    [
        (
            "Dto.HttpServletRequest",
            "import other.Dto;\n",
            "src/main/java/other/Dto.java",
            "package other; public class Dto { public static class HttpServletRequest {"
            " public String getRemoteUser() { return null; } } }\n",
        ),
        (
            "Api.Principal",
            "import other.Api;\n",
            "src/main/java/other/Api.java",
            "package other; public class Api { public static class Principal {"
            " public String getRemoteUser() { return null; } } }\n",
        ),
        (
            "other.Dto.HttpServletRequest",
            "",
            "src/main/java/other/Dto.java",
            "package other; public class Dto { public static class HttpServletRequest {"
            " public String getRemoteUser() { return null; } } }\n",
        ),
    ],
)
def test_imported_and_qualified_outer_lookalikes_are_checkout_types(
    tmp_path, kind: str, outer_import: str, outer_rel: str, outer_src: str
) -> None:
    """A nested lookalike reached through an outer class from another package (`Dto.HttpServlet…`
    with `import other.Dto`, or fully qualified) is a checkout type, not a framework request."""
    source = (
        "package provenance;\n"
        "import org.springframework.web.bind.annotation.*;\n"
        f"{outer_import}"
        "class Card { Long id; String ownerEmail; }\n"
        "interface CardRepository extends JpaRepository<Card, Long> {\n"
        " Optional<Card> findByIdAndOwnerEmail(Long id, String ownerEmail);\n}\n"
        "@RestController class Api {\n private CardRepository cards;\n"
        ' @GetMapping("/requests/{id}") Card get(@PathVariable Long id,'
        f" @RequestBody {kind} body) {{\n"
        "  return cards.findByIdAndOwnerEmail(id, body.getRemoteUser()).orElseThrow();\n"
        " }\n}\n"
    )
    result = _tree(
        tmp_path,
        {
            "pom.xml": POM,
            "src/main/java/provenance/Api.java": source,
            outer_rel: outer_src,
            "src/main/java/provenance/Security.java": METHOD_SECURITY,
        },
    )
    row = _row(result, "GET", "/requests/{id}")
    assert row["ownership"] in {"caller-blind", "unchecked"}
    assert row["judgement_required"] is True


def test_inherited_field_types_are_judged_by_their_declaring_file(tmp_path) -> None:
    """A superclass field of a checkout lookalike type (`HttpServletRequest` in package a) is
    request data even when the subclass imports the real framework type."""
    base = "package a;\npublic class Base {\n  protected HttpServletRequest request;\n}\n"
    lookalike = (
        "package a;\n"
        "public class HttpServletRequest { public String getRemoteUser() { return null; } }\n"
    )
    api = (
        "package b;\n"
        "import org.springframework.web.bind.annotation.*;\n"
        "import jakarta.servlet.http.HttpServletRequest;\n"
        "import a.Base;\n"
        "class Card { Long id; String ownerEmail; }\n"
        "interface CardRepository extends JpaRepository<Card, Long> {\n"
        "  Optional<Card> findByIdAndOwnerEmail(Long id, String ownerEmail);\n}\n"
        "@RestController class Api extends Base {\n"
        "  private CardRepository cards;\n"
        '  @GetMapping("/cards/{id}") Card get(@PathVariable Long id) {\n'
        "    return cards.findByIdAndOwnerEmail(id, request.getRemoteUser()).orElseThrow();\n"
        "  }\n"
        "}\n"
    )
    result = _tree(
        tmp_path,
        {
            "pom.xml": POM,
            "src/main/java/a/Base.java": base,
            "src/main/java/a/HttpServletRequest.java": lookalike,
            "src/main/java/b/Api.java": api,
            "src/main/java/b/Security.java": METHOD_SECURITY,
        },
    )
    row = _row(result, "GET", "/cards/{id}")
    assert row["ownership"] in {"caller-blind", "unchecked"}
    assert row["judgement_required"] is True


def test_an_inherited_real_request_field_stays_the_caller(tmp_path) -> None:
    """The same shape with a genuine inherited servlet request field stays scoped: the declaring
    file's own type, not an import in the subclass, decides."""
    base = (
        "package a;\n"
        "import jakarta.servlet.http.HttpServletRequest;\n"
        "public class Base {\n"
        "  protected HttpServletRequest request;\n"
        "}\n"
    )
    api = (
        "package b;\n"
        "import org.springframework.web.bind.annotation.*;\n"
        "import a.Base;\n"
        "class Card { Long id; String ownerEmail; }\n"
        "interface CardRepository extends JpaRepository<Card, Long> {\n"
        "  Optional<Card> findByIdAndOwnerEmail(Long id, String ownerEmail);\n}\n"
        "@RestController class Api extends Base {\n"
        "  private CardRepository cards;\n"
        '  @GetMapping("/cards/{id}") Card get(@PathVariable Long id) {\n'
        "    return cards.findByIdAndOwnerEmail(id, request.getRemoteUser()).orElseThrow();\n"
        "  }\n"
        "}\n"
    )
    result = _tree(
        tmp_path,
        {
            "pom.xml": POM,
            "src/main/java/a/Base.java": base,
            "src/main/java/b/Api.java": api,
            "src/main/java/b/Security.java": METHOD_SECURITY,
        },
    )
    row = _row(result, "GET", "/cards/{id}")
    assert row["ownership"] == "scoped"
    assert row["judgement_required"] is False
