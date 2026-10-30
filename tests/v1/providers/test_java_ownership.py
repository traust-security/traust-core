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
    "  void audit(Long invoiceId) { trail.record(invoiceId); }\n}\n"
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
        ("GET", "/api/filtered/{id}", "scoped", False),
        ("DELETE", "/api/invoices/{id}", "checked", False),
        ("PUT", "/api/invoices/{id}", "checked", False),
        ("GET", "/api/currencies/{code}", "none", False),
        ("GET", "/api/invoices/{id}/total", "caller-blind", True),
        ("GET", "/api/invoices/{id}/audit", "unknown", False),
        ("GET", "/api/raw/{id}", "unchecked", True),
        ("DELETE", "/api/admin/invoices/{id}", "n/a", False),
        ("GET", "/api/clerk/invoices/{id}", "caller-blind", True),
        ("GET", "/api/invoices", "n/a", False),
        ("GET", "/docs/{id}", "scoped", False),
        ("DELETE", "/docs/{id}", "caller-blind", True),
        ("GET", "/api/owned/{id}", "scoped", False),
        ("GET", "/api/keyed/{raw}", "caller-blind", True),
        ("GET", "/api/logged/{id}", "unchecked", True),
        ("GET", "/api/permitted/{id}", "checked", False),
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
