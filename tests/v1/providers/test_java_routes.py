"""The Spring and JAX-RS route x guard matrix: annotations, Spring Security request-matcher
rules, Quarkus HTTP permissions, and the gaps for what isn't enumerated."""

from __future__ import annotations

from pathlib import Path

import pytest

from traust_core.v1.providers import java_routes
from traust_core.v1.providers.route_guards import route_guards
from traust_core.v1.providers.tree import tree_files

SPRING = "import org.springframework.web.bind.annotation.*;\n"
JAXRS = "import jakarta.ws.rs.*;\n"
ITEMS_API = (
    SPRING + "@RestController class Api {\n"
    '  @GetMapping("/items") String list() { return ""; }\n}\n'
)
METHOD_SECURITY = (
    "import org.springframework.security.config.annotation.method.configuration.*;\n"
    "@EnableMethodSecurity class MethodSecurity {}\n"
)


def _write(root: Path, rel: str, text: str) -> None:
    path = root / rel
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(text)


def _enum(root: Path) -> dict:
    return route_guards(tree_files(root)).model_dump(mode="json")


def _route(result: dict, method: str, pattern: str) -> dict:
    [row] = [r for r in result["routes"] if r["method"] == method and r["pattern"] == pattern]
    return row


def _patterns(result: dict, family: str) -> set[tuple[str, str]]:
    return {(r["method"], r["pattern"]) for r in result["routes"] if r["family"] == family}


def test_spring_controller_prefix_method_guard_and_bare_sibling(tmp_path):
    _write(tmp_path, "src/main/java/app/MethodSecurity.java", METHOD_SECURITY)
    _write(
        tmp_path,
        "src/main/java/app/Pets.java",
        SPRING + '@RestController\n@RequestMapping("/api/pets")\nclass Pets {\n'
        '  @GetMapping("/{id}") Pet get(@PathVariable String id) { return null; }\n'
        '  @PreAuthorize("hasRole(\'ADMIN\')") @DeleteMapping("/{id}") void delete() {}\n'
        "  @PostMapping Pet create() { return null; }\n"
        "  void helper() {}\n}\n",
    )
    result = _enum(tmp_path)
    assert _patterns(result, "spring") == {
        ("GET", "/api/pets/{id}"),
        ("DELETE", "/api/pets/{id}"),
        ("POST", "/api/pets"),
    }
    delete = _route(result, "DELETE", "/api/pets/{id}")
    assert delete["guards"] == ["@PreAuthorize(\"hasRole('ADMIN')\")"]
    assert delete["unguard_markers"] == [] and delete["view_class"] == "Pets"
    get = _route(result, "GET", "/api/pets/{id}")
    assert get["handler"]["expr"] == "Pets.get"
    assert get["judgement_required"] and get["asymmetry"]
    assert result["coverage_gaps"] == []


def test_method_security_annotations_without_method_security_are_judged(tmp_path):
    _write(
        tmp_path,
        "src/main/java/app/Admin.java",
        SPRING + "@RestController class Admin {\n"
        '  @Secured("ROLE_ADMIN") @PostMapping("/admin/reset") void reset() {}\n}\n',
    )
    row = _route(_enum(tmp_path), "POST", "/admin/reset")
    assert row["guards"] == ['@Secured("ROLE_ADMIN")']
    assert row["unguard_markers"] == [java_routes.METHOD_SECURITY_OFF]
    assert row["judgement_required"]


def test_request_matcher_rules_apply_first_match_by_verb(tmp_path):
    _write(
        tmp_path,
        "src/main/java/app/Security.java",
        "import org.springframework.security.web.SecurityFilterChain;\n"
        "class Security {\n"
        "  @Bean SecurityFilterChain chain(HttpSecurity http) throws Exception {\n"
        "    http.authorizeHttpRequests(a -> a\n"
        '      .requestMatchers("/public/**", "/healthz").permitAll()\n'
        '      .requestMatchers(HttpMethod.POST, "/api/**").hasRole("ADMIN")\n'
        "      .anyRequest().authenticated());\n    return http.build();\n  }\n}\n",
    )
    _write(
        tmp_path,
        "src/main/java/app/Api.java",
        SPRING + "@RestController class Api {\n"
        '  @GetMapping("/public/docs/{page}") String docs() { return ""; }\n'
        '  @GetMapping("/healthz") String health() { return ""; }\n'
        '  @PostMapping("/api/items") void create() {}\n'
        '  @GetMapping("/api/items") String list() { return ""; }\n'
        '  @RequestMapping("/api/any") String any() { return ""; }\n}\n',
    )
    result = _enum(tmp_path)
    docs = _route(result, "GET", "/public/docs/{page}")
    assert docs["unguard_markers"] == ["spring-security:permitAll"] and docs["judgement_required"]
    assert _route(result, "GET", "/healthz")["unguard_markers"] == ["spring-security:permitAll"]
    assert _route(result, "POST", "/api/items")["scope_guards"] == [
        'spring-security:hasRole("ADMIN")'
    ]
    assert _route(result, "GET", "/api/items")["scope_guards"] == ["spring-security:authenticated"]
    # a POST-only rule can't guard a route that takes every verb
    assert _route(result, "ALL", "/api/any")["scope_guards"] == ["spring-security:authenticated"]


def test_a_scoped_filter_chain_wins_over_the_catch_all(tmp_path):
    _write(
        tmp_path,
        "src/main/java/app/Security.java",
        "class Security {\n"
        "  @Bean @Order(1) SecurityFilterChain api(HttpSecurity http) throws Exception {\n"
        '    http.securityMatcher("/api/**").authorizeHttpRequests(a -> a.anyRequest()'
        ".authenticated());\n    return http.build();\n  }\n"
        "  @Bean SecurityFilterChain web(HttpSecurity http) throws Exception {\n"
        "    http.authorizeHttpRequests(a -> a.anyRequest().permitAll());\n"
        "    return http.build();\n  }\n}\n",
    )
    _write(
        tmp_path,
        "src/main/java/app/Web.java",
        SPRING + "@Controller class Web {\n"
        '  @GetMapping("/api/me") String me() { return ""; }\n'
        '  @GetMapping("/") String home() { return ""; }\n}\n',
    )
    result = _enum(tmp_path)
    assert _route(result, "GET", "/api/me")["scope_guards"] == ["spring-security:authenticated"]
    assert _route(result, "GET", "/")["unguard_markers"] == ["spring-security:permitAll"]


def test_conditional_filter_chains_report_every_outcome_and_are_judged(tmp_path):
    chain = (
        "{cls}class {name} {{\n"
        "  @Bean SecurityFilterChain f(HttpSecurity http) throws Exception {{\n"
        "    http.authorizeHttpRequests(a -> a.anyRequest().{rule}());\n"
        "    return http.build();\n  }}\n}}\n"
    )
    for name, cond, rule in (("Off", "false", "permitAll"), ("On", "true", "authenticated")):
        cls = f'@ConditionalOnProperty(name = "app.security", havingValue = "{cond}")\n'
        text = chain.format(cls=cls, name=name, rule=rule)
        _write(tmp_path, f"src/main/java/app/{name}.java", text)
    _write(tmp_path, "src/main/java/app/Api.java", ITEMS_API)
    row = _route(_enum(tmp_path), "GET", "/items")
    assert row["scope_guards"] == ["spring-security:authenticated"]
    assert row["unguard_markers"] == [
        java_routes.CONDITIONAL_CONFIG,
        "spring-security:permitAll",
    ]
    assert row["judgement_required"]


def test_the_security_starter_without_config_authenticates_every_route(tmp_path):
    _write(
        tmp_path,
        "pom.xml",
        "<dependency><artifactId>spring-boot-starter-security</artifactId></dependency>",
    )
    _write(
        tmp_path,
        "src/main/java/app/Api.java",
        ITEMS_API,
    )
    row = _route(_enum(tmp_path), "GET", "/items")
    assert row["scope_guards"] == [java_routes.SPRING_DEFAULT_GUARD]
    assert not row["judgement_required"]


def test_no_starter_and_no_config_leaves_routes_bare(tmp_path):
    _write(
        tmp_path,
        "src/main/java/app/Api.java",
        ITEMS_API,
    )
    row = _route(_enum(tmp_path), "GET", "/items")
    assert row["scope_guards"] == [] and row["judgement_required"]


def test_generated_api_interface_and_the_controller_that_implements_it(tmp_path):
    _write(tmp_path, "src/main/java/app/MethodSecurity.java", METHOD_SECURITY)
    _write(
        tmp_path,
        "src/main/java/api/PetApi.java",
        SPRING + '@RequestMapping("/v2")\npublic interface PetApi {\n'
        '  @GetMapping(value = Paths.PETS, produces = "application/json") List<Pet> list();\n'
        "  @PostMapping(Paths.PETS) Pet add();\n}\n",
    )
    _write(
        tmp_path,
        "src/main/java/api/Paths.java",
        'public final class Paths {\n  static final String BASE = "/pets";\n'
        '  public static final String PETS = BASE + "";\n}\n',
    )
    _write(
        tmp_path,
        "src/main/java/app/PetController.java",
        SPRING + "@RestController class PetController implements PetApi, Comparable<Pet> {\n"
        '  @PreAuthorize("isAuthenticated()") public Pet add() { return null; }\n'
        "  public List<Pet> list() { return null; }\n}\n",
    )
    result = _enum(tmp_path)
    assert _patterns(result, "spring") == {("GET", "/v2/pets"), ("POST", "/v2/pets")}
    add = _route(result, "POST", "/v2/pets")
    assert add["guards"] == ['@PreAuthorize("isAuthenticated()")']
    assert add["registration"]["path"] == "src/main/java/api/PetApi.java"
    assert add["handler"]["expr"] == "PetController.add"


def test_client_interfaces_and_abstract_bases_are_not_routes_but_subclasses_inherit(tmp_path):
    _write(
        tmp_path,
        "src/main/java/app/Clients.java",
        SPRING + '@FeignClient("billing") interface Billing {\n'
        '  @GetMapping("/invoices") List<Invoice> all();\n}\n'
        'abstract class Base {\n  @GetMapping("/status") String status() { return ""; }\n}\n'
        "@RestController class Orders extends Base {\n"
        '  @GetMapping("/orders") String orders() { return ""; }\n}\n',
    )
    result = _enum(tmp_path)
    assert _patterns(result, "spring") == {("GET", "/status"), ("GET", "/orders")}
    assert _route(result, "GET", "/status")["handler"]["expr"] == "Orders.status"


def test_request_mapping_verbs_arrays_and_unresolved_paths(tmp_path):
    _write(
        tmp_path,
        "src/main/java/app/Api.java",
        SPRING + "@RestController class Api {\n"
        '  @RequestMapping(path = {"/a", "/b"}, method = {RequestMethod.GET, RequestMethod.PUT})\n'
        '  String ab() { return ""; }\n'
        '  @GetMapping(Config.dynamicPath()) String dyn() { return ""; }\n}\n',
    )
    result = _enum(tmp_path)
    assert {("GET", "/a"), ("PUT", "/a"), ("GET", "/b"), ("PUT", "/b")} <= _patterns(
        result, "spring"
    )
    [dynamic] = [r for r in result["routes"] if r["pattern_dynamic"]]
    assert "dynamicPath" in dynamic["pattern"]


def test_jaxrs_resource_with_application_path_and_annotations(tmp_path):
    _write(
        tmp_path,
        "src/main/java/app/Rest.java",
        JAXRS + '@ApplicationPath("/rest") public class Rest extends Application {}\n',
    )
    _write(
        tmp_path,
        "src/main/java/app/Orders.java",
        JAXRS + 'import jakarta.annotation.security.*;\n@Path("/orders")\n@RolesAllowed("user")\n'
        "public class Orders {\n"
        "  @GET public List<Order> list() { return null; }\n"
        '  @GET @Path("/count") @PermitAll public int count() { return 0; }\n'
        '  @POST @RolesAllowed("admin") public void add() {}\n'
        '  @Path("/{id}/items") public Items items() { return null; }\n}\n',
    )
    result = _enum(tmp_path)
    assert _patterns(result, "jax-rs") == {
        ("GET", "/rest/orders"),
        ("GET", "/rest/orders/count"),
        ("POST", "/rest/orders"),
    }
    assert _route(result, "GET", "/rest/orders")["scope_guards"] == ['@RolesAllowed("user")']
    assert _route(result, "POST", "/rest/orders")["guards"] == ['@RolesAllowed("admin")']
    count = _route(result, "GET", "/rest/orders/count")
    assert count["unguard_markers"] == ["@PermitAll"] and count["judgement_required"]


def test_quarkus_http_permissions_most_specific_wins_and_dev_profile_is_ignored(tmp_path):
    _write(
        tmp_path,
        "src/main/resources/application.properties",
        "quarkus.http.auth.permission.authenticated.paths=/api/*\n"
        "quarkus.http.auth.permission.authenticated.policy=authenticated\n"
        "quarkus.http.auth.permission.public.paths=/api/public/*\n"
        "quarkus.http.auth.permission.public.policy=permit\n"
        "%dev.quarkus.http.auth.permission.everything.paths=/*\n"
        "%dev.quarkus.http.auth.permission.everything.policy=permit\n"
        "quarkus.security.jaxrs.deny-unannotated-endpoints=true\n",
    )
    _write(
        tmp_path,
        "src/main/java/app/Api.java",
        JAXRS + '@Path("/api")\npublic class Api {\n'
        '  @GET @Path("/public/info") public String info() { return ""; }\n'
        '  @GET @Path("/orders") public String orders() { return ""; }\n}\n'
        '@Path("/other") class Other {\n  @GET public String get() { return ""; }\n}\n',
    )
    result = _enum(tmp_path)
    info = _route(result, "GET", "/api/public/info")
    assert info["unguard_markers"] == ["quarkus:permit"]
    assert _route(result, "GET", "/api/orders")["scope_guards"] == [
        "quarkus:authenticated",
        "quarkus:deny-unannotated-endpoints",
    ]
    assert _route(result, "GET", "/other")["scope_guards"] == ["quarkus:deny-unannotated-endpoints"]


def test_a_handler_body_guard_call_counts(tmp_path):
    _write(
        tmp_path,
        "src/main/java/app/Api.java",
        SPRING + "@RestController class Api {\n"
        '  @DeleteMapping("/x") void x() { access.requireAdmin(user); repo.delete(); }\n}\n',
    )
    assert _route(_enum(tmp_path), "DELETE", "/x")["guards"] == ["call:requireAdmin"]


def test_controllers_on_interfaces_generated_at_build_time_are_a_gap(tmp_path):
    _write(
        tmp_path,
        "src/main/java/app/Owners.java",
        SPRING + '@RestController\n@RequestMapping("/api")\nclass Owners implements OwnersApi {\n'
        "  @Override @PreAuthorize(\"hasRole('OWNER')\") public Owner getOwner(int id) {"
        " return null; }\n"
        '  @GetMapping("/owners/count") public int count() { return 0; }\n}\n',
    )
    result = _enum(tmp_path)
    assert _patterns(result, "spring") == {("GET", "/api/owners/count")}
    [gap] = result["coverage_gaps"]
    assert gap["system"] == "spring" and "generated at build time" in gap["reason"]
    assert gap["evidence"] == "src/main/java/app/Owners.java"


def test_without_the_java_extra_routes_are_a_named_gap(tmp_path, monkeypatch):
    monkeypatch.setattr(java_routes, "parser", lambda: None)
    _write(
        tmp_path,
        "src/main/java/app/Api.java",
        SPRING + '@RestController class Api { @GetMapping("/x") String x() { return ""; } }\n',
    )
    result = _enum(tmp_path)
    [gap] = result["coverage_gaps"]
    assert gap["system"] == "spring" and "traust-core[java]" in gap["reason"]
    assert result["routes"] == []


@pytest.mark.parametrize(
    ("rel", "text", "system"),
    [
        (
            "src/main/kotlin/Api.kt",
            '@RestController class Api { @GetMapping("/x") fun x() = "" }\n',
            "spring (kotlin)",
        ),
        (
            "src/main/java/Api.java",
            'import io.micronaut.http.annotation.*;\n@Controller("/x") class Api {}\n',
            "micronaut",
        ),
        (
            "src/main/java/Routes.java",
            "class Routes {\n"
            '  RouterFunction<?> r() { return RouterFunctions.route(GET("/x"), h); }\n}\n',
            "spring functional routes",
        ),
        (
            "src/main/java/Config.java",
            SPRING + "class Config { }\n",
            "spring",
        ),
    ],
)
def test_detected_but_not_enumerated_is_a_gap(tmp_path, rel, text, system):
    _write(tmp_path, rel, text)
    result = _enum(tmp_path)
    assert [g["system"] for g in result["coverage_gaps"]] == [system]
    assert "UNENUMERATED" in result["coverage_gaps"][0]["reason"]
