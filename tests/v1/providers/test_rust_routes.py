"""The axum and actix-web route x guard matrix: layer order, nesting, extractors, actix scopes
and route macros, and the gaps for what isn't enumerated."""

from __future__ import annotations

from pathlib import Path

from traust_core.v1.providers import rust_routes
from traust_core.v1.providers.route_guards import route_guards
from traust_core.v1.providers.tree import tree_files


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


def test_axum_layer_guards_only_the_routes_added_before_it(tmp_path):
    _write(
        tmp_path,
        "src/main.rs",
        "use axum::{routing::get, Router, middleware};\n"
        "fn app() -> Router {\n    Router::new()\n"
        '        .route("/items", get(list).post(create))\n'
        "        .route_layer(middleware::from_fn(require_auth))\n"
        '        .route("/health", get(health))\n}\n'
        "async fn list() {}\nasync fn create() {}\nasync fn health() {}\n",
    )
    result = _enum(tmp_path)
    assert _patterns(result, "axum") == {("GET", "/items"), ("POST", "/items"), ("GET", "/health")}
    assert _route(result, "POST", "/items")["scope_guards"] == ["require_auth"]
    health = _route(result, "GET", "/health")
    assert health["scope_guards"] == [] and health["judgement_required"] and health["asymmetry"]
    assert result["coverage_gaps"] == []


def test_axum_nest_and_merge_across_modules_with_prefixes(tmp_path):
    _write(
        tmp_path,
        "src/api.rs",
        "use axum::{routing::{get, delete}, Router};\n"
        "pub fn router() -> Router<AppState> {\n"
        '    Router::<AppState>::new().route("/users/:id", get(user).delete(remove))\n}\n'
        'pub fn admin() -> Router { Router::new().route("/stats", get(stats)) }\n',
    )
    _write(
        tmp_path,
        "src/main.rs",
        "use axum::Router;\n"
        "fn app() -> Router {\n"
        "    let admin = api::admin().layer(RequireAuthorizationLayer::bearer(token));\n"
        "    Router::new()\n"
        '        .nest("/api", api::router())\n'
        '        .nest("/admin", admin)\n'
        "        .layer(CorsLayer::permissive())\n}\n",
    )
    result = _enum(tmp_path)
    assert _patterns(result, "axum") == {
        ("GET", "/api/users/:id"),
        ("DELETE", "/api/users/:id"),
        ("GET", "/admin/stats"),
    }
    assert _route(result, "GET", "/admin/stats")["scope_guards"] == [
        "RequireAuthorizationLayer::bearer",
        "token",
    ]
    # CORS sets headers, it never refuses
    assert _route(result, "GET", "/api/users/:id")["scope_guards"] == []
    assert _route(result, "GET", "/api/users/:id")["registration"]["path"] == "src/api.rs"


def test_axum_extractors_and_method_router_layers_guard_a_route(tmp_path):
    _write(
        tmp_path,
        "src/main.rs",
        "use axum::{routing::{get, post}, Router};\n"
        "fn app() -> Router {\n    Router::new()\n"
        '        .route("/me", get(me))\n'
        '        .route("/upload", post(upload).layer(from_fn(verify_token)))\n'
        '        .route("/session", get(session_info))\n}\n'
        "async fn me(AuthUser(user): AuthUser, State(s): State<AppState>) -> String { todo!() }\n"
        "async fn upload() {}\n"
        "async fn session_info(session: Session) {}\n",
    )
    result = _enum(tmp_path)
    me = _route(result, "GET", "/me")
    assert me["guards"] == ["extractor:AuthUser"] and me["handler"]["line"] == 8
    assert _route(result, "POST", "/upload")["guards"] == ["verify_token"]
    # a session extractor reads state, it never refuses a request
    assert _route(result, "GET", "/session")["guards"] == []


def test_actix_scopes_wrap_every_service_and_macros_carry_paths(tmp_path):
    _write(
        tmp_path,
        "src/main.rs",
        "use actix_web::{get, post, web, App, HttpServer};\n"
        '#[get("/users/{id}")]\nasync fn user(id: web::Path<u32>) -> String { todo!() }\n'
        '#[post("/users")]\n#[protect("ADMIN")]\nasync fn create() -> String { todo!() }\n'
        '#[get("/health")]\nasync fn health() -> String { todo!() }\n'
        "fn main() {\n    HttpServer::new(|| {\n        App::new()\n"
        "            .service(health)\n"
        '            .service(web::scope("/v1").wrap(HttpAuthentication::bearer(validator))'
        ".service(user).service(create))\n"
        '            .route("/ping", web::get().to(ping))\n    });\n}\n'
        'async fn ping() -> &\'static str { "pong" }\n',
    )
    result = _enum(tmp_path)
    assert _patterns(result, "actix-web") == {
        ("GET", "/health"),
        ("GET", "/v1/users/{id}"),
        ("POST", "/v1/users"),
        ("GET", "/ping"),
    }
    user = _route(result, "GET", "/v1/users/{id}")
    assert user["scope_guards"] == ["HttpAuthentication::bearer"]
    assert _route(result, "POST", "/v1/users")["guards"] == ['#[protect("ADMIN")]']
    assert _route(result, "GET", "/health")["scope_guards"] == []
    assert _route(result, "GET", "/ping")["handler"]["expr"] == "ping"


def test_actix_configure_resources_and_unregistered_macros(tmp_path):
    _write(
        tmp_path,
        "src/routes.rs",
        "use actix_web::{get, web};\n"
        '#[get("/orphan")]\nasync fn orphan() -> String { todo!() }\n'
        "pub fn config(cfg: &mut web::ServiceConfig) {\n"
        '    cfg.service(web::resource("/items").route(web::get().to(list)).route(web::post()'
        ".to(add)));\n}\n"
        "async fn list(claims: Claims) {}\nasync fn add() {}\n",
    )
    _write(
        tmp_path,
        "src/main.rs",
        "use actix_web::App;\nfn app() { App::new().configure(routes::config); }\n",
    )
    result = _enum(tmp_path)
    assert _route(result, "GET", "/items")["guards"] == ["extractor:Claims"]
    assert _route(result, "POST", "/items")["guards"] == []
    orphan = _route(result, "GET", "/orphan")
    assert orphan["unguard_markers"] == [rust_routes.ACTIX_UNREGISTERED]
    assert orphan["judgement_required"]


def test_a_route_path_from_a_constant_is_dynamic(tmp_path):
    _write(
        tmp_path,
        "src/main.rs",
        "use axum::{routing::get, Router};\n"
        "fn app() -> Router { Router::new().route(PATHS.health, get(health)) }\n"
        "async fn health() {}\n",
    )
    [row] = _enum(tmp_path)["routes"]
    assert row["pattern_dynamic"] and row["pattern"] == "PATHS.health"


def test_without_the_rust_extra_routes_are_a_named_gap(tmp_path, monkeypatch):
    monkeypatch.setattr(rust_routes, "parser", lambda: None)
    _write(
        tmp_path,
        "src/main.rs",
        'use axum::Router;\nfn app() -> Router { Router::new().route("/x", get(x)) }\n',
    )
    result = _enum(tmp_path)
    [gap] = result["coverage_gaps"]
    assert gap["system"] == "axum" and "traust-core[rust]" in gap["reason"]
    assert result["routes"] == []


def test_a_framework_used_with_no_recognized_route_is_a_gap(tmp_path):
    _write(tmp_path, "src/lib.rs", "use actix_web::HttpResponse;\npub fn ok() -> HttpResponse {}\n")
    [gap] = _enum(tmp_path)["coverage_gaps"]
    assert gap["system"] == "actix-web" and "UNENUMERATED" in gap["reason"]


def test_session_and_identity_middleware_loads_state_but_doesnt_guard(tmp_path):
    _write(
        tmp_path,
        "src/main.rs",
        "use actix_web::{web, App};\n"
        "fn app() {\n    App::new()\n"
        "        .wrap(IdentityMiddleware::default())\n"
        "        .wrap(SessionMiddleware::builder(CookieSessionStore::default(), key)"
        ".cookie_secure(false).build())\n"
        '        .route("/", web::get().to(index))\n'
        '        .route("/login", web::post().to(login))\n}\n'
        "async fn index(user: Option<Identity>) {}\n"
        "async fn login(form: web::Form<AuthPayload>, session: Session) { session.insert(1); }\n",
    )
    result = _enum(tmp_path)
    assert _route(result, "GET", "/")["scope_guards"] == []
    assert _route(result, "GET", "/")["guards"] == ["extractor:Identity"]
    # a login form's payload type and a session write are not guards
    assert _route(result, "POST", "/login")["guards"] == []
