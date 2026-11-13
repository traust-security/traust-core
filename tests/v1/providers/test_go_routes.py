"""Go HTTP routes: each router's prefixes, middleware and handlers, followed through groups,
sub-routers, mounts and the functions a router is passed to."""

from __future__ import annotations

import json
from pathlib import Path
from textwrap import dedent

import pytest

from traust_core.v1.providers.route_guards import route_guards
from traust_core.v1.providers.tree import tree_files

GO_MOD = "module example.com/app\n\ngo 1.22\n"


def _rows(tmp_path: Path, files: dict[str, str]) -> dict[tuple[str, str], dict]:
    for rel, text in {"go.mod": GO_MOD, **files}.items():
        path = tmp_path / rel
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(dedent(text))
    out = {}
    for r in route_guards(tree_files(tmp_path)).model_dump(mode="json")["routes"]:
        if r["family"] == "go-http":
            out[(r["method"], r["pattern"])] = r
    return out


def _guarded(row: dict) -> list[str]:
    return [*row["guards"], *row["scope_guards"]]


def test_net_http_method_patterns_mounts_and_a_wrapped_mux(tmp_path: Path) -> None:
    rows = _rows(
        tmp_path,
        {
            "main.go": """
            package main

            import "net/http"

            func main() {
                api := http.NewServeMux()
                api.HandleFunc("GET /notes/{id}", getNote)
                mux := http.NewServeMux()
                mux.Handle("/api/", http.StripPrefix("/api", requireAuth(api)))
                mux.HandleFunc("/health", health)
                http.ListenAndServe(":8080", mux)
            }

            func getNote(w http.ResponseWriter, r *http.Request) {}
            func health(w http.ResponseWriter, r *http.Request) {}

            func requireAuth(next http.Handler) http.Handler {
                return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
                    next.ServeHTTP(w, r)
                })
            }
            """,
        },
    )
    note = rows[("GET", "/api/notes/{id}")]
    assert _guarded(note) == ["requireAuth"]
    assert note["handler"]["line"] == 15  # the function, not the registration
    assert _guarded(rows[("ANY", "/health")]) == []
    assert ("ANY", "/api/") not in rows  # a mount is no route of its own


def test_a_mux_wrapped_where_it_is_served_guards_all_of_its_routes(tmp_path: Path) -> None:
    rows = _rows(
        tmp_path,
        {
            "main.go": """
            package main

            import "net/http"

            func main() {
                mux := http.NewServeMux()
                mux.HandleFunc("DELETE /notes/{id}", deleteNote)
                http.ListenAndServe(":8080", authenticate(mux))
            }

            func authenticate(next http.Handler) http.Handler {
                return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
                    next.ServeHTTP(w, r)
                })
            }
            """,
        },
    )
    assert _guarded(rows[("DELETE", "/notes/{id}")]) == ["authenticate"]


def test_gorilla_subrouters_their_middleware_and_methods(tmp_path: Path) -> None:
    rows = _rows(
        tmp_path,
        {
            "routes.go": """
            package main

            import "github.com/gorilla/mux"

            func routes() *mux.Router {
                r := mux.NewRouter()
                r.HandleFunc("/login", login).Methods("POST")
                api := r.PathPrefix("/api").Subrouter()
                api.HandleFunc("/notes/{id:[0-9]+}", getNote).Methods("GET", "HEAD")
                api.Use(authMiddleware)
                return r
            }
            """,
        },
    )
    assert _guarded(rows[("GET", "/api/notes/{id:[0-9]+}")]) == ["authMiddleware"]
    assert ("HEAD", "/api/notes/{id:[0-9]+}") in rows  # gorilla's `Use` covers every route
    assert _guarded(rows[("POST", "/login")]) == []


def test_chi_route_group_with_and_mount(tmp_path: Path) -> None:
    rows = _rows(
        tmp_path,
        {
            "main.go": """
            package main

            import "github.com/go-chi/chi/v5"

            func main() {
                r := chi.NewRouter()
                r.Get("/", index)
                r.Route("/notes", func(r chi.Router) {
                    r.Use(jwtauth.Authenticator(tokenAuth))
                    r.Get("/{noteID}", getNote)
                })
                r.Group(func(r chi.Router) {
                    r.Use(RequireUser)
                    r.Delete("/items/{id}", deleteItem)
                })
                r.With(AdminOnly).Post("/reindex", reindex)
                r.Mount("/admin", adminRouter())
            }

            func adminRouter() chi.Router {
                r := chi.NewRouter()
                r.Use(AdminOnly)
                r.Get("/users/{id}", getUser)
                return r
            }
            """,
        },
    )
    assert _guarded(rows[("GET", "/")]) == []
    assert _guarded(rows[("GET", "/notes/{noteID}")]) == ["jwtauth.Authenticator"]
    assert _guarded(rows[("DELETE", "/items/{id}")]) == ["RequireUser"]
    assert _guarded(rows[("POST", "/reindex")]) == ["AdminOnly"]
    assert _guarded(rows[("GET", "/admin/users/{id}")]) == ["AdminOnly"]


def test_gin_groups_and_use_cover_only_later_routes(tmp_path: Path) -> None:
    rows = _rows(
        tmp_path,
        {
            "router.go": """
            package api

            import "github.com/gin-gonic/gin"

            func Setup(r *gin.Engine) {
                v1 := r.Group("/api/v1")
                v1.GET("/ping", ping)
                v1.Use(middleware.AuthRequired())
                v1.GET("/notes/:id", h.GetNote)
                admin := v1.Group("/admin", gin.BasicAuth(accounts))
                admin.DELETE("/users/:id", h.DeleteUser)
            }
            """,
            "main.go": """
            package api

            import "github.com/gin-gonic/gin"

            func Main() {
                r := gin.Default()
                Setup(r)
            }
            """,
        },
    )
    assert _guarded(rows[("GET", "/api/v1/ping")]) == []  # added before the `Use`
    assert _guarded(rows[("GET", "/api/v1/notes/:id")]) == ["middleware.AuthRequired"]
    assert _guarded(rows[("DELETE", "/api/v1/admin/users/:id")]) == [
        "middleware.AuthRequired",
        "gin.BasicAuth",
    ]


def test_echo_route_middleware_follows_the_handler_and_root_use_is_global(
    tmp_path: Path,
) -> None:
    rows = _rows(
        tmp_path,
        {
            "main.go": """
            package main

            import "github.com/labstack/echo/v4"

            func main() {
                e := echo.New()
                e.GET("/articles/:slug", getArticle, jwtMiddleware)
                e.GET("/tags", listTags)
                g := e.Group("/api")
                g.GET("/open/:id", openThing)
                g.Use(requireLogin)
                g.GET("/closed/:id", closedThing)
                e.Use(middleware.KeyAuth(validator))
            }
            """,
        },
    )
    article = rows[("GET", "/articles/:slug")]
    assert article["guards"] == ["jwtMiddleware"]
    assert article["handler"]["expr"] == "getArticle"
    assert _guarded(rows[("GET", "/tags")]) == ["middleware.KeyAuth"]  # the root `Use`: all
    assert _guarded(rows[("GET", "/api/open/:id")]) == ["middleware.KeyAuth"]
    assert sorted(_guarded(rows[("GET", "/api/closed/:id")])) == [
        "middleware.KeyAuth",
        "requireLogin",
    ]


def test_fiber_handlers_run_in_order_and_use_takes_a_path(tmp_path: Path) -> None:
    rows = _rows(
        tmp_path,
        {
            "main.go": """
            package main

            import "github.com/gofiber/fiber/v2"

            func main() {
                app := fiber.New()
                app.Use("/api", jwtware.New(cfg))
                api := app.Group("/api")
                api.Get("/notes/:id", getNote)
                app.Get("/public/:id", getPublic)
                app.Post("/upload/:id", saveUpload, requireAuth)
            }
            """,
        },
    )
    assert _guarded(rows[("GET", "/api/notes/:id")]) == ["jwtware.New"]
    assert _guarded(rows[("GET", "/public/:id")]) == []
    # a guard after the handler runs only if the handler calls `Next`: none
    assert _guarded(rows[("POST", "/upload/:id")]) == []


def test_a_router_held_in_a_struct_field(tmp_path: Path) -> None:
    rows = _rows(
        tmp_path,
        {
            "server.go": """
            package server

            import "github.com/gin-gonic/gin"

            type Server struct{ router *gin.Engine }

            func New() *Server {
                s := &Server{router: gin.New()}
                s.router.Use(AuthMiddleware())
                return s
            }

            func (s *Server) routes() {
                s.router.GET("/notes/:id", s.getNote)
            }

            func (s *Server) getNote(c *gin.Context) {}
            """,
        },
    )
    note = rows[("GET", "/notes/:id")]
    assert note["handler"]["path"] == "server.go"
    assert note["handler"]["line"] == 18


def test_handlers_resolve_across_packages_and_to_methods(tmp_path: Path) -> None:
    rows = _rows(
        tmp_path,
        {
            "cmd/main.go": """
            package main

            import (
                "github.com/go-chi/chi/v5"
                "example.com/app/notes"
            )

            func main() {
                r := chi.NewRouter()
                h := &notes.Handler{}
                r.Get("/notes/{id}", h.Show)
                r.Get("/list", notes.List)
            }
            """,
            "notes/notes.go": """
            package notes

            type Handler struct{}

            func (h *Handler) Show(w http.ResponseWriter, r *http.Request) {}

            func List(w http.ResponseWriter, r *http.Request) {}
            """,
        },
    )
    assert rows[("GET", "/notes/{id}")]["handler"]["path"] == "notes/notes.go"
    assert rows[("GET", "/list")]["handler"]["line"] == 8


@pytest.mark.parametrize(
    "call",
    [
        'cache.Get("session-key", &value)',
        'client.Get("https://example.com")',
        'values.Get("id")',
    ],
)
def test_a_getter_that_is_no_route_is_not_one(tmp_path: Path, call: str) -> None:
    rows = _rows(
        tmp_path,
        {"main.go": f"package main\n\nfunc main() {{\n\t{call}\n}}\n"},
    )
    assert rows == {}


def test_pocketbase_bind_guards_a_route_and_a_group(tmp_path: Path) -> None:
    rows = _rows(
        tmp_path,
        {
            "apis/notes.go": """
            package apis

            func bindNotes(rg *router.RouterGroup[*core.RequestEvent]) {
                sub := rg.Group("/notes").Bind(RequireAuth())
                sub.GET("/{id}", viewNote)
                rg.DELETE("/files/{id}", deleteFile).Bind(RequireSuperuserAuth())
                rg.GET("/open/{id}", openFile)
            }
            """,
        },
    )
    assert _guarded(rows[("GET", "/notes/{id}")]) == ["RequireAuth"]
    assert _guarded(rows[("DELETE", "/files/{id}")]) == ["RequireSuperuserAuth"]
    assert _guarded(rows[("GET", "/open/{id}")]) == []


def test_middleware_that_only_loads_the_caller_is_no_guard(tmp_path: Path) -> None:
    rows = _rows(
        tmp_path,
        {
            "main.go": """
            package main

            import "github.com/gin-gonic/gin"

            func main() {
                r := gin.New()
                r.Use(loadAuthToken(), auth.OptionalUser())
                r.GET("/notes/:id", getNote)
                r.GET("/items/:id", auth.RequireUser(), getItem)
            }
            """,
        },
    )
    assert _guarded(rows[("GET", "/notes/:id")]) == []
    assert _guarded(rows[("GET", "/items/:id")]) == ["auth.RequireUser"]


def test_a_query_getter_is_no_route_but_a_joined_path_is(tmp_path: Path) -> None:
    rows = _rows(
        tmp_path,
        {
            "main.go": """
            package main

            import (
                "path"
                "github.com/labstack/echo/v4"
            )

            const uriAdmin = "/admin"

            func main() {
                e := echo.New()
                e.GET(path.Join(uriAdmin, "/lists/:id"), viewList, requireAdmin)
                db.Get(&out, "SELECT * FROM notes WHERE id = $1", id)
            }
            """,
        },
    )
    assert set(rows) == {("GET", "/admin/lists/:id")}
    assert rows[("GET", "/admin/lists/:id")]["pattern_dynamic"] is False


def test_a_go_parser_that_wont_load_is_a_named_gap(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    from traust_core.v1.providers import go_routes

    monkeypatch.setattr(go_routes, "parser", lambda: None)
    (tmp_path / "main.go").write_text(
        'package main\n\nimport "github.com/go-chi/chi/v5"\n\nfunc main() { r.Get("/x/{id}", h) }\n'
    )
    result = route_guards(tree_files(tmp_path)).model_dump(mode="json")
    assert [r for r in result["routes"] if r["family"] == "go-http"] == []
    [gap] = [g for g in result["coverage_gaps"] if g["system"] == "go-http"]
    assert "tree-sitter-go" in gap["reason"] and "UNENUMERATED" in gap["reason"]


WRAP = """
func requireAuth(next http.Handler) http.Handler {
    return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { next.ServeHTTP(w, r) })
}
"""
CHI = 'package main\n\nimport "github.com/go-chi/chi/v5"\n\n'
HTTP = 'package main\n\nimport "net/http"\n\n'
GIN = 'package main\n\nimport "github.com/gin-gonic/gin"\n\n'
# (files, {(method, pattern): guards and scope guards}, routes that must not exist)
ROUND1 = {
    "a_call_taking_the_router_is_no_wrapper": (
        {
            "main.go": CHI
            + 'func main() {\n r := chi.NewRouter()\n r.Get("/admin/reset", resetAll)\n'
            " if err := registerLoginRoutes(r); err != nil { panic(err) }\n}\n"
        },
        {("GET", "/admin/reset"): []},
        [],
    ),
    "served_raw_and_wrapped_are_two_places": (
        {
            "main.go": HTTP + "func main() {\n mux := http.NewServeMux()\n"
            ' mux.HandleFunc("POST /admin/reset", resetAll)\n go http.ListenAndServe(":9", mux)\n'
            ' http.ListenAndServe(":8", requireAuth(mux))\n}\n' + WRAP
        },
        {("POST", "/admin/reset"): None},  # both rows: one guarded, one not
        [],
    ),
    "a_mounted_router_served_raw_too": (
        {
            "main.go": HTTP + "func main() {\n api := http.NewServeMux()\n"
            ' api.HandleFunc("GET /notes/{id}", getNote)\n mux := http.NewServeMux()\n'
            ' mux.Handle("/api/", http.StripPrefix("/api", requireAuth(api)))\n'
            ' go http.ListenAndServe(":9", api)\n http.ListenAndServe(":8", mux)\n}\n' + WRAP
        },
        {("GET", "/api/notes/{id}"): ["requireAuth"], ("GET", "/notes/{id}"): []},
        [],
    ),
    "a_shadowed_router_keeps_its_own_use": (
        {
            "main.go": CHI
            + 'func main() {\n r := chi.NewRouter()\n r.Get("/export/{id}", export)\n'
            " if admin {\n  r := chi.NewRouter()\n  r.Use(AdminOnly)\n"
            '  r.Get("/stats", stats)\n }\n}\n'
        },
        {("GET", "/export/{id}"): [], ("GET", "/stats"): ["AdminOnly"]},
        [],
    ),
    "a_reassigned_router_keeps_its_own_use": (
        {
            "main.go": 'package main\n\nimport "github.com/gorilla/mux"\n\nfunc main() {\n'
            ' r := mux.NewRouter()\n r.HandleFunc("/export/{id}", export)\n r = mux.NewRouter()\n'
            ' r.Use(authMiddleware)\n r.HandleFunc("/notes/{id}", getNote)\n}\n'
        },
        {("ANY", "/export/{id}"): [], ("ANY", "/notes/{id}"): ["authMiddleware"]},
        [],
    ),
    "a_package_router_use_counts_in_order": (
        {
            "main.go": GIN + "var router = gin.Default()\n\nfunc main() {\n"
            ' router.GET("/public/:id", pub)\n router.Use(AuthRequired())\n'
            ' router.GET("/notes/:id", note)\n}\n'
        },
        {("GET", "/public/:id"): [], ("GET", "/notes/:id"): ["AuthRequired"]},
        [],
    ),
    "a_package_router_shadowed_by_a_local": (
        {
            "main.go": CHI
            + 'var r = chi.NewRouter()\n\nfunc main() { r.Get("/files/{id}", dl) }\n\n'
            'func admin() {\n r := chi.NewRouter()\n r.Use(AdminOnly)\n r.Get("/stats", stats)\n}\n'
        },
        {("GET", "/files/{id}"): [], ("GET", "/stats"): ["AdminOnly"]},
        [],
    ),
    "a_checkout_factory_is_no_wrapper": (
        {
            "main.go": CHI + "var store Store\n\nfunc main() {\n r := chi.NewRouter()\n"
            ' r.Post("/tokens/{id}/revoke", RevokeToken(store))\n}\n\n'
            "func RevokeToken(s Store) http.HandlerFunc {\n"
            " return func(w http.ResponseWriter, r *http.Request) { s.Revoke() }\n}\n"
        },
        {("POST", "/tokens/{id}/revoke"): []},
        [],
    ),
    "echo_order_from_the_router_not_the_file": (
        {
            "server/server.go": 'package server\n\nimport "github.com/labstack/echo/v4"\n\n'
            "type Server struct{ e *echo.Echo }\n\nfunc New() *Server {\n"
            " s := &Server{e: echo.New()}\n s.routes()\n return s\n}\n",
            "server/routes.go": "package server\n\nfunc (s *Server) routes() {\n"
            ' s.e.DELETE("/tokens/:id", s.revokeToken, s.rateLimit)\n}\n',
        },
        {("DELETE", "/tokens/:id"): []},
        [],
    ),
    "session_loaders_are_no_guard": (
        {
            "main.go": HTTP + "func main() {\n mux := http.NewServeMux()\n"
            ' mux.HandleFunc("GET /notes/{id}", getNote)\n'
            ' http.ListenAndServe(":8", sessionManager.LoadAndSave(mux))\n}\n'
        },
        {("GET", "/notes/{id}"): []},
        [],
    ),
    "a_mux_mounted_without_strip_keeps_its_paths": (
        {
            "main.go": HTTP + "func main() {\n api := http.NewServeMux()\n"
            ' api.HandleFunc("/api/notes", list)\n mux := http.NewServeMux()\n'
            ' mux.Handle("GET /api/", requireAuth(api))\n http.ListenAndServe(":8", mux)\n}\n'
            + WRAP
        },
        {("GET", "/api/notes"): ["requireAuth"]},  # behind a `GET /api/` mount: GET only
        [("ANY", "/api/api/notes"), ("ANY", "/api/"), ("ANY", "/api/notes")],
    ),
    "gin_wraph_mount_keeps_route_middleware": (
        {
            "main.go": GIN + 'import "net/http"\n\nfunc main() {\n r := gin.New()\n'
            ' legacy := http.NewServeMux()\n legacy.HandleFunc("GET /legacy/reports/{id}", rep)\n'
            ' r.Any("/legacy/*path", AuthRequired(), gin.WrapH(legacy))\n}\n'
        },
        {("GET", "/legacy/reports/{id}"): ["AuthRequired"]},
        [],
    ),
    "a_router_given_to_a_handler_as_data": (
        {
            "main.go": HTTP + "func main() {\n mux := http.NewServeMux()\n"
            ' mux.HandleFunc("GET /notes/{id}", getNote)\n'
            ' mux.Handle("GET /debug/routes", routesHandler(mux))\n'
            ' http.ListenAndServe(":8", mux)\n}\n'
            "\nfunc routesHandler(m *http.ServeMux) http.Handler { return describe(m.Pattern) }\n"
        },
        {("GET", "/notes/{id}"): [], ("GET", "/debug/routes"): []},
        [],
    ),
    "a_mount_of_a_router_parameter": (
        {
            "main.go": CHI + "func main() {\n root := chi.NewRouter()\n admin := chi.NewRouter()\n"
            ' admin.Delete("/users/{id}", del)\n mountAdmin(root, admin)\n}\n\n'
            "func mountAdmin(root, admin chi.Router) {\n"
            ' root.Mount("/admin", requireAdmin(admin))\n}\n'
            "\nfunc requireAdmin(next http.Handler) http.Handler {\n"
            " return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {"
            " next.ServeHTTP(w, r) })\n}\n"
        },
        {("DELETE", "/admin/users/{id}"): ["requireAdmin"]},
        [("DELETE", "/users/{id}")],
    ),
    "a_mount_of_a_local_holding_a_wrapped_router": (
        {
            "main.go": HTTP + "func main() {\n api := http.NewServeMux()\n"
            ' api.HandleFunc("GET /notes/{id}", getNote)\n protected := requireAuth(api)\n'
            " mux := http.NewServeMux()\n"
            ' mux.Handle("/api/", http.StripPrefix("/api", protected))\n'
            ' http.ListenAndServe(":8", mux)\n}\n' + WRAP
        },
        {("GET", "/api/notes/{id}"): ["requireAuth"]},
        [("GET", "/notes/{id}"), ("ANY", "/api/")],
    ),
    "method_constants": (
        {
            "main.go": GIN + 'import "net/http"\n\nfunc main() {\n r := gin.New()\n'
            ' r.Handle(http.MethodDelete, "/notes/:id", del)\n}\n'
        },
        {("DELETE", "/notes/:id"): []},
        [],
    ),
    "host_patterns": (
        {
            "main.go": HTTP + "func main() {\n mux := http.NewServeMux()\n"
            ' mux.HandleFunc("GET api.example.com/notes/{id}", getNote)\n}\n'
        },
        {("GET", "api.example.com/notes/{id}"): []},
        [],
    ),
    "namesake_methods_keep_their_own_routers": (
        {
            "main.go": CHI + "type Notes struct{}\n\nfunc (n *Notes) Routes(r chi.Router) "
            '{ r.Get("/notes/{id}", n.get) }\n\ntype Admin struct{}\n\n'
            'func (a *Admin) Routes(r chi.Router) { r.Get("/stats", a.stats) }\n\nfunc main() {\n'
            " notes, admin := &Notes{}, &Admin{}\n pub := chi.NewRouter()\n notes.Routes(pub)\n"
            " adm := chi.NewRouter()\n adm.Use(AdminOnly)\n admin.Routes(adm)\n"
            ' pub.Mount("/admin", adm)\n http.ListenAndServe(":8", pub)\n}\n'
        },
        {("GET", "/notes/{id}"): [], ("GET", "/admin/stats"): ["AdminOnly"]},
        [("GET", "/admin/notes/{id}"), ("GET", "/stats")],
    ),
    "a_client_and_a_zookeeper_call_are_no_routes": (
        {
            "main.go": 'package main\n\nfunc main() {\n n := Note{Title: "x"}\n'
            ' c.Post("/notes", n)\n conn.Delete("/locks/leader", -1)\n}\n'
        },
        {},
        [("POST", "/notes"), ("DELETE", "/locks/leader")],
    ),
    "fiber_use_orders_by_registration": (
        {
            "main.go": 'package main\n\nimport "github.com/gofiber/fiber/v2"\n\nfunc main() {\n'
            ' app := fiber.New()\n api := app.Group("/api")\n app.Use(requireAuth)\n'
            ' api.Get("/notes/:id", getNote)\n}\n'
        },
        {("GET", "/api/notes/:id"): ["requireAuth"]},
        [],
    ),
    "gin_field_use_in_order": (
        {
            "main.go": GIN + "type Server struct{ router *gin.Engine }\n\nfunc New() *Server {\n"
            ' s := &Server{router: gin.New()}\n s.router.GET("/public/:id", s.pub)\n'
            ' s.router.Use(AuthMiddleware())\n s.router.GET("/notes/:id", s.note)\n return s\n}\n'
        },
        {("GET", "/public/:id"): [], ("GET", "/notes/:id"): ["AuthMiddleware"]},
        [],
    ),
}


@pytest.mark.parametrize("case", ROUND1)
def test_the_shapes_a_review_found(tmp_path: Path, case: str) -> None:
    files, expected, absent = ROUND1[case]
    rows = _rows_all(tmp_path, files)
    for key, guards in expected.items():
        found = [sorted(_guarded(r)) for r in rows if (r["method"], r["pattern"]) == key]
        if guards is None:
            assert sorted(map(tuple, found)) == [(), ("requireAuth",)], key
        else:
            assert found == [sorted(guards)], key
    keys = {(r["method"], r["pattern"]) for r in rows}
    assert not keys & set(absent)


def test_many_routes_in_one_function_stay_linear(tmp_path: Path) -> None:
    body = "".join(f' r.Get("/r{i}/{{id}}", h{i})\n' for i in range(2000))
    rows = _rows_all(
        tmp_path, {"main.go": CHI + "func main() {\n r := chi.NewRouter()\n" + body + "}\n"}
    )
    assert len(rows) == 2000


def _rows_all(tmp_path: Path, files: dict[str, str]) -> list[dict]:
    for rel, text in {"go.mod": GO_MOD, **files}.items():
        path = tmp_path / rel
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(text)
    routes = route_guards(tree_files(tmp_path)).model_dump(mode="json")["routes"]
    return [r for r in routes if r["family"] == "go-http"]


MUX = 'package main\n\nimport "github.com/gorilla/mux"\n\n'
ROUND2 = {
    "a_tls_serve_is_a_place_of_its_own": (
        {
            "main.go": HTTP + "func main() {\n api := http.NewServeMux()\n"
            ' api.HandleFunc("GET /notes/{id}", getNote)\n mux := http.NewServeMux()\n'
            ' mux.Handle("/api/", http.StripPrefix("/api", requireAuth(api)))\n'
            ' go http.ListenAndServe(":8080", mux)\n'
            ' http.ListenAndServeTLS(":8443", "cert.pem", "key.pem", api)\n}\n' + WRAP
        },
        {("GET", "/api/notes/{id}"): ["requireAuth"], ("GET", "/notes/{id}"): []},
        [],
    ),
    "a_guard_word_in_a_middleware_argument": (
        {
            "main.go": CHI + "func main() {\n r := chi.NewRouter()\n"
            ' r.Use(cors.New(cors.Options{AllowedHeaders: []string{"Authorization"}}).Handler)\n'
            ' r.Delete("/users/{id}", deleteUser)\n}\n'
        },
        {("DELETE", "/users/{id}"): []},
        [],
    ),
    "a_handler_reassigned_in_a_branch": (
        {
            "main.go": HTTP + "func main() {\n mux := http.NewServeMux()\n"
            ' mux.HandleFunc("POST /admin/reset", resetAll)\n handler := requireAuth(mux)\n'
            ' if dev {\n  handler = mux\n }\n http.ListenAndServe(":8080", handler)\n}\n' + WRAP
        },
        {("POST", "/admin/reset"): None},
        [],
    ),
    "a_field_use_of_another_type": (
        {
            "main.go": MUX + "type publicAPI struct{ router *mux.Router }\n"
            "type adminAPI struct{ router *mux.Router }\n\n"
            "func newPublicAPI() *publicAPI {\n p := &publicAPI{router: mux.NewRouter()}\n"
            ' p.router.HandleFunc("/files/{id}", download)\n return p\n}\n\n'
            "func newAdminAPI() *adminAPI { return &adminAPI{router: mux.NewRouter()} }\n\n"
            "func main() {\n adm := newAdminAPI()\n adm.router.Use(requireAdmin)\n"
            " pub := newPublicAPI()\n _ = pub\n}\n"
        },
        {("ANY", "/files/{id}"): []},
        [],
    ),
    "routers_from_one_helper_are_separate": (
        {
            "main.go": CHI + "func newRouter() chi.Router { return chi.NewRouter() }\n\n"
            "type publicAPI struct{ router chi.Router }\n"
            "type adminAPI struct{ router chi.Router }\n\n"
            "func main() {\n p := &publicAPI{router: newRouter()}\n"
            " a := &adminAPI{router: newRouter()}\n"
            " a.router.Use(RequireAdmin)\n"
            ' p.router.Get("/files/{id}", download)\n a.router.Get("/stats", stats)\n}\n'
        },
        {("GET", "/files/{id}"): [], ("GET", "/stats"): ["RequireAdmin"]},
        [],
    ),
    "a_range_variable_shadows_a_package_router": (
        {
            "main.go": MUX + "var router = mux.NewRouter()\n\n"
            'func init() { router.HandleFunc("/files/{id}", download) }\n\n'
            "func protect(rs ...*mux.Router) {\n for _, router := range rs {\n"
            "  router.Use(requireUser)\n }\n}\n"
        },
        {("ANY", "/files/{id}"): []},
        [],
    ),
    "header_middleware_is_no_guard": (
        {
            "main.go": HTTP + "func main() {\n mux := http.NewServeMux()\n"
            ' mux.HandleFunc("GET /snippet/view/{id}", view)\n'
            ' http.ListenAndServe(":8080", secureHeaders(mux))\n}\n\n'
            "func secureHeaders(next http.Handler) http.Handler {\n"
            " return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {"
            " next.ServeHTTP(w, r) })\n}\n"
        },
        {("GET", "/snippet/view/{id}"): []},
        [],
    ),
    "a_helper_returning_its_router_is_no_wrapper": (
        {
            "main.go": HTTP + "func main() {\n mux := http.NewServeMux()\n"
            ' mux.HandleFunc("POST /admin/reset", resetAll)\n'
            ' http.ListenAndServe(":8080", addAuthRoutes(mux))\n}\n\n'
            "func addAuthRoutes(mux *http.ServeMux) *http.ServeMux {\n"
            ' mux.HandleFunc("POST /login", login)\n return mux\n}\n'
        },
        {("POST", "/admin/reset"): [], ("POST", "/login"): []},
        [],
    ),
    "a_client_post_is_no_route": (
        {
            "main.go": "package main\n\nfunc (c *Client) Create(body []byte) {\n"
            ' c.hc.Post("/v1/notes", "application/json", bytes.NewReader(body))\n}\n'
        },
        {},
        [("POST", "/v1/notes")],
    ),
    "gorilla_path_prefix_handlers": (
        {
            "main.go": MUX + 'import "net/http"\n\nfunc main() {\n r := mux.NewRouter()\n'
            ' r.PathPrefix("/files/").HandlerFunc(serveFiles)\n'
            ' http.ListenAndServe(":8080", r)\n}\n'
            "\nfunc serveFiles(w http.ResponseWriter, r *http.Request) {}\n"
        },
        {("ANY", "/files/"): []},
        [],
    ),
    "chi_route_with_a_named_function": (
        {
            "main.go": CHI + "func main() {\n r := chi.NewRouter()\n r.Use(RequireUser)\n"
            ' r.Route("/articles", articleRouter)\n}\n\n'
            'func articleRouter(r chi.Router) { r.Get("/{articleID}", getArticle) }\n'
        },
        {("GET", "/articles/{articleID}"): ["RequireUser"]},
        [("GET", "/{articleID}")],
    ),
    "chi_mounting_a_servemux_keeps_its_paths": (
        {
            "main.go": CHI + 'import "net/http"\n\nfunc main() {\n r := chi.NewRouter()\n'
            " legacy := http.NewServeMux()\n"
            ' legacy.HandleFunc("GET /legacy/reports/{id}", report)\n'
            ' r.Mount("/legacy", legacy)\n}\n'
        },
        {("GET", "/legacy/reports/{id}"): []},
        [("GET", "/legacy/legacy/reports/{id}")],
    ),
    "a_router_given_to_a_handler_factory_as_data": (
        {
            "main.go": CHI + "func main() {\n r := chi.NewRouter()\n"
            ' r.Get("/routes", listRoutes(r))\n r.Post("/admin/reset", resetAll)\n}\n\n'
            "func listRoutes(r chi.Router) http.HandlerFunc {\n"
            " return func(w http.ResponseWriter, _ *http.Request) { chi.Walk(r, visit) }\n}\n"
        },
        {("GET", "/routes"): [], ("POST", "/admin/reset"): []},
        [],
    ),
    "a_spread_handler_list": (
        {
            "main.go": GIN + "func main() {\n r := gin.New()\n"
            ' r.DELETE("/users/:id", append(chain, deleteUser)...)\n}\n'
        },
        {("DELETE", "/users/:id"): []},
        [],
    ),
    "subrouter_methods": (
        {
            "main.go": MUX + "func main() {\n r := mux.NewRouter()\n"
            ' r.Methods("GET").Subrouter().HandleFunc("/notes/{id}", getNote)\n}\n'
        },
        {("GET", "/notes/{id}"): []},
        [("ANY", "/notes/{id}")],
    ),
    "use_in_a_helper_called_first": (
        {
            "main.go": GIN
            + "func main() {\n r := gin.New()\n setupMiddleware(r)\n setupRoutes(r)\n}\n\n"
            "func setupMiddleware(r *gin.Engine) { r.Use(AuthRequired()) }\n\n"
            'func setupRoutes(r *gin.Engine) { r.GET("/notes/:id", getNote) }\n'
        },
        {("GET", "/notes/:id"): ["AuthRequired"]},
        [],
    ),
    "a_guard_inside_a_checkout_wrapper": (
        {
            "main.go": HTTP + "func main() {\n mux := http.NewServeMux()\n"
            ' mux.HandleFunc("POST /notes", createNote)\n'
            ' http.ListenAndServe(":8080", withMiddleware(mux))\n}\n\n'
            "func withMiddleware(next http.Handler) http.Handler {"
            " return logRequest(requireAuth(next)) }\n"
            "func logRequest(next http.Handler) http.Handler {\n"
            " return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {"
            " next.ServeHTTP(w, r) })\n}\n" + WRAP
        },
        {("POST", "/notes"): ["requireAuth"]},  # the other two carry no guard word
        [],
    ),
    "the_default_mux_served_wrapped": (
        {
            "main.go": HTTP + "func main() {\n"
            ' http.HandleFunc("POST /notes", createNote)\n'
            ' http.ListenAndServe(":8080", requireAuth(http.DefaultServeMux))\n}\n' + WRAP
        },
        {("POST", "/notes"): ["requireAuth"]},
        [],
    ),
    "a_handler_returning_nil_is_no_default_mux": (
        {
            "main.go": MUX + 'import "net/http"\n\nfunc main() {\n r := mux.NewRouter()\n'
            ' r.PathPrefix("/admin/").Handler(adminHandler())\n'
            ' http.ListenAndServe(":8080", r)\n}\n'
            "\nfunc adminHandler() http.Handler { return nil }\n"
        },
        {("ANY", "/admin/"): []},
        [],
    ),
}


@pytest.mark.parametrize("case", ROUND2)
def test_the_shapes_a_second_review_found(tmp_path: Path, case: str) -> None:
    files, expected, absent = ROUND2[case]
    rows = _rows_all(tmp_path, files)
    for key, guards in expected.items():
        found = [sorted(_guarded(r)) for r in rows if (r["method"], r["pattern"]) == key]
        if guards is None:
            assert sorted(map(tuple, found)) == [(), ("requireAuth",)], key
        else:
            assert found == [sorted(guards)], key
    assert not {(r["method"], r["pattern"]) for r in rows} & set(absent)


def test_chained_locals_stay_fast(tmp_path: Path) -> None:
    lines = "".join(
        f" c{i} := newC(c{i - 1}, c{max(i - 2, 0)}, c{max(i - 3, 0)})\n" for i in range(1, 40)
    )
    body = HTTP + "func main() {\n mux := http.NewServeMux()\n c0 := newC()\n" + lines
    body += ' mux.Handle("GET /reports/{id}", reportHandler(c39, logger))\n}\n'
    rows = _rows_all(tmp_path, {"main.go": body})
    assert [r["pattern"] for r in rows] == ["/reports/{id}"]


REVIEW = json.loads(
    (Path(__file__).parents[2] / "fixtures/code_facts/go_routes_review.json").read_text()
)


@pytest.mark.parametrize("case", sorted(REVIEW))
def test_the_shapes_later_reviews_found(tmp_path: Path, case: str) -> None:
    """A guard counts only where it surely runs before the route (D42)."""
    for rel, text in REVIEW[case]["files"].items():
        path = tmp_path / rel
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(text)
    routes = route_guards(tree_files(tmp_path)).model_dump(mode="json")["routes"]
    got = sorted(
        {
            (r["method"], r["pattern"], tuple(sorted(r["guards"] + r["scope_guards"])))
            for r in routes
            if r["family"] == "go-http"
        }
    )
    assert [[m, p, list(g)] for m, p, g in got] == REVIEW[case]["rows"]


def test_a_router_walked_recursively_stays_fast(tmp_path: Path) -> None:
    body = HTTP + "func main() {\n mux := http.NewServeMux()\n"
    body += ' mux.Handle("GET /debug/routes", dump(mux, 3))\n}\n\n'
    body += "func dump(m *http.ServeMux, d int) http.Handler {\n"
    body += " if d > 0 {\n  dump(m, d-1)\n  dump(m, d-1)\n  dump(m, d-1)\n }\n"
    body += " return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {})\n}\n"
    rows = _rows_all(tmp_path, {"main.go": body})
    assert [r["pattern"] for r in rows] == ["/debug/routes"]


def test_thousands_of_routes_in_one_function_stay_linear(tmp_path: Path) -> None:
    body = "".join(f' r.Get("/r{i}/{{id}}", h{i})\n' for i in range(6000))
    rows = _rows_all(
        tmp_path,
        {
            "main.go": CHI
            + "func main() {\n r := chi.NewRouter()\n r.Use(RequireUser)\n"
            + body
            + "}\n"
        },
    )
    assert len(rows) == 6000 and all(r["scope_guards"] == ["RequireUser"] for r in rows)


ECHO = (
    'package main\n\nimport (\n "github.com/labstack/echo/v4"\n'
    ' "github.com/labstack/echo/v4/middleware"\n)\n\n'
)
PASS = "\nfunc RequireAuth[T any](next http.Handler, x T) http.Handler { return next }\n"
# (files, {(method, pattern): guards}, routes that must not exist): Qodo's review of #438
QODO = {
    "a_skipper_in_a_config_variable": (
        {
            "main.go": ECHO
            + "func main() {\n e := echo.New()\n cfg := middleware.JWTConfig{SigningKey: key}\n"
            " cfg.Skipper = func(c echo.Context) bool { return true }\n"
            " e.Use(middleware.JWTWithConfig(cfg))\n"
            ' e.DELETE("/users/:id", deleteUser)\n}\n'
        },
        {("DELETE", "/users/:id"): []},
        [],
    ),
    "a_generic_pass_through": (
        {
            "main.go": HTTP + "func main() {\n mux := http.NewServeMux()\n"
            ' mux.Handle("DELETE /users/{id}", RequireAuth[int](http.HandlerFunc(del), 1))\n'
            ' mux.Handle("GET /x/{id}", RequireAuth[int](http.HandlerFunc(del), 1))\n}\n' + PASS
        },
        {("DELETE", "/users/{id}"): [], ("GET", "/x/{id}"): []},
        [],
    ),
    "two_instances_of_one_struct": (
        {
            "main.go": CHI + "type Server struct{ router chi.Router }\n\nfunc main() {\n"
            " public := &Server{router: chi.NewRouter()}\n"
            " admin := &Server{router: chi.NewRouter()}\n"
            " admin.router.Use(AdminOnly)\n"
            ' public.router.Get("/files/{id}", download)\n admin.router.Get("/stats", stats)\n}\n'
        },
        {("GET", "/files/{id}"): []},
        [],
    ),
    "connect_only": (
        {
            "main.go": CHI
            + 'func main() {\n r := chi.NewRouter()\n r.Connect("/tunnel/{id}", tunnel)\n}\n'
        },
        {("CONNECT", "/tunnel/{id}"): []},
        [],
    ),
    "a_test_file_router": (
        {
            "main.go": CHI + 'func main() {\n r := chi.NewRouter()\n r.Get("/health", health)\n}\n',
            "main_test.go": CHI + "func TestX(t *testing.T) {\n r := chi.NewRouter()\n"
            ' r.Delete("/users/{id}", deleteUser)\n}\n',
        },
        {("GET", "/health"): []},
        [("DELETE", "/users/{id}")],
    ),
    "a_package_router_set_in_init": (
        {
            "main.go": CHI + "var router chi.Router\n\nfunc init() {\n router = chi.NewRouter()\n"
            ' router.Use(RequireUser)\n}\n\nfunc routes() { router.Get("/notes/{id}", getNote) }\n'
        },
        {("GET", "/notes/{id}"): ["RequireUser"]},
        [],
    ),
    "a_package_router_replaced": (
        {
            "main.go": CHI
            + "var router = chi.NewRouter()\n\nfunc init() { router.Use(RequireUser) }\n\n"
            "func reset() { router = chi.NewRouter() }\n\n"
            'func routes() { router.Get("/notes/{id}", getNote) }\n'
        },
        {("GET", "/notes/{id}"): []},
        [],
    ),
    "a_constant_in_build_variants": (
        {
            "main.go": CHI + "func main() {\n r := chi.NewRouter()\n r.Get(notesPath, list)\n}\n",
            "paths_prod.go": '//go:build prod\n\npackage main\n\nconst notesPath = "/prod/notes"\n',
            "paths_dev.go": '//go:build !prod\n\npackage main\n\nconst notesPath = "/dev/notes"\n',
        },
        {},
        [("GET", "/prod/notes"), ("GET", "/dev/notes")],
    ),
    "a_store_match_call": (
        {
            "main.go": GIN + "func main() {\n r := gin.New()\n"
            ' r.Match([]string{"GET"}, "/r/:id", h)\n'
            ' store.Match([]string{"GET"}, "/x", handle)\n}\n'
        },
        {("GET", "/r/:id"): []},
        [("GET", "/x")],
    ),
    "a_local_named_like_a_guard": (
        {
            "main.go": CHI + "func main() {\n r := chi.NewRouter()\n"
            " requireAuth := func(h http.Handler) http.Handler { return h }\n r.Use(requireAuth)\n"
            ' r.Delete("/users/{id}", deleteUser)\n}\n\n'
            "func mount(r chi.Router, requireAuth func(http.Handler) http.Handler) {\n"
            ' r.Use(requireAuth)\n r.Delete("/items/{id}", deleteItem)\n}\n' + WRAP
        },
        {("DELETE", "/users/{id}"): [], ("DELETE", "/items/{id}"): []},
        [],
    ),
    "a_fiber_use_prefix_needs_a_slash": (
        {
            "main.go": 'package main\n\nimport "github.com/gofiber/fiber/v2"\n\nfunc main() {\n'
            ' app := fiber.New()\n app.Use("/api", requireAuth)\n'
            ' app.Get("/apikeys/:id", getKey)\n app.Get("/api/notes/:id", getNote)\n}\n'
        },
        {("GET", "/apikeys/:id"): [], ("GET", "/api/notes/:id"): ["requireAuth"]},
        [],
    ),
}


@pytest.mark.parametrize("case", QODO)
def test_the_shapes_qodo_found(tmp_path: Path, case: str) -> None:
    files, expected, absent = QODO[case]
    rows = _rows_all(tmp_path, files)
    for key, guards in expected.items():
        found = [sorted(_guarded(r)) for r in rows if (r["method"], r["pattern"]) == key]
        assert found == [sorted(guards)], key
    assert not {(r["method"], r["pattern"]) for r in rows} & set(absent)


def test_a_generic_receivers_method_resolves(tmp_path: Path) -> None:
    rows = _rows_all(
        tmp_path,
        {
            "main.go": CHI + "type Handler[T any] struct{}\n\n"
            "func (h *Handler[T]) Show(w http.ResponseWriter, r *http.Request) {}\n\n"
            "type Other struct{}\n\n"
            "func (o *Other) Show(w http.ResponseWriter, r *http.Request) {}\n\n"
            "func main() {\n r := chi.NewRouter()\n h := &Handler[int]{}\n"
            ' r.Get("/x/{id}", h.Show)\n}\n'
        },
    )
    assert [r["handler"]["line"] for r in rows] == [7]  # `Handler[T]`'s, not `Other`'s


JWT = 'package main\n\nimport (\n "net/http"\n jwt "github.com/go-chi/jwtauth/v5"\n)\n\n'
QODO2 = {
    "a_replaced_package_router": (
        {
            "main.go": CHI + "var router = newGuarded()\n\nfunc newGuarded() chi.Router {\n"
            " r := chi.NewRouter()\n r.Use(RequireUser)\n return r\n}\n\n"
            "func init() { router = chi.NewRouter() }\n\n"
            'func routes() { router.Delete("/users/{id}", deleteUser) }\n'
        },
        {("DELETE", "/users/{id}"): None},
        [],
    ),
    "a_verifier_wrapping_a_mux": (
        {
            "main.go": JWT + "func main() {\n api := http.NewServeMux()\n"
            ' api.HandleFunc("DELETE /users/{id}", deleteUser)\n'
            ' http.ListenAndServe(":8080", jwt.Verifier(ta)(api))\n}\n'
        },
        {("DELETE", "/users/{id}"): []},
        [],
    ),
    "an_aliased_verifier_in_use": (
        {
            "main.go": JWT
            + 'import "github.com/go-chi/chi/v5"\n\nfunc main() {\n r := chi.NewRouter()\n'
            ' r.Use(jwt.Verifier(ta))\n r.Delete("/users/{id}", deleteUser)\n}\n'
        },
        {("DELETE", "/users/{id}"): []},
        [],
    ),
    "a_token_method": (
        {
            "main.go": HTTP + "func main() {\n mux := http.NewServeMux()\n"
            ' mux.HandleFunc("M-SEARCH /discover", discover)\n}\n'
        },
        {("M-SEARCH", "/discover"): []},
        [("ANY", "M-SEARCH /discover")],
    ),
    "a_repeated_constant": (
        {
            "main.go": CHI + 'const (\n base = "/api"\n routePath\n)\n\n'
            "func main() {\n r := chi.NewRouter()\n r.Get(routePath, list)\n}\n"
        },
        {("GET", "/api"): []},
        [],
    ),
    "an_aliased_path_import": (
        {
            "main.go": 'package main\n\nimport (\n p "path"\n "github.com/go-chi/chi/v5"\n)\n\n'
            'func main() {\n r := chi.NewRouter()\n r.Get(p.Join("/api", "users"), list)\n'
            ' r.Get(p.Join("/api", "../health"), health)\n}\n'
        },
        {("GET", "/api/users"): [], ("GET", "/health"): []},
        [("GET", "/api/../health")],
    ),
}


@pytest.mark.parametrize("case", QODO2)
def test_the_shapes_a_second_qodo_review_found(tmp_path: Path, case: str) -> None:
    files, expected, absent = QODO2[case]
    rows = _rows_all(tmp_path, files)
    for key, guards in expected.items():
        found = sorted(sorted(_guarded(r)) for r in rows if (r["method"], r["pattern"]) == key)
        if guards is None:  # never guarded: whichever router it lands on
            assert found and all(g == [] for g in found), key
        else:
            assert found == [sorted(guards)], key
    assert not {(r["method"], r["pattern"]) for r in rows} & set(absent)


def test_many_setup_calls_stay_small(tmp_path: Path) -> None:
    helper = (
        "func setup(r chi.Router) {\n" + "".join(f" r.Use(mw{i})\n" for i in range(300)) + "}\n"
    )
    calls = "".join(" setup(r)\n" for _ in range(300))
    body = (
        CHI + helper + "\nfunc main() {\n r := chi.NewRouter()\n" + calls + ' r.Get("/x", h)\n}\n'
    )
    rows = _rows_all(tmp_path, {"main.go": body})
    assert len(rows) == 1


QODO3 = {
    "a_dot_imported_verifier": (
        {
            "main.go": 'package main\n\nimport (\n "github.com/go-chi/chi/v5"\n'
            ' . "github.com/go-chi/jwtauth/v5"\n)\n\n'
            "func main() {\n r := chi.NewRouter()\n r.Use(Verify(ta, TokenFromHeader))\n"
            ' r.Delete("/users/{id}", del)\n}\n'
        },
        {("DELETE", "/users/{id}"): []},
        [],
    ),
    "a_local_named_like_a_framework": (
        {
            "main.go": "package main\n\nfunc main() {\n gin := newRegistry()\n reg := gin.New()\n"
            ' reg.Use(RequireAuth())\n reg.GET("/jobs/:id", runJob)\n}\n'
        },
        {},
        [("GET", "/jobs/:id")],
    ),
    "a_struct_of_another_package": (
        {
            "a/server.go": 'package a\n\nimport "github.com/go-chi/chi/v5"\n\n'
            "type Server struct{ Router chi.Router }\n\n"
            "func New(parent chi.Router) *Server {\n r := chi.NewRouter()\n"
            ' parent.Mount("/admin", r)\n return &Server{Router: r}\n}\n',
            "b/server.go": 'package b\n\nimport "github.com/go-chi/chi/v5"\n\n'
            "type Server struct{ Router chi.Router }\n",
            "c/routes.go": 'package c\n\nimport "example.com/app/b"\n\n'
            'func routes(s *b.Server) { s.Router.Get("/files/{id}", download) }\n\n'
            "func download(w http.ResponseWriter, r *http.Request) {}\n",
        },
        {("GET", "/files/{id}"): []},
        [("GET", "/admin/files/{id}")],
    ),
    "a_framework_server_serving_raw": (
        {
            "main.go": GIN + 'import "net/http"\n\nfunc main() {\n r := gin.New()\n'
            ' r.DELETE("/users/:id", deleteUser)\n go r.Run(":9090")\n'
            ' http.ListenAndServe(":8080", requireAuth(r))\n}\n' + WRAP
        },
        {("DELETE", "/users/:id"): None},
        [],
    ),
}


@pytest.mark.parametrize("case", QODO3)
def test_the_shapes_a_third_qodo_review_found(tmp_path: Path, case: str) -> None:
    files, expected, absent = QODO3[case]
    rows = _rows_all(tmp_path, files)
    for key, guards in expected.items():
        found = sorted(sorted(_guarded(r)) for r in rows if (r["method"], r["pattern"]) == key)
        if guards is None:  # served raw too: an unguarded row beside the guarded one
            assert [] in found and ["requireAuth"] in found, key
        else:
            assert found == [sorted(guards)], key
    assert not {(r["method"], r["pattern"]) for r in rows} & set(absent)


QODO4 = {
    "echo_start_server_serves_raw": (
        {
            "main.go": ECHO + 'import "net/http"\n\nfunc main() {\n e := echo.New()\n'
            ' e.DELETE("/users/:id", deleteUser)\n go e.StartServer(&http.Server{Addr: ":9090"})\n'
            ' http.ListenAndServe(":8080", requireAuth(e))\n}\n' + WRAP
        },
        {("DELETE", "/users/:id"): None},
        [],
    ),
    "a_package_value_named_gin": (
        {
            "main.go": "package main\n\nvar gin = registry{}\n\nfunc main() {\n r := gin.New()\n"
            ' r.Use(requireAuth)\n r.GET("/jobs/:id", runJob)\n}\n'
        },
        {},
        [("GET", "/jobs/:id")],
    ),
    "a_gorilla_method_prefixed_path": (
        {
            "main.go": MUX
            + 'func main() {\n r := mux.NewRouter()\n r.HandleFunc("GET /reports", reports)\n}\n'
        },
        {},
        [("GET", "/reports"), ("ANY", "GET /reports")],
    ),
    "a_goto_over_the_use": (
        {
            "main.go": CHI + "func main() {\n r := chi.NewRouter()\n if skip {\n  goto route\n }\n"
            ' r.Use(RequireUser)\nroute:\n r.Get("/private/{id}", h)\n}\n'
        },
        {("GET", "/private/{id}"): []},
        [],
    ),
    "a_handler_field_of_another_struct": (
        {
            "main.go": HTTP + "type Route struct{ Handler http.Handler }\n\nfunc main() {\n"
            ' api := http.NewServeMux()\n api.HandleFunc("DELETE /users/{id}", del)\n'
            " _ = Route{Handler: requireAuth(api)}\n"
            ' http.ListenAndServe(":8080", api)\n}\n' + WRAP
        },
        {("DELETE", "/users/{id}"): []},
        [],
    ),
    "build_tag_text_in_the_body": (
        {
            "main.go": CHI
            + "const doc = `\n//go:build ignore\n`\n\nfunc main() {\n r := chi.NewRouter()\n"
            ' r.Use(RequireUser)\n r.Get("/notes/{id}", getNote)\n}\n'
        },
        {("GET", "/notes/{id}"): ["RequireUser"]},
        [],
    ),
}


@pytest.mark.parametrize("case", QODO4)
def test_the_shapes_a_fourth_qodo_review_found(tmp_path: Path, case: str) -> None:
    files, expected, absent = QODO4[case]
    rows = _rows_all(tmp_path, files)
    for key, guards in expected.items():
        found = sorted(sorted(_guarded(r)) for r in rows if (r["method"], r["pattern"]) == key)
        if guards is None:  # served raw too: an unguarded row beside the guarded one
            assert [] in found and ["requireAuth"] in found, key
        else:
            assert found == [sorted(guards)], key
    assert not {(r["method"], r["pattern"]) for r in rows} & set(absent)


def test_a_lone_store_call_claims_no_gap_without_the_grammar(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    from traust_core.v1.providers import go_routes

    monkeypatch.setattr(go_routes, "parser", lambda: None)
    (tmp_path / "main.go").write_text('package main\n\nfunc main() { db.Get(&out, "q") }\n')
    result = route_guards(tree_files(tmp_path)).model_dump(mode="json")
    assert [g for g in result["coverage_gaps"] if g["system"] == "go-http"] == []


DOT_HTTP = 'package main\n\nimport . "net/http"\n\n'
QODO5 = {
    "a_dot_imported_server_serving_raw": (
        {
            "main.go": DOT_HTTP + "func main() {\n mux := NewServeMux()\n"
            ' mux.HandleFunc("DELETE /users/{id}", del)\n'
            ' go ListenAndServe(":8080", requireAuth(mux))\n'
            ' srv := &Server{Addr: ":9090", Handler: mux}\n srv.ListenAndServe()\n}\n'
            "\nfunc requireAuth(next Handler) Handler {\n"
            " return HandlerFunc(func(w ResponseWriter, r *Request) { next.ServeHTTP(w, r) })\n}\n"
        },
        {("DELETE", "/users/{id}"): None},
        [],
    ),
    "a_declared_server_serving_raw": (
        {
            "main.go": HTTP + "func main() {\n mux := http.NewServeMux()\n"
            ' mux.HandleFunc("DELETE /users/{id}", del)\n'
            ' go http.ListenAndServe(":8080", requireAuth(mux))\n'
            " var srv http.Server\n srv.Handler = mux\n srv.ListenAndServe()\n}\n" + WRAP
        },
        {("DELETE", "/users/{id}"): None},
        [],
    ),
    "a_new_server_serving_the_default_mux": (
        {
            "main.go": HTTP + "func main() {\n"
            ' http.HandleFunc("POST /admin/reset", reset)\n'
            ' go http.ListenAndServe(":8080", requireAuth(http.DefaultServeMux))\n'
            " srv := new(http.Server)\n srv.ListenAndServe()\n}\n" + WRAP
        },
        {("POST", "/admin/reset"): None},
        [],
    ),
    "a_pass_through_helper_keeps_the_guard": (
        {
            "main.go": CHI + "func passthrough(r chi.Router) chi.Router { return r }\n\n"
            "func main() {\n r := chi.NewRouter()\n r.Use(RequireUser)\n"
            ' passthrough(r).Get("/notes/{id}", getNote)\n}\n'
        },
        {("GET", "/notes/{id}"): ["RequireUser"]},
        [],
    ),
    "a_dot_imported_gin": (
        {
            "main.go": 'package main\n\nimport . "github.com/gin-gonic/gin"\n\n'
            'func main() {\n r := Default()\n r.GET("/admin/:id", handlers.Admin)\n}\n'
        },
        {("GET", "/admin/:id"): []},
        [],
    ),
    "an_escaped_path": (
        {"main.go": GIN + 'func main() {\n r := gin.New()\n r.GET("\\x2fadmin/:id", admin)\n}\n'},
        {("GET", "/admin/:id"): []},
        [],
    ),
    "a_host_pattern_without_a_dot": (
        {
            "main.go": HTTP + "func main() {\n mux := http.NewServeMux()\n"
            ' mux.HandleFunc("localhost/admin", admin)\n mux.HandleFunc("intranet:8080/x", x)\n}\n'
        },
        {("ANY", "localhost/admin"): [], ("ANY", "intranet:8080/x"): []},
        [],
    ),
    "a_file_go_ignores_by_name": (
        {
            "main.go": CHI + 'func main() {\n r := chi.NewRouter()\n r.Get("/health", health)\n}\n',
            "_old_routes.go": CHI + 'func old(r chi.Router) { r.Delete("/users/{id}", del) }\n',
        },
        {("GET", "/health"): []},
        [("DELETE", "/users/{id}")],
    ),
}


@pytest.mark.parametrize("case", QODO5)
def test_the_shapes_a_fifth_qodo_review_found(tmp_path: Path, case: str) -> None:
    files, expected, absent = QODO5[case]
    rows = _rows_all(tmp_path, files)
    for key, guards in expected.items():
        found = sorted(sorted(_guarded(r)) for r in rows if (r["method"], r["pattern"]) == key)
        if guards is None:  # served raw too: an unguarded row beside the guarded one
            assert [] in found and ["requireAuth"] in found, key
        else:
            assert found == [sorted(guards)], key
    assert not {(r["method"], r["pattern"]) for r in rows} & set(absent)


QODO6 = {
    "a_converted_nil_handler": (
        {
            "main.go": HTTP + "func main() {\n"
            ' http.HandleFunc("POST /admin/reset", reset)\n'
            ' go http.ListenAndServe(":9090", http.Handler(nil))\n'
            ' http.ListenAndServe(":8080", requireAuth(http.DefaultServeMux))\n}\n' + WRAP
        },
        {("POST", "/admin/reset"): None},
        [],
    ),
    "an_unused_or_later_handled_server": (
        {
            "main.go": HTTP + "func main() {\n"
            ' http.HandleFunc("POST /admin/reset", reset)\n'
            ' _ = &http.Server{Addr: ":7070"}\n srv := &http.Server{Addr: ":9090"}\n'
            " srv.Handler = requireAuth(http.DefaultServeMux)\n srv.ListenAndServe()\n}\n" + WRAP
        },
        {("POST", "/admin/reset"): ["requireAuth"]},
        [],
    ),
    "a_utf8_escape": (
        {
            "main.go": GIN
            + 'func main() {\n r := gin.New()\n r.GET("/caf\\xc3\\xa9/:id", menu)\n}\n'
        },
        {("GET", "/café/:id"): []},
        [],
    ),
    "init_use_on_a_package_gin_router": (
        {
            "main.go": GIN + "var r = gin.New()\n\nfunc init() { r.Use(AuthRequired()) }\n\n"
            'func routes() { r.GET("/notes/:id", getNote) }\n'
        },
        {("GET", "/notes/:id"): ["AuthRequired"]},
        [],
    ),
    "a_checkout_method_constant": (
        {
            "main.go": CHI + 'const MethodGet = "POST"\n\nfunc main() {\n r := chi.NewRouter()\n'
            ' r.Method(MethodGet, "/x/{id}", h)\n}\n'
        },
        {("POST", "/x/{id}"): []},
        [("GET", "/x/{id}")],
    ),
    "an_if_scoped_router": (
        {
            "main.go": CHI + "func guarded() chi.Router {\n g := chi.NewRouter()\n"
            " g.Use(RequireUser)\n return g\n}\n\n"
            "func main() {\n r := chi.NewRouter()\n if r := guarded(); r != nil {\n"
            '  r.Get("/inner/{id}", h)\n }\n r.Get("/outer/{id}", h)\n}\n'
        },
        {("GET", "/outer/{id}"): [], ("GET", "/inner/{id}"): ["RequireUser"]},
        [],
    ),
}


@pytest.mark.parametrize("case", QODO6)
def test_the_shapes_a_sixth_qodo_review_found(tmp_path: Path, case: str) -> None:
    files, expected, absent = QODO6[case]
    rows = _rows_all(tmp_path, files)
    for key, guards in expected.items():
        found = sorted(sorted(_guarded(r)) for r in rows if (r["method"], r["pattern"]) == key)
        if guards is None:  # served raw too: an unguarded row beside the guarded one
            assert [] in found and ["requireAuth"] in found, key
        else:
            assert found == [sorted(guards)], key
    assert not {(r["method"], r["pattern"]) for r in rows} & set(absent)


def test_a_split_package_keeps_its_parser_gap(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    from traust_core.v1.providers import go_routes

    monkeypatch.setattr(go_routes, "parser", lambda: None)
    (tmp_path / "router.go").write_text(
        'package main\n\nimport "github.com/go-chi/chi/v5"\n\nvar router = chi.NewRouter()\n'
    )
    (tmp_path / "routes.go").write_text('package main\n\nfunc routes() { router.Get("/x", h) }\n')
    result = route_guards(tree_files(tmp_path)).model_dump(mode="json")
    assert [g["system"] for g in result["coverage_gaps"] if g["system"] == "go-http"] == ["go-http"]


CHI_HTTP = 'package main\n\nimport (\n "net/http"\n\n "github.com/go-chi/chi/v5"\n)\n\n'
CHECKED = ' if r.Header.Get("X-User") == "" {\n  http.Error(w, "no", 401)\n  return\n }\n'
GIN_CHECKED = ' if c.GetHeader("X-User") == "" {\n  c.AbortWithStatus(401)\n  return\n }\n'
QODO7 = {
    "an_init_after_the_registering_init": (
        {
            "a.go": GIN + 'var r = gin.New()\n\nfunc init() { r.GET("/early/:id", getNote) }\n',
            "a0.go": "package main\n\nfunc init() { setup() }\n\n"
            'func setup() { r.GET("/setup/:id", getNote) }\n',
            "b.go": "package main\n\nfunc init() { r.Use(AuthRequired()) }\n",
            "c.go": 'package main\n\nfunc init() { r.GET("/late/:id", getNote) }\n',
        },
        {
            ("GET", "/early/:id"): [],
            ("GET", "/setup/:id"): [],
            ("GET", "/late/:id"): ["AuthRequired"],
        },
        [],
    ),
    "a_local_constant_shadowing_a_package_one": (
        {
            "main.go": CHI + 'const path = "/public"\n\nfunc main() {\n r := chi.NewRouter()\n'
            ' const path = "/private/{id}"\n r.Get(path, h)\n}\n'
        },
        {("GET", "/private/{id}"): []},
        [("GET", "/public")],
    ),
    "a_dev_bypass_inside_the_wrapper": (
        {
            "main.go": CHI_HTTP + "var dev bool\n\n"
            "func RequireUser(next http.Handler) http.Handler {\n"
            " return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {\n"
            "  if dev {\n   next.ServeHTTP(w, r)\n   return\n  }\n"
            + CHECKED
            + " next.ServeHTTP(w, r)\n"
            " })\n}\n\nfunc main() {\n r := chi.NewRouter()\n r.Use(RequireUser)\n"
            ' r.Get("/x/{id}", h)\n}\n'
        },
        {("GET", "/x/{id}"): []},
        [],
    ),
    "a_wrapper_that_forwards_only_after_the_check": (
        {
            "main.go": CHI_HTTP + "func RequireUser(next http.Handler) http.Handler {\n"
            " return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {\n"
            + CHECKED
            + " next.ServeHTTP(w, r)\n })\n}\n\nfunc main() {\n r := chi.NewRouter()\n"
            ' r.Use(RequireUser)\n r.Get("/x/{id}", h)\n}\n'
        },
        {("GET", "/x/{id}"): ["RequireUser"]},
        [],
    ),
    "a_dev_bypass_inside_a_gin_step": (
        {
            "main.go": GIN + "var dev bool\n\nfunc AuthRequired() gin.HandlerFunc {\n"
            " return func(c *gin.Context) {\n  if dev {\n   c.Next()\n   return\n  }\n"
            + GIN_CHECKED
            + "  c.Next()\n }\n}\n\nfunc main() {\n r := gin.New()\n r.Use(AuthRequired())\n"
            ' r.GET("/notes/:id", getNote)\n}\n'
        },
        {("GET", "/notes/:id"): []},
        [],
    ),
    "a_gin_step_that_forwards_only_after_the_check": (
        {
            "main.go": GIN + "func AuthRequired() gin.HandlerFunc {\n"
            " return func(c *gin.Context) {\n" + GIN_CHECKED + "  c.Next()\n }\n}\n\n"
            "func main() {\n r := gin.New()\n r.Use(AuthRequired())\n"
            ' r.GET("/notes/:id", getNote)\n}\n'
        },
        {("GET", "/notes/:id"): ["AuthRequired"]},
        [],
    ),
}


@pytest.mark.parametrize("case", QODO7)
def test_the_shapes_a_seventh_qodo_review_found(tmp_path: Path, case: str) -> None:
    files, expected, absent = QODO7[case]
    rows = _rows_all(tmp_path, files)
    for key, guards in expected.items():
        found = sorted(sorted(_guarded(r)) for r in rows if (r["method"], r["pattern"]) == key)
        assert found == [sorted(guards)], key
    assert not {(r["method"], r["pattern"]) for r in rows} & set(absent)


def test_a_dot_imported_handler_keeps_its_source(tmp_path: Path) -> None:
    rows = _rows_all(
        tmp_path,
        {
            "main.go": 'package main\n\nimport (\n "github.com/go-chi/chi/v5"\n\n'
            ' . "example.com/app/handlers"\n)\n\nfunc main() {\n r := chi.NewRouter()\n'
            ' r.Get("/notes/{id}", ShowNote)\n}\n',
            "handlers/notes.go": 'package handlers\n\nimport "net/http"\n\n'
            "func ShowNote(w http.ResponseWriter, r *http.Request) {}\n",
        },
    )
    (note,) = [r for r in rows if r["pattern"] == "/notes/{id}"]
    assert (note["handler"]["path"], note["handler"]["line"]) == ("handlers/notes.go", 5)


def _wrapper(body: str) -> str:
    return (
        CHI_HTTP + "var guest bool\n\nfunc RequireUser(next http.Handler) http.Handler {\n"
        " return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {\n"
        + body
        + " })\n}\n\nfunc main() {\n r := chi.NewRouter()\n r.Use(RequireUser)\n"
        ' r.Get("/x/{id}", h)\n}\n'
    )


def _gin_step(body: str) -> str:
    return (
        GIN + "var dev bool\n\nfunc AuthRequired(c *gin.Context) {\n" + body + "}\n\n"
        "func main() {\n r := gin.New()\n r.Use(AuthRequired)\n"
        ' r.GET("/notes/:id", getNote)\n}\n'
    )


GUARD_TYPE = (
    "type Guard struct{}\n\nfunc (g *Guard) Auth(next http.Handler) http.Handler {\n"
    " return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {\n"
    + CHECKED
    + " next.ServeHTTP(w, r)\n })\n}\n\n"
)
QODO8 = {
    "a_forward_through_an_alias": (
        {
            "main.go": _wrapper(
                " downstream := next\n if guest {\n  downstream.ServeHTTP(w, r)\n  return\n }\n"
                + CHECKED
                + " downstream.ServeHTTP(w, r)\n"
            )
        },
        {("GET", "/x/{id}"): []},
    ),
    "a_forward_through_a_local_closure": (
        {
            "main.go": _wrapper(
                " pass := func() { next.ServeHTTP(w, r) }\n if guest {\n  pass()\n  return\n }\n"
                + CHECKED
                + " pass()\n"
            )
        },
        {("GET", "/x/{id}"): []},
    ),
    "a_gin_step_returning_without_abort": (
        {"main.go": _gin_step(" if dev {\n  return\n }\n" + GIN_CHECKED)},
        {("GET", "/notes/:id"): []},
    ),
    "a_gin_step_that_only_aborts_early": (
        {"main.go": _gin_step(GIN_CHECKED)},
        {("GET", "/notes/:id"): ["AuthRequired"]},
    ),
    "a_library_value_with_a_namesake_method": (
        {
            "main.go": 'package main\n\nimport (\n "net/http"\n\n "github.com/acme/authlib"\n'
            ' "github.com/go-chi/chi/v5"\n)\n\nvar client = authlib.New()\n\n'
            + GUARD_TYPE
            + 'func main() {\n r := chi.NewRouter()\n r.Use(client.Auth)\n r.Get("/x/{id}", h)\n}\n'
        },
        {("GET", "/x/{id}"): []},
    ),
    "a_package_value_of_the_checkout_type": (
        {
            "main.go": CHI_HTTP + "var guard = &Guard{}\n\n" + GUARD_TYPE + "func main() {\n"
            ' r := chi.NewRouter()\n r.Use(guard.Auth)\n r.Get("/x/{id}", h)\n}\n'
        },
        {("GET", "/x/{id}"): ["guard.Auth"]},
    ),
    "nested_setup_helpers": (
        {
            "main.go": GIN + "func installAuth(r *gin.Engine) { r.Use(AuthRequired()) }\n\n"
            "func setupAuth(r *gin.Engine) { installAuth(r) }\n\n"
            'func main() {\n r := gin.New()\n setupAuth(r)\n r.GET("/notes/:id", getNote)\n}\n'
        },
        {("GET", "/notes/:id"): ["AuthRequired"]},
    ),
}


@pytest.mark.parametrize("case", QODO8)
def test_the_shapes_an_eighth_qodo_review_found(tmp_path: Path, case: str) -> None:
    files, expected = QODO8[case]
    rows = _rows_all(tmp_path, files)
    for key, guards in expected.items():
        found = sorted(sorted(_guarded(r)) for r in rows if (r["method"], r["pattern"]) == key)
        assert found == [sorted(guards)], key


QODO9 = {
    "a_deferred_forward": " defer next.ServeHTTP(w, r)\n" + CHECKED,
    "a_forward_in_a_goroutine": " go next.ServeHTTP(w, r)\n" + CHECKED,
}


@pytest.mark.parametrize("case", QODO9)
def test_a_forward_that_runs_on_the_refusing_path_is_no_guard(tmp_path: Path, case: str) -> None:
    rows = _rows_all(tmp_path, {"main.go": _wrapper(QODO9[case])})
    assert [_guarded(r) for r in rows if r["pattern"] == "/x/{id}"] == [[]]


def test_many_route_helpers_walk_their_package_once(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    from traust_core.v1.providers import go_routes

    walks: list[str] = []
    values_in = go_routes._Matrix.values_in

    def counted(self: go_routes._Matrix, where: str) -> set[str]:
        walks.append(where)
        return values_in(self, where)

    monkeypatch.setattr(go_routes._Matrix, "values_in", counted)
    helpers = "".join(f'func routes{i}(r chi.Router) {{ r.Get("/r{i}", h) }}\n' for i in range(400))
    calls = "".join(f" routes{i}(r)\n" for i in range(400))
    rows = _rows_all(
        tmp_path,
        {"main.go": CHI + helpers + "\nfunc main() {\n r := chi.NewRouter()\n" + calls + "}\n"},
    )
    assert len(rows) == 400
    assert len(walks) == 1


QODO10 = {
    "a_space_before_the_registration_call": (
        {"main.go": GIN + 'func main() {\n r := gin.New()\n r.GET ("/notes/:id", getNote)\n}\n'},
        {("GET", "/notes/:id"): []},
    ),
    "a_comment_before_the_registration_call": (
        {
            "main.go": HTTP + "func main() {\n mux := http.NewServeMux()\n"
            ' mux.HandleFunc /* notes */ ("GET /notes/{id}", getNote)\n'
            ' http.ListenAndServe(":8080", mux)\n}\n'
        },
        {("GET", "/notes/{id}"): []},
    ),
    "a_server_handler_set_in_a_branch": (
        {
            "main.go": HTTP + "var prod bool\n\nfunc main() {\n"
            ' http.HandleFunc("POST /admin/reset", reset)\n srv := &http.Server{Addr: ":8080"}\n'
            " if prod {\n  srv.Handler = requireAuth(http.DefaultServeMux)\n }\n"
            " srv.ListenAndServe()\n}\n" + WRAP
        },
        {("POST", "/admin/reset"): None},
    ),
    "a_server_handler_set_before_the_start": (
        {
            "main.go": HTTP + "func main() {\n"
            ' http.HandleFunc("POST /admin/reset", reset)\n srv := &http.Server{Addr: ":8080"}\n'
            " srv.Handler = requireAuth(http.DefaultServeMux)\n srv.ListenAndServe()\n}\n" + WRAP
        },
        {("POST", "/admin/reset"): ["requireAuth"]},
    ),
    "a_library_typed_parameter_with_a_namesake_method": (
        {
            "main.go": 'package main\n\nimport (\n "net/http"\n\n "github.com/acme/extlib"\n'
            ' "github.com/go-chi/chi/v5"\n)\n\ntype Service struct{}\n\n'
            "func (s *Service) Auth(next http.Handler) http.Handler {\n"
            " return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {\n"
            + CHECKED
            + " next.ServeHTTP(w, r)\n })\n}\n\n"
            "func register(r chi.Router, svc extlib.Service) {\n r.Use(svc.Auth)\n"
            ' r.Get("/x/{id}", h)\n}\n\nfunc main() {\n r := chi.NewRouter()\n'
            " register(r, extlib.Service{})\n}\n"
        },
        {("GET", "/x/{id}"): []},
    ),
    "a_checkout_typed_parameter": (
        {
            "main.go": CHI_HTTP + "type Service struct{}\n\n"
            "func (s *Service) Auth(next http.Handler) http.Handler {\n"
            " return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {\n"
            + CHECKED
            + " next.ServeHTTP(w, r)\n })\n}\n\n"
            "func register(r chi.Router, svc *Service) {\n r.Use(svc.Auth)\n"
            ' r.Get("/x/{id}", h)\n}\n\nfunc main() {\n r := chi.NewRouter()\n'
            " register(r, &Service{})\n}\n"
        },
        {("GET", "/x/{id}"): ["svc.Auth"]},
    ),
}


@pytest.mark.parametrize("case", QODO10)
def test_the_shapes_a_tenth_qodo_review_found(tmp_path: Path, case: str) -> None:
    files, expected = QODO10[case]
    rows = _rows_all(tmp_path, files)
    for key, guards in expected.items():
        found = sorted(sorted(_guarded(r)) for r in rows if (r["method"], r["pattern"]) == key)
        if guards is None:  # served raw too: an unguarded row beside the guarded one
            assert [] in found and ["requireAuth"] in found, key
        else:
            assert found == [sorted(guards)], key


RESET = ' http.HandleFunc("POST /admin/reset", reset)\n'
GUARDED_SERVE = ' http.ListenAndServe(":8443", requireAuth(http.DefaultServeMux))\n'
FACTORY = (
    CHI_HTTP + "func RequireAuth(config http.Handler) func(http.Handler) http.Handler {\n"
    " return func(next http.Handler) http.Handler {\n{inner} }\n}\n\n"
    'func main() {\n r := chi.NewRouter()\n r.Use(RequireAuth(cfg))\n r.Get("/x/{id}", h)\n}\n'
)
QODO11 = {
    "a_nil_handler_variable": (
        {
            "main.go": HTTP + "func main() {\n" + RESET + " var h http.Handler\n"
            ' srv := &http.Server{Addr: ":8080"}\n srv.Handler = h\n go srv.ListenAndServe()\n'
            + GUARDED_SERVE
            + "}\n"
            + WRAP
        },
        {("POST", "/admin/reset"): None},
    ),
    "a_handler_set_through_a_pointer_alias": (
        {
            "main.go": HTTP + "func main() {\n" + RESET + ' srv := &http.Server{Addr: ":8080"}\n'
            " other := srv\n other.Handler = requireAuth(http.DefaultServeMux)\n"
            " srv.ListenAndServe()\n}\n" + WRAP
        },
        {("POST", "/admin/reset"): ["requireAuth"]},
    ),
    "a_package_server_with_a_handler": (
        {
            "main.go": HTTP + 'var srv = &http.Server{Addr: ":8080", Handler: requireAuth('
            "http.DefaultServeMux)}\n\nfunc main() {\n"
            + RESET
            + " srv.ListenAndServe()\n}\n"
            + WRAP
        },
        {("POST", "/admin/reset"): ["requireAuth"]},
    ),
    "a_no_op_middleware_factory": (
        {"main.go": FACTORY.replace("{inner}", "  return next\n")},
        {("GET", "/x/{id}"): []},
    ),
    "a_middleware_factory_that_wraps": (
        {
            "main.go": FACTORY.replace(
                "{inner}",
                "  return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {\n"
                + CHECKED
                + "  next.ServeHTTP(w, r)\n  })\n",
            )
        },
        {("GET", "/x/{id}"): ["RequireAuth"]},
    ),
    "a_checkout_method_named_serve": (
        {
            "main.go": HTTP + "type Worker struct{}\n\n"
            "func (w *Worker) Serve(addr string, h http.Handler) {}\n\n"
            "func main() {\n mux := http.NewServeMux()\n"
            ' mux.HandleFunc("POST /admin/reset", reset)\n wk := &Worker{}\n'
            ' wk.Serve(":9090", mux)\n'
            ' http.ListenAndServe(":8080", requireAuth(mux))\n}\n' + WRAP
        },
        {("POST", "/admin/reset"): ["requireAuth"]},
    ),
    "a_checkout_helper_that_serves": (
        {
            "main.go": HTTP
            + "func serve(addr string, h http.Handler) { http.ListenAndServe(addr, h) }\n\n"
            "func main() {\n mux := http.NewServeMux()\n"
            ' mux.HandleFunc("POST /admin/reset", reset)\n go serve(":9090", mux)\n'
            ' http.ListenAndServe(":8080", requireAuth(mux))\n}\n' + WRAP
        },
        {("POST", "/admin/reset"): None},
    ),
}


@pytest.mark.parametrize("case", QODO11)
def test_the_shapes_an_eleventh_qodo_review_found(tmp_path: Path, case: str) -> None:
    files, expected = QODO11[case]
    rows = _rows_all(tmp_path, files)
    for key, guards in expected.items():
        found = sorted(sorted(_guarded(r)) for r in rows if (r["method"], r["pattern"]) == key)
        if guards is None:  # served raw too: an unguarded row beside the guarded one
            assert [] in found and ["requireAuth"] in found, key
        else:
            assert found == [sorted(guards)], key


STORE = (
    'package store\n\nimport "net/http"\n\ntype DB struct{}\n\nfunc Open() *DB { return &DB{} }\n\n'
    "func (d *DB) Get(key string, f http.HandlerFunc) {}\n"
)
GIN_API = (
    "type API struct{ e *gin.Engine }\n\n"
    "func (a *API) GET(path string, h gin.HandlerFunc) { a.e.GET(path, h) }\n\n"
)


def test_a_checkout_store_method_is_no_route(tmp_path: Path) -> None:
    rows = _rows_all(
        tmp_path,
        {
            "main.go": 'package main\n\nimport (\n "net/http"\n\n "example.com/app/store"\n)\n\n'
            "func handler(w http.ResponseWriter, r *http.Request) {}\n\n"
            'func main() {\n db := store.Open()\n db.Get("/internal", handler)\n}\n',
            "store/store.go": STORE,
        },
    )
    assert [r["pattern"] for r in rows] == []


def test_a_checkout_router_wrapper_still_registers(tmp_path: Path) -> None:
    rows = _rows_all(
        tmp_path,
        {
            "main.go": GIN + GIN_API + "func main() {\n api := &API{e: gin.New()}\n"
            ' api.GET("/notes/:id", getNote)\n}\n'
        },
    )
    assert "/notes/:id" in [r["pattern"] for r in rows]


def test_an_unlisted_router_keeps_its_parser_gap(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    from traust_core.v1.providers import go_routes

    monkeypatch.setattr(go_routes, "parser", lambda: None)
    (tmp_path / "main.go").write_text(
        'package main\n\nimport "github.com/julienschmidt/httprouter"\n\n'
        'func main() {\n router := httprouter.New()\n router.GET("/x", h)\n}\n'
    )
    result = route_guards(tree_files(tmp_path)).model_dump(mode="json")
    assert [g["system"] for g in result["coverage_gaps"] if g["system"] == "go-http"] == ["go-http"]


@pytest.mark.parametrize("arch", ["amd64p32", "armbe", "arm64be", "mips64p32le", "ppc", "sparc64"])
def test_a_rare_architecture_file_credits_no_guard(tmp_path: Path, arch: str) -> None:
    rows = _rows_all(
        tmp_path,
        {
            f"routes_{arch}.go": CHI + "func main() {\n r := chi.NewRouter()\n"
            ' r.Use(RequireUser)\n r.Get("/notes/{id}", getNote)\n}\n'
        },
    )
    assert [_guarded(r) for r in rows] == [[]]


def test_a_raw_string_route_keeps_its_parser_gap(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    from traust_core.v1.providers import go_routes

    monkeypatch.setattr(go_routes, "parser", lambda: None)
    (tmp_path / "main.go").write_text(
        "package main\n\nfunc routes(router Router) {\n router.GET(`/notes/:id`, h)\n}\n"
    )
    result = route_guards(tree_files(tmp_path)).model_dump(mode="json")
    assert [g["system"] for g in result["coverage_gaps"] if g["system"] == "go-http"] == ["go-http"]
