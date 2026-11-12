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
                    r.Use(jwtauth.Verifier(tokenAuth))
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
    assert _guarded(rows[("GET", "/notes/{noteID}")]) == ["jwtauth.Verifier"]
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
    (tmp_path / "main.go").write_text('package main\n\nfunc main() { r.Get("/x/{id}", h) }\n')
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
def test_the_shapes_a_third_review_found(tmp_path: Path, case: str) -> None:
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
