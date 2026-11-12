"""Go HTTP routes: each router's prefixes, middleware and handlers, followed through groups,
sub-routers, mounts and the functions a router is passed to."""

from __future__ import annotations

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
