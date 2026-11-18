"""The Go ownership reader: it judges only (D35), over the Go route matrix's handlers."""

from __future__ import annotations

import json
import time
from pathlib import Path

import pytest

from traust_core.v1.providers.route_guards import route_guards
from traust_core.v1.providers.tree import tree_files

GO_MOD = "module example.com/app\n\ngo 1.22\n"
NOTE = "type Note struct {\n ID uint\n UserID uint\n Body string\n}\n\n"
PRODUCT = "type Product struct {\n ID uint\n Name string\n}\n\n"
CHI = (
    'package main\n\nimport (\n "encoding/json"\n "net/http"\n\n "github.com/go-chi/chi/v5"\n'
    ' "gorm.io/gorm"\n)\n\nvar db *gorm.DB\n\n' + NOTE + PRODUCT
)
CHI_MAIN = (
    "func main() {\n r := chi.NewRouter()\n r.Use(RequireUser)\n"
    ' r.Get("/notes/{id}", getNote)\n http.ListenAndServe(":8080", r)\n}\n\n'
)
GIN = 'package main\n\nimport "github.com/gin-gonic/gin"\n\n' + NOTE
GIN_MAIN = (
    "func main() {\n r := gin.New()\n r.Use(AuthRequired())\n"
    ' r.GET("/notes/:id", getNote)\n r.Run()\n}\n\n'
)


def _chi(body: str) -> str:
    return (
        CHI
        + CHI_MAIN
        + "func getNote(w http.ResponseWriter, r *http.Request) {\n"
        + body
        + " json.NewEncoder(w).Encode(nil)\n}\n"
    )


def _gin(body: str) -> str:
    return GIN + GIN_MAIN + "func getNote(c *gin.Context) {\n" + body + " c.JSON(200, nil)\n}\n"


def _owned(tmp_path: Path, text: str, extra: dict[str, str] | None = None) -> tuple[list, list]:
    for rel, data in {"go.mod": GO_MOD, "main.go": text, **(extra or {})}.items():
        path = tmp_path / rel
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(data)
    result = route_guards(tree_files(tmp_path)).model_dump(mode="json")
    rows = [r for r in result["routes"] if r["family"] == "go-http"]
    gaps = [g["system"] for g in result["coverage_gaps"] if g["system"].endswith(" ownership")]
    return rows, gaps


CASES = {
    # judged: a read by the path id alone
    "an_id_only_read_with_no_caller": (
        _chi(' id := chi.URLParam(r, "id")\n var n Note\n db.First(&n, id)\n'),
        "caller-blind",
        "Note",
    ),
    "an_id_only_read_beside_the_caller": (
        _chi(
            " user := r.Context().Value(userKey).(*User)\n _ = user\n"
            ' id := chi.URLParam(r, "id")\n var n Note\n db.First(&n, id)\n'
        ),
        "unchecked",
        "Note",
    ),
    "a_gin_closure_handler": (
        GIN + "func main() {\n r := gin.New()\n r.Use(AuthRequired())\n"
        ' r.GET("/notes/:id", func(c *gin.Context) {\n  u := c.MustGet("user")\n  _ = u\n'
        '  var n Note\n  db.First(&n, c.Param("id"))\n  c.JSON(200, n)\n })\n r.Run()\n}\n',
        "unchecked",
        "Note",
    ),
    "an_echo_handler": (
        'package main\n\nimport "github.com/labstack/echo/v4"\n\n' + NOTE + "func main() {\n"
        ' e := echo.New()\n g := e.Group("/api", echojwt.JWT(key))\n g.GET("/notes/:id", getNote)\n'
        ' e.Start(":1")\n}\n\nfunc getNote(c echo.Context) error {\n u := c.Get("user")\n _ = u\n'
        ' var n Note\n db.First(&n, c.Param("id"))\n return c.JSON(200, n)\n}\n',
        "unchecked",
        "Note",
    ),
    "a_fiber_handler": (
        'package main\n\nimport "github.com/gofiber/fiber/v2"\n\n' + NOTE + "func main() {\n"
        ' app := fiber.New()\n app.Use(jwtware.New(cfg))\n app.Get("/notes/:id", getNote)\n'
        ' app.Listen(":1")\n}\n\nfunc getNote(c *fiber.Ctx) error {\n id, _ := c.ParamsInt("id")\n'
        " var n Note\n db.First(&n, id)\n return c.JSON(n)\n}\n",
        "caller-blind",
        "Note",
    ),
    "a_gorilla_handler": (
        'package main\n\nimport (\n "net/http"\n\n "github.com/gorilla/mux"\n)\n\n'
        + NOTE
        + "func main() {\n r := mux.NewRouter()\n r.Use(RequireAuth)\n"
        ' r.HandleFunc("/notes/{id}", getNote).Methods("GET")\n http.ListenAndServe(":1", r)\n}\n\n'
        "func getNote(w http.ResponseWriter, r *http.Request) {\n vars := mux.Vars(r)\n"
        ' var n Note\n db.First(&n, vars["id"])\n}\n',
        "caller-blind",
        "Note",
    ),
    "a_net_http_delete_by_a_parsed_id": (
        'package main\n\nimport (\n "net/http"\n "strconv"\n)\n\n' + NOTE + "func main() {\n"
        ' mux := http.NewServeMux()\n mux.HandleFunc("DELETE /notes/{id}", del)\n'
        ' http.ListenAndServe(":1", requireAuth(mux))\n}\n\n'
        "func requireAuth(next http.Handler) http.Handler {\n"
        " return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {\n"
        '  if r.Header.Get("X-User") == "" {\n   http.Error(w, "no", 401)\n   return\n  }\n'
        "  next.ServeHTTP(w, r)\n })\n}\n\n"
        "func del(w http.ResponseWriter, r *http.Request) {\n"
        ' id, err := strconv.Atoi(r.PathValue("id"))\n if err != nil {\n'
        '  http.Error(w, "bad", 400)\n  return\n }\n db.Delete(&Note{}, id)\n}\n',
        "caller-blind",
        "Note",
    ),
    "a_bound_uri": (
        GIN.replace(NOTE, NOTE + 'type uri struct{ ID uint `uri:"id"` }\n\n')
        + GIN_MAIN
        + "func getNote(c *gin.Context) {\n var u uri\n c.ShouldBindUri(&u)\n var n Note\n"
        " db.First(&n, u.ID)\n c.JSON(200, n)\n}\n",
        "caller-blind",
        "Note",
    ),
    "an_id_read_by_a_checkout_helper": (
        GIN + "func parseID(c *gin.Context) uint {\n"
        ' v, _ := strconv.Atoi(c.Param("id"))\n return uint(v)\n}\n\n'
        + GIN_MAIN
        + "func getNote(c *gin.Context) {\n id := parseID(c)\n var n Note\n db.First(&n, id)\n}\n",
        "caller-blind",
        "Note",
    ),
    "a_handler_factory": (
        CHI + "func getNote(db *gorm.DB) http.HandlerFunc {\n"
        " return func(w http.ResponseWriter, r *http.Request) {\n"
        '  var n Note\n  db.First(&n, chi.URLParam(r, "id"))\n }\n}\n\n'
        + CHI_MAIN.replace("getNote)", "getNote(db))"),
        "caller-blind",
        "Note",
    ),
    "a_read_one_checkout_call_deep": (
        CHI + "type store struct{ db *gorm.DB }\n\n"
        "func (s *store) GetNote(id string) (*Note, error) {\n var n Note\n"
        " err := s.db.First(&n, id).Error\n return &n, err\n}\n\n"
        "type api struct{ s *store }\n\n"
        "func (a *api) getNote(w http.ResponseWriter, r *http.Request) {\n"
        ' n, err := a.s.GetNote(chi.URLParam(r, "id"))\n _ = err\n'
        " json.NewEncoder(w).Encode(n)\n}\n\n"
        "func main() {\n a := &api{}\n r := chi.NewRouter()\n r.Use(RequireUser)\n"
        ' r.Get("/notes/{id}", a.getNote)\n http.ListenAndServe(":8080", r)\n}\n',
        "caller-blind",
        "Note",
    ),
    "a_delete_through_an_interface_store": (
        CHI + "type Store interface{ Delete(id string) error }\n\nvar st Store\n\n"
        "func main() {\n r := chi.NewRouter()\n r.Use(RequireUser)\n"
        ' r.Delete("/notes/{id}", del)\n http.ListenAndServe(":8080", r)\n}\n\n'
        "func del(w http.ResponseWriter, r *http.Request) {\n"
        ' st.Delete(chi.URLParam(r, "id"))\n}\n',
        "caller-blind",
        None,
    ),
    "a_pocketbase_record_read": (
        'package main\n\nimport (\n "github.com/pocketbase/pocketbase"\n'
        ' "github.com/pocketbase/pocketbase/apis"\n "github.com/pocketbase/pocketbase/core"\n)\n\n'
        "func main() {\n app := pocketbase.New()\n"
        " app.OnServe().BindFunc(func(se *core.ServeEvent) error {\n"
        '  se.Router.GET("/api/notes/{id}", getNote).Bind(apis.RequireAuth())\n'
        "  return se.Next()\n })\n app.Start()\n}\n\n"
        "func getNote(e *core.RequestEvent) error {\n"
        ' rec, err := e.App.FindRecordById("notes", e.Request.PathValue("id"))\n'
        " if err != nil {\n  return err\n }\n return e.JSON(200, rec)\n}\n",
        "caller-blind",
        None,
    ),
    # never credited (D35): what the shared classification would credit reads unknown
    "a_read_scoped_by_the_caller": (
        _chi(
            " user := r.Context().Value(userKey).(*User)\n"
            ' id := chi.URLParam(r, "id")\n var n Note\n'
            ' db.Where("user_id = ?", user.ID).First(&n, id)\n'
        ),
        "unknown",
        None,
    ),
    "a_query_builder_scoped_by_the_caller": (
        _chi(
            " _, claims, _ := jwtauth.FromContext(r.Context())\n"
            ' q := db.Where("user_id = ?", claims["sub"])\n var n Note\n'
            ' q.First(&n, chi.URLParam(r, "id"))\n'
        ).replace('"gorm.io/gorm"\n', '"gorm.io/gorm"\n "github.com/go-chi/jwtauth/v5"\n'),
        "unknown",
        None,
    ),
    "an_ownerless_record": (
        _chi(' id := chi.URLParam(r, "id")\n var p Product\n db.First(&p, id)\n'),
        "unknown",
        None,
    ),
    "a_caller_read_with_no_owner_field_known": (
        _gin(' u := c.MustGet("user")\n _ = u\n rec, _ := store.Find(c.Param("id"))\n _ = rec\n'),
        "unknown",
        None,
    ),
    "a_handler_that_never_reads_the_id": (_chi(' w.Write([]byte("hi"))\n'), "unknown", None),
    "an_unauthenticated_route": (
        _chi(' var n Note\n db.First(&n, chi.URLParam(r, "id"))\n').replace(
            " r.Use(RequireUser)\n", ""
        ),
        "n/a",
        None,
    ),
}


@pytest.mark.parametrize("case", CASES)
def test_each_shape_reads_as_judged_or_unknown(tmp_path: Path, case: str) -> None:
    text, ownership, record = CASES[case]
    rows, gaps = _owned(tmp_path, text)
    (row,) = [r for r in rows if r["pattern"] in ("/notes/{id}", "/notes/:id", "/api/notes/:id",
                                                  "/api/notes/{id}")]  # fmt: skip
    assert row["ownership"] == ownership
    assert (row.get("ownership_evidence") or {}).get("record_type") == record
    assert row["judgement_required"] or ownership not in ("caller-blind", "unchecked")
    assert gaps == []


def test_an_unresolved_handler_is_an_ownership_gap(tmp_path: Path) -> None:
    rows, gaps = _owned(tmp_path, CHI + CHI_MAIN.replace("getNote)", "handlers.Get)"))
    assert [r["ownership"] for r in rows] == [None]
    assert gaps == ["go-http ownership"]


def test_the_judged_row_points_at_the_read(tmp_path: Path) -> None:
    text = _chi(' id := chi.URLParam(r, "id")\n var n Note\n db.First(&n, id)\n')
    rows, _ = _owned(tmp_path, text)
    (row,) = rows
    evidence = row["ownership_evidence"]
    line = text.splitlines().index(" db.First(&n, id)") + 1
    assert (evidence["lookup"]["path"], evidence["lookup"]["line"]) == ("main.go", line)
    assert evidence["owner_field"] == "UserID"
    assert evidence["caller"] is None


def test_a_hop_is_named_in_the_evidence(tmp_path: Path) -> None:
    text = CASES["a_read_one_checkout_call_deep"][0]
    rows, _ = _owned(tmp_path, text)
    (row,) = rows
    assert (
        row["ownership_evidence"]["hop"]["line"]
        == text.splitlines().index(' n, err := a.s.GetNote(chi.URLParam(r, "id"))') + 1
    )


READ = ' var n Note\n db.First(&n, chi.URLParam(r, "id"))\n'
CALLERS = {
    "a_context_value": " u := r.Context().Value(userKey)\n _ = u\n",
    "a_string_context_key": ' u := r.Context().Value("user_id")\n _ = u\n',
    "a_caller_named_call": " u := auth.CurrentUser(r)\n _ = u\n",
    "a_from_context_of_an_auth_package": " _, claims, _ := jwtauth.FromContext(r.Context())\n"
    " _ = claims\n",
    "basic_auth": " name, _, _ := r.BasicAuth()\n _ = name\n",
}


@pytest.mark.parametrize("case", CALLERS)
def test_each_caller_shape_makes_the_read_unchecked(tmp_path: Path, case: str) -> None:
    text = _chi(CALLERS[case] + READ).replace(
        '"gorm.io/gorm"\n', '"gorm.io/gorm"\n "github.com/go-chi/jwtauth/v5"\n'
    )
    rows, _ = _owned(tmp_path, text)
    assert [r["ownership"] for r in rows] == ["unchecked"]


def test_a_fiber_local_and_a_pocketbase_auth_are_callers(tmp_path: Path) -> None:
    fiber = (
        'package main\n\nimport "github.com/gofiber/fiber/v2"\n\n' + NOTE + "func main() {\n"
        ' app := fiber.New()\n app.Use(jwtware.New(cfg))\n app.Get("/notes/:id", getNote)\n'
        ' app.Listen(":1")\n}\n\nfunc getNote(c *fiber.Ctx) error {\n u := c.Locals("user")\n'
        ' _ = u\n var n Note\n db.First(&n, c.Params("id"))\n return c.JSON(n)\n}\n'
    )
    rows, _ = _owned(tmp_path / "fiber", fiber)
    assert [r["ownership"] for r in rows] == ["unchecked"]
    pocketbase = CASES["a_pocketbase_record_read"][0].replace(
        " if err != nil {", " _ = e.Auth\n if err != nil {"
    )
    rows, _ = _owned(tmp_path / "pocketbase", pocketbase)
    assert [r["ownership"] for r in rows] == ["unknown"]  # a caller, no owner field known


INERT = {
    "logged": ' log.Printf("note %s", chi.URLParam(r, "id"))\n',
    "answered": ' http.Error(w, chi.URLParam(r, "id"), 404)\n',
    "parsed": ' n, _ := strconv.Atoi(chi.URLParam(r, "id"))\n _ = n\n',
    "logger_method": ' logger.Info("note", chi.URLParam(r, "id"))\n',
}


@pytest.mark.parametrize("case", INERT)
def test_an_id_only_parsed_logged_or_answered_reads_nothing(tmp_path: Path, case: str) -> None:
    rows, _ = _owned(tmp_path, _chi(INERT[case]))
    assert [r["ownership"] for r in rows] == ["unknown"]  # a GET acting on nothing: no credit
    assert rows[0].get("ownership_evidence") is None


REVIEW = json.loads(
    (Path(__file__).parents[2] / "fixtures/code_facts/go_ownership_review.json").read_text()
)


@pytest.mark.parametrize("case", sorted(REVIEW))
def test_the_shapes_the_blind_review_found(tmp_path: Path, case: str) -> None:
    for rel, text in REVIEW[case]["files"].items():
        path = tmp_path / rel
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(text)
    result = route_guards(tree_files(tmp_path)).model_dump(mode="json")
    rows = sorted(
        [r["method"], r["pattern"], r["ownership"]]
        for r in result["routes"]
        if r["family"] == "go-http"
    )
    assert rows == REVIEW[case]["rows"]


def test_deeply_nested_id_arguments_stay_fast(tmp_path: Path) -> None:
    inner = 'chi.URLParam(r, "id")'
    for _ in range(300):
        inner = f"wrap({inner})"
    text = _chi(f" var n Note\n db.First(&n, {inner})\n") + (
        "func wrap(s string) string { return s }\n"
    )
    start = time.perf_counter()
    rows, _ = _owned(tmp_path, text)
    assert [r["ownership"] for r in rows] == ["caller-blind"]
    assert time.perf_counter() - start < 30


def test_an_id_handed_to_a_callback_parameter_is_a_handoff(tmp_path: Path) -> None:
    text = (
        GIN
        + (
            "func withID(c *gin.Context, name string, f func(id uint)) {\n"
            " v, _ := strconv.ParseUint(c.Param(name), 10, 64)\n f(uint(v))\n}\n\n"
        )
        + GIN_MAIN
        + 'func getNote(c *gin.Context) {\n withID(c, "id", func(id uint) { show(id) })\n}\n'
    )
    rows, _ = _owned(tmp_path, text)
    assert [r["ownership"] for r in rows] == ["unknown"]


def test_helpers_that_fan_out_stay_fast(tmp_path: Path) -> None:
    helpers = "func f0(s string) string { return s }\n" + "".join(
        f"func f{i}(s string) string {{\n a := f{i - 1}(s)\n b := f{i - 1}(s)\n return a + b\n}}\n"
        for i in range(1, 17)
    )
    text = _chi(' var n Note\n db.First(&n, f16(chi.URLParam(r, "id")))\n') + helpers
    start = time.perf_counter()
    rows, _ = _owned(tmp_path, text)
    assert [r["ownership"] for r in rows] == ["caller-blind"]  # read by what the id becomes
    assert time.perf_counter() - start < 30


CALLER = " user := r.Context().Value(userKey).(*User)\n _ = user\n"
ID = ' id := chi.URLParam(r, "id")\n'
QODO1 = {
    "a_helper_that_only_logs_the_id": (
        {
            "main.go": _chi(" var n Note\n db.First(&n, pick(r))\n")
            + 'func pick(r *http.Request) int {\n log.Println(r.PathValue("id"))\n return 42\n}\n'
        },
        "unknown",
    ),
    "a_store_package_named_like_uuid": (
        {
            "main.go": _chi(ID + " n, _ := uuidstore.Load(id)\n _ = n\n").replace(
                '"gorm.io/gorm"\n', '"gorm.io/gorm"\n "github.com/acme/uuidstore"\n'
            )
        },
        "caller-blind",
    ),
    "a_cache_key_named_like_the_caller": (
        {
            "main.go": _chi(
                ' uid := cache.Get("user_id")\n _ = uid\n' + ID + " var n Note\n db.First(&n, id)\n"
            )
        },
        "caller-blind",
    ),
    "an_ownerless_record_named_like_an_owned_one": (
        {
            "main.go": _chi(ID + " var n models.Note\n db.First(&n, id)\n").replace(
                '"gorm.io/gorm"\n', '"gorm.io/gorm"\n "example.com/app/models"\n'
            ),
            "models/note.go": "package models\n\ntype Note struct {\n ID uint\n Body string\n}\n",
        },
        "unknown",
    ),
    "a_caller_value_overwritten_on_a_branch": (
        {
            "main.go": _chi(
                CALLER
                + " uid := user.ID\n if dev {\n  uid = 0\n }\n"
                + ID
                + ' var n Note\n db.Where("user_id = ?", uid).First(&n, id)\n'
            )
            + "var dev bool\n"
        },
        "unchecked",
    ),
    "a_builder_scoped_after_it_runs": (
        {
            "main.go": _chi(
                CALLER + ID + ' var n Note\n q := db.Where("id = ?", id)\n q.First(&n)\n'
                ' q = q.Where("user_id = ?", user.ID)\n'
            )
        },
        "unchecked",
    ),
    "a_closure_never_called": (
        {
            "main.go": _chi(
                ' load := func() {\n  var n Note\n  db.First(&n, chi.URLParam(r, "id"))\n }\n'
            )
        },
        "unknown",
    ),
    "an_unrelated_param_call": (
        {"main.go": _chi(' var n Note\n db.First(&n, cfg.Param("id"))\n') + "var cfg Config\n"},
        "unknown",
    ),
    "a_relation_named_like_the_caller": (
        {"main.go": _chi(ID + " var n Note\n db.First(&n, id)\n owner := n.User()\n _ = owner\n")},
        "caller-blind",
    ),
    "an_inline_new_record": (
        {"main.go": _chi(CALLER + ID + " db.First(new(Note), id)\n")},
        "unchecked",
    ),
}


@pytest.mark.parametrize("case", QODO1)
def test_the_shapes_the_first_qodo_review_found(tmp_path: Path, case: str) -> None:
    files, expected = QODO1[case]
    rows, _ = _owned(tmp_path, files.pop("main.go"), files)
    assert [r["ownership"] for r in rows] == [expected]


QODO2 = {
    "an_id_in_a_helpers_second_result": (
        _chi(" _, id := ids(r)\n var n Note\n db.First(&n, id)\n")
        + 'func ids(r *http.Request) (int, string) {\n return 1, r.PathValue("id")\n}\n',
        "caller-blind",
    ),
    "a_helpers_other_result_is_no_id": (
        _chi(CALLER + " n, id := ids(r)\n _ = id\n var note Note\n db.First(&note, n)\n")
        + 'func ids(r *http.Request) (int, string) {\n return 1, r.PathValue("id")\n}\n',
        "unknown",
    ),
    "a_builder_narrowed_before_it_runs": (
        _chi(
            CALLER + ID + ' q := db.Where("id = ?", id)\n q = q.Where("user_id = ?", user.ID)\n'
            " var note Note\n q.First(&note)\n"
        ),
        "unknown",
    ),
}


@pytest.mark.parametrize("case", QODO2)
def test_the_shapes_the_second_qodo_review_found(tmp_path: Path, case: str) -> None:
    text, expected = QODO2[case]
    rows, _ = _owned(tmp_path, text)
    assert [r["ownership"] for r in rows] == [expected]


QODO3 = {
    "a_builder_narrowed_and_run_in_one_statement": (
        _chi(
            CALLER + ID + ' q := db.Model(&Note{}).Where("id = ?", id)\n var note Note\n'
            ' q = q.Where("user_id = ?", user.ID).First(&note)\n'
        ),
        "unknown",
    ),
    "an_id_forwarded_by_a_wrapper": (
        _chi(" _, id := wrap(r)\n var n Note\n db.First(&n, id)\n")
        + 'func ids(r *http.Request) (int, string) {\n return 1, r.PathValue("id")\n}\n\n'
        "func wrap(r *http.Request) (int, string) {\n return ids(r)\n}\n",
        "caller-blind",
    ),
}


@pytest.mark.parametrize("case", QODO3)
def test_the_shapes_the_third_qodo_review_found(tmp_path: Path, case: str) -> None:
    text, expected = QODO3[case]
    rows, _ = _owned(tmp_path, text)
    assert [r["ownership"] for r in rows] == [expected]


def test_a_read_before_its_chained_filter_is_unscoped(tmp_path: Path) -> None:
    text = _chi(
        CALLER + ID + ' q := db.Model(&Note{}).Where("id = ?", id)\n var note Note\n'
        ' q = q.First(&note).Where("user_id = ?", user.ID)\n'
    )
    rows, _ = _owned(tmp_path, text)
    assert [r["ownership"] for r in rows] == ["unchecked"]


def test_a_chain_builder_before_the_filter_is_no_run(tmp_path: Path) -> None:
    text = _chi(
        CALLER + ID + ' q := db.Model(&Note{}).Where("id = ?", id)\n'
        ' q = q.Select("*").Where("user_id = ?", user.ID)\n var note Note\n q.First(&note)\n'
    )
    rows, _ = _owned(tmp_path, text)
    assert [r["ownership"] for r in rows] == ["unknown"]  # scoped before it runs


def test_a_go_pg_select_filling_a_record_is_a_run(tmp_path: Path) -> None:
    text = _chi(
        CALLER + ID + ' var note Note\n q := db.Model(&note).Where("id = ?", id)\n'
        ' q.Select(&note)\n q = q.Where("user_id = ?", user.ID)\n q.Select()\n'
    )
    rows, _ = _owned(tmp_path, text)
    assert [r["ownership"] for r in rows] == ["unchecked"]  # read before the filter


def test_a_select_of_columns_in_a_variable_builds_the_query(tmp_path: Path) -> None:
    text = _chi(
        CALLER + ID + ' cols := "id"\n var note Note\n q := db.Model(&note).Where("id = ?", id)\n'
        ' q = q.Select(cols)\n q = q.Where("user_id = ?", user.ID)\n q.First(&note)\n'
    )
    rows, _ = _owned(tmp_path, text)
    assert [r["ownership"] for r in rows] == ["unknown"]  # narrowed before it runs


def test_a_select_binding_a_pointer_value_builds_the_query(tmp_path: Path) -> None:
    text = _chi(
        CALLER + ID + " var fallback int\n var note Note\n"
        ' q := db.Model(&note).Where("id = ?", id)\n'
        ' q = q.Select("COALESCE(?, id) AS id", &fallback).Where("user_id = ?", user.ID)\n'
        " q.First(&note)\n"
    )
    rows, _ = _owned(tmp_path, text)
    assert [r["ownership"] for r in rows] == ["unknown"]  # narrowed before it runs


def test_a_go_pg_select_into_a_pointer_variable_is_a_run(tmp_path: Path) -> None:
    text = _chi(
        CALLER + ID + " var title, body string\n var note Note\n"
        ' q := db.Model(&note).Where("id = ?", id)\n first := &title\n q.Select(first, &body)\n'
        ' q = q.Where("user_id = ?", user.ID)\n q.Select()\n'
    )
    rows, _ = _owned(tmp_path, text)
    assert [r["ownership"] for r in rows] == ["unchecked"]  # read before the filter
