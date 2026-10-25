"""The route x guard matrix. The asymmetry fixtures mirror the AWX miss shape: sibling
registrations in one file where some carry the guard and some don't. Ported from traust
tests/test_enumerate_route_guards.py."""

from __future__ import annotations

from datetime import UTC, datetime
from pathlib import Path

import pytest

from traust_core.v1.errors import ValidationError
from traust_core.v1.models.code_facts import RouteGuardFact
from traust_core.v1.providers.clock import FixedClock
from traust_core.v1.providers.route_guards import RouteGuardMatrix, route_guards
from traust_core.v1.providers.tools import ToolRequest
from traust_core.v1.providers.tree import tree_files


def _enum(repo: Path) -> dict:
    return route_guards(tree_files(repo)).model_dump(mode="json")


def _by_pattern(result: dict, pattern: str) -> list:
    return [r for r in result["routes"] if r["pattern"] == pattern]


# --------------------------------------------------------------------------
# go-http
# --------------------------------------------------------------------------


@pytest.fixture
def go_asym_repo(tmp_path):
    (tmp_path / "server.go").write_text(
        "package api\n\n"
        "func routes(mux *http.ServeMux) {\n"
        '\tmux.HandleFunc("/api/jobs", requireAuth(handleJobs))\n'
        '\tmux.HandleFunc("/api/admin", requireAuth(handleAdmin))\n'
        '\tmux.HandleFunc("/api/callback", handleCallback)\n'
        "}\n"
    )
    return tmp_path


def test_go_guarded_and_bare_rows(go_asym_repo):
    result = _enum(go_asym_repo)
    [jobs] = _by_pattern(result, "/api/jobs")
    assert jobs["guards"] == ["requireAuth"]
    assert jobs["judgement_required"] is False
    [cb] = _by_pattern(result, "/api/callback")
    assert cb["guards"] == []
    assert cb["judgement_required"] is True


def test_go_asymmetry_group_detected(go_asym_repo):
    result = _enum(go_asym_repo)
    [asym] = result["asymmetries"]
    assert asym["unguarded"] == ["/api/callback"]
    assert set(asym["guarded"]) == {"/api/jobs", "/api/admin"}
    [cb] = _by_pattern(result, "/api/callback")
    assert cb["asymmetry"] is True


def test_go_receiver_scoped_use_middleware(tmp_path):
    (tmp_path / "router.go").write_text(
        "package api\n"
        "func routes(r chi.Router) {\n"
        "\tr.Use(authMiddleware)\n"
        '\tr.Get("/things", listThings)\n'
        "}\n"
    )
    result = _enum(tmp_path)
    [row] = _by_pattern(result, "/things")
    assert row["scope_guards"] == ["authMiddleware"]
    assert row["guards"] == []
    assert row["judgement_required"] is False


def test_go_unguard_marker_forces_judgement(tmp_path):
    (tmp_path / "public.go").write_text(
        "package api\n"
        "func routes(r chi.Router) {\n"
        '\tr.Get("/metrics", skipAuth(metricsHandler))\n'
        "}\n"
    )
    result = _enum(tmp_path)
    [row] = _by_pattern(result, "/metrics")
    assert row["judgement_required"] is True
    assert row["unguard_markers"] == ["skipAuth"]


def test_go_test_files_excluded(tmp_path):
    (tmp_path / "server_test.go").write_text(
        'func t(mux *http.ServeMux) { mux.HandleFunc("/t", handler) }\n'
    )
    assert _enum(tmp_path)["routes"] == []


# --------------------------------------------------------------------------
# django-drf
# --------------------------------------------------------------------------


@pytest.fixture
def django_repo(tmp_path):
    app = tmp_path / "app"
    app.mkdir()
    (app / "urls.py").write_text(
        "urlpatterns = [\n"
        "    path('jobs/', JobView.as_view()),\n"
        "    path('callback/', CallbackView.as_view()),\n"
        "    path('legacy/', legacy_view),\n"
        "]\n"
    )
    (app / "views.py").write_text(
        "class JobView(APIView):\n"
        "    permission_classes = [IsAuthenticated]\n"
        "    def get(self, request): ...\n"
        "\n"
        "class CallbackView(APIView):\n"
        "    permission_classes = [AllowAny]\n"
        "    def post(self, request): ...\n"
        "\n"
        "@login_required\n"
        "def legacy_view(request): ...\n"
    )
    return tmp_path


def test_django_permission_classes_resolved(django_repo):
    result = _enum(django_repo)
    [jobs] = _by_pattern(result, "jobs/")
    assert jobs["guards"] == ["IsAuthenticated"]
    assert jobs["judgement_required"] is False
    assert jobs["handler"]["path"].endswith("views.py")


def test_django_allowany_is_judged(django_repo):
    result = _enum(django_repo)
    [cb] = _by_pattern(result, "callback/")
    assert "AllowAny" in cb["unguard_markers"]
    assert cb["judgement_required"] is True


def test_django_decorator_guard(django_repo):
    result = _enum(django_repo)
    [legacy] = _by_pattern(result, "legacy/")
    assert legacy["guards"] == ["login_required"]


def test_drf_default_permissions_as_scope_guard(tmp_path):
    app = tmp_path / "svc"
    app.mkdir()
    (app / "settings.py").write_text(
        "REST_FRAMEWORK = {\n"
        "    'DEFAULT_PERMISSION_CLASSES': ["
        "'rest_framework.permissions.IsAuthenticated'],\n"
        "}\n"
    )
    (app / "urls.py").write_text("urlpatterns = [path('items/', ItemView.as_view())]\n")
    (app / "views.py").write_text("class ItemView(APIView):\n    def get(self, request): ...\n")
    result = _enum(tmp_path)
    [row] = _by_pattern(result, "items/")
    assert row["guards"] == []
    assert any("IsAuthenticated" in g for g in row["scope_guards"])
    assert row["judgement_required"] is False


def test_django_no_guard_no_default_is_judged(tmp_path):
    app = tmp_path / "svc"
    app.mkdir()
    (app / "urls.py").write_text("urlpatterns = [path('open/', OpenView.as_view())]\n")
    (app / "views.py").write_text("class OpenView(APIView):\n    def get(self, request): ...\n")
    result = _enum(tmp_path)
    [row] = _by_pattern(result, "open/")
    assert row["judgement_required"] is True


# --------------------------------------------------------------------------
# flask
# --------------------------------------------------------------------------


def _write(root: Path, rel: str, body: str) -> None:
    p = root / rel
    p.parent.mkdir(parents=True, exist_ok=True)
    p.write_text(body)


def _flask(result: dict) -> list:
    return [r for r in result["routes"] if r["family"] == "flask"]


def _row(result: dict, method: str, pattern: str) -> dict:
    [row] = [r for r in _flask(result) if r["method"] == method and r["pattern"] == pattern]
    return row


@pytest.fixture
def flask_asym_repo(tmp_path):
    _write(
        tmp_path,
        "app/views.py",
        "from flask import Blueprint\n"
        "from .auth import login_required\n\n"
        "bp = Blueprint('items', __name__)\n\n"
        "@bp.route('/items', methods=['GET'])\n"
        "@login_required\n"
        "def list_items():\n"
        "    return []\n\n"
        "@bp.route('/items/<id>', methods=['DELETE'])\n"
        "@login_required\n"
        "def delete_item(id):\n"
        "    return ''\n\n"
        "@bp.post('/items/import')\n"
        "def import_items():\n"
        "    return ''\n",
    )
    return tmp_path


def test_flask_decorator_routes_and_guards(flask_asym_repo):
    result = _enum(flask_asym_repo)
    listing = _row(result, "GET", "/items")
    assert listing["guards"] == ["login_required"]
    assert listing["judgement_required"] is False
    assert listing["handler"]["expr"] == "list_items"
    assert listing["handler"]["line"] == 8
    assert listing["registration"]["line"] == 6
    imp = _row(result, "POST", "/items/import")
    assert imp["guards"] == [] and imp["scope_guards"] == []
    assert imp["judgement_required"] is True


def test_flask_bare_sibling_is_asymmetry(flask_asym_repo):
    result = _enum(flask_asym_repo)
    [asym] = [
        a for a in result["asymmetries"] if a["family"] == "flask" and a["guard_family"] is None
    ]
    assert asym["unguarded"] == ["POST /items/import"]
    assert set(asym["guarded"]) == {"GET /items", "DELETE /items/<id>"}
    assert _row(result, "POST", "/items/import")["asymmetry"] is True


def test_flask_blueprint_before_request_is_baseline(tmp_path):
    _write(
        tmp_path,
        "svc/admin.py",
        "from flask import Blueprint, abort, g\n\n"
        "admin = Blueprint('admin', __name__)\n\n"
        "@admin.before_request\n"
        "def require_admin_session():\n"
        "    if not g.user or not g.user.is_admin:\n"
        "        abort(403)\n\n"
        "@admin.route('/settings')\n"
        "def settings():\n"
        "    return {}\n",
    )
    _write(
        tmp_path,
        "svc/public.py",
        "from flask import Blueprint\n\n"
        "pub = Blueprint('pub', __name__)\n\n"
        "@pub.route('/status')\n"
        "def status():\n"
        "    return 'ok'\n",
    )
    result = _enum(tmp_path)
    settings = _row(result, "GET", "/settings")
    assert settings["guards"] == []
    assert settings["scope_guards"] == ["before_request:require_admin_session"]
    assert settings["judgement_required"] is False
    # the baseline is receiver-scoped: another blueprint does not inherit it
    status = _row(result, "GET", "/status")
    assert status["scope_guards"] == []
    assert status["judgement_required"] is True


def test_flask_before_request_that_cannot_reject_is_not_a_guard(tmp_path):
    _write(
        tmp_path,
        "svc/views.py",
        "from flask import Blueprint, g\n\n"
        "bp = Blueprint('x', __name__)\n\n"
        "@bp.before_request\n"
        "def load_session_user():\n"
        "    g.user = None\n\n"
        "@bp.route('/x')\n"
        "def x():\n"
        "    return ''\n",
    )
    row = _row(_enum(tmp_path), "GET", "/x")
    assert row["scope_guards"] == []
    assert row["judgement_required"] is True


def test_flask_methodview_one_row_per_method(tmp_path):
    _write(
        tmp_path,
        "svc/views.py",
        "from flask import Flask\n"
        "from flask.views import MethodView\n"
        "from .auth import token_required\n\n"
        "app = Flask(__name__)\n\n"
        "class WidgetAPI(MethodView):\n"
        "    @token_required\n"
        "    def get(self, wid):\n"
        "        return {}\n\n"
        "    @token_required\n"
        "    def put(self, wid):\n"
        "        return {}\n\n"
        "    def delete(self, wid):\n"
        "        return ''\n\n"
        "app.add_url_rule('/widgets/<wid>', view_func=WidgetAPI.as_view('widget'))\n",
    )
    result = _enum(tmp_path)
    rows = [r for r in _flask(result) if r["pattern"] == "/widgets/<wid>"]
    assert sorted(r["method"] for r in rows) == ["DELETE", "GET", "PUT"]
    assert all(r["view_class"] == "WidgetAPI" for r in rows)
    get = _row(result, "GET", "/widgets/<wid>")
    assert get["guards"] == ["token_required"]
    assert get["handler"]["expr"] == "WidgetAPI.get"
    delete = _row(result, "DELETE", "/widgets/<wid>")
    assert delete["guards"] == [] and delete["judgement_required"] is True
    assert delete["asymmetry"] is True


def test_flask_restx_method_decorators_and_inheritance(tmp_path):
    _write(
        tmp_path,
        "svc/base.py",
        "from flask_restx import Resource\n"
        "from .auth import require_auth\n\n"
        "class AuthedResource(Resource):\n"
        "    method_decorators = [require_auth]\n",
    )
    _write(
        tmp_path,
        "svc/api.py",
        "from flask_restx import Api, Namespace, Resource\n"
        "from .base import AuthedResource\n"
        "from .auth import require_scope\n\n"
        "api = Api()\n"
        "ns = Namespace('reports')\n\n"
        "@ns.route('/reports')\n"
        "class Reports(AuthedResource):\n"
        "    @require_scope('read')\n"
        "    def get(self):\n"
        "        return []\n\n"
        "    @require_scope('write')\n"
        "    def post(self):\n"
        "        return {}\n\n"
        "    def delete(self):\n"
        "        return ''\n\n"
        "class Health(Resource):\n"
        "    def get(self):\n"
        "        return 'ok'\n\n"
        "api.add_resource(Health, '/health', '/healthz')\n",
    )
    result = _enum(tmp_path)
    get = _row(result, "GET", "/reports")
    assert get["guards"] == ["require_scope"]
    assert get["scope_guards"] == ["require_auth"]  # inherited method_decorators
    # every Reports method carries the inherited authn guard, but only two
    # of three carry the scope check — the odd one out must be judged
    delete = _row(result, "DELETE", "/reports")
    assert delete["scope_guards"] == ["require_auth"]
    assert delete["judgement_required"] is True
    assert delete["guard_family_gaps"] == ["scope"]
    fam = [a for a in result["asymmetries"] if a.get("guard_family") == "scope"]
    assert fam and fam[0]["unguarded"] == ["DELETE /reports"]
    # add_resource with two paths -> one row per path
    health = sorted(r["pattern"] for r in _flask(result) if r.get("view_class") == "Health")
    assert health == ["/health", "/healthz"]


def test_flask_restful_method_decorators_dict(tmp_path):
    _write(
        tmp_path,
        "svc/api.py",
        "from flask_restful import Api, Resource\n"
        "from .auth import admin_required\n\n"
        "api = Api()\n\n"
        "class Users(Resource):\n"
        "    method_decorators = {'post': [admin_required]}\n"
        "    def get(self):\n"
        "        return []\n"
        "    def post(self):\n"
        "        return {}\n\n"
        "api.add_resource(Users, '/users')\n",
    )
    result = _enum(tmp_path)
    assert _row(result, "POST", "/users")["scope_guards"] == ["admin_required"]
    assert _row(result, "GET", "/users")["scope_guards"] == []


def test_flask_public_marker_forces_judgement(tmp_path):
    _write(
        tmp_path,
        "svc/views.py",
        "from flask import Flask\n"
        "from .auth import public_endpoint, csrf\n\n"
        "app = Flask(__name__)\n\n"
        "@app.route('/hook', methods=['POST'])\n"
        "@public_endpoint\n"
        "@csrf.exempt\n"
        "def hook():\n"
        "    return ''\n",
    )
    row = _row(_enum(tmp_path), "POST", "/hook")
    assert row["unguard_markers"] == ["csrf.exempt", "public_endpoint"]
    assert row["guards"] == []
    assert row["judgement_required"] is True


def test_flask_add_url_rule_function_view(tmp_path):
    _write(
        tmp_path,
        "svc/views.py",
        "from flask import Flask\n"
        "from .auth import login_required\n\n"
        "app = Flask(__name__)\n\n"
        "@login_required\n"
        "def export():\n"
        "    return ''\n\n"
        "app.add_url_rule('/export', 'export', export, methods=['POST'])\n",
    )
    row = _row(_enum(tmp_path), "POST", "/export")
    assert row["guards"] == ["login_required"]
    assert row["handler"]["line"] == 7  # the def line, not the decorator


def test_flask_app_hook_scoped_to_its_app_and_registered_blueprints(tmp_path):
    _write(
        tmp_path,
        "svc/app.py",
        "from flask import Flask, abort, request\n"
        "from .views import bp\n\n"
        "app = Flask(__name__)\n\n"
        "def check_token():\n"
        "    if not request.headers.get('Authorization'):\n"
        "        abort(401)\n\n"
        "app.before_request(check_token)\n"
        "app.register_blueprint(bp)\n\n"
        "@app.route('/me')\n"
        "def me():\n"
        "    return {}\n",
    )
    _write(
        tmp_path,
        "svc/views.py",
        "from flask import Blueprint\n\n"
        "bp = Blueprint('v', __name__)\n\n"
        "@bp.route('/orders')\n"
        "def orders():\n"
        "    return []\n",
    )
    _write(
        tmp_path,
        "tools/other_app.py",
        "from flask import Flask\n\n"
        "app = Flask(__name__)\n\n"
        "@app.route('/debug')\n"
        "def debug():\n"
        "    return ''\n",
    )
    result = _enum(tmp_path)
    assert _row(result, "GET", "/me")["scope_guards"] == ["before_request:check_token"]
    assert _row(result, "GET", "/orders")["scope_guards"] == ["before_request:check_token"]
    # a second app in the same tree does not inherit the first app's hook
    debug = _row(result, "GET", "/debug")
    assert debug["scope_guards"] == []
    assert debug["judgement_required"] is True


def test_flask_computed_rules_and_lambda_views_are_kept(tmp_path):
    _write(tmp_path, "svc/paths.py", "EXPORT_PATH = '/api/export'\n")
    _write(
        tmp_path,
        "svc/app.py",
        "from flask import Flask\n"
        "from .paths import EXPORT_PATH\n\n"
        "app = Flask(__name__)\n\n"
        "def export(fmt):\n"
        "    return ''\n\n"
        "app.add_url_rule(rule=EXPORT_PATH, view_func=lambda: export('csv'), methods=['POST'])\n\n"
        "@app.route(prefixed('/health'))\n"
        "def health():\n"
        "    return 'ok'\n",
    )
    result = _enum(tmp_path)
    export = _row(result, "POST", "/api/export")
    assert export["handler"]["expr"] == "export"
    assert export["pattern_dynamic"] is False
    [health] = [r for r in _flask(result) if r["handler"]["expr"] == "health"]
    assert health["pattern"] == "prefixed('/health')"
    assert health["pattern_dynamic"] is True


def test_flask_rows_under_test_dirs_are_tagged(tmp_path):
    _write(
        tmp_path,
        "tests/fixtures/server.py",
        "from flask import Flask\n\napp = Flask(__name__)\n\n"
        "@app.route('/x')\n"
        "def x():\n"
        "    return ''\n",
    )
    [row] = _flask(_enum(tmp_path))
    assert row["test_path"] is True


def test_flask_not_a_coverage_gap_when_enumerated(flask_asym_repo):
    result = _enum(flask_asym_repo)
    assert not [g for g in result["coverage_gaps"] if g["system"] == "flask"]
    assert len(_flask(result)) == 3


def test_flask_unrecognized_registration_is_a_coverage_gap(tmp_path):
    _write(
        tmp_path,
        "svc/app.py",
        "from flask import Flask\n\napp = Flask(__name__)\nregister_everything(app)\n",
    )
    result = _enum(tmp_path)
    [gap] = [g for g in result["coverage_gaps"] if g["system"] == "flask"]
    assert "UNENUMERATED" in gap["reason"]
    assert gap["evidence"] == "svc/app.py"


def test_fastapi_verb_decorators_are_not_flask_rows(tmp_path):
    _write(
        tmp_path,
        "svc/main.py",
        "from fastapi import FastAPI\n\napp = FastAPI()\n\n"
        "@app.get('/things')\n"
        "def things():\n"
        "    return []\n",
    )
    result = _enum(tmp_path)
    assert _flask(result) == []
    assert [g["system"] for g in result["coverage_gaps"]] == ["fastapi"]


def test_fastapi_file_does_not_borrow_a_flask_receiver_name(tmp_path):
    # the tree has a flask `app`; a separate fastapi module also names its
    # (subclassed) application `app` — its verb decorators are not flask rows
    _write(
        tmp_path,
        "svc/web.py",
        "from flask import Flask\n\napp = Flask(__name__)\n\n"
        "@app.route('/ui')\n"
        "def ui():\n"
        "    return ''\n",
    )
    _write(
        tmp_path,
        "svc/gateway.py",
        "from fastapi import FastAPI\n\n"
        "class GatewayApp(FastAPI):\n"
        "    pass\n\n"
        "app = GatewayApp()\n\n"
        "@app.get('/v1/things')\n"
        "def things():\n"
        "    return []\n",
    )
    result = _enum(tmp_path)
    assert [r["pattern"] for r in _flask(result)] == ["/ui"]


# --------------------------------------------------------------------------
# coverage gaps + output contracts
# --------------------------------------------------------------------------


def test_express_detected_as_coverage_gap(tmp_path):
    (tmp_path / "app.js").write_text(
        "const express = require('express');\n"
        "const app = express();\n"
        "app.get('/things', handler);\n"
    )
    result = _enum(tmp_path)
    [gap] = [g for g in result["coverage_gaps"] if g["system"] == "express"]
    assert "UNENUMERATED" in gap["reason"]
    assert result["routes"] == []


def test_ordering_puts_judged_and_asymmetry_rows_first(go_asym_repo):
    result = _enum(go_asym_repo)
    assert len(result["routes"]) == 3
    assert sum(r["judgement_required"] for r in result["routes"]) == 1
    assert sum(r["asymmetry"] for r in result["routes"]) == 1
    assert result["routes"][0]["pattern"] == "/api/callback"


def test_enumerator_returns_one_matrix(go_asym_repo):
    at = datetime(2026, 10, 25, tzinfo=UTC)
    result = RouteGuardMatrix(FixedClock(at)).enumerate(ToolRequest(workspace=go_asym_repo))
    [matrix] = result.data
    assert isinstance(matrix, RouteGuardFact)
    assert len(matrix.routes) == 3
    assert result.acquisition.provider == "route-guards"
    assert result.acquisition.acquired_at == at


def test_empty_tree_is_an_empty_matrix(tmp_path):
    assert route_guards(tree_files(tmp_path)) == RouteGuardFact()


def test_missing_workspace_is_refused(tmp_path):
    with pytest.raises(ValidationError, match="not a directory"):
        RouteGuardMatrix(FixedClock(datetime(2026, 10, 25, tzinfo=UTC))).enumerate(
            ToolRequest(workspace=tmp_path / "absent")
        )


def test_symlinked_files_are_never_read(tmp_path):
    outside = tmp_path / "outside"
    outside.mkdir()
    (outside / "server.go").write_text('func r(m *M) { m.HandleFunc("/x", h) }\n')
    repo = tmp_path / "repo"
    repo.mkdir()
    (repo / "server.go").symlink_to(outside / "server.go")
    assert _enum(repo)["routes"] == []


def test_unparseable_python_is_skipped(tmp_path):
    (tmp_path / "views.py").write_text("from flask import Flask\ndef broken(:\n")
    assert _enum(tmp_path)["routes"] == []
