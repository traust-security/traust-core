"""The Django and DRF route matrix: include() chains and their prefixes, DRF routers and the
viewsets they register, each view's methods and guards, and what can't be placed."""

from __future__ import annotations

import json
from pathlib import Path
from textwrap import dedent

import pytest

from traust_core.v1.providers.route_guards import route_guards
from traust_core.v1.providers.tree import tree_files


def _write(root: Path, files: dict[str, str]) -> None:
    for rel, text in files.items():
        path = root / rel
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(text)


def _rows(root: Path) -> dict[tuple[str, str], dict]:
    result = route_guards(tree_files(root)).model_dump(mode="json")
    return {(r["method"], r["pattern"]): r for r in result["routes"]}


def test_include_chains_join_their_prefixes(tmp_path: Path) -> None:
    _write(
        tmp_path,
        {
            "site/settings.py": 'ROOT_URLCONF = "site.urls"\n',
            "site/urls.py": (
                "from django.urls import include, path, re_path\n"
                "urlpatterns = [\n"
                '    path("api/", include("notes.urls")),\n'
                '    re_path(r"^legacy/", include([re_path(r"^n/(?P<pk>\\d+)/$", views.note)])),\n'
                "]\n"
            ),
            "notes/urls.py": (
                "from django.urls import path\nfrom . import views\n"
                'urlpatterns = [path("notes/<int:pk>/", views.note)]\n'
            ),
            "notes/views.py": "def note(request, pk): ...\n",
        },
    )
    rows = _rows(tmp_path)
    assert set(rows) == {("any", "api/notes/<int:pk>/"), ("any", "^legacy/n/(?P<pk>\\d+)/$")}
    assert rows[("any", "api/notes/<int:pk>/")]["handler"]["path"] == "notes/views.py"


def test_a_namespaced_include_mounts_under_its_prefix(tmp_path: Path) -> None:
    """`include(("app.urls", "app"), namespace="x")`: the tuple's module resolves and mounts
    with its prefix. The namespace itself names reverse() lookups, not the URL pattern or the
    view, so the row's identity (method, pattern, handler) needs no extra field."""
    _write(
        tmp_path,
        {
            "site/settings.py": 'ROOT_URLCONF = "site.urls"\n',
            "site/urls.py": (
                "from django.urls import include, path\n"
                "urlpatterns = [\n"
                '    path("v1/", include(("notes.urls", "notes"), namespace="notes-v1")),\n'
                '    path("v2/", include("notes.urls", namespace="notes-v2")),\n'
                "]\n"
            ),
            "notes/urls.py": (
                'from django.urls import path\nfrom . import views\napp_name = "notes"\n'
                'urlpatterns = [path("notes/<int:pk>/", views.note, name="detail")]\n'
            ),
            "notes/views.py": "def note(request, pk): ...\n",
        },
    )
    rows = _rows(tmp_path)
    assert set(rows) == {("any", "v1/notes/<int:pk>/"), ("any", "v2/notes/<int:pk>/")}
    assert rows[("any", "v1/notes/<int:pk>/")]["handler"]["path"] == "notes/views.py"


def test_routers_record_their_own_trailing_slash_forms_distinctly(tmp_path: Path) -> None:
    """A DefaultRouter and a `trailing_slash=False` router keep their own URL forms —
    `/notes/` beside `/items` — each recorded as configured, never collapsed."""
    _write(
        tmp_path,
        {
            "site/settings.py": 'ROOT_URLCONF = "site.urls"\n',
            "site/urls.py": (
                "from django.urls import include, path\n"
                "from rest_framework.routers import DefaultRouter, SimpleRouter\n"
                "from notes.views import NoteViewSet\n"
                "default = DefaultRouter()\ndefault.register('notes', NoteViewSet)\n"
                "simple = SimpleRouter(trailing_slash=False)\n"
                "simple.register('items', NoteViewSet)\n"
                "urlpatterns = [\n"
                '    path("d/", include(default.urls)),\n'
                '    path("s/", include(simple.urls)),\n'
                "]\n"
            ),
            "notes/views.py": (
                "from rest_framework.viewsets import ModelViewSet\n"
                "class NoteViewSet(ModelViewSet): ...\n"
            ),
        },
    )
    rows = _rows(tmp_path)
    assert ("GET", "d/") in rows  # DefaultRouter's API root view
    assert ("GET", "d/notes/") in rows and ("GET", "d/notes/<pk>/") in rows
    assert ("GET", "s/items") in rows and ("GET", "s/items/<pk>") in rows
    assert ("GET", "s/") not in rows  # a SimpleRouter has no API root
    assert {pattern for _, pattern in rows if pattern.startswith("s/")} == {
        "s/items",
        "s/items/<pk>",
    }


def test_a_trailing_slash_class_attribute_or_instance_assignment_shapes_the_urls(
    tmp_path: Path,
) -> None:
    """DRF reads `trailing_slash` off the instance at route-generation time, so a subclass's
    class attribute or a later `router.trailing_slash = ...` changes the generated URLs the
    way the init kwarg does. The kwarg wins over the class attribute (the constructor sets
    the instance attribute), and the last instance assignment wins overall."""
    _write(
        tmp_path,
        {
            "site/settings.py": 'ROOT_URLCONF = "site.urls"\n',
            "site/urls.py": (
                "from django.urls import include, path\n"
                "from rest_framework.routers import DefaultRouter\n"
                "from notes.views import NoteViewSet\n"
                "class NoSlashRouter(DefaultRouter):\n"
                "    trailing_slash = False\n"
                "no_slash = NoSlashRouter()\nno_slash.register('a', NoteViewSet)\n"
                "kwarg = NoSlashRouter(trailing_slash=True)\nkwarg.register('b', NoteViewSet)\n"
                "assigned = DefaultRouter()\nassigned.trailing_slash = ''\n"
                "assigned.register('c', NoteViewSet)\n"
                "urlpatterns = [path('', include(no_slash.urls)),\n"
                "    path('', include(kwarg.urls)),\n"
                "    path('', include(assigned.urls))]\n"
            ),
            "notes/views.py": (
                "from rest_framework.viewsets import ModelViewSet\n"
                "class NoteViewSet(ModelViewSet): ...\n"
            ),
        },
    )
    rows = _rows(tmp_path)
    assert ("GET", "a") in rows and ("GET", "a/<pk>") in rows
    assert ("GET", "b/") in rows and ("GET", "b/<pk>/") in rows  # the kwarg wins
    assert ("GET", "c") in rows and ("GET", "c/<pk>") in rows
    assert ("GET", "a/") not in rows and ("GET", "b") not in rows and ("GET", "c/") not in rows


def test_a_trailing_slash_assignment_in_a_module_that_imports_the_router(tmp_path: Path) -> None:
    """`from .routers import router; router.trailing_slash = ""` in the urlconf that
    mounts it: the assignment rides a module other than the one binding the router,
    resolved through the import exactly as a register() call is."""
    _write(
        tmp_path,
        {
            "site/settings.py": 'ROOT_URLCONF = "site.urls"\n',
            "site/urls.py": (
                "from django.urls import include, path\n"
                "from .routers import router\n"
                "router.trailing_slash = ''\n"
                "urlpatterns = [path('api/', include(router.urls))]\n"
            ),
            "site/routers.py": (
                "from rest_framework.routers import DefaultRouter\n"
                "from notes.views import NoteViewSet\n"
                "router = DefaultRouter()\nrouter.register('notes', NoteViewSet)\n"
            ),
            "notes/views.py": (
                "from rest_framework.viewsets import ModelViewSet\n"
                "class NoteViewSet(ModelViewSet): ...\n"
            ),
        },
    )
    rows = _rows(tmp_path)
    assert ("GET", "api/notes") in rows and ("GET", "api/notes/<pk>") in rows
    assert ("GET", "api/notes/") not in rows and ("GET", "api/notes/<pk>/") not in rows


def test_an_annotated_trailing_slash_assignment_shapes_the_urls(tmp_path: Path) -> None:
    """`router.trailing_slash: bool = False` is an annotated assignment, not a plain one."""
    _write(
        tmp_path,
        {
            "site/settings.py": 'ROOT_URLCONF = "site.urls"\n',
            "site/urls.py": (
                "from django.urls import include, path\n"
                "from rest_framework.routers import DefaultRouter\n"
                "from notes.views import NoteViewSet\n"
                "router = DefaultRouter()\n"
                "router.trailing_slash: bool = False\n"
                "router.register('notes', NoteViewSet)\n"
                "urlpatterns = [path('api/', include(router.urls))]\n"
            ),
            "notes/views.py": (
                "from rest_framework.viewsets import ModelViewSet\n"
                "class NoteViewSet(ModelViewSet): ...\n"
            ),
        },
    )
    rows = _rows(tmp_path)
    assert ("GET", "api/notes") in rows and ("GET", "api/notes/") not in rows


def test_a_conditional_trailing_slash_assignment_leaves_the_rows_dynamic(tmp_path: Path) -> None:
    """`if DEBUG: router.trailing_slash = ''` may or may not run: the form reads unknown."""
    _write(
        tmp_path,
        {
            "site/settings.py": 'ROOT_URLCONF = "site.urls"\n',
            "site/urls.py": (
                "from django.urls import include, path\n"
                "from rest_framework.routers import DefaultRouter\n"
                "from notes.views import NoteViewSet\n"
                "router = DefaultRouter()\n"
                "if DEBUG:\n"
                "    router.trailing_slash = ''\n"
                "router.register('notes', NoteViewSet)\n"
                "urlpatterns = [path('api/', include(router.urls))]\n"
            ),
            "notes/views.py": (
                "from rest_framework.viewsets import ModelViewSet\n"
                "class NoteViewSet(ModelViewSet): ...\n"
            ),
        },
    )
    rows = _rows(tmp_path)
    slashless = [r for r in rows.values() if r["pattern"] in ("api/notes", "api/notes/")]
    assert slashless and all(r["pattern_dynamic"] for r in slashless)


def test_a_trailing_slash_assignment_after_the_include_changes_nothing(tmp_path: Path) -> None:
    """`router.urls` is evaluated where it is included: an assignment below the include
    cannot change the routes that were already built."""
    _write(
        tmp_path,
        {
            "site/settings.py": 'ROOT_URLCONF = "site.urls"\n',
            "site/urls.py": (
                "from django.urls import include, path\n"
                "from rest_framework.routers import DefaultRouter\n"
                "from notes.views import NoteViewSet\n"
                "router = DefaultRouter()\n"
                "router.register('notes', NoteViewSet)\n"
                "urlpatterns = [path('api/', include(router.urls))]\n"
                "router.trailing_slash = ''\n"
            ),
            "notes/views.py": (
                "from rest_framework.viewsets import ModelViewSet\n"
                "class NoteViewSet(ModelViewSet): ...\n"
            ),
        },
    )
    rows = _rows(tmp_path)
    assert ("GET", "api/notes/") in rows and ("GET", "api/notes") not in rows


def test_disagreeing_trailing_slash_assignments_leave_the_rows_dynamic(tmp_path: Path) -> None:
    """Two assignments to one router's trailing_slash, in different modules: their
    order is import order, which the walk cannot see — the form reads unknown."""
    _write(
        tmp_path,
        {
            "site/settings.py": 'ROOT_URLCONF = "site.urls"\n',
            "site/urls.py": (
                "from django.urls import include, path\n"
                "from .routers import router\n"
                "router.trailing_slash = ''\n"
                "urlpatterns = [path('api/', include(router.urls))]\n"
            ),
            "site/routers.py": (
                "from rest_framework.routers import DefaultRouter\n"
                "from notes.views import NoteViewSet\n"
                "router = DefaultRouter()\nrouter.trailing_slash = '/'\n"
                "router.register('notes', NoteViewSet)\n"
            ),
            "notes/views.py": (
                "from rest_framework.viewsets import ModelViewSet\n"
                "class NoteViewSet(ModelViewSet): ...\n"
            ),
        },
    )
    rows = _rows(tmp_path)
    slashless = [r for r in rows.values() if r["pattern"] in ("api/notes", "api/notes/")]
    assert slashless and all(r["pattern_dynamic"] for r in slashless)


def test_a_computed_root_urlconf_scopes_the_settings_nowhere(tmp_path: Path) -> None:
    """`ROOT_URLCONF = os.environ.get(..)` is set but not literal: which urlconf it
    names is unknown, so the settings' guards scope nowhere — the beside-the-settings
    fallback must not apply one project's middleware to the urlconfs beside it."""
    _write(
        tmp_path,
        {
            "a/settings.py": (
                "import os\n"
                'ROOT_URLCONF = os.environ.get("URLCONF", "a.urls")\n'
                "MIDDLEWARE = ['django.contrib.auth.middleware.LoginRequiredMiddleware']\n"
            ),
            "a/urls.py": (
                "from django.urls import path\nfrom . import views\n"
                'urlpatterns = [path("a-note/", views.a_note)]\n'
            ),
            "a/views.py": "def a_note(request): ...\n",
        },
    )
    rows = _rows(tmp_path)
    assert set(rows) == {("any", "a-note/")}
    assert rows[("any", "a-note/")]["scope_guards"] == []
    assert rows[("any", "a-note/")]["judgement_required"]


def test_a_settings_module_guards_only_its_own_projects_routes(tmp_path: Path) -> None:
    """Two projects in one checkout: one's LoginRequiredMiddleware and DRF defaults scope to
    the urlconfs its ROOT_URLCONF reaches, never to the other project's routes."""
    _write(
        tmp_path,
        {
            "a/settings.py": (
                'ROOT_URLCONF = "a.urls"\n'
                "MIDDLEWARE = ['django.contrib.auth.middleware.LoginRequiredMiddleware']\n"
                "REST_FRAMEWORK = {'DEFAULT_PERMISSION_CLASSES': "
                "['rest_framework.permissions.IsAuthenticated']}\n"
            ),
            "a/urls.py": (
                "from django.urls import include, path\n"
                'urlpatterns = [path("", include("a.app.urls"))]\n'
            ),
            "a/app/urls.py": (
                "from django.urls import path\nfrom . import views\n"
                'urlpatterns = [path("a-note/", views.a_note)]\n'
            ),
            "a/app/views.py": "def a_note(request): ...\n",
            "b/settings.py": 'ROOT_URLCONF = "b.urls"\n',
            "b/urls.py": (
                "from django.urls import path\nfrom . import views\n"
                'urlpatterns = [path("b-note/", views.b_note)]\n'
            ),
            "b/views.py": "def b_note(request): ...\n",
        },
    )
    rows = _rows(tmp_path)
    assert rows[("any", "a-note/")]["scope_guards"] == ["LoginRequiredMiddleware"]
    assert rows[("any", "b-note/")]["scope_guards"] == []
    assert rows[("any", "b-note/")]["guards"] == []


def test_a_class_view_has_a_row_per_method_it_defines(tmp_path: Path) -> None:
    _write(
        tmp_path,
        {
            "app/urls.py": (
                "from django.urls import path\nfrom .views import NoteView, NoteList\n"
                "urlpatterns = [\n"
                '    path("notes/<int:pk>/", NoteView.as_view()),\n'
                '    path("notes/", NoteList.as_view()),\n'
                "]\n"
            ),
            "app/views.py": (
                "from django.contrib.auth.mixins import LoginRequiredMixin\n"
                "from django.views import View\n"
                "from rest_framework.generics import ListCreateAPIView\n"
                "class NoteView(LoginRequiredMixin, View):\n"
                "    def get(self, request, pk): ...\n"
                "    def delete(self, request, pk): ...\n"
                "class NoteList(ListCreateAPIView):\n"
                "    permission_classes = [IsAuthenticated]\n"
            ),
        },
    )
    rows = _rows(tmp_path)
    assert set(rows) == {
        ("GET", "notes/<int:pk>/"),
        ("DELETE", "notes/<int:pk>/"),
        ("GET", "notes/"),
        ("POST", "notes/"),
    }
    assert rows[("DELETE", "notes/<int:pk>/")]["guards"] == ["LoginRequiredMixin"]
    assert rows[("DELETE", "notes/<int:pk>/")]["handler"]["line"] == 6
    assert rows[("POST", "notes/")]["guards"] == ["IsAuthenticated"]


def test_a_router_expands_to_list_detail_and_action_routes(tmp_path: Path) -> None:
    _write(
        tmp_path,
        {
            "app/settings.py": (
                "REST_FRAMEWORK = {'DEFAULT_PERMISSION_CLASSES': "
                "['rest_framework.permissions.IsAuthenticated']}\n"
            ),
            "app/urls.py": (
                "from django.urls import include, path\n"
                "from rest_framework.routers import DefaultRouter\n"
                "from .views import NoteViewSet\n"
                "router = DefaultRouter()\n"
                'router.register(r"notes", NoteViewSet)\n'
                'urlpatterns = [path("api/", include(router.urls))]\n'
            ),
            "app/views.py": (
                "from rest_framework import viewsets\n"
                "from rest_framework.decorators import action\n"
                "class NoteViewSet(viewsets.ReadOnlyModelViewSet):\n"
                '    lookup_field = "slug"\n'
                '    @action(detail=True, methods=["post"], permission_classes=[AllowAny])\n'
                "    def share(self, request, slug=None): ...\n"
                "    @action(detail=False)\n"
                "    def recent(self, request): ...\n"
            ),
        },
    )
    rows = _rows(tmp_path)
    assert set(rows) == {
        ("GET", "api/"),  # DefaultRouter's API root view
        ("GET", "api/notes/"),
        ("GET", "api/notes/<slug>/"),
        ("POST", "api/notes/<slug>/share/"),
        ("GET", "api/notes/recent/"),
    }
    # DRF's default permissions guard a viewset that names none
    assert rows[("GET", "api/notes/<slug>/")]["scope_guards"] == [
        "rest_framework.permissions.IsAuthenticated"
    ]
    # an action's own permission_classes replace the viewset's
    share = rows[("POST", "api/notes/<slug>/share/")]
    assert share["unguard_markers"] == ["AllowAny"] and share["scope_guards"] == []
    assert share["judgement_required"]


def test_drf_defaults_guard_only_drf_views(tmp_path: Path) -> None:
    _write(
        tmp_path,
        {
            "app/settings.py": (
                "REST_FRAMEWORK = {'DEFAULT_PERMISSION_CLASSES': ['IsAuthenticated']}\n"
            ),
            "app/urls.py": (
                "from django.urls import path\nfrom . import views\n"
                'urlpatterns = [path("page/", views.page), path("api/", views.api)]\n'
            ),
            "app/views.py": (
                "from rest_framework.decorators import api_view\n"
                "def page(request): ...\n"
                '@api_view(["GET"])\n'
                "def api(request): ...\n"
            ),
        },
    )
    rows = _rows(tmp_path)
    assert rows[("any", "page/")]["scope_guards"] == []
    assert rows[("any", "page/")]["judgement_required"]
    assert rows[("GET", "api/")]["scope_guards"] == ["IsAuthenticated"]


def test_csrf_method_and_lookalike_decorators_are_not_guards(tmp_path: Path) -> None:
    _write(
        tmp_path,
        {
            "app/urls.py": (
                "from django.urls import path\nfrom . import views\n"
                'urlpatterns = [path("hook/", views.hook), path("me/", views.me)]\n'
            ),
            "app/views.py": (
                "from django.views.decorators.csrf import csrf_exempt\n"
                "from django.views.decorators.http import require_POST\n"
                "@csrf_exempt\n"
                "@require_POST\n"
                '@require_setting("SLACK_TOKEN")\n'
                "def hook(request): ...\n"
                "@login_required\n"
                "def me(request): ...\n"
            ),
        },
    )
    rows = _rows(tmp_path)
    # a name that only looks like a guard (`require_setting`) is none (D36)
    assert rows[("POST", "hook/")]["guards"] == [] and rows[("POST", "hook/")]["judgement_required"]
    assert rows[("any", "me/")]["guards"] == ["login_required"]


def test_what_the_walk_cant_place_is_listed_not_dropped(tmp_path: Path) -> None:
    _write(
        tmp_path,
        {
            "site/urls.py": (
                "from functools import reduce\nfrom operator import add\n"
                "from django.conf import settings\n"
                "from django.urls import include, path\n"
                "from django.contrib import admin\n"
                "from .utils import opt_slash_path\n"
                "from . import views\n"
                "prefix = settings.BASE\n"
                'core = [path("accounts/", include("allauth.urls")),\n'
                '        path("admin/", admin.site.urls)]\n'
                "groups = [core]\n"
                "if settings.DEBUG:\n"
                '    groups.append([opt_slash_path("_debug", views.debug)])\n'
                "urlpatterns = reduce(add, groups)\n"
                'urlpatterns += [path(f"{prefix}status/", views.status)]\n'
            ),
            "site/utils.py": (
                "from django.urls import re_path\n"
                "def opt_slash_path(route, view):\n"
                '    return re_path(rf"^{route}/?$", view)\n'
            ),
            "site/views.py": "def debug(request): ...\ndef status(request): ...\n",
            "site/plugins.py": (
                "from django.urls import path\n"
                "def plugin_urls():\n"
                '    return [path("plugin/", plugin_view)]\n'
            ),
        },
    )
    rows = _rows(tmp_path)
    assert set(rows) == {
        ("any", "accounts/"),  # a library's urlconf
        ("any", "admin/"),
        ("any", "_debug"),  # through the checkout's own path() helper, conditionally added
        ("any", "[prefix]status/"),
        ("any", "plugin/"),  # built by a function: its mount is unknown
    }
    assert rows[("any", "[prefix]status/")]["pattern_dynamic"]
    assert rows[("any", "plugin/")]["pattern_dynamic"]
    assert not rows[("any", "_debug")]["pattern_dynamic"]
    assert rows[("any", "admin/")]["judgement_required"]


def test_a_decorator_applied_in_the_urlconf_guards_its_view(tmp_path: Path) -> None:
    _write(
        tmp_path,
        {
            "app/urls.py": (
                "from django.contrib.auth.decorators import login_required\n"
                "from django.views.decorators.cache import cache_page\n"
                "from django.urls import path\nfrom . import views\n"
                "urlpatterns = [\n"
                '    path("a/<int:pk>/", login_required(views.Note.as_view())),\n'
                '    path("b/", cache_page(60)(login_required(views.page))),\n'
                '    path("c/", login_required(library.view)),\n'
                "]\n"
            ),
            "app/views.py": (
                "from django.views import View\n"
                "class Note(View):\n    def get(self, request, pk): ...\n"
                "def page(request): ...\n"
            ),
        },
    )
    rows = _rows(tmp_path)
    assert rows[("GET", "a/<int:pk>/")]["guards"] == ["login_required"]
    assert rows[("any", "b/")]["guards"] == ["login_required"]
    assert rows[("any", "c/")]["guards"] == ["login_required"]


def test_a_method_decorator_naming_one_method_guards_only_it(tmp_path: Path) -> None:
    _write(
        tmp_path,
        {
            "app/urls.py": (
                "from django.urls import path\nfrom .views import Notes\n"
                'urlpatterns = [path("notes/<int:pk>/", Notes.as_view())]\n'
            ),
            "app/views.py": (
                "from django.contrib.auth.decorators import login_required\n"
                "from django.utils.decorators import method_decorator\n"
                "from rest_framework.views import APIView\n"
                '@method_decorator(login_required, name="post")\n'
                "class Notes(APIView):\n"
                "    authentication_classes = [SessionAuthentication]\n"
                "    def get(self, request, pk): ...\n"
                "    def post(self, request, pk): ...\n"
            ),
        },
    )
    rows = _rows(tmp_path)
    assert rows[("POST", "notes/<int:pk>/")]["guards"] == ["login_required"]
    # authentication_classes reads a caller but refuses no one
    assert rows[("GET", "notes/<int:pk>/")]["guards"] == []
    assert rows[("GET", "notes/<int:pk>/")]["judgement_required"]


def test_viewset_mappings_and_nested_routers(tmp_path: Path) -> None:
    _write(
        tmp_path,
        {
            "app/urls.py": (
                "from django.urls import include, path\n"
                "from rest_framework_nested.routers import NestedSimpleRouter, SimpleRouter\n"
                "from .views import CommentViewSet, NoteViewSet\n"
                "router = SimpleRouter()\n"
                'router.register(r"notes", NoteViewSet)\n'
                'comments = NestedSimpleRouter(router, r"notes", lookup="note")\n'
                'comments.register(r"comments", CommentViewSet)\n'
                "urlpatterns = [\n"
                '    path("", include(router.urls)),\n'
                '    path("", include(comments.urls)),\n'
                '    path("mine/<int:pk>/", NoteViewSet.as_view({"get": "retrieve"})),\n'
                "]\n"
            ),
            "app/views.py": (
                "from rest_framework import mixins, viewsets\n"
                "class NoteViewSet(mixins.RetrieveModelMixin, viewsets.GenericViewSet):\n"
                "    permission_classes = [IsAuthenticated]\n"
                "class CommentViewSet(viewsets.ViewSet):\n"
                "    def list(self, request, note_pk=None): ...\n"
                "    def destroy(self, request, note_pk=None, pk=None): ...\n"
            ),
        },
    )
    rows = _rows(tmp_path)
    assert set(rows) == {
        ("GET", "notes/<pk>/"),
        ("GET", "notes/<note_pk>/comments/"),
        ("DELETE", "notes/<note_pk>/comments/<pk>/"),
        ("GET", "mine/<int:pk>/"),
    }
    assert rows[("GET", "mine/<int:pk>/")]["guards"] == ["IsAuthenticated"]
    assert rows[("DELETE", "notes/<note_pk>/comments/<pk>/")]["guards"] == []


def test_permissions_are_read_per_method_and_in_method_resolution_order(tmp_path: Path) -> None:
    _write(
        tmp_path,
        {
            "app/urls.py": (
                "from django.urls import path\nfrom . import views\n"
                "urlpatterns = [\n"
                '    path("a/", views.A.as_view()),\n'
                '    path("b/", views.B.as_view()),\n'
                '    path("c/", views.C.as_view()),\n'
                '    path("d/", views.D.as_view(permission_classes=[AllowAny])),\n'
                '    path("e/", views.E.as_view()),\n'
                "]\n"
            ),
            "app/views.py": (
                "from django.contrib.auth.mixins import LoginRequiredMixin\n"
                "from django.views import View\n"
                "from rest_framework.views import APIView\n"
                "class A(APIView):\n"
                "    permission_classes = [IsAuthenticatedOrReadOnly]\n"
                "    def get(self, request): ...\n"
                "    def post(self, request): ...\n"
                "class B(APIView):\n"
                "    permission_classes = [IsAuthenticated | ReadOnly]\n"
                "    def get(self, request): ...\n"
                "class C(View, LoginRequiredMixin):\n"  # View.dispatch runs first
                "    def get(self, request): ...\n"
                "class D(APIView):\n"
                "    permission_classes = [IsAuthenticated]\n"
                "    def get(self, request): ...\n"
                "class E(APIView):\n"
                "    permission_classes = [IsAuthenticated]\n"
                "    def get_permissions(self): ...\n"
                "    def get(self, request): ...\n"
            ),
        },
    )
    rows = _rows(tmp_path)
    assert rows[("GET", "a/")]["unguard_markers"] == ["IsAuthenticatedOrReadOnly"]
    assert rows[("POST", "a/")]["guards"] == ["IsAuthenticatedOrReadOnly"]
    assert rows[("GET", "b/")]["judgement_required"]
    assert rows[("GET", "c/")]["guards"] == [] and rows[("GET", "c/")]["judgement_required"]
    assert rows[("GET", "d/")]["unguard_markers"] == ["AllowAny"]  # as_view initkwargs
    assert rows[("GET", "e/")]["unguard_markers"] == ["get_permissions"]


def test_drf_policy_decorators_count_only_below_api_view(tmp_path: Path) -> None:
    _write(
        tmp_path,
        {
            "app/urls.py": (
                "from django.urls import path\nfrom . import views\n"
                'urlpatterns = [path("a/", views.a), path("b/", views.b), path("c/", views.c)]\n'
            ),
            "app/views.py": (
                "from rest_framework.decorators import api_view, permission_classes\n"
                "@permission_classes([IsAuthenticated])\n"
                '@api_view(["GET"])\n'
                "def a(request): ...\n"
                '@api_view(["GET"])\n'
                "@permission_classes([IsAuthenticated])\n"
                "def b(request): ...\n"
                '@api_view(["POST"])\n'
                "@permission_classes([])\n"
                "@extend_schema(request=LoginSerializer)\n"
                "def c(request): ...\n"
            ),
        },
    )
    rows = _rows(tmp_path)
    assert rows[("GET", "a/")]["guards"] == [] and rows[("GET", "a/")]["judgement_required"]
    assert rows[("GET", "b/")]["guards"] == ["IsAuthenticated"]
    assert rows[("POST", "c/")]["guards"] == [] and rows[("POST", "c/")]["judgement_required"]


def test_settings_are_code_and_guard_only_their_own_project(tmp_path: Path) -> None:
    _write(
        tmp_path,
        {
            "accounts/settings.py": (
                'ROOT_URLCONF = "accounts.urls"\n'
                "MIDDLEWARE = ['django.contrib.auth.middleware.LoginRequiredMiddleware']\n"
            ),
            "accounts/urls.py": (
                "from django.urls import path\nfrom . import views\n"
                'urlpatterns = [path("me/", views.me), path("health/", views.health)]\n'
            ),
            "accounts/views.py": (
                "from django.contrib.auth.decorators import login_not_required\n"
                "def me(request): ...\n"
                "@login_not_required\n"
                "def health(request): ...\n"
            ),
            "billing/settings.py": (
                'ROOT_URLCONF = "billing.urls"\n'
                "# MIDDLEWARE = ['django.contrib.auth.middleware.LoginRequiredMiddleware']\n"
                "MIDDLEWARE = []\n"
            ),
            "billing/urls.py": (
                "from django.urls import path\nfrom . import views\n"
                'urlpatterns = [path("invoices/", views.invoices)]\n'
            ),
            "billing/views.py": "def invoices(request): ...\n",
        },
    )
    rows = _rows(tmp_path)
    assert rows[("any", "me/")]["scope_guards"] == ["LoginRequiredMiddleware"]
    assert rows[("any", "health/")]["unguard_markers"] == ["login_not_required"]
    assert rows[("any", "invoices/")]["scope_guards"] == []


# Invented apps from independent blind reviews of the Django and Flask matrix: routes once
# missing, guards once shown that don't protect, prefixes once wrong; each with the rows it
# lists now (family, method, pattern, guards, judged, pattern computed).
_REVIEW = Path(__file__).parents[2] / "fixtures/code_facts/django_flask_matrix_review.json"
_CASES = json.loads(_REVIEW.read_text())


@pytest.mark.parametrize("case", _CASES, ids=[c["case"] for c in _CASES])
def test_matrix_holes_a_review_found_stay_closed(tmp_path: Path, case: dict) -> None:
    for rel, text in case["files"].items():
        path = tmp_path / rel
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(dedent(text))
    rows = sorted(
        [
            r["family"],
            r["method"],
            r["pattern"],
            sorted({*r["guards"], *r["scope_guards"]}),
            r["judgement_required"],
            r["pattern_dynamic"],
        ]
        for r in route_guards(tree_files(tmp_path)).model_dump(mode="json")["routes"]
        if r["family"] in ("django-drf", "flask")
    )
    assert rows == case["rows"]


_DRF_DEFAULT = (
    "ROOT_URLCONF = 'app.urls'\n"
    "REST_FRAMEWORK = {'DEFAULT_PERMISSION_CLASSES': "
    "['rest_framework.permissions.IsAuthenticated']}\n"
)
_LOGIN_MIDDLEWARE = (
    "ROOT_URLCONF = 'app.urls'\n"
    "MIDDLEWARE = ['django.contrib.auth.middleware.LoginRequiredMiddleware']\n"
)


def _urls(*routes: str, imports: str = "from . import views") -> str:
    return f"from django.urls import path\n{imports}\nurlpatterns = [{', '.join(routes)}]\n"


# per app, the guards each row shows: none where a binding, an order or a library is unread (D38)
_PROTECTION = {
    "drf_package_named_like_rest_framework_sets_its_own": (
        {
            "app/settings.py": _DRF_DEFAULT,
            "app/urls.py": _urls("path('t/', views.T.as_view())"),
            "app/views.py": """\
                from rest_framework_simplejwt.views import TokenObtainPairView
                class T(TokenObtainPairView):
                    pass
            """,
        },
        {("any", "t/"): []},
    ),
    "drf_view_with_its_own_permissions": (
        {
            "app/settings.py": _DRF_DEFAULT,
            "app/urls.py": _urls("path('t/', views.T.as_view())"),
            "app/views.py": """\
                from rest_framework.authtoken.views import ObtainAuthToken
                class T(ObtainAuthToken):
                    pass
            """,
        },
        {("any", "t/"): []},
    ),
    "drf_permission_method_later_in_the_order": (
        {
            "app/urls.py": _urls("path('a/', views.A.as_view())"),
            "app/views.py": """\
                from rest_framework.views import APIView
                from rest_framework.permissions import IsAuthenticated
                class Open:
                    def get_permissions(self):
                        return []
                class A(Open, APIView):
                    permission_classes = [IsAuthenticated]
                    def get(self, request): ...
            """,
        },
        {("GET", "a/"): []},
    ),
    "drf_permission_classes_set_outside_the_class_body": (
        {
            "app/urls.py": _urls(*(f"path('{c}/', views.{c.upper()}.as_view())" for c in "acd")),
            "app/views.py": """\
                from rest_framework.views import APIView
                from rest_framework.permissions import AllowAny, IsAuthenticated
                def public(cls):
                    cls.permission_classes = [AllowAny]
                    return cls
                class A(APIView):
                    permission_classes = [IsAuthenticated]
                    def get(self, request): ...
                A.permission_classes = [AllowAny]
                class C(APIView):
                    permission_classes = [IsAuthenticated]
                    def setup(self, request, *args, **kwargs):
                        self.permission_classes = [AllowAny]
                    def get(self, request): ...
                @public
                class D(APIView):
                    permission_classes = [IsAuthenticated]
                    def get(self, request): ...
            """,
        },
        {("GET", "a/"): [], ("GET", "c/"): [], ("GET", "d/"): []},
    ),
    "dj_guard_name_bound_by_checkout_code": (
        {
            "app/urls.py": _urls(*(f"path('{v}/', views.{v})" for v in "abcd")),
            "app/sso.py": (
                "class SSO:\n    def login_required(self, view):\n        return view\n"
                "sso = SSO()\n"
            ),
            "app/auth.py": (
                "from django.contrib.auth.decorators import user_passes_test\n"
                "login_required = user_passes_test(lambda u: True)\n"
            ),
            "app/views.py": """\
                from django.conf import settings
                from django.contrib.auth.decorators import login_required
                from .sso import sso
                from . import auth
                if settings.DEBUG:
                    def login_required(view):
                        return view
                staff_member_required = lambda v: v
                @login_required
                def a(request): ...
                @staff_member_required
                def b(request): ...
                @auth.login_required
                def c(request): ...
                @sso.login_required
                def d(request): ...
            """,
        },
        {("any", "a/"): [], ("any", "b/"): [], ("any", "c/"): [], ("any", "d/"): []},
    ),
    "dj_guard_in_a_module_python_cant_parse": (
        {
            "app/urls.py": _urls("path('a/', views.a)"),
            "app/auth.py": "def login_required(view):\n    print 'todo'\n    return view\n",
            "app/views.py": (
                "from .auth import login_required\n@login_required\ndef a(request): ...\n"
            ),
        },
        {("any", "a/"): []},
    ),
    "dj_star_import_order_decides_the_binding": (
        {
            "app/urls.py": _urls(
                "path('a/', views.a)",
                "path('b/', views2.b)",
                "path('c/', pages.page)",
                imports="from . import views, views2, pages",
            ),
            "app/auth.py": "def login_required(view):\n    return view\n",
            "app/views.py": """\
                from django.contrib.auth.decorators import login_required
                from .auth import *
                @login_required
                def a(request): ...
            """,
            "app/views2.py": """\
                from .auth import *
                from django.contrib.auth.decorators import login_required
                @login_required
                def b(request): ...
            """,
            "app/pages/__init__.py": "from .secure import *\nfrom .legacy import *\n",
            "app/pages/secure.py": (
                "from django.contrib.auth.decorators import login_required\n"
                "@login_required\ndef page(request): ...\n"
            ),
            "app/pages/legacy.py": "def page(request): ...\n",
        },
        {("any", "a/"): [], ("any", "b/"): ["login_required"], ("any", "c/"): []},
    ),
    "dj_library_view_method_ahead_of_a_guarded_mixin": (
        {
            "app/urls.py": _urls("path('a/', views.A.as_view())", "path('b/', views.B.as_view())"),
            "app/views.py": """\
                from django.contrib.auth.decorators import login_required
                from django.utils.decorators import method_decorator
                from django.views.generic import TemplateView
                class Secure:
                    @method_decorator(login_required)
                    def get(self, request): ...
                class A(TemplateView, Secure):
                    pass
                class B(Secure, TemplateView):
                    pass
            """,
        },
        {("GET", "a/"): [], ("GET", "b/"): ["login_required"]},
    ),
    "dj_settings_changed_in_place_deleted_or_star_imported_under_try": (
        {
            "app/settings.py": (
                "ROOT_URLCONF = 'app.urls'\n"
                "REST_FRAMEWORK = {'DEFAULT_PERMISSION_CLASSES': ['IsAuthenticated']}\n"
                "REST_FRAMEWORK |= {'DEFAULT_PERMISSION_CLASSES': ['AllowAny']}\n"
            ),
            "app/urls.py": _urls("path('a/', views.A.as_view())"),
            "app/views.py": (
                "from rest_framework.views import APIView\n"
                "class A(APIView):\n    def get(self, request): ...\n"
            ),
            "b/settings.py": (
                "ROOT_URLCONF = 'b.urls'\n"
                "MIDDLEWARE = ['django.contrib.auth.middleware.LoginRequiredMiddleware']\n"
                "del MIDDLEWARE[-1]\n"
            ),
            "b/urls.py": _urls("path('b/', views.me)"),
            "b/views.py": "def me(request): ...\n",
            "c/settings/__init__.py": (
                "ROOT_URLCONF = 'c.urls'\n"
                "MIDDLEWARE = ['django.contrib.auth.middleware.LoginRequiredMiddleware']\n"
                "try:\n    from .local import *\nexcept ImportError:\n    pass\n"
            ),
            "c/settings/local.py": "MIDDLEWARE = []\n",
            "c/urls.py": _urls("path('c/', views.me)"),
            "c/views.py": "def me(request): ...\n",
            "d/settings/base.py": _LOGIN_MIDDLEWARE.replace("app.urls", "d.urls"),
            "d/settings/open.py": "MIDDLEWARE = []\n",
            "d/settings/production.py": "from .base import *\nfrom .open import *\n",
            "d/urls.py": _urls("path('d/', views.me)"),
            "d/views.py": "def me(request): ...\n",
        },
        {("GET", "a/"): [], ("any", "b/"): [], ("any", "c/"): [], ("any", "d/"): []},
    ),
    "dj_dispatch_answering_before_the_mixins": (
        {
            "app/urls.py": _urls("path('a/', views.A.as_view())", "path('b/', views.B.as_view())"),
            "app/views.py": """\
                from django.contrib.auth.mixins import LoginRequiredMixin
                from django.views import View
                class Preview:
                    def dispatch(self, request, *args, **kwargs):
                        if request.GET.get('preview'):
                            return self.get(request)
                        return super().dispatch(request, *args, **kwargs)
                class Fast:
                    async def dispatch(self, request, *args, **kwargs):
                        return await self.get(request)
                class A(Preview, LoginRequiredMixin, View):
                    def get(self, request): ...
                class B(Fast, LoginRequiredMixin, View):
                    async def get(self, request): ...
            """,
        },
        {("GET", "a/"): [], ("GET", "b/"): []},
    ),
    "dj_middleware_exemptions_by_attribute_or_alias": (
        {
            "app/settings.py": _LOGIN_MIDDLEWARE,
            "app/urls.py": _urls(
                "path('h/', views.h)", "path('h2/', views.h2)", "path('me/', views.me)"
            ),
            "app/views.py": """\
                from django.contrib.auth.decorators import login_not_required as public_view
                def h(request): ...
                h.login_required = False
                @public_view
                def h2(request): ...
                def me(request): ...
            """,
        },
        {("any", "h/"): [], ("any", "h2/"): [], ("any", "me/"): ["LoginRequiredMiddleware"]},
    ),
    "drf_permissions_a_cache_or_decorator_puts_out_of_reach": (
        {
            "app/urls.py": _urls(
                "path('s/', cache_page(60)(views.S.as_view()))",
                "path('s2/', views.S.as_view())",
                "path('a/', views.a)",
                "path('b/', views.b)",
                imports="from django.views.decorators.cache import cache_page\nfrom . import views",
            ),
            "app/views.py": """\
                from rest_framework.decorators import api_view, permission_classes
                from rest_framework.permissions import IsAuthenticated
                from rest_framework.views import APIView
                def timed(f):
                    def inner(*a, **k):
                        return f(*a, **k)
                    return inner
                class S(APIView):
                    permission_classes = [IsAuthenticated]
                    def get(self, request): ...
                @api_view(['GET'])
                @timed
                @permission_classes([IsAuthenticated])
                def a(request): ...
                @api_view(['GET'])
                @permission_classes([IsAuthenticated])
                @timed
                def b(request): ...
            """,
        },
        {
            ("GET", "s/"): [],
            ("GET", "s2/"): ["IsAuthenticated"],
            ("GET", "a/"): [],
            ("GET", "b/"): ["IsAuthenticated"],
        },
    ),
    "dj_permission_requirement_asking_for_nothing": (
        {
            "app/urls.py": _urls(
                "path('a/', views.a)", "path('b/', views.B.as_view())", "path('c/', views.c)"
            ),
            "app/views.py": """\
                from django.contrib.auth.decorators import permission_required
                from django.contrib.auth.mixins import PermissionRequiredMixin
                from django.views import View
                @permission_required([])
                def a(request): ...
                class B(PermissionRequiredMixin, View):
                    permission_required = ()
                    def get(self, request): ...
                @permission_required('notes.view_note')
                def c(request): ...
            """,
        },
        {("any", "a/"): [], ("GET", "b/"): [], ("any", "c/"): ["permission_required"]},
    ),
    "fl_guard_name_bound_by_checkout_code": (
        {
            "app/auth.py": "login_required = lambda f: f\n",
            "app/legacy.py": "def fresh_login_required(f):\n    print 'todo'\n",
            "app/one.py": "def jwt_required(f):\n    return f\n",
            "app/two.py": "def jwt_required(f):\n    return f\n",
            "app/views.py": """\
                from flask import Flask
                from app.auth import login_required
                from app.legacy import fresh_login_required
                from flask_jwt_extended import jwt_required
                from app.one import *
                app = Flask(__name__)
                @app.route('/a')
                @login_required
                def a(): ...
                @app.route('/b')
                @fresh_login_required
                def b(): ...
                @app.route('/c')
                @jwt_required
                def c(): ...
                @login_required
                def d(): ...
                def d(): ...
                app.add_url_rule('/d', view_func=d)
            """,
        },
        {("GET", "/a"): [], ("GET", "/b"): [], ("GET", "/c"): [], ("GET", "/d"): []},
    ),
    "fl_class_decorators_read_in_method_order": (
        {
            "app.py": """\
                from flask import Flask
                from flask.views import MethodView
                from flask_login import login_required
                app = Flask(__name__)
                class Base(MethodView):
                    decorators = [login_required]
                    @login_required
                    def get(self): ...
                class A(Base):
                    pass
                class B(Base):
                    decorators = []
                    def get(self): ...
                class V(A, B):
                    pass
                class Items(MethodView):
                    decorators = [login_required]
                    def get(self): ...
                Items.decorators = []
                app.add_url_rule('/v', view_func=V.as_view('v'))
                app.add_url_rule('/items', view_func=Items.as_view('items'))
            """,
        },
        {("GET", "/v"): [], ("GET", "/items"): []},
    ),
    "fl_decorators_that_let_anyone_through": (
        {
            "app.py": """\
                from flask import Flask
                from flask.views import MethodView
                from flask_restful import Api, Resource
                from flask_jwt_extended import jwt_required
                from flask_login import login_required
                app = Flask(__name__)
                api = Api(app)
                class Feed(MethodView):
                    decorators = [jwt_required(optional=True)]
                    def get(self): ...
                class Items(Resource):
                    method_decorators = {'get': [jwt_required(optional=True)]}
                    def get(self): ...
                class BaseResource(MethodView):
                    method_decorators = [login_required]
                class Docs(BaseResource):
                    def get(self): ...
                def wall(): ...
                app.add_url_rule('/feed', view_func=Feed.as_view('feed'))
                api.add_resource(Items, '/items')
                app.add_url_rule('/docs', view_func=Docs.as_view('docs'))
                app.add_url_rule('/wall', view_func=jwt_required(optional=True)(wall))
            """,
        },
        {("GET", "/feed"): [], ("GET", "/items"): [], ("GET", "/docs"): [], ("GET", "/wall"): []},
    ),
    "fl_login_disabled_in_a_config_file": (
        {
            "app.py": """\
                from flask import Flask
                from flask_login import login_required
                app = Flask(__name__)
                app.config.from_pyfile('settings.cfg')
                @app.route('/me')
                @login_required
                def me(): ...
            """,
            "settings.cfg": "LOGIN_DISABLED = True\n",
        },
        {("GET", "/me"): []},
    ),
    "fl_login_disabled_by_setdefault": (
        {
            "app.py": """\
                from flask import Flask
                from flask_login import login_required
                app = Flask(__name__)
                app.config.setdefault('LOGIN_DISABLED', True)
                @app.route('/me')
                @login_required
                def me(): ...
            """,
        },
        {("GET", "/me"): []},
    ),
    "fl_login_disabled_by_the_legacy_setter": (
        {
            "app.py": """\
                from flask import Flask
                from flask_login import LoginManager, login_required
                app = Flask(__name__)
                LoginManager(app)._login_disabled = True
                @app.route('/me')
                @login_required
                def me(): ...
            """,
        },
        {("GET", "/me"): []},
    ),
    "fl_auth_decorators_let_options_through": (
        {
            "app.py": """\
                from flask import Flask
                from flask.views import MethodView
                from flask_login import login_required
                from flask_jwt_extended import jwt_required
                app = Flask(__name__)
                @app.route('/x', methods=['POST', 'OPTIONS'])
                @login_required
                def x(): ...
                class Z(MethodView):
                    decorators = [jwt_required()]
                    def get(self): ...
                    def options(self): ...
                app.add_url_rule('/z', view_func=Z.as_view('z'))
            """,
        },
        {
            ("OPTIONS", "/x"): [],
            ("POST", "/x"): ["login_required"],
            ("OPTIONS", "/z"): [],
            ("GET", "/z"): ["jwt_required"],
        },
    ),
    "fl_response_cache_outside_the_guard": (
        {
            "app.py": """\
                from flask import Flask
                from flask.views import MethodView
                from flask_caching import Cache
                from flask_login import login_required
                app = Flask(__name__)
                cache = Cache(app)
                @app.route('/dash')
                @cache.cached(timeout=60)
                @login_required
                def dash(): ...
                @app.route('/dash2')
                @login_required
                @cache.cached(timeout=60)
                def dash2(): ...
                class V(MethodView):
                    decorators = [login_required, cache.cached(timeout=60)]
                    def get(self): ...
                class W(MethodView):
                    decorators = [cache.cached(timeout=60), login_required]
                    def get(self): ...
                app.add_url_rule('/v', view_func=V.as_view('v'))
                app.add_url_rule('/w', view_func=W.as_view('w'))
            """,
        },
        {
            ("GET", "/dash"): [],
            ("GET", "/dash2"): ["login_required"],
            ("GET", "/v"): [],
            ("GET", "/w"): ["login_required"],
        },
    ),
}


@pytest.mark.parametrize(("files", "shown"), _PROTECTION.values(), ids=_PROTECTION)
def test_a_row_shows_only_guards_that_protect_it(
    tmp_path: Path, files: dict[str, str], shown: dict[tuple[str, str], list[str]]
) -> None:
    _write(tmp_path, {rel: dedent(text) for rel, text in files.items()})
    rows = _rows(tmp_path)
    for key, guards in shown.items():
        row = rows[key]
        assert [*row["guards"], *row["scope_guards"]] == guards, key
        assert row["judgement_required"] is not guards, key


def test_routes_a_library_serves_are_listed_with_their_path_unknown(tmp_path: Path) -> None:
    _write(
        tmp_path,
        {
            "app/urls.py": (
                "from django.urls import include, path\n"
                "from rest_framework.routers import SimpleRouter\nfrom . import views\n"
                "router = SimpleRouter()\nrouter.register('users', views.Users)\n"
                "urlpatterns = [path('', include(router.urls))]\n"
                "handler404 = views.not_found\nhandler500 = 'app.views.oops'\n"
            ),
            "app/views.py": (
                "from djoser.views import UserViewSet\n"
                "class Users(UserViewSet):\n    pass\n"
                "def not_found(request, exception): ...\ndef oops(request): ...\n"
            ),
            "web.py": dedent("""\
                from flask import Flask
                from flask_dance.contrib.github import make_github_blueprint
                from flask_admin import Admin
                app = Flask(__name__)
                gh = make_github_blueprint(client_id='x')
                app.register_blueprint(gh, url_prefix='/login')
                admin = Admin(app)
            """),
            "spec/app.py": (
                "import connexion\napp = connexion.App(__name__)\napp.add_api('api.yaml')\n"
            ),
        },
    )
    result = route_guards(tree_files(tmp_path))
    rows = {(r.method, r.pattern): r for r in result.routes}
    for key in (
        ("any", "users/[UserViewSet actions]"),  # the library viewset's `@action`s
        ("any", "[handler404]"),
        ("any", "[handler500]"),
        ("ANY", "/login/[gh]"),
        ("ANY", "/admin/[Flask-Admin]"),
    ):
        assert rows[key].pattern_dynamic and rows[key].judgement_required, key
    assert rows[("any", "[handler500]")].handler.expr == "oops"
    assert "connexion" in {g.system for g in result.coverage_gaps}


def test_prefixes_drf_nested_routers_and_wsgi_dispatchers_add(tmp_path: Path) -> None:
    _write(
        tmp_path,
        {
            "app/urls.py": (
                "from django.urls import include, path\n"
                "from rest_framework.routers import SimpleRouter\n"
                "from rest_framework_nested.routers import NestedSimpleRouter\n"
                "from . import views\n"
                "router = SimpleRouter()\nrouter.register('notes', views.Notes)\n"
                "nested = NestedSimpleRouter(router, 'notes')\n"
                "nested.register('comments', views.Notes)\n"
                "urlpatterns = [path('', include(nested.urls))]\n"
            ),
            "app/views.py": (
                "from rest_framework import viewsets\n"
                "class Notes(viewsets.ReadOnlyModelViewSet):\n    pass\n"
            ),
            "web.py": dedent("""\
                from flask import Flask
                from werkzeug.middleware.dispatcher import DispatcherMiddleware
                front = Flask('front')
                api = Flask('api')
                @api.route('/items')
                def items(): ...
                front.wsgi_app = DispatcherMiddleware(front.wsgi_app, {'/api': api.wsgi_app})
            """),
        },
    )
    rows = _rows(tmp_path)
    # drf-nested-routers' default lookup, which the reading can't be sure of
    assert rows[("GET", "notes/<nested_1_pk>/comments/")]["pattern_dynamic"]
    assert not rows[("GET", "/api/items")]["pattern_dynamic"]


def test_a_root_urlconf_re_exporting_a_list_keeps_its_projects_guards(tmp_path: Path) -> None:
    _write(
        tmp_path,
        {
            "site/settings.py": (
                "ROOT_URLCONF = 'site.urls'\n"
                "MIDDLEWARE = ['django.contrib.auth.middleware.LoginRequiredMiddleware']\n"
            ),
            "site/urls.py": "from notes.urls import urlpatterns\n",
            "notes/urls.py": (
                "from django.urls import path\nfrom . import views\n"
                "urlpatterns = [path('notes/', views.notes)]\n"
            ),
            "notes/views.py": "def notes(request): ...\n",
        },
    )
    result = route_guards(tree_files(tmp_path)).model_dump(mode="json")
    [row] = [r for r in result["routes"] if r["family"] == "django-drf"]
    assert row["scope_guards"] == ["LoginRequiredMiddleware"]


def test_urlconfs_importing_each_others_lists_end_the_walk(tmp_path: Path) -> None:
    _write(
        tmp_path,
        {
            "a/urls.py": "from b.urls import urlpatterns as b_urls\nurlpatterns = b_urls\n",
            "b/urls.py": "from a.urls import urlpatterns as a_urls\nurlpatterns = a_urls\n",
        },
    )
    assert _rows(tmp_path) == {}


@pytest.mark.parametrize(
    ("router", "pattern"),
    [("SimpleRouter(trailing_slash='')", "notes"), ("SimpleRouter(trailing_slash=0)", "notes")],
)
def test_router_actions_read_imported_methods_and_any_falsy_slash(
    tmp_path: Path, router: str, pattern: str
) -> None:
    _write(
        tmp_path,
        {
            "app/urls.py": (
                "from rest_framework.routers import SimpleRouter\nfrom .views import NoteViewSet\n"
                f"router = {router}\nrouter.register('notes', NoteViewSet)\n"
                "urlpatterns = router.urls\n"
            ),
            "app/consts.py": "WRITE = ['post', 'put']\n",
            "app/views.py": (
                "from rest_framework import viewsets\n"
                "from rest_framework.decorators import action\nfrom . import consts\n"
                "class NoteViewSet(viewsets.ViewSet):\n"
                "    def list(self, request): ...\n"
                "    @action(detail=True, methods=consts.WRITE)\n"
                "    def pin(self, request, pk=None): ...\n"
            ),
        },
    )
    assert set(_rows(tmp_path)) == {
        ("GET", pattern),
        ("POST", f"{pattern}/<pk>/pin"),
        ("PUT", f"{pattern}/<pk>/pin"),
    }


def test_guards_read_through_aliases_and_only_from_auth_libraries(tmp_path: Path) -> None:
    _write(
        tmp_path,
        {
            "app/urls.py": (
                "from django.urls import path\nfrom . import views\n"
                "urlpatterns = [\n"
                "    path('a/', views.a), path('b/', views.b), path('c/', views.C.as_view())\n"
                "]\n"
            ),
            "app/views.py": (
                "from django.contrib.auth.decorators import login_required as require_login\n"
                "from someauth.decorators import login_required\n"
                "from rest_framework.views import APIView\n"
                "from rest_framework.permissions import IsAuthenticated as Authenticated\n"
                "@require_login\ndef a(request): ...\n"
                "@login_required\ndef b(request): ...\n"
                "class C(APIView):\n"
                "    permission_classes = [Authenticated]\n"
                "    def get(self, request): ...\n"
            ),
        },
    )
    rows = _rows(tmp_path)
    assert rows[("any", "a/")]["guards"] == ["require_login"]
    assert rows[("any", "b/")]["guards"] == [] and rows[("any", "b/")]["judgement_required"]
    assert rows[("GET", "c/")]["guards"] == ["Authenticated"]


@pytest.mark.parametrize(
    ("names", "methods"),
    [
        ("['get']", {"GET"}),
        ("('get', 'delete')", {"GET", "DELETE"}),
        ("ALLOWED", {"GET", "POST", "DELETE"}),  # not a literal: not read
        ("['get']\n    http_method_names: list[str] = ['post']", {"POST"}),  # the last binding
        ("['head']", {"HEAD"}),  # `get` serves HEAD
    ],
)
def test_a_class_view_lists_only_the_verbs_its_http_method_names_allow(
    tmp_path: Path, names: str, methods: set[str]
) -> None:
    _write(
        tmp_path,
        {
            "app/urls.py": (
                "from django.urls import path\nfrom .views import NoteView\n"
                "urlpatterns = [path('notes/', NoteView.as_view())]\n"
            ),
            "app/views.py": (
                "from django.views import View\n"
                "class Base(View):\n"
                f"    http_method_names = {names}\n"
                "class NoteView(Base):\n"
                "    def get(self, request): ...\n"
                "    def post(self, request): ...\n"
                "    def delete(self, request): ...\n"
            ),
        },
    )
    assert {m for m, _ in _rows(tmp_path)} == methods
