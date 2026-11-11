"""Ownership of the object a Django or DRF id route acts on. The reader judges only (D35): an
id-only read is judged, and every other shape, protected or not, reads unknown."""

from __future__ import annotations

from pathlib import Path
from textwrap import dedent

import pytest

from traust_core.v1.providers.route_guards import route_guards
from traust_core.v1.providers.tree import tree_files

MODELS = """
from django.conf import settings
from django.contrib.auth.models import User
from django.db import models


class Note(models.Model):
    owner = models.ForeignKey(User, on_delete=models.CASCADE, related_name="notes")
    title = models.CharField(max_length=100)
    archived = models.BooleanField(default=False)


class Ping(models.Model):
    note = models.ForeignKey(Note, on_delete=models.CASCADE)


class Tag(models.Model):
    name = models.CharField(max_length=40)
"""

URLS = """
from django.urls import path
from . import views

urlpatterns = [path("notes/<int:pk>/", views.note)]
"""

HEAD = """
from django.contrib.auth.decorators import login_required
from django.http import HttpResponse, JsonResponse
from django.shortcuts import get_object_or_404
from django.forms.models import model_to_dict
from .models import Note, Ping, Tag
from .access import load_note

"""


def _write(root: Path, files: dict[str, str]) -> None:
    for rel, text in files.items():
        path = root / rel
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(dedent(text))


def _rows(root: Path) -> dict[tuple[str, str], tuple[str | None, bool]]:
    return {
        (r.method, r.pattern): (r.ownership.value if r.ownership else None, r.judgement_required)
        for r in route_guards(tree_files(root)).routes
        if r.family.value == "django-drf"
    }


def _note(tmp_path: Path, view: str, **extra: str) -> tuple[str | None, bool]:
    _write(
        tmp_path,
        {
            "app/models.py": MODELS,
            "app/urls.py": URLS,
            "app/views.py": HEAD + dedent(view),
            "app/access.py": "def load_note(request, pk): ...\n",
            **extra,
        },
    )
    [row] = _rows(tmp_path).values()
    return row


CASES = [
    (
        "id_only_read_never_seeing_the_caller",
        """
        @login_required
        def note(request, pk):
            return JsonResponse(model_to_dict(get_object_or_404(Note, pk=pk)))
        """,
        "caller-blind",
    ),
    (
        "id_only_read_beside_a_caller_reference",
        """
        @login_required
        def note(request, pk):
            note = Note.objects.get(pk=pk)
            return HttpResponse(f"{request.user}: {note.title}")
        """,
        "unchecked",
    ),
    (
        "id_read_narrowed_only_by_a_literal",
        """
        @login_required
        def note(request, pk):
            return JsonResponse(model_to_dict(Note.objects.get(pk=pk, archived=False)))
        """,
        "caller-blind",
    ),
    (
        "caller_bound_read_is_never_credited",
        """
        @login_required
        def note(request, pk):
            return JsonResponse(model_to_dict(Note.objects.get(pk=pk, owner=request.user)))
        """,
        "unknown",
    ),
    (
        "caller_related_manager_read_is_never_credited",
        """
        @login_required
        def note(request, pk):
            return JsonResponse(model_to_dict(request.user.notes.get(pk=pk)))
        """,
        "unknown",
    ),
    (
        "caller_bound_through_a_relation_lookup",
        """
        @login_required
        def note(request, pk):
            return JsonResponse(model_to_dict(Note.objects.get(pk=pk, owner__in=[request.user])))
        """,
        "unknown",
    ),
    (
        "read_narrowed_by_a_local_reads_unknown",
        """
        @login_required
        def note(request, pk):
            parent = load_note(request, pk)
            return JsonResponse(model_to_dict(Note.objects.get(pk=pk, owner=parent.owner)))
        """,
        "unknown",
    ),
    (
        "read_by_a_local_not_the_path_id_is_no_id_read",
        """
        @login_required
        def note(request, pk):
            parent = load_note(request, pk)
            pings = Ping.objects.filter(note=parent)
            return JsonResponse({"n": pings.count()})
        """,
        "unknown",
    ),
    (
        "request_handed_to_a_helper_carries_the_caller",
        """
        @login_required
        def note(request, pk):
            load_note(request, pk)
            tag = get_object_or_404(Tag, pk=pk)
            return JsonResponse(model_to_dict(tag))
        """,
        "unknown",
    ),
    (
        "request_handed_to_a_helper_then_an_id_only_owner_read",
        """
        @login_required
        def note(request, pk):
            load_note(request, 0)
            return JsonResponse(model_to_dict(get_object_or_404(Note, pk=pk)))
        """,
        "unchecked",
    ),
    (
        "id_only_read_then_a_hand_check_stays_judged",
        """
        from django.core.exceptions import PermissionDenied

        @login_required
        def note(request, pk):
            note = get_object_or_404(Note, pk=pk)
            if note.owner != request.user:
                raise PermissionDenied
            return JsonResponse(model_to_dict(note))
        """,
        "unchecked",
    ),
    (
        "id_handed_to_a_helper_is_not_followed",
        """
        @login_required
        def note(request, pk):
            return JsonResponse(model_to_dict(load_note(None, pk)))
        """,
        "unknown",
    ),
    (
        "q_object_read_reads_unknown",
        """
        from django.db.models import Q

        @login_required
        def note(request, pk):
            return JsonResponse(model_to_dict(Note.objects.get(Q(pk=pk))))
        """,
        "unknown",
    ),
    (
        "shaping_methods_dont_hide_an_id_only_read",
        """
        @login_required
        def note(request, pk):
            note = Note.objects.select_related("owner").only("title").get(pk=pk)
            return JsonResponse(model_to_dict(note))
        """,
        "caller-blind",
    ),
    (
        "a_queryset_handed_to_get_object_or_404",
        """
        @login_required
        def note(request, pk):
            note = get_object_or_404(Note.objects.select_for_update(), pk=pk)
            return JsonResponse(model_to_dict(note))
        """,
        "caller-blind",
    ),
    (
        "values_then_first",
        """
        @login_required
        def note(request, pk):
            return JsonResponse(Note.objects.filter(pk=pk).values("title").first())
        """,
        "caller-blind",
    ),
    (
        "an_id_cast_is_the_id",
        """
        @login_required
        def note(request, pk):
            return JsonResponse(model_to_dict(Note.objects.get(pk=int(pk))))
        """,
        "caller-blind",
    ),
    (
        "an_async_read",
        """
        @login_required
        async def note(request, pk):
            note = await Note.objects.aget(pk=pk)
            return JsonResponse(model_to_dict(note))
        """,
        "caller-blind",
    ),
    (
        "the_shortcut_through_its_module",
        """
        from django import shortcuts

        @login_required
        def note(request, pk):
            return JsonResponse(model_to_dict(shortcuts.get_object_or_404(Note, pk=pk)))
        """,
        "caller-blind",
    ),
    (
        "a_model_through_its_module_or_an_alias",
        """
        from . import models
        from .models import Note as N

        @login_required
        def note(request, pk):
            first, second = get_object_or_404(models.Note, pk=pk), N.objects.get(pk=pk)
            return JsonResponse({"a": model_to_dict(first), "b": model_to_dict(second)})
        """,
        "caller-blind",
    ),
    (
        "harmless_library_decorators",
        """
        from django.views.decorators.cache import cache_control
        from django.views.decorators.gzip import gzip_page

        @login_required
        @cache_control(private=True)
        @gzip_page
        def note(request, pk):
            return JsonResponse(model_to_dict(get_object_or_404(Note, pk=pk)))
        """,
        "caller-blind",
    ),
    (
        "a_checkout_shortcut_namesake_isnt_djangos",
        """
        from .access import load_note as get_object_or_404

        @login_required
        def note(request, pk):
            return JsonResponse(model_to_dict(get_object_or_404(Note, pk=pk)))
        """,
        "unknown",
    ),
    (
        "a_session_comparison_sees_the_caller",
        """
        from django.core.exceptions import PermissionDenied

        @login_required
        def note(request, pk):
            note = get_object_or_404(Note, pk=pk)
            if note.owner_id != request.session["_auth_user_id"]:
                raise PermissionDenied
            return JsonResponse(model_to_dict(note))
        """,
        "unchecked",
    ),
    (
        "checkout_decorator_runs_first",
        """
        from .access import load_note as only_mine

        @login_required
        @only_mine
        def note(request, pk):
            return JsonResponse(model_to_dict(get_object_or_404(Note, pk=pk)))
        """,
        "unknown",
    ),
]


@pytest.mark.parametrize(("view", "ownership"), [c[1:] for c in CASES], ids=[c[0] for c in CASES])
def test_each_shape_reads_unknown_beside_a_twin_it_judges(
    tmp_path: Path, view: str, ownership: str
) -> None:
    found, judged = _note(tmp_path, view)
    assert found == ownership
    assert judged == (ownership in ("caller-blind", "unchecked"))


def test_a_request_user_assignment_elsewhere_doesnt_judge_a_caller_bound_read(
    tmp_path: Path,
) -> None:
    view = """
    @login_required
    def note(request, pk):
        return JsonResponse(model_to_dict(Note.objects.get(pk=pk, owner=request.user)))
    """
    middleware = "def impersonate(request):\n    request.user = request.session['as']\n"
    assert _note(tmp_path, view, **{"app/middleware.py": middleware}) == ("unknown", False)


DRF_URLS = """
from django.urls import include, path
from rest_framework.routers import SimpleRouter
from . import views

router = SimpleRouter()
router.register(r"notes", views.NoteViewSet)
urlpatterns = [path("", include(router.urls))]
"""

DRF_HEAD = """
from rest_framework import viewsets
from rest_framework.decorators import action
from rest_framework.permissions import IsAuthenticated
from rest_framework.response import Response
from .models import Note
from .serializers import NoteSerializer

"""


def _viewset(tmp_path: Path, body: str) -> dict[tuple[str, str], tuple[str | None, bool]]:
    _write(
        tmp_path,
        {
            "app/models.py": MODELS,
            "app/urls.py": DRF_URLS,
            "app/serializers.py": (
                "from rest_framework import serializers\n"
                "from .models import Note\n\n"
                "class NoteSerializer(serializers.ModelSerializer):\n"
                "    class Meta:\n        model = Note\n        fields = ['title']\n"
            ),
            "app/views.py": DRF_HEAD + dedent(body),
        },
    )
    return _rows(tmp_path)


def test_a_viewset_reading_every_row_by_its_pk_is_judged(tmp_path: Path) -> None:
    rows = _viewset(
        tmp_path,
        """
        class NoteViewSet(viewsets.ModelViewSet):
            permission_classes = [IsAuthenticated]
            queryset = Note.objects.all()
            serializer_class = NoteSerializer
        """,
    )
    assert rows[("GET", "notes/<pk>/")] == ("caller-blind", True)
    assert rows[("DELETE", "notes/<pk>/")] == ("caller-blind", True)


def test_a_viewset_whose_queryset_names_the_caller_is_never_credited(tmp_path: Path) -> None:
    rows = _viewset(
        tmp_path,
        """
        class NoteViewSet(viewsets.ModelViewSet):
            permission_classes = [IsAuthenticated]
            serializer_class = NoteSerializer

            def get_queryset(self):
                return Note.objects.filter(owner=self.request.user)
        """,
    )
    assert rows[("GET", "notes/<pk>/")] == ("unknown", False)


def test_a_mapped_extra_action_reads_like_the_action_it_maps(tmp_path: Path) -> None:
    rows = _viewset(
        tmp_path,
        """
        class NoteViewSet(viewsets.ViewSet):
            permission_classes = [IsAuthenticated]

            @action(detail=True, methods=["post"])
            def share(self, request, pk=None):
                return Response(NoteSerializer(Note.objects.get(pk=pk)).data)

            @share.mapping.delete
            def unshare(self, request, pk=None):
                Note.objects.get(pk=pk).delete()
                return Response(status=204)
        """,
    )
    assert rows[("POST", "notes/<pk>/share/")] == ("caller-blind", True)
    assert rows[("DELETE", "notes/<pk>/share/")] == ("caller-blind", True)


def test_a_class_view_reads_the_id_from_kwargs_and_self_request_is_the_caller(
    tmp_path: Path,
) -> None:
    urls = URLS.replace("views.note", "views.NoteView.as_view()")
    view = """
    from django.contrib.auth.mixins import LoginRequiredMixin
    from django.core.exceptions import PermissionDenied
    from django.views import View

    class NoteView(LoginRequiredMixin, View):
        def get(self, request, *args, **kwargs):
            note = get_object_or_404(Note, pk=kwargs["pk"])
            return JsonResponse(model_to_dict(note))

        def delete(self, request, *args, **kwargs):
            note = get_object_or_404(Note, pk=self.kwargs["pk"])
            if note.owner != self.request.user:
                raise PermissionDenied
            note.delete()
            return HttpResponse(status=204)
    """
    rows = _rows_of(tmp_path, view, urls)
    assert rows[("GET", "notes/<int:pk>/")] == ("caller-blind", True)
    assert rows[("DELETE", "notes/<int:pk>/")] == ("unchecked", True)


def _rows_of(
    tmp_path: Path, view: str, urls: str, models: str = MODELS
) -> dict[tuple[str, str], tuple[str | None, bool]]:
    _write(
        tmp_path,
        {
            "app/models.py": models,
            "app/urls.py": urls,
            "app/views.py": HEAD + dedent(view),
            "app/access.py": "def load_note(request, pk): ...\n",
        },
    )
    return _rows(tmp_path)


READ = """
@login_required
def note(request, pk):
    return JsonResponse(model_to_dict(get_object_or_404(Note, pk=pk)))
"""


@pytest.mark.parametrize(
    ("models", "ownership"),
    [
        (
            MODELS.replace("    archived =", "    objects = models.Manager()\n    archived ="),
            "caller-blind",
        ),
        (
            MODELS.replace("    archived =", "    objects = MineManager()\n    archived ="),
            "unknown",
        ),
        (
            MODELS.replace(
                "class Note(models.Model):",
                "class Stamped(models.Model):\n    class Meta:\n        abstract = True\n\n\n"
                "class Note(Stamped):",
            ),
            "caller-blind",
        ),
        (
            MODELS.replace(
                "class Note(models.Model):",
                "class Scoped(models.Model):\n    objects = MineManager()\n\n\nclass Note(Scoped):",
            ),
            "unknown",
        ),
    ],
    ids=["explicit_default_manager", "custom_manager", "abstract_base", "inherited_custom_manager"],
)
def test_the_default_manager_decides_whether_a_read_is_read(
    tmp_path: Path, models: str, ownership: str
) -> None:
    assert _rows_of(tmp_path, READ, URLS, models)[("any", "notes/<int:pk>/")][0] == ownership


@pytest.mark.parametrize(
    "urls",
    [
        URLS.replace(
            'path("notes/<int:pk>/", views.note)', 're_path(r"^notes/(\\d+)/$", views.note)'
        ).replace("import path", "import path, re_path"),
        URLS.replace(
            'path("notes/<int:pk>/", views.note)', "path(settings.NOTE_ROUTE, views.note)"
        ).replace("from . import views", "from django.conf import settings\nfrom . import views"),
    ],
    ids=["unnamed_group", "pattern_from_settings"],
)
def test_an_unreadable_id_route_is_listed_not_credited(tmp_path: Path, urls: str) -> None:
    [(ownership, judged)] = _rows_of(tmp_path, READ, urls).values()
    assert (ownership, judged) == ("unknown", False)


def test_a_detail_view_on_a_custom_manager_model_is_not_judged(tmp_path: Path) -> None:
    urls = URLS.replace("views.note", "views.NoteView.as_view()")
    view = """
    from django.contrib.auth.mixins import LoginRequiredMixin
    from django.views.generic import DetailView

    class NoteView(LoginRequiredMixin, DetailView):
        model = Note
    """
    models = MODELS.replace("    archived =", "    objects = MineManager()\n    archived =")
    [row] = _rows_of(tmp_path, view, urls, models).values()
    assert row == ("unknown", False)


@pytest.mark.parametrize(
    ("extra", "detail"),
    [
        (
            "    def perform_create(self, s):\n        s.save(owner=self.request.user)\n",
            "caller-blind",
        ),
        ("    def get_serializer_class(self):\n        return NoteSerializer\n", "caller-blind"),
        ("    filter_backends = [OwnerFilter]\n", "unknown"),
        (
            "    def get_object(self):\n        return Note.objects.get(owner=self.request.user)\n",
            "unknown",
        ),
    ],
    ids=[
        "perform_create",
        "get_serializer_class",
        "checkout_filter_backend",
        "get_object_override",
    ],
)
def test_only_what_changes_the_read_stops_a_viewset_being_judged(
    tmp_path: Path, extra: str, detail: str
) -> None:
    rows = _viewset(
        tmp_path,
        "from .filters import OwnerFilter\n\n"
        "class NoteViewSet(viewsets.ModelViewSet):\n"
        "    permission_classes = [IsAuthenticated]\n"
        "    queryset = Note.objects.all()\n"
        "    serializer_class = NoteSerializer\n" + extra,
    )
    assert rows[("GET", "notes/<pk>/")][0] == detail


def test_an_extra_action_reads_through_get_object(tmp_path: Path) -> None:
    rows = _viewset(
        tmp_path,
        """
        class NoteViewSet(viewsets.ModelViewSet):
            permission_classes = [IsAuthenticated]
            queryset = Note.objects.all()
            serializer_class = NoteSerializer

            @action(detail=True, methods=["post"])
            def archive(self, request, pk=None):
                note = self.get_object()
                note.delete()
                return Response(status=204)
        """,
    )
    assert rows[("POST", "notes/<pk>/archive/")] == ("caller-blind", True)


def test_a_default_filter_backend_of_the_checkouts_stops_judging(tmp_path: Path) -> None:
    (tmp_path / "proj").mkdir()
    (tmp_path / "proj/settings.py").write_text(
        'REST_FRAMEWORK = {"DEFAULT_FILTER_BACKENDS": ["app.filters.OwnerFilter"]}\n'
    )
    rows = _viewset(
        tmp_path,
        """
        class NoteViewSet(viewsets.ModelViewSet):
            permission_classes = [IsAuthenticated]
            queryset = Note.objects.all()
            serializer_class = NoteSerializer
        """,
    )
    assert rows[("GET", "notes/<pk>/")][0] == "unknown"


def test_a_deep_middleware_constant_doesnt_abort_the_scan(tmp_path: Path) -> None:
    banner = "class BannerMiddleware:\n    BANNER = " + " + ".join(['"x"'] * 3000) + "\n"
    assert _note(tmp_path, READ, **{"app/middleware.py": banner}) == ("caller-blind", True)


def _class_rows(
    tmp_path: Path, view: str, *, pattern: str = "notes/<int:pk>/", models: str = MODELS
) -> dict[tuple[str, str], tuple[str | None, bool]]:
    urls = (
        "from django.urls import path\nfrom . import views\n\n"
        f'urlpatterns = [path("{pattern}", views.NoteView.as_view())]\n'
    )
    head = (
        DRF_HEAD + "from rest_framework import generics\nfrom rest_framework.views import APIView\n"
    )
    _write(
        tmp_path,
        {
            "app/models.py": models,
            "app/urls.py": urls,
            "app/serializers.py": "class NoteSerializer: ...\n",
            "app/views.py": head + HEAD + dedent(view),
            "app/access.py": "def load_note(request, pk): ...\n",
        },
    )
    return _rows(tmp_path)


def test_an_apiview_get_object_helper_is_followed_one_hop(tmp_path: Path) -> None:
    rows = _class_rows(
        tmp_path,
        """
        from django.http import Http404

        class NoteView(APIView):
            permission_classes = [IsAuthenticated]

            def get_object(self, pk):
                try:
                    return Note.objects.get(pk=pk)
                except Note.DoesNotExist:
                    raise Http404

            def get(self, request, pk):
                return Response(NoteSerializer(self.get_object(pk)).data)

            def delete(self, request, pk):
                self.get_object(pk).delete()
                return Response(status=204)
        """,
    )
    assert rows[("GET", "notes/<int:pk>/")] == ("caller-blind", True)
    assert rows[("DELETE", "notes/<int:pk>/")] == ("caller-blind", True)


def test_a_helper_that_reads_by_another_id_is_no_id_read(tmp_path: Path) -> None:
    rows = _class_rows(
        tmp_path,
        """
        class NoteView(APIView):
            permission_classes = [IsAuthenticated]

            def get_object(self, pk):
                return Note.objects.get(pk=pk)

            def get(self, request, pk):
                return Response(NoteSerializer(self.get_object(request.user.id)).data)
        """,
    )
    assert rows[("GET", "notes/<int:pk>/")][1] is False


def test_a_queryset_bound_to_a_name_or_the_class_is_read_through(tmp_path: Path) -> None:
    rows = _viewset(
        tmp_path,
        """
        from django.shortcuts import get_object_or_404

        class NoteViewSet(viewsets.ViewSet):
            permission_classes = [IsAuthenticated]
            queryset = Note.objects.all()

            def retrieve(self, request, pk=None):
                queryset = Note.objects.all()
                return Response(NoteSerializer(get_object_or_404(queryset, pk=pk)).data)

            def destroy(self, request, pk=None):
                get_object_or_404(self.queryset, pk=pk).delete()
                return Response(status=204)
        """,
    )
    assert rows[("GET", "notes/<pk>/")] == ("caller-blind", True)
    assert rows[("DELETE", "notes/<pk>/")] == ("caller-blind", True)


def test_a_generic_view_narrowed_only_by_a_parent_path_id_is_judged(tmp_path: Path) -> None:
    rows = _class_rows(
        tmp_path,
        """
        class NoteView(generics.RetrieveDestroyAPIView):
            permission_classes = [IsAuthenticated]
            serializer_class = NoteSerializer

            def get_queryset(self):
                return Ping.objects.filter(note_id=self.kwargs["note_pk"])
        """,
        pattern="notes/<int:note_pk>/pings/<int:pk>/",
    )
    assert rows[("GET", "notes/<int:note_pk>/pings/<int:pk>/")] == ("caller-blind", True)


@pytest.mark.parametrize(
    ("get_object", "ownership"),
    [
        ('return get_object_or_404(Note, pk=self.kwargs["pk"])', "caller-blind"),
        (
            'return get_object_or_404(Note, pk=self.kwargs["pk"], owner=self.request.user)',
            "unknown",
        ),
        ("return super().get_object()", "unknown"),
    ],
    ids=["by_the_path_id", "tied_to_the_caller", "the_librarys"],
)
def test_a_get_object_override_is_read(tmp_path: Path, get_object: str, ownership: str) -> None:
    rows = _class_rows(
        tmp_path,
        f"""
        class NoteView(generics.RetrieveAPIView):
            permission_classes = [IsAuthenticated]
            serializer_class = NoteSerializer

            def get_object(self):
                {get_object}
        """,
    )
    assert rows[("GET", "notes/<int:pk>/")][0] == ownership


@pytest.mark.parametrize(
    "models",
    [
        MODELS.replace("class Note(models.Model):", "class Note(TimeStampedModel):").replace(
            "from django.db import models",
            "from django.db import models\n"
            "from django_extensions.db.models import TimeStampedModel",
        ),
        MODELS.replace(
            "from django.db import models",
            "from django.db import models\nfrom django.db import models as m",
        ).replace("class Note(models.Model):", "class Note(m.Model):"),
    ],
    ids=["library_base", "aliased_module"],
)
def test_a_model_on_a_base_outside_the_checkout_is_read(tmp_path: Path, models: str) -> None:
    assert _rows_of(tmp_path, READ, URLS, models)[("any", "notes/<int:pk>/")] == (
        "caller-blind",
        True,
    )


@pytest.mark.parametrize(
    "read",
    [
        "Note._default_manager.get(pk=pk)",
        "Note._base_manager.get(pk=pk)",
        "get_list_or_404(Ping, note_id=pk)[0]",
    ],
)
def test_other_read_forms_are_read(tmp_path: Path, read: str) -> None:
    view = f"""
    from django.shortcuts import get_list_or_404

    @login_required
    def note(request, pk):
        return JsonResponse(model_to_dict({read}))
    """
    assert _note(tmp_path, view) == ("caller-blind", True)


def test_an_async_view_through_sync_to_async_is_read(tmp_path: Path) -> None:
    view = """
    from asgiref.sync import sync_to_async

    @login_required
    async def note(request, pk):
        note = await sync_to_async(get_object_or_404)(Note, pk=pk)
        return JsonResponse(model_to_dict(note))
    """
    assert _note(tmp_path, view) == ("caller-blind", True)


def test_an_object_permission_class_sees_the_caller(tmp_path: Path) -> None:
    rows = _viewset(
        tmp_path,
        """
        from .permissions import IsOwner

        class NoteViewSet(viewsets.ModelViewSet):
            permission_classes = [IsAuthenticated, IsOwner]
            queryset = Note.objects.all()
            serializer_class = NoteSerializer
        """
        + "",
    )
    assert rows[("GET", "notes/<pk>/")] == ("caller-blind", True)
    (tmp_path / "app/permissions.py").write_text(
        "from rest_framework.permissions import BasePermission\n\n"
        "class IsOwner(BasePermission):\n"
        "    def has_object_permission(self, request, view, obj):\n"
        "        return obj.owner == request.user\n"
    )
    assert _rows(tmp_path)[("GET", "notes/<pk>/")] == ("unchecked", True)


def test_a_checkout_wrapper_in_the_urlconf_runs_first(tmp_path: Path) -> None:
    urls = URLS.replace("views.note)", "owns_note(views.note))").replace(
        "from . import views", "from . import views\nfrom .access import owns_note"
    )
    [row] = _rows_of(tmp_path, READ, urls).values()
    assert row == ("unknown", False)


@pytest.mark.parametrize(
    ("managers", "ownership"),
    [
        ("    mine = MineManager()\n", "unknown"),
        ("    objects = models.Manager()\n    mine = MineManager()\n", "caller-blind"),
        (
            "    objects = models.Manager()\n    mine = MineManager()\n\n"
            '    class Meta:\n        default_manager_name = "mine"\n',
            "unknown",
        ),
        ("    mine = MineManager()\n    objects = models.Manager()\n", "unknown"),
    ],
    ids=["only_a_custom_manager", "django_first", "meta_names_the_custom", "custom_first"],
)
def test_the_default_manager_is_the_first_declared_or_the_one_meta_names(
    tmp_path: Path, managers: str, ownership: str
) -> None:
    models = MODELS.replace("    archived =", managers + "    archived =")
    assert _rows_of(tmp_path, READ, URLS, models)[("any", "notes/<int:pk>/")][0] == ownership


def test_deep_model_inheritance_doesnt_abort_the_scan(tmp_path: Path) -> None:
    chain = "class Y1500(models.Model):\n    pass\n" + "".join(
        f"class Y{i:04}(Y{i + 1:04}):\n    pass\n" for i in range(1499, -1, -1)
    )
    models = MODELS + chain
    assert _rows_of(tmp_path, READ, URLS, models)[("any", "notes/<int:pk>/")] == (
        "caller-blind",
        True,
    )


@pytest.mark.parametrize(
    ("models", "read", "ownership"),
    [
        (
            MODELS.replace("    archived =", "    objects = tenant_objects\n    archived ="),
            "Note.objects.get(pk=pk)",
            "unknown",
        ),
        (
            MODELS.replace(
                "from django.db import models",
                "from django.db import models\nfrom app.managers import Manager",
            ).replace("    archived =", "    objects = Manager()\n    archived ="),
            "Note.objects.get(pk=pk)",
            "unknown",
        ),
        (
            MODELS.replace(
                "    archived =",
                "    mine = MineManager()\n\n"
                '    class Meta:\n        base_manager_name = "mine"\n\n    archived =',
            ),
            "Note._base_manager.get(pk=pk)",
            "unknown",
        ),
    ],
    ids=["manager_bound_elsewhere", "imported_namesake_manager", "custom_base_manager"],
)
def test_a_manager_that_may_narrow_the_rows_reads_unknown(
    tmp_path: Path, models: str, read: str, ownership: str
) -> None:
    view = f"""
    @login_required
    def note(request, pk):
        return JsonResponse(model_to_dict({read}))
    """
    assert _rows_of(tmp_path, view, URLS, models)[("any", "notes/<int:pk>/")][0] == ownership


@pytest.mark.parametrize(
    "decorators",
    [
        "from .access import load_note as cache_page\n\n@login_required\n@cache_page\n",
        "def atomic(view):\n    return view\n\n@login_required\n@atomic\n",
    ],
    ids=["imported_namesake", "local_namesake"],
)
def test_a_checkout_decorator_named_like_a_library_one_runs_first(
    tmp_path: Path, decorators: str
) -> None:
    view = (
        decorators
        + "def note(request, pk):\n"
        + "    return JsonResponse(model_to_dict(get_object_or_404(Note, pk=pk)))\n"
    )
    assert _note(tmp_path, view) == ("unknown", False)


def test_a_checkout_urlconf_wrapper_named_like_a_library_one_runs_first(tmp_path: Path) -> None:
    urls = URLS.replace("views.note)", "cache_page(views.note))").replace(
        "from . import views", "from . import views\nfrom .access import load_note as cache_page"
    )
    [row] = _rows_of(tmp_path, READ, urls).values()
    assert row == ("unknown", False)


def test_a_get_object_override_is_read_despite_a_filter_backend(tmp_path: Path) -> None:
    rows = _class_rows(
        tmp_path,
        """
        from .filters import OwnerFilter

        class NoteView(generics.RetrieveAPIView):
            permission_classes = [IsAuthenticated]
            serializer_class = NoteSerializer
            filter_backends = [OwnerFilter]

            def get_object(self):
                return get_object_or_404(Note, pk=self.kwargs["pk"])
        """,
    )
    assert rows[("GET", "notes/<int:pk>/")] == ("caller-blind", True)


def test_an_inherited_object_permission_sees_the_caller(tmp_path: Path) -> None:
    (tmp_path / "app").mkdir()
    (tmp_path / "app/permissions.py").write_text(
        "from rest_framework.permissions import BasePermission\n\n"
        "class OwnerBase(BasePermission):\n"
        "    def has_object_permission(self, request, view, obj):\n"
        "        return obj.owner == request.user\n\n\n"
        "class IsOwner(OwnerBase):\n"
        "    pass\n"
    )
    rows = _viewset(
        tmp_path,
        """
        from .permissions import IsOwner

        class NoteViewSet(viewsets.ModelViewSet):
            permission_classes = [IsAuthenticated, IsOwner]
            queryset = Note.objects.all()
            serializer_class = NoteSerializer
        """,
    )
    assert rows[("GET", "notes/<pk>/")] == ("unchecked", True)


@pytest.mark.parametrize(
    ("read", "ownership"),
    [
        ("Note.objects.using(request.user.database).get(pk=pk)", "unknown"),
        ("Note.objects.using(db_for(pk)).get(pk=pk)", "unknown"),
        ('Note.objects.select_for_update(of=("self",)).get(pk=pk)', "caller-blind"),
    ],
    ids=["caller_selected_database", "computed_database", "literal_shaping"],
)
def test_shaping_by_anything_but_literals_reads_unknown(
    tmp_path: Path, read: str, ownership: str
) -> None:
    view = f"""
    from .access import load_note as db_for

    @login_required
    def note(request, pk):
        return JsonResponse(model_to_dict({read}))
    """
    assert _note(tmp_path, view)[0] == ownership


@pytest.mark.parametrize(
    ("check", "ownership"),
    [
        ("", "caller-blind"),
        ("        self.check_object_permissions(self.request, note)\n", "unchecked"),
    ],
    ids=["skips_the_check", "runs_the_check"],
)
def test_a_get_object_override_runs_object_permissions_only_if_it_calls_them(
    tmp_path: Path, check: str, ownership: str
) -> None:
    (tmp_path / "app").mkdir()
    (tmp_path / "app/permissions.py").write_text(
        "from rest_framework.permissions import BasePermission\n\n"
        "class IsOwner(BasePermission):\n"
        "    def has_object_permission(self, request, view, obj):\n"
        "        return obj.owner == request.user\n"
    )
    view = (
        "from .permissions import IsOwner\n\n"
        "class NoteView(generics.RetrieveAPIView):\n"
        "    permission_classes = [IsAuthenticated, IsOwner]\n"
        "    serializer_class = NoteSerializer\n\n"
        "    def get_object(self):\n"
        '        note = get_object_or_404(Note, pk=self.kwargs["pk"])\n'
        + check
        + "        return note\n"
    )
    assert _class_rows(tmp_path, view)[("GET", "notes/<int:pk>/")] == (ownership, True)


def test_a_checkout_class_decorator_runs_before_a_generic_read(tmp_path: Path) -> None:
    rows = _class_rows(
        tmp_path,
        """
        from django.utils.decorators import method_decorator
        from .access import load_note as only_mine

        @method_decorator(only_mine, name="dispatch")
        class NoteView(generics.RetrieveAPIView):
            permission_classes = [IsAuthenticated]
            queryset = Note.objects.all()
            serializer_class = NoteSerializer
        """,
    )
    assert rows[("GET", "notes/<int:pk>/")] == ("unknown", False)


def test_a_library_class_decorator_doesnt_stop_judging(tmp_path: Path) -> None:
    rows = _class_rows(
        tmp_path,
        """
        from django.utils.decorators import method_decorator
        from django.views.decorators.cache import never_cache

        @method_decorator(never_cache, name="dispatch")
        class NoteView(generics.RetrieveAPIView):
            permission_classes = [IsAuthenticated]
            queryset = Note.objects.all()
            serializer_class = NoteSerializer
        """,
    )
    assert rows[("GET", "notes/<int:pk>/")] == ("caller-blind", True)


@pytest.mark.parametrize(
    ("extra", "expected"),
    [
        (
            "    def check_object_permissions(self, request, obj):\n        owns(request, obj)\n",
            ("unknown", False),
        ),
        ("    filter_backends: list = [OwnerFilter]\n", ("unknown", False)),
        # the matrix can't read dynamic permissions: no guard, judged as unguarded
        (
            "    def get_permissions(self):\n        return [IsAuthenticated(), IsOwner()]\n",
            ("n/a", True),
        ),
    ],
    ids=["check_object_permissions_override", "annotated_filter_backends", "get_permissions"],
)
def test_what_may_narrow_or_check_a_generic_read_isnt_judged_caller_blind(
    tmp_path: Path, extra: str, expected: tuple[str, bool]
) -> None:
    rows = _viewset(
        tmp_path,
        "from .filters import OwnerFilter\nfrom .permissions import IsOwner, owns\n\n"
        "class NoteViewSet(viewsets.ModelViewSet):\n"
        "    permission_classes = [IsAuthenticated]\n"
        "    queryset = Note.objects.all()\n"
        "    serializer_class = NoteSerializer\n" + extra,
    )
    assert rows[("GET", "notes/<pk>/")] == expected


def test_route_reading_middleware_runs_before_an_id_only_view(tmp_path: Path) -> None:
    middleware = (
        "class NoteMiddleware:\n"
        "    def process_view(self, request, view, args, view_kwargs):\n"
        "        request.note_id = view_kwargs.get('pk')\n"
    )
    assert _note(tmp_path, READ, **{"app/middleware.py": middleware}) == ("unknown", False)


def test_a_model_declared_through_a_star_import_is_read(tmp_path: Path) -> None:
    models = (
        "from django.contrib.auth.models import User\n"
        "from django.db.models import *\n\n\n"
        "class Note(Model):\n"
        "    owner = ForeignKey(User, on_delete=CASCADE)\n"
        "    title = CharField(max_length=100)\n\n\n"
        "class Ping(Model):\n    pass\n\n\nclass Tag(Model):\n    pass\n"
    )
    assert _rows_of(tmp_path, READ, URLS, models)[("any", "notes/<int:pk>/")] == (
        "caller-blind",
        True,
    )


def test_annotated_and_request_aliases_are_read(tmp_path: Path) -> None:
    urls = URLS.replace("views.note", "views.NoteView.as_view()")
    view = """
    from django.contrib.auth.mixins import LoginRequiredMixin
    from django.core.exceptions import PermissionDenied
    from django.views import View

    class NoteView(LoginRequiredMixin, View):
        def get(self, request, *args, **kwargs):
            pk: int = self.kwargs["pk"]
            return JsonResponse(model_to_dict(Note.objects.get(pk=pk)))

        def delete(self, request, *args, **kwargs):
            req = self.request
            note = Note.objects.get(pk=kwargs["pk"])
            if note.owner != req.user:
                raise PermissionDenied
            note.delete()
            return HttpResponse(status=204)
    """
    rows = _rows_of(tmp_path, view, urls)
    assert rows[("GET", "notes/<int:pk>/")] == ("caller-blind", True)
    assert rows[("DELETE", "notes/<int:pk>/")] == ("unchecked", True)


def test_middleware_comparing_the_path_alone_doesnt_stop_judging(tmp_path: Path) -> None:
    middleware = (
        "class HealthMiddleware:\n"
        "    def __call__(self, request):\n"
        '        return "ok" if request.path == "/health" else self.get_response(request)\n'
    )
    assert _note(tmp_path, READ, **{"app/middleware.py": middleware}) == ("caller-blind", True)


def test_a_checkout_class_decorator_runs_before_an_explicit_method(tmp_path: Path) -> None:
    urls = URLS.replace("views.note", "views.NoteView.as_view()")
    view = """
    from django.contrib.auth.mixins import LoginRequiredMixin
    from django.utils.decorators import method_decorator
    from django.views import View
    from .access import load_note as only_mine

    @method_decorator(only_mine, name="dispatch")
    class NoteView(LoginRequiredMixin, View):
        def get(self, request, pk):
            return JsonResponse(model_to_dict(get_object_or_404(Note, pk=pk)))
    """
    assert _rows_of(tmp_path, view, urls)[("GET", "notes/<int:pk>/")] == ("unknown", False)


def test_an_aliased_checkout_base_brings_its_managers(tmp_path: Path) -> None:
    models = (
        "from django.contrib.auth.models import User\n"
        "from django.db import models\n"
        "from .base import Scoped as H\n\n\n"
        "class Note(H):\n"
        "    owner = models.ForeignKey(User, on_delete=models.CASCADE)\n"
        "    title = models.CharField(max_length=100)\n\n\n"
        "class Ping(models.Model):\n    pass\n\n\nclass Tag(models.Model):\n    pass\n"
    )
    base = (
        "from django.db import models\n\n\n"
        "class Scoped(models.Model):\n"
        "    objects = MineManager()\n\n"
        "    class Meta:\n        abstract = True\n"
    )
    view = """
    @login_required
    def note(request, pk):
        return JsonResponse(model_to_dict(Note.objects.get(pk=pk)))
    """
    assert _note(tmp_path, view, **{"app/models.py": models, "app/base.py": base})[0] == "unknown"


@pytest.mark.parametrize(
    ("read", "ownership"),
    [
        ("Note.objects.filter(pk=pk).exclude(owner=request.user).first()", "unknown"),
        ("get_object_or_404(Note.objects.filter(pk=pk).exclude(owner=request.user))", "unknown"),
        ("Note.objects.filter(pk=pk).update(title=request.POST['t'])", "caller-blind"),
    ],
    ids=["outer_exclude", "outer_exclude_in_a_shortcut", "update_acts_on_the_rows_read"],
)
def test_an_unread_link_above_an_id_read_hides_it(
    tmp_path: Path, read: str, ownership: str
) -> None:
    view = f"""
    @login_required
    def note(request, pk):
        return JsonResponse({{"n": str({read})}})
    """
    assert _note(tmp_path, view)[0] == ownership


@pytest.mark.parametrize(
    ("middleware", "ownership"),
    [
        (
            "class NoteMiddleware:\n    def __call__(self, request):\n"
            "        if request.resolver_match.url_name == 'x':\n            pass\n",
            "caller-blind",
        ),
        (
            "class NoteMiddleware:\n    def process_view(self, request, view, args, kwargs):\n"
            "        request.started = 1\n",
            "caller-blind",
        ),
        (
            "class NoteMiddleware:\n    def __call__(self, request):\n"
            "        request.note = request.resolver_match.kwargs.get('pk')\n",
            "unknown",
        ),
    ],
    ids=["route_name_check", "process_view_ignoring_the_route", "resolver_kwargs"],
)
def test_only_middleware_reading_the_route_ids_hands_views_off(
    tmp_path: Path, middleware: str, ownership: str
) -> None:
    assert _note(tmp_path, READ, **{"app/middleware.py": middleware})[0] == ownership


def test_a_checkout_namesake_of_a_library_filter_backend_hands_the_read_off(
    tmp_path: Path,
) -> None:
    rows = _viewset(
        tmp_path,
        """
        from .filters import SearchFilter

        class NoteViewSet(viewsets.ModelViewSet):
            permission_classes = [IsAuthenticated]
            queryset = Note.objects.all()
            serializer_class = NoteSerializer
            filter_backends: list = [SearchFilter]
        """,
    )
    assert rows[("GET", "notes/<pk>/")][0] == "unknown"


def test_a_library_filter_backend_keeps_the_read_judged(tmp_path: Path) -> None:
    rows = _viewset(
        tmp_path,
        """
        from rest_framework.filters import SearchFilter

        class NoteViewSet(viewsets.ModelViewSet):
            permission_classes = [IsAuthenticated]
            queryset = Note.objects.all()
            serializer_class = NoteSerializer
            filter_backends = [SearchFilter]
        """,
    )
    assert rows[("GET", "notes/<pk>/")] == ("caller-blind", True)


def test_an_annotated_base_manager_name_is_read(tmp_path: Path) -> None:
    models = MODELS.replace(
        "    archived =",
        "    mine = MineManager()\n\n"
        '    class Meta:\n        base_manager_name: str = "mine"\n\n    archived =',
    )
    view = """
    @login_required
    def note(request, pk):
        return JsonResponse(model_to_dict(Note._base_manager.get(pk=pk)))
    """
    assert _rows_of(tmp_path, view, URLS, models)[("any", "notes/<int:pk>/")][0] == "unknown"


def test_middleware_listed_in_settings_is_middleware_whatever_its_name(tmp_path: Path) -> None:
    middleware = (
        "class Loader:\n    def __call__(self, request):\n"
        "        request.note = request.resolver_match.kwargs.get('pk')\n"
    )
    settings = 'MIDDLEWARE = ["django.middleware.common.CommonMiddleware", "app.mw.Loader"]\n'
    extra = {"app/mw.py": middleware, "proj/settings.py": settings}
    assert _note(tmp_path, READ, **extra) == ("unknown", False)


def test_a_same_named_filter_from_another_package_narrows_the_read(tmp_path: Path) -> None:
    rows = _viewset(
        tmp_path,
        """
        from other_package.filters import SearchFilter

        class NoteViewSet(viewsets.ModelViewSet):
            permission_classes = [IsAuthenticated]
            queryset = Note.objects.all()
            serializer_class = NoteSerializer
            filter_backends = [SearchFilter]
        """,
    )
    assert rows[("GET", "notes/<pk>/")][0] == "unknown"


def test_an_update_naming_the_caller_sees_it(tmp_path: Path) -> None:
    view = """
    @login_required
    def note(request, pk):
        Note.objects.filter(pk=pk).update(owner=request.user)
        return HttpResponse(status=204)
    """
    assert _note(tmp_path, view) == ("unchecked", True)


def test_middleware_listed_in_a_composed_setting_is_middleware(tmp_path: Path) -> None:
    middleware = (
        "class Loader:\n    def __call__(self, request):\n"
        "        request.note = request.resolver_match.kwargs.get('pk')\n"
    )
    settings = (
        'BASE_MIDDLEWARE = ["django.middleware.common.CommonMiddleware"]\n'
        'MIDDLEWARE = BASE_MIDDLEWARE + ["app.mw.Loader"]\n'
    )
    extra = {"app/mw.py": middleware, "proj/settings.py": settings}
    assert _note(tmp_path, READ, **extra) == ("unknown", False)
