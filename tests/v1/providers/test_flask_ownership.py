"""Ownership of the object a Flask id route acts on. The reader judges only (D35): an id-only read
is judged, and every other shape, protected or not, reads unknown."""

from __future__ import annotations

from pathlib import Path
from textwrap import dedent

import pytest

from traust_core.v1.providers.route_guards import route_guards
from traust_core.v1.providers.tree import tree_files

EXT = """
from flask_sqlalchemy import SQLAlchemy

db = SQLAlchemy()
"""

MODELS = """
from .ext import db


class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)


class Note(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    owner_id = db.Column(db.Integer, db.ForeignKey("user.id"))
    title = db.Column(db.String(100))
    archived = db.Column(db.Boolean, default=False)


class Tag(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(40))
"""

HEAD = """
from flask import Blueprint, abort, g, jsonify, request, session
from flask_login import current_user, login_required
from sqlalchemy import and_, select
from .ext import db
from .models import Note, Tag
from .access import load_note

bp = Blueprint("notes", __name__)

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
        if r.family.value == "flask"
    }


def _note(tmp_path: Path, view: str, **extra: str) -> tuple[str | None, bool]:
    _write(
        tmp_path,
        {
            "app/ext.py": EXT,
            "app/models.py": MODELS,
            "app/views.py": HEAD + dedent(view),
            "app/access.py": "def load_note(note_id): ...\n",
            **extra,
        },
    )
    rows = _rows(tmp_path)
    [row] = [v for (m, p), v in rows.items() if "<" in p]
    return row


def _view(body: str, method: str = "GET") -> str:
    return (
        f'@bp.route("/notes/<int:note_id>", methods=["{method}"])\n'
        "@login_required\n"
        "def note(note_id):\n" + body
    )


CASES = [
    (
        "query_get_or_404",
        "    return jsonify(Note.query.get_or_404(note_id).title)\n",
        "caller-blind",
    ),
    ("query_get", "    return jsonify(Note.query.get(note_id).title)\n", "caller-blind"),
    ("session_get", "    return jsonify(db.session.get(Note, note_id).title)\n", "caller-blind"),
    ("db_get_or_404", "    return jsonify(db.get_or_404(Note, note_id).title)\n", "caller-blind"),
    (
        "filter_by_first",
        "    return jsonify(Note.query.filter_by(id=note_id).first_or_404().title)\n",
        "caller-blind",
    ),
    (
        "filter_equality",
        "    return jsonify(Note.query.filter(Note.id == note_id).one().title)\n",
        "caller-blind",
    ),
    (
        "session_query",
        "    return jsonify(db.session.query(Note).filter_by(id=note_id).first().title)\n",
        "caller-blind",
    ),
    (
        "select_execute",
        "    note = db.session.execute(select(Note).where(Note.id == note_id)).scalar_one()\n"
        "    return jsonify(note.title)\n",
        "caller-blind",
    ),
    (
        "db_first_or_404_select",
        "    return jsonify(db.first_or_404(select(Note).filter_by(id=note_id)).title)\n",
        "caller-blind",
    ),
    (
        "narrowed_by_a_literal",
        "    return jsonify(Note.query.filter_by(id=note_id, archived=False).first().title)\n",
        "caller-blind",
    ),
    (
        "an_id_cast",
        "    return jsonify(Note.query.get_or_404(int(note_id)).title)\n",
        "caller-blind",
    ),
    (
        "id_only_read_beside_the_caller",
        "    note = Note.query.get_or_404(note_id)\n"
        "    return jsonify(note.title, current_user.id)\n",
        "unchecked",
    ),
    (
        "a_hand_check_after_the_read_stays_judged",
        "    note = Note.query.get_or_404(note_id)\n"
        "    if note.owner_id != current_user.id:\n"
        "        abort(403)\n"
        "    return jsonify(note.title)\n",
        "unchecked",
    ),
    (
        "g_user_is_the_caller",
        "    note = Note.query.get_or_404(note_id)\n"
        "    if note.owner_id != g.user.id:\n"
        "        abort(403)\n"
        "    return jsonify(note.title)\n",
        "unchecked",
    ),
    (
        "session_is_the_caller",
        "    note = Note.query.get_or_404(note_id)\n"
        '    if note.owner_id != session["uid"]:\n'
        "        abort(403)\n"
        "    return jsonify(note.title)\n",
        "unchecked",
    ),
    (
        "owner_bound_filter_by_is_never_credited",
        "    q = Note.query.filter_by(id=note_id, owner_id=current_user.id)\n"
        "    return jsonify(q.first().title)\n",
        "unknown",
    ),
    (
        "owner_bound_filter_is_never_credited",
        "    note = Note.query.filter(and_(Note.id == note_id, Note.owner_id == current_user.id))\n"
        "    return jsonify(note.first().title)\n",
        "unknown",
    ),
    (
        "owner_bound_select_is_never_credited",
        "    stmt = select(Note).where(Note.id == note_id, Note.owner_id == g.user.id)\n"
        "    return jsonify(db.session.scalars(stmt).first().title)\n",
        "unknown",
    ),
    (
        "narrowed_by_a_local_reads_unknown",
        "    parent = load_note(note_id)\n"
        "    q = Note.query.filter_by(id=note_id, owner_id=parent.owner_id)\n"
        "    return jsonify(q.first().title)\n",
        "unknown",
    ),
    (
        "a_read_by_another_value_is_no_id_read",
        "    return jsonify(Tag.query.filter_by(name=request.args['t']).first().name)\n",
        "unknown",
    ),
    (
        "id_handed_to_a_helper_is_not_followed",
        "    return jsonify(load_note(note_id).title)\n",
        "unknown",
    ),
    (
        "an_unread_filter_reads_unknown",
        "    return jsonify(Note.query.filter(Note.id.in_([note_id])).first().title)\n",
        "unknown",
    ),
    (
        "a_mutating_view_never_seeing_the_caller",
        "    db.session.delete(Note.query.get_or_404(note_id))\n"
        "    db.session.commit()\n"
        "    return '', 204\n",
        "caller-blind",
    ),
]


@pytest.mark.parametrize(("body", "ownership"), [c[1:] for c in CASES], ids=[c[0] for c in CASES])
def test_each_shape_reads_unknown_beside_a_twin_it_judges(
    tmp_path: Path, body: str, ownership: str
) -> None:
    found, judged = _note(tmp_path, _view(body))
    assert found == ownership
    assert judged == (ownership in ("caller-blind", "unchecked"))


def test_a_checkout_decorator_runs_first(tmp_path: Path) -> None:
    view = (
        "from .access import load_note as owns_note\n\n"
        '@bp.route("/notes/<int:note_id>")\n'
        "@login_required\n"
        "@owns_note\n"
        "def note(note_id):\n"
        "    return jsonify(Note.query.get_or_404(note_id).title)\n"
    )
    assert _note(tmp_path, view) == ("unknown", False)


@pytest.mark.parametrize(
    ("extra", "ownership"),
    [
        (
            {"app/ext.py": EXT.replace("SQLAlchemy()", "SQLAlchemy(query_class=OwnerQuery)")},
            "unknown",
        ),
        (
            {
                "app/models.py": MODELS.replace(
                    "    archived =", "    query_class = OwnerQuery\n    archived ="
                )
            },
            "unknown",
        ),
        (
            {
                "app/hooks.py": "from sqlalchemy import event\nfrom sqlalchemy.orm import Session, "
                "with_loader_criteria\n\n"
                '@event.listens_for(Session, "do_orm_execute")\n'
                "def scope(state):\n    state.statement = state.statement.options(\n"
                "        with_loader_criteria(Note, Note.owner_id == 1))\n"
            },
            "unknown",
        ),
        (
            {
                "app/hooks.py": "from .views import bp\nfrom flask import g, request\n\n"
                "@bp.before_request\n"
                "def load():\n    g.note = request.view_args.get('note_id')\n"
            },
            "unknown",
        ),
        (
            {
                "app/ext.py": EXT.replace("SQLAlchemy()", "SQLAlchemy(model_class=Mixin)")
                + "class Mixin:\n    def save(self): ...\n"
            },
            "caller-blind",
        ),
        (
            {
                "app/ext.py": EXT.replace(
                    "SQLAlchemy()", 'SQLAlchemy(session_options={"expire_on_commit": False})'
                )
            },
            "caller-blind",
        ),
    ],
    ids=[
        "query_class",
        "model_query_class",
        "session_criteria",
        "view_args_hook",
        "plain_model_class",
        "plain_session_options",
    ],
)
def test_what_may_narrow_every_read_reads_unknown(
    tmp_path: Path, extra: dict[str, str], ownership: str
) -> None:
    view = _view("    return jsonify(Note.query.get_or_404(note_id).title)\n")
    assert _note(tmp_path, view, **extra)[0] == ownership


def test_a_method_view_reads_its_methods_and_one_hop(tmp_path: Path) -> None:
    view = """
    from flask.views import MethodView

    class NoteAPI(MethodView):
        decorators = [login_required]

        def _load(self, note_id):
            return Note.query.get_or_404(note_id)

        def get(self, note_id):
            return jsonify(self._load(note_id).title)

        def delete(self, note_id):
            note = Note.query.filter_by(id=note_id, owner_id=current_user.id).first_or_404()
            db.session.delete(note)
            return "", 204

    bp.add_url_rule("/notes/<int:note_id>", view_func=NoteAPI.as_view("note"))
    """
    _write(
        tmp_path,
        {
            "app/ext.py": EXT,
            "app/models.py": MODELS,
            "app/views.py": HEAD + dedent(view),
            "app/access.py": "def load_note(note_id): ...\n",
        },
    )
    rows = _rows(tmp_path)
    assert rows[("GET", "/notes/<int:note_id>")] == ("caller-blind", True)
    assert rows[("DELETE", "/notes/<int:note_id>")] == ("unknown", False)


def test_a_method_view_with_its_own_dispatch_reads_unknown(tmp_path: Path) -> None:
    view = """
    from flask.views import MethodView

    class NoteAPI(MethodView):
        decorators = [login_required]

        def dispatch_request(self, **kwargs):
            return super().dispatch_request(**kwargs)

        def get(self, note_id):
            return jsonify(Note.query.get_or_404(note_id).title)

    bp.add_url_rule("/notes/<int:note_id>", view_func=NoteAPI.as_view("note"))
    """
    _write(
        tmp_path,
        {
            "app/ext.py": EXT,
            "app/models.py": MODELS,
            "app/views.py": HEAD + dedent(view),
            "app/access.py": "def load_note(note_id): ...\n",
        },
    )
    assert _rows(tmp_path)[("GET", "/notes/<int:note_id>")][0] == "unknown"


def test_a_blueprint_imported_from_the_checkout_is_a_library_registration(
    tmp_path: Path,
) -> None:
    _write(
        tmp_path,
        {
            "app/ext.py": EXT,
            "app/models.py": MODELS,
            "app/bp.py": 'from flask import Blueprint\n\nbp = Blueprint("notes", __name__)\n',
            "app/views.py": (
                "from flask import jsonify\nfrom flask_login import login_required\n"
                "from .bp import bp\nfrom .models import Note\n\n"
                + _view("    return jsonify(Note.query.get_or_404(note_id).title)\n")
            ),
        },
    )
    assert _rows(tmp_path)[("GET", "/notes/<int:note_id>")] == ("caller-blind", True)


ROUND1 = [
    (
        "sa_select",
        "import sqlalchemy as sa\n\n",
        "    return jsonify(db.first_or_404(sa.select(Note).where(Note.id == note_id)).title)\n",
        "caller-blind",
    ),
    (
        "db_select",
        "",
        "    return jsonify(db.one_or_404(db.select(Note).filter_by(id=note_id)).title)\n",
        "caller-blind",
    ),
    (
        "a_select_built_then_run",
        "",
        "    stmt = select(Note).where(Note.id == note_id)\n"
        "    return jsonify(db.session.scalars(stmt).first().title)\n",
        "caller-blind",
    ),
    (
        "a_with_session",
        "from sqlalchemy.orm import Session\nengine = None\n\n",
        "    with Session(engine) as s:\n        return jsonify(s.get(Note, note_id).title)\n",
        "caller-blind",
    ),
    (
        "get_one",
        "",
        "    return jsonify(db.session.get_one(Note, note_id).title)\n",
        "caller-blind",
    ),
    (
        "a_query_refined_by_the_caller_in_a_later_statement",
        "",
        "    q = Note.query.filter_by(id=note_id)\n"
        "    q = q.filter_by(owner_id=current_user.id)\n"
        "    return jsonify(q.first_or_404().title)\n",
        "unknown",
    ),
    (
        "flask_login_through_its_module",
        "import flask_login\n\n",
        "    note = Note.query.get_or_404(note_id)\n"
        "    return jsonify(note.title, flask_login.current_user.id)\n",
        "unchecked",
    ),
    (
        "g_bookkeeping_isnt_the_caller",
        "",
        "    note = Note.query.get_or_404(note_id)\n    return jsonify(note.title, g.request_id)\n",
        "caller-blind",
    ),
    (
        "a_checkout_call_not_reading_the_caller",
        "from .access import serialize\n\n",
        "    return jsonify(serialize(Note.query.get_or_404(note_id)))\n",
        "caller-blind",
    ),
    (
        "a_checkout_call_reading_the_caller",
        "from .access import owned\n\n",
        "    return jsonify(owned(Note.query.get_or_404(note_id)))\n",
        "unchecked",
    ),
]

ACCESS = (
    "from flask_login import current_user\n\n"
    "def load_note(note_id): ...\n\n"
    "def serialize(n):\n    return {'t': n.title}\n\n"
    "def owned(n):\n    return n.owner_id == current_user.id\n"
)


@pytest.mark.parametrize(
    ("imports", "body", "ownership"), [c[1:] for c in ROUND1], ids=[c[0] for c in ROUND1]
)
def test_the_forms_a_review_found(tmp_path: Path, imports: str, body: str, ownership: str) -> None:
    view = imports + _view(body)
    assert _note(tmp_path, view, **{"app/access.py": ACCESS})[0] == ownership


def test_a_directory_named_like_a_library_doesnt_make_it_the_checkouts(tmp_path: Path) -> None:
    extra = {"tests/flask/conftest.py": "x = 1\n", "docs/flask_login/conf.py": "x = 1\n"}
    view = _view("    return jsonify(Note.query.get_or_404(note_id).title)\n")
    assert _note(tmp_path, view, **extra) == ("caller-blind", True)


@pytest.mark.parametrize(
    ("hook", "ownership"),
    [
        (
            "lang = Blueprint('lang', __name__)\n\n"
            "@lang.url_value_preprocessor\n"
            "def pull(endpoint, values):\n    g.lang = values.pop('lang_code', None)\n",
            "caller-blind",
        ),
        (
            "@bp.url_value_preprocessor\n"
            "def pull(endpoint, values):\n    g.note = values.get('note_id')\n",
            "unknown",
        ),
        (
            "@bp.before_request\ndef check():\n    if request.view_args:\n        pass\n",
            "caller-blind",
        ),
        (
            "@bp.before_request\ndef check():\n    g.note = request.view_args['note_id']\n",
            "unknown",
        ),
    ],
    ids=["unrelated_blueprint", "own_blueprint_reads_the_id", "tests_only", "reads_the_id"],
)
def test_a_hook_hands_off_only_the_routes_whose_ids_it_reads(
    tmp_path: Path, hook: str, ownership: str
) -> None:
    view = _view("    return jsonify(Note.query.get_or_404(note_id).title)\n") + "\n" + hook
    assert _note(tmp_path, view)[0] == ownership


@pytest.mark.parametrize(
    "extra",
    [
        {"app/ext.py": EXT + "# TODO: consider with_loader_criteria, do_orm_execute\n"},
    ],
    ids=["a_comment"],
)
def test_text_alone_doesnt_narrow_every_read(tmp_path: Path, extra: dict[str, str]) -> None:
    view = _view("    return jsonify(Note.query.get_or_404(note_id).title)\n")
    assert _note(tmp_path, view, **extra) == ("caller-blind", True)


@pytest.mark.parametrize(
    "extra",
    [
        {"app/ext.py": EXT + "class TenantQuery: ...\ndb.Model.query_class = TenantQuery\n"},
        {
            "app/ext.py": EXT
            + "class TenantQuery: ...\nclass Base: ...\n"
            + "Base.query = db.session.query_property(TenantQuery)\n"
        },
        {
            "app/hooks.py": "from sqlalchemy import event\nfrom sqlalchemy.orm import Query\n\n"
            '@event.listens_for(Query, "before_compile", retval=True)\n'
            "def scope(query):\n    return query\n"
        },
    ],
    ids=["query_class_assigned", "positional_query_property", "before_compile"],
)
def test_narrowing_outside_the_view_reads_unknown(tmp_path: Path, extra: dict[str, str]) -> None:
    view = _view("    return jsonify(Note.query.get_or_404(note_id).title)\n")
    assert _note(tmp_path, view, **extra)[0] == "unknown"


def test_an_app_factory_route_is_read(tmp_path: Path) -> None:
    _write(
        tmp_path,
        {
            "app/ext.py": EXT,
            "app/models.py": MODELS,
            "app/__init__.py": (
                "from flask import Flask, jsonify\nfrom flask_login import login_required\n"
                "from .models import Note\n\n"
                "def create_app():\n"
                "    app = Flask(__name__)\n\n"
                '    @app.route("/notes/<int:note_id>")\n'
                "    @login_required\n"
                "    def note(note_id):\n"
                "        return jsonify(Note.query.get_or_404(note_id).title)\n\n"
                "    return app\n"
            ),
        },
    )
    assert _rows(tmp_path)[("GET", "/notes/<int:note_id>")] == ("caller-blind", True)


@pytest.mark.parametrize(
    "decorator",
    [
        "from flasgger import swag_from\n\n@swag_from('note.yml')\n",
        "from flask_pydantic import validate\n\n@validate()\n",
    ],
    ids=["swag_from", "validate"],
)
def test_documentation_and_validation_decorators_dont_stop_judging(
    tmp_path: Path, decorator: str
) -> None:
    view = (
        decorator.split("\n\n")[0]
        + "\n\n"
        + '@bp.route("/notes/<int:note_id>")\n@login_required\n'
        + decorator.split("\n\n")[1]
        + "def note(note_id):\n    return jsonify(Note.query.get_or_404(note_id).title)\n"
    )
    assert _note(tmp_path, view) == ("caller-blind", True)


@pytest.mark.parametrize(
    ("models", "ownership"),
    [
        (
            MODELS.replace(
                "    archived =", '    __mapper_args__ = {"eager_defaults": True}\n    archived ='
            ),
            "unchecked",
        ),
        (
            "from sqlalchemy.orm import Mapped, mapped_column\nfrom .ext import db\n\n\n"
            "class Note(db.Model):\n    id: Mapped[int] = mapped_column(primary_key=True)\n"
            "    owner_id: Mapped[int]\n\n\nclass Tag(db.Model):\n    id: Mapped[int]\n",
            "unchecked",
        ),
        (
            "from sqlalchemy.orm import declared_attr\nfrom .ext import db\n\n\n"
            "class Owned:\n    @declared_attr\n    def owner_id(cls):\n"
            "        return db.Column(db.Integer)\n\n\n"
            "class Note(Owned, db.Model):\n    id = db.Column(db.Integer, primary_key=True)\n\n\n"
            "class Tag(db.Model):\n    id = db.Column(db.Integer, primary_key=True)\n",
            "unchecked",
        ),
    ],
    ids=["mapper_args", "annotation_only_column", "declared_attr_mixin"],
)
def test_model_fields_the_reader_reads(tmp_path: Path, models: str, ownership: str) -> None:
    view = _view(
        "    note = Note.query.get_or_404(note_id)\n    return jsonify(note.id, current_user.id)\n"
    )
    assert _note(tmp_path, view, **{"app/models.py": models})[0] == ownership


def test_a_star_import_of_the_models_and_a_schema_namesake(tmp_path: Path) -> None:
    head = HEAD.replace("from .models import Note, Tag", "from .models import *")
    _write(
        tmp_path,
        {
            "app/ext.py": EXT,
            "app/models.py": MODELS,
            "app/schemas.py": "class Note:\n    title = None\n",
            "app/views.py": head
            + _view("    return jsonify(Note.query.get_or_404(note_id).title)\n"),
            "app/access.py": ACCESS,
        },
    )
    assert _rows(tmp_path)[("GET", "/notes/<int:note_id>")] == ("caller-blind", True)


def test_a_method_view_inheriting_its_verb_and_decorators(tmp_path: Path) -> None:
    base = (
        "from flask import jsonify\nfrom flask.views import MethodView\n"
        "from flask_login import login_required\nfrom .models import Note\n\n"
        "class NoteBase(MethodView):\n"
        "    decorators = [login_required]\n\n"
        "    def get(self, note_id):\n"
        "        return jsonify(Note.query.get_or_404(note_id).title)\n"
    )
    checked = base.replace(
        "    decorators = [login_required]",
        "    decorators = [owns_note, login_required]",
    ).replace(
        "from .models import Note",
        "from .models import Note\nfrom .access import load_note as owns_note",
    )
    for text, expected in ((base, ("caller-blind", True)), (checked, ("unknown", False))):
        root = tmp_path / str(len(text))
        _write(
            root,
            {
                "app/ext.py": EXT,
                "app/models.py": MODELS,
                "app/base.py": text,
                "app/access.py": ACCESS,
                "app/views.py": (
                    "from flask import Blueprint\nfrom .base import NoteBase\n\n"
                    "bp = Blueprint('notes', __name__)\n\n"
                    "class NoteAPI(NoteBase):\n    pass\n\n"
                    'bp.add_url_rule("/notes/<int:note_id>", view_func=NoteAPI.as_view("note"))\n'
                ),
            },
        )
        assert _rows(root)[("GET", "/notes/<int:note_id>")] == expected


def test_an_admin_only_role_decorator_is_out_of_scope(tmp_path: Path) -> None:
    view = (
        "from flask_security import roles_required\n\n"
        '@bp.route("/notes/<int:note_id>")\n'
        "@login_required\n"
        "@roles_required('admin')\n"
        "def note(note_id):\n"
        "    return jsonify(Note.query.get_or_404(note_id).title)\n"
    )
    assert _note(tmp_path, view)[0] == "n/a"


def test_flask_jwt_extendeds_current_user_is_the_caller(tmp_path: Path) -> None:
    view = "from flask_jwt_extended import current_user as jwt_user\n\n" + _view(
        "    note = Note.query.get_or_404(note_id)\n    return jsonify(note.title, jwt_user.id)\n"
    )
    assert _note(tmp_path, view)[0] == "unchecked"


READ_NOTE = "    return jsonify(Note.query.get_or_404(note_id).title)\n"


def _views(
    tmp_path: Path, views: str, **extra: str
) -> dict[tuple[str, str], tuple[str | None, bool]]:
    _write(
        tmp_path,
        {
            "app/ext.py": EXT,
            "app/models.py": MODELS,
            "app/access.py": ACCESS,
            "app/views.py": HEAD + dedent(views),
            **extra,
        },
    )
    return _rows(tmp_path)


def test_a_view_classs_own_dispatch_request_is_the_view(tmp_path: Path) -> None:
    rows = _views(
        tmp_path,
        """
        from flask.views import View

        class NoteView(View):
            decorators = [login_required]

            def dispatch_request(self, note_id):
                return jsonify(Note.query.get_or_404(note_id).title)

        bp.add_url_rule("/notes/<int:note_id>", view_func=NoteView.as_view("note"))
        """,
    )
    assert rows[("ANY", "/notes/<int:note_id>")] == ("caller-blind", True)


def test_a_generic_resource_reads_its_subclasss_model(tmp_path: Path) -> None:
    rows = _views(
        tmp_path,
        """
        from flask.views import MethodView

        class ModelResource(MethodView):
            decorators = [login_required]
            model = None

            def get(self, note_id):
                return jsonify(self.model.query.get_or_404(note_id).title)

        class NoteResource(ModelResource):
            model = Note

        bp.add_url_rule("/notes/<int:note_id>", view_func=NoteResource.as_view("note"))
        """,
    )
    assert rows[("GET", "/notes/<int:note_id>")] == ("caller-blind", True)


@pytest.mark.parametrize(
    ("body", "ownership"),
    [
        (
            "    s = SessionLocal()\n    return jsonify(s.get(Note, note_id).title)\n",
            "caller-blind",
        ),
        (
            "    with SqlSession(engine) as s:\n"
            "        rows = s.exec(select(Note).where(Note.id == note_id))\n"
            "        return jsonify(rows.first().title)\n",
            "caller-blind",
        ),
        (
            "    session = SessionLocal()\n    return jsonify(session.get(Note, note_id).title)\n",
            "caller-blind",
        ),
        (
            "    note = Note.query.get_or_404(note_id)\n"
            "    return jsonify(note.title, session.get('theme'))\n",
            "caller-blind",
        ),
        (
            "    note = Note.query.get_or_404(note_id)\n    return jsonify(note.title, g.me.id)\n",
            "unchecked",
        ),
        (
            "    note = Note.query.get_or_404(note_id)\n    return jsonify(note.title, me.id)\n",
            "unchecked",
        ),
        (
            "    note = Note.query.get_or_404(note_id)\n"
            "    return jsonify(note.title, decode_token(request.headers['X'])['sub'])\n",
            "unchecked",
        ),
    ],
    ids=[
        "app_sessionmaker",
        "sqlmodel_exec",
        "a_local_session_shadows_flasks",
        "a_session_key_not_the_callers",
        "g_me",
        "a_local_proxy",
        "decode_token",
    ],
)
def test_sessions_and_callers_a_second_review_found(
    tmp_path: Path, body: str, ownership: str
) -> None:
    head = (
        "from sqlalchemy.orm import sessionmaker\n"
        "from sqlmodel import Session as SqlSession\n"
        "from werkzeug.local import LocalProxy\n"
        "from flask_jwt_extended import decode_token\n"
        "engine = None\n"
        "SessionLocal = sessionmaker(bind=engine)\n"
        "me = LocalProxy(lambda: g.user)\n\n"
    )
    assert _note(tmp_path, head + _view(body), **{"app/access.py": ACCESS})[0] == ownership


@pytest.mark.parametrize(
    ("models", "views", "ownership"),
    [
        (
            MODELS.replace(
                "class Note(db.Model):\n    id = db.Column(db.Integer, primary_key=True)\n"
                '    owner_id = db.Column(db.Integer, db.ForeignKey("user.id"))\n'
                "    title = db.Column(db.String(100))\n"
                "    archived = db.Column(db.Boolean, default=False)\n",
                "class Note(db.Model):\n"
                "    __table__ = db.Table('note', db.metadata, autoload_with=None)\n",
            ),
            {},
            "caller-blind",
        ),
        (
            MODELS.replace("    archived =", "    query: 'Query'\n    archived ="),
            {},
            "caller-blind",
        ),
        (
            MODELS,
            {
                "app/zadmin/models.py": "from ..ext import db\n\n\n"
                "class Note(db.Model):\n    id = db.Column(db.Integer)\n"
            },
            "unchecked",
        ),
    ],
    ids=["unreadable_table", "annotated_query", "a_same_named_model_elsewhere"],
)
def test_models_a_second_review_found(
    tmp_path: Path, models: str, views: dict[str, str], ownership: str
) -> None:
    body = "    note = Note.query.get_or_404(note_id)\n    return jsonify(note.title)\n"
    if ownership == "unchecked":
        body = (
            "    note = Note.query.get_or_404(note_id)\n"
            "    return jsonify(note.title, current_user.id)\n"
        )
    assert _note(tmp_path, _view(body), **{"app/models.py": models, **views})[0] == ownership


@pytest.mark.parametrize(
    ("hook", "ownership"),
    [
        (
            "@bp.before_request\ndef log():\n"
            "    current_app.logger.debug('%s', request.view_args)\n",
            "caller-blind",
        ),
        (
            "@bp.before_request\ndef lang():\n    if 'lang' in request.view_args:\n        pass\n",
            "caller-blind",
        ),
        (
            "@bp.url_value_preprocessor\n"
            "def pull(endpoint, values):\n    if values is not None:\n"
            "        values.pop('lang', None)\n",
            "caller-blind",
        ),
        (
            "def check():\n    g.n = request.view_args['note_id']\n\nbp.before_request(check)\n",
            "unknown",
        ),
        (
            "from flask import Flask\nother = Flask('other')\n"
            "other.url_value_preprocessor(lambda e, v: None)\n",
            "caller-blind",
        ),
        (
            "import re\n\n@bp.before_request\ndef owns():\n"
            "    m = re.match(r'/notes/(\\\\d+)', request.path)\n"
            "    if m and current_user.id != 1:\n        abort(403)\n",
            "unknown",
        ),
        (
            "class Mw:\n    def __init__(self, app): ...\n\nbp.wsgi_app = Mw(bp.wsgi_app)\n",
            "unknown",
        ),
    ],
    ids=[
        "logging_hook",
        "membership_test",
        "none_test_and_other_key",
        "registered_by_call",
        "an_unrelated_apps_lambda",
        "a_path_parsing_caller_check",
        "checkout_wsgi_middleware",
    ],
)
def test_hooks_a_second_review_found(tmp_path: Path, hook: str, ownership: str) -> None:
    views = _view(READ_NOTE).replace("def note(", "def note(") + "\n" + hook
    head = "from flask import current_app\n"
    assert _note(tmp_path, head + views)[0] == ownership


def test_a_hook_on_a_blueprint_alias_or_its_parent_covers_its_routes(tmp_path: Path) -> None:
    hooks = (
        "from flask import Blueprint, abort, request\n"
        "from .views import bp as notes\n\n"
        "api = Blueprint('api', __name__)\n"
        "api.register_blueprint(notes)\n\n"
        "@api.before_request\n"
        "def check():\n    if request.view_args['note_id'] != 1:\n        abort(403)\n"
    )
    rows = _views(tmp_path, _view(READ_NOTE), **{"app/hooks.py": hooks})
    assert rows[("GET", "/notes/<int:note_id>")][0] == "unknown"


@pytest.mark.parametrize(
    "extra",
    [
        {
            "app/hooks.py": "from sqlalchemy import event\n"
            "from sqlalchemy.orm import Session\n\ndef scope(s): ...\n\n"
            "event.listen(Session, 'do_orm_execute', scope)\n"
        },
        {
            "app/hooks.py": "from sqlalchemy.orm import with_loader_criteria as wlc\n"
            "\ndef scope(s):\n    return wlc(None, None)\n"
        },
        {
            "app/ext.py": "from flask_sqlalchemy import SQLAlchemy as _SA\n\n\n"
            "class SQLAlchemy(_SA):\n    def __init__(self, **kw):\n"
            "        super().__init__(query_class=object, **kw)\n\n\n"
            "db = SQLAlchemy()\n"
        },
        {
            "app/ext.py": "from flask_sqlalchemy import SQLAlchemy\n\n"
            "db = SQLAlchemy(session_options={'class_': object})\n"
        },
    ],
    ids=[
        "event_listen",
        "aliased_with_loader_criteria",
        "query_class_in_a_subclass",
        "session_class",
    ],
)
def test_narrowing_a_second_review_found(tmp_path: Path, extra: dict[str, str]) -> None:
    assert _note(tmp_path, _view(READ_NOTE), **extra)[0] == "unknown"


@pytest.mark.parametrize(
    ("ext", "decorator", "ownership"),
    [
        ("admin_auth = HTTPTokenAuth()\n", "@admin_auth.login_required\n", "caller-blind"),
        ("ADMIN_ROLES = ['admin']\n", "@roles_required(*ADMIN_ROLES)\n", "caller-blind"),
        ("ADMIN = 'user'\n", "@roles_required(ADMIN)\n", "caller-blind"),
    ],
    ids=["an_admin_named_instance", "starred_roles", "a_role_constant"],
)
def test_admin_only_comes_from_literal_roles_never_names(
    tmp_path: Path, ext: str, decorator: str, ownership: str
) -> None:
    view = (
        "from flask_httpauth import HTTPTokenAuth\nfrom flask_security import roles_required\n"
        + ext
        + '\n@bp.route("/notes/<int:note_id>")\n@login_required\n'
        + decorator
        + "def note(note_id):\n"
        + READ_NOTE
    )
    assert _note(tmp_path, view)[0] == ownership


def test_layered_mixins_are_read_in_linear_time(tmp_path: Path) -> None:
    mixins = "".join(
        f"class M{i}({', '.join(f'M{j}' for j in range(max(0, i - 5), i)) or 'object'}):\n"
        f"    f{i} = db.Column(db.Integer)\n\n\n"
        for i in range(40)
    )
    models = MODELS + "\n\n" + mixins
    assert _note(tmp_path, _view(READ_NOTE), **{"app/models.py": models}) == ("caller-blind", True)
