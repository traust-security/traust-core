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
