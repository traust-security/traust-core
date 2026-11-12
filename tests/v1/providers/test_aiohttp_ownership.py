"""Ownership of the object an aiohttp id route acts on. The reader judges only (D35): an id-only
read is judged, and every other shape, protected or not, reads unknown."""

from __future__ import annotations

from pathlib import Path
from textwrap import dedent

import pytest

from traust_core.v1.providers.route_guards import route_guards
from traust_core.v1.providers.tree import tree_files

MAIN = """
from aiohttp import web
from .views import note

@web.middleware
async def auth_middleware(request, handler):
    if "Authorization" not in request.headers:
        raise web.HTTPUnauthorized()
    return await handler(request)

app = web.Application(middlewares=[auth_middleware])
app.router.add_route("*", "/notes/{note_id}", note)
"""

MODELS = """
import sqlalchemy as sa
from sqlalchemy.orm import DeclarativeBase, Mapped, mapped_column

meta = sa.MetaData()

notes = sa.Table(
    "notes",
    meta,
    sa.Column("id", sa.Integer, primary_key=True),
    sa.Column("owner_id", sa.Integer),
    sa.Column("title", sa.String),
)


class Base(DeclarativeBase):
    pass


class Note(Base):
    __tablename__ = "orm_notes"
    id: Mapped[int] = mapped_column(primary_key=True)
    owner_id: Mapped[int] = mapped_column()
"""

HEAD = """
import aiohttp_security
import sqlalchemy as sa
from aiohttp import web
from aiohttp_security import authorized_userid
from aiohttp_session import get_session
from bson import ObjectId
from sqlalchemy import select
from .models import Note, notes
from .access import load_note

"""


def _write(root: Path, files: dict[str, str]) -> None:
    for rel, text in files.items():
        path = root / rel
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(dedent(text))


def _note(tmp_path: Path, body: str, imports: str = "", **extra: str) -> tuple[str | None, bool]:
    view = "async def note(request):\n" + body
    _write(
        tmp_path,
        {
            "app/main.py": MAIN,
            "app/models.py": MODELS,
            "app/views.py": HEAD + imports + view,
            "app/access.py": "async def load_note(note_id): ...\n",
            **extra,
        },
    )
    rows = [
        (r.ownership.value if r.ownership else None, r.judgement_required)
        for r in route_guards(tree_files(tmp_path)).routes
        if r.family.value == "aiohttp" and "{" in r.pattern
    ]
    assert len(rows) == 1, rows
    return rows[0]


ID = '    note_id = int(request.match_info["note_id"])\n'

CASES = [
    (
        "core_select_on_a_connection",
        ID + "    async with request.app['db'].acquire() as conn:\n"
        "        row = await conn.execute(notes.select().where(notes.c.id == note_id))\n"
        "        return web.json_response(dict(await row.first()))\n",
        "caller-blind",
    ),
    (
        "core_select_list_form",
        ID + "    async with request.app['db'].acquire() as conn:\n"
        "        row = await conn.execute(sa.select([notes]).where(notes.c.id == note_id))\n"
        "        return web.json_response(dict(await row.first()))\n",
        "caller-blind",
    ),
    (
        "orm_select",
        ID + "    async with request.app['session']() as s:\n"
        "        note = (await s.execute(select(Note).where(Note.id == note_id))).scalar_one()\n"
        "        return web.json_response({'id': note.id})\n",
        "caller-blind",
    ),
    (
        "literal_sql_asyncpg",
        '    note = await request.app["pool"].fetchrow(\n'
        '        "SELECT * FROM notes WHERE id = $1", request.match_info["note_id"]\n'
        "    )\n"
        "    return web.json_response(dict(note))\n",
        "caller-blind",
    ),
    (
        "literal_sql_aiopg",
        ID + "    async with request.app['db'].acquire() as conn:\n"
        '        await conn.execute("DELETE FROM notes WHERE id = %s", (note_id,))\n'
        "    return web.Response(status=204)\n",
        "caller-blind",
    ),
    (
        "motor_find_one",
        '    doc = await request.app["mongo"].notes.find_one(\n'
        '        {"_id": ObjectId(request.match_info["note_id"])}\n'
        "    )\n"
        "    return web.json_response(doc)\n",
        "caller-blind",
    ),
    (
        "id_only_read_beside_the_caller",
        ID + "    user_id = await authorized_userid(request)\n"
        "    async with request.app['db'].acquire() as conn:\n"
        "        row = await conn.execute(notes.select().where(notes.c.id == note_id))\n"
        "        return web.json_response({'note': dict(await row.first()), 'me': user_id})\n",
        "unchecked",
    ),
    (
        "a_hand_check_after_the_read_stays_judged",
        ID + "    user_id = await authorized_userid(request)\n"
        "    async with request.app['db'].acquire() as conn:\n"
        "        result = await conn.execute(notes.select().where(notes.c.id == note_id))\n"
        "        row = await result.first()\n"
        "    if row['owner_id'] != user_id:\n"
        "        raise web.HTTPForbidden()\n"
        "    return web.json_response(dict(row))\n",
        "unchecked",
    ),
    (
        "core_read_tied_to_the_caller",
        ID + "    user_id = await authorized_userid(request)\n"
        "    async with request.app['db'].acquire() as conn:\n"
        "        row = await conn.execute(\n"
        "            notes.select().where(notes.c.id == note_id)\n"
        "            .where(notes.c.owner_id == user_id)\n"
        "        )\n"
        "        return web.json_response(dict(await row.first()))\n",
        "unknown",
    ),
    (
        "sql_tied_to_the_session_user",
        "    session = await get_session(request)\n"
        '    note = await request.app["pool"].fetchrow(\n'
        '        "SELECT * FROM notes WHERE id = $1 AND owner_id = $2",\n'
        '        request.match_info["note_id"], session["user_id"],\n'
        "    )\n"
        "    return web.json_response(dict(note))\n",
        "unknown",
    ),
    (
        "motor_tied_to_the_request_user",
        '    doc = await request.app["mongo"].notes.find_one(\n'
        '        {"_id": ObjectId(request.match_info["note_id"]), "owner": request["user"]}\n'
        "    )\n"
        "    return web.json_response(doc)\n",
        "unknown",
    ),
    (
        "sql_with_an_or_reads_unknown",
        '    note = await request.app["pool"].fetchrow(\n'
        '        "SELECT * FROM notes WHERE id = $1 OR public", request.match_info["note_id"]\n'
        "    )\n"
        "    return web.json_response(dict(note))\n",
        "unknown",
    ),
    (
        "sql_with_a_comment_reads_unknown",
        '    note = await request.app["pool"].fetchrow(\n'
        '        "SELECT * FROM notes WHERE id = $1 -- AND owner_id = me",\n'
        '        request.match_info["note_id"],\n'
        "    )\n"
        "    return web.json_response(dict(note))\n",
        "unknown",
    ),
    (
        "motor_operator_filter_reads_unknown",
        '    doc = await request.app["mongo"].notes.find_one(\n'
        '        {"$or": [{"_id": request.match_info["note_id"]}, {"public": True}]}\n'
        "    )\n"
        "    return web.json_response(doc)\n",
        "unknown",
    ),
    (
        "id_handed_to_a_helper_is_not_followed",
        ID + "    return web.json_response(await load_note(note_id))\n",
        "unknown",
    ),
    (
        "a_mutating_view_never_seeing_the_caller",
        ID + "    async with request.app['db'].acquire() as conn:\n"
        "        await conn.execute(notes.delete().where(notes.c.id == note_id))\n"
        "    return web.Response(status=204)\n",
        "caller-blind",
    ),
]


@pytest.mark.parametrize(("body", "ownership"), [c[1:] for c in CASES], ids=[c[0] for c in CASES])
def test_each_shape_reads_unknown_beside_a_twin_it_judges(
    tmp_path: Path, body: str, ownership: str
) -> None:
    found, judged = _note(tmp_path, body)
    assert found == ownership
    assert judged == (ownership in ("caller-blind", "unchecked"))


def test_a_class_view_reads_self_request(tmp_path: Path) -> None:
    main = MAIN.replace("from .views import note", "from .views import NoteView").replace(
        'app.router.add_route("*", "/notes/{note_id}", note)',
        'app.router.add_view("/notes/{note_id}", NoteView)',
    )
    view = """
    class NoteView(web.View):
        async def get(self):
            note_id = int(self.request.match_info["note_id"])
            async with self.request.app["db"].acquire() as conn:
                row = await conn.execute(notes.select().where(notes.c.id == note_id))
                return web.json_response(dict(await row.first()))
    """
    _write(
        tmp_path,
        {
            "app/main.py": main,
            "app/models.py": MODELS,
            "app/views.py": HEAD + dedent(view),
            "app/access.py": "async def load_note(note_id): ...\n",
        },
    )
    rows = {
        (r.method, r.pattern): (r.ownership.value if r.ownership else None)
        for r in route_guards(tree_files(tmp_path)).routes
        if r.family.value == "aiohttp"
    }
    assert rows[("GET", "/notes/{note_id}")] == "caller-blind"


@pytest.mark.parametrize(
    ("middleware", "ownership"),
    [
        (
            "from aiohttp import web\n\n@web.middleware\nasync def loader(request, handler):\n"
            "    request['note'] = request.match_info.get('note_id')\n"
            "    return await handler(request)\n",
            "unknown",
        ),
        (
            "from aiohttp import web\n\n@web.middleware\nasync def namer(request, handler):\n"
            "    request['route'] = request.match_info.route.name\n"
            "    return await handler(request)\n",
            "caller-blind",
        ),
    ],
    ids=["reads_the_id", "reads_the_route_name"],
)
def test_middleware_reading_the_route_ids_runs_first(
    tmp_path: Path, middleware: str, ownership: str
) -> None:
    body = (
        ID + "    async with request.app['db'].acquire() as conn:\n"
        "        row = await conn.execute(notes.select().where(notes.c.id == note_id))\n"
        "        return web.json_response(dict(await row.first()))\n"
    )
    assert _note(tmp_path, body, **{"app/mw.py": middleware})[0] == ownership


TORTOISE = """
from tortoise import fields
from tortoise.models import Model


class Doc(Model):
    id = fields.IntField(pk=True)
    owner_id = fields.IntField()
"""

CORE = ID + "    async with request.app['db'].acquire() as conn:\n"

ROUND1 = [
    (
        "a_statement_bound_to_a_local",
        CORE + "        query = notes.select().where(notes.c.id == note_id)\n"
        "        row = await conn.execute(query)\n"
        "        return web.json_response(dict(await row.first()))\n",
        "caller-blind",
    ),
    (
        "a_select_of_columns",
        CORE + "        row = await conn.execute(\n"
        "            sa.select(notes.c.id, notes.c.title).where(notes.c.id == note_id)\n"
        "        )\n"
        "        return web.json_response(dict(await row.first()))\n",
        "caller-blind",
    ),
    (
        "sql_with_a_table_alias_and_a_cast",
        '    note = await request.app["pool"].fetchrow(\n'
        '        "SELECT n.* FROM notes n WHERE n.id = $1::int", request.match_info["note_id"]\n'
        "    )\n"
        "    return web.json_response(dict(note))\n",
        "caller-blind",
    ),
    (
        "sql_in_a_module_constant",
        '    note = await request.app["pool"].fetchrow(GET_NOTE, request.match_info["note_id"])\n'
        "    return web.json_response(dict(note))\n",
        "caller-blind",
    ),
    (
        "an_update_with_set_placeholders",
        ID + '    await request.app["pool"].execute(\n'
        '        "UPDATE notes SET title = $1 WHERE id = $2", "x", note_id\n'
        "    )\n"
        "    return web.Response(status=204)\n",
        "caller-blind",
    ),
    (
        "databases_named_values",
        ID + "    note = await request.app['database'].fetch_one(\n"
        '        "SELECT * FROM notes WHERE id = :id", values={"id": note_id}\n'
        "    )\n"
        "    return web.json_response(dict(note))\n",
        "caller-blind",
    ),
    (
        "databases_query_keyword",
        ID + "    note = await request.app['database'].fetch_one(\n"
        "        query=notes.select().where(notes.c.id == note_id)\n"
        "    )\n"
        "    return web.json_response(dict(note))\n",
        "caller-blind",
    ),
    (
        "a_schema_qualified_table_with_the_caller",
        "    me = await authorized_userid(request)\n"
        '    note = await request.app["pool"].fetchrow(\n'
        '        "SELECT * FROM public.notes WHERE id = $1", request.match_info["note_id"]\n'
        "    )\n"
        "    return web.json_response({'note': dict(note), 'me': me})\n",
        "unchecked",
    ),
    (
        "sql_on_an_orm_models_table_with_the_caller",
        "    me = await authorized_userid(request)\n"
        '    note = await request.app["pool"].fetchrow(\n'
        '        "SELECT * FROM orm_notes WHERE id = $1", request.match_info["note_id"]\n'
        "    )\n"
        "    return web.json_response({'note': dict(note), 'me': me})\n",
        "unchecked",
    ),
    (
        "motor_through_an_id_alias_and_a_filter_keyword",
        '    oid = ObjectId(request.match_info["note_id"])\n'
        '    doc = await request.app["mongo"].notes.find_one(filter={"_id": oid})\n'
        "    return web.json_response(doc)\n",
        "caller-blind",
    ),
    (
        "an_orm_session_from_app_state",
        ID + "    async with request.app['session']() as s:\n"
        "        note = await s.get(Note, note_id)\n"
        "        return web.json_response({'id': note.id})\n",
        "caller-blind",
    ),
    (
        "tortoise_get_and_filter",
        ID + "    a = await Doc.get(id=note_id)\n"
        "    b = await Doc.filter(id=note_id).first()\n"
        "    return web.json_response({'a': a.id, 'b': b.id})\n",
        "caller-blind",
    ),
    (
        "a_walrus_id",
        '    if (note_id := request.match_info.get("note_id")) is None:\n'
        "        raise web.HTTPNotFound()\n"
        "    async with request.app['db'].acquire() as conn:\n"
        "        row = await conn.execute(notes.select().where(notes.c.id == note_id))\n"
        "        return web.json_response(dict(await row.first()))\n",
        "caller-blind",
    ),
    (
        "a_join_in_the_from_clause_reads_unknown",
        '    note = await request.app["pool"].fetchrow(\n'
        '        "SELECT n.* FROM notes n JOIN acl a ON a.note_id = n.id WHERE id = $1",\n'
        '        request.match_info["note_id"],\n'
        "    )\n"
        "    return web.json_response(dict(note))\n",
        "unknown",
    ),
    (
        "an_aiohttp_security_object_check_sees_the_caller",
        CORE + "        result = await conn.execute(notes.select().where(notes.c.id == note_id))\n"
        "        row = await result.first()\n"
        "    await aiohttp_security.check_permission(request, 'note:read', context=row)\n"
        "    return web.json_response(dict(row))\n",
        "unchecked",
    ),
]


@pytest.mark.parametrize(("body", "ownership"), [c[1:] for c in ROUND1], ids=[c[0] for c in ROUND1])
def test_the_forms_a_review_found(tmp_path: Path, body: str, ownership: str) -> None:
    extra = {
        "app/models.py": MODELS,
        "app/tortoise_models.py": TORTOISE,
        "app/queries.py": 'GET_NOTE = "SELECT * FROM notes WHERE id = $1"\n',
    }
    imports = "from .tortoise_models import Doc\nfrom .queries import GET_NOTE\n"
    found = _note(tmp_path, body, imports, **extra)
    assert found[0] == ownership


def test_a_method_handler_takes_the_request_after_self(tmp_path: Path) -> None:
    main = MAIN.replace("from .views import note", "from .views import Handler").replace(
        'app.router.add_route("*", "/notes/{note_id}", note)',
        'h = Handler()\napp.router.add_route("*", "/notes/{note_id}", h.note)',
    )
    view = (
        "class Handler:\n"
        "    async def note(self, request):\n"
        '        note_id = int(request.match_info["note_id"])\n'
        "        async with request.app['db'].acquire() as conn:\n"
        "            row = await conn.execute(notes.select().where(notes.c.id == note_id))\n"
        "            return web.json_response(dict(await row.first()))\n"
    )
    _write(tmp_path, {"app/main.py": main, "app/models.py": MODELS, "app/views.py": HEAD + view})
    rows = [
        r.ownership.value
        for r in route_guards(tree_files(tmp_path)).routes
        if r.family.value == "aiohttp" and r.ownership
    ]
    assert rows == ["caller-blind"]


READ = CORE + (
    "        row = await conn.execute(notes.select().where(notes.c.id == note_id))\n"
    "        return web.json_response(dict(await row.first()))\n"
)


@pytest.mark.parametrize(
    ("extra", "ownership"),
    [
        (
            {
                "app/mw.py": "async def owner_factory(app, handler):\n"
                "    async def check(request):\n"
                "        request['n'] = request.match_info['note_id']\n"
                "        return await handler(request)\n"
                "    return check\n"
            },
            "unknown",
        ),
        (
            {
                "app/mw.py": "class NoteOwner:\n"
                "    async def __call__(self, request, handler):\n"
                "        request['n'] = request.match_info['note_id']\n"
                "        return await handler(request)\n"
            },
            "unknown",
        ),
        (
            {
                "app/mw.py": "from aiohttp import web\n"
                "from aiohttp_security import authorized_userid\n"
                "import re\n\n@web.middleware\nasync def owns(request, handler):\n"
                "    m = re.match(r'/notes/(\\d+)', request.path)\n"
                "    if m and await authorized_userid(request) != 1:\n"
                "        raise web.HTTPForbidden()\n"
                "    return await handler(request)\n"
            },
            "unknown",
        ),
        (
            {
                "app/mw.py": "from aiohttp import web\nfrom .checks import ensure_owner\n\n"
                "@web.middleware\nasync def owns(request, handler):\n"
                "    await ensure_owner(request)\n"
                "    return await handler(request)\n",
                "app/checks.py": "async def ensure_owner(request):\n"
                "    return request.match_info['note_id']\n",
            },
            "unknown",
        ),
        (
            {
                "tests/test_mw.py": "from aiohttp import web\n\n@web.middleware\n"
                "async def fake_middleware(request, handler):\n"
                "    request['n'] = request.match_info['note_id']\n"
                "    return await handler(request)\n"
            },
            "caller-blind",
        ),
        (
            {
                "app/flask_side.py": "from flask import Flask, g, request\n"
                "app2 = Flask(__name__)\n\n"
                "@app2.before_request\ndef load():\n    g.args = request.view_args\n"
            },
            "caller-blind",
        ),
        (
            {
                "app/orm_events.py": "from sqlalchemy import event\n"
                "from sqlalchemy.orm import Session\n\n"
                '@event.listens_for(Session, "do_orm_execute")\ndef scope(state): ...\n'
            },
            "unknown",  # it does narrow the Core read through a Session-backed engine
        ),
    ],
    ids=[
        "old_style_factory",
        "class_middleware",
        "path_parsing_caller_check",
        "a_checkout_call_reading_match_info",
        "a_test_file_middleware",
        "a_flask_hook_elsewhere",
        "a_session_criteria",
    ],
)
def test_middleware_a_review_found(tmp_path: Path, extra: dict[str, str], ownership: str) -> None:
    assert _note(tmp_path, READ, **extra)[0] == ownership


def test_a_session_criteria_never_reaches_literal_sql_or_mongo(tmp_path: Path) -> None:
    body = (
        '    note = await request.app["pool"].fetchrow(\n'
        '        "SELECT * FROM notes WHERE id = $1", request.match_info["note_id"]\n'
        "    )\n"
        "    return web.json_response(dict(note))\n"
    )
    events = (
        "from sqlalchemy import event\nfrom sqlalchemy.orm import Session\n\n"
        '@event.listens_for(Session, "do_orm_execute")\ndef scope(state): ...\n'
    )
    assert _note(tmp_path, body, **{"app/orm_events.py": events})[0] == "caller-blind"


def test_a_sub_apps_own_middleware_covers_only_its_routes(tmp_path: Path) -> None:
    main = MAIN + ("\nfrom .admin import admin_app\napp.add_subapp('/admin', admin_app)\n")
    admin = (
        "from aiohttp import web\n\n@web.middleware\nasync def admin_loader(request, handler):\n"
        "    request['n'] = request.match_info['note_id']\n"
        "    return await handler(request)\n\n"
        "admin_app = web.Application(middlewares=[admin_loader])\n"
    )
    assert (
        _note(tmp_path, READ, **{"app/main.py": main, "app/admin.py": admin})[0] == "caller-blind"
    )


POOL = (
    '    row = await request.app["pool"].fetchrow({sql}, note_id)\n'
    "    return web.json_response(dict(row))\n"
)
SQL = '"SELECT * FROM notes WHERE id = $1"'
CONN = (
    "    async with request.app['db'].acquire() as conn:\n"
    "        await conn.execute({stmt})\n"
    "    return web.Response()\n"
)
TORTOISE_Q = """
from tortoise import fields
from tortoise.models import Model
class Doc(Model):
    id = fields.IntField(pk=True)
    owner_id = fields.IntField()
"""
GINO = """
from gino import Gino
db = Gino()
class GNote(db.Model):
    __tablename__ = "gnotes"
    id = db.Column(db.Integer(), primary_key=True)
    owner_id = db.Column(db.Integer())
"""
ROUND2 = [
    # what an id-only read hides behind: each is judged now
    (
        "request_aliased",
        '    req = request\n    note_id = int(req.match_info["note_id"])\n'
        + POOL.format(sql=SQL).replace("request.app", "req.app"),
        "caller-blind",
    ),
    (
        "match_info_aliased",
        '    mi = request.match_info\n    note_id = int(mi["note_id"])\n' + POOL.format(sql=SQL),
        "caller-blind",
    ),
    ("sql_in_a_local", ID + f"    sql = {SQL}\n" + POOL.format(sql="sql"), "caller-blind"),
    ("sql_in_a_class_constant", ID + POOL.format(sql="Q.GET"), "caller-blind"),
    ("sql_trailing_semicolon", ID + POOL.format(sql=SQL[:-1] + ';"'), "caller-blind"),
    (
        "sa_text_with_values",
        ID + CONN.format(stmt='sa.text("SELECT * FROM notes WHERE id = :id"), {"id": note_id}'),
        "caller-blind",
    ),
    (
        "sa_update_core",
        ID + CONN.format(stmt="sa.update(notes).where(notes.c.id == note_id).values(title='x')"),
        "caller-blind",
    ),
    (
        "sa_delete_core",
        ID + CONN.format(stmt="sa.delete(notes).where(notes.c.id == note_id)"),
        "caller-blind",
    ),
    (
        "sa_delete_orm",
        ID + "    async with request.app['session']() as s:\n"
        "        await s.execute(sa.delete(Note).where(Note.id == note_id))\n"
        "    return web.Response()\n",
        "caller-blind",
    ),
    (
        "mongo_filter_in_a_local",
        '    q = {"_id": ObjectId(request.match_info["note_id"])}\n'
        '    return web.json_response(await request.app["db"].notes.find_one(q))\n',
        "caller-blind",
    ),
    (
        "gino_delete",
        ID + "    await GNote.delete.where(GNote.id == note_id).gino.status()\n"
        "    return web.Response()\n",
        "caller-blind",
    ),
    (
        "session_called_from_the_app",
        ID + "    s = request.app['Session']()\n"
        "    n = s.query(Note).filter(Note.id == note_id).first()\n"
        "    return web.json_response({'id': n.id})\n",
        "caller-blind",
    ),
    (
        "session_held_by_the_app",
        ID + "    session = request.app['session']\n    n = await session.get(Note, note_id)\n"
        "    return web.json_response({'id': n.id})\n",
        "caller-blind",
    ),
    (
        "deep_column_chain",
        ID + CONN.format(stmt="notes.select().where(notes" + ".c" * 2000 + " == note_id)"),
        "caller-blind",
    ),
    (
        "deep_and_chain",
        ID
        + CONN.format(
            stmt="notes.select().where(" + " & ".join(["(notes.c.id == note_id)"] * 1200) + ")"
        ),
        "caller-blind",
    ),
    # what may narrow or check what we don't read: unknown
    (
        "tortoise_q_tied_to_the_caller",
        ID + "    d = await TDoc.filter(Q(owner_id=request['user']), id=note_id).first()\n"
        "    return web.json_response({'id': d.id})\n",
        "unknown",
    ),
    (
        "tortoise_get_or_none_q",
        ID + "    d = await TDoc.get_or_none(Q(owner_id=request['user']), id=note_id)\n"
        "    return web.json_response({'id': d.id})\n",
        "unknown",
    ),
    (
        "tortoise_q_or",
        ID + "    d = await TDoc.filter(Q(public=True) | Q(shared=True), id=note_id).first()\n"
        "    return web.json_response({'id': d.id})\n",
        "unknown",
    ),
    (
        "tortoise_custom_manager",
        ID + "    d = await Doc.get(id=note_id)\n    return web.json_response({'id': d.id})\n",
        "unknown",
    ),
    (
        "checkout_function_named_like_a_driver",
        ID
        + "    row = await db.fetchrow("
        + SQL
        + ", note_id)\n    return web.json_response(dict(row))\n",
        "unknown",
    ),
    *(
        (
            name,
            "    me = await authorized_userid(request)\n"
            '    async with request.app["pool"].acquire() as conn:\n'
            f"        await conn.execute({setter})\n"
            '        row = await conn.fetchrow("SELECT * FROM notes WHERE id = $1", '
            'int(request.match_info["note_id"]))\n'
            "    return web.json_response(dict(row))\n",
            "unknown",
        )
        for name, setter in (
            (
                "row_level_security_set_config",
                "\"SELECT set_config('app.user_id', $1, true)\", str(me)",
            ),
            ("row_level_security_set_local", "f\"SET LOCAL app.user_id = '{int(me)}'\""),
        )
    ),
    # the caller seen only inside the write, or through a helper: unchecked
    (
        "caller_in_an_update_set",
        ID + '    await request.app["pool"].execute(\n'
        '        "UPDATE notes SET owner_id = $1 WHERE id = $2", request["user"], note_id\n'
        "    )\n    return web.Response()\n",
        "unchecked",
    ),
    (
        "caller_in_a_mongo_update",
        '    await request.app["db"].notes.update_one(\n'
        '        {"_id": ObjectId(request.match_info["note_id"])},\n'
        '        {"$set": {"editor": request["user"]}},\n'
        "    )\n    return web.Response()\n",
        "unchecked",
    ),
    (
        "caller_in_core_values",
        ID
        + CONN.format(
            stmt="notes.update().where(notes.c.id == note_id).values(owner_id=request['user'])"
        ),
        "unchecked",
    ),
    (
        "caller_through_a_checkout_helper",
        "    me = await current_user(request)\n" + ID + POOL.format(sql=SQL),
        "unchecked",
    ),
    (
        "caller_from_an_inline_session",
        "    me = (await get_session(request)).get('user_id')\n" + ID + POOL.format(sql=SQL),
        "unchecked",
    ),
]


@pytest.mark.parametrize(("body", "ownership"), [c[1:] for c in ROUND2], ids=[c[0] for c in ROUND2])
def test_the_forms_a_second_review_found(tmp_path: Path, body: str, ownership: str) -> None:
    manager = (
        "from tortoise import fields\nfrom tortoise.manager import Manager\n"
        "from tortoise.models import Model\n\n"
        "class TenantManager(Manager):\n    def get_queryset(self):\n"
        "        return super().get_queryset().filter(owner_id=1)\n\n"
        "class Doc(Model):\n    id = fields.IntField(pk=True)\n    owner_id = fields.IntField()\n\n"
        "    class Meta:\n        manager = TenantManager()\n"
    )
    extra = {
        "app/tortoise_models.py": manager,
        "app/tq.py": TORTOISE_Q,
        "app/gm.py": GINO,
        "app/queries.py": 'class Q:\n    GET = "SELECT * FROM notes WHERE id = $1"\n',
        "app/db.py": "async def fetchrow(sql, *args): ...\n",
        "app/auth.py": 'async def current_user(request):\n    return request["user"]\n',
    }
    imports = (
        "from tortoise.expressions import Q\nfrom . import db\nfrom .auth import current_user\n"
        "from .gm import GNote\nfrom .tortoise_models import Doc\nfrom .tq import Doc as TDoc\n"
    )
    if "Q.GET" in body:
        imports = "from .queries import Q\nfrom .gm import GNote\n"
    assert _note(tmp_path, body, imports, **extra)[0] == ownership


ALLOW_LIST = """
from aiohttp import web
from aiohttp_security import authorized_userid
from .views import note

PUBLIC = {"/login", "/health"}

@web.middleware
async def auth_middleware(request, handler):
    if request.path in PUBLIC or request.path.startswith("/static"):
        return await handler(request)
    if getattr(request.match_info.handler, "public", False):
        return await handler(request)
    user = await authorized_userid(request)
    if user is None:
        raise web.HTTPUnauthorized()
    request["user"] = user
    return await handler(request)

app = web.Application(middlewares=[auth_middleware])
app.router.add_route("*", "/notes/{note_id}", note)
"""
OWNER_MW = """
from aiohttp import web

@web.middleware
async def note_owner(request, handler):
    nid = request.match_info.get("note_id")
    if nid is not None and not await owns(request, nid):
        raise web.HTTPForbidden()
    return await handler(request)

async def owns(request, nid): ...
"""

METHOD_MW = """
from aiohttp import web
from .owners import owns

class OwnerCheck:
    def __init__(self, db):
        self.db = db

    @web.middleware
    async def check(self, request, handler):
        if not await owns(request, request.match_info.get("note_id")):
            raise web.HTTPForbidden()
        return await handler(request)
"""


def _main_with(middlewares: str) -> str:
    return MAIN.replace(
        "app = web.Application(middlewares=[auth_middleware])",
        f"from .mw import OwnerCheck\napp = web.Application(middlewares={middlewares})",
    )


@pytest.mark.parametrize(
    ("extra", "ownership"),
    [
        ({"app/main.py": ALLOW_LIST}, "caller-blind"),
        (
            {
                "app/main.py": _main_with("[auth_middleware, OwnerCheck(None).check]"),
                "app/mw.py": METHOD_MW,
                "app/owners.py": "async def owns(request, nid): ...\n",
            },
            "unknown",
        ),
        (
            {
                "app/main.py": MAIN.replace(
                    "app = web.Application(middlewares=[auth_middleware])\n"
                    'app.router.add_route("*", "/notes/{note_id}", note)',
                    "from .mw import note_owner\nfrom .routes import setup_routes\n\n"
                    "def create_app():\n"
                    "    app = web.Application(middlewares=[auth_middleware, note_owner])\n"
                    "    setup_routes(app)\n    return app\n",
                ),
                "app/mw.py": OWNER_MW,
                "app/routes.py": "from .views import note\n\ndef setup_routes(app):\n"
                '    app.router.add_get("/notes/{note_id}", note)\n',
            },
            "unknown",
        ),
    ],
    ids=["an_allow_list_compares_the_path", "a_method_middleware", "routes_added_in_a_helper"],
)
def test_middleware_a_second_review_found(
    tmp_path: Path, extra: dict[str, str], ownership: str
) -> None:
    assert _note(tmp_path, READ, **extra)[0] == ownership


def test_a_view_base_dispatching_in_iter_runs_first(tmp_path: Path) -> None:
    main = MAIN.replace("from .views import note", "from .views import NoteView").replace(
        'app.router.add_route("*", "/notes/{note_id}", note)',
        'app.router.add_view("/notes/{note_id}", NoteView)',
    )
    view = (
        "class OwnedView(web.View):\n"
        "    async def _iter(self):\n"
        '        if not await owns(self.request, self.request.match_info["note_id"]):\n'
        "            raise web.HTTPForbidden()\n"
        "        return await super()._iter()\n\n"
        "async def owns(request, nid): ...\n\n"
        "class NoteView({base}):\n"
        "    async def get(self):\n"
        '        note_id = int(self.request.match_info["note_id"])\n'
        "        async with self.request.app['db'].acquire() as conn:\n"
        "            row = await conn.execute(notes.select().where(notes.c.id == note_id))\n"
        "            return web.json_response(dict(await row.first()))\n"
    )
    found = {}
    for base in ("OwnedView", "web.View"):
        root = tmp_path / base
        _write(
            root,
            {
                "app/main.py": main,
                "app/models.py": MODELS,
                "app/views.py": HEAD + view.format(base=base),
            },
        )
        found[base] = [
            r.ownership.value
            for r in route_guards(tree_files(root)).routes
            if r.family.value == "aiohttp" and r.ownership
        ]
    assert found == {"OwnedView": ["unknown"], "web.View": ["caller-blind"]}


INSTALLED = """
from aiohttp import web
from .views import note
from .mw import OwnerCheck, owner_guard


@web.middleware
async def auth_middleware(request, handler):
    if "Authorization" not in request.headers:
        raise web.HTTPUnauthorized()
    return await handler(request)

{install}
app.router.add_route("*", "/notes/{{note_id}}", note)
"""
GUARDS = """
from aiohttp import web

async def owns(request, nid): ...

async def owner_guard(request, handler):
    if not await owns(request, request.match_info["note_id"]):
        raise web.HTTPForbidden()
    return await handler(request)

class OwnerCheck:
    def __init__(self, db):
        self.db = db

    async def check(self, request, handler):
        if not await owns(request, request.match_info.get("note_id")):
            raise web.HTTPForbidden()
        return await handler(request)
"""
FACTORY = """
from aiohttp import web
from .views import note

async def owns(request, nid): ...

@web.middleware
async def auth_middleware(request, handler):
    if "Authorization" not in request.headers:
        raise web.HTTPUnauthorized()
    return await handler(request)

def create_app():
    @web.middleware
    async def owner(request, handler):
        if not await owns(request, request.match_info["note_id"]):
            raise web.HTTPForbidden()
        return await handler(request)

    app = web.Application(middlewares=[auth_middleware{installed}])
    app.router.add_route("*", "/notes/{{note_id}}", note)
    return app
"""
PATH_LOCAL = """
from aiohttp import web
from aiohttp_security import authorized_userid
from .views import note

PUBLIC = {"/login"}

@web.middleware
async def auth_middleware(request, handler):
    path = request.path
    if path in PUBLIC:
        return await handler(request)
    if await authorized_userid(request) is None:
        raise web.HTTPUnauthorized()
    return await handler(request)

app = web.Application(middlewares=[auth_middleware])
app.router.add_route("*", "/notes/{note_id}", note)
"""


@pytest.mark.parametrize(
    ("extra", "ownership"),
    [
        *(
            ({"app/main.py": INSTALLED.format(install=install), "app/mw.py": GUARDS}, ownership)
            for install, ownership in (
                ("app = web.Application(middlewares=[auth_middleware])", "caller-blind"),
                (
                    "app = web.Application(middlewares=[auth_middleware])\n"
                    "app.middlewares.append(OwnerCheck(None).check)",
                    "unknown",
                ),
                (
                    "app = web.Application(middlewares=[auth_middleware])\n"
                    "app.middlewares.extend([owner_guard])",
                    "unknown",
                ),
                (
                    "app = web.Application(middlewares=[auth_middleware])\n"
                    "app.middlewares.insert(0, owner_guard)",
                    "unknown",
                ),
            )
        ),
        ({"app/main.py": FACTORY.format(installed=", owner")}, "unknown"),
        ({"app/main.py": PATH_LOCAL}, "caller-blind"),
        (
            {
                "app/util.py": "def log_middleware(request):\n"
                "    return request.match_info['note_id']\n"
            },
            "caller-blind",
        ),
    ],
    ids=[
        "uninstalled_guards",
        "an_appended_method",
        "extended",
        "inserted",
        "a_factorys_own_middleware",
        "a_path_local_only_compared",
        "a_helper_named_middleware",
    ],
)
def test_middleware_qodo_found(tmp_path: Path, extra: dict[str, str], ownership: str) -> None:
    assert _note(tmp_path, READ, **extra)[0] == ownership


def test_a_factory_middleware_installed_nowhere_reads_nothing(tmp_path: Path) -> None:
    main = FACTORY.format(installed="")
    assert _note(tmp_path, READ, **{"app/main.py": main})[0] == "caller-blind"


@pytest.mark.parametrize(
    ("body", "ownership"),
    [
        (
            '    me = request["user"]\n'
            '    d = await request.app["db"]["notes"].find_one(\n'
            '        {"_id": ObjectId(request.match_info["note_id"])}\n'
            "    )\n    return web.json_response(d)\n",
            "unchecked",
        ),
        (
            '    me = request["user"]\n'
            '    d = await request.app["db"].get_collection("notes").find_one(\n'
            '        {"_id": ObjectId(request.match_info["note_id"])}\n'
            "    )\n    return web.json_response(d)\n",
            "unchecked",
        ),
        (
            '    req = request\n    note_id = int(req.match_info["note_id"])\n\n'
            "    def inner():\n        req = None\n        return req\n\n"
            '    row = await req.app["pool"].fetchrow(\n'
            '        "SELECT * FROM notes WHERE id = $1", note_id\n'
            "    )\n"
            "    return web.json_response(dict(row))\n",
            "caller-blind",
        ),
        (
            ID + "    n = await GNote.query.where(GNote.id == note_id).gino.first()\n"
            "    return web.json_response({'id': n.id})\n",
            "caller-blind",
        ),
    ],
    ids=["a_bracketed_collection", "get_collection", "a_nested_rebinding", "gino_query"],
)
def test_reads_qodo_found(tmp_path: Path, body: str, ownership: str) -> None:
    assert _note(tmp_path, body, "from .gm import GNote\n", **{"app/gm.py": GINO})[0] == ownership


@pytest.mark.parametrize(
    ("check", "ownership"),
    [
        (
            '    if request.path in PUBLIC or request.path.startswith(("/static", "/a")):\n',
            "caller-blind",
        ),
        ("    path = request.path\n    if path == PUBLIC_ROOT:\n", "caller-blind"),
        ('    if not request.path.startswith(f"/users/{uid}/"):\n', "unknown"),
        ('    if request.path != f"/users/{uid}/notes":\n', "unknown"),
        ("    path = request.path\n    if not path.startswith(prefix(uid)):\n", "unknown"),
        ("    mine = f'/users/{uid}'\n    if not request.path.startswith(mine):\n", "unknown"),
    ],
    ids=[
        "fixed_allow_list",
        "fixed_local",
        "caller_prefix",
        "caller_compare",
        "caller_call_via_local",
        "caller_local_prefix",
    ],
)
def test_a_path_compared_with_the_caller_is_a_route_read(
    tmp_path: Path, check: str, ownership: str
) -> None:
    main = (
        "from aiohttp import web\nfrom aiohttp_security import authorized_userid\n"
        "from .views import note\n\n"
        'PUBLIC = {"/login"}\nPUBLIC_ROOT = "/"\n\n'
        "def prefix(uid):\n    return f'/users/{uid}/'\n\n"
        "@web.middleware\nasync def auth_middleware(request, handler):\n"
        "    uid = await authorized_userid(request)\n"
        "    if uid is None:\n        raise web.HTTPUnauthorized()\n"
        + check
        + "        raise web.HTTPForbidden()\n"
        "    return await handler(request)\n\n"
        "app = web.Application(middlewares=[auth_middleware])\n"
        'app.router.add_route("*", "/notes/{note_id}", note)\n'
    )
    assert _note(tmp_path, READ, **{"app/main.py": main})[0] == ownership


CLASS_GUARD = """
from aiohttp import web
from aiohttp_security import authorized_userid
from .views import note

PUBLIC = {{"/login"}}

class Guard:
    async def __call__(self, request, handler):
        uid = await authorized_userid(request)
        if uid is None:
            raise web.HTTPUnauthorized()
        self.expected = {expected}
        if request.path != self.expected:
            raise web.HTTPForbidden()
        return await handler(request)

app = web.Application(middlewares=[Guard()])
app.router.add_route("*", "/notes/{{note_id}}", note)
"""
NESTED_NAME = """
from aiohttp import web
from aiohttp_security import authorized_userid
from .views import note

PUBLIC = {"/login"}

@web.middleware
async def auth_middleware(request, handler):
    def unrelated():
        PUBLIC = set()
        return PUBLIC

    if request.path in PUBLIC:
        return await handler(request)
    if await authorized_userid(request) is None:
        raise web.HTTPUnauthorized()
    return await handler(request)

app = web.Application(middlewares=[auth_middleware])
app.router.add_route("*", "/notes/{note_id}", note)
"""


@pytest.mark.parametrize(
    ("main", "ownership"),
    [
        (CLASS_GUARD.format(expected='f"/notes/{uid}"'), "unknown"),
        (NESTED_NAME, "caller-blind"),
    ],
    ids=["a_method_attribute_from_the_caller", "a_nested_functions_namesake"],
)
def test_what_a_path_is_compared_with_is_read_in_its_own_scope(
    tmp_path: Path, main: str, ownership: str
) -> None:
    assert _note(tmp_path, READ, **{"app/main.py": main})[0] == ownership
