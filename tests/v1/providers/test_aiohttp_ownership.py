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
