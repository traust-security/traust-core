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


def _note(tmp_path: Path, body: str, **extra: str) -> tuple[str | None, bool]:
    view = "async def note(request):\n" + body
    _write(
        tmp_path,
        {
            "app/main.py": MAIN,
            "app/models.py": MODELS,
            "app/views.py": HEAD + view,
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
