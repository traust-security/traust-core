"""Ownership of the object an axum or actix-web id route acts on: each allowed shape beside code
that looks protected but isn't, which must stay judged (or unknown)."""

from __future__ import annotations

import json
import time
from pathlib import Path
from textwrap import dedent

import pytest

from traust_core.v1.providers.route_guards import route_guards
from traust_core.v1.providers.rust_ownership import RustCode, _sql
from traust_core.v1.providers.tree import tree_files

CARGO = '[package]\nname = "app"\nversion = "0.1.0"\n'

AUTH = """
use axum::extract::{FromRequestParts, Request};
use axum::http::{request::Parts, StatusCode};
use axum::{middleware::Next, response::Response};

pub async fn require_auth(req: Request, next: Next) -> Result<Response, StatusCode> {
    Ok(next.run(req).await)
}

pub struct AuthUser {
    pub id: String,
    pub is_admin: bool,
}

impl<S: Send + Sync> FromRequestParts<S> for AuthUser {
    type Rejection = StatusCode;

    async fn from_request_parts(parts: &mut Parts, _state: &S) -> Result<Self, Self::Rejection> {
        parts.extensions.get::<AuthUser>().cloned().ok_or(StatusCode::UNAUTHORIZED)
    }
}

/// Trusts whatever the client puts in a header.
pub struct HeaderAuth {
    pub id: String,
}

impl<S: Send + Sync> FromRequestParts<S> for HeaderAuth {
    type Rejection = StatusCode;

    async fn from_request_parts(parts: &mut Parts, _state: &S) -> Result<Self, Self::Rejection> {
        let id = parts.headers.get("x-user-id").ok_or(StatusCode::UNAUTHORIZED)?;
        Ok(HeaderAuth { id: id.to_str().unwrap_or_default().to_string() })
    }
}

/// Decodes a signed token from the header.
pub struct TokenUser {
    pub id: String,
}

impl<S: Send + Sync> FromRequestParts<S> for TokenUser {
    type Rejection = StatusCode;

    async fn from_request_parts(parts: &mut Parts, _state: &S) -> Result<Self, Self::Rejection> {
        let raw = parts.headers.get("authorization").ok_or(StatusCode::UNAUTHORIZED)?;
        let key = jsonwebtoken::DecodingKey::from_secret(b"k");
        let claims = jsonwebtoken::decode::<Claims>(
            raw.to_str().unwrap_or_default(),
            &key,
            &jsonwebtoken::Validation::default(),
        )
        .map_err(|_| StatusCode::UNAUTHORIZED)?;
        Ok(TokenUser { id: claims.claims.sub })
    }
}

/// Hands the header to a library call we can't read.
pub struct VendorAuth {
    pub id: String,
}

impl<S: Send + Sync> FromRequestParts<S> for VendorAuth {
    type Rejection = StatusCode;

    async fn from_request_parts(parts: &mut Parts, _state: &S) -> Result<Self, Self::Rejection> {
        let raw = parts.headers.get("authorization").ok_or(StatusCode::UNAUTHORIZED)?;
        let claims = vendor_sdk::decode_token(raw.to_str().unwrap_or_default())?;
        Ok(VendorAuth { id: claims.sub })
    }
}
"""

MODELS = """
#[derive(sqlx::FromRow)]
pub struct Note {
    pub id: i64,
    pub owner: String,
    pub body: String,
}

pub struct Tag {
    pub id: i64,
    pub label: String,
}

pub struct User {
    pub id: String,
}
"""

STORE = """
use std::collections::HashMap;
use std::sync::{LazyLock, Mutex};

use crate::models::Note;

pub struct NoteStore(Mutex<HashMap<i64, Note>>);

pub static NOTES: LazyLock<NoteStore> = LazyLock::new(|| NoteStore(Mutex::new(HashMap::new())));

impl NoteStore {
    pub fn find(&self, id: i64) -> Option<Note> {
        self.0.lock().unwrap().get(&id).cloned()
    }

    pub fn find_for(&self, owner: &str, id: i64) -> Option<Note> {
        self.find(id).filter(|note| note.owner == owner)
    }

    pub fn find_any(&self, owner: &str, id: i64) -> Option<Note> {
        self.find(id).filter(|note| note.owner == owner || note.id > 0)
    }

    pub fn remove(&self, id: i64) {
        self.0.lock().unwrap().remove(&id);
    }
}
"""

SCHEMA = """
diesel::table! {
    notes (id) {
        id -> Int8,
        owner -> Text,
        body -> Text,
    }
}
"""

ENTITY = """
use sea_orm::entity::prelude::*;

#[derive(Clone, Debug, DeriveEntityModel)]
#[sea_orm(table_name = "note")]
pub struct Model {
    #[sea_orm(primary_key)]
    pub id: i64,
    pub owner: String,
}
"""

HEAD = """
use axum::{extract::{Extension, Path, State}, http::StatusCode, Json};
use sqlx::PgPool;

use crate::auth::{AuthUser, HeaderAuth, TokenUser, VendorAuth};
use crate::models::{Note, Tag, User};
use crate::store::NOTES;
use crate::schema::notes;
use crate::entity::note;
"""

MAIN = """
use axum::{{routing::{{delete, get, post, put}}, Router}};

mod auth;
mod entity;
mod handlers;
mod models;
mod schema;
mod store;

pub fn app() -> Router {{
    Router::new()
        .route("/a/:id", {verb}(handlers::h))
        .route_layer(axum::middleware::from_fn(auth::require_auth))
}}
"""


def _ownership(root: Path, handler: str, verb: str = "get", extra: dict | None = None) -> str:
    files = {
        "Cargo.toml": CARGO,
        "src/main.rs": MAIN.format(verb=verb),
        "src/auth.rs": AUTH,
        "src/models.rs": MODELS,
        "src/store.rs": STORE,
        "src/schema.rs": SCHEMA,
        "src/entity/mod.rs": "pub mod note;\n",
        "src/entity/note.rs": ENTITY,
        "src/handlers.rs": HEAD + dedent(handler),
        **(extra or {}),
    }
    for rel, text in files.items():
        path = root / rel
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(dedent(text))
    [row] = [
        r
        for r in route_guards(tree_files(root)).routes
        if r.family.value == "axum" and r.pattern == "/a/:id"
    ]
    return row.ownership.value if row.ownership else "None"


# Rust never credits (D34): the shapes it once credited read unknown, beside twins it judges
CASES = [
    # shape 1 (D27): a plain-equality query naming the caller
    (
        "sqlx-scoped",
        """
        pub async fn h(
            user: AuthUser,
            Path(id): Path<i64>,
            State(db): State<PgPool>,
        ) -> Result<Json<Note>, StatusCode> {
            let note = sqlx::query_as!(
                Note, "select * from note where id = $1 and owner = $2",
                id, user.id,
            )
                .fetch_one(&db).await.map_err(|_| StatusCode::NOT_FOUND)?;
            Ok(Json(note))
        }
        """,
        "unknown",
    ),
    (
        "sqlx-no-owner",
        """
        pub async fn h(
            user: AuthUser,
            Path(id): Path<i64>,
            State(db): State<PgPool>,
        ) -> Result<Json<Note>, StatusCode> {
            let note = sqlx::query_as!(Note, "select * from note where id = $1", id)
                .fetch_one(&db).await.map_err(|_| StatusCode::NOT_FOUND)?;
            Ok(Json(note))
        }
        """,
        "unchecked",
    ),
    (
        "sqlx-or-widens",
        """
        pub async fn h(
            user: AuthUser,
            Path(id): Path<i64>,
            State(db): State<PgPool>,
        ) -> Result<Json<Note>, StatusCode> {
            let note = sqlx::query_as!(
                Note, "select * from note where id = $1 and owner = $2 or true",
                id, user.id,
            )
                .fetch_one(&db).await.map_err(|_| StatusCode::NOT_FOUND)?;
            Ok(Json(note))
        }
        """,
        "unchecked",
    ),
    (
        "sqlx-owner-from-the-body",
        """
        pub async fn h(
            user: AuthUser,
            Path(id): Path<i64>,
            State(db): State<PgPool>,
            Json(q): Json<Note>,
        ) -> Result<Json<Note>, StatusCode> {
            let note = sqlx::query_as!(
                Note, "select * from note where id = $1 and owner = $2",
                id, q.owner,
            )
                .fetch_one(&db).await.map_err(|_| StatusCode::NOT_FOUND)?;
            Ok(Json(note))
        }
        """,
        "unchecked",
    ),
    (
        "sqlx-bind-scoped",
        """
        pub async fn h(
            user: AuthUser,
            Path(id): Path<i64>,
            State(db): State<PgPool>,
        ) -> StatusCode {
            sqlx::query("delete from note where id = $1 and owner = $2").bind(id).bind(&user.id)
                .execute(&db).await.ok();
            StatusCode::NO_CONTENT
        }
        """,
        "unknown",
    ),
    (
        "sqlx-bind-swapped",
        """
        pub async fn h(
            user: AuthUser,
            Path(id): Path<i64>,
            State(db): State<PgPool>,
        ) -> StatusCode {
            sqlx::query("delete from note where owner = $2 and id = $1").bind(&user.id).bind(id)
                .execute(&db).await.ok();
            StatusCode::NO_CONTENT
        }
        """,
        "unchecked",
    ),
    (
        "sqlx-cte-not-credited",
        """
        pub async fn h(
            user: AuthUser,
            Path(id): Path<i64>,
            State(db): State<PgPool>,
        ) -> StatusCode {
            sqlx::query!(
                "with d as (delete from note where id = $1 and owner = $2 returning 1) select 1",
                id, user.id,
            )
                .fetch_one(&db).await.ok();
            StatusCode::NO_CONTENT
        }
        """,
        "unknown",
    ),
    # shape 2 (D25) is not credited in Rust (D31): one read, then a refusal of a foreign record
    (
        "check-then-refuse",
        """
        pub async fn h(
            user: AuthUser,
            Path(id): Path<i64>,
            State(db): State<PgPool>,
        ) -> Result<StatusCode, StatusCode> {
            let note = sqlx::query_as!(Note, "select * from note where id = $1", id)
                .fetch_optional(&db).await.map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?
                .ok_or(StatusCode::NOT_FOUND)?;
            if note.owner != user.id {
                return Err(StatusCode::FORBIDDEN);
            }
            sqlx::query!("delete from note where id = $1", id).execute(&db).await.ok();
            Ok(StatusCode::NO_CONTENT)
        }
        """,
        "unchecked",
    ),
    (
        "check-only-logs",
        """
        pub async fn h(
            user: AuthUser,
            Path(id): Path<i64>,
            State(db): State<PgPool>,
        ) -> Result<StatusCode, StatusCode> {
            let note = sqlx::query_as!(Note, "select * from note where id = $1", id)
                .fetch_optional(&db).await.map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?
                .ok_or(StatusCode::NOT_FOUND)?;
            if note.owner != user.id {
                tracing::warn!("foreign note");
            }
            sqlx::query!("delete from note where id = $1", id).execute(&db).await.ok();
            Ok(StatusCode::NO_CONTENT)
        }
        """,
        "unchecked",
    ),
    (
        "check-answers-ok",
        """
        pub async fn h(
            user: AuthUser,
            Path(id): Path<i64>,
            State(db): State<PgPool>,
        ) -> Result<StatusCode, StatusCode> {
            let note = sqlx::query_as!(Note, "select * from note where id = $1", id)
                .fetch_optional(&db).await.map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?
                .ok_or(StatusCode::NOT_FOUND)?;
            if note.owner != user.id {
                return Ok(StatusCode::OK);
            }
            sqlx::query!("delete from note where id = $1", id).execute(&db).await.ok();
            Ok(StatusCode::NO_CONTENT)
        }
        """,
        "unchecked",
    ),
    (
        "check-after-the-write",
        """
        pub async fn h(
            user: AuthUser,
            Path(id): Path<i64>,
            State(db): State<PgPool>,
        ) -> Result<StatusCode, StatusCode> {
            sqlx::query!("delete from note where id = $1", id).execute(&db).await.ok();
            let note = sqlx::query_as!(Note, "select * from note where id = $1", id)
                .fetch_optional(&db).await.map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?
                .ok_or(StatusCode::NOT_FOUND)?;
            if note.owner != user.id {
                return Err(StatusCode::FORBIDDEN);
            }
            Ok(StatusCode::NO_CONTENT)
        }
        """,
        "unchecked",
    ),
    (
        "check-compares-with-the-path",
        """
        pub async fn h(
            user: AuthUser,
            Path((id, owner)): Path<(i64, String)>,
            State(db): State<PgPool>,
        ) -> Result<StatusCode, StatusCode> {
            let note = sqlx::query_as!(Note, "select * from note where id = $1", id)
                .fetch_optional(&db).await.map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?
                .ok_or(StatusCode::NOT_FOUND)?;
            if note.owner != owner {
                return Err(StatusCode::FORBIDDEN);
            }
            Ok(StatusCode::NO_CONTENT)
        }
        """,
        "unchecked",
    ),
    (
        "check-refuses-the-owner",
        """
        pub async fn h(
            user: AuthUser,
            Path(id): Path<i64>,
            State(db): State<PgPool>,
        ) -> Result<StatusCode, StatusCode> {
            let note = sqlx::query_as!(Note, "select * from note where id = $1", id)
                .fetch_optional(&db).await.map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?
                .ok_or(StatusCode::NOT_FOUND)?;
            if note.owner == user.id {
                return Err(StatusCode::FORBIDDEN);
            }
            Ok(StatusCode::NO_CONTENT)
        }
        """,
        "unchecked",
    ),
    (
        "check-let-else-then-ensure",
        """
        pub async fn h(
            user: AuthUser,
            Path(id): Path<i64>,
            State(db): State<PgPool>,
        ) -> anyhow::Result<Json<Note>> {
            let Some(note) = sqlx::query_as!(Note, "select * from note where id = $1", id)
                .fetch_optional(&db).await? else {
                anyhow::bail!("not found");
            };
            anyhow::ensure!(note.owner == user.id, "forbidden");
            Ok(Json(note))
        }
        """,
        "unchecked",
    ),
    (
        "check-ensure-the-wrong-way",
        """
        pub async fn h(
            user: AuthUser,
            Path(id): Path<i64>,
            State(db): State<PgPool>,
        ) -> anyhow::Result<Json<Note>> {
            let Some(note) = sqlx::query_as!(Note, "select * from note where id = $1", id)
                .fetch_optional(&db).await? else {
                anyhow::bail!("not found");
            };
            anyhow::ensure!(note.owner != user.id, "forbidden");
            Ok(Json(note))
        }
        """,
        "unchecked",
    ),
    # shape 2 as one match: the owned arm runs, every other arm refuses
    (
        "match-guard",
        """
        pub async fn h(user: AuthUser, Path(id): Path<i64>) -> StatusCode {
            match NOTES.find(id) {
                Some(note) if note.owner == user.id => {
                    NOTES.remove(id);
                    StatusCode::NO_CONTENT
                }
                _ => StatusCode::FORBIDDEN,
            }
        }
        """,
        "unchecked",
    ),
    (
        "match-other-arm-succeeds",
        """
        pub async fn h(user: AuthUser, Path(id): Path<i64>) -> StatusCode {
            match NOTES.find(id) {
                Some(note) if note.owner == user.id => {
                    NOTES.remove(id);
                    StatusCode::NO_CONTENT
                }
                _ => StatusCode::OK,
            }
        }
        """,
        "unchecked",
    ),
    (
        "match-no-guard",
        """
        pub async fn h(user: AuthUser, Path(id): Path<i64>) -> StatusCode {
            match NOTES.find(id) {
                Some(note) => {
                    NOTES.remove(id);
                    StatusCode::NO_CONTENT
                }
                None => StatusCode::NOT_FOUND,
            }
        }
        """,
        "unchecked",
    ),
    (
        "match-arm-acts-before-refusing",
        """
        pub async fn h(user: AuthUser, Path(id): Path<i64>) -> StatusCode {
            match NOTES.find(id) {
                Some(note) if note.owner == user.id => StatusCode::NO_CONTENT,
                _ => {
                    NOTES.remove(id);
                    StatusCode::FORBIDDEN
                }
            }
        }
        """,
        "unchecked",
    ),
    (
        "if-let-then-refuse",
        """
        pub async fn h(user: AuthUser, Path(id): Path<i64>) -> Result<StatusCode, StatusCode> {
            if let Some(note) = NOTES.find(id) {
                if note.owner != user.id {
                    return Err(StatusCode::FORBIDDEN);
                }
                NOTES.remove(id);
                Ok(StatusCode::NO_CONTENT)
            } else {
                Err(StatusCode::NOT_FOUND)
            }
        }
        """,
        "unchecked",
    ),
    # shape 5: a hop returning the record only when the caller owns it
    # a check inside a hop is never credited: only the handler's own code is (D30)
    (
        "hop-returns-only-owned",
        """
        pub async fn h(user: AuthUser, Path(id): Path<i64>) -> Result<Json<Note>, StatusCode> {
            NOTES.find_for(&user.id, id).map(Json).ok_or(StatusCode::NOT_FOUND)
        }
        """,
        "unchecked",
    ),
    (
        "hop-filter-with-an-or",
        """
        pub async fn h(user: AuthUser, Path(id): Path<i64>) -> Result<Json<Note>, StatusCode> {
            NOTES.find_any(&user.id, id).map(Json).ok_or(StatusCode::NOT_FOUND)
        }
        """,
        "unchecked",
    ),
    (
        "hop-plain-find",
        """
        pub async fn h(user: AuthUser, Path(id): Path<i64>) -> Result<Json<Note>, StatusCode> {
            NOTES.find(id).map(Json).ok_or(StatusCode::NOT_FOUND)
        }
        """,
        "unchecked",
    ),
    # diesel and sea-orm (D27)
    (
        "diesel-scoped",
        """
        pub async fn h(user: AuthUser, Path(id): Path<i64>) -> Result<Json<Note>, StatusCode> {
            let conn = &mut pool();
            let note = notes::table.find(id).filter(notes::owner.eq(&user.id)).first::<Note>(conn)
                .map_err(|_| StatusCode::NOT_FOUND)?;
            Ok(Json(note))
        }
        """,
        "unknown",
    ),
    (
        "diesel-by-id",
        """
        pub async fn h(user: AuthUser, Path(id): Path<i64>) -> Result<Json<Note>, StatusCode> {
            let conn = &mut pool();
            let note = notes::table.find(id)
                .first::<Note>(conn).map_err(|_| StatusCode::NOT_FOUND)?;
            Ok(Json(note))
        }
        """,
        "unchecked",
    ),
    (
        "diesel-or-filter",
        """
        pub async fn h(user: AuthUser, Path(id): Path<i64>) -> Result<Json<Note>, StatusCode> {
            let conn = &mut pool();
            let note = notes::table.find(id)
                .filter(notes::owner.eq(&user.id)).or_filter(notes::id.eq(id))
                .first::<Note>(conn).map_err(|_| StatusCode::NOT_FOUND)?;
            Ok(Json(note))
        }
        """,
        "unchecked",
    ),
    (
        "sea-orm-scoped",
        """
        pub async fn h(
            user: AuthUser,
            Path(id): Path<i64>,
            State(db): State<DatabaseConnection>,
        ) -> Result<StatusCode, StatusCode> {
            note::Entity::delete_by_id(id)
                .filter(note::Column::Owner.eq(&user.id)).exec(&db).await.ok();
            Ok(StatusCode::NO_CONTENT)
        }
        """,
        "unknown",
    ),
    (
        "sea-orm-by-id",
        """
        pub async fn h(
            user: AuthUser,
            Path(id): Path<i64>,
            State(db): State<DatabaseConnection>,
        ) -> Result<StatusCode, StatusCode> {
            note::Entity::delete_by_id(id).exec(&db).await.ok();
            Ok(StatusCode::NO_CONTENT)
        }
        """,
        "unchecked",
    ),
    # the caller (D26)
    (
        "no-caller",
        """
        pub async fn h(Path(id): Path<i64>) -> StatusCode {
            NOTES.remove(id);
            StatusCode::NO_CONTENT
        }
        """,
        "caller-blind",
    ),
    (
        "forged-caller",
        """
        pub async fn h(
            user: HeaderAuth,
            Path(id): Path<i64>,
            State(db): State<PgPool>,
        ) -> StatusCode {
            sqlx::query("delete from note where id = $1 and owner = $2").bind(id).bind(&user.id)
                .execute(&db).await.ok();
            StatusCode::NO_CONTENT
        }
        """,
        "caller-blind",
    ),
    (
        "decoded-caller",
        """
        pub async fn h(
            user: TokenUser,
            Path(id): Path<i64>,
            State(db): State<PgPool>,
        ) -> StatusCode {
            sqlx::query("delete from note where id = $1 and owner = $2").bind(id).bind(&user.id)
                .execute(&db).await.ok();
            StatusCode::NO_CONTENT
        }
        """,
        "unknown",
    ),
    (
        "unread-verifier",
        """
        pub async fn h(
            user: VendorAuth,
            Path(id): Path<i64>,
            State(db): State<PgPool>,
        ) -> StatusCode {
            sqlx::query("delete from note where id = $1 and owner = $2").bind(id).bind(&user.id)
                .execute(&db).await.ok();
            StatusCode::NO_CONTENT
        }
        """,
        "unknown",
    ),
    (
        "extension-caller",
        """
        pub async fn h(
            Extension(user): Extension<User>,
            Path(id): Path<i64>,
            State(db): State<PgPool>,
        ) -> StatusCode {
            sqlx::query("delete from note where id = $1 and owner = $2").bind(id).bind(&user.id)
                .execute(&db).await.ok();
            StatusCode::NO_CONTENT
        }
        """,
        "unknown",
    ),
    (
        "caller-rebound",
        """
        pub async fn h(
            user: AuthUser,
            Path(id): Path<i64>,
            State(db): State<PgPool>,
            Json(q): Json<Note>,
        ) -> StatusCode {
            let user = q;
            sqlx::query("delete from note where id = $1 and owner = $2").bind(id).bind(&user.owner)
                .execute(&db).await.ok();
            StatusCode::NO_CONTENT
        }
        """,
        "caller-blind",
    ),
    (
        "caller-from-an-unread-library",
        """
        pub async fn h(user: SomeLibraryAuth, Path(id): Path<i64>) -> StatusCode {
            NOTES.remove(id);
            StatusCode::NO_CONTENT
        }
        """,
        "unknown",
    ),
    # D28: a session bound to the caller is listed, not judged or credited
    (
        "caller-bound-session",
        """
        pub async fn h(
            user: AuthUser,
            Path(id): Path<i64>,
            State(db): State<UserDb>,
        ) -> StatusCode {
            let mut tx = db.begin(&user).await.unwrap();
            sqlx::query!("delete from note where id = $1", id).execute(&mut *tx).await.ok();
            StatusCode::NO_CONTENT
        }
        """,
        "unknown",
    ),
    (
        "plain-transaction",
        """
        pub async fn h(
            user: AuthUser,
            Path(id): Path<i64>,
            State(db): State<PgPool>,
        ) -> StatusCode {
            let mut tx = db.begin().await.unwrap();
            sqlx::query!("delete from note where id = $1", id).execute(&mut *tx).await.ok();
            StatusCode::NO_CONTENT
        }
        """,
        "unchecked",
    ),
    # D7: a kept load handed the caller; a dropped one isn't kept
    # a kept load we can't follow is never credited (D30 retires D7's credit in Rust)
    (
        "kept-load-handed-the-caller",
        """
        pub async fn h(
            user: AuthUser,
            Path(id): Path<i64>,
            State(repo): State<Repo>,
        ) -> Result<Json<Note>, StatusCode> {
            let note = repo.note_for(&user.id, id).await.map_err(|_| StatusCode::NOT_FOUND)?;
            Ok(Json(note))
        }
        """,
        "unknown",
    ),
    (
        "dropped-load",
        """
        pub async fn h(
            user: AuthUser,
            Path(id): Path<i64>,
            State(repo): State<Repo>,
        ) -> StatusCode {
            let _ = repo.wipe(&user.id, id).await;
            StatusCode::NO_CONTENT
        }
        """,
        "unknown",
    ),
    (
        "ownerless-record",
        """
        pub async fn h(
            user: AuthUser,
            Path(id): Path<i64>,
            State(db): State<PgPool>,
        ) -> Result<Json<Tag>, StatusCode> {
            let tag = sqlx::query_as!(Tag, "select * from tag where id = $1", id)
                .fetch_one(&db).await.map_err(|_| StatusCode::NOT_FOUND)?;
            Ok(Json(tag))
        }
        """,
        "unknown",
    ),
    (
        "alias-naming-itself",
        """
        pub type Result<T> = std::result::Result<T, StatusCode>;
        type NotePath = Path<i64>;

        pub async fn h(user: AuthUser, Path(id): NotePath) -> Result<StatusCode> {
            NOTES.remove(id);
            Ok(StatusCode::NO_CONTENT)
        }
        """,
        "unchecked",
    ),
    (
        "ignores-the-id",
        """
        pub async fn h(user: AuthUser) -> StatusCode {
            StatusCode::NO_CONTENT
        }
        """,
        "unknown",
    ),
]


@pytest.mark.parametrize(
    ("handler", "ownership"), [c[1:] for c in CASES], ids=[c[0] for c in CASES]
)
def test_each_shape_reads_unknown_beside_a_twin_it_judges(
    tmp_path: Path, handler: str, ownership: str
) -> None:
    assert _ownership(tmp_path, handler) == ownership


# Invented apps from independent reviews: code that looks protected while another user's object
# stays reachable, beside protected twins; Rust credits neither (D34), so each reads judged or
# unknown.
_REVIEW = Path(__file__).parents[2] / "fixtures/code_facts/rust_ownership_review.json"
_CASES = json.loads(_REVIEW.read_text())


@pytest.mark.parametrize(
    ("case", "method", "pattern", "ownership"),
    [(c["case"], e["method"], e["pattern"], e["ownership"]) for c in _CASES for e in c["expect"]],
)
def test_holes_a_review_found_stay_closed(
    tmp_path: Path, case: str, method: str, pattern: str, ownership: str | list[str]
) -> None:
    for rel, text in next(c["files"] for c in _CASES if c["case"] == case).items():
        path = tmp_path / rel
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(dedent(text))
    found = sorted(
        r.ownership.value if r.ownership else "None"
        for r in route_guards(tree_files(tmp_path)).routes
        if r.method == method and r.pattern == pattern
    )
    assert found == (ownership if isinstance(ownership, list) else [ownership])


def test_a_caller_extension_copied_from_a_header_is_no_caller(tmp_path: Path) -> None:
    middleware = """
        use axum::{extract::Request, http::StatusCode, middleware::Next, response::Response};
        use crate::auth::AuthUser;
        pub async fn from_header(mut req: Request, next: Next) -> Result<Response, StatusCode> {
            let id = req.headers().get("x-user-id").and_then(|v| v.to_str().ok()).unwrap_or("");
            let user = AuthUser { id: id.to_string(), is_admin: false };
            req.extensions_mut().insert(user);
            Ok(next.run(req).await)
        }
        """
    handler = """
        pub async fn h(
            Extension(user): Extension<AuthUser>,
            Path(id): Path<i64>,
            State(db): State<PgPool>,
        ) -> Result<Json<Note>, StatusCode> {
            let note = sqlx::query_as!(
                Note, "select * from note where id = $1 and owner = $2", id, user.id,
            )
                .fetch_one(&db).await.map_err(|_| StatusCode::NOT_FOUND)?;
            Ok(Json(note))
        }
        """
    # the owner it binds is whatever the client sent: the route is judged, not settled
    assert _ownership(tmp_path, handler, extra={"src/header.rs": middleware}) == "caller-blind"


def test_a_caller_extension_beside_an_unrelated_verifier_is_no_caller(tmp_path: Path) -> None:
    middleware = """
        use axum::{extract::Request, http::StatusCode, middleware::Next, response::Response};
        use crate::auth::AuthUser;
        pub async fn from_header(mut req: Request, next: Next) -> Result<Response, StatusCode> {
            let service = vendor_sdk::load_user("svc").await.map_err(|_| StatusCode::UNAUTHORIZED)?;
            tracing::debug!(?service);
            let id = req.headers().get("x-user-id").and_then(|v| v.to_str().ok()).unwrap_or("");
            let user = AuthUser { id: id.to_string(), is_admin: false };
            req.extensions_mut().insert(user);
            Ok(next.run(req).await)
        }
        """
    handler = """
        pub async fn h(
            Extension(user): Extension<AuthUser>,
            Path(id): Path<i64>,
            State(db): State<PgPool>,
        ) -> Result<Json<Note>, StatusCode> {
            let note = sqlx::query_as!(
                Note, "select * from note where id = $1 and owner = $2", id, user.id,
            )
                .fetch_one(&db).await.map_err(|_| StatusCode::NOT_FOUND)?;
            Ok(Json(note))
        }
        """
    # the verifier's result is not what goes into the extensions
    assert _ownership(tmp_path, handler, extra={"src/header.rs": middleware}) == "caller-blind"


@pytest.mark.parametrize(
    "literal",
    [
        "select * from note where id = $1 and owner = $" + "9" * 5000,
        "select * from note where id = $1 and owner = $2 and body = '\\u{110000}'",
        "select * from note where id = $1 and owner = $2 and body = '\\u{ffffffffffffffffff}'",
    ],
    ids=["oversized-placeholder", "escape-past-unicode", "escape-past-any-int"],
)
def test_malformed_sql_is_judged_unread_instead_of_aborting_the_scan(
    tmp_path: Path, literal: str
) -> None:
    handler = f"""
        pub async fn h(
            user: AuthUser,
            Path(id): Path<i64>,
            State(db): State<PgPool>,
        ) -> Result<Json<Note>, StatusCode> {{
            let note = sqlx::query_as!(Note, "{literal}", id, user.id)
                .fetch_one(&db).await.map_err(|_| StatusCode::NOT_FOUND)?;
            Ok(Json(note))
        }}
        """
    assert _ownership(tmp_path, handler) == "unchecked"


@pytest.mark.parametrize(
    "sql",
    ['select * from \\"notes\\" where id = $1', "select * from note where id = $1"],
    ids=["quoted-diesel-table", "table-named-like-the-struct"],
)
def test_an_unscoped_read_finds_its_record_through_the_table_spelling(
    tmp_path: Path, sql: str
) -> None:
    handler = f"""
        pub async fn h(
            user: AuthUser,
            Path(id): Path<i64>,
            State(db): State<PgPool>,
        ) -> Result<StatusCode, StatusCode> {{
            sqlx::query("{sql}").bind(id).fetch_one(&db).await.map_err(|_| StatusCode::NOT_FOUND)?;
            Ok(StatusCode::OK)
        }}
        """
    # no sea-orm entity keyed `note`: only the `Note` struct and diesel's `notes` name the table
    extra = {"src/entity/note.rs": "pub struct Model;\n"}
    assert _ownership(tmp_path, handler, extra=extra) == "unchecked"


def test_a_local_find_by_id_helper_is_followed_not_read_as_sea_orm(tmp_path: Path) -> None:
    handler = """
        async fn find_by_id(id: i64, db: &PgPool) -> Option<Note> {
            sqlx::query_as!(Note, "select * from note where id = $1", id)
                .fetch_optional(db).await.ok().flatten()
        }

        pub async fn h(
            user: AuthUser,
            Path(id): Path<i64>,
            State(db): State<PgPool>,
        ) -> Result<Json<Note>, StatusCode> {
            find_by_id(id, &db).await.map(Json).ok_or(StatusCode::NOT_FOUND)
        }
        """
    assert _ownership(tmp_path, handler) == "unchecked"


def test_glob_cycles_resolve_each_module_once(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    calls: list[list[str]] = []
    target = RustCode._target

    def counted(self: RustCode, full: list[str], *args: object, **kwargs: object) -> object:
        calls.append(full)
        return target(self, full, *args, **kwargs)  # type: ignore[arg-type]

    monkeypatch.setattr(RustCode, "_target", counted)
    modules = [f"m{i}" for i in range(6)]
    extra = {f"src/{m}.rs": "use super::*;\nuse crate::*;\n" for m in modules}
    extra["src/lib.rs"] = "".join(f"pub mod {m};\npub use crate::{m}::*;\n" for m in modules)
    handler = """
        use crate::*;
        pub async fn h(user: AuthUser, Path(id): Path<i64>) -> StatusCode {
            missing(id);
            StatusCode::NO_CONTENT
        }
        """
    _ownership(tmp_path, handler, extra=extra)
    assert len(calls) < 500


def test_a_long_where_clause_parses_in_linear_time() -> None:
    n = 40000
    sql = (
        "select extract(epoch from a) "
        + "".join(f", trim(both from c{i})" for i in range(n))
        + " from note where "
        + " and ".join(f"c{i} = ?" for i in range(n))
    )
    started = time.perf_counter()
    parsed = _sql(sql)
    assert time.perf_counter() - started < 2
    assert parsed.table == "note" and parsed.equalities == tuple((f"c{i}", i) for i in range(n))


@pytest.mark.parametrize(
    ("bind", "ownership"),
    [
        ("let u = user.unwrap();", "unknown"),
        ('let u = user.expect("login");', "unknown"),
        ("let u = user.ok_or(StatusCode::UNAUTHORIZED)?;", "unknown"),
        ("let u = user.unwrap_or(AuthUser { id: String::new(), is_admin: false });", "unchecked"),
    ],
    ids=["unwrap", "expect", "ok-or-refused", "fallback"],
)
def test_an_optional_caller_refused_when_absent_is_a_caller(
    tmp_path: Path, bind: str, ownership: str
) -> None:
    handler = f"""
        pub async fn h(
            user: Option<AuthUser>,
            Path(id): Path<i64>,
            State(db): State<PgPool>,
        ) -> Result<Json<Note>, StatusCode> {{
            {bind}
            let note = sqlx::query_as!(
                Note, "select * from note where id = $1 and owner = $2", id, u.id,
            )
                .fetch_one(&db).await.map_err(|_| StatusCode::NOT_FOUND)?;
            Ok(Json(note))
        }}
        """
    assert _ownership(tmp_path, handler) == ownership


_OWNER_READ = """
    pub async fn h(
        Extension(user): Extension<AuthUser>,
        Path(id): Path<i64>,
        State(db): State<PgPool>,
    ) -> Result<Json<Note>, StatusCode> {
        let note = sqlx::query_as!(
            Note, "select * from note where id = $1 and owner = $2", id, user.id,
        )
            .fetch_one(&db).await.map_err(|_| StatusCode::NOT_FOUND)?;
        Ok(Json(note))
    }
    """


def test_a_caller_extension_with_a_header_fallback_is_no_caller(tmp_path: Path) -> None:
    middleware = """
        use axum::{extract::Request, http::StatusCode, middleware::Next, response::Response};
        use crate::auth::AuthUser;
        pub async fn from_header(mut req: Request, next: Next) -> Result<Response, StatusCode> {
            let id = req.headers().get("x-user-id").and_then(|v| v.to_str().ok()).unwrap_or("");
            let existing = req.extensions().get::<AuthUser>().cloned();
            let user = existing.unwrap_or(AuthUser { id: id.to_string(), is_admin: false });
            req.extensions_mut().insert(user);
            Ok(next.run(req).await)
        }
        """
    extra = {"src/header.rs": middleware}
    assert _ownership(tmp_path, _OWNER_READ, extra=extra) == "caller-blind"


def test_an_extractor_reading_a_caller_copied_from_a_header_is_no_caller(tmp_path: Path) -> None:
    middleware = """
        use axum::{extract::Request, http::StatusCode, middleware::Next, response::Response};
        use crate::auth::AuthUser;
        pub async fn from_header(mut req: Request, next: Next) -> Result<Response, StatusCode> {
            let id = req.headers().get("x-user-id").and_then(|v| v.to_str().ok()).unwrap_or("");
            req.extensions_mut().insert(AuthUser { id: id.to_string(), is_admin: false });
            Ok(next.run(req).await)
        }
        """
    handler = """
        pub async fn h(
            user: AuthUser,
            Path(id): Path<i64>,
            State(db): State<PgPool>,
        ) -> Result<Json<Note>, StatusCode> {
            let note = sqlx::query_as!(
                Note, "select * from note where id = $1 and owner = $2", id, user.id,
            )
                .fetch_one(&db).await.map_err(|_| StatusCode::NOT_FOUND)?;
            Ok(Json(note))
        }
        """
    # `AuthUser`'s extractor reads the extension the middleware filled from the header
    assert _ownership(tmp_path, handler, extra={"src/header.rs": middleware}) == "caller-blind"


def test_a_from_inside_a_dollar_quoted_literal_is_not_the_table(tmp_path: Path) -> None:
    handler = """
        pub async fn h(
            user: AuthUser,
            Path(id): Path<i64>,
            State(db): State<PgPool>,
        ) -> Result<StatusCode, StatusCode> {
            sqlx::query("select $$ from fake $$, id from note where id = $1")
                .bind(id).fetch_one(&db).await.map_err(|_| StatusCode::NOT_FOUND)?;
            Ok(StatusCode::OK)
        }
        """
    assert _ownership(tmp_path, handler) == "unchecked"


def test_an_aliased_sqlx_query_is_read(tmp_path: Path) -> None:
    handler = """
        use sqlx::query as fetch_query;

        pub async fn h(
            user: AuthUser,
            Path(id): Path<i64>,
            State(db): State<PgPool>,
        ) -> Result<StatusCode, StatusCode> {
            fetch_query("select * from note where id = $1")
                .bind(id).fetch_one(&db).await.map_err(|_| StatusCode::NOT_FOUND)?;
            Ok(StatusCode::OK)
        }
        """
    assert _ownership(tmp_path, handler) == "unchecked"


def test_an_extractor_querying_its_own_client_still_reads_a_caller(tmp_path: Path) -> None:
    extractor = """
        use axum::{extract::FromRequestParts, http::{request::Parts, StatusCode}};
        use crate::auth::AuthUser;
        pub struct AuthenticatedUser {
            pub id: String,
        }
        impl<S: Send + Sync> FromRequestParts<S> for AuthenticatedUser {
            type Rejection = StatusCode;
            async fn from_request_parts(
                parts: &mut Parts,
                state: &S,
            ) -> Result<Self, Self::Rejection> {
                let u = parts.extensions.get::<AuthUser>().cloned();
                let u = u.ok_or(StatusCode::UNAUTHORIZED)?;
                let client = state.audit.get().await.map_err(|_| StatusCode::UNAUTHORIZED)?;
                client.query("insert into seen (who) values ($1)", &[&u.id]).await.ok();
                Ok(AuthenticatedUser { id: u.id })
            }
        }
        """
    handler = """
        use crate::current::AuthenticatedUser;

        pub async fn h(
            user: AuthenticatedUser,
            Path(id): Path<i64>,
            State(db): State<PgPool>,
        ) -> Result<Json<Note>, StatusCode> {
            let note = sqlx::query_as!(
                Note, "select * from note where id = $1 and owner = $2", id, user.id,
            )
                .fetch_one(&db).await.map_err(|_| StatusCode::NOT_FOUND)?;
            Ok(Json(note))
        }
        """
    # its own client's `query` is no client input: the caller stands (scoped, so unknown, D34)
    assert _ownership(tmp_path, handler, extra={"src/current.rs": extractor}) == "unknown"


def test_a_verified_token_beside_a_client_picked_identity_is_no_caller(tmp_path: Path) -> None:
    extractor = """
        use axum::{extract::FromRequestParts, http::{request::Parts, StatusCode}};
        pub struct AuthedUser {
            pub id: String,
        }
        impl<S: Send + Sync> FromRequestParts<S> for AuthedUser {
            type Rejection = StatusCode;
            async fn from_request_parts(
                parts: &mut Parts,
                _state: &S,
            ) -> Result<Self, Self::Rejection> {
                let raw = parts.headers.get("authorization").ok_or(StatusCode::UNAUTHORIZED)?;
                let raw = raw.to_str().map_err(|_| StatusCode::UNAUTHORIZED)?;
                let (token, who) = raw.split_once(':').ok_or(StatusCode::UNAUTHORIZED)?;
                let key = jsonwebtoken::DecodingKey::from_secret(b"k");
                jsonwebtoken::decode::<Claims>(token, &key, &jsonwebtoken::Validation::default())
                    .map_err(|_| StatusCode::UNAUTHORIZED)?;
                Ok(AuthedUser { id: who.to_string() })
            }
        }
        """
    handler = """
        use crate::authed::AuthedUser;

        pub async fn h(
            user: AuthedUser,
            Path(id): Path<i64>,
            State(db): State<PgPool>,
        ) -> Result<Json<Note>, StatusCode> {
            let note = sqlx::query_as!(
                Note, "select * from note where id = $1 and owner = $2", id, user.id,
            )
                .fetch_one(&db).await.map_err(|_| StatusCode::NOT_FOUND)?;
            Ok(Json(note))
        }
        """
    # the token is verified, but who the caller is comes from the unsigned half of the header
    assert _ownership(tmp_path, handler, extra={"src/authed.rs": extractor}) == "caller-blind"


def test_indexing_a_client_sent_list_by_the_id_is_no_lookup(tmp_path: Path) -> None:
    handler = """
        pub async fn h(
            user: AuthUser,
            Path(id): Path<usize>,
            Json(items): Json<Vec<Note>>,
        ) -> Result<Json<Note>, StatusCode> {
            Ok(Json(items[id].clone()))
        }
        """
    assert _ownership(tmp_path, handler, verb="post") == "unknown"


def test_an_uncredited_row_carries_no_evidence_of_protection(tmp_path: Path) -> None:
    assert _ownership(tmp_path, dict((c[0], c[1]) for c in CASES)["sqlx-scoped"]) == "unknown"
    [row] = [r for r in route_guards(tree_files(tmp_path)).routes if r.pattern == "/a/:id"]
    assert row.ownership_evidence is None
