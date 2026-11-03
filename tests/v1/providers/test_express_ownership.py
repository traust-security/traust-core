"""Ownership of the object an Express id route acts on: each allowed shape beside code that looks
protected but isn't, which must stay judged."""

from __future__ import annotations

import json
from pathlib import Path
from textwrap import dedent

import pytest

from traust_core.v1.providers.route_guards import route_guards
from traust_core.v1.providers.tree import tree_files

AUTH = """
import jwt from "jsonwebtoken";

export const requireAuth = (req, res, next) => {
  req.user = jwt.verify(req.headers.authorization, "k");
  next();
};
export const admin = (req, res, next) => (req.user.isAdmin ? next() : res.sendStatus(403));
export const auth = { required: requireAuth, optional: (req, res, next) => next() };
"""

MODELS = """
import mongoose from "mongoose";

const postSchema = new mongoose.Schema({ user: String, title: String, public: Boolean });
export const Post = mongoose.model("Post", postSchema);
"""

PRISMA = """
model Note {
  id      Int    @id
  ownerId Int
  title   String
}
"""

STORE = """
interface Holiday {
  id: string;
  name: string;
}
const comments = new Map<string, any>();
const holidays = new Map<string, Holiday>();

export const Comment = {
  get: (id: string) => comments.get(id),
  getFor: (author: string, id: string) => {
    const comment = comments.get(id);
    return comment?.author === author ? comment : undefined;
  },
  getAny: (author: string, id: string) => {
    const comment = comments.get(id);
    return comment?.author === author || comment ? comment : undefined;
  },
  remove: (id: string) => comments.delete(id),
};
export const Holidays = { get: (id: string) => holidays.get(id) };
"""

LOADERS = """
import mongoose from "mongoose";
import { Post } from "./models";

export const checkId = (name) => (req, res, next) => {
  if (!mongoose.Types.ObjectId.isValid(req.params[name])) return res.sendStatus(400);
  next();
};
export const loadBy = (name) => async (req, res, next) => {
  req.post = await Post.findById(req.params[name]);
  next();
};

export const loadOwnPost = async (req, res, next) => {
  req.post = await Post.findOne({ _id: req.params.id, user: req.user.id });
  if (!req.post) return res.sendStatus(404);
  next();
};
export const loadAnyPost = async (req, res, next) => {
  req.post = await Post.findById(req.params.id);
  next();
};
export const showPost = () => async (req, res) => {
  const post = await Post.findById(req.params.id);
  if (!post || post.user !== req.user.id) return res.sendStatus(404);
  res.json(post);
};
"""

CONTROLLER = """
const { Post } = require("./models");

exports.remove = async (req, res) => {
  await Post.deleteOne({ _id: req.params.id, user: req.user.id });
  res.sendStatus(204);
};
exports.show = async (req, res) => {
  const post = await Post.findOne({ _id: req.params.id, user: req.user.id });
  if (!post) return res.sendStatus(404);
  res.json(post);
};
exports.mine = async (input, id) => {
  const me = input.user.id;
  return Post.findOne({ _id: id, user: me });
};
"""

ROUTES = """
import express from "express";
import { PrismaClient } from "@prisma/client";
import { requireAuth, admin, auth } from "./auth";
import { Post } from "./models";
import { Comment, Holidays } from "./store";
import { loadOwnPost, loadAnyPost, showPost, checkId, loadBy } from "./loaders";
import wrap from "some-router-kit";
import expressAsyncHandler from "express-async-handler";
const { Task } = require("./sequelize");
const posts = require("./controller");

const prisma = new PrismaClient();
const app = express();
const asyncHandler = (fn) => (req, res, next) => fn(req, res, next).catch(next);

// shape 1: a query naming the caller, refused when absent
app.get("/scoped/:id", requireAuth, async (req, res) => {
  const post = await Post.findOne({ _id: req.params.id, user: req.user.id });
  if (!post) return res.status(404).json({});
  res.json(post);
});
app.delete("/scoped/:id", requireAuth, async (req, res) => {
  const { id } = req.params;
  const post = await Post.findOne({ _id: id, user: req.user.id });
  if (!post) return res.sendStatus(404);
  await Post.deleteOne({ _id: id });
  res.sendStatus(204);
});
app.delete("/orfail/:id", requireAuth, async (req, res) => {
  await Post.findOne({ _id: req.params.id, user: req.user.id }).orFail();
  await Post.deleteOne({ _id: req.params.id });
  res.sendStatus(204);
});
app.get("/either/:id", requireAuth, async (req, res) => {
  const post = await Post.findOne({
    _id: req.params.id,
    $or: [{ user: req.user.id }, { public: true }],
  });
  if (!post) return res.sendStatus(404);
  res.json(post);
});
app.get("/body/:id", requireAuth, async (req, res) => {
  const post = await Post.findOne({ _id: req.params.id, user: req.body.user });
  if (!post) return res.sendStatus(404);
  res.json(post);
});
app.get("/fallback/:id", requireAuth, async (req, res) => {
  const post = await Post.findOne({ _id: req.params.id, user: req.query.user || req.user.id });
  if (!post) return res.sendStatus(404);
  res.json(post);
});
app.delete("/unrefused/:id", requireAuth, async (req, res) => {
  const post = await Post.findOne({ _id: req.params.id, user: req.user.id });
  await Post.deleteOne({ _id: req.params.id });
  res.json(post);
});
app.put("/update-filter/:id", requireAuth, async (req, res) => {
  await Post.updateOne({ _id: req.params.id }, { user: req.user.id });
  res.sendStatus(204);
});

// shape 2: a single read, then a refusal of a foreign record
app.delete("/checked/:id", requireAuth, async (req, res) => {
  const post = await Post.findById(req.params.id);
  if (!post) return res.status(404).json({});
  if (post.user.toString() !== req.user.id) return res.status(403).json({});
  await Post.deleteOne({ _id: req.params.id });
  res.sendStatus(204);
});
app.delete("/combined/:id", requireAuth, async (req, res) => {
  const post = await Post.findById(req.params.id);
  if (!post || post.user !== req.user.id) {
    res.status(403).json({});
    return;
  }
  await Post.deleteOne({ _id: req.params.id });
});
app.delete("/thrown/:id", requireAuth, async (req, res) => {
  const post = await Post.findById(req.params.id);
  if (post.user !== req.user.id) throw new Error("forbidden");
  await Post.deleteOne({ _id: req.params.id });
});
app.delete("/next/:id", requireAuth, async (req, res, next) => {
  const post = await Post.findById(req.params.id);
  if (post.user !== req.user.id) return next(new Error("forbidden"));
  await Post.deleteOne({ _id: req.params.id });
});
app.delete("/superuser/:id", requireAuth, async (req, res) => {
  const post = await Post.findById(req.params.id);
  if (!req.user.isAdmin && post.user !== req.user.id) return res.sendStatus(403);
  await Post.deleteOne({ _id: req.params.id });
});
app.delete("/tried/:id", requireAuth, async (req, res, next) => {
  try {
    const post = await Post.findById(req.params.id);
    if (post.user !== req.user.id) return res.sendStatus(403);
    await Post.deleteOne({ _id: req.params.id });
  } catch (err) {
    next(err);
  }
});
app.delete("/ok-send/:id", requireAuth, async (req, res) => {
  const post = await Post.findById(req.params.id);
  if (post.user !== req.user.id) {
    res.json({ ok: false });
    return;
  }
  await Post.deleteOne({ _id: req.params.id });
});
app.delete("/no-return/:id", requireAuth, async (req, res) => {
  const post = await Post.findById(req.params.id);
  if (post.user !== req.user.id) {
    res.status(403).json({});
  }
  await Post.deleteOne({ _id: req.params.id });
});
app.delete("/redirect/:id", requireAuth, async (req, res) => {
  const post = await Post.findById(req.params.id);
  if (post.user !== req.user.id) return res.redirect("/");
  await Post.deleteOne({ _id: req.params.id });
});
app.delete("/next-route/:id", requireAuth, async (req, res, next) => {
  const post = await Post.findById(req.params.id);
  if (post.user !== req.user.id) return next("route");
  await Post.deleteOne({ _id: req.params.id });
});
app.delete("/public-flag/:id", requireAuth, async (req, res) => {
  const post = await Post.findById(req.params.id);
  if (post.public !== true) return res.sendStatus(403);
  await Post.deleteOne({ _id: req.params.id });
  res.json(req.user);
});
app.delete("/record-flag/:id", requireAuth, async (req, res) => {
  const post = await Post.findById(req.params.id);
  if (!post.isAdmin && post.user !== req.user.id) return res.sendStatus(403);
  await Post.deleteOne({ _id: req.params.id });
});
app.delete("/late/:id", requireAuth, async (req, res) => {
  const post = await Post.findById(req.params.id);
  await Post.deleteOne({ _id: req.params.id });
  if (post.user !== req.user.id) return res.sendStatus(403);
});
app.delete("/caught/:id", requireAuth, async (req, res) => {
  try {
    const post = await Post.findById(req.params.id);
    if (post.user !== req.user.id) throw new Error("forbidden");
  } catch (err) {
    await Post.deleteOne({ _id: req.params.id });
  }
});
app.delete("/repointed/:id", requireAuth, async (req, res) => {
  const post = await Post.findById(req.params.id);
  if (post.user !== req.user.id) return res.sendStatus(403);
  req.params.id = req.body.id;
  await Post.deleteOne({ _id: req.params.id });
});
app.delete("/impersonated/:id", requireAuth, async (req, res) => {
  req.user = { id: req.body.owner };
  const post = await Post.findById(req.params.id);
  if (post.user !== req.user.id) return res.sendStatus(403);
  await Post.deleteOne({ _id: req.params.id });
});

// shape 5: a store returning the record only when owned
app.get("/comments/:id", requireAuth, (req, res) => {
  const comment = Comment.getFor(req.user.sub, req.params.id);
  if (!comment) return res.sendStatus(404);
  res.json(comment);
});
app.get("/any-comments/:id", requireAuth, (req, res) => {
  const comment = Comment.getAny(req.user.sub, req.params.id);
  if (!comment) return res.sendStatus(404);
  res.json(comment);
});
app.delete("/comments/:id", requireAuth, (req, res) => {
  Comment.getFor(req.user.sub, req.params.id);
  Comment.remove(req.params.id);
  res.sendStatus(204);
});
app.get("/holidays/:id", requireAuth, (req, res) => res.json(Holidays.get(req.params.id)));

// Sequelize's `rejectOnEmpty`
app.delete("/tasks-reject/:id", requireAuth, async (req, res) => {
  await Task.findOne({ where: { id: req.params.id, userId: req.user.id }, rejectOnEmpty: true });
  await Task.destroy({ where: { id: req.params.id } });
});
app.delete("/tasks-no-reject/:id", requireAuth, async (req, res) => {
  await Task.findOne({ where: { id: req.params.id, userId: req.user.id }, rejectOnEmpty: false });
  await Task.destroy({ where: { id: req.params.id } });
});
app.delete("/tasks-unread-reject/:id", requireAuth, async (req, res) => {
  const strict = process.env.STRICT === "1";
  await Task.findOne({ where: { id: req.params.id, userId: req.user.id }, rejectOnEmpty: strict });
  await Task.destroy({ where: { id: req.params.id } });
});

// Prisma
app.get("/notes/:id", requireAuth, async (req, res) => {
  const note = await prisma.note.findFirst({
    where: { id: Number(req.params.id), ownerId: req.user.id },
  });
  if (!note) return res.sendStatus(404);
  res.json(note);
});
app.get("/notes-or-throw/:id", requireAuth, async (req, res) => {
  const note = await prisma.note.findUniqueOrThrow({
    where: { id: Number(req.params.id), ownerId: req.user.id },
  });
  res.json(note);
});
app.get("/related-notes/:id", requireAuth, async (req, res) => {
  const note = await prisma.note.findFirst({
    where: { id: Number(req.params.id), owner: { id: req.user.id } },
  });
  if (!note) return res.sendStatus(404);
  res.json(note);
});
app.get("/other-notes/:id", requireAuth, async (req, res) => {
  const note = await prisma.note.findFirst({
    where: { id: Number(req.params.id), owner: { id: { not: req.user.id } } },
  });
  if (!note) return res.sendStatus(404);
  res.json(note);
});
app.put("/claimed-notes/:id", requireAuth, async (req, res) => {
  const note = await prisma.note.update({
    where: { id: Number(req.params.id) },
    data: { ownerId: req.user.id },
  });
  res.json(note);
});

// who is calling, and what authenticates
app.get("/open/:id", async (req, res) => {
  res.json(await Post.findOne({ _id: req.params.id, user: req.user.id }));
});
app.get("/optional/:id", auth.optional, async (req, res) => {
  res.json(await Post.findById(req.params.id));
});
app.get("/admin/:id", requireAuth, admin, async (req, res) => {
  res.json(await Post.findById(req.params.id));
});
app.get("/locals/:id", requireAuth, async (req, res) => {
  const post = await Post.findOne({ _id: req.params.id, user: res.locals.user.id });
  if (!post) return res.sendStatus(404);
  res.json(post);
});

// handler forms and the route's chain
app.get("/factory/:id", requireAuth, showPost());
app.get("/wrapped/:id", requireAuth, asyncHandler(async (req, res) => {
  const post = await Post.findById(req.params.id);
  if (!post || post.user !== req.user.id) return res.sendStatus(404);
  res.json(post);
}));
app.delete("/controller/:id", requireAuth, posts.remove);
app.delete("/loaded/:id", requireAuth, loadOwnPost, async (req, res) => {
  await req.post.remove();
  res.sendStatus(204);
});
app.delete("/loaded-any/:id", requireAuth, loadAnyPost, async (req, res) => {
  await req.post.remove();
  res.sendStatus(204);
});
app.get("/passed/:id", requireAuth, (req, res) => posts.show(req, res));
app.delete("/valid-id/:id", [requireAuth, checkId("id")], async (req, res) => {
  const post = await Post.findById(req.params.id);
  if (!post || post.user !== req.user.id) return res.sendStatus(403);
  await Post.deleteOne({ _id: req.params.id });
});
app.delete("/loaded-by/:id", requireAuth, loadBy("id"), async (req, res) => {
  const post = await Post.findOne({ _id: req.params.id, user: req.user.id });
  if (!post) return res.sendStatus(404);
  await req.post.remove();
});
app.get("/handed-body/:id", requireAuth, async (req, res) => {
  const post = await posts.mine(req.body, req.params.id);
  if (!post) return res.sendStatus(404);
  res.json(post);
});
app.get("/destructured/:id", requireAuth, async ({ params, user }, res) => {
  res.json(await Post.findById(params.id));
});
app.get("/validated/:id", requireAuth, async (req, res) => {
  validationResult(req).throw();
  const post = await Post.findOne({ _id: req.params.id, user: req.user.id });
  if (!post) return res.sendStatus(404);
  res.json(post);
});
app.delete("/coded/:id", requireAuth, async (req, res) => {
  const code = 403;
  const post = await Post.findById(req.params.id);
  if (post.user !== req.user.id) return res.status(code).json({});
  await Post.deleteOne({ _id: req.params.id });
});
app.delete("/early/:id", loadOwnPost, requireAuth, async (req, res) => {
  await req.post.remove();
  res.sendStatus(204);
});
app.get("/sends-it/:id", requireAuth, async (req, res) => {
  const post = await Post.findById(req.params.id);
  if (post.user !== req.user.id) return res.status(403).json(post);
  res.json(post);
});
app.delete("/var-caught/:id", requireAuth, async (req, res) => {
  try {
    var post = await Post.findById(req.params.id);
    if (post.user !== req.user.id) throw new Error("forbidden");
    await Post.deleteOne({ _id: req.params.id });
  } catch (err) {
    res.json(post);
  }
});
app.delete("/null-next/:id", requireAuth, async (req, res, next) => {
  const err = null;
  const post = await Post.findById(req.params.id);
  if (post.user !== req.user.id) return next(err);
  await Post.deleteOne({ _id: req.params.id });
});
app.delete("/error-next/:id", requireAuth, async (req, res, next) => {
  const err = new Error("forbidden");
  const post = await Post.findById(req.params.id);
  if (post.user !== req.user.id) return next(err);
  await Post.deleteOne({ _id: req.params.id });
});
app.get("/headers/:id", requireAuth, async (req, res) => {
  res.setHeader("Cache-Control", "no-store");
  res.locals.errors = [];
  const post = await Post.findOne({ _id: req.params.id, user: req.user.id });
  if (!post) return res.sendStatus(404);
  res.json(post);
});
app.get("/locals-user/:id", requireAuth, async (req, res) => {
  res.locals.user = { id: req.query.as };
  const post = await Post.findOne({ _id: req.params.id, user: res.locals.user.id });
  if (!post) return res.sendStatus(404);
  res.json(post);
});
app.get("/unknown-wrapper/:id", requireAuth, wrap(async (req, res) => {
  res.json(await Post.findOne({ _id: req.params.id, user: req.user.id }).orFail());
}));
app.get("/library-wrapper/:id", requireAuth, expressAsyncHandler(async (req, res) => {
  res.json(await Post.findOne({ _id: req.params.id, user: req.user.id }).orFail());
}));
"""

PRELOADED = """
import express from "express";
import { requireAuth } from "./auth";
import { Post } from "./models";

const router = express.Router();
router.param("id", async (req, res, next, id) => {
  req.post = await Post.findById(id);
  next();
});
router.get("/:id", requireAuth, (req, res) => res.json(req.post));
const app = express();
app.use("/preloaded", router);
"""


def _tree(root: Path, files: dict[str, str]) -> dict:
    for rel, text in files.items():
        path = root / rel
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(dedent(text))
    return route_guards(tree_files(root)).model_dump(mode="json")


def _row(result: dict, method: str, pattern: str) -> dict:
    [row] = [
        r
        for r in result["routes"]
        if r["family"] == "express" and r["method"] == method and r["pattern"] == pattern
    ]
    return row


@pytest.fixture(scope="module")
def app(tmp_path_factory: pytest.TempPathFactory) -> dict:
    return _tree(
        tmp_path_factory.mktemp("app"),
        {
            "src/auth.ts": AUTH,
            "src/models.ts": MODELS,
            "prisma/schema.prisma": PRISMA,
            "src/store.ts": STORE,
            "src/loaders.ts": LOADERS,
            "src/controller.js": CONTROLLER,
            "src/sequelize.js": SEQUELIZE,
            "src/routes.ts": ROUTES,
            "src/preloaded.ts": PRELOADED,
        },
    )


@pytest.mark.parametrize(
    ("method", "pattern", "ownership"),
    [
        ("GET", "/scoped/:id", "scoped"),  # shape 1, refused when absent
        ("DELETE", "/scoped/:id", "checked"),  # the id is verified for the delete
        ("DELETE", "/orfail/:id", "checked"),  # `.orFail()` refuses the absent record
        ("GET", "/either/:id", "unchecked"),  # `$or` doesn't narrow to the caller
        ("GET", "/body/:id", "caller-blind"),  # the request body as the owner
        ("GET", "/fallback/:id", "unchecked"),  # `req.query.user || req.user.id`
        ("DELETE", "/unrefused/:id", "unchecked"),  # nothing refused when absent
        ("PUT", "/update-filter/:id", "unchecked"),  # the owner in the update, not the filter
        ("DELETE", "/checked/:id", "checked"),  # shape 2
        ("DELETE", "/combined/:id", "checked"),  # `!post ||`, a send, then a bare return
        ("DELETE", "/thrown/:id", "checked"),  # a throw refuses
        ("DELETE", "/next/:id", "checked"),  # `return next(err)` refuses
        ("DELETE", "/superuser/:id", "checked"),  # the caller's admin flag bypasses (D10)
        ("DELETE", "/tried/:id", "checked"),  # inside the handler's closing `try`
        ("DELETE", "/ok-send/:id", "unchecked"),  # a 2xx answer isn't a refusal
        ("DELETE", "/no-return/:id", "unchecked"),  # the 403 falls through to the delete
        ("DELETE", "/redirect/:id", "unchecked"),  # a redirect isn't a 4xx refusal
        ("DELETE", "/next-route/:id", "unchecked"),  # `next("route")` runs the next route
        ("DELETE", "/public-flag/:id", "unchecked"),  # `public` is no owner
        ("DELETE", "/record-flag/:id", "unchecked"),  # the record's flag, not the caller's
        ("DELETE", "/late/:id", "unchecked"),  # deleted before the check
        ("DELETE", "/caught/:id", "unchecked"),  # `catch` runs when the check refuses
        ("DELETE", "/repointed/:id", "unchecked"),  # `req.params.id` rewritten after the check
        ("DELETE", "/impersonated/:id", "caller-blind"),  # `req.user` written by the handler
        ("GET", "/comments/:id", "checked"),  # shape 5, refused when absent
        ("GET", "/any-comments/:id", "unknown"),  # `||`: returned whenever present
        ("DELETE", "/comments/:id", "unknown"),  # the owned result is ignored
        ("GET", "/holidays/:id", "none"),  # a typed store of ownerless records
        ("DELETE", "/tasks-reject/:id", "checked"),  # `rejectOnEmpty: true` refuses the missing
        ("DELETE", "/tasks-no-reject/:id", "unchecked"),  # `rejectOnEmpty: false` returns null
        ("DELETE", "/tasks-unread-reject/:id", "unchecked"),  # a value we can't read
        ("GET", "/notes/:id", "scoped"),  # Prisma `where`
        ("GET", "/notes-or-throw/:id", "scoped"),  # `findUniqueOrThrow`
        ("GET", "/related-notes/:id", "scoped"),  # a relation filter `owner: { id: me }`
        ("GET", "/other-notes/:id", "unchecked"),  # `{ not: me }` is no equality
        ("PUT", "/claimed-notes/:id", "unchecked"),  # `data` isn't the filter
        ("GET", "/open/:id", "n/a"),  # no guard
        ("GET", "/optional/:id", "n/a"),  # an optional guard lets anyone in
        ("GET", "/admin/:id", "n/a"),  # an admin-only middleware
        ("GET", "/locals/:id", "scoped"),  # `res.locals.user` is the caller
        ("GET", "/factory/:id", "checked"),  # the handler a factory builds
        ("GET", "/wrapped/:id", "checked"),  # `asyncHandler(fn)`
        ("DELETE", "/controller/:id", "scoped"),  # `exports.remove` through `require`
        ("DELETE", "/loaded/:id", "scoped"),  # a loader middleware scoping the record
        ("DELETE", "/loaded-any/:id", "caller-blind"),  # a loader that loads anyone's
        ("GET", "/preloaded/:id", "unknown"),  # `router.param` loads it first
        ("GET", "/passed/:id", "scoped"),  # `posts.show(req, res)` continues the handler
        ("DELETE", "/valid-id/:id", "checked"),  # middleware that only validates `req.params[name]`
        ("DELETE", "/loaded-by/:id", "unchecked"),  # middleware loading by `req.params[name]`
        ("GET", "/handed-body/:id", "caller-blind"),  # a helper's `input.user` isn't the caller
        ("GET", "/destructured/:id", "unknown"),  # `({ params }, res)` isn't read
        ("GET", "/validated/:id", "scoped"),  # a library reading `req` loads nothing of ours
        ("DELETE", "/coded/:id", "unchecked"),  # a status we can't read isn't a refusal
        ("DELETE", "/early/:id", "caller-blind"),  # a loader running before the guard
        ("GET", "/sends-it/:id", "unchecked"),  # a 403 sending the record isn't a refusal
        (
            "DELETE",
            "/var-caught/:id",
            "unchecked",
        ),  # `catch` sees the `var` record the try threw on
        ("DELETE", "/null-next/:id", "unchecked"),  # `next(null)` through a name
        ("DELETE", "/error-next/:id", "checked"),  # `next(err)` with an error
        ("GET", "/headers/:id", "scoped"),  # headers and other locals aren't the caller
        ("GET", "/locals-user/:id", "caller-blind"),  # `res.locals.user` written by the handler
        ("GET", "/unknown-wrapper/:id", "unknown"),  # a library wrapper we can't read
        ("GET", "/library-wrapper/:id", "scoped"),  # express-async-handler only forwards errors
    ],
)
def test_only_the_allowed_shapes_count_as_protection(
    app: dict, method: str, pattern: str, ownership: str
) -> None:
    row = _row(app, method, pattern)
    assert row["ownership"] == ownership
    if ownership in ("caller-blind", "unchecked"):
        assert row["judgement_required"]


def test_the_evidence_names_the_record_and_its_owner(app: dict) -> None:
    evidence = _row(app, "DELETE", "/public-flag/:id")["ownership_evidence"]
    assert (evidence["record_type"], evidence["owner_field"]) == ("Post", "user")
    assert _row(app, "GET", "/other-notes/:id")["ownership_evidence"]["owner_field"] == "ownerId"


@pytest.mark.parametrize(
    ("code", "pattern", "guarded"),
    [
        (
            'app.use(["/api", "/admin"], requireAuth);\napp.get("/admin/x/:id", h);\n',
            "/admin/x/:id",
            True,
        ),
        (
            'app.use(["/api", "/admin"], requireAuth);\napp.get("/open/x/:id", h);\n',
            "/open/x/:id",
            False,
        ),
        (
            'const ROUTE = "/api/x/:id";\napp.use("/api", requireAuth);\napp.get(ROUTE, h);\n',
            "/api/x/:id",
            True,
        ),
        ('app.use("/api", requireAuth);\napp.get("/apix/:id", h);\n', "/apix/:id", False),
    ],
    ids=["array-prefix", "array-prefix-elsewhere", "constant-route-path", "prefix-boundary"],
)
def test_prefixed_guards_cover_the_paths_under_them(
    tmp_path: Path, code: str, pattern: str, guarded: bool
) -> None:
    app = (
        'import express from "express";\nconst app = express();\n'
        "const requireAuth = (req, res, next) => next();\nconst h = (req, res) => res.json({});\n"
        + code
    )
    row = _row(_tree(tmp_path, {"app.js": app}), "GET", pattern)
    assert bool(row["guards"] or row["scope_guards"]) is guarded


@pytest.mark.parametrize(
    ("middleware", "guarded"),
    [
        ("lusca.xssProtection(true)", False),  # security headers
        ("loginLimiter", False),  # a rate limiter
        ("requireAuth", True),
    ],
)
def test_what_authenticates_an_express_route(
    tmp_path: Path, middleware: str, guarded: bool
) -> None:
    code = (
        'import express from "express";\nconst app = express();\n'
        f"app.use({middleware});\n"
        'app.get("/things/:id", (req, res) => res.json(req.params.id));\n'
    )
    result = _tree(tmp_path, {"app.js": code})
    row = _row(result, "GET", "/things/:id")
    assert bool(row["guards"] or row["scope_guards"]) is guarded


SEQUELIZE = """
const { DataTypes, Model } = require("sequelize");
const sequelize = require("./db");

const Task = sequelize.define("Task", { userId: DataTypes.INTEGER, title: DataTypes.STRING });
class Project extends Model {}
Project.init({ ownerId: DataTypes.INTEGER, name: DataTypes.STRING }, { sequelize });
module.exports = { Task, Project };
"""

TYPEORM = """
import { Entity, Column } from "typeorm";
import { AppDataSource } from "./source";

@Entity()
export class Order {
  @Column() id: number;
  @Column() ownerId: number;
}
export const orders = AppDataSource.getRepository(Order);
"""

SERVICES = """
import mongoose from "mongoose";
import { Post } from "./models";

export function loadOwned(me, id) {
  return Post.findOne({ _id: id, user: me });
}

class PostService {
  find(id, me) {
    return Post.findOne({ _id: id, user: me });
  }
}
export const postService = new PostService();
export default new PostService();
export const byModel = (id) => mongoose.model("Post").findById(id);
"""

RESOLVED = """
import express from "express";
import * as svc from "./services";
import defaultService, { postService, byModel } from "./services";
import { orders } from "./typeorm";
import { requireAuth } from "./auth";
import { Exporter } from "./exporter";
const { Task, Project } = require("./sequelize");

const app = express();
const cache = {};

app.get("/tasks/:id", requireAuth, async (req, res) => {
  const task = await Task.findOne({ where: { id: req.params.id, userId: req.user.id } });
  if (!task) return res.sendStatus(404);
  res.json(task);
});
app.get("/projects/:id", requireAuth, async (req, res) => {
  res.json(await Project.findByPk(req.params.id));
});
app.get("/orders/:id", requireAuth, async (req, res) => {
  const order = await orders.findOneBy({ id: Number(req.params.id), ownerId: req.user.id });
  if (!order) return res.sendStatus(404);
  res.json(order);
});
app.get("/namespaced/:id", requireAuth, async (req, res) => {
  const post = await svc.loadOwned(req.user.id, req.params.id);
  if (!post) return res.sendStatus(404);
  res.json(post);
});
app.get("/instance/:id", requireAuth, async (req, res) => {
  const post = await postService.find(req.params.id, req.user.id);
  if (!post) return res.sendStatus(404);
  res.json(post);
});
app.get("/default-instance/:id", requireAuth, async (req, res) => {
  const post = await defaultService.find(req.params.id, req.user.id);
  if (!post) return res.sendStatus(404);
  res.json(post);
});
app.get("/by-model/:id", requireAuth, async (req, res) => res.json(await byModel(req.params.id)));
app.get("/cached/:id", requireAuth, (req, res) => res.json(cache[req.params.id]));
app.get("/exported/:id", requireAuth, (req, res) => res.json(new Exporter(req.params.id).run()));
app.get("/nested/:id", requireAuth, async (req, res) => {
  function load() {
    return Task.findByPk(req.params.id);
  }
  res.json(await load());
});
app.delete("/each/:id", requireAuth, async (req, res) => {
  [req.params.id].forEach(drop);
  res.sendStatus(204);
});
"""


@pytest.fixture(scope="module")
def resolved(tmp_path_factory: pytest.TempPathFactory) -> dict:
    return _tree(
        tmp_path_factory.mktemp("resolved"),
        {
            "src/auth.ts": AUTH,
            "src/models.ts": MODELS,
            "src/sequelize.js": SEQUELIZE,
            "src/typeorm.ts": TYPEORM,
            "src/services.ts": SERVICES,
            "src/exporter.ts": "export class Exporter { constructor(id) {} run() {} }\n",
            "src/routes.ts": RESOLVED,
        },
    )


@pytest.mark.parametrize(
    ("method", "pattern", "ownership", "record"),
    [
        ("GET", "/tasks/:id", "scoped", "Task"),  # `sequelize.define`
        ("GET", "/projects/:id", "caller-blind", "Project"),  # `Model.init({ … }, { sequelize })`
        ("GET", "/orders/:id", "scoped", "Order"),  # TypeORM `getRepository(Order)`
        ("GET", "/namespaced/:id", "scoped", "Post"),  # `import * as svc`
        ("GET", "/instance/:id", "scoped", "Post"),  # a class instance's method
        ("GET", "/default-instance/:id", "scoped", "Post"),  # `export default new …`
        ("GET", "/by-model/:id", "caller-blind", "Post"),  # `mongoose.model("Post")`
        ("GET", "/cached/:id", "caller-blind", None),  # a subscript by the id
        ("GET", "/exported/:id", "unknown", None),  # a checkout class built with the id
        ("GET", "/nested/:id", "caller-blind", "Task"),  # a local function read in place
        ("DELETE", "/each/:id", "unknown", None),  # the id handed to a callback
    ],
)
def test_the_code_a_handler_reaches_is_resolved(
    resolved: dict, method: str, pattern: str, ownership: str, record: str | None
) -> None:
    row = _row(resolved, method, pattern)
    assert row["ownership"] == ownership
    assert (row["ownership_evidence"] or {}).get("record_type") == record


# Invented Express apps from an independent review: code credited as protected while another
# user's object stays reachable (each must stay judged or unknown), beside twins that are protected.
_REVIEW = Path(__file__).parents[2] / "fixtures/code_facts/express_ownership_review.json"
_CASES = json.loads(_REVIEW.read_text())


@pytest.mark.parametrize(
    ("case", "method", "pattern", "ownership"),
    [(c["case"], e["method"], e["pattern"], e["ownership"]) for c in _CASES for e in c["expect"]],
)
def test_holes_a_review_found_stay_closed(
    tmp_path: Path, case: str, method: str, pattern: str, ownership: str
) -> None:
    files = next(c["files"] for c in _CASES if c["case"] == case)
    assert _row(_tree(tmp_path, files), method, pattern)["ownership"] == ownership


@pytest.mark.parametrize(
    ("route", "ownership"),
    [
        # a condition of a thousand terms
        (
            'app.delete("/a/:id", requireAuth, async (req, res) => {\n'
            "  const post = await Post.findById(req.params.id);\n"
            "  if (!post || "
            + " || ".join(f"post.user !== req.user.id{k}" for k in range(1200))
            + ") return res.sendStatus(403);\n"
            "  await Post.deleteOne({ _id: req.params.id });\n});\n",
            "checked",
        ),
        # a member chain a thousand deep
        (
            'app.get("/a/:id", requireAuth, async (req, res) => {\n'
            "  res.json(await Post.findById(req.params.id."
            + ".".join(f"p{k}" for k in range(1200))
            + "));\n});\n",
            "caller-blind",
        ),
        # a schema nested a thousand deep
        (
            'const Deep = mongoose.model("Deep", new mongoose.Schema('
            + "{ a: " * 1200
            + "String"
            + " }" * 1200
            + "));\n"
            'app.get("/a/:id", requireAuth, async (req, res) => {\n'
            "  res.json(await Deep.findById(req.params.id));\n});\n",
            "caller-blind",
        ),
        # middleware arrays nested a thousand deep
        (
            'app.get("/a/:id", '
            + "[" * 1200
            + "requireAuth"
            + "]" * 1200
            + ", async (req, res) => {\n"
            "  res.json(await Post.findById(req.params.id));\n});\n",
            "caller-blind",
        ),
        # conversions nested a thousand deep
        (
            'app.get("/a/:id", requireAuth, async (req, res) => {\n'
            "  res.json(await Post.findById("
            + "String(" * 1200
            + "req.params.id"
            + ")" * 1200
            + "));\n});\n",
            "caller-blind",
        ),
        # `where` nested a thousand deep
        (
            'app.get("/a/:id", requireAuth, async (req, res) => {\n'
            "  res.json(await Post.findOne("
            + "{ where: " * 1200
            + "{ _id: req.params.id }"
            + " }" * 1200
            + "));\n});\n",
            "caller-blind",
        ),
        # an admin check of a thousand terms
        (
            "const requireAdmin = (req, res, next) => {\n  if (!req.user || "
            + " || ".join(["!req.user.isAdmin"] * 1200)
            + ") return res.sendStatus(403);\n  next();\n};\n"
            'app.delete("/a/:id", requireAuth, requireAdmin, async (req, res) => {\n'
            "  await Post.findByIdAndDelete(req.params.id);\n});\n",
            "n/a",
        ),
        # an admin check under a thousand negations
        (
            "const isAdmin = (req, res, next) => {\n  if ("
            + "!" * 2401
            + "req.user.isAdmin) return res.sendStatus(403);\n  next();\n};\n"
            'app.delete("/a/:id", requireAuth, isAdmin, async (req, res) => {\n'
            "  await Post.findByIdAndDelete(req.params.id);\n});\n",
            "caller-blind",
        ),
        # schema names bound to each other
        (
            "function a() { const schema = opts; }\nfunction b() { const opts = schema; }\n"
            'const Loop = mongoose.model("Loop", schema);\n'
            'app.get("/a/:id", requireAuth, async (req, res) => {\n'
            "  res.json(await Loop.findById(req.params.id));\n});\n",
            "caller-blind",
        ),
    ],
    ids=[
        "or-chain",
        "member-chain",
        "schema",
        "arrays",
        "conversions",
        "where",
        "admin-or-chain",
        "admin-negations",
        "schema-loop",
    ],
)
def test_pathological_code_neither_crashes_nor_credits(
    tmp_path: Path, route: str, ownership: str
) -> None:
    app = (
        'import express from "express";\nimport mongoose from "mongoose";\n'
        'import { requireAuth } from "./auth";\nimport { Post } from "./models";\n'
        f"const app = express();\n{route}"
    )
    result = _tree(tmp_path, {"auth.ts": AUTH, "models.ts": MODELS, "app.ts": app})
    assert (
        _row(result, "GET" if "app.get" in route else "DELETE", "/a/:id")["ownership"] == ownership
    )


FORGING = """
import express from "express";
import session from "express-session";
import { requireAuth } from "./auth";
import { Post, User } from "./models";

const app = express();
const actAs = (req, res, next) => {
  req.user = { id: req.body.owner };
  next();
};
const loadUser = async (req, res, next) => {
  req.user = await User.findById(req.session.userId);
  next();
};
const shareUser = (req, res, next) => {
  res.locals.user = req.user;
  next();
};
const signup = async (req, res, next) => {
  req.user = await User.create(req.body);
  next();
};
const show = async (req, res) => {
  const post = await Post.findById(req.params.id);
  if (!post || post.user !== req.user.id) return res.sendStatus(403);
  res.json(post);
};
app.get("/forged/:id", requireAuth, actAs, show);
app.get("/sessioned/:id", requireAuth, loadUser, show);
app.get("/shared/:id", requireAuth, shareUser, show);
app.post("/signup/:invite", signup, (req, res) => res.json(req.user));
app.get("/plain/:id", requireAuth, show);
"""

FORGING_USE = """
import express from "express";
import { requireAuth } from "./auth";
import { Post } from "./models";

const app = express();
app.use(requireAuth);
app.use((req, res, next) => {
  if (req.query.as) req.user = { id: req.query.as };
  next();
});
app.get("/everywhere/:id", async (req, res) => {
  const post = await Post.findById(req.params.id);
  if (!post || post.user !== req.user.id) return res.sendStatus(403);
  res.json(post);
});
"""


@pytest.mark.parametrize(
    ("app_code", "method", "pattern", "ownership"),
    [
        (FORGING, "GET", "/forged/:id", "caller-blind"),  # `req.user = req.body.owner` before it
        (FORGING, "GET", "/sessioned/:id", "checked"),  # a caller loaded from the session
        (FORGING, "GET", "/shared/:id", "checked"),  # the caller copied into `res.locals`
        (FORGING, "GET", "/plain/:id", "checked"),  # a writer elsewhere runs on its own route
        (FORGING_USE, "GET", "/everywhere/:id", "caller-blind"),  # `app.use` forging every route
    ],
    ids=["forged", "sessioned", "shared", "plain", "use"],
)
def test_middleware_building_the_caller_from_request_data_forges_it(
    tmp_path: Path, app_code: str, method: str, pattern: str, ownership: str
) -> None:
    models = (
        MODELS
        + 'export const User = mongoose.model("User", new mongoose.Schema({ name: String }));\n'
    )
    result = _tree(tmp_path, {"auth.ts": AUTH, "models.ts": models, "app.ts": app_code})
    assert _row(result, method, pattern)["ownership"] == ownership
