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
            + " || ".join(["post.user !== req.user.id"] * 1200)
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


@pytest.mark.parametrize(
    ("handler", "ownership"),
    [
        # another user the caller names is not the caller
        ("findOne({ _id: req.params.id, user: req.user.managerId })", "unchecked"),
        ("findOne({ _id: req.params.id, user: req.user['managerId'] })", "unchecked"),
        ("findOne({ _id: req.params.id, user: req.user.manager.id })", "unchecked"),
        # the caller's own id, through a payload, and its tenant
        ("findOne({ _id: req.params.id, user: req.user.id })", "scoped"),
        ("findOne({ _id: req.params.id, user: req.user.payload.sub })", "scoped"),
        ("findOne({ _id: req.params.id, user: req.user.userId })", "scoped"),
    ],
)
def test_only_the_callers_own_fields_stand_for_it(
    tmp_path: Path, handler: str, ownership: str
) -> None:
    app = (
        'import express from "express";\nimport { requireAuth } from "./auth";\n'
        'import { Post } from "./models";\nconst app = express();\n'
        'app.get("/a/:id", requireAuth, async (req, res) => {\n'
        f"  res.json(await Post.{handler});\n}});\n"
    )
    result = _tree(tmp_path, {"auth.ts": AUTH, "models.ts": MODELS, "app.ts": app})
    assert _row(result, "GET", "/a/:id")["ownership"] == ownership


@pytest.mark.parametrize(
    ("bind", "name", "ownership"),
    [
        ("const { managerId } = req.user;", "managerId", "unchecked"),
        ("const { id } = req.user;", "id", "checked"),
        # a quoted key is its string value: the caller's own id under another name
        ('const { "id": ownerId } = req.user;', "ownerId", "checked"),
        ("const { 'id': ownerId } = req.user;", "ownerId", "checked"),
        ('const { "managerId": ownerId } = req.user;', "ownerId", "unchecked"),
        # a computed key is no field name we can read
        ("const { [key]: ownerId } = req.user;", "ownerId", "unchecked"),
    ],
)
def test_a_destructured_field_is_the_caller_only_when_its_own(
    tmp_path: Path, bind: str, name: str, ownership: str
) -> None:
    app = (
        'import express from "express";\nimport { requireAuth } from "./auth";\n'
        'import { Post } from "./models";\nconst app = express();\n'
        'app.delete("/a/:id", requireAuth, async (req, res) => {\n'
        f"  {bind}\n  const post = await Post.findById(req.params.id);\n"
        f"  if (!post || post.user !== {name}) return res.sendStatus(403);\n"
        "  await post.deleteOne();\n});\n"
    )
    result = _tree(tmp_path, {"auth.ts": AUTH, "models.ts": MODELS, "app.ts": app})
    assert _row(result, "DELETE", "/a/:id")["ownership"] == ownership


_BACKSTAGE_PLUGIN = """
import { coreServices, createBackendPlugin } from '@backstage/backend-plugin-api';
import { createRouter } from './router';
export const notesPlugin = createBackendPlugin({
  pluginId: 'notes',
  register(env) {
    env.registerInit({
      deps: { httpRouter: coreServices.httpRouter, httpAuth: coreServices.httpAuth },
      async init({ httpRouter, httpAuth }) {
        httpRouter.use(await createRouter({ httpAuth }));
      },
    });
  },
});
"""

_USER_REF = (
    "const getUserEntityRef = async (req) => "
    "(await httpAuth.credentials(req, { allow: ['user'] })).principal.userEntityRef;"
)


@pytest.mark.parametrize(
    ("helper", "owner", "ownership"),
    [
        # a local helper over the user's credentials is the caller
        (_USER_REF, "await getUserEntityRef(req)", "scoped"),
        (
            "async function getUser(req) {\n"
            "    const credentials = await httpAuth.credentials(req, { allow: ['user'] });\n"
            "    return credentials.principal.userEntityRef;\n  }",
            "await getUser(req)",
            "scoped",
        ),
        (
            "const getUser = async (req) => userInfo.getUserInfo("
            "await httpAuth.credentials(req, { allow: ['user'] }));",
            "(await getUser(req)).userEntityRef",
            "scoped",
        ),
        # the credentials inline
        (
            "",
            "(await httpAuth.credentials(req, { allow: ['user'] })).principal.userEntityRef",
            "scoped",
        ),
        # a bare `credentials(req)` or a service allowed may be a service's principal
        (
            "const getUserEntityRef = async (req) => "
            "(await httpAuth.credentials(req)).principal.userEntityRef;",
            "await getUserEntityRef(req)",
            "caller-blind",
        ),
        (
            "const getUserEntityRef = async (req) => (await httpAuth.credentials(req, "
            "{ allow: ['user', 'service'] })).principal.userEntityRef;",
            "await getUserEntityRef(req)",
            "caller-blind",
        ),
        # rebindable, or returning what the request names
        (_USER_REF.replace("const ", "let "), "await getUserEntityRef(req)", "caller-blind"),
        (
            "const getUserEntityRef = async (req) => req.query.user;",
            "await getUserEntityRef(req)",
            "caller-blind",
        ),
        (
            "async function getUser(req) {\n"
            "    if (req.query.as) return req.query.as;\n"
            "    return (await httpAuth.credentials(req, { allow: ['user'] })).principal"
            ".userEntityRef;\n  }",
            "await getUser(req)",
            "caller-blind",
        ),
        # another user the principal names, or the helper handed something else
        (
            "const getUserEntityRef = async (req) => (await httpAuth.credentials(req, "
            "{ allow: ['user'] })).principal.managerRef;",
            "await getUserEntityRef(req)",
            "caller-blind",
        ),
        (_USER_REF, "await getUserEntityRef(req.body)", "caller-blind"),
    ],
)
def test_backstage_caller_helpers_are_the_caller(
    tmp_path: Path, helper: str, owner: str, ownership: str
) -> None:
    router = (
        "import Router from 'express-promise-router';\n"
        'import { Post } from "./models";\n'
        "export async function createRouter({ httpAuth, userInfo }) {\n"
        "  const router = Router();\n"
        f"  {helper}\n"
        "  router.get('/notes/:id', async (req, res) => {\n"
        f"    const owner = {owner};\n"
        "    res.json(await Post.findOne({ _id: req.params.id, user: owner }).orFail());\n"
        "  });\n"
        "  return router;\n"
        "}\n"
    )
    result = _tree(
        tmp_path,
        {"plugin.ts": _BACKSTAGE_PLUGIN, "router.ts": router, "models.ts": MODELS},
    )
    assert _row(result, "GET", "/notes/:id")["ownership"] == ownership


def test_a_shadowed_backstage_helper_is_not_the_caller(tmp_path: Path) -> None:
    router = (
        "import Router from 'express-promise-router';\n"
        'import { Post } from "./models";\n'
        f"{_USER_REF.replace('httpAuth', 'auth')}\n"
        "export async function createRouter({ httpAuth }) {\n"
        "  const router = Router();\n"
        "  const getUserEntityRef = async (req) => req.body.user;\n"
        "  router.get('/notes/:id', async (req, res) => {\n"
        "    const owner = await getUserEntityRef(req);\n"
        "    res.json(await Post.findOne({ _id: req.params.id, user: owner }).orFail());\n"
        "  });\n"
        "  return router;\n"
        "}\n"
    )
    result = _tree(
        tmp_path,
        {"plugin.ts": _BACKSTAGE_PLUGIN, "router.ts": router, "models.ts": MODELS},
    )
    assert _row(result, "GET", "/notes/:id")["ownership"] == "caller-blind"


def test_a_module_backstage_helper_is_the_caller(tmp_path: Path) -> None:
    router = (
        "import Router from 'express-promise-router';\n"
        'import { Post } from "./models";\n'
        "export const getUserEntityRef = async (req, httpAuth) => (await httpAuth.credentials("
        "req, { allow: ['user'] })).principal.userEntityRef;\n"
        "export async function createRouter({ httpAuth }) {\n"
        "  const router = Router();\n"
        "  router.get('/notes/:id', async (req, res) => {\n"
        "    const owner = await getUserEntityRef(req, httpAuth);\n"
        "    res.json(await Post.findOne({ _id: req.params.id, user: owner }).orFail());\n"
        "  });\n"
        "  return router;\n"
        "}\n"
    )
    result = _tree(
        tmp_path,
        {"plugin.ts": _BACKSTAGE_PLUGIN, "router.ts": router, "models.ts": MODELS},
    )
    assert _row(result, "GET", "/notes/:id")["ownership"] == "scoped"


@pytest.mark.parametrize(
    ("extra", "credentials", "ownership"),
    [
        ("", "httpAuth.credentials(req, { allow: ['user'] })", "scoped"),
        # a spread may replace `allow`
        ("", "httpAuth.credentials(req, { allow: ['user'], ...opts })", "caller-blind"),
        # the checkout's own `credentials` method is no credentials service
        (
            "const auth = { credentials: async (req, o) => ({ principal: "
            "{ userEntityRef: req.query.as } }) };\n",
            "auth.credentials(req, { allow: ['user'] })",
            "caller-blind",
        ),
    ],
)
def test_only_backstages_user_credentials_are_the_caller(
    tmp_path: Path, extra: str, credentials: str, ownership: str
) -> None:
    router = (
        "import Router from 'express-promise-router';\n"
        'import { Post } from "./models";\n'
        f"{extra}"
        "export async function createRouter({ httpAuth, opts }) {\n"
        "  const router = Router();\n"
        "  router.get('/notes/:id', async (req, res) => {\n"
        f"    const owner = (await {credentials}).principal.userEntityRef;\n"
        "    res.json(await Post.findOne({ _id: req.params.id, user: owner }).orFail());\n"
        "  });\n"
        "  return router;\n"
        "}\n"
    )
    result = _tree(
        tmp_path,
        {"plugin.ts": _BACKSTAGE_PLUGIN, "router.ts": router, "models.ts": MODELS},
    )
    assert _row(result, "GET", "/notes/:id")["ownership"] == ownership


def _backstage_route(factory: str, before: str, owner: str, *, header: str = "") -> str:
    return (
        "import Router from 'express-promise-router';\n"
        'import { Post } from "./models";\n'
        f"{header}"
        f"export async function createRouter({factory}) {{\n"
        "  const router = Router();\n"
        f"  {before}\n"
        "  router.get('/notes/:id', async (req, res) => {\n"
        f"    const owner = {owner};\n"
        "    res.json(await Post.findOne({ _id: req.params.id, user: owner }).orFail());\n"
        "  });\n"
        "  return router;\n"
        "}\n"
    )


_CREDS = "httpAuth.credentials(req, { allow: ['user'] })"


@pytest.mark.parametrize(
    ("router", "ownership"),
    [
        # the service from the factory's options, however it is reached
        (
            _backstage_route("options", "", f"(await options.{_CREDS}).principal.userEntityRef"),
            "scoped",
        ),
        (
            _backstage_route(
                "options",
                "const { httpAuth } = options;",
                f"(await {_CREDS}).principal.userEntityRef",
            ),
            "scoped",
        ),
        # a credentials service the checkout builds or imports is no Backstage service
        (
            _backstage_route(
                "{}",
                "",
                f"(await {_CREDS}).principal.userEntityRef",
                header="import { httpAuth } from './fake-auth';\n",
            ),
            "caller-blind",
        ),
        (
            _backstage_route(
                "{}",
                "const httpAuth = { credentials: async (req, o) => ({ principal: "
                "{ userEntityRef: req.query.as } }) };",
                f"(await {_CREDS}).principal.userEntityRef",
            ),
            "caller-blind",
        ),
        # the service parameter replaced, or its default standing in for it
        (
            _backstage_route(
                "{ httpAuth }",
                "httpAuth = makeFake();",
                f"(await {_CREDS}).principal.userEntityRef",
            ),
            "caller-blind",
        ),
        (
            _backstage_route(
                "{ httpAuth = fake }", "", f"(await {_CREDS}).principal.userEntityRef"
            ),
            "caller-blind",
        ),
        # a later computed `allow` overrides the user-only one
        (
            _backstage_route(
                "{ httpAuth }",
                "",
                "(await httpAuth.credentials(req, { allow: ['user'], ['allow']: ['service'] }))"
                ".principal.userEntityRef",
            ),
            "caller-blind",
        ),
        # a `userInfo` the checkout builds returns what it likes
        (
            _backstage_route(
                "{ httpAuth }",
                "const userInfo = { getUserInfo: async () => ({ userEntityRef: req.query.as }) };",
                f"(await userInfo.getUserInfo(await {_CREDS})).userEntityRef",
            ),
            "caller-blind",
        ),
        (
            _backstage_route(
                "{ httpAuth, userInfo }",
                "",
                f"(await userInfo.getUserInfo(await {_CREDS})).userEntityRef",
            ),
            "scoped",
        ),
    ],
)
def test_backstage_services_are_the_ones_handed_in(
    tmp_path: Path, router: str, ownership: str
) -> None:
    result = _tree(
        tmp_path,
        {
            "plugin.ts": _BACKSTAGE_PLUGIN,
            "router.ts": router,
            "models.ts": MODELS,
            "fake-auth.ts": "export const httpAuth = { credentials: async (req) => "
            "({ principal: { userEntityRef: req.query.as } }) };\n",
        },
    )
    assert _row(result, "GET", "/notes/:id")["ownership"] == ownership


_HELPER = f"const getUserEntityRef = async (req) => (await {_CREDS}).principal.userEntityRef;"


@pytest.mark.parametrize(
    ("before", "handler_local", "ownership"),
    [
        # an out-of-scope block declaring the same name doesn't hide the helper, but the hop
        # into a name the file declares twice is a hand-off: unknown, never judged
        (_HELPER + "\n  { const getUserEntityRef = () => 'x'; }", "", "unknown"),
        # a nearer binding in the handler hides it: a declaration, a destructuring
        (_HELPER, "const getUserEntityRef = async (req) => req.query.as;", "caller-blind"),
        (_HELPER, "const { getUserEntityRef } = req.app.locals;", "caller-blind"),
        (_HELPER, "var getUserEntityRef = async (req) => req.query.as;", "caller-blind"),
        # the helper reassigned
        (_HELPER.replace("const", "var") + "\n  getUserEntityRef = fake;", "", "caller-blind"),
        # the helper's credentials rewritten or replaced before they are returned
        (
            "async function getUserEntityRef(req) {\n"
            f"    const credentials = await {_CREDS};\n"
            "    credentials.principal = { userEntityRef: req.query.as };\n"
            "    return credentials.principal.userEntityRef;\n  }",
            "",
            "unchecked",
        ),
        (
            "async function getUserEntityRef(req) {\n"
            f"    let owner = (await {_CREDS}).principal.userEntityRef;\n"
            "    owner = req.query.as;\n"
            "    return owner;\n  }",
            "",
            "caller-blind",
        ),
        (
            "async function getUserEntityRef(req) {\n"
            f"    const credentials = await {_CREDS};\n"
            "    Object.assign(credentials, req.body);\n"
            "    return credentials.principal.userEntityRef;\n  }",
            "",
            "caller-blind",
        ),
        # a path falling through returns `undefined`
        (
            "async function getUserEntityRef(req) {\n"
            f"    if (req.query.ok) {{ return (await {_CREDS}).principal.userEntityRef; }}\n  }}",
            "",
            "caller-blind",
        ),
        # the request rewritten inside the helper
        (
            "async function getUserEntityRef(req) {\n"
            "    req = { headers: { authorization: req.query.token } };\n"
            f"    return (await {_CREDS}).principal.userEntityRef;\n  }}",
            "",
            "caller-blind",
        ),
        # a checkout `credentials` method, through a helper
        (
            "const auth = { credentials: async (req, o) => ({ principal: "
            "{ userEntityRef: req.query.as } }) };\n  "
            "const getUserEntityRef = async (req) => "
            "(await auth.credentials(req, { allow: ['user'] })).principal.userEntityRef;",
            "",
            "caller-blind",
        ),
    ],
)
def test_backstage_helpers_resolve_where_called(
    tmp_path: Path, before: str, handler_local: str, ownership: str
) -> None:
    router = (
        "import Router from 'express-promise-router';\n"
        'import { Post } from "./models";\n'
        "export async function createRouter({ httpAuth }) {\n"
        "  const router = Router();\n"
        f"  {before}\n"
        "  router.get('/notes/:id', async (req, res) => {\n"
        f"    {handler_local}\n"
        "    const owner = await getUserEntityRef(req);\n"
        "    res.json(await Post.findOne({ _id: req.params.id, user: owner }).orFail());\n"
        "  });\n"
        "  return router;\n"
        "}\n"
    )
    result = _tree(
        tmp_path,
        {"plugin.ts": _BACKSTAGE_PLUGIN, "router.ts": router, "models.ts": MODELS},
    )
    assert _row(result, "GET", "/notes/:id")["ownership"] == ownership


def test_a_parameter_shadowing_a_backstage_helper_is_not_it(tmp_path: Path) -> None:
    router = (
        "import Router from 'express-promise-router';\n"
        'import { Post } from "./models";\n'
        "export async function createRouter({ httpAuth }) {\n"
        "  const router = Router();\n"
        f"  {_HELPER}\n"
        "  const mount = (getUserEntityRef) => {\n"
        "    router.get('/notes/:id', async (req, res) => {\n"
        "      const owner = await getUserEntityRef(req);\n"
        "      res.json(await Post.findOne({ _id: req.params.id, user: owner }).orFail());\n"
        "    });\n"
        "  };\n"
        "  mount(async (req) => req.query.as);\n"
        "  return router;\n"
        "}\n"
    )
    result = _tree(
        tmp_path,
        {"plugin.ts": _BACKSTAGE_PLUGIN, "router.ts": router, "models.ts": MODELS},
    )
    assert _row(result, "GET", "/notes/:id")["ownership"] == "caller-blind"


@pytest.mark.parametrize(
    ("factory", "before", "owner", "ownership"),
    [
        # a plain parameter's default stands in for the service
        ("{}, httpAuth = fake", "", f"(await {_CREDS}).principal.userEntityRef", "caller-blind"),
        # the service replaced or mutated anywhere in the file
        (
            "{ httpAuth }",
            "({ httpAuth } = { httpAuth: fake });",
            f"(await {_CREDS}).principal.userEntityRef",
            "caller-blind",
        ),
        (
            "{ httpAuth }",
            "httpAuth.credentials = fake;",
            f"(await {_CREDS}).principal.userEntityRef",
            "caller-blind",
        ),
        (
            "{ httpAuth }",
            "Object.assign(httpAuth, { credentials: fake });",
            f"(await {_CREDS}).principal.userEntityRef",
            "caller-blind",
        ),
        (
            "{ httpAuth }",
            "const alias = httpAuth; alias.credentials = fake;",
            f"(await {_CREDS}).principal.userEntityRef",
            "caller-blind",
        ),
        (
            "{ httpAuth }",
            "setup({ httpAuth });",
            f"(await {_CREDS}).principal.userEntityRef",
            "caller-blind",
        ),
        # the object holding it written, or handed on whole
        (
            "options",
            "const { httpAuth } = options;\n  options.httpAuth.credentials = fake;",
            f"(await {_CREDS}).principal.userEntityRef",
            "caller-blind",
        ),
        (
            "options",
            "Object.assign(options, { httpAuth: fake });",
            f"(await options.{_CREDS}).principal.userEntityRef",
            "caller-blind",
        ),
        # reading other options leaves the service alone
        (
            "options",
            "const log = options.logger;",
            f"(await options.{_CREDS}).principal.userEntityRef",
            "scoped",
        ),
        # `getUserInfo` inline in the filter is no store read
        (
            "{ httpAuth, userInfo }",
            "",
            f"(await userInfo.getUserInfo(await {_CREDS})).userEntityRef",
            "scoped",
        ),
    ],
)
def test_backstage_services_stay_what_they_were_handed(
    tmp_path: Path, factory: str, before: str, owner: str, ownership: str
) -> None:
    router = _backstage_route(factory, before, owner)
    result = _tree(
        tmp_path,
        {"plugin.ts": _BACKSTAGE_PLUGIN, "router.ts": router, "models.ts": MODELS},
    )
    assert _row(result, "GET", "/notes/:id")["ownership"] == ownership


def test_inline_user_info_in_the_filter_is_the_caller(tmp_path: Path) -> None:
    router = (
        "import Router from 'express-promise-router';\n"
        'import { Post } from "./models";\n'
        "export async function createRouter({ httpAuth, userInfo }) {\n"
        "  const router = Router();\n"
        "  router.get('/notes/:id', async (req, res) => {\n"
        "    res.json(await Post.findOne({ _id: req.params.id, user: (await userInfo"
        f".getUserInfo(await {_CREDS})).userEntityRef }}).orFail());\n"
        "  });\n"
        "  return router;\n"
        "}\n"
    )
    result = _tree(
        tmp_path,
        {"plugin.ts": _BACKSTAGE_PLUGIN, "router.ts": router, "models.ts": MODELS},
    )
    assert _row(result, "GET", "/notes/:id")["ownership"] == "scoped"


@pytest.mark.parametrize(
    ("handed", "ownership"),
    [
        ("httpAuth", "scoped"),  # the service the factory is handed
        ("fakeAuth", "caller-blind"),  # a stand-in at the call site
        ("{ credentials: fake }", "caller-blind"),
    ],
)
def test_a_helpers_service_is_what_its_call_site_hands_it(
    tmp_path: Path, handed: str, ownership: str
) -> None:
    router = (
        "import Router from 'express-promise-router';\n"
        'import { Post } from "./models";\n'
        "const fakeAuth = { credentials: async (req) => ({ principal: "
        "{ userEntityRef: req.query.as } }) };\n"
        "const getUser = async (req, httpAuth) => "
        f"(await {_CREDS}).principal.userEntityRef;\n"
        "export async function createRouter({ httpAuth }) {\n"
        "  const router = Router();\n"
        "  router.get('/notes/:id', async (req, res) => {\n"
        f"    const owner = await getUser(req, {handed});\n"
        "    res.json(await Post.findOne({ _id: req.params.id, user: owner }).orFail());\n"
        "  });\n"
        "  return router;\n"
        "}\n"
    )
    result = _tree(
        tmp_path,
        {"plugin.ts": _BACKSTAGE_PLUGIN, "router.ts": router, "models.ts": MODELS},
    )
    assert _row(result, "GET", "/notes/:id")["ownership"] == ownership


@pytest.mark.parametrize(
    ("helper", "ownership"),
    [
        # every branch returns the caller
        (
            "async function getUserEntityRef(req) {\n"
            "    if (req.query.fresh) {\n"
            f"      return (await {_CREDS}).principal.userEntityRef;\n"
            "    } else {\n"
            f"      return (await {_CREDS}).principal.userEntityRef;\n"
            "    }\n  }",
            "scoped",
        ),
        (
            "async function getUserEntityRef(req) {\n"
            "    if (!req.headers.authorization) throw new Error('no token');\n"
            "    else return (await "
            f"{_CREDS}).principal.userEntityRef;\n  }}",
            "scoped",
        ),
        # an `if` without `else` may fall through
        (
            "async function getUserEntityRef(req) {\n"
            "    if (req.query.fresh) {\n"
            f"      return (await {_CREDS}).principal.userEntityRef;\n"
            "    }\n  }",
            "caller-blind",
        ),
        # a nearer `req` in the helper is another request
        (
            "async function getUserEntityRef(req) {\n"
            "    {\n"
            "      const req = { headers: { authorization: `Bearer ${req.query.token}` } };\n"
            f"      return (await {_CREDS}).principal.userEntityRef;\n"
            "    }\n  }",
            "caller-blind",
        ),
    ],
)
def test_backstage_helper_paths(tmp_path: Path, helper: str, ownership: str) -> None:
    router = _backstage_route("{ httpAuth }", helper, "await getUserEntityRef(req)")
    result = _tree(
        tmp_path,
        {"plugin.ts": _BACKSTAGE_PLUGIN, "router.ts": router, "models.ts": MODELS},
    )
    assert _row(result, "GET", "/notes/:id")["ownership"] == ownership


def test_a_switch_case_declaration_hides_the_helper(tmp_path: Path) -> None:
    router = (
        "import Router from 'express-promise-router';\n"
        'import { Post } from "./models";\n'
        "export async function createRouter({ httpAuth }) {\n"
        "  const router = Router();\n"
        f"  {_HELPER}\n"
        "  router.get('/notes/:id', async (req, res) => {\n"
        "    switch (req.query.mode) {\n"
        "      case 'as':\n"
        "        const getUserEntityRef = async (r) => r.query.as;\n"
        "      case 'me': {\n"
        "        const owner = await getUserEntityRef(req);\n"
        "        res.json(await Post.findOne({ _id: req.params.id, user: owner }).orFail());\n"
        "      }\n"
        "    }\n"
        "  });\n"
        "  return router;\n"
        "}\n"
    )
    result = _tree(
        tmp_path,
        {"plugin.ts": _BACKSTAGE_PLUGIN, "router.ts": router, "models.ts": MODELS},
    )
    assert _row(result, "GET", "/notes/:id")["ownership"] == "caller-blind"


def test_a_nearer_request_in_the_handler_is_not_the_caller(tmp_path: Path) -> None:
    router = _backstage_route(
        "{ httpAuth }",
        "",
        "await (async () => { const req = forged; return (await "
        f"{_CREDS}).principal.userEntityRef; }})()",
    )
    result = _tree(
        tmp_path,
        {"plugin.ts": _BACKSTAGE_PLUGIN, "router.ts": router, "models.ts": MODELS},
    )
    assert _row(result, "GET", "/notes/:id")["ownership"] != "scoped"


def test_a_helpers_returns_resolve_to_their_own_binding(tmp_path: Path) -> None:
    router = (
        "import Router from 'express-promise-router';\n"
        'import { Post } from "./models";\n'
        "export async function createRouter({ httpAuth }) {\n"
        "  const router = Router();\n"
        "  router.get('/notes/:id', async (req, res) => {\n"
        "    const owner = req.query.as;\n"
        "    const getUserEntityRef = async (req) => {\n"
        "      if (req.query.me) {\n"
        f"        const owner = (await {_CREDS}).principal.userEntityRef;\n"
        "        return owner;\n"
        "      }\n"
        "      return owner;\n"
        "    };\n"
        "    const who = await getUserEntityRef(req);\n"
        "    res.json(await Post.findOne({ _id: req.params.id, user: who }).orFail());\n"
        "  });\n"
        "  return router;\n"
        "}\n"
    )
    result = _tree(
        tmp_path,
        {"plugin.ts": _BACKSTAGE_PLUGIN, "router.ts": router, "models.ts": MODELS},
    )
    assert _row(result, "GET", "/notes/:id")["ownership"] != "scoped"


@pytest.mark.parametrize(
    ("before", "ownership"),
    [
        # another binding of the name, elsewhere, is not the service
        (
            "function other(httpAuth) { setup(httpAuth); }\n"
            "  { const httpAuth = fake; Object.assign(httpAuth, {}); }",
            "scoped",
        ),
        # a loop header that only reads the helper doesn't declare it
        ("for (const x of [1]) { void getUserEntityRef; }", "scoped"),
        # a helper the service is handed to must not rewrite it either
        (
            "const prime = (httpAuth) => { httpAuth.credentials = fake; };\n  prime(httpAuth);",
            "caller-blind",
        ),
        # `for (name of ..)` without a declaration rewrites the helper
        (
            "for (getUserEntityRef of fakes) {}",
            "caller-blind",
        ),
    ],
)
def test_backstage_names_resolve_to_their_binding(
    tmp_path: Path, before: str, ownership: str
) -> None:
    helper = _HELPER.replace("const ", "var ") if "for (getUser" in before else _HELPER
    router = _backstage_route(
        "{ httpAuth }", f"{helper}\n  {before}", "await getUserEntityRef(req)"
    )
    result = _tree(
        tmp_path,
        {"plugin.ts": _BACKSTAGE_PLUGIN, "router.ts": router, "models.ts": MODELS},
    )
    assert _row(result, "GET", "/notes/:id")["ownership"] == ownership


def test_a_route_in_a_loop_reading_the_helper_keeps_it(tmp_path: Path) -> None:
    router = (
        "import Router from 'express-promise-router';\n"
        'import { Post } from "./models";\n'
        "export async function createRouter({ httpAuth }) {\n"
        "  const router = Router();\n"
        f"  {_HELPER}\n"
        "  for (const resolve of [getUserEntityRef]) {\n"
        "    router.get('/notes/:id', async (req, res) => {\n"
        "      const owner = await getUserEntityRef(req);\n"
        "      res.json(await Post.findOne({ _id: req.params.id, user: owner }).orFail());\n"
        "    });\n"
        "  }\n"
        "  return router;\n"
        "}\n"
    )
    result = _tree(
        tmp_path,
        {"plugin.ts": _BACKSTAGE_PLUGIN, "router.ts": router, "models.ts": MODELS},
    )
    assert _row(result, "GET", "/notes/:id")["ownership"] == "scoped"


@pytest.mark.parametrize(
    ("helper", "ownership"),
    [
        # a destructured principal is the caller's
        (
            "async function getUserEntityRef(req) {\n"
            f"    const {{ principal }} = await {_CREDS};\n"
            "    return principal.userEntityRef;\n  }",
            "scoped",
        ),
        (
            "async function getUserEntityRef(req) {\n"
            f"    const {{ principal: who }} = await {_CREDS};\n"
            "    return who.userEntityRef;\n  }",
            "scoped",
        ),
        # another field, a default or a use outside the return is not
        (
            "async function getUserEntityRef(req) {\n"
            f"    const {{ token }} = await {_CREDS};\n"
            "    return token;\n  }",
            "caller-blind",
        ),
        (
            "async function getUserEntityRef(req) {\n"
            f"    const {{ principal = req.body }} = await {_CREDS};\n"
            "    return principal.userEntityRef;\n  }",
            "caller-blind",
        ),
        (
            "async function getUserEntityRef(req) {\n"
            f"    const {{ principal }} = await {_CREDS};\n"
            "    principal.userEntityRef = req.query.as;\n"
            "    return principal.userEntityRef;\n  }",
            "caller-blind",
        ),
    ],
)
def test_backstage_destructured_credentials(tmp_path: Path, helper: str, ownership: str) -> None:
    router = _backstage_route("{ httpAuth }", helper, "await getUserEntityRef(req)")
    result = _tree(
        tmp_path,
        {"plugin.ts": _BACKSTAGE_PLUGIN, "router.ts": router, "models.ts": MODELS},
    )
    assert _row(result, "GET", "/notes/:id")["ownership"] == ownership


@pytest.mark.parametrize(
    ("header", "factory", "before", "owner", "ownership"),
    [
        # a method of the options object may replace the service
        (
            "",
            "options",
            "options.replaceHttpAuth(fake);",
            f"(await options.{_CREDS}).principal.userEntityRef",
            "caller-blind",
        ),
        # a write to another binding of the helper's name elsewhere is not a write to it; the
        # hop into a name the file declares twice is still a hand-off: unknown, never judged
        (
            "",
            "{ httpAuth }",
            f"{_HELPER}\n  function other() {{ let getUserEntityRef; getUserEntityRef = 1; }}",
            "await getUserEntityRef(req)",
            "unknown",
        ),
        # an aliased import binds its alias, not the name it imports
        (
            "import { getUserEntityRef as remote } from './remote';\n",
            "{ httpAuth }",
            _HELPER,
            "await getUserEntityRef(req)",
            "scoped",
        ),
    ],
)
def test_backstage_round_five(
    tmp_path: Path, header: str, factory: str, before: str, owner: str, ownership: str
) -> None:
    router = _backstage_route(factory, before, owner, header=header)
    result = _tree(
        tmp_path,
        {
            "plugin.ts": _BACKSTAGE_PLUGIN,
            "router.ts": router,
            "models.ts": MODELS,
            "remote.ts": "export const getUserEntityRef = async (req) => req.query.as;\n",
        },
    )
    assert _row(result, "GET", "/notes/:id")["ownership"] == ownership


@pytest.mark.parametrize(
    ("factory", "before", "owner", "ownership"),
    [
        # a service destructured under another name and rewritten through it
        (
            "options",
            "const { httpAuth: alias } = options;\n  alias.credentials = fake;",
            f"(await options.{_CREDS}).principal.userEntityRef",
            "caller-blind",
        ),
        (
            "options",
            "const { ...rest } = options;\n  rest.httpAuth.credentials = fake;",
            f"(await options.{_CREDS}).principal.userEntityRef",
            "caller-blind",
        ),
        # destructured under another name, only called: the service
        (
            "options",
            "const { httpAuth: alias, logger } = options;",
            f"(await options.{_CREDS}).principal.userEntityRef",
            "scoped",
        ),
        # bracket access to the service and its method
        (
            "{ httpAuth }",
            "",
            "(await httpAuth['credentials'](req, { allow: ['user'] })).principal.userEntityRef",
            "scoped",
        ),
        (
            "options",
            "",
            "(await options['httpAuth'].credentials(req, { allow: ['user'] }))"
            ".principal.userEntityRef",
            "scoped",
        ),
        # a computed key on the options may be the service
        (
            "options",
            "options[key] = fake;",
            f"(await options.{_CREDS}).principal.userEntityRef",
            "caller-blind",
        ),
    ],
)
def test_backstage_round_six_services(
    tmp_path: Path, factory: str, before: str, owner: str, ownership: str
) -> None:
    router = _backstage_route(factory, before, owner)
    result = _tree(
        tmp_path,
        {"plugin.ts": _BACKSTAGE_PLUGIN, "router.ts": router, "models.ts": MODELS},
    )
    assert _row(result, "GET", "/notes/:id")["ownership"] == ownership


@pytest.mark.parametrize(
    ("helpers", "ownership"),
    [
        # a bracket chain to the caller's own fields
        (
            "const getUserEntityRef = async (req) => "
            f"(await {_CREDS})['principal']['userEntityRef'];",
            "scoped",
        ),
        (
            f"const getUserEntityRef = async (req) => (await {_CREDS})['principal']['managerRef'];",
            "caller-blind",
        ),
        # a helper delegating to another that returns the caller: taken for the caller, but
        # the route's second hop with the request is a hand-off (D2): unknown, never judged
        (
            f"const inner = async (req) => (await {_CREDS}).principal.userEntityRef;\n"
            "  const getUserEntityRef = async (req) => inner(req);",
            "unknown",
        ),
        (
            "const inner = async (req) => req.query.as;\n"
            "  const getUserEntityRef = async (req) => inner(req);",
            "caller-blind",
        ),
        (
            f"const inner = async (req) => (await {_CREDS}).principal.userEntityRef;\n"
            "  const getUserEntityRef = async (req) => inner(forged);",
            "caller-blind",
        ),
    ],
)
def test_backstage_round_six_helpers(tmp_path: Path, helpers: str, ownership: str) -> None:
    router = _backstage_route("{ httpAuth }", helpers, "await getUserEntityRef(req)")
    result = _tree(
        tmp_path,
        {"plugin.ts": _BACKSTAGE_PLUGIN, "router.ts": router, "models.ts": MODELS},
    )
    assert _row(result, "GET", "/notes/:id")["ownership"] == ownership


@pytest.mark.parametrize(
    ("factory", "before", "owner", "ownership"),
    [
        # a renamed service is still the service
        (
            "{ httpAuth: auth }",
            "",
            "(await auth.credentials(req, { allow: ['user'] })).principal.userEntityRef",
            "scoped",
        ),
        (
            "options",
            "const { httpAuth: auth } = options;",
            "(await auth.credentials(req, { allow: ['user'] })).principal.userEntityRef",
            "scoped",
        ),
        # but a plain parameter under another name is not
        (
            "auth",
            "",
            "(await auth.credentials(req, { allow: ['user'] })).principal.userEntityRef",
            "caller-blind",
        ),
        (
            "{ httpAuth: auth }",
            "auth.credentials = fake;",
            "(await auth.credentials(req, { allow: ['user'] })).principal.userEntityRef",
            "caller-blind",
        ),
    ],
)
def test_backstage_renamed_services(
    tmp_path: Path, factory: str, before: str, owner: str, ownership: str
) -> None:
    router = _backstage_route(factory, before, owner)
    result = _tree(
        tmp_path,
        {"plugin.ts": _BACKSTAGE_PLUGIN, "router.ts": router, "models.ts": MODELS},
    )
    assert _row(result, "GET", "/notes/:id")["ownership"] == ownership


@pytest.mark.parametrize(
    ("helper", "call", "ownership"),
    [
        # a nearer `req` handed to the helper is another request
        (
            _HELPER,
            "await (async () => { const req = forged; return getUserEntityRef(req); })()",
            "not scoped",
        ),
        (
            _HELPER,
            "await (() => { { const req = forged; return getUserEntityRef(req); } })()",
            "not scoped",
        ),
        # the request handed twice: the position the helper reads counts
        (
            f"const getOwner = async (other, req) => (await {_CREDS}).principal.userEntityRef;",
            "await getOwner(req, req)",
            "not judged",
        ),
        # credentials, then user info, then its field, across consts
        (
            "async function getUserEntityRef(req) {\n"
            f"    const credentials = await {_CREDS};\n"
            "    const user = await userInfo.getUserInfo(credentials);\n"
            "    return user.userEntityRef;\n  }",
            "await getUserEntityRef(req)",
            "scoped",
        ),
        # an unused const still runs: its use of the credentials is unchecked
        (
            "async function getUserEntityRef(req) {\n"
            f"    const credentials = await {_CREDS};\n"
            "    const spoiled = mutate(credentials);\n"
            "    return credentials.principal.userEntityRef;\n  }",
            "await getUserEntityRef(req)",
            "not scoped",
        ),
    ],
)
def test_backstage_round_seven_helpers(
    tmp_path: Path, helper: str, call: str, ownership: str
) -> None:
    router = _backstage_route("{ httpAuth, userInfo }", helper, call)
    result = _tree(
        tmp_path,
        {"plugin.ts": _BACKSTAGE_PLUGIN, "router.ts": router, "models.ts": MODELS},
    )
    got = _row(result, "GET", "/notes/:id")["ownership"]
    if ownership == "not scoped":
        assert got != "scoped"
    elif ownership == "not judged":
        assert got not in ("caller-blind", "unchecked")
    else:
        assert got == ownership


@pytest.mark.parametrize(
    ("handed", "ownership"),
    [
        # handed the request, it may load by `req.params`: a hand-off, never `n/a`
        ("req", "unknown"),
    ],
)
def test_user_info_handed_the_request_is_a_hand_off(
    tmp_path: Path, handed: str, ownership: str
) -> None:
    router = (
        "import Router from 'express-promise-router';\n"
        "export async function createRouter({ httpAuth, userInfo }) {\n"
        "  const router = Router();\n"
        "  router.get('/notes/:id', async (req, res) => {\n"
        f"    await userInfo.getUserInfo({handed});\n"
        "    res.json({ ok: true });\n"
        "  });\n"
        "  return router;\n"
        "}\n"
    )
    result = _tree(
        tmp_path,
        {"plugin.ts": _BACKSTAGE_PLUGIN, "router.ts": router, "models.ts": MODELS},
    )
    assert _row(result, "GET", "/notes/:id")["ownership"] == ownership


def test_a_block_shadowing_the_request_hands_the_helper_another(tmp_path: Path) -> None:
    router = (
        "import Router from 'express-promise-router';\n"
        'import { Post } from "./models";\n'
        "export async function createRouter({ httpAuth }) {\n"
        "  const router = Router();\n"
        f"  {_HELPER}\n"
        "  router.get('/notes/:id', async (req, res) => {\n"
        "    const id = req.params.id;\n"
        "    {\n"
        "      const req = { headers: { authorization: forgedToken } };\n"
        "      const owner = await getUserEntityRef(req);\n"
        "      res.json(await Post.findOne({ _id: id, user: owner }).orFail());\n"
        "    }\n"
        "  });\n"
        "  return router;\n"
        "}\n"
    )
    result = _tree(
        tmp_path,
        {"plugin.ts": _BACKSTAGE_PLUGIN, "router.ts": router, "models.ts": MODELS},
    )
    assert _row(result, "GET", "/notes/:id")["ownership"] != "scoped"


@pytest.mark.parametrize(
    ("rewrite", "ownership"),
    [
        # the route's own request, rewritten before its credentials are read
        ("req.headers.authorization = `Bearer ${req.query.token}`;", "not scoped"),
        ("req.headers['authorization'] = req.query.token;", "not scoped"),
        ("Object.assign(req.headers, { authorization: req.query.token });", "not scoped"),
        ("const h = req.headers; h.authorization = req.query.token;", "not scoped"),
        ("delete req.headers.authorization;", "not scoped"),
        ("rewrite(req);", "not scoped"),
        # reading the request leaves it as it came
        ("const token = req.headers.authorization; void req.get('x-request-id');", "scoped"),
    ],
)
def test_a_rewritten_request_carries_no_caller(
    tmp_path: Path, rewrite: str, ownership: str
) -> None:
    router = (
        "import Router from 'express-promise-router';\n"
        'import { Post } from "./models";\n'
        "export async function createRouter({ httpAuth }) {\n"
        "  const router = Router();\n"
        "  router.get('/notes/:id', async (req, res) => {\n"
        "    const id = req.params.id;\n"
        f"    {rewrite}\n"
        f"    const owner = (await {_CREDS}).principal.userEntityRef;\n"
        "    res.json(await Post.findOne({ _id: id, user: owner }).orFail());\n"
        "  });\n"
        "  return router;\n"
        "}\n"
    )
    result = _tree(
        tmp_path,
        {"plugin.ts": _BACKSTAGE_PLUGIN, "router.ts": router, "models.ts": MODELS},
    )
    got = _row(result, "GET", "/notes/:id")["ownership"]
    assert got != "scoped" if ownership == "not scoped" else got == ownership


@pytest.mark.parametrize(
    ("rewrite", "ownership"),
    [
        # rewritten in the handler, then handed to the helper
        ("req.headers.authorization = req.query.token;", "not scoped"),
        ("", "scoped"),
    ],
)
def test_a_helper_handed_a_rewritten_request_carries_no_caller(
    tmp_path: Path, rewrite: str, ownership: str
) -> None:
    router = (
        "import Router from 'express-promise-router';\n"
        'import { Post } from "./models";\n'
        "export async function createRouter({ httpAuth }) {\n"
        "  const router = Router();\n"
        f"  {_HELPER}\n"
        "  router.get('/notes/:id', async (req, res) => {\n"
        "    const id = req.params.id;\n"
        f"    {rewrite}\n"
        "    const owner = await getUserEntityRef(req);\n"
        "    res.json(await Post.findOne({ _id: id, user: owner }).orFail());\n"
        "  });\n"
        "  return router;\n"
        "}\n"
    )
    result = _tree(
        tmp_path,
        {"plugin.ts": _BACKSTAGE_PLUGIN, "router.ts": router, "models.ts": MODELS},
    )
    got = _row(result, "GET", "/notes/:id")["ownership"]
    assert got != "scoped" if ownership == "not scoped" else got == ownership


def test_an_inner_block_of_the_same_name_leaves_the_const_trusted(tmp_path: Path) -> None:
    helper = (
        "async function getUserEntityRef(req) {\n"
        f"    const credentials = await {_CREDS};\n"
        "    { const credentials = 1; void credentials; }\n"
        "    return credentials.principal.userEntityRef;\n  }"
    )
    router = _backstage_route("{ httpAuth }", helper, "await getUserEntityRef(req)")
    result = _tree(
        tmp_path,
        {"plugin.ts": _BACKSTAGE_PLUGIN, "router.ts": router, "models.ts": MODELS},
    )
    assert _row(result, "GET", "/notes/:id")["ownership"] == "scoped"


_REWRITER = (
    "const auth = { credentials: async (req) => { "
    "req.headers.authorization = `Bearer ${req.query.token}`; } };"
)


@pytest.mark.parametrize(
    ("before", "first", "ownership"),
    [
        # a checkout `credentials` method rewrites the request before the real call
        (_REWRITER, "await auth.credentials(req);", "not scoped"),
        # handed to a helper as its service, a stand-in may rewrite the request too
        (
            _REWRITER
            + "\n  const prime = async (req, httpAuth) => { await httpAuth.credentials(req); };",
            "await prime(req, auth);",
            "not scoped",
        ),
        # the real service read first changes nothing
        ("", f"await {_CREDS};", "scoped"),
    ],
)
def test_a_credentials_stand_in_may_rewrite_the_request(
    tmp_path: Path, before: str, first: str, ownership: str
) -> None:
    router = (
        "import Router from 'express-promise-router';\n"
        'import { Post } from "./models";\n'
        "export async function createRouter({ httpAuth }) {\n"
        "  const router = Router();\n"
        f"  {before}\n"
        "  router.get('/notes/:id', async (req, res) => {\n"
        "    const id = req.params.id;\n"
        f"    {first}\n"
        f"    const owner = (await {_CREDS}).principal.userEntityRef;\n"
        "    res.json(await Post.findOne({ _id: id, user: owner }).orFail());\n"
        "  });\n"
        "  return router;\n"
        "}\n"
    )
    result = _tree(
        tmp_path,
        {"plugin.ts": _BACKSTAGE_PLUGIN, "router.ts": router, "models.ts": MODELS},
    )
    got = _row(result, "GET", "/notes/:id")["ownership"]
    assert got != "scoped" if ownership == "not scoped" else got == ownership
