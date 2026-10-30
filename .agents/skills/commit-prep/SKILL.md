---
name: commit-prep
description: Take traust-core changes from working tree to merged PR in one run — gates, conventional signed commit, branch, PR body. Use when asked to prep a commit, open a PR, or land changes in traust-core.
---

# Commit Prep (traust-core)

Run the changes through this repo's gates, then land them as a PR. The org ruleset
requires a PR for main but **zero approvals** — self-merge is legal — and commits
must be signed (`commit.gpgsign` is on in this repo, so signing is automatic).

## Workflow

1. **Scope the change.** `git status`, `git diff --stat`, `git log --oneline -5` for
   style. If the tree mixes unrelated changes, split commits by concern before
   proceeding — one PR carries one story.
2. **Run the gates, in order, all must pass:**
   ```bash
   make lint-fix && make test && make coverage && make db-up && make test-integration
   ```
   - `make coverage` fails below 80% — new code needs tests; stub bodies are excluded.
   - **Known flake:** integration fixtures failing with `UndefinedColumn` (e.g.
     `column "severity" does not exist`) means the shared `traust_test` container
     holds the other DDL generation (contracts branch vs the pinned dep both
     recreate it). Clear and re-run:
     ```bash
     podman exec traust-postgres psql -U traust -d traust_test -c \
       'DROP SCHEMA IF EXISTS traust_storage CASCADE; DROP SCHEMA IF EXISTS traust_ledger CASCADE;'
     ```
     If it persists after clearing, it is a real schema mismatch — stop and report.
3. **Commit.** Conventional subject, enforced by the commit-msg hook:
   `type(scope): subject` — types feat/fix/refactor/docs/test/chore/ci/perf, scope is
   the narrowest affected area, imperative lowercase subject. Hooks run ruff on
   staged files; do not bypass with `--no-verify`.
4. **Branch and push.** Kebab-case `type/short-description`, off current main:
   `git push -u origin <branch>`. Never force-push `main` (org ruleset blocks it).
5. **Open the PR** with `gh pr create --base main`, body shaped like:
   - **What** — the change in 1–3 bullets, tied to the model/slice it serves
   - **The decisions** — any rule that governed it (one owner, DB-owned identity, pattern set)
   - **Tests** — which gates ran, any known environmental caveat
   - **Tracker** — the XWING story key
6. **Merge.** `gh pr merge <n> --merge --delete-branch` once the five CI checks pass
   (lint, test 3.11/3.12, api-check, postgres). Post-merge: pull main
   locally, log the milestone to the story.

## Rules

- Gates first: no PR opens with a red suite. If a gate cannot pass, report why —
  do not weaken the gate.
- One PR, one story. Split mixed trees into separate commits/PRs.
- Never merge another author's PR or one with a human's open review request.
- Never push directly to `main` — the ruleset rejects it anyway.
- If contracts or DDL shapes are involved, say so in the PR body and flag the pin.

## Done when

The PR is merged, local main is synced,
and the milestone is logged to the story.
