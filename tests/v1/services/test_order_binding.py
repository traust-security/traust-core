"""Structural invariant: every order-bound service writer routes through `order_binding` or
`RecordingService.recording`."""

from __future__ import annotations

import ast
from pathlib import Path

SERVICES_DIR = Path(__file__).resolve().parents[3] / "src" / "traust_core" / "v1" / "services"

# Modules that implement the fencing doors themselves rather than calling them.
_EXCLUDED_MODULES = frozenset({"order_binding.py", "operations.py"})


def _call_names(node: ast.AST) -> set[str]:
    names: set[str] = set()
    for child in ast.walk(node):
        if isinstance(child, ast.Call):
            if isinstance(child.func, ast.Name):
                names.add(child.func.id)
            elif isinstance(child.func, ast.Attribute):
                names.add(child.func.attr)
    return names


def _forwarded_method(func: ast.FunctionDef | ast.AsyncFunctionDef) -> str | None:
    """Return `target` for a wrapper `return self.<svc>.<target>(..., lease_generation=...)`."""
    body = [
        stmt
        for stmt in func.body
        if not (isinstance(stmt, ast.Expr) and isinstance(stmt.value, ast.Constant))
    ]
    if len(body) != 1 or not isinstance(body[0], ast.Return):
        return None
    call = body[0].value
    if (
        isinstance(call, ast.Call)
        and isinstance(call.func, ast.Attribute)
        and isinstance(call.func.value, ast.Attribute)
        and isinstance(call.func.value.value, ast.Name)
        and call.func.value.value.id == "self"
        and any(kw.arg == "lease_generation" for kw in call.keywords)
    ):
        return call.func.attr
    return None


def _unbounded_writers(
    tree: ast.Module, *, fenced_delegates: set[str] | None = None
) -> tuple[list[str], set[str]]:
    """Return (violations, fenced_method_names) for public order-bound writers in `tree`."""
    violations: list[str] = []
    fenced: set[str] = set()

    def check_func(
        func: ast.FunctionDef | ast.AsyncFunctionDef,
        prefix: str,
        class_methods: dict[str, ast.FunctionDef | ast.AsyncFunctionDef] | None = None,
    ) -> None:
        if func.name.startswith("_"):
            return
        args = {a.arg for a in (*func.args.posonlyargs, *func.args.args, *func.args.kwonlyargs)}
        is_order_writer = "lease_generation" in args or (
            "run_order_id" in args and bool({"worker", "principal"} & args)
        )
        if not is_order_writer:
            return
        seen: set[str] = set()
        queue = [func]
        while queue:
            cur = queue.pop()
            calls = _call_names(cur)
            if "order_binding" in calls or "recording" in calls:
                fenced.add(func.name)
                return
            if class_methods is not None:
                for called in calls:
                    if called in class_methods and called not in seen:
                        seen.add(called)
                        queue.append(class_methods[called])
        forwarded = _forwarded_method(func)
        if forwarded is not None and fenced_delegates is not None and forwarded in fenced_delegates:
            fenced.add(func.name)
            return
        violations.append(f"{prefix}{func.name}")

    for node in tree.body:
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
            check_func(node, "")
        elif isinstance(node, ast.ClassDef):
            methods = {
                item.name: item
                for item in node.body
                if isinstance(item, (ast.FunctionDef, ast.AsyncFunctionDef))
            }
            for item in methods.values():
                check_func(item, f"{node.name}.", methods)
    return violations, fenced


def test_every_order_bound_service_writer_routes_through_order_binding_or_recording() -> None:
    trees = [
        (path.relative_to(SERVICES_DIR).as_posix(), ast.parse(path.read_text(encoding="utf-8")))
        for path in sorted(SERVICES_DIR.rglob("*.py"))
        if path.name not in _EXCLUDED_MODULES
    ]
    directly_fenced: set[str] = set()
    for _rel, tree in trees:
        _, fenced = _unbounded_writers(tree)
        directly_fenced.update(fenced)
    found_writers = 0
    violations: list[str] = []
    for rel, tree in trees:
        for node in ast.walk(tree):
            if isinstance(
                node, (ast.FunctionDef, ast.AsyncFunctionDef)
            ) and not node.name.startswith("_"):
                args = {
                    a.arg for a in (*node.args.posonlyargs, *node.args.args, *node.args.kwonlyargs)
                }
                if "lease_generation" in args:
                    found_writers += 1
        bad, _ = _unbounded_writers(tree, fenced_delegates=directly_fenced)
        violations.extend(f"{rel}:{name}" for name in bad)
    assert found_writers >= 10, f"expected at least 10 order-bound writers, found {found_writers}"
    assert violations == [], f"order-bound writers bypassing order_binding/recording: {violations}"


def test_invariant_catches_an_order_bound_writer_that_bypasses_order_binding() -> None:
    bypass = ast.parse(
        "class BadService:\n"
        "    def record_thing(self, run_order_id, worker, lease_generation):\n"
        "        return self._uow.write()\n"
    )
    assert _unbounded_writers(bypass)[0] == ["BadService.record_thing"]
