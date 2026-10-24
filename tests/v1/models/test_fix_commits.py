"""Fix-commit references and changed functions, ported from traust
src/traust/cli/resolve_advisory_symbols.py (development)."""

from __future__ import annotations

import pytest

from traust_core.v1.models.fix_commits import changed_functions, fix_commits

URL = "https://github.com/org/lib/commit/abc1234"


@pytest.mark.parametrize(
    ("url", "found"),
    [
        (URL, ("github.com", "org/lib", "abc1234")),
        (
            "https://gitlab.com/group/sub/lib/-/commit/0123abcd",
            ("gitlab.com", "group/sub/lib", "0123abcd"),
        ),
        (
            "https://git.example.org/cgit/glibc.git/commit/?id=deadbeef1",
            ("git.example.org", "cgit/glibc.git/commit", "deadbeef1"),
        ),
        (
            "https://git.example.org/cgit/sqlite.git/commit/?h=cafebabe1",
            ("git.example.org", "cgit/sqlite.git/commit", "cafebabe1"),
        ),
    ],
)
def test_commit_references_name_the_repository_and_sha(
    url: str, found: tuple[str, str, str]
) -> None:
    [commit], pulls = fix_commits([url])
    assert (commit.host, commit.repo, commit.sha, commit.url) == (*found, url)
    assert pulls == []


def test_pull_requests_are_listed_and_repeats_collapse() -> None:
    pull = "https://github.com/org/lib/pull/42"
    commits, pulls = fix_commits([URL, URL + "#diff", pull, "https://nvd.nist.gov/vuln/CVE-1"])
    assert [c.sha for c in commits] == ["abc1234"]
    assert pulls == [pull]


JAVA_PATCH = """@@ -10,7 +10,7 @@ public class Introspector {
-    public static PropertyDescriptor[] introspectInterfaces(Class<?> c) {
+    public static PropertyDescriptor[] introspectInterfaces(Class<?> c, boolean safe) {
@@ -40,3 +40,4 @@ private void cache(String key) {
+        if (key == null) {
"""


def test_java_functions_are_package_qualified_and_changed_lines_outrank_hunk_context() -> None:
    found = changed_functions(
        URL, [("spring-beans/src/main/java/org/example/beans/Introspector.java", JAVA_PATCH)]
    )
    assert {s.symbol: s.confidence for s in found} == {
        "org.example.beans.Introspector#introspectInterfaces": "high",
        "org.example.beans.Introspector#cache": "medium",
    }
    assert {(s.source, s.reference, s.file) for s in found} == {
        ("fix_commit", URL, "spring-beans/src/main/java/org/example/beans/Introspector.java")
    }


@pytest.mark.parametrize(
    ("path", "patch", "symbols"),
    [
        (
            "src/pkg/sub/mod.py",
            "+def parse_header(raw):\n+    async def x(): pass",
            ["pkg.sub.parse_header", "pkg.sub.x"],
        ),
        ("lib/merge.js", "+function merge(a, b) {\n-deep = (o) => o", ["merge", "deep"]),
        ("src/tls.c", "+int ssl_verify(SSL *s,\n+    if (x) {", ["ssl_verify"]),
        ("Main.java", "+  public void run() {", ["Main#run"]),
    ],
)
def test_declarations_per_language(path: str, patch: str, symbols: list[str]) -> None:
    assert [s.symbol for s in changed_functions(URL, [(path, patch)])] == symbols


@pytest.mark.parametrize(
    "path",
    [
        "src/test/java/org/A.java",
        "tests/test_mod.py",
        "lib/__tests__/a.js",
        "src/FooTest.java",
        "main.go",
        "README.md",
    ],
)
def test_tests_and_unmined_languages_are_skipped(path: str) -> None:
    assert changed_functions(URL, [(path, "+def f():\n+func F() {\n+public void f() {")]) == []


def test_keywords_and_unchanged_context_lines_are_not_functions() -> None:
    patch = "@@ -1 +1 @@ if (x)\n while (y) {\n+    return f(x);\n--- a/file\n+++ b/file"
    assert changed_functions(URL, [("a.c", patch)]) == []
