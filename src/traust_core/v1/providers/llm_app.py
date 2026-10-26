"""LLM, agent and MCP application detection: a checkout is one when its own code imports a model
SDK, an agent framework, an MCP server SDK or a vector store, when a manifest declares one
directly (never a lockfile, which also lists transitive libraries), or when it ships
prompt-template files. Files are read, never imported, built or run."""

from __future__ import annotations

import json
import re
import tomllib
from collections import defaultdict
from collections.abc import Iterator
from pathlib import PurePosixPath

from traust_core.v1.models.code_facts import (
    CodeFactDetail,
    CodeFactKind,
    LlmAppFact,
    LlmAppKind,
    LlmAppSignal,
    LlmAppStats,
    LlmSignalSource,
    LlmTaggedFile,
)
from traust_core.v1.models.common import CodeSpan, RepoPath
from traust_core.v1.providers.base import Acquisition, Readiness, Result
from traust_core.v1.providers.clock import Clock
from traust_core.v1.providers.tools import ToolRequest
from traust_core.v1.providers.tree import SKIP_DIRS, TreeFile, tree_files

M, A, P, V = (
    LlmAppKind.MODEL_SDK,
    LlmAppKind.AGENT_FRAMEWORK,
    LlmAppKind.MCP_SERVER,
    LlmAppKind.VECTOR_STORE,
)
_ORDER = tuple(LlmAppKind)

# Import root -> (kind, library). Python roots are module names, JS roots package names (a
# trailing "/" is a scope), Go and Java roots path prefixes, Rust roots crate names.
PYTHON = {
    "openai": (M, "openai"), "anthropic": (M, "anthropic"), "google.genai": (M, "google-genai"),
    "google.generativeai": (M, "google-generativeai"), "vertexai": (M, "vertexai"),
    "mistralai": (M, "mistralai"), "cohere": (M, "cohere"), "groq": (M, "groq"),
    "ollama": (M, "ollama"), "litellm": (M, "litellm"), "transformers": (M, "transformers"),
    "vllm": (M, "vllm"), "llama_cpp": (M, "llama-cpp-python"),
    "langchain": (A, "langchain"), "langchain_core": (A, "langchain"),
    "langchain_community": (A, "langchain"), "langchain_openai": (A, "langchain"),
    "langchain_anthropic": (A, "langchain"), "langgraph": (A, "langgraph"),
    "llama_index": (A, "llama-index"), "crewai": (A, "crewai"), "autogen": (A, "autogen"),
    "autogen_agentchat": (A, "autogen"), "semantic_kernel": (A, "semantic-kernel"),
    "haystack": (A, "haystack"), "dspy": (A, "dspy"), "smolagents": (A, "smolagents"),
    "pydantic_ai": (A, "pydantic-ai"),
    "mcp": (P, "mcp"), "fastmcp": (P, "fastmcp"),
    "chromadb": (V, "chromadb"), "pinecone": (V, "pinecone"), "qdrant_client": (V, "qdrant"),
    "weaviate": (V, "weaviate"), "pymilvus": (V, "milvus"), "faiss": (V, "faiss"),
    "lancedb": (V, "lancedb"), "pgvector": (V, "pgvector"),
}  # fmt: skip
NPM = {
    "openai": (M, "openai"), "@anthropic-ai/sdk": (M, "anthropic"),
    "@google/genai": (M, "google-genai"), "@google/generative-ai": (M, "google-generativeai"),
    "@mistralai/mistralai": (M, "mistralai"), "cohere-ai": (M, "cohere"),
    "groq-sdk": (M, "groq"), "ollama": (M, "ollama"), "ai": (M, "vercel-ai-sdk"),
    "@ai-sdk/": (M, "vercel-ai-sdk"), "langchain": (A, "langchain"),
    "@langchain/": (A, "langchain"), "llamaindex": (A, "llama-index"), "@mastra/": (A, "mastra"),
    "@modelcontextprotocol/sdk": (P, "mcp"), "@pinecone-database/pinecone": (V, "pinecone"),
    "chromadb": (V, "chromadb"), "@qdrant/js-client-rest": (V, "qdrant"),
    "weaviate-client": (V, "weaviate"),
}  # fmt: skip
GO = {
    "github.com/openai/openai-go": (M, "openai"),
    "github.com/sashabaranov/go-openai": (M, "openai"),
    "github.com/anthropics/anthropic-sdk-go": (M, "anthropic"),
    "google.golang.org/genai": (M, "google-genai"),
    "github.com/google/generative-ai-go": (M, "google-generativeai"),
    "github.com/ollama/ollama/api": (M, "ollama"),
    "github.com/tmc/langchaingo": (A, "langchaingo"),
    "github.com/cloudwego/eino": (A, "eino"),
    "github.com/mark3labs/mcp-go": (P, "mcp"),
    "github.com/modelcontextprotocol/go-sdk": (P, "mcp"),
    "github.com/qdrant/go-client": (V, "qdrant"),
    "github.com/milvus-io/milvus-sdk-go": (V, "milvus"),
    "github.com/weaviate/weaviate-go-client": (V, "weaviate"),
    "github.com/pinecone-io/go-pinecone": (V, "pinecone"),
}
JAVA = {
    "dev.langchain4j": (A, "langchain4j"), "org.springframework.ai": (A, "spring-ai"),
    "com.openai": (M, "openai"), "com.anthropic": (M, "anthropic"),
    "io.modelcontextprotocol": (P, "mcp"),
}  # fmt: skip
RUST = {
    "async_openai": (M, "openai"), "ollama_rs": (M, "ollama"), "rig": (A, "rig"),
    "rmcp": (P, "mcp"), "qdrant_client": (V, "qdrant"),
}  # fmt: skip
# PyPI and crates.io package names that differ from their import root.
PYPI_ALIASES = {
    "google-genai": "google.genai", "google-generativeai": "google.generativeai",
    "google-cloud-aiplatform": "vertexai", "llama-cpp-python": "llama_cpp",
    "llama-index": "llama_index", "llama-index-core": "llama_index",
    "pyautogen": "autogen", "haystack-ai": "haystack", "dspy-ai": "dspy",
    "pinecone-client": "pinecone", "faiss-cpu": "faiss", "faiss-gpu": "faiss",
    "weaviate-client": "weaviate",
}  # fmt: skip
CARGO_ALIASES = {"async-openai": "async_openai", "ollama-rs": "ollama_rs"}

Hit = tuple[LlmAppKind, str]
LANGUAGES = {
    ".py": "python", ".js": "js", ".jsx": "js", ".mjs": "js", ".cjs": "js", ".ts": "js",
    ".tsx": "js", ".mts": "js", ".cts": "js", ".go": "go", ".java": "java", ".kt": "java",
    ".rs": "rust",
}  # fmt: skip
_SKIP = SKIP_DIRS | {"site-packages"}
PROMPT_SUFFIXES = (".prompt", ".prompty", ".prompt.yaml", ".prompt.yml", ".prompt.md")
PROMPT_DIR_SUFFIXES = (
    ".txt", ".md", ".j2", ".jinja", ".jinja2", ".mustache", ".hbs", ".tmpl", ".yaml", ".yml",
)  # fmt: skip

_PY_IMPORT = re.compile(
    r"^\s*(?:from\s+([A-Za-z_][\w.]*)\s+import\b|"
    r"import\s+([A-Za-z_][\w.]*(?:\s*,\s*[A-Za-z_][\w.]*)*))"
)
_JS_IMPORT = re.compile(
    r"""\bfrom\s*['"]([^'"]+)['"]|\bimport\s*['"]([^'"]+)['"]|"""
    r"""\brequire\s*\(\s*['"]([^'"]+)['"]\s*\)|\bimport\s*\(\s*['"]([^'"]+)['"]\s*\)"""
)
_GO_IMPORT = re.compile(r'^\s*(?:import\s+)?(?:[\w.]+\s+)?"([^"]+)"')
_JAVA_IMPORT = re.compile(r"^\s*import\s+(?:static\s+)?([\w.]+)")
_RUST_USE = re.compile(r"^\s*(?:pub\s+)?(?:use|extern\s+crate)\s+([A-Za-z_]\w*)")
_PY_LOCAL = re.compile(r"^\s*(?:from\s+(\.*[\w.]*)\s+import\s+([\w*, ()]+)|import\s+([\w.]+))")
_JS_LOCAL = re.compile(
    r"""(?:\bfrom\s*|\brequire\s*\(\s*|\bimport\s*\(?\s*)['"](\.{1,2}/[^'"]+)['"]"""
)
_JS_EXTS = (".ts", ".tsx", ".js", ".jsx", ".mjs", ".cjs", ".mts", ".cts")
_YAML_ITEM = re.compile(r"(?m)^\s*-\s*([A-Za-z0-9][A-Za-z0-9._-]*)")
_REQUIREMENT = re.compile(r"^\s*([A-Za-z0-9][A-Za-z0-9._-]*)")
_SETUP_LIST = re.compile(r"install_requires\s*=\s*\[([^\]]*)\]", re.S)
_QUOTED = re.compile(r"""['"]([^'"]+)['"]""")
_POM_DEP = re.compile(r"<dependency>.*?<groupId>([^<]+)</groupId>.*?</dependency>", re.S)
_GRADLE_DEP = re.compile(r"""\b\w+\s*\(?\s*['"]([\w.-]+):[\w.-]+(?::[^'"]*)?['"]""")
_GOMOD_REQUIRE = re.compile(r"(?m)^\s*(?:require\s+)?([\w.~/-]+\.[\w.~/-]+)\s+v\S+(.*)$")


def _python_match(module: str) -> Hit | None:
    parts = module.split(".")
    for n in range(len(parts), 0, -1):
        if hit := PYTHON.get(".".join(parts[:n])):
            return hit
    return None


def _npm_match(spec: str) -> Hit | None:
    if spec.startswith((".", "/")):
        return None
    if hit := NPM.get(spec):
        return hit
    for prefix, hit in NPM.items():
        if prefix.endswith("/") and spec.startswith(prefix):
            return hit
    parts = spec.split("/")
    return NPM.get("/".join(parts[:2]) if spec.startswith("@") else parts[0])


def _prefix_match(path: str, table: dict[str, Hit]) -> Hit | None:
    for prefix, hit in table.items():
        if path == prefix or path.startswith((prefix + "/", prefix + ".")):
            return hit
    return None


def _imports(lang: str, text: str) -> Iterator[tuple[int, Hit]]:
    in_go_block = False
    for lineno, line in enumerate(text.splitlines(), 1):
        hits: list[Hit | None] = []
        if lang == "python" and (m := _PY_IMPORT.match(line)):
            mods = [m.group(1)] if m.group(1) else [s.strip() for s in m.group(2).split(",")]
            hits = [_python_match(mod) for mod in mods]
        elif lang == "js":
            hits = [_npm_match(next(g for g in m.groups() if g)) for m in _JS_IMPORT.finditer(line)]
        elif lang == "go":
            stripped = line.strip()
            if stripped.startswith("import ("):
                in_go_block = True
                continue
            if in_go_block and stripped.startswith(")"):
                in_go_block = False
                continue
            if (in_go_block or stripped.startswith("import ")) and (m := _GO_IMPORT.match(line)):
                hits = [_prefix_match(m.group(1), GO)]
        elif lang == "java" and (m := _JAVA_IMPORT.match(line)):
            hits = [_prefix_match(m.group(1), JAVA)]
        elif lang == "rust" and (m := _RUST_USE.match(line)):
            hits = [RUST.get(m.group(1))]
        for hit in hits:
            if hit:
                yield lineno, hit


def _python_locals(rel: str, text: str, known: set[str]) -> set[str]:
    here, out = PurePosixPath(rel).parent, set()
    for line in text.splitlines():
        if not (m := _PY_LOCAL.match(line)):
            continue
        if m.group(3):
            mods = [m.group(3)]
        else:
            base, names = m.group(1), m.group(2)
            dots = len(base) - len(base.lstrip("."))
            root = here
            for _ in range(max(dots - 1, 0)):
                root = root.parent
            prefix = (root.as_posix() + "/" if root.as_posix() != "." else "") if dots else ""
            stem = base.lstrip(".")
            dotted = prefix.replace("/", ".")
            mods = [dotted + stem] if stem else []
            mods += [
                f"{dotted}{stem + '.' if stem else ''}{n}"
                for n in re.split(r"[,\s()]+", names)
                if n and n != "*"
            ]
        for mod in mods:
            path = mod.strip(".").replace(".", "/")
            out.update(c for c in (f"{path}.py", f"{path}/__init__.py") if c in known)
    return out


def _js_locals(rel: str, text: str, known: set[str]) -> set[str]:
    here, out = PurePosixPath(rel).parent, set()
    for m in _JS_LOCAL.finditer(text):
        parts: list[str] = []
        for seg in (here / m.group(1)).as_posix().split("/"):
            if seg == "..":
                if parts:
                    parts.pop()
            elif seg not in (".", ""):
                parts.append(seg)
        base = "/".join(parts)
        stem = re.sub(r"\.(js|mjs|cjs)$", "", base)
        candidates = [base, *(stem + e for e in _JS_EXTS), *(f"{base}/index{e}" for e in _JS_EXTS)]
        out.update(c for c in candidates if c in known)
    return out


def _is_prompt_template(rel: str) -> bool:
    low = rel.lower()
    if low.endswith(PROMPT_SUFFIXES):
        return True
    parts = PurePosixPath(low).parts
    return any(p in ("prompt", "prompts") for p in parts[:-1]) and low.endswith(PROMPT_DIR_SUFFIXES)


def _pypi_hit(name: str) -> Hit | None:
    norm = re.sub(r"[-_.]+", "-", name).lower()
    return _python_match(PYPI_ALIASES.get(norm, norm.replace("-", "_")))


def _toml(text: str) -> dict:
    try:
        return tomllib.loads(text)
    except tomllib.TOMLDecodeError:
        return {}  # a malformed manifest only costs its signals


def _pyproject_names(text: str) -> list[str]:
    doc = _toml(text)
    project = doc.get("project") or {}
    specs = list(project.get("dependencies") or [])
    for group in (project.get("optional-dependencies") or {}).values():
        specs += group
    names = [m.group(1) for s in specs if isinstance(s, str) and (m := _REQUIREMENT.match(s))]
    poetry = (doc.get("tool") or {}).get("poetry") or {}
    names += list(poetry.get("dependencies") or {}) + list(poetry.get("dev-dependencies") or {})
    for group in (poetry.get("group") or {}).values():
        names += list((group or {}).get("dependencies") or {})
    return names


def _cargo_names(text: str) -> list[str]:
    doc = _toml(text)
    tables = [doc.get(k) or {} for k in ("dependencies", "dev-dependencies")]
    return [name for t in tables if isinstance(t, dict) for name in t]


def _package_json_names(text: str) -> list[str]:
    try:
        doc = json.loads(text)
    except ValueError:
        return []
    if not isinstance(doc, dict):
        return []
    keys = ("dependencies", "devDependencies")
    return [name for k in keys if isinstance(doc.get(k), dict) for name in doc[k]]


def _declared(f: TreeFile) -> list[tuple[str, Hit]]:
    """(package, hit) for each LLM library a manifest declares directly."""
    name, text = f.name, f.text
    if name == "go.mod":
        found = [
            (m.group(1), hit)
            for m in _GOMOD_REQUIRE.finditer(text)
            if "// indirect" not in m.group(2) and (hit := _prefix_match(m.group(1), GO))
        ]
        return found
    if _is_requirements(name):
        lines = [ln for ln in text.splitlines() if not ln.lstrip().startswith(("#", "-"))]
        pairs = [
            (m.group(1), _pypi_hit(m.group(1))) for ln in lines if (m := _REQUIREMENT.match(ln))
        ]
    elif name in ("environment.yml", "environment.yaml"):
        pairs = [(m.group(1), _pypi_hit(m.group(1))) for m in _YAML_ITEM.finditer(text)]
    elif name == "pyproject.toml":
        pairs = [(n, _pypi_hit(n)) for n in _pyproject_names(text)]
    elif name == "setup.py":
        pairs = [
            (m.group(1), _pypi_hit(m.group(1)))
            for block in _SETUP_LIST.findall(text)
            for q in _QUOTED.findall(block)
            if (m := _REQUIREMENT.match(q))
        ]
    elif name == "package.json":
        pairs = [(n, _npm_match(n)) for n in _package_json_names(text)]
    elif name == "pom.xml":
        pairs = [(g.strip(), _prefix_match(g.strip(), JAVA)) for g in _POM_DEP.findall(text)]
    elif name in ("build.gradle", "build.gradle.kts"):
        pairs = [(g, _prefix_match(g, JAVA)) for g in _GRADLE_DEP.findall(text)]
    elif name == "Cargo.toml":
        pairs = [
            (n, RUST.get(CARGO_ALIASES.get(n, n.replace("-", "_")))) for n in _cargo_names(text)
        ]
    else:
        return []
    return [(dep, hit) for dep, hit in pairs if hit]


_MANIFESTS = ("go.mod", "pyproject.toml", "setup.py", "package.json", "pom.xml", "build.gradle",
              "build.gradle.kts", "Cargo.toml", "environment.yml", "environment.yaml")  # fmt: skip


def _is_requirements(name: str) -> bool:
    return name.endswith(".txt") and ("requirements" in name.lower() or name == "constraints.txt")


def _is_manifest(name: str) -> bool:
    return name in _MANIFESTS or _is_requirements(name)


class _Signals:
    def __init__(self) -> None:
        self.via: dict[Hit, set[LlmSignalSource]] = defaultdict(set)
        self.evidence: dict[Hit, list[CodeSpan]] = defaultdict(list)

    def note(self, hit: Hit, source: LlmSignalSource, span: CodeSpan) -> None:
        self.via[hit].add(source)
        if len(self.evidence[hit]) < 25 and span not in self.evidence[hit]:
            self.evidence[hit].append(span)

    def models(self) -> list[LlmAppSignal]:
        return [
            LlmAppSignal(
                kind=kind,
                library=library,
                via=tuple(sorted(self.via[(kind, library)])),
                evidence=tuple(self.evidence[(kind, library)]),
            )
            for kind, library in sorted(self.via, key=lambda h: (_ORDER.index(h[0]), h[1]))
        ]


def llm_app(files: list[TreeFile]) -> LlmAppFact:
    """The detection over a checkout's files: signals, tagged files and what was read."""
    signals = _Signals()
    tagged: dict[str, set[LlmAppKind]] = defaultdict(set)
    sources: dict[str, tuple[str, str]] = {}
    manifests = 0
    for f in files:
        lang = LANGUAGES.get(f.path.suffix)
        if _is_prompt_template(f.rel):
            hit = (LlmAppKind.PROMPT_TEMPLATE, "prompt-files")
            signals.note(hit, LlmSignalSource.FILE, CodeSpan(path=RepoPath(f.rel)))
            tagged[f.rel].add(LlmAppKind.PROMPT_TEMPLATE)
        if lang:
            sources[f.rel] = (lang, f.text)
            for lineno, hit in _imports(lang, f.text):
                signals.note(
                    hit, LlmSignalSource.IMPORT, CodeSpan(path=RepoPath(f.rel), line=lineno)
                )
                tagged[f.rel].add(hit[0])
        if _is_manifest(f.name):
            manifests += 1
            for dep, hit in _declared(f):
                span = CodeSpan(path=RepoPath(f.rel), symbol=dep)
                signals.note(hit, LlmSignalSource.DECLARED, span)
    # One hop: a file importing a tagged in-repo module (an internal SDK wrapper) uses it too.
    code_tagged = {rel for rel, k in tagged.items() if k - {LlmAppKind.PROMPT_TEMPLATE}}
    known = set(sources)
    wrappers: dict[str, set[str]] = {}
    for rel, (lang, text) in sources.items():
        if rel in code_tagged:
            continue
        local = (
            _python_locals(rel, text, known)
            if lang == "python"
            else (_js_locals(rel, text, known) if lang == "js" else set())
        )
        if targets := (local - {rel}) & code_tagged:
            wrappers[rel] = targets
    for rel, targets in wrappers.items():
        for target in targets:
            tagged[rel].update(tagged[target] - {LlmAppKind.PROMPT_TEMPLATE})
    found = signals.models()
    return LlmAppFact(
        llm_application=bool(found),
        kinds=tuple(sorted({s.kind for s in found}, key=_ORDER.index)),
        signals=tuple(found),
        files=tuple(
            LlmTaggedFile(
                path=RepoPath(rel),
                kinds=tuple(sorted(kinds, key=_ORDER.index)),
                via_wrapper=tuple(RepoPath(t) for t in sorted(wrappers.get(rel, ()))),
            )
            for rel, kinds in sorted(tagged.items())
        ),
        stats=LlmAppStats(source_files_read=len(sources), manifests_read=manifests),
    )


class LlmAppDetector:
    kind = CodeFactKind.LLM_APP
    name = "llm-app"

    def __init__(self, clock: Clock) -> None:
        self._clock = clock

    def check(self) -> Readiness:
        return Readiness(ready=True)

    def enumerate(self, request: ToolRequest) -> Result[list[CodeFactDetail]]:
        fact = llm_app(tree_files(request.checkout(), _SKIP))
        return Result([fact], Acquisition(provider=self.name, acquired_at=self._clock.now()))
