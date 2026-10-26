"""LLM, agent and MCP application detection: imports, declarations, prompts, negatives. Ported
from traust-engine tests/test_llm_app.py."""

from __future__ import annotations

from datetime import UTC, datetime
from pathlib import Path

import pytest

from traust_core.v1.errors import ValidationError
from traust_core.v1.models.code_facts import LlmAppFact, LlmAppKind, LlmSignalSource
from traust_core.v1.providers.clock import FixedClock
from traust_core.v1.providers.llm_app import _SKIP, LlmAppDetector, llm_app
from traust_core.v1.providers.tools import ToolRequest
from traust_core.v1.providers.tree import tree_files


def write(root: Path, rel: str, text: str) -> None:
    p = root / rel
    p.parent.mkdir(parents=True, exist_ok=True)
    p.write_text(text, encoding="utf-8")


def detect(root: Path) -> LlmAppFact:
    return llm_app(tree_files(root, _SKIP))


def libs(fact: LlmAppFact) -> set[tuple[str, str]]:
    return {(s.kind.value, s.library) for s in fact.signals}


def files(fact: LlmAppFact) -> dict[str, list[str]]:
    return {str(f.path): [k.value for k in f.kinds] for f in fact.files}


def test_a_plain_service_is_not_an_llm_application(tmp_path):
    write(tmp_path, "app.py", "import os\nfrom flask import Flask\n")
    write(tmp_path, "requirements.txt", "flask==3.0.0\n")
    fact = detect(tmp_path)
    assert fact.llm_application is False
    assert fact.signals == () and fact.files == ()
    assert fact.stats.source_files_read == 1 and fact.stats.manifests_read == 1


@pytest.mark.parametrize(
    ("rel", "text", "expected"),
    [
        ("agent.py", "from openai import OpenAI\n", ("model-sdk", "openai")),
        ("a.py", "import anthropic, os\n", ("model-sdk", "anthropic")),
        ("g.py", "from google.genai import types\n", ("model-sdk", "google-genai")),
        (
            "lc.py",
            "from langchain_core.prompts import ChatPromptTemplate\n",
            ("agent-framework", "langchain"),
        ),
        ("srv.py", "from mcp.server.fastmcp import FastMCP\n", ("mcp-server", "mcp")),
        ("rag.py", "import chromadb\n", ("vector-store", "chromadb")),
        (
            "srv.ts",
            "import { McpServer } from '@modelcontextprotocol/sdk/server/mcp.js';\n",
            ("mcp-server", "mcp"),
        ),
        ("c.ts", 'const Anthropic = require("@anthropic-ai/sdk");\n', ("model-sdk", "anthropic")),
        (
            "l.ts",
            "import { ChatOpenAI } from '@langchain/openai';\n",
            ("agent-framework", "langchain"),
        ),
        ("v.ts", "import { generateText } from 'ai';\n", ("model-sdk", "vercel-ai-sdk")),
        (
            "m.go",
            'package m\n\nimport (\n\t"fmt"\n\tmcp "github.com/mark3labs/mcp-go/server"\n)\n',
            ("mcp-server", "mcp"),
        ),
        (
            "o.go",
            'package o\n\nimport "github.com/sashabaranov/go-openai"\n',
            ("model-sdk", "openai"),
        ),
        (
            "A.java",
            "import dev.langchain4j.model.chat.ChatModel;\n",
            ("agent-framework", "langchain4j"),
        ),
        ("main.rs", "use async_openai::Client;\n", ("model-sdk", "openai")),
    ],
)
def test_source_imports_are_detected_with_evidence(tmp_path, rel, text, expected):
    write(tmp_path, rel, text)
    fact = detect(tmp_path)
    assert fact.llm_application is True
    assert expected in libs(fact)
    [sig] = [s for s in fact.signals if (s.kind.value, s.library) == expected]
    assert sig.via == (LlmSignalSource.IMPORT,)
    assert str(sig.evidence[0].path) == rel and sig.evidence[0].line is not None
    assert files(fact)[rel] == [expected[0]]


def test_lookalikes_are_not_matched(tmp_path):
    write(tmp_path, "x.py", "import openai_helpers_local\nfrom mcpx import y\n")
    write(tmp_path, "y.ts", "import x from './openai';\nimport z from 'aircraft';\n")
    write(tmp_path, "z.go", 'package z\n\nimport "github.com/openai/openai-gopher"\n')
    assert detect(tmp_path).signals == ()


def test_direct_declarations_count_and_lockfiles_do_not(tmp_path):
    write(tmp_path, "requirements.txt", "langchain-core==0.3.0\nqdrant-client>=1.9\n")
    write(tmp_path, "web/package.json", '{"dependencies": {"@modelcontextprotocol/sdk": "1.0.0"}}')
    write(
        tmp_path,
        "web/package-lock.json",
        '{"packages": {"node_modules/openai": {"version": "4.0.0"}}}',
    )
    write(
        tmp_path,
        "go.mod",
        "module x\n\nrequire (\n\tgithub.com/tmc/langchaingo v0.1.0\n"
        "\tgithub.com/qdrant/go-client v1.0.0 // indirect\n)\n",
    )
    fact = detect(tmp_path)
    assert libs(fact) == {
        ("agent-framework", "langchain"),
        ("vector-store", "qdrant"),
        ("mcp-server", "mcp"),
        ("agent-framework", "langchaingo"),
    }  # not openai (lockfile only), not the indirect qdrant go client
    assert all(s.via == (LlmSignalSource.DECLARED,) for s in fact.signals)
    [mcp] = [s for s in fact.signals if s.library == "mcp"]
    assert mcp.evidence[0].symbol == "@modelcontextprotocol/sdk"
    assert fact.files == ()  # declarations tag no source file


@pytest.mark.parametrize(
    ("rel", "text", "expected"),
    [
        (
            "pyproject.toml",
            '[project]\ndependencies = ["anthropic>=0.30"]\n'
            '[project.optional-dependencies]\nrag = ["chromadb"]\n',
            {("model-sdk", "anthropic"), ("vector-store", "chromadb")},
        ),
        (
            "pyproject.toml",
            '[tool.poetry.dependencies]\npython = "^3.11"\nlangchain = "*"\n',
            {("agent-framework", "langchain")},
        ),
        (
            "setup.py",
            "setup(install_requires=['openai>=1', 'requests'])\n",
            {("model-sdk", "openai")},
        ),
        (
            "pom.xml",
            "<project><dependencies><dependency><groupId>dev.langchain4j</groupId>"
            "<artifactId>langchain4j</artifactId></dependency></dependencies></project>",
            {("agent-framework", "langchain4j")},
        ),
        (
            "build.gradle.kts",
            'dependencies {\n    implementation("org.springframework.ai:spring-ai-core:1.0")\n}\n',
            {("agent-framework", "spring-ai")},
        ),
        (
            "Cargo.toml",
            '[dependencies]\nasync-openai = "0.20"\nserde = "1"\n',
            {("model-sdk", "openai")},
        ),
        ("pyproject.toml", "[project\nbroken", set()),
        ("package.json", "not json", set()),
    ],
)
def test_each_manifest_shape_declares_its_libraries(tmp_path, rel, text, expected):
    write(tmp_path, rel, text)
    assert libs(detect(tmp_path)) == expected


def test_prompt_templates(tmp_path):
    write(tmp_path, "prompts/summarize.j2", "Summarize {{ text }}")
    write(tmp_path, "app/review.prompty", "---\nname: review\n---\n")
    write(tmp_path, "docs/notes.md", "not a prompt")
    fact = detect(tmp_path)
    assert libs(fact) == {("prompt-template", "prompt-files")}
    assert set(files(fact)) == {"prompts/summarize.j2", "app/review.prompty"}
    assert fact.signals[0].via == (LlmSignalSource.FILE,)


def test_vendored_and_dependency_dirs_are_skipped(tmp_path):
    for d in ("node_modules/openai", "vendor/github.com/x", ".venv/lib", "site-packages/y"):
        write(tmp_path, f"{d}/index.py", "import openai\n")
    write(tmp_path, "node_modules/x/index.js", "require('openai')\n")
    assert detect(tmp_path).llm_application is False


def test_kinds_are_ordered_and_evidence_capped(tmp_path):
    for i in range(40):
        write(tmp_path, f"m{i}.py", "import openai\nimport chromadb\n")
    fact = detect(tmp_path)
    assert fact.kinds == (LlmAppKind.MODEL_SDK, LlmAppKind.VECTOR_STORE)
    assert all(len(s.evidence) <= 25 for s in fact.signals)
    assert len(fact.files) == 40


def test_a_file_using_an_in_repo_wrapper_is_tagged(tmp_path):
    write(tmp_path, "app/llm.py", "from openai import OpenAI\n")
    write(tmp_path, "app/reports.py", "from app.llm import complete\n")
    write(tmp_path, "app/relative.py", "from .llm import complete\n")
    write(tmp_path, "app/plain.py", "import json\n")
    fact = detect(tmp_path)
    by_path = {str(f.path): f for f in fact.files}
    assert files(fact)["app/reports.py"] == ["model-sdk"]
    assert files(fact)["app/relative.py"] == ["model-sdk"]
    assert "app/plain.py" not in by_path
    assert [str(p) for p in by_path["app/reports.py"].via_wrapper] == ["app/llm.py"]
    assert [str(p) for p in by_path["app/relative.py"].via_wrapper] == ["app/llm.py"]
    assert by_path["app/llm.py"].via_wrapper == ()


def test_the_wrapper_hop_covers_relative_js_imports(tmp_path):
    write(tmp_path, "src/lib/model.ts", "import OpenAI from 'openai';\n")
    write(tmp_path, "src/routes/chat.ts", "import { ask } from '../lib/model';\n")
    write(tmp_path, "src/routes/index.js", "const m = require('./chat.js');\n")
    fact = detect(tmp_path)
    assert files(fact)["src/routes/chat.ts"] == ["model-sdk"]
    # one hop only: index.js imports chat.ts, which is tagged only via the wrapper
    assert "src/routes/index.js" not in files(fact)


def test_the_detector_is_one_fact_with_provenance(tmp_path):
    write(tmp_path, "a.py", "import openai\n")
    detector = LlmAppDetector(FixedClock(datetime(2026, 10, 26, tzinfo=UTC)))
    assert detector.check().ready
    result = detector.enumerate(ToolRequest(workspace=tmp_path))
    assert [type(f) for f in result.data] == [LlmAppFact]
    assert result.acquisition.provider == "llm-app"


def test_not_a_directory(tmp_path):
    with pytest.raises(ValidationError):
        LlmAppDetector(FixedClock(datetime(2026, 10, 26, tzinfo=UTC))).enumerate(
            ToolRequest(workspace=tmp_path / "missing")
        )
