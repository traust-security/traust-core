"""Config matrix: a checkout's effective deployed defaults as (key, default, sink) triples, all
static (helm values, kustomize literals, compose and k8s env, code-side env fallbacks, Python
settings parsed and never imported). Shipped defaults plus single override files, never their
cross-product; systems it can't expand are coverage gaps."""

from __future__ import annotations

import ast
import re
from collections.abc import Callable, Iterator
from pathlib import Path
from typing import Any

from traust_core.v1.errors import ValidationError
from traust_core.v1.models.code_facts import (
    CodeFactDetail,
    CodeFactKind,
    ConfigClass,
    ConfigFact,
    ConfigSink,
    ConfigSource,
    ConfigSystem,
    ConfigTriple,
    CoverageGap,
    SinkStatus,
)
from traust_core.v1.models.common import CodeSpan, RepoPath
from traust_core.v1.providers.base import Acquisition, Readiness, Result
from traust_core.v1.providers.clock import Clock
from traust_core.v1.providers.tools import ToolRequest
from traust_core.v1.providers.tree import TreeFile, tree_files

MAX_TRIPLES = 2000
_GAP_PATHS = 20

# First match wins; run over "<key>=<value>" so a composed fact (sslmode=disable) matches.
CLASS_PATTERNS = (
    (
        ConfigClass.DSN,
        re.compile(
            r"(sslmode|ssl_mode|dsn|database_url|db_url|connection_string|"
            r"jdbc:|postgres(ql)?://|mysql://|mongodb(\+srv)?://|redis://|"
            r"amqps?://)",
            re.I,
        ),
    ),
    (
        ConfigClass.TLS,
        re.compile(
            r"(tls|ssl|https?_only|insecure|skip[_-]?verify|verify[_-]?"
            r"(peer|cert|hostname|ssl|tls)|ca[_-]?(file|cert|bundle)|"
            r"cert[_-]?file|key[_-]?file|cipher|min[_-]?version)",
            re.I,
        ),
    ),
    (
        ConfigClass.AUTH,
        re.compile(
            r"(auth|anonymous|no[_-]?login|allow[_-]?guest|rbac|"
            r"authoriz|authentic|oidc|oauth|token[_-]?(auth|required)|"
            r"api[_-]?key|basic[_-]?auth|require[_-]?(auth|login)|csrf|"
            r"skip[_-]?auth|verify\w*signature|signature\w*verif)",
            re.I,
        ),
    ),
    (
        ConfigClass.SECRET,
        re.compile(
            r"(password|passwd|secret|credential|private[_-]?key|"
            r"access[_-]?key|client[_-]?secret|signing[_-]?key|encryption[_-]?key|"
            r"hmac[_-]?key|(?<![a-z])salt(?![a-z]))",
            re.I,
        ),
    ),
    (
        ConfigClass.LISTENER,
        re.compile(
            r"(listen|bind[_-]?(addr|address|host|ip)|0\.0\.0\.0|"
            r"host[_-]?(addr|address)?=|expose|public[_-]?(addr|url|port))",
            re.I,
        ),
    ),
    (
        ConfigClass.DEBUG,
        re.compile(
            r"(debug|pprof|profil|trace[_-]?enabled|verbose|dev[_-]?mode|"
            r"development[_-]?mode|test[_-]?mode|\btesting\b)",
            re.I,
        ),
    ),
)
# Orders the worklist only: the judge sees every relevant triple either way.
WEAK_VALUE_RX = re.compile(
    r"^(disable[d]?|allow|prefer|false|0|off|none|noverify|insecure|"
    r"anonymous|guest|admin|changeme|password|0\.0\.0\.0(:\d+)?|\*|"
    r"http://.*)$",
    re.I,
)
_CRED_SUFFIXES = ("key", "token", "salt", "secret", "password", "passwd")
_NOT_SECRET_NAMES = {"primarykey", "foreignkey", "publickey", "sortkey", "partitionkey",
                     "cachekey", "idempotencykey"}  # fmt: skip
URL_USERINFO_RX = re.compile(
    r"(?P<scheme>[a-z][a-z0-9+.-]*://)(?P<user>[^:/@\s]*):(?P<pw>[^@/\s]+)@", re.I
)
_HELM_VALUES = re.compile(r"^values([.-].*)?\.ya?ml$")
_COMPOSE = re.compile(r"^(docker-)?compose([.-].*)?\.ya?ml$")
_WORKLOAD_KINDS = {"Deployment", "StatefulSet", "DaemonSet", "CronJob", "Job", "Pod"}
_VALUES_USE = re.compile(r"\.Values\.([A-Za-z0-9_.]+)")
_GO_GETENV = re.compile(r'(?P<var>\w+)\s*:?=\s*os\.(?:Getenv|LookupEnv)\(\s*"(?P<key>[^"]+)"\s*\)')
_GO_IF_EMPTY = r'if\s+{var}\s*==\s*""\s*\{{\s*{var}\s*=\s*"(?P<default>[^"]*)"'
_GO_CMP_OR = re.compile(
    r'cmp\.Or\(\s*os\.Getenv\(\s*"(?P<key>[^"]+)"\s*\)\s*,\s*"(?P<default>[^"]*)"\s*\)'
)
_GO_VIPER = re.compile(
    r'viper\.SetDefault\(\s*"(?P<key>[^"]+)"\s*,\s*(?P<default>"[^"]*"|true|false|[\d.]+)\s*\)'
)
_PY_GET = re.compile(
    r'os\.(?:environ\.get|getenv)\(\s*["\'](?P<key>[^"\']+)["\']\s*,\s*'
    r'(?P<default>"[^"]*"|\'[^\']*\'|True|False|None|[\d.]+)\s*\)'
)
_JS_ENV = re.compile(
    r"process\.env\.(?P<key>\w+)\s*(?:\|\||\?\?)\s*"
    r'(?P<default>"[^"]*"|\'[^\']*\'|`[^`]*`|true|false|[\d.]+)'
)
_ENV_CHAIN = {
    ".go": ConfigSystem.ENV_CHAIN_GO,
    ".py": ConfigSystem.ENV_CHAIN_PYTHON,
    ".js": ConfigSystem.ENV_CHAIN_JS,
    ".ts": ConfigSystem.ENV_CHAIN_JS,
    ".mjs": ConfigSystem.ENV_CHAIN_JS,
    ".jsx": ConfigSystem.ENV_CHAIN_JS,
    ".tsx": ConfigSystem.ENV_CHAIN_JS,
}
_TEST_FILE = re.compile(r"(^|[._-])(test|spec|mock|fixture)s?([._-]|$)")
_TEST_DIRS = {"tests", "test", "testing", "fixtures"}
_PY_SETTINGS_FILE = re.compile(r"^(settings|config|conf|configuration)([._-].*)?\.py$", re.I)
_PY_SETTINGS_CLASS = re.compile(r"(Settings|Config|Configuration)$")
_PY_SETTINGS_BASES = {"BaseSettings"}
_UPPER_NAME = re.compile(r"^[A-Z][A-Z0-9_]*$")
_PY_READERS = (
    re.compile(r"\b(?:settings|config|conf|cfg)\s*\.\s*(?P<name>[A-Za-z_]\w*)"),
    re.compile(r"\bconfig\s*(?:\.get\s*\(|\[)\s*[\"'](?P<name>[A-Za-z_]\w*)[\"']"),
    re.compile(r"\bgetattr\s*\(\s*(?:settings|config|conf)\s*,\s*[\"'](?P<name>[A-Za-z_]\w*)[\"']"),
)
_DSN_RX = dict(CLASS_PATTERNS)[ConfigClass.DSN]
_BIND_ALL = re.compile(r"^(0\.0\.0\.0|::|\[::\])(:\d+)?$")
_TRUTHY = {"true", "1", "yes", "on"}
_UNEXPANDED = re.compile(r"\.(toml|ini|properties|conf|cfg)$")

Scalar = str | int | float | bool | None
# Parses YAML text to its documents, ValidationError when malformed; context supplies it.
YamlLoader = Callable[[str], list[object]]


def classify(key: str, value: object) -> tuple[ConfigClass, bool]:
    probe = f"{key}={value}".lower()
    return next(
        ((cls, True) for cls, rx in CLASS_PATTERNS if rx.search(probe)), (ConfigClass.OTHER, False)
    )


def is_weak(value: object) -> bool:
    return bool(WEAK_VALUE_RX.match(str(value).strip()))


def _credential_name(key: str) -> bool:
    """The key's last segment ends in a credential word at a word boundary: SIGNING_KEY,
    apiToken, session-secret; not monkey or public_key."""
    seg = re.split(r"[./]", key)[-1]
    low = seg.lower()
    if re.sub(r"[_-]", "", low) in _NOT_SECRET_NAMES:
        return False
    for suffix in _CRED_SUFFIXES:
        if low == suffix:
            return True
        if low.endswith(suffix) and len(seg) > len(suffix):
            before, first = seg[-len(suffix) - 1], seg[-len(suffix)]
            if before in "_-" or (first.isupper() and before.islower()):
                return True
    return False


def redact(key: str, value: Scalar) -> tuple[Scalar, bool]:
    """(shown, redacted): a literal under a credential-shaped name shows only its length, a URL's
    password is masked; templated or env-reference values are not literals."""
    if not isinstance(value, str) or not value or "${" in value or "{{" in value:
        return value, False
    if classify(key, "")[0] is ConfigClass.SECRET or _credential_name(key):
        return f"<hardcoded literal, {len(value)} chars>", True
    masked, n = URL_USERINFO_RX.subn(r"\g<scheme>\g<user>:<redacted>@", value)
    return (masked, True) if n else (value, False)


def triple(
    key: str,
    value: Scalar,
    system: ConfigSystem,
    path: str,
    line: int | None,
    sink: ConfigSink | None = None,
) -> ConfigTriple:
    shown, redacted = redact(key, value)
    cls, relevant = classify(key, "" if redacted else value)
    if redacted and not relevant:
        cls, relevant = ConfigClass.SECRET, True
    if redacted and sink is not None and sink.expr is not None and isinstance(value, str):
        sink = sink.model_copy(update={"expr": sink.expr.replace(value, str(shown))})
    return ConfigTriple(
        key=key,
        effective_default="" if shown is None else str(shown),
        source=ConfigSource(system=system, path=RepoPath(path), line=line),
        sink=sink or ConfigSink(status=SinkStatus.UNRESOLVED),
        config_class=cls,
        judgement_required=relevant or redacted,
        weak_default=redacted or (relevant and is_weak(value)),
        literal_redacted=redacted,
    )


def _mappings(load: YamlLoader, text: str) -> list[dict[str, Any]]:
    """The mapping documents; a file that doesn't parse is skipped (best effort over a tree)."""
    try:
        return [d for d in load(text) if isinstance(d, dict)]
    except ValidationError:
        return []


def _flatten(prefix: str, node: object, out: dict[str, Scalar]) -> None:
    if isinstance(node, dict):
        for k, v in node.items():
            _flatten(f"{prefix}.{k}" if prefix else str(k), v, out)
    elif isinstance(node, str | int | float | bool) or node is None:
        out[prefix] = node
    # lists: scalars join into one default; index-expanding lists is the cross-product trap
    elif isinstance(node, list) and all(isinstance(i, str | int | float | bool) for i in node):
        out[prefix] = ",".join(str(i) for i in node)


def _line_of(text: str, needle: str) -> int | None:
    return next((i for i, line in enumerate(text.splitlines(), 1) if needle in line), None)


def _rel(root: Path, path: Path) -> str:
    return path.relative_to(root).as_posix()


def _helm(
    load: YamlLoader, root: Path, files: list[TreeFile]
) -> Iterator[ConfigTriple | CoverageGap]:
    for chart in (f.path.parent for f in files if f.name == "Chart.yaml"):
        values = sorted(p for p in chart.iterdir() if p.is_file() and _HELM_VALUES.match(p.name))
        if not values:
            yield CoverageGap(
                system="helm",
                path=RepoPath(_rel(root, chart)),
                reason="chart has no local values*.yaml — defaults resolve only at render time "
                "(v1 never executes helm template)",
            )
            continue
        usage: dict[str, ConfigSink] = {}
        templates = chart / "templates"
        for tpl in sorted(templates.rglob("*")) if templates.is_dir() else ():
            if not tpl.is_file() or tpl.suffix not in (".yaml", ".yml", ".tpl", ".txt"):
                continue
            for i, line in enumerate(TreeFile(_rel(root, tpl), tpl).text.splitlines(), 1):
                for m in _VALUES_USE.finditer(line):
                    usage.setdefault(
                        m.group(1),
                        ConfigSink(
                            status=SinkStatus.TEMPLATE,
                            path=RepoPath(_rel(root, tpl)),
                            line=i,
                            expr=line.strip()[:200],
                        ),
                    )
        for vf in values:
            text = TreeFile(_rel(root, vf), vf).text
            flat: dict[str, Scalar] = {}
            for doc in _mappings(load, text):
                _flatten("", doc, flat)
            for key, value in flat.items():
                yield triple(
                    key,
                    value,
                    ConfigSystem.HELM,
                    _rel(root, vf),
                    _line_of(text, key.split(".")[-1]),
                    usage.get(key),
                )


def _kustomize(load: YamlLoader, files: list[TreeFile]) -> Iterator[ConfigTriple]:
    for f in files:
        if not re.fullmatch(r"kustomization\.y.*ml", f.name):
            continue
        for doc in _mappings(load, f.text):
            for gen_key in ("configMapGenerator", "secretGenerator"):
                for gen in doc.get(gen_key) or []:
                    for lit in gen.get("literals") or [] if isinstance(gen, dict) else []:
                        if isinstance(lit, str) and "=" in lit:
                            k, _, v = lit.partition("=")
                            yield triple(k, v, ConfigSystem.KUSTOMIZE, f.rel, _line_of(f.text, lit))


def _compose(load: YamlLoader, files: list[TreeFile]) -> Iterator[ConfigTriple]:
    for f in files:
        if not _COMPOSE.match(f.name):
            continue
        for doc in _mappings(load, f.text):
            services = doc.get("services")
            for service, svc in services.items() if isinstance(services, dict) else ():
                env = svc.get("environment") if isinstance(svc, dict) else None
                items: list[tuple[Any, Any]] = []
                if isinstance(env, dict):
                    items = list(env.items())
                elif isinstance(env, list):
                    items = [
                        tuple(e.partition("=")[::2]) for e in env if isinstance(e, str) and "=" in e
                    ]
                for k, v in items:
                    yield triple(
                        str(k),
                        v,
                        ConfigSystem.COMPOSE,
                        f.rel,
                        _line_of(f.text, str(k)),
                        ConfigSink(status=SinkStatus.SERVICE, service=str(service)),
                    )


def _k8s(load: YamlLoader, files: list[TreeFile]) -> Iterator[ConfigTriple]:
    for f in files:
        if f.path.suffix not in (".yaml", ".yml") or "templates" in f.parts:
            continue
        if _COMPOSE.match(f.name) or _HELM_VALUES.match(f.name) or "kind:" not in f.text:
            continue
        for doc in _mappings(load, f.text):
            kind = doc.get("kind")
            if kind == "ConfigMap":
                data = doc.get("data")
                for k, v in data.items() if isinstance(data, dict) else ():
                    if not (isinstance(v, str) and len(v) > 300):  # embedded file bodies
                        yield triple(
                            str(k), v, ConfigSystem.K8S_CONFIGMAP, f.rel, _line_of(f.text, str(k))
                        )
            elif kind in _WORKLOAD_KINDS:
                spec = doc.get("spec") or {}
                tpl = (
                    (spec.get("jobTemplate") or {}).get("spec", {}).get("template")
                    or spec.get("template")
                    or {}
                )
                pod = tpl.get("spec") or {}
                for ctr in (pod.get("containers") or []) + (pod.get("initContainers") or []):
                    for env in ctr.get("env") or [] if isinstance(ctr, dict) else []:
                        if isinstance(env, dict) and "value" in env:
                            yield triple(
                                str(env.get("name")),
                                env.get("value"),
                                ConfigSystem.K8S_ENV,
                                f.rel,
                                _line_of(f.text, str(env.get("name"))),
                                ConfigSink(status=SinkStatus.CONTAINER, container=ctr.get("name")),
                            )


def _strip_quotes(s: str) -> str:
    s = s.strip()
    return s[1:-1] if len(s) >= 2 and s[0] in "\"'`" and s[-1] == s[0] else s


def _code_triple(
    f: TreeFile, system: ConfigSystem, key: str, default: str, offset: int, expr: str
) -> ConfigTriple:
    line = f.text.count("\n", 0, offset) + 1
    sink = ConfigSink(
        status=SinkStatus.CODE, path=RepoPath(f.rel), line=line, expr=expr.strip()[:200]
    )
    return triple(key, default, system, f.rel, line, sink)


def _env_chain(files: list[TreeFile]) -> Iterator[ConfigTriple]:
    for f in files:
        system = _ENV_CHAIN.get(f.path.suffix)
        name = f.name.lower()
        if system is None or name.endswith("_test.go") or _TEST_FILE.search(name):
            continue
        text = f.text
        if system is ConfigSystem.ENV_CHAIN_GO:
            for m in _GO_CMP_OR.finditer(text):
                yield _code_triple(f, system, m["key"], m["default"], m.start(), m.group(0))
            for m in _GO_VIPER.finditer(text):
                default = _strip_quotes(m["default"])
                yield _code_triple(f, system, m["key"], default, m.start(), m.group(0))
            lines = text.splitlines()
            for m in _GO_GETENV.finditer(text):
                var, key = m["var"], m["key"]
                ln = text.count("\n", 0, m.start()) + 1
                window = "\n".join(lines[ln - 1 : ln + 8])
                if found := re.search(_GO_IF_EMPTY.format(var=re.escape(var)), window):
                    default = found["default"]
                    expr = f'{var} := os.Getenv("{key}") // fallback "{default}"'
                    yield _code_triple(f, system, key, default, m.start(), expr)
        else:
            rx = _PY_GET if system is ConfigSystem.ENV_CHAIN_PYTHON else _JS_ENV
            for m in rx.finditer(text):
                if m["default"] != "None":
                    default = _strip_quotes(m["default"])
                    yield _code_triple(f, system, m["key"], default, m.start(), m.group(0))


def _is_test_file(f: TreeFile) -> bool:
    return (
        f.name == "conftest.py"
        or bool(_TEST_FILE.search(f.name.lower()))
        or any(p in _TEST_DIRS for p in f.parts[:-1])
    )


def _base_names(node: ast.ClassDef) -> set[str]:
    return {
        b.id if isinstance(b, ast.Name) else b.attr
        for b in node.bases
        if isinstance(b, ast.Name | ast.Attribute)
    }


def _settings_assignments(
    body: list[ast.stmt], field_ok: Callable[[str], object]
) -> Iterator[tuple[str, Scalar, int]]:
    """(name, value, line) for literal assignments; computed values and env reads are skipped."""
    for stmt in body:
        if isinstance(stmt, ast.Assign):
            targets, value = stmt.targets, stmt.value
        elif isinstance(stmt, ast.AnnAssign) and stmt.value is not None:
            targets, value = [stmt.target], stmt.value
        else:
            continue
        if not (
            isinstance(value, ast.Constant)
            and (value.value is None or isinstance(value.value, str | int | float | bool))
        ):
            continue
        for target in targets:
            if isinstance(target, ast.Name) and field_ok(target.id):
                yield target.id, value.value, stmt.lineno


def _python_readers(files: list[TreeFile]) -> dict[str, list[CodeSpan]]:
    readers: dict[str, list[CodeSpan]] = {}
    for f in files:
        for n, line in enumerate(f.text.splitlines(), 1):
            for rx in _PY_READERS:
                for m in rx.finditer(line):
                    readers.setdefault(m["name"], []).append(CodeSpan(path=RepoPath(f.rel), line=n))
    return readers


def _classify_setting(name: str, value: Scalar) -> tuple[ConfigClass, bool]:
    """By the setting's NAME (values are often module paths matching class words by accident);
    the value marks only a DSN or a bind-all listener."""
    cls, relevant = classify(name, "")
    if not relevant and isinstance(value, str):
        if _DSN_RX.search(value):
            return ConfigClass.DSN, True
        if _BIND_ALL.match(value.strip()):
            return ConfigClass.LISTENER, True
    return cls, relevant


def _settings_triple(
    key: str, name: str, value: Scalar, rel: str, line: int, readers: dict[str, list[CodeSpan]]
) -> ConfigTriple:
    sites = readers.get(name, [])
    sink = (
        ConfigSink(status=SinkStatus.READERS, sites=tuple(sites[:10]), count=len(sites))
        if sites
        else None
    )
    t = triple(key, value, ConfigSystem.PYTHON_SETTINGS, rel, line, sink)
    if t.literal_redacted:
        return t
    cls, relevant = _classify_setting(name, value)
    weak = (str(value).strip().lower() in _TRUTHY) if cls is ConfigClass.DEBUG else is_weak(value)
    return t.model_copy(
        update={
            "config_class": cls,
            "judgement_required": relevant,
            "weak_default": relevant and weak,
        }
    )


def _python_settings(files: list[TreeFile]) -> Iterator[ConfigTriple | CoverageGap]:
    """Settings modules' UPPER_CASE literals, and settings classes' literals (UPPER_CASE, or every
    field of a BaseSettings), each sinking into the setting's readers."""
    py = [f for f in files if f.path.suffix == ".py" and not _is_test_file(f)]
    readers: dict[str, list[CodeSpan]] | None = None
    unparsed = []
    for f in py:
        is_module = bool(_PY_SETTINGS_FILE.match(f.name))
        if not is_module and "class " not in f.text:
            continue
        try:
            tree = ast.parse(f.text, filename=f.rel)
        except (SyntaxError, ValueError):
            if is_module:
                unparsed.append(RepoPath(f.rel))
            continue
        found = (
            [(n, n, v, line) for n, v, line in _settings_assignments(tree.body, _UPPER_NAME.match)]
            if is_module
            else []
        )
        for node in ast.walk(tree):
            if not isinstance(node, ast.ClassDef):
                continue
            pydantic = bool(_base_names(node) & _PY_SETTINGS_BASES)
            if not (pydantic or _PY_SETTINGS_CLASS.search(node.name)):
                continue

            def field_ok(name: str, every: bool = pydantic) -> bool:
                return not name.startswith("_") and (every or bool(_UPPER_NAME.match(name)))

            found += [
                (f"{node.name}.{n}", n, v, line)
                for n, v, line in _settings_assignments(node.body, field_ok)
            ]
        if found and readers is None:
            readers = _python_readers(py)
        for key, name, value, line in found:
            yield _settings_triple(key, name, value, f.rel, line, readers or {})
    if unparsed:
        yield CoverageGap(
            system="python-settings",
            reason="settings module that does not parse — defaults not enumerated",
            paths=tuple(unparsed[:_GAP_PATHS]),
            count=len(unparsed),
        )


def _unexpanded(files: list[TreeFile]) -> Iterator[CoverageGap]:
    config_files = [RepoPath(f.rel) for f in files if _UNEXPANDED.search(f.name)]
    if config_files:
        yield CoverageGap(
            system="config-file",
            reason="toml/ini/properties config file — no v1 expander",
            paths=tuple(config_files[:_GAP_PATHS]),
            count=len(config_files),
        )
    crds = [RepoPath(f.rel) for f in files if f.path.suffix == ".yaml" and "crd" in f.name.lower()]
    if crds:
        yield CoverageGap(
            system="crd",
            reason="CRD-shaped config — effective defaults are operator-applied, not derivable "
            "from the tree",
            paths=tuple(crds[:_GAP_PATHS]),
            count=len(crds),
        )


def config_matrix(root: Path, load: YamlLoader, max_triples: int = MAX_TRIPLES) -> ConfigFact:
    """Every tier's triples, deduplicated on (key, default, source), judged and weak first; past
    `max_triples` the lowest-priority ones drop and the cut is a gap."""
    files = tree_files(root)
    found = [
        *_helm(load, root, files),
        *_kustomize(load, files),
        *_compose(load, files),
        *_k8s(load, files),
        *_env_chain(files),
        *_python_settings(files),
        *_unexpanded(files),
    ]
    gaps = [g for g in found if isinstance(g, CoverageGap)]
    seen: set[tuple[str, str, str, int | None]] = set()
    unique = []
    for t in found:
        if isinstance(t, ConfigTriple):
            sig = (t.key, t.effective_default, t.source.path, t.source.line)
            if sig not in seen:
                seen.add(sig)
                unique.append(t)
    unique.sort(key=lambda t: (not t.judgement_required, not t.weak_default, t.config_class, t.key))
    if (cut := len(unique) - max_triples) > 0:
        gaps.append(
            CoverageGap(
                system="expander",
                reason=f"triple cap {max_triples} reached — {cut} lowest-priority triples dropped "
                "(judged classes kept first)",
                count=cut,
            )
        )
        unique = unique[:max_triples]
    return ConfigFact(triples=tuple(unique), coverage_gaps=tuple(gaps))


class ConfigMatrix:
    kind = CodeFactKind.CONFIG
    name = "config-matrix"

    def __init__(self, clock: Clock, load: YamlLoader) -> None:
        self._clock = clock
        self._load = load

    def check(self) -> Readiness:
        return Readiness(ready=True)

    def enumerate(self, request: ToolRequest) -> Result[list[CodeFactDetail]]:
        fact = config_matrix(request.workspace, self._load)
        return Result([fact], Acquisition(provider=self.name, acquired_at=self._clock.now()))
