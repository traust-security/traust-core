"""The opengrep rule packs and canary repositories `DetectionQualityService` scores against.
Nothing here touches the network: a supplemental pack is read only from the clone an opengrep
scan already made."""

from __future__ import annotations

import re
import shutil
from collections.abc import Callable, Sequence
from pathlib import Path
from typing import Any

from pydantic import ValidationError as InvalidModel

from traust_core.v1.errors import ConfigError, ServiceError, ValidationError
from traust_core.v1.models.detection_quality import (
    CanaryInjection,
    CanaryKind,
    CanaryRepo,
    CanarySource,
    RuleId,
    RulePack,
    RuleRef,
    SeededFinding,
)
from traust_core.v1.providers.base import Readiness, on_path
from traust_core.v1.providers.config_matrix import YamlLoader
from traust_core.v1.providers.process import ProcessRunner
from traust_core.v1.providers.tools.opengrep import (
    SupplementalPack,
    pinned_rules_source,
    rules_cache_dir,
    rules_root,
)

GIT_TIMEOUT = 120.0
TRAUST_PACK = "traust"
_CWE = re.compile(r"CWE-\d+", re.IGNORECASE)
# Never a command the repository's own config names (fsmonitor, hooks).
_HARDENED = ("-c", "core.fsmonitor=false", "-c", "core.hooksPath=/dev/null")


class OpengrepRulePacks:
    """The traust pack and each allowlisted supplement (read on first use), as rule ids with their
    languages and metadata CWEs."""

    name = "opengrep"

    def __init__(
        self,
        pack: Path,
        version: str,
        supplements: Callable[[], Sequence[SupplementalPack]],
        git: ProcessRunner,
        load: YamlLoader,
    ) -> None:
        self._pack = pack
        self._version = version
        self._supplements = supplements
        self._git = git
        self._load = load

    def check(self) -> Readiness:
        if self._pack.is_dir():
            return Readiness(ready=True)
        return Readiness(ready=False, detail=f"rule pack {self._pack} is not a directory")

    def packs(self) -> list[RulePack]:
        own = rule_refs(self._pack, self._load)
        traust = RulePack(name=TRAUST_PACK, version=self._version, rules=tuple(own.values()))
        return [traust, *map(self._supplement, self._supplements())]

    def _supplement(self, supplement: SupplementalPack) -> RulePack:
        try:
            url, ref = pinned_rules_source(supplement.source)
        except ValueError as e:
            raise ConfigError(f"rule pack {supplement.name}: {e}") from e
        dest = rules_cache_dir(url, ref)
        if not dest.is_dir():
            raise ConfigError(
                f"rule pack {supplement.name}: {supplement.source} is not fetched yet "
                f"({dest}); an opengrep scan with the allowlist fetches it"
            )
        self._verify(supplement.name, dest, ref)
        found = rule_refs(rules_root(url, dest), self._load)
        if missing := sorted(set(supplement.rules) - set(found)):
            raise ValidationError(
                f"rule pack {supplement.name}@{ref[:12]}: allowlisted rules not in the pack: "
                + ", ".join(missing)
            )
        return RulePack(
            name=supplement.name,
            version=ref,
            rules=tuple(found[r] for r in dict.fromkeys(supplement.rules)),
        )

    def _verify(self, name: str, dest: Path, ref: str) -> None:
        """A cached pack counts only at its pin with a pristine worktree: a prior scan of a
        hostile repository (or a local edit) must not change the rules under a pinned SHA."""
        try:
            head = self._run_git(dest, "rev-parse", "HEAD").strip()
            dirty = self._run_git(dest, "status", "--porcelain").strip()
        except ServiceError as e:
            raise ConfigError(f"rule pack {name}: cache {dest} unreadable: {e}") from e
        if head != ref or dirty:
            raise ConfigError(
                f"rule pack {name}: cache {dest} fails pin/cleanliness verification "
                f"(HEAD {head[:12]}, {'dirty' if dirty else 'clean'}); refusing unverifiable rules"
            )

    def _run_git(self, repo: Path, *args: str) -> str:
        return self._git.run(["git", "-C", str(repo), *_HARDENED, *args]).stdout.decode()


def rule_refs(root: Path, load: YamlLoader) -> dict[str, RuleRef]:
    """Every rule under `root`, by id; opengrep test targets (`*.test.yaml`, tests/) and hidden
    directories hold no rules, and a YAML file with no `rules:` list is not a rule file."""
    found: dict[str, RuleRef] = {}
    for path in sorted([*root.rglob("*.yaml"), *root.rglob("*.yml")]):
        parts = path.relative_to(root).parts
        if ".test." in path.name or "tests" in parts or any(p.startswith(".") for p in parts):
            continue
        try:
            doc = _one_document(load, path.read_text(encoding="utf-8"))
        except (OSError, UnicodeDecodeError, ValidationError) as e:
            raise ValidationError(f"rule file {path}: unreadable: {e}") from e
        if not (isinstance(doc, dict) and isinstance(doc.get("rules"), list)):
            continue
        for rule in doc["rules"]:
            if not (isinstance(rule, dict) and rule.get("id")):
                raise ValidationError(f"rule file {path}: a rule has no id")
            cwe = (rule.get("metadata") or {}).get("cwe") or ()
            cwes = _CWE.findall(" ".join(map(str, [cwe] if isinstance(cwe, str) else cwe)))
            found[str(rule["id"])] = RuleRef(
                id=RuleId(str(rule["id"])),
                languages=tuple(str(lang) for lang in rule.get("languages") or ()),
                cwes=tuple(dict.fromkeys(c.upper() for c in cwes)),
            )
    return found


# Fixed identity and date, so a canary's HEAD SHA depends only on its tree's content.
_CANARY_GIT_ENV = {
    "GIT_AUTHOR_NAME": "canary-builder",
    "GIT_AUTHOR_EMAIL": "canary@invalid",
    "GIT_COMMITTER_NAME": "canary-builder",
    "GIT_COMMITTER_EMAIL": "canary@invalid",
    "GIT_AUTHOR_DATE": "2026-01-01T00:00:00 +0000",
    "GIT_COMMITTER_DATE": "2026-01-01T00:00:00 +0000",
    # The builder's own git config (autocrlf, signing, templates) must not reach the commit.
    "GIT_CONFIG_GLOBAL": "/dev/null",
    "GIT_CONFIG_NOSYSTEM": "1",
}
# Only committed content: bytecode caches would make the SHA depend on who last ran Python.
_NOT_COMMITTED = shutil.ignore_patterns("__pycache__", "*.pyc")


class GitCanaryMaterializer:
    """Canary and seeded-fixture sources (`<name>/{canary,seed}.yaml + tree/`), each committed
    into a fresh local repository; the answer key never enters it."""

    name = "canary-git"

    def __init__(
        self, sources_dir: Path, repos_dir: Path, git: ProcessRunner, load: YamlLoader
    ) -> None:
        self._sources = sources_dir
        self._repos = repos_dir
        self._git = git
        self._load = load

    def check(self) -> Readiness:
        if not self._sources.is_dir():
            return Readiness(ready=False, detail=f"no canary sources at {self._sources}")
        return on_path("git")

    def sources(self) -> list[CanarySource]:
        if not self._sources.is_dir():
            raise ConfigError(f"no canary sources at {self._sources}")
        return [
            canary_source(d, self._sources.name, self._load)
            for d in sorted(self._sources.iterdir())
            if any((d / k.answer_key).is_file() for k in CanaryKind)
        ]

    def materialize(self, source: CanarySource) -> CanaryRepo:
        tree = self._sources / source.name / "tree"
        if not tree.is_dir():
            raise ValidationError(f"canary {source.name}: no tree/ at {tree}")
        dest = (self._repos / source.name).resolve()
        if dest.exists():
            shutil.rmtree(dest)
        self._repos.mkdir(parents=True, exist_ok=True)
        # Links stay links: following one would commit a file from outside the source tree.
        shutil.copytree(tree, dest, symlinks=True, ignore=_NOT_COMMITTED)
        for args in (
            ("init", "-q", "-b", "main"),
            ("add", "-A"),
            # Never signed: a signature carries its own timestamp, so the SHA would differ per run.
            ("-c", "commit.gpgsign=false", "commit", "-q", "-m", f"import {source.name}"),
        ):
            self._run_git(dest, *args)
        sha = self._run_git(dest, "rev-parse", "HEAD").strip()
        return CanaryRepo(repo_url=f"file://{dest}", sha=sha)

    def _run_git(self, repo: Path, *args: str) -> str:
        argv = ["git", "-C", str(repo), *_HARDENED, *args]
        return self._git.run(argv, env=_CANARY_GIT_ENV).stdout.decode()


def canary_source(directory: Path, sources_name: str, load: YamlLoader) -> CanarySource:
    """One `<name>/` source directory: its answer key, and the files of tree/ that get committed."""
    keys = [k for k in CanaryKind if (directory / k.answer_key).is_file()]
    if len(keys) != 1:
        raise ValidationError(f"canary {directory.name}: both canary.yaml and seed.yaml — use one")
    kind = keys[0]
    try:
        meta: Any = _one_document(load, (directory / kind.answer_key).read_text(encoding="utf-8"))
    except (OSError, ValidationError) as e:
        raise ValidationError(f"canary {directory.name}: unreadable {kind.answer_key}: {e}") from e
    try:
        if meta["name"] != directory.name:
            raise ValidationError(
                f"canary {directory.name}: {kind.answer_key} names {meta['name']!r}, "
                "not its directory"
            )
        expected = meta["expected"] if isinstance(meta["expected"], list) else [meta["expected"]]
        injection = meta.get("injection")
        tree = directory / "tree"
        if not tree.is_dir():
            raise ValidationError(f"canary {directory.name}: no tree/ beside its answer key")
        if any(".git" in p.relative_to(tree).parts for p in tree.rglob(".git")):
            raise ValidationError(
                f"canary {directory.name}: a .git entry inside tree/ would configure the git "
                "that commits it"
            )
        return CanarySource(
            name=directory.name,
            kind=kind,
            recipe=f"{sources_name}/{directory.name}",
            expected=tuple(
                SeededFinding(
                    cwes=tuple(str(c) for c in e["cwes"]),
                    paths=tuple(e["paths"]),
                    severity=e["severity"],
                    title=e.get("title", ""),
                )
                for e in expected
            ),
            tree=tuple(
                sorted(
                    p.relative_to(tree).as_posix()
                    for p in tree.rglob("*")
                    if (p.is_file() or p.is_symlink())
                    and "__pycache__" not in p.relative_to(tree).parts
                    and p.suffix != ".pyc"
                )
            ),
            language=meta.get("language"),
            injection=CanaryInjection(
                injection_class=injection["class"], tokens=tuple(injection["tokens"])
            )
            if injection
            else None,
        )
    except (OSError, KeyError, TypeError, InvalidModel) as e:
        raise ValidationError(f"canary {directory.name}: unreadable {kind.answer_key}: {e}") from e


def _one_document(load: YamlLoader, text: str) -> object:
    """`yaml.safe_load`: None for no document, and more than one is unreadable."""
    documents = load(text)
    if len(documents) > 1:
        raise ValidationError("expected a single document, found more than one")
    return documents[0] if documents else None
