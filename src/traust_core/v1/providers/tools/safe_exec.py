"""Target-derived commands vetted against a named profile (`safe-exec-profiles.yaml`, policy as
data) and run without a shell: a single argv or an allowlisted pipeline, in a scrubbed env."""

from __future__ import annotations

import re
import shlex
from collections.abc import Mapping, Sequence
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from traust_core.v1.errors import ConfigError, ServiceError, ValidationError
from traust_core.v1.providers.process import ProcessRunner, ProcessTimeout

RECURSION_ENV = "SAFE_EXEC_DEPTH"
MAX_RECURSION = 3

HARD_DENY_BINARIES = frozenset(
    {
        # privilege / system mutation
        "sudo",
        "su",
        "doas",
        "chown",
        "chgrp",
        "dd",
        "mkfs",
        "mount",
        "umount",
        "systemctl",
        "service",
        "crontab",
        "launchctl",
        "reboot",
        "shutdown",
        "insmod",
        "rmmod",
        "sysctl",
        # process/host tampering
        "kill",
        "pkill",
        "killall",
        "renice",
        "nohup",
        # raw network tools (profiles needing egress use scoped tools, not these)
        "nc",
        "ncat",
        "netcat",
        "socat",
        "telnet",
        "ssh",
        "scp",
        "sftp",
        "rsync",
        "ftp",
        "wget",
        # package managers (runtime installs are S7 territory, never build steps)
        "pip",
        "pip3",
        "dnf",
        "yum",
        "apt",
        "apt-get",
        "brew",
        "gem",
        "cargo-install",
    }
)

SHELLS = frozenset({"sh", "bash", "zsh", "ksh", "dash", "fish", "csh", "tcsh"})

# Deny-by-default but profile-grantable (python-test runs python3/pytest); shells are not.
INTERPRETERS = frozenset(
    {
        "python",
        "python2",
        "python3",
        "perl",
        "ruby",
        "node",
        "deno",
        "lua",
        "php",
        "awk",
        "gawk",
        "mawk",
        "xargs",
        "env",
        "eval",
        "exec",
        "command",
        "time",
        "timeout",
        "nice",
        "setsid",
        "script",
    }
)

GIT_NETWORK_SUBCOMMANDS = frozenset(
    {"push", "pull", "fetch", "clone", "remote", "submodule", "ls-remote"}
)

# `git -c key=value` / `--config-env` keys that are code-exec or credential-theft primitives,
# matched case-insensitively; an entry ending in "." is a prefix.
GIT_DANGEROUS_C_KEYS = (
    "core.pager",
    "core.editor",
    "core.sshcommand",
    "core.hookspath",
    "core.fsmonitor",
    "core.askpass",
    "core.alternateobjectdirectories",
    "credential.",
    "filter.",
    "diff.external",
    "difftool.",
    "mergetool.",
    "merge.",
    "remote.",
    "http.proxy",
    "http.sslcainfo",
    "http.sslcert",
    "http.sslkey",
    "protocol.",
    "sendemail.",
    "alias.",
    "gpg.program",
    "ssh.variant",
    "uploadpack.",
    "sshcommand",
)

PROTECTED_ENV_VARS = frozenset(
    {
        "PATH",
        "LD_PRELOAD",
        "LD_LIBRARY_PATH",
        "LD_AUDIT",
        "DYLD_INSERT_LIBRARIES",
        "DYLD_LIBRARY_PATH",
        "PYTHONPATH",
        "PYTHONSTARTUP",
        "PERL5LIB",
        "NODE_OPTIONS",
        "RUBYOPT",
        "BASH_ENV",
        "ENV",
        "IFS",
        "SHELL",
        "GIT_SSH",
        "GIT_SSH_COMMAND",
        "GIT_PROXY_COMMAND",
        "GIT_EXTERNAL_DIFF",
        "GIT_PAGER",
        "GIT_ASKPASS",
        "GIT_CONFIG_GLOBAL",
        "GIT_CONFIG_SYSTEM",
        "GIT_INDEX_FILE",
        "GIT_OBJECT_DIRECTORY",
        "JAVA_TOOL_OPTIONS",
        "MAVEN_OPTS",
        "GRADLE_OPTS",
        "_JAVA_OPTIONS",
        "SAFE_EXEC_MODE",
        "SAFE_EXEC_DISABLED",
        RECURSION_ENV,
    }
)

# Applied to the string form before tokenizing. No newline deny: nothing here reaches a shell, so
# a quoted newline is data and an unquoted one whitespace, and every token is still vetted.
RAW_DENY_PATTERNS = (
    (re.compile(r"`"), "backtick command substitution"),
    (re.compile(r"\$\("), "command substitution $( )"),
    (re.compile(r"\$\{"), "parameter expansion ${ }"),
    (re.compile(r"[<>]\("), "process substitution"),
    (re.compile(r"\$'"), "ANSI-C quoting"),
    (re.compile(r"/dev/(tcp|udp)/"), "raw socket via /dev/tcp|udp"),
)

# The env a run keeps, plus its profile's keep_env.
BASE_KEEP_ENV = (
    "PATH",
    "HOME",
    "LANG",
    "LC_ALL",
    "TMPDIR",
    "TERM",
    "http_proxy",
    "https_proxy",
    "no_proxy",
    "HTTP_PROXY",
    "HTTPS_PROXY",
    "NO_PROXY",
)

# Upload, file-read and config forms turn a lab probe into local-file exfiltration
# (assessment 2026-07-31 live-F5); a probe never needs them.
CURL_DENY_FLAGS = frozenset(
    {
        "-F",
        "--form",
        "--form-string",
        "-T",
        "--upload-file",
        "--config",
        "-K",
        "--netrc",
        "-n",
        "--netrc-file",
        "--output-dir",
        "--create-dirs",
    }
)

# Cluster and credential overrides never belong in target-derived commands: the adapter supplies
# the context (assessment 2026-07-31 live-F1/F2; the execute layer is the other fence).
KUBE_DENY_FLAGS = frozenset(
    {
        "--kubeconfig",
        "--context",
        "--cluster",
        "--user",
        "--server",
        "-s",
        "--token",
        "--as",
        "--as-group",
        "--as-uid",
        "--insecure-skip-tls-verify",
        "--tls-server-name",
        "--certificate-authority",
        "--client-certificate",
        "--client-key",
        "--username",
        "--password",
    }
)

_ENV_PREFIX_RX = re.compile(r"^([A-Za-z_][A-Za-z0-9_]*)=(.*)$", re.S)

Segments = tuple[tuple[str, ...], ...]
Outcome = tuple[int, str, str]


@dataclass(frozen=True, slots=True)
class Profile:
    name: str
    description: str
    allow: frozenset[str]
    allowed_path_heads: frozenset[str]
    allow_pipelines: bool
    keep_env: tuple[str, ...]

    def permits(self, head: str) -> bool:
        if "/" in head:
            return head in self.allowed_path_heads
        return head in self.allow


@dataclass(frozen=True, slots=True)
class Verdict:
    ok: bool
    reason: str = ""
    segments: Segments = ()  # the tokenized pipeline, for the string form


def profiles_of(document: Mapping[str, Any]) -> dict[str, Profile]:
    """The profiles of a schema-checked `safe-exec-profiles.yaml`; ConfigError for a profile that
    grants a hard-denied binary or a shell."""
    out = {}
    for name, spec in (document.get("profiles") or {}).items():
        allow = frozenset(spec.get("allow") or [])
        if bad := sorted(allow & (HARD_DENY_BINARIES | SHELLS)):
            raise ConfigError(
                f"profile {name!r} grants hard-denied binaries {bad} — "
                "hard denies are never grantable; fix safe-exec-profiles.yaml"
            )
        out[name] = Profile(
            name=name,
            description=str(spec.get("description", "")),
            allow=allow,
            allowed_path_heads=frozenset(spec.get("allowed_path_heads") or []),
            allow_pipelines=bool(spec.get("allow_pipelines", False)),
            keep_env=tuple(spec.get("keep_env") or ()),
        )
    return out


class SafeExec:
    """The deployment's safe-exec profiles; `depth` is how many safe-exec runs we are inside."""

    def __init__(self, profiles: Mapping[str, Profile], *, depth: int) -> None:
        self.profiles = dict(profiles)
        self._depth = depth

    def profile(self, name: str) -> Profile:
        try:
            return self.profiles[name]
        except KeyError:
            raise ConfigError(
                f"unknown safe_exec profile {name!r}; known: {sorted(self.profiles)} "
                "(see the safe-exec-profiles.yaml traust-core ships)"
            ) from None

    def validate_argv(self, argv: Sequence[str], profile: Profile) -> Verdict:
        """One command (no pipeline) as an argv list."""
        if not argv:
            return Verdict(False, "empty command")
        if self._depth >= MAX_RECURSION:
            return Verdict(False, f"safe_exec recursion depth cap ({MAX_RECURSION}) reached")
        head = None
        for tok in argv:
            if (m := _ENV_PREFIX_RX.match(tok)) and head is None:
                var = m.group(1)
                if var.upper() in PROTECTED_ENV_VARS or var.upper().startswith("GIT_"):
                    return Verdict(False, f"assignment to protected env var {var!r}")
                continue
            head = tok
            break
        if head is None:
            return Verdict(False, "command has no executable head")
        name = Path(head).name
        if name in HARD_DENY_BINARIES:
            return Verdict(False, f"{name!r} is hard-denied (never grantable)")
        if name in SHELLS:
            return Verdict(
                False, f"shell {name!r} is never grantable — pipelines run natively under safe_exec"
            )
        if name in ("safe_exec", "safe_exec.py"):
            return Verdict(False, "safe_exec may not re-invoke itself")
        if not profile.permits(head if "/" in head else name):
            if name in INTERPRETERS:
                return Verdict(
                    False, f"interpreter {name!r} not granted by profile {profile.name!r}"
                )
            allowlist = sorted(profile.allow)
            return Verdict(
                False, f"binary {head!r} not in profile {profile.name!r} allowlist {allowlist}"
            )
        rest = list(argv[list(argv).index(head) :])
        if reason := _HARDENING.get(name, _no_reason)(rest):
            return Verdict(False, reason)
        return Verdict(True)

    def vet_command_string(self, cmd: str, profile: Profile) -> Verdict:
        """A PoC-derived command string; on success `segments` holds its pipeline."""
        for rx, why in RAW_DENY_PATTERNS:
            if rx.search(cmd or ""):
                return Verdict(False, f"{why} not allowed in step text")
        lex = shlex.shlex(cmd, posix=True, punctuation_chars=True)
        lex.whitespace_split = True
        try:
            tokens = list(lex)
        except ValueError as e:
            return Verdict(False, f"unparseable step command: {e}")
        if not tokens:
            return Verdict(False, "empty step command")
        for t in tokens:
            if t and all(c in ";&<>|()" for c in t) and t != "|":
                return Verdict(False, f"shell operator {t!r} not allowed in step text")
        segments: list[list[str]] = [[]]
        for t in tokens:
            if t == "|":
                segments.append([])
            else:
                segments[-1].append(t)
        if len(segments) > 1 and not profile.allow_pipelines:
            return Verdict(False, f"profile {profile.name!r} does not allow pipelines")
        for seg in segments:
            if not (v := self.validate_argv(seg, profile)).ok:
                return v
        return Verdict(True, segments=tuple(tuple(s) for s in segments))

    def run(
        self,
        cmd: str | Sequence[str],
        profile_name: str,
        *,
        timeout: int = 120,
        cwd: Path | None = None,
        input_: str | None = None,
        extra_env: Mapping[str, str] | None = None,
    ) -> Outcome:
        """Vet then run an argv or a command string: (exit code, stdout, stderr); 126 when vetting
        refuses it."""
        profile = self.profile(profile_name)
        if isinstance(cmd, str):
            verdict = self.vet_command_string(cmd, profile)
            segments = verdict.segments
        else:
            verdict = self.validate_argv(list(cmd), profile)
            segments = (tuple(cmd),)
        if not verdict.ok:
            return 126, "", f"[safe_exec blocked: {verdict.reason}]"
        return self.run_segments(
            segments, profile, timeout=timeout, cwd=cwd, input_=input_, extra_env=extra_env
        )

    def run_segments(
        self,
        segments: Sequence[Sequence[str]],
        profile: Profile,
        *,
        timeout: int = 120,
        cwd: Path | None = None,
        input_: str | None = None,
        extra_env: Mapping[str, str] | None = None,
    ) -> Outcome:
        """Run already-vetted segments in the profile's env: (exit code, stdout, stderr). The exit
        code and stderr are the last segment's, with a note for each upstream one that failed;
        124 on timeout, 127 when a segment can't start."""
        env = {RECURSION_ENV: str(self._depth + 1)}
        for k, v in (extra_env or {}).items():
            if k.upper() in PROTECTED_ENV_VARS:
                raise ValidationError(f"extra_env may not set protected {k!r}")
            env[k] = v
        # Vetted already (or run anyway, the caller's choice): the runner adds env and no-shell.
        runner = ProcessRunner(
            {Path(seg[0]).name for seg in segments if seg},
            keep_env=(*BASE_KEEP_ENV, *profile.keep_env),
            timeout_seconds=timeout,
        )
        stdin = input_.encode() if input_ is not None else None
        try:
            if len(segments) == 1:
                done = runner.run(segments[0], cwd=cwd, env=env, stdin=stdin, check=False)
                return done.returncode, _text(done.stdout), _text(done.stderr)
            *upstream, last = runner.pipeline(segments, cwd=cwd, env=env, stdin=stdin)
        except ProcessTimeout as e:
            if len(segments) == 1:
                return 124, _text(e.stdout), _text(e.stderr) + f"\n[timeout after {timeout}s]"
            return 124, "", f"[pipeline timeout after {timeout}s]"
        except ServiceError as e:
            return 127, "", f"[exec failed: {e.__cause__ or e}]"
        except ValidationError as e:
            return 126, "", f"[safe_exec blocked: {e}]"
        notes = "".join(
            f"\n[pipeline segment {i} exited {r.returncode}]"
            for i, r in enumerate(upstream)
            if r.returncode != 0
        )
        return last.returncode, _text(last.stdout), _text(last.stderr) + notes


def _text(data: bytes) -> str:
    return data.decode(errors="replace")


def _no_reason(_: list[str]) -> str:
    return ""


def _check_git_argv(argv: list[str]) -> str:
    i = 1
    subcommand = None
    while i < len(argv):
        tok = argv[i]
        if tok in ("-c", "--config-env"):
            if i + 1 < len(argv):
                key = argv[i + 1].split("=", 1)[0].strip().lower()
                for danger in GIT_DANGEROUS_C_KEYS:
                    if key == danger or (danger.endswith(".") and key.startswith(danger)):
                        return f"git config key {key!r} is a code-exec/credential primitive"
                i += 2
                continue
            return "dangling git -c"
        if tok == "-C":
            i += 2
            continue
        if tok.startswith("-"):
            i += 1
            continue
        subcommand = tok
        break
    if subcommand in GIT_NETWORK_SUBCOMMANDS:
        return (
            f"git network subcommand {subcommand!r} is denied under "
            "safe_exec (clones/fetches belong to S3-gated skill "
            "steps, not target-derived commands)"
        )
    return ""


def _check_curl_argv(argv: list[str]) -> str:
    for tok in argv[1:]:
        flag = tok.split("=", 1)[0]
        if flag in CURL_DENY_FLAGS:
            return (
                f"curl flag {flag!r} is denied under safe_exec "
                "(local-file read/upload/config — exfiltration "
                "primitives; assessment 2026-07-31 F5)"
            )
        if tok.startswith(("-d@", "--data@")):
            return "curl -d@<file> is denied under safe_exec"
        if flag in ("-d", "--data", "--data-binary", "--data-raw", "--data-urlencode"):
            idx = argv.index(tok)
            if "=" in tok:
                val = tok.split("=", 1)[1]
            else:
                val = argv[idx + 1] if idx + 1 < len(argv) else ""
            if val.startswith("@"):
                return "curl --data @<file> is denied under safe_exec"
        if tok.startswith("file://"):
            return "curl file:// scheme is denied under safe_exec"
    return ""


def _check_kube_argv(argv: list[str]) -> str:
    for tok in argv[1:]:
        flag = tok.split("=", 1)[0]
        if flag in KUBE_DENY_FLAGS:
            return (
                f"kubectl/oc flag {flag!r} is denied under safe_exec "
                "— target-derived commands run only against the "
                "engagement-pinned context (assessment 2026-07-31 F2)"
            )
    return ""


_HARDENING = {
    "git": _check_git_argv,
    "curl": _check_curl_argv,
    "kubectl": _check_kube_argv,
    "oc": _check_kube_argv,
}
