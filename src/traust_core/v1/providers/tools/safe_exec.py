"""Target-derived commands vetted against a named profile (`safe-exec-profiles.yaml`, policy as
data) and run without a shell: a single argv or an allowlisted pipeline, in a scrubbed env."""

from __future__ import annotations

import contextlib
import ipaddress
import os
import re
import shlex
import socket
from collections.abc import Iterable, Mapping, Sequence
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Literal
from urllib.parse import urlsplit

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

Posture = Literal["restricted", "baseline", "privileged"]
POSTURE_ALIASES: dict[str, Posture] = {
    "restricted": "restricted",
    "high": "restricted",
    "baseline": "baseline",
    "medium": "baseline",
    "privileged": "privileged",
    "low": "privileged",
}
_ROUTING_ENV = frozenset(
    {
        "HTTP_PROXY",
        "HTTPS_PROXY",
        "ALL_PROXY",
        "NO_PROXY",
        "FTP_PROXY",
        "CURL_PROXY",
        "CURL_CA_BUNDLE",
        "SSL_CERT_FILE",
        "SSL_CERT_DIR",
        "RES_OPTIONS",
        "LOCALDOMAIN",
        "HOSTALIASES",
        "XDG_CONFIG_HOME",
        "SSLKEYLOGFILE",
    }
)
_TARGET_PROTECTED_ENV = frozenset({"HOME", "KUBECONFIG", "CURL_HOME", "XDG_CONFIG_HOME"})

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
    keep_env_heads: tuple[str, ...] = ()
    curl_allowed_hosts: tuple[str, ...] = ()
    posture: Posture = "privileged"

    def permits(self, head: str) -> bool:
        if "/" in head:
            return head in self.allowed_path_heads
        return head in self.allow


@dataclass(frozen=True, slots=True)
class Verdict:
    ok: bool
    reason: str = ""
    segments: Segments = ()  # the tokenized pipeline, for the string form


_BASELINE_DENIED_SUFFIXES = (
    ".local",
    ".internal",
    ".lan",
    ".home.arpa",
    ".cluster.local",
    ".localhost",
    ".svc",
)
_BASELINE_DENIED_NAMES = frozenset({"localhost", "instance-data", "metadata"})


def _parse_ip(literal: str) -> ipaddress.IPv4Address | ipaddress.IPv6Address | None:
    """Parse standard or libc-compatible IPv4/IPv6 address literals."""
    with contextlib.suppress(ValueError):
        return ipaddress.ip_address(literal)
    with contextlib.suppress(OSError, ValueError):
        return ipaddress.ip_address(socket.inet_ntoa(socket.inet_aton(literal)))
    return None


def _is_baseline_denied_host(host: str) -> str | None:
    """Check whether a normalized hostname/IP is denied under the 'baseline' posture."""
    lowered = host.lower().rstrip(".")
    literal = lowered.removeprefix("[").removesuffix("]")
    if (ip := _parse_ip(literal)) and not ip.is_global:
        return (
            f"curl host {host!r} is a non-global IP address ({ip}) — "
            "denied under posture 'baseline' (allowlist it explicitly in "
            "curl_allowed_hosts or call-site allowed_hosts)"
        )
    if ip:
        return None
    if lowered in _BASELINE_DENIED_NAMES:
        return (
            f"curl host {host!r} is a local/internal name — denied under posture "
            "'baseline' (allowlist it explicitly in curl_allowed_hosts or call-site allowed_hosts)"
        )
    if lowered.endswith(_BASELINE_DENIED_SUFFIXES):
        return (
            f"curl host {host!r} is in an internal domain — "
            "denied under posture 'baseline' (allowlist it explicitly in "
            "curl_allowed_hosts or call-site allowed_hosts)"
        )
    if "." not in lowered:
        return (
            f"curl host {host!r} is a single-label host (intranet/cluster service) — "
            "denied under posture 'baseline' (allowlist it explicitly in "
            "curl_allowed_hosts or call-site allowed_hosts)"
        )
    return None


def _norm_host(entry: object) -> str:
    if not isinstance(entry, str) or not entry or entry != entry.strip():
        return ""
    if any(c in entry for c in "*?{}\\ \t\r\n%"):
        return ""
    raw = entry
    if "://" in raw:
        scheme, raw = raw.split("://", 1)
        if scheme.lower() not in ("http", "https"):
            return ""
    if raw.count(":") > 1 and "[" not in raw and "/" not in raw:
        raw = f"[{raw}]"
    try:
        parts = urlsplit(f"//{raw}")
        host = parts.hostname
        if parts.username is not None or (parts.port is not None and parts.port > 65535):
            return ""
        if not host or any(c in host for c in "[]@%"):
            return ""
        return host.lower().rstrip(".")
    except ValueError:
        return ""


def _hosts(entries: Iterable[str]) -> tuple[str, ...]:
    normalized = []
    for entry in entries:
        host = _norm_host(entry)
        if not host:
            raise ValueError("invalid curl allowed host")
        normalized.append(host)
    return tuple(sorted(set(normalized)))


def _posture(value: object, context: str) -> Posture:
    if not isinstance(value, str) or value not in POSTURE_ALIASES:
        raise ConfigError(f"{context} has invalid safe-exec posture {value!r}")
    return POSTURE_ALIASES[value]


def _protected_assignment(name: str) -> bool:
    upper = name.upper()
    return (
        upper in PROTECTED_ENV_VARS
        or upper in _ROUTING_ENV
        or upper in _TARGET_PROTECTED_ENV
        or upper.startswith("GIT_")
    )


def _routing_env(name: str) -> bool:
    upper = name.upper()
    return upper in _ROUTING_ENV or upper.endswith("_PROXY") or upper.startswith("CURL_")


def profiles_of(document: Mapping[str, Any]) -> dict[str, Profile]:
    """The profiles of a schema-checked `safe-exec-profiles.yaml`; ConfigError for a profile that
    grants a hard-denied binary or a shell."""
    out = {}
    default_posture = _posture(
        (document.get("defaults") or {}).get("posture", "privileged"), "defaults"
    )
    for name, spec in (document.get("profiles") or {}).items():
        allow = frozenset(spec.get("allow") or [])
        if bad := sorted(allow & (HARD_DENY_BINARIES | SHELLS)):
            raise ConfigError(
                f"profile {name!r} grants hard-denied binaries {bad} — "
                "hard denies are never grantable; fix safe-exec-profiles.yaml"
            )
        posture = _posture(spec.get("posture", default_posture), f"profile {name!r}")
        keep_env_heads = tuple(spec.get("keep_env_heads") or ())
        if posture == "restricted" and spec.get("allow_pipelines", False) and not keep_env_heads:
            raise ConfigError(f"profile {name!r}: restricted pipelines require keep_env_heads")
        try:
            hosts = _hosts(spec.get("curl_allowed_hosts") or ())
        except ValueError as e:
            raise ConfigError(f"profile {name!r}: {e}") from e
        out[name] = Profile(
            name=name,
            description=str(spec.get("description", "")),
            allow=allow,
            allowed_path_heads=frozenset(spec.get("allowed_path_heads") or []),
            allow_pipelines=bool(spec.get("allow_pipelines", False)),
            keep_env=tuple(spec.get("keep_env") or ()),
            keep_env_heads=keep_env_heads,
            curl_allowed_hosts=hosts,
            posture=posture,
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

    def validate_argv(
        self, argv: Sequence[str], profile: Profile, *, allowed_hosts: Iterable[str] = ()
    ) -> Verdict:
        """One command (no pipeline) as an argv list."""
        if not argv:
            return Verdict(False, "empty command")
        if self._depth >= MAX_RECURSION:
            return Verdict(False, f"safe_exec recursion depth cap ({MAX_RECURSION}) reached")
        head = None
        for tok in argv:
            if (m := _ENV_PREFIX_RX.match(tok)) and head is None:
                var = m.group(1)
                if _protected_assignment(var) or _routing_env(var):
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
        if name == "curl":
            try:
                hosts = _hosts((*profile.curl_allowed_hosts, *allowed_hosts))
            except ValueError as e:
                return Verdict(False, str(e))
            curl_argv = argv[list(argv).index(head) :]
            if reason := _CurlVetter(hosts, profile.posture).check_argv(curl_argv):
                return Verdict(False, reason)
        rest = list(argv[list(argv).index(head) :])
        if reason := _HARDENING.get(name, _no_reason)(rest):
            return Verdict(False, reason)
        return Verdict(True)

    def vet_command_string(
        self, cmd: str, profile: Profile, *, allowed_hosts: Iterable[str] = ()
    ) -> Verdict:
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
        allowed_hosts = tuple(allowed_hosts)
        for seg in segments:
            if not (v := self.validate_argv(seg, profile, allowed_hosts=allowed_hosts)).ok:
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
        allowed_hosts: Iterable[str] = (),
    ) -> Outcome:
        """Vet then run an argv or a command string: (exit code, stdout, stderr); 126 when vetting
        refuses it."""
        profile = self.profile(profile_name)
        allowed_hosts = tuple(allowed_hosts)
        if isinstance(cmd, str):
            verdict = self.vet_command_string(cmd, profile, allowed_hosts=allowed_hosts)
            segments = verdict.segments
        else:
            verdict = self.validate_argv(list(cmd), profile, allowed_hosts=allowed_hosts)
            segments = (tuple(cmd),)
        if not verdict.ok:
            return 126, "", f"[safe_exec blocked: {verdict.reason}]"
        return self.run_segments(
            segments,
            profile,
            timeout=timeout,
            cwd=cwd,
            input_=input_,
            extra_env=extra_env,
            allowed_hosts=allowed_hosts,
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
        allowed_hosts: Iterable[str] = (),
        curl_connect_to: tuple[str, int, int] | None = None,
        curl_stdin_headers: Sequence[str] = (),
        curl_ca_bundle: str | None = None,
        curl_insecure_tls: bool = False,
        curl_insecure_lab: bool = False,
    ) -> Outcome:
        """Execute trusted, already-vetted segments; callers own any explicit bypass."""
        allowed_hosts = tuple(allowed_hosts)
        if not segments:
            return 126, "", "[safe_exec blocked: empty pipeline]"
        for seg in segments:
            if not seg or not all(isinstance(tok, str) for tok in seg):
                return 126, "", "[safe_exec blocked: invalid segment]"
            for tok in seg:
                if not (assignment := _ENV_PREFIX_RX.match(tok)):
                    break
                if _protected_assignment(assignment.group(1)) or _routing_env(assignment.group(1)):
                    return 126, "", "[safe_exec blocked: protected environment assignment]"
            if not _prepare_segment(seg):
                return 126, "", "[safe_exec blocked: command has no executable head]"
        for k in extra_env or {}:
            if k.upper() in PROTECTED_ENV_VARS or _routing_env(k):
                raise ValidationError(f"extra_env may not set protected {k!r}")
        prepared = [_prepare_segment(seg) for seg in segments]
        if not isinstance(curl_insecure_tls, bool) or not isinstance(curl_insecure_lab, bool):
            raise ValidationError("invalid trusted TLS policy")
        if (
            curl_connect_to is not None
            or curl_stdin_headers
            or curl_ca_bundle is not None
            or curl_insecure_tls
        ):
            if len(prepared) != 1 or Path(prepared[0][0]).name != "curl":
                raise ValidationError("trusted curl bindings require one curl segment")
            try:
                hosts = _hosts((*profile.curl_allowed_hosts, *allowed_hosts))
            except ValueError as e:
                raise ValidationError("invalid trusted curl host grant") from e
            urls: list[str] = []
            if (
                _CurlVetter(hosts, profile.posture).check_argv(
                    prepared[0], bound_urls=urls, private_headers=bool(curl_stdin_headers)
                )
                or len(urls) != 1
            ):
                raise ValidationError("invalid trusted curl request")
            parts = urlsplit(urls[0])
            if parts.scheme not in ("http", "https") or not parts.hostname:
                raise ValidationError("trusted curl request needs an absolute HTTP URL")
            if curl_insecure_tls and not curl_insecure_lab:
                raise ValidationError("insecure TLS requires explicit lab authorization")
            if curl_ca_bundle is not None:
                if (
                    not isinstance(curl_ca_bundle, str)
                    or not Path(curl_ca_bundle).is_absolute()
                    or any(c in curl_ca_bundle for c in "\x00\r\n")
                ):
                    raise ValidationError("invalid trusted CA bundle path")
                prepared[0][2:2] = ["--cacert", curl_ca_bundle]
            if curl_insecure_tls:
                prepared[0].insert(2, "--insecure")
            if curl_connect_to is not None:
                host, origin_port, local_port = curl_connect_to
                if (
                    not isinstance(host, str)
                    or not _norm_host(host)
                    or _norm_host(host) not in hosts
                    or _norm_host(host) != parts.hostname.rstrip(".")
                    or any(
                        not isinstance(p, int) or isinstance(p, bool) or not 1 <= p <= 65535
                        for p in (origin_port, local_port)
                    )
                    or origin_port != (parts.port or (443 if parts.scheme == "https" else 80))
                ):
                    raise ValidationError("invalid trusted curl connection binding")
                source = f"[{parts.hostname}]" if ":" in parts.hostname else parts.hostname
                prepared[0][2:2] = [
                    "--connect-to",
                    f"{source}:{origin_port}:127.0.0.1:{local_port}",
                ]
            if curl_stdin_headers:
                if input_ is not None or any(
                    not isinstance(h, str)
                    or not re.fullmatch(r"[!#$%&'*+.^_`|~0-9A-Za-z-]+: [^\x00-\x1f\x7f]*", h)
                    or _authority_header(h)
                    for h in curl_stdin_headers
                ):
                    raise ValidationError("invalid trusted curl headers or conflicting stdin")
                prepared[0][2:2] = ["-H", "@-"]
                input_ = "\n".join(curl_stdin_headers) + "\n"
        envs = [_segment_env(seg, profile, self._depth, extra_env) for seg in segments]
        runner = ProcessRunner(
            {Path(seg[0]).name for seg in prepared}, keep_env=(), timeout_seconds=timeout
        )
        stdin = input_.encode() if input_ is not None else None
        try:
            if len(prepared) == 1:
                done = runner.run(prepared[0], cwd=cwd, env=envs[0], stdin=stdin, check=False)
                return done.returncode, _text(done.stdout), _text(done.stderr)
            *upstream, last = runner.pipeline(prepared, cwd=cwd, segment_envs=envs, stdin=stdin)
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


def _prepare_segment(seg: Sequence[str]) -> list[str]:
    start = 0
    while start < len(seg) and _ENV_PREFIX_RX.match(seg[start]):
        start += 1
    argv = list(seg[start:])
    if argv and Path(argv[0]).name == "curl":
        argv.insert(1, "-q")
    return argv


def _segment_env(
    seg: Sequence[str], profile: Profile, depth: int, extra_env: Mapping[str, str] | None
) -> dict[str, str]:
    argv = _prepare_segment(seg)
    head = Path(argv[0]).name
    with_keep = not profile.keep_env_heads or head in profile.keep_env_heads
    names = (*BASE_KEEP_ENV, *(profile.keep_env if with_keep else ()))
    env = {
        k: os.environ[k]
        for k in names
        if k in os.environ and (not _routing_env(k) or (head != "curl" and with_keep))
    }
    env[RECURSION_ENV] = str(depth + 1)
    if with_keep:
        env.update(extra_env or {})
    for tok in seg:
        if not (m := _ENV_PREFIX_RX.match(tok)):
            break
        env[m.group(1)] = m.group(2)
    return env


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
        if tok in ("--git-dir", "--work-tree", "--namespace", "--attr-source", "--shallow-file"):
            # these globals always take the next token as their value — skipping
            # only the flag (the generic dash-skip below) would make the value the
            # "subcommand" and hide the real one from the network check
            if i + 1 < len(argv):
                i += 2
                continue
            return f"dangling git {tok}"
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


_CURL_SHORT_BOOL = frozenset("sSviILfgGlMNRqVhjZa#046")

_CurlValueKind = Literal["data", "urlencode", "header", "cookie", "writeout", "sink", "url"]

_CURL_VALUE_KIND: dict[str, _CurlValueKind | None] = {
    "-A": None,
    "--user-agent": None,
    "-e": None,
    "--referer": None,
    "-m": None,
    "--max-time": None,
    "-r": None,
    "--range": None,
    "-u": None,
    "--user": None,
    "-X": None,
    "--request": None,
    "-C": None,
    "--continue-at": None,
    "-Y": None,
    "--speed-limit": None,
    "-y": None,
    "--speed-time": None,
    "--connect-timeout": None,
    "--keepalive-time": None,
    "--retry": None,
    "--retry-delay": None,
    "--retry-max-time": None,
    "--max-redirs": None,
    "--max-filesize": None,
    "--limit-rate": None,
    "--oauth2-bearer": None,
    "--request-target": None,
    "--noproxy": None,
    "--aws-sigv4": None,
    # request bodies: the @file/@- upload leg is the exfil primitive;
    # inline bodies stay allowed (probes legitimately POST JSON)
    "-d": "data",
    "--data": "data",
    "--data-ascii": "data",
    "--data-binary": "data",
    "--data-raw": "data",
    "--json": "data",
    "--data-urlencode": "urlencode",
    "--url-query": "urlencode",
    "-H": "header",
    "--header": "header",
    "-b": "cookie",
    "--cookie": "cookie",
    "-w": "writeout",
    "--write-out": "writeout",
    # local-file sinks: only the no-op targets are allowed so the
    # validate-findings idiom `-s -o /dev/null -w '%{http_code}'` works
    "-o": "sink",
    "--output": "sink",
    "-D": "sink",
    "--dump-header": "sink",
    "-c": "sink",
    "--cookie-jar": "sink",
    "--trace": "sink",
    "--trace-ascii": "sink",
    "--stderr": "sink",
    "--url": "url",
}

_CURL_SHORT_VALUE = frozenset(k[1] for k in _CURL_VALUE_KIND if len(k) == 2)

_CURL_SHORT_DENY = {
    "E": "local key-material read",
    "F": "multipart upload (local-file read)",
    "K": "config-file read",
    "n": "netrc credential read",
    "O": "server-named local file write",
    "J": "server-named local file write",
    "P": "ftp active mode",
    "Q": "server-side (ftp) command",
    "T": "local-file upload",
    "U": "proxy credentials",
    "p": "proxy tunnel",
    "t": "telnet option",
    "x": "proxy redirection",
    "z": "local-file mtime read (If-Modified-Since oracle)",
}

_CURL_LONG_BOOL = frozenset(
    {
        "--silent",
        "--show-error",
        "--verbose",
        "--include",
        "--head",
        "--get",
        "--globoff",
        "--location",
        "--fail",
        "--fail-with-body",
        "--fail-early",
        "--compressed",
        "--raw",
        "--path-as-is",
        "--tcp-nodelay",
        "--ipv4",
        "--ipv6",
        "--http0.9",
        "--http1.0",
        "--http1.1",
        "--http2",
        "--http2-prior-knowledge",
        "--http3",
        "--http3-only",
        "--digest",
        "--basic",
        "--anyauth",
        "--ntlm",
        "--negotiate",
        "--retry-connrefused",
        "--retry-all-errors",
        "--progress-bar",
        "--disable",
        "--junk-session-cookies",
        "--parallel",
        "--next",
        "--trace-time",
        "--styled-output",
        "--buffer",
        "--keepalive",
        "--progress-meter",
        "--version",
        "--help",
        "--manual",
    }
)

_CURL_LONG_DENY = {
    "--upload-file": "local-file upload",
    "--form": "multipart upload (local-file read)",
    "--form-string": "multipart upload",
    "--config": "config-file read",
    "--netrc": "netrc credential read",
    "--netrc-file": "netrc credential read",
    "--netrc-optional": "netrc credential read",
    "--variable": "local file/stdin read into request variables",
    "--etag-compare": "local-file read",
    "--etag-save": "local file write",
    "--alt-svc": "local cache-file write",
    "--hsts": "local cache-file write",
    "--libcurl": "local file write",
    "--remote-name": "server-named local file write",
    "--remote-name-all": "server-named local file write",
    "--remote-header-name": "server-named local file write",
    "--output-dir": "local directory write",
    "--create-dirs": "local directory write",
    "--resolve": "connection redirection",
    "--connect-to": "connection redirection",
    "--unix-socket": "connection redirection",
    "--abstract-unix-socket": "connection redirection",
    "--interface": "connection redirection",
    "--location-trusted": "credential-forwarding redirects",
    "--proto": "protocol-allowlist override",
    "--proto-default": "protocol-allowlist override",
    "--proto-redir": "protocol-allowlist override",
    "--doh-url": "DNS resolution redirection",
    "--cert": "local key-material read",
    "--key": "local key-material read",
    "--quote": "server-side (ftp) command",
    "--telnet-option": "telnet option",
    "--time-cond": "local-file mtime read (If-Modified-Since oracle)",
}

_CURL_REDIRECT_SHORT = frozenset("L")
_CURL_REDIRECT_LONG = frozenset({"--location"})
_CURL_REDIRECT_WHY = "follows redirects off the enforced host allowlist"

_CURL_DENY_PREFIXES = (
    ("--proxy", "proxy redirection"),
    ("--socks", "proxy redirection"),
    ("--expand-", "curl variable expansion"),
    ("--ftp-", "ftp option"),
    ("--mail-", "smtp option"),
    ("--tftp-", "tftp option"),
)

_CURL_SINK_OK = frozenset({"-", "/dev/null", "/dev/stdout", "/dev/stderr"})

_SCHEME_RX = re.compile(r"^([A-Za-z][A-Za-z0-9+.\-]*):")

_CURL_KNOWN_SCHEMES = frozenset(
    {
        "http",
        "https",
        "ftp",
        "ftps",
        "file",
        "dict",
        "gopher",
        "gophers",
        "imap",
        "imaps",
        "ldap",
        "ldaps",
        "mqtt",
        "pop3",
        "pop3s",
        "rtmp",
        "rtmpe",
        "rtmps",
        "rtmpt",
        "rtmpte",
        "rtmpts",
        "rtsp",
        "scp",
        "sftp",
        "smb",
        "smbs",
        "smtp",
        "smtps",
        "telnet",
        "tftp",
        "ws",
        "wss",
    }
)

_PORT_SHORTHAND_RX = re.compile(r"^\d+([/?#].*)?$")

_CURL_GUESSED_SCHEME_LABELS = frozenset({"ftp", "dict", "ldap", "imap", "smtp", "pop3"})


def _is_bracketed_ip(authority: str) -> bool:
    """True when `authority` is a bracketed IP literal with an optional
    `:port` — what curl takes as a host, as opposed to a `[1-9]`-style
    glob. `ipaddress` decides whether the literal is real."""
    if not authority.startswith("["):
        return False
    literal, closed, port = authority[1:].partition("]")
    if not closed or (port and not (port.startswith(":") and port[1:].isdigit())):
        return False
    try:
        ipaddress.ip_address(literal)
    except ValueError:
        return False
    return True


def _curl_deny(opt: str, why: str) -> str:
    return f"curl option {opt!r} is denied under safe_exec ({why})"


@dataclass(frozen=True, slots=True)
class _CurlVetter:
    """Vets one curl argv against the tables above, returning the deny
    reason or '' so callers can shape their own Verdict. A non-empty
    `allowed_hosts` additionally pins every URL operand to those hostnames
    and denies redirect-following (which would leave the allowlist). When it
    is empty, `posture` decides."""

    allowed_hosts: tuple[str, ...] = ()
    posture: Posture = "privileged"

    def check_argv(
        self,
        argv: Sequence[str],
        *,
        bound_urls: list[str] | None = None,
        private_headers: bool = False,
    ) -> str:
        """Walk a curl argv the way curl's own option parser does: short-flag
        clusters with attached or following values, `--opt value`,
        `--opt=value`, and `--` end-of-options. Every option must be on the
        vetted tables above; unknown options are denied."""
        i = 1
        end_of_options = False
        while i < len(argv):
            tok = argv[i]
            i += 1
            if end_of_options or tok == "-" or not tok.startswith("-"):
                if bound_urls is not None:
                    return "trusted curl requests require explicit --url"
                reason = self._check_url(tok)
                if reason:
                    return reason
                continue
            if tok == "--":
                end_of_options = True
                continue
            if tok.startswith("--"):
                opt, sep, attached = tok.partition("=")
                if bound_urls is not None and opt == "--next":
                    return _curl_deny(opt, "trusted curl requests require one transfer")
                if private_headers and opt in ("--verbose", "--trace", "--trace-ascii"):
                    return _curl_deny(opt, "private request headers")
                if opt == "--request-target" and (
                    private_headers
                    or self.allowed_hosts
                    or self.posture in ("restricted", "baseline")
                ):
                    return _curl_deny(opt, "request target can redirect an authorized request")
                why = next((w for prefix, w in _CURL_DENY_PREFIXES if opt.startswith(prefix)), "")
                if why:
                    return _curl_deny(opt, why)
                if opt in _CURL_LONG_DENY:
                    return _curl_deny(opt, _CURL_LONG_DENY[opt])
                if opt in _CURL_REDIRECT_LONG and (
                    private_headers
                    or self.allowed_hosts
                    or self.posture in ("restricted", "baseline")
                ):
                    return _curl_deny(opt, _CURL_REDIRECT_WHY)
                if opt in _CURL_LONG_BOOL:
                    continue
                if opt in _CURL_VALUE_KIND:
                    if sep:
                        val = attached
                    elif i < len(argv):
                        val = argv[i]
                        i += 1
                    else:
                        val = None
                    reason = self._check_value(opt, _CURL_VALUE_KIND[opt], val, private_headers)
                    if reason:
                        return reason
                    if bound_urls is not None and opt == "--url" and val is not None:
                        bound_urls.append(val)
                    continue
                if opt.startswith("--no-") and "--" + opt[5:] in _CURL_LONG_BOOL:
                    continue
                return _curl_deny(opt, "not on the vetted option table — denied by default")
            j = 1
            while j < len(tok):
                ch = tok[j]
                j += 1
                if private_headers and ch == "v":
                    return _curl_deny("-v", "private request headers")
                if ch in _CURL_SHORT_DENY:
                    return _curl_deny(f"-{ch}", _CURL_SHORT_DENY[ch])
                if ch in _CURL_REDIRECT_SHORT and (
                    private_headers
                    or self.allowed_hosts
                    or self.posture in ("restricted", "baseline")
                ):
                    return _curl_deny(f"-{ch}", _CURL_REDIRECT_WHY)
                if ch in _CURL_SHORT_BOOL:
                    continue
                if ch in _CURL_SHORT_VALUE:
                    if j < len(tok):
                        val = tok[j:]
                    elif i < len(argv):
                        val = argv[i]
                        i += 1
                    else:
                        val = None
                    reason = self._check_value(
                        f"-{ch}", _CURL_VALUE_KIND[f"-{ch}"], val, private_headers
                    )
                    if reason:
                        return reason
                    break
                return _curl_deny(f"-{ch}", "not on the vetted option table — denied by default")
        return ""

    def _check_url(self, tok: str) -> str:
        rest = tok
        schemeless = True
        m = _SCHEME_RX.match(tok)
        if m:
            scheme = m.group(1).lower()
            if scheme in ("http", "https"):
                if not tok[m.end() :].startswith("//"):
                    return "curl URL is denied under safe_exec (invalid HTTP URL)"
                rest = tok[m.end() + 2 :]
                schemeless = False
            elif scheme not in _CURL_KNOWN_SCHEMES and _PORT_SHORTHAND_RX.match(tok[m.end() :]):
                pass
            else:
                return f"curl URL scheme {scheme!r} is denied under safe_exec (only http/https)"
        authority = re.split(r"[/?#]", rest, maxsplit=1)[0]
        if any(c in authority for c in "@%\\ \t\r\n"):
            return "curl URL authority is denied under safe_exec"
        if any(c in authority for c in "{}") or (
            ("[" in authority or "]" in authority) and not _is_bracketed_ip(authority)
        ):
            return "curl URL host globbing is denied under safe_exec"
        if schemeless:
            label = authority.split(":", 1)[0].split(".", 1)[0].lower()
            if label in _CURL_GUESSED_SCHEME_LABELS:
                return f"curl URL guesses {label}:// and is denied under safe_exec"
        try:
            parts = urlsplit("http://" + rest)
            host = parts.hostname
            port = parts.port
        except ValueError:
            return "unparseable curl URL is denied under safe_exec"
        if not host or (port is not None and port < 1):
            return "curl URL has no valid hostname or port — denied under safe_exec"
        if not self.allowed_hosts and self.posture == "restricted":
            return "curl URL is denied under safe_exec — restricted posture requires allowed hosts"
        if (self.allowed_hosts or self.posture == "baseline") and (
            any(c in tok for c in "{}")
            or any("[" in part or "]" in part for part in (parts.path, parts.query, parts.fragment))
        ):
            return "curl URL globbing is denied under safe_exec when hosts are enforced"
        norm = host.lower().rstrip(".")
        if self.posture == "baseline":
            if norm not in self.allowed_hosts and (denied := _is_baseline_denied_host(norm)):
                return denied
        elif self.allowed_hosts and norm not in self.allowed_hosts:
            return f"curl host {host!r} is not in the enforced allowlist"
        return ""

    def _check_value(
        self, opt: str, kind: _CurlValueKind | None, val: str | None, private_headers: bool
    ) -> str:
        if val is None:
            return f"curl option {opt!r} is missing its value and is denied under safe_exec"
        if kind == "data":
            if val.startswith("@"):
                return _curl_deny(opt, f"{opt} @<file>/@- upload — local-file exfiltration")
        elif kind == "urlencode":
            if re.match(r"^[^=]*@", val):
                return _curl_deny(opt, f"{opt} [name]@<file> upload — local-file exfiltration")
        elif kind == "header":
            if val.startswith("@"):
                return _curl_deny(opt, f"{opt} @<file> — header read from local file")
            if _authority_header(val) and (
                private_headers or self.allowed_hosts or self.posture in ("restricted", "baseline")
            ):
                return _curl_deny(opt, "request authority override")
        elif kind == "cookie":
            if "=" not in val:
                return _curl_deny(opt, "cookie-file read — local-file exfiltration")
        elif kind == "writeout":
            if val.startswith("@"):
                return _curl_deny(opt, f"{opt} @<file> — format read from local file")
            if "%output{" in val:
                return _curl_deny(opt, "%output{} — local file write")
        elif kind == "sink":
            if val not in _CURL_SINK_OK:
                return _curl_deny(
                    opt, f"local file write sink {val!r} — only {sorted(_CURL_SINK_OK)}"
                )
        elif kind == "url":
            return self._check_url(val)
        return ""


def _authority_header(value: str) -> bool:
    return bool(re.match(r"^\s*(?:host\s*[:;]|:authority\s*:)", value, re.IGNORECASE))


def _check_kube_argv(argv: list[str]) -> str:
    for tok in argv[1:]:
        flag = tok.split("=", 1)[0]
        if tok.startswith("-") and not tok.startswith("--"):
            for ch in tok[1:]:
                if ch == "s":
                    return "kubectl/oc flag '-s' is denied under safe_exec (cluster override)"
                if ch in "nol":
                    break
        if flag in KUBE_DENY_FLAGS:
            return (
                f"kubectl/oc flag {flag!r} is denied under safe_exec "
                "— target-derived commands run only against the "
                "engagement-pinned context (assessment 2026-07-31 F2)"
            )
    return ""


_HARDENING = {
    "git": _check_git_argv,
    "kubectl": _check_kube_argv,
    "oc": _check_kube_argv,
}
