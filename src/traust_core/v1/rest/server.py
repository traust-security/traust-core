"""`traust-server`: serve the REST API, mint a local token for it, or run the
store's db-contract upgrades. Imports nothing from FastAPI until it serves."""

from __future__ import annotations

import argparse
import logging
import sys
from pathlib import Path

from traust_core.v1.context import Config, Context, StoreState
from traust_core.v1.context.serve import hand_config, hand_role, handed_config, handed_role
from traust_core.v1.errors import ConfigError
from traust_core.v1.rest.roles import Role

_REST_EXTRA = {"fastapi", "starlette", "uvicorn"}
_UNTRUSTED = "this config does not trust its local issuer: set identity.trust_local: true"
# The rate card spend is priced from, beside traust.yaml (contracts `model-registry`).
_RATE_CARD = "model-registry.yaml"
_WORKER_FACTORY = "traust_core.v1.rest.server:_worker_app"

log = logging.getLogger(__name__)


def main(argv: list[str] | None = None) -> None:
    args = _parser().parse_args(argv)
    config = Config.from_file(args.config) if args.config else Config()
    if args.command == "token":
        print(_token(config, args.identity, machine=args.machine))
        return
    if args.command == "db":
        raise SystemExit(_db_upgrade(Context(config), args))
    try:
        import uvicorn
    except ModuleNotFoundError as e:
        if (e.name or "").split(".")[0] not in _REST_EXTRA:
            raise
        raise SystemExit(
            "traust-server needs the REST extra: pip install 'traust-core[rest]'"
        ) from e

    if args.workers > 1:
        # uvicorn spawns fresh processes and can only take an import string for them:
        # the config path is handed over, never the object
        if args.config is not None:
            hand_config(args.config)
        hand_role(args.role)
        uvicorn.run(
            _WORKER_FACTORY,
            host=args.host,
            port=args.port,
            workers=args.workers,
            factory=True,
            log_config=None,
        )
        return
    uvicorn.run(
        _app(config, args.config, Role(args.role)),
        host=args.host,
        port=args.port,
        log_config=None,
    )


def _app(config: Config, config_path: Path | None, role: Role = Role.ALL):
    """The app fully wired: feeds registered, the rate card loaded when the deployment
    ships one beside its config."""
    context = Context(config)
    context.configure_logging()
    context.register_feeds()
    if (rate_card := _rate_card(config_path)) is not None:
        context.register_model_catalog(rate_card)
        log.info("model registry (rate card) loaded from %s", rate_card)
    else:
        log.warning(
            "no %s beside %s: usage settles as spend-unpriced, never as a priced spend_event",
            _RATE_CARD,
            config_path,
        )
    from traust_core.v1.rest.app import create_app

    log.info("serving role %s", role, extra={"operation": "server.role", "outcome": role})
    return create_app(context, role)


def _worker_app():
    """The importable factory a multi-worker uvicorn spawns in each process: the config
    re-read from the path the parent handed it. One worker per process is what the
    CPU-bound insight reads need - a fold in one process no longer taxes every other
    request (measured: 7 concurrent dashboard reads, 29.4s p50 single-process, 14.2s at
    four workers)."""
    path = handed_config()
    return _app(Config.from_file(path) if path else Config(), path, Role(handed_role() or "all"))


def _rate_card(config_path: Path | None) -> Path | None:
    """The model registry beside the served traust.yaml, when the deployment ships one; the
    registry is a config-home file, not a traust.yaml key."""
    if config_path is None:
        return None
    path = config_path.parent / _RATE_CARD
    return path if path.is_file() else None


def _token(config: Config, identity: str, *, machine: bool) -> str:
    """A token from this server's local issuer, for development against a local server."""
    if config.identity is None or not config.identity.trust_local:
        raise SystemExit(_UNTRUSTED)
    return Context(config).local_issuer.mint(identity, machine=machine).token.get_secret_value()


def _db_upgrade(context: Context, args: argparse.Namespace) -> int:
    """Plan the store's db-contract upgrades; ``--apply`` runs them, the operator's call.

    The command an operator (or deploy job) runs against a pinned store: names, hashes and
    declared destructive reasons first, application only when asked, destructive work only
    when acknowledged. A store from before the channel starts at its beginning: the plan
    lists every script, 0001 first. Exit 0: current, applied, or no local store yet. Exit 1:
    pending without ``--apply``, an empty configured database (its deployment provisions
    it), or a channel refusal.
    """
    try:
        if args.allow_destructive and not args.apply:
            print(
                "--allow-destructive acknowledges an apply: add --apply, or drop the flag",
                file=sys.stderr,
            )
            return 2
        status = context.store_status()
        if status.state is StoreState.EMPTY:
            if context.config.database.url is None:
                print("no store yet: it is created on first open (local) or by its deployment")
                return 0
            print(
                "the configured database is empty: its deployment provisions it, never this "
                "command (core README, Two setups, one API)"
            )
            return 1
        if status.state is StoreState.PRE_CHANNEL:
            if not args.apply:
                print("not on the channel yet: the store predates it and is presumed current.")
                print("bringing it on stamps every shipped script as done - nothing runs:")
                for upgrade in context.shipped_db_upgrades():
                    mark = f"  [destructive: {upgrade.destructive}]" if upgrade.destructive else ""
                    print(f"  {upgrade.name}  sha256:{upgrade.sha256[:12]}{mark}")
                print("rerun with --apply to bring it on at the channel's head")
                return 1
            stamped = context.apply_db_upgrades()
            names = ", ".join(upgrade.name for upgrade in stamped) or "nothing"
            print(f"on the channel: {len(stamped)} script(s) presumed done ({names})")
            return 0
        if not status.pending:
            print("up to date")
            return 0
        print(f"{len(status.pending)} upgrade(s) pending:")
        for upgrade in status.pending:
            mark = f"  [destructive: {upgrade.destructive}]" if upgrade.destructive else ""
            print(f"  {upgrade.name}  sha256:{upgrade.sha256[:12]}{mark}")
        if not args.apply:
            print("pending upgrades - rerun with --apply to run them")
            return 1
        applied = context.apply_db_upgrades(allow_destructive=args.allow_destructive)
    except ConfigError as error:
        print(str(error), file=sys.stderr)
        return 1
    names = ", ".join(upgrade.name for upgrade in applied) or "nothing"
    print(f"applied {len(applied)} upgrade(s): {names}")
    return 0


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="traust-server", description=__doc__)
    parser.add_argument("--config", type=Path, help="traust-core config YAML (default: ~/.traust)")
    parser.add_argument("--host", default="127.0.0.1")
    parser.add_argument("--port", type=int, default=8080)
    parser.add_argument(
        "--workers",
        type=int,
        default=1,
        help="server processes: CPU-bound insight reads serialize in one, so concurrent "
        "dashboards need more than one process to use the CPU budget",
    )
    parser.add_argument(
        "--role",
        choices=[r.value for r in Role],
        default=Role.ALL.value,
        help="serve one role: query (reads), command (writes), ops (run orders); all serves "
        "every route",
    )
    commands = parser.add_subparsers(dest="command")
    token = commands.add_parser("token", help="print a token from this server's local issuer")
    token.add_argument("identity", help="a person's email, or a runner's name with --machine")
    token.add_argument("--machine", action="store_true", help="a machine (runner) identity")
    db = commands.add_parser("db", help="the store's db-contract channel")
    db_commands = db.add_subparsers(dest="db_command", required=True)
    upgrade = db_commands.add_parser(
        "upgrade", help="plan pending db-contract upgrades; --apply runs them"
    )
    upgrade.add_argument(
        "--apply", action="store_true", help="apply what the plan shows (default: plan only)"
    )
    upgrade.add_argument(
        "--allow-destructive",
        action="store_true",
        help="with --apply: acknowledge scripts that declare a destructive reason",
    )
    return parser
