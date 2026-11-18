"""`traust-server`: serve the REST API, or mint a local token for it. Imports nothing from FastAPI
until it serves."""

from __future__ import annotations

import argparse
import logging
from pathlib import Path

from traust_core.v1.context import Config, Context
from traust_core.v1.context.serve import hand_config, handed_config

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
        uvicorn.run(
            _WORKER_FACTORY,
            host=args.host,
            port=args.port,
            workers=args.workers,
            factory=True,
            log_config=None,
        )
        return
    uvicorn.run(_app(config, args.config), host=args.host, port=args.port, log_config=None)


def _app(config: Config, config_path: Path | None):
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

    return create_app(context)


def _worker_app():
    """The importable factory a multi-worker uvicorn spawns in each process: the config
    re-read from the path the parent handed it. One worker per process is what the
    CPU-bound insight reads need - a fold in one process no longer taxes every other
    request (measured: 7 concurrent dashboard reads, 29.4s p50 single-process, 14.2s at
    four workers)."""
    path = handed_config()
    return _app(Config.from_file(path) if path else Config(), path)


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
    commands = parser.add_subparsers(dest="command")
    token = commands.add_parser("token", help="print a token from this server's local issuer")
    token.add_argument("identity", help="a person's email, or a runner's name with --machine")
    token.add_argument("--machine", action="store_true", help="a machine (runner) identity")
    return parser
