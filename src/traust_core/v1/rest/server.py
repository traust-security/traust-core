"""`traust-server`: serve the REST API, or mint a local token for it. Imports nothing from FastAPI
until it serves."""

from __future__ import annotations

import argparse
from pathlib import Path

from traust_core.v1.context import Config, Context

_REST_EXTRA = {"fastapi", "starlette", "uvicorn"}
_UNTRUSTED = "this config does not trust its local issuer: set identity.trust_local: true"


def main(argv: list[str] | None = None) -> None:
    args = _parser().parse_args(argv)
    config = Config.from_file(args.config) if args.config else Config()
    if args.command == "token":
        print(_token(config, args.identity, machine=args.machine))
        return
    try:
        import uvicorn

        from traust_core.v1.rest.app import create_app
    except ModuleNotFoundError as e:
        if (e.name or "").split(".")[0] not in _REST_EXTRA:
            raise
        raise SystemExit(
            "traust-server needs the REST extra: pip install 'traust-core[rest]'"
        ) from e

    context = Context(config)
    context.configure_logging()
    uvicorn.run(create_app(context), host=args.host, port=args.port, log_config=None)


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
    commands = parser.add_subparsers(dest="command")
    token = commands.add_parser("token", help="print a token from this server's local issuer")
    token.add_argument("identity", help="a person's email, or a runner's name with --machine")
    token.add_argument("--machine", action="store_true", help="a machine (runner) identity")
    return parser
