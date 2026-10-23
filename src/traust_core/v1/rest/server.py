"""`traust-server`: serve the REST API. Imports nothing from FastAPI until it runs."""

from __future__ import annotations

import argparse
from pathlib import Path

from traust_core.v1.context import Config, Context

_REST_EXTRA = {"fastapi", "starlette", "uvicorn"}
_MISSING_EXTRA = "traust-server needs the REST extra: pip install 'traust-core[rest]'"


def main(argv: list[str] | None = None) -> None:
    args = _parser().parse_args(argv)
    try:
        import uvicorn

        from traust_core.v1.rest.app import create_app
    except ModuleNotFoundError as e:
        if (e.name or "").split(".")[0] not in _REST_EXTRA:
            raise
        raise SystemExit(
            "traust-server needs the REST extra: pip install 'traust-core[rest]'"
        ) from e

    config = Config.from_file(args.config) if args.config else Config()
    uvicorn.run(create_app(Context(config)), host=args.host, port=args.port, log_config=None)


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="traust-server", description=__doc__)
    parser.add_argument("--config", type=Path, help="traust-core config YAML (default: ~/.traust)")
    parser.add_argument("--host", default="127.0.0.1")
    parser.add_argument("--port", type=int, default=8080)
    return parser
