from __future__ import annotations

import json
import logging
import sys
from datetime import UTC, datetime
from logging.handlers import RotatingFileHandler
from pathlib import Path
from threading import RLock

from traust_core.v1.context.config import LoggingConfig
from traust_core.v1.providers.correlation import current_correlation

_lock = RLock()
_handlers: tuple[logging.Handler, ...] = ()
_installed: tuple[LoggingConfig, Path] | None = None
_overrides: set[str] = set()


class _CorrelationFilter(logging.Filter):
    def filter(self, record: logging.LogRecord) -> bool:
        if record.name != "traust_core" and not record.name.startswith("traust_core."):
            return False
        value = current_correlation()
        record.request_id = value.request_id if value else None
        record.order_id = str(value.order_id) if value and value.order_id else None
        record.run_id = str(value.run_id) if value and value.run_id else None
        record.actor_kind = str(value.actor_kind) if value and value.actor_kind else None
        return True


class _SafeFormatter(logging.Formatter):
    def __init__(self, format_name: str) -> None:
        super().__init__()
        self._format_name = format_name

    def format(self, record: logging.LogRecord) -> str:
        stamp = datetime.fromtimestamp(record.created, UTC).isoformat(timespec="milliseconds")
        message = record.getMessage()
        fields = {
            "timestamp": stamp,
            "level": record.levelname,
            "logger": record.name,
            "request_id": record.request_id,
            "order_id": record.order_id,
            "run_id": record.run_id,
            "actor_kind": record.actor_kind,
            "error_type": getattr(record, "error_type", None),
            "message": message,
        }
        if self._format_name == "json":
            return json.dumps(fields, ensure_ascii=False)
        names = ("request_id", "order_id", "run_id", "actor_kind", "error_type")
        labels = " ".join(f"{name}={fields[name] or '-'}" for name in names)
        escaped = message.replace("\r", "\\r").replace("\n", "\\n")
        return f"{stamp} {record.levelname} {record.name} {labels} {escaped}"


def configure_logging(config: LoggingConfig, home: Path) -> None:
    """Install one process-wide core logger setup without touching host handlers."""
    global _handlers, _installed, _overrides
    path = config.file.expanduser()
    if not path.is_absolute():
        path = home / path
    with _lock:
        key = (config, path)
        root = logging.getLogger()
        if _installed == key and all(handler in root.handlers for handler in _handlers):
            return
        path.parent.mkdir(parents=True, exist_ok=True)
        formatter = _SafeFormatter(config.format)
        stream = logging.StreamHandler(sys.stderr)
        rolling = RotatingFileHandler(
            path,
            maxBytes=config.max_bytes,
            backupCount=config.backups,
            encoding="utf-8",
            delay=True,
        )
        for handler in _handlers:
            root.removeHandler(handler)
            handler.close()
        for handler in (stream, rolling):
            handler.addFilter(_CorrelationFilter())
            handler.setFormatter(formatter)
            root.addHandler(handler)
        logging.getLogger("traust_core").setLevel(config.level)
        for name in _overrides:
            logging.getLogger(name).setLevel(logging.NOTSET)
        for name, level in config.levels.items():
            logging.getLogger(name).setLevel(level)
        _overrides = set(config.levels)
        _handlers, _installed = (stream, rolling), key
