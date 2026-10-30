from __future__ import annotations

import json
import logging
import os
import sys
from datetime import UTC, datetime
from io import TextIOWrapper
from logging.handlers import RotatingFileHandler
from pathlib import Path
from threading import RLock

from traust_core.v1.context.config import LoggingConfig
from traust_core.v1.providers.correlation import current_correlation

_lock = RLock()
_handlers: tuple[logging.Handler, ...] = ()
_installed: tuple[LoggingConfig, Path] | None = None
_overrides: set[str] = set()


class _PrivateRotatingFileHandler(RotatingFileHandler):
    def _open(self) -> TextIOWrapper:
        descriptor = os.open(self.baseFilename, os.O_WRONLY | os.O_APPEND | os.O_CREAT, 0o600)
        Path(self.baseFilename).chmod(0o600)
        return os.fdopen(descriptor, self.mode, encoding=self.encoding, errors=self.errors)


class _CorrelationFilter(logging.Filter):
    def filter(self, record: logging.LogRecord) -> bool:
        value = current_correlation()
        fields = {
            "request_id": value.request_id if value else None,
            "order_id": str(value.order_id) if value and value.order_id else None,
            "run_id": str(value.run_id) if value and value.run_id else None,
            "actor_kind": str(value.actor_kind) if value and value.actor_kind else None,
        }
        for name, field in fields.items():
            if not hasattr(record, name):
                setattr(record, name, field)
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
            "error_source": getattr(record, "error_source", None),
            "operation": getattr(record, "operation", None),
            "target_hash": getattr(record, "target_hash", None),
            "outcome": getattr(record, "outcome", None),
            "attempts": getattr(record, "attempts", None),
            "duration_ms": getattr(record, "duration_ms", None),
            "message": message,
        }
        if record.name == "traust_core.rest.access":
            fields.update(
                {
                    name: getattr(record, name, None)
                    for name in ("method", "route", "status", "duration_ms")
                }
            )
        if self._format_name == "json":
            return json.dumps(fields, ensure_ascii=False)
        names = (
            "request_id",
            "order_id",
            "run_id",
            "actor_kind",
            "error_type",
            "error_source",
            "operation",
            "target_hash",
            "outcome",
            "attempts",
            "duration_ms",
        )
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
        core = logging.getLogger("traust_core")
        core.propagate = False
        if _installed == key and all(handler in core.handlers for handler in _handlers):
            return
        parent_created = not path.parent.exists()
        path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
        if parent_created:
            path.parent.chmod(0o700)
        formatter = _SafeFormatter(config.format)
        stream = logging.StreamHandler(sys.stderr)
        rolling = _PrivateRotatingFileHandler(
            path,
            maxBytes=config.max_bytes,
            backupCount=config.backups,
            encoding="utf-8",
            delay=True,
        )
        for handler in _handlers:
            core.removeHandler(handler)
            handler.close()
        for handler in (stream, rolling):
            handler.addFilter(_CorrelationFilter())
            handler.setFormatter(formatter)
            core.addHandler(handler)
        core.setLevel(config.level)
        for name in _overrides:
            logging.getLogger(name).setLevel(logging.NOTSET)
        for name, level in config.levels.items():
            logging.getLogger(name).setLevel(level)
        _overrides = set(config.levels)
        _handlers, _installed = (stream, rolling), key
