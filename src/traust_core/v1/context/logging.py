from __future__ import annotations

import json
import logging
import os
import stat
import sys
from datetime import UTC, datetime
from io import TextIOWrapper
from logging.handlers import RotatingFileHandler
from pathlib import Path
from threading import RLock

from traust_core.v1.context.config import FIRST_PARTY_LOGGERS, LoggingConfig
from traust_core.v1.errors import ConfigError
from traust_core.v1.providers.correlation import current_correlation

_lock = RLock()
_handlers: tuple[logging.Handler, ...] = ()
_installed: tuple[LoggingConfig, Path, tuple[str, ...]] | None = None
_root_states: dict[str, tuple[int, bool]] = {}
_override_levels: dict[str, int] = {}


def _directory_descriptor(path: Path) -> int:
    try:
        descriptor = os.open(path, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
    except OSError as error:
        raise ConfigError(f"logging directory {path} must be a real directory") from error
    mode = stat.S_IMODE(os.fstat(descriptor).st_mode)
    if mode & 0o022:
        os.close(descriptor)
        raise ConfigError(f"logging directory {path} must not be group or world writable")
    return descriptor


def _private_descriptor(path: Path, *, create: bool) -> int | None:
    directory = _directory_descriptor(path.parent)
    descriptor = None
    flags = os.O_WRONLY | os.O_APPEND | os.O_NOFOLLOW
    if create:
        flags |= os.O_CREAT
    try:
        try:
            descriptor = os.open(path.name, flags, 0o600, dir_fd=directory)
        except FileNotFoundError:
            if not create:
                return None
            raise
        if not stat.S_ISREG(os.fstat(descriptor).st_mode):
            os.close(descriptor)
            descriptor = None
            raise ConfigError(f"logging file {path} must be a regular file")
        os.fchmod(descriptor, 0o600)
        return descriptor
    except OSError as error:
        if descriptor is not None:
            os.close(descriptor)
        raise ConfigError(f"logging file {path} must not be a symlink") from error
    finally:
        os.close(directory)


class _PrivateRotatingFileHandler(RotatingFileHandler):
    def _open(self) -> TextIOWrapper:
        descriptor = _private_descriptor(Path(self.baseFilename), create=True)
        assert descriptor is not None
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
            "status": getattr(record, "status", None),
            "returncode": getattr(record, "returncode", None),
            "repository_id": getattr(record, "repository_id", None),
            "decision_id": getattr(record, "decision_id", None),
            "layer_id": getattr(record, "layer_id", None),
            "count": getattr(record, "count", None),
            "errors": getattr(record, "errors", None),
            "warnings": getattr(record, "warnings", None),
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
            "status",
            "returncode",
            "repository_id",
            "decision_id",
            "layer_id",
            "count",
            "errors",
            "warnings",
        )
        labels = " ".join(
            f"{name}={_one_line(fields[name] if fields[name] is not None else '-')}"
            for name in names
        )
        escaped = _one_line(message)
        return f"{stamp} {record.levelname} {record.name} {labels} {escaped}"


def _one_line(value: object) -> str:
    return str(value).replace("\r", "\\r").replace("\n", "\\n")


def _file_handler(config: LoggingConfig, path: Path) -> logging.Handler:
    parent_created = not path.parent.exists()
    path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
    directory = _directory_descriptor(path.parent)
    if parent_created:
        os.fchmod(directory, 0o700)
    os.close(directory)
    paths = (path, *(Path(f"{path}.{index}") for index in range(1, config.backups + 1)))
    for candidate in paths:
        descriptor = _private_descriptor(candidate, create=candidate == path)
        if descriptor is not None:
            os.close(descriptor)
    return _PrivateRotatingFileHandler(
        path,
        maxBytes=config.max_bytes,
        backupCount=config.backups,
        encoding="utf-8",
        delay=True,
    )


def _logger_roots(extra: tuple[str, ...]) -> tuple[str, ...]:
    roots = tuple(dict.fromkeys(("traust_core", *extra)))
    unsupported = sorted(set(roots) - set(FIRST_PARTY_LOGGERS))
    if unsupported:
        raise ConfigError(f"unsupported first-party logger root: {', '.join(unsupported)}")
    return roots


def _levels(config: LoggingConfig, roots: tuple[str, ...]) -> dict[str, str]:
    return {
        name: level
        for name, level in config.levels.items()
        if any(name == root or name.startswith(f"{root}.") for root in roots)
    }


def configure_logging(config: LoggingConfig, home: Path, extra_roots: tuple[str, ...] = ()) -> None:
    """Install one process-wide first-party setup without touching host handlers."""
    global _handlers, _installed, _override_levels, _root_states
    path = config.file.expanduser()
    if not path.is_absolute():
        path = home / path
    roots = _logger_roots(extra_roots)
    levels = _levels(config, roots)
    with _lock:
        key = (config, path, roots)
        if _installed == key and all(
            handler in logging.getLogger(name).handlers for name in roots for handler in _handlers
        ):
            for name in roots:
                logger = logging.getLogger(name)
                logger.setLevel(config.level)
                logger.propagate = False
            for name, level in levels.items():
                logging.getLogger(name).setLevel(level)
            return
        for name in _root_states:
            logging.getLogger(name).propagate = False
        formatter = _SafeFormatter(config.format)
        handlers: list[logging.Handler] = []
        try:
            if "stderr" in config.outputs:
                handlers.append(logging.StreamHandler(sys.stderr))
            if "file" in config.outputs:
                handlers.append(_file_handler(config, path))
            for handler in handlers:
                handler.addFilter(_CorrelationFilter())
                handler.setFormatter(formatter)
        except Exception:
            for handler in handlers:
                handler.close()
            raise
        for name, level in _override_levels.items():
            logging.getLogger(name).setLevel(level)
        old_roots, new_roots = set(_root_states), set(roots)
        root_states = {name: state for name, state in _root_states.items() if name in new_roots}
        for name in old_roots - new_roots:
            logger = logging.getLogger(name)
            for handler in _handlers:
                logger.removeHandler(handler)
            logger.setLevel(_root_states[name][0])
            logger.propagate = _root_states[name][1]
        for name in roots:
            logger = logging.getLogger(name)
            if name not in old_roots:
                root_states[name] = (logger.level, logger.propagate)
                logger.propagate = False
            logger.setLevel(config.level)
            for handler in handlers:
                logger.addHandler(handler)
            for handler in _handlers:
                logger.removeHandler(handler)
        for handler in _handlers:
            handler.close()
        override_levels = {name: logging.getLogger(name).level for name in levels}
        for name, level in levels.items():
            logging.getLogger(name).setLevel(level)
        _handlers, _installed = tuple(handlers), key
        _override_levels, _root_states = override_levels, root_states
