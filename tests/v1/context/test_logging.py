from __future__ import annotations

import json
import logging
from pathlib import Path
from unittest.mock import patch
from uuid import UUID

import pydantic
import pytest

from traust_core.v1.context import Config, Context, LoggingConfig
from traust_core.v1.models.vocabulary import ActorKind
from traust_core.v1.providers.correlation import correlation_scope


def test_repeated_setup_emits_one_json_event_per_log_and_omits_exception_details(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    file = tmp_path / "logs" / "audit.log"
    context = Context(Config(home=tmp_path, logging=LoggingConfig(level="INFO", file=file)))
    context.configure_logging()
    context.configure_logging()
    logger = logging.getLogger("traust_core.v1.tests.logging")
    order_id = UUID("00000000-0000-4000-8000-000000000001")
    secret = "synthetic-only-never-a-real-credential"
    with correlation_scope("req-123", order_id=order_id, actor_kind=ActorKind.HUMAN):
        logger.info("published %s", "safe-id")
        try:
            raise RuntimeError(secret)
        except RuntimeError:
            logger.error("failed", exc_info=True, extra={"error_type": "RuntimeError"})
    payload = file.read_text()
    first, second = [json.loads(line) for line in payload.splitlines()]
    assert first["message"] == "published safe-id"
    assert (first["request_id"], first["order_id"], first["actor_kind"]) == (
        "req-123",
        str(order_id),
        "human",
    )
    assert second["message"] == "failed" and second["error_type"] == "RuntimeError"
    assert secret not in payload
    assert capsys.readouterr().err.count('"message": "published safe-id"') == 1


def test_text_format_escapes_lines_and_rotates_with_a_bounded_retention(
    tmp_path: Path,
) -> None:
    file = tmp_path / "logs" / "rotating.log"
    context = Context(
        Config(
            home=tmp_path,
            logging=LoggingConfig(
                format="text", level="INFO", file=file, max_bytes=1024, backups=2
            ),
        )
    )
    context.configure_logging()
    logger = logging.getLogger("traust_core.v1.tests.logging")
    with correlation_scope("text-1"):
        logger.info("one\nline")
    assert "request_id=text-1" in file.read_text()
    assert "one\\nline" in file.read_text()
    for index in range(60):
        logger.info("event-%03d %s", index, "safe" * 20)
    assert file.stat().st_size <= 1024
    assert (tmp_path / "logs" / "rotating.log.1").is_file()
    assert (tmp_path / "logs" / "rotating.log.2").is_file()
    assert not (tmp_path / "logs" / "rotating.log.3").exists()


def test_levels_default_to_warnings_except_access_and_reject_other_packages(tmp_path: Path) -> None:
    file = tmp_path / "levels.log"
    context = Context(Config(home=tmp_path, logging=LoggingConfig(file=file)))
    context.configure_logging()
    logging.getLogger("traust_core.v1.tests.logging").info("suppressed")
    logging.getLogger("traust_core.rest.access").info("access")
    assert [json.loads(line)["message"] for line in file.read_text().splitlines()] == ["access"]
    with pytest.raises(pydantic.ValidationError):
        LoggingConfig(levels={"sqlalchemy.engine": "DEBUG"})


def test_core_setup_does_not_suppress_dependency_errors(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    root = logging.getLogger()
    with patch.object(root, "handlers", []):
        Context(Config(home=tmp_path)).configure_logging()
        logging.getLogger("synthetic_dependency").error("dependency failed")
        assert "dependency failed" in capsys.readouterr().err


def test_config_file_can_select_logging_format_and_levels(tmp_path: Path) -> None:
    path = tmp_path / "config.yaml"
    path.write_text(
        "logging:\n  format: text\n  level: INFO\n  levels:\n    traust_core.rest.access: DEBUG\n"
    )
    config = Config.from_file(path)
    assert (config.logging.format, config.logging.level, config.logging.levels) == (
        "text",
        "INFO",
        {"traust_core.rest.access": "DEBUG"},
    )
