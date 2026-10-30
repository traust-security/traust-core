from __future__ import annotations

import json
import logging
import stat
from io import StringIO
from pathlib import Path
from unittest.mock import patch
from uuid import UUID

import pydantic
import pytest

from traust_core.v1.context import (
    Config,
    Context,
    LoggingConfig,
    correlation_scope,
    current_correlation,
    enrich_correlation,
)
from traust_core.v1.errors import ConfigError
from traust_core.v1.models.vocabulary import ActorKind


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


def test_repeated_setup_repairs_managed_logger_state(tmp_path: Path) -> None:
    file = tmp_path / "repaired.log"
    context = Context(Config(home=tmp_path, logging=LoggingConfig(outputs=("file",), file=file)))
    context.configure_logging("traust_engine")
    core, engine = logging.getLogger("traust_core"), logging.getLogger("traust_engine")
    core.propagate = engine.propagate = True
    core.setLevel(logging.ERROR)
    engine.setLevel(logging.ERROR)
    context.configure_logging("traust_engine")
    assert (core.propagate, engine.propagate) == (False, False)
    assert (core.level, engine.level) == (logging.INFO, logging.INFO)


def test_handlers_are_safe_before_attachment(tmp_path: Path) -> None:
    file = tmp_path / "attachment.log"
    logger = logging.getLogger("traust")
    add_handler = logger.addHandler
    secret = "synthetic-attachment-secret"

    def emit_during_attachment(handler: logging.Handler) -> None:
        add_handler(handler)
        try:
            raise RuntimeError(secret)
        except RuntimeError:
            logger.error("failed during attachment", exc_info=True)

    with patch.object(logger, "addHandler", side_effect=emit_during_attachment):
        Context(
            Config(home=tmp_path, logging=LoggingConfig(outputs=("file",), file=file))
        ).configure_logging("traust")
    payload = file.read_text()
    assert "failed during attachment" in payload
    assert secret not in payload and "Traceback" not in payload


def test_reconfiguration_never_routes_managed_events_to_host_handlers(tmp_path: Path) -> None:
    engine = logging.getLogger("traust_engine")
    first = Context(
        Config(
            home=tmp_path,
            logging=LoggingConfig(outputs=("file",), file=tmp_path / "first.log"),
        )
    )
    first.configure_logging("traust_engine")
    host_stream = StringIO()
    host = logging.StreamHandler(host_stream)
    root = logging.getLogger()
    root.addHandler(host)
    remove_handler = engine.removeHandler
    secret = "synthetic-swap-secret"

    def emit_during_removal(handler: logging.Handler) -> None:
        remove_handler(handler)
        try:
            raise RuntimeError(secret)
        except RuntimeError:
            engine.error("failed during swap", exc_info=True)

    try:
        with patch.object(engine, "removeHandler", side_effect=emit_during_removal):
            Context(
                Config(
                    home=tmp_path,
                    logging=LoggingConfig(outputs=("file",), file=tmp_path / "second.log"),
                )
            ).configure_logging("traust_engine")
        payload = (tmp_path / "second.log").read_text()
        assert "failed during swap" in payload
        assert secret not in payload and host_stream.getvalue() == ""
    finally:
        root.removeHandler(host)
        host.close()


def test_new_root_transition_drops_events_before_safe_handlers_are_attached(tmp_path: Path) -> None:
    engine = logging.getLogger("traust_engine")
    host_stream = StringIO()
    host = logging.StreamHandler(host_stream)
    root = logging.getLogger()
    root.addHandler(host)
    set_level = engine.setLevel
    secret = "synthetic-new-root-transition-secret"

    def emit_before_attachment(level: int | str) -> None:
        set_level(level)
        try:
            raise RuntimeError(secret)
        except RuntimeError:
            engine.error("failed during new root transition", exc_info=True)

    try:
        with patch.object(engine, "setLevel", side_effect=emit_before_attachment):
            Context(
                Config(
                    home=tmp_path,
                    logging=LoggingConfig(outputs=("file",), file=tmp_path / "new-root.log"),
                )
            ).configure_logging("traust_engine")
        assert host_stream.getvalue() == ""
        assert secret not in (tmp_path / "new-root.log").read_text()
    finally:
        root.removeHandler(host)
        host.close()


def test_removed_root_transition_drops_events_before_host_state_is_restored(tmp_path: Path) -> None:
    engine = logging.getLogger("traust_engine")
    first = Context(
        Config(
            home=tmp_path,
            logging=LoggingConfig(outputs=("file",), file=tmp_path / "first.log"),
        )
    )
    first.configure_logging("traust_engine")
    host_stream = StringIO()
    host = logging.StreamHandler(host_stream)
    root = logging.getLogger()
    root.addHandler(host)
    remove_handler = engine.removeHandler
    secret = "synthetic-removed-root-transition-secret"

    def emit_during_removal(handler: logging.Handler) -> None:
        remove_handler(handler)
        if isinstance(handler, logging.NullHandler):
            return
        try:
            raise RuntimeError(secret)
        except RuntimeError:
            engine.error("failed during removed root transition", exc_info=True)

    try:
        with patch.object(engine, "removeHandler", side_effect=emit_during_removal):
            Context(
                Config(
                    home=tmp_path,
                    logging=LoggingConfig(outputs=("file",), file=tmp_path / "second.log"),
                )
            ).configure_logging()
        assert host_stream.getvalue() == ""
        assert secret not in (tmp_path / "second.log").read_text()
    finally:
        root.removeHandler(host)
        host.close()


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


def test_active_and_retained_log_files_are_made_private_before_writing(tmp_path: Path) -> None:
    file = tmp_path / "private-logs" / "traust.log"
    file.parent.mkdir(mode=0o700)
    retained = file.with_suffix(".log.1")
    for existing in (file, retained):
        existing.write_text("old\n")
        existing.chmod(0o644)
    Context(
        Config(
            home=tmp_path,
            logging=LoggingConfig(file=file, max_bytes=1024, backups=1),
        )
    ).configure_logging()
    assert stat.S_IMODE(file.parent.stat().st_mode) == 0o700
    assert stat.S_IMODE(file.stat().st_mode) == 0o600
    assert stat.S_IMODE(retained.stat().st_mode) == 0o600
    logger = logging.getLogger("traust_core.v1.tests.logging")
    for index in range(60):
        logger.info("event-%03d %s", index, "safe" * 20)
    assert stat.S_IMODE(file.stat().st_mode) == 0o600
    assert stat.S_IMODE(retained.stat().st_mode) == 0o600


def test_a_new_log_directory_is_private_immediately(tmp_path: Path) -> None:
    file = tmp_path / "new-logs" / "traust.log"
    Context(Config(home=tmp_path, logging=LoggingConfig(file=file))).configure_logging()
    assert stat.S_IMODE(file.parent.stat().st_mode) == 0o700
    assert stat.S_IMODE(file.stat().st_mode) == 0o600


def test_logging_refuses_a_symlink_file(tmp_path: Path) -> None:
    directory = tmp_path / "private-logs"
    directory.mkdir(mode=0o700)
    target = tmp_path / "target.log"
    target.write_text("untouched")
    link = directory / "traust.log"
    link.symlink_to(target)
    with pytest.raises(ConfigError, match="must not be a symlink"):
        Context(Config(home=tmp_path, logging=LoggingConfig(file=link))).configure_logging()
    assert target.read_text() == "untouched"


def test_text_format_escapes_structured_fields(tmp_path: Path) -> None:
    file = tmp_path / "structured.log"
    Context(
        Config(home=tmp_path, logging=LoggingConfig(file=file, format="text"))
    ).configure_logging()
    logging.getLogger("traust_core.v1.tests.logging").info(
        "safe message", extra={"operation": "lookup\nforged"}
    )
    payload = file.read_text()
    assert payload.count("\n") == 1
    assert "operation=lookup\\nforged" in payload


def test_registered_first_party_roots_share_handlers_and_correlation(tmp_path: Path) -> None:
    file = tmp_path / "consumers.log"
    context = Context(
        Config(
            home=tmp_path,
            logging=LoggingConfig(
                outputs=("file",),
                file=file,
                levels={"traust_engine.ops": "DEBUG"},
            ),
        )
    )
    context.configure_logging("traust_engine", "traust_ledger", "traust_engine")
    with correlation_scope("engine-123"):
        enrich_correlation(order_id=UUID("00000000-0000-4000-8000-000000000002"))
        assert current_correlation() is not None
        logging.getLogger("traust_engine.ops").debug("engine event")
        logging.getLogger("traust_ledger.integrity.signing").info("ledger event")
        logging.getLogger("synthetic_dependency").error("dependency event")
    assert current_correlation() is None
    records = [json.loads(line) for line in file.read_text().splitlines()]
    assert [(row["logger"], row["message"]) for row in records] == [
        ("traust_engine.ops", "engine event"),
        ("traust_ledger.integrity.signing", "ledger event"),
    ]
    assert {row["request_id"] for row in records} == {"engine-123"}
    assert {row["order_id"] for row in records} == {"00000000-0000-4000-8000-000000000002"}


def test_reconfiguration_restores_a_removed_consumer_root(tmp_path: Path) -> None:
    Context(
        Config(
            home=tmp_path,
            logging=LoggingConfig(outputs=("file",), file=tmp_path / "baseline.log"),
        )
    ).configure_logging()
    engine = logging.getLogger("traust_engine")
    original = (engine.level, engine.propagate)
    first = Context(
        Config(
            home=tmp_path,
            logging=LoggingConfig(outputs=("file",), file=tmp_path / "first.log"),
        )
    )
    first.configure_logging("traust_engine")
    assert engine.propagate is False
    Context(
        Config(
            home=tmp_path,
            logging=LoggingConfig(outputs=("file",), file=tmp_path / "second.log"),
        )
    ).configure_logging()
    assert (engine.level, engine.propagate) == original


def test_logging_rejects_unowned_logger_roots(tmp_path: Path) -> None:
    with pytest.raises(ConfigError, match="unsupported first-party logger root"):
        Context(Config(home=tmp_path)).configure_logging("sqlalchemy")


def test_default_info_and_first_party_only_level_overrides(tmp_path: Path) -> None:
    file = tmp_path / "levels.log"
    context = Context(Config(home=tmp_path, logging=LoggingConfig(file=file)))
    context.configure_logging()
    logging.getLogger("traust_core.v1.tests.logging").info("core event")
    logging.getLogger("traust_core.rest.access").info("access")
    assert [json.loads(line)["message"] for line in file.read_text().splitlines()] == [
        "core event",
        "access",
    ]
    filtered = tmp_path / "filtered.log"
    Context(
        Config(
            home=tmp_path,
            logging=LoggingConfig(
                file=filtered, levels={"traust_core.v1.tests.logging": "WARNING"}
            ),
        )
    ).configure_logging()
    logging.getLogger("traust_core.v1.tests.logging").info("suppressed")
    logging.getLogger("traust_core.rest.access").info("access")
    assert [json.loads(line)["message"] for line in filtered.read_text().splitlines()] == ["access"]
    assert LoggingConfig(levels={"traust_engine.ops": "DEBUG"}).levels == {
        "traust_engine.ops": "DEBUG"
    }
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


def test_core_events_never_reach_host_handlers_or_leak_exception_text(tmp_path: Path) -> None:
    root = logging.getLogger()
    host_stream = StringIO()
    handler = logging.StreamHandler(host_stream)
    root.addHandler(handler)
    try:
        file = tmp_path / "core.log"
        Context(Config(home=tmp_path, logging=LoggingConfig(file=file))).configure_logging()
        secret = "synthetic-only-never-a-real-credential"
        with correlation_scope("safe-1"):
            try:
                raise RuntimeError(secret)
            except RuntimeError:
                logging.getLogger("traust_core.v1.tests.logging").error("failed", exc_info=True)
        logging.getLogger("synthetic_dependency").error("dependency failed")
        assert host_stream.getvalue().splitlines() == ["dependency failed"]
        assert secret not in host_stream.getvalue()
        assert secret not in file.read_text()
    finally:
        root.removeHandler(handler)
        handler.close()


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


def test_logging_outputs_can_be_selected_independently(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    file = tmp_path / "logs" / "selected.log"
    logger = logging.getLogger("traust_core.v1.tests.logging")
    Context(
        Config(home=tmp_path, logging=LoggingConfig(outputs=("stderr",), file=file))
    ).configure_logging()
    logger.info("stream only")
    assert '"message": "stream only"' in capsys.readouterr().err
    assert not file.parent.exists()

    Context(
        Config(home=tmp_path, logging=LoggingConfig(outputs=("file",), file=file))
    ).configure_logging()
    logger.info("file only")
    assert capsys.readouterr().err == ""
    assert [json.loads(line)["message"] for line in file.read_text().splitlines()] == ["file only"]


def test_config_file_can_select_logging_outputs(tmp_path: Path) -> None:
    path = tmp_path / "config.yaml"
    path.write_text("logging:\n  outputs: [stderr]\n")
    assert Config.from_file(path).logging.outputs == ("stderr",)


@pytest.mark.parametrize("outputs", [(), ("stderr", "stderr")])
def test_logging_outputs_must_be_nonempty_and_unique(outputs: tuple[str, ...]) -> None:
    with pytest.raises(pydantic.ValidationError):
        LoggingConfig(outputs=outputs)  # type: ignore[arg-type]
