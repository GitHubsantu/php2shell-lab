"""Logging: rotating file handler plus a quiet console handler."""
from __future__ import annotations

import logging
import logging.handlers
from pathlib import Path

LOGGER_NAME = "php2shell"


def setup_logging(
    log_dir: Path,
    level: str = "INFO",
    max_bytes: int = 1_048_576,
    backup_count: int = 5,
) -> logging.Logger:
    """Configure and return the framework logger. Idempotent."""
    logger = logging.getLogger(LOGGER_NAME)
    if getattr(logger, "_p2s_configured", False):
        return logger

    log_dir = Path(log_dir)
    log_dir.mkdir(parents=True, exist_ok=True)

    logger.setLevel(getattr(logging, level.upper(), logging.INFO))
    logger.propagate = False

    fmt = logging.Formatter(
        "%(asctime)s %(levelname)-7s %(name)s: %(message)s",
        datefmt="%Y-%m-%dT%H:%M:%S",
    )

    file_handler = logging.handlers.RotatingFileHandler(
        log_dir / "php2shell.log",
        maxBytes=max_bytes,
        backupCount=backup_count,
        encoding="utf-8",
    )
    file_handler.setFormatter(fmt)
    logger.addHandler(file_handler)

    # Console stays at WARNING: Rich owns normal output.
    console = logging.StreamHandler()
    console.setLevel(logging.WARNING)
    console.setFormatter(fmt)
    logger.addHandler(console)

    logger._p2s_configured = True  # type: ignore[attr-defined]
    return logger


def get_logger() -> logging.Logger:
    return logging.getLogger(LOGGER_NAME)


def log_command(argv: list[str]) -> None:
    """Record a subprocess command line before executing it."""
    get_logger().info("exec: %s", " ".join(str(a) for a in argv))