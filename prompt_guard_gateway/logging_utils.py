"""Logging utilities.

Flagged prompts are logged as JSON lines to `logs/flagged.log` by default.

You can override the output directory with:
- PROMPT_GUARD_LOG_DIR=/path/to/logs
"""

import json
import logging
import os
import threading
from logging.handlers import RotatingFileHandler
from pathlib import Path
from typing import Any, Dict


_LOGGER_LOCK = threading.Lock()


def _ensure_log_dir() -> Path:
    log_dir = Path(os.environ.get("PROMPT_GUARD_LOG_DIR", "logs"))
    log_dir.mkdir(parents=True, exist_ok=True)
    return log_dir


def get_flagged_logger() -> logging.Logger:
    """Get (and configure) the logger used for flagged prompts."""

    logger = logging.getLogger("prompt_guard.flagged")
    if logger.handlers:
        return logger

    with _LOGGER_LOCK:
        if logger.handlers:
            return logger

        logger.setLevel(logging.INFO)
        logger.propagate = False

        log_dir = _ensure_log_dir()
        handler = RotatingFileHandler(
            log_dir / "flagged.log",
            maxBytes=5 * 1024 * 1024,
            backupCount=3,
            encoding="utf-8",
        )
        handler.setFormatter(logging.Formatter("%(message)s"))
        logger.addHandler(handler)
        return logger


def log_flagged_attempt(payload: Dict[str, Any]) -> None:
    """Write a single JSON line entry."""

    logger = get_flagged_logger()
    try:
        logger.info(json.dumps(payload, ensure_ascii=False))
    except (TypeError, ValueError) as e:
        logger.error(f"Failed to serialize flagged attempt: {e}")
