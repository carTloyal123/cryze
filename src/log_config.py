"""Shared logging configuration for all Python services.

Usage:
    from log_config import get_logger
    log = get_logger("relay")
    log.info("listening on port %d", port)

Output format matches the C++ bridge:
    2026-05-17T14:23:01.123Z [INFO ] [relay] listening on port 28800

Set LOG_LEVEL env var to debug/info/warn/error (default: info).
Set LOG_FILE env var to also write to a file.
"""

import logging
import os
import sys
from datetime import datetime, timezone


class BridgeFormatter(logging.Formatter):
    LEVELS = {
        logging.DEBUG:    "DEBUG",
        logging.INFO:     "INFO ",
        logging.WARNING:  "WARN ",
        logging.ERROR:    "ERROR",
        logging.CRITICAL: "FATAL",
    }

    def __init__(self, component: str):
        super().__init__()
        self.component = component

    def format(self, record: logging.LogRecord) -> str:
        now = datetime.now(timezone.utc)
        ts = now.strftime("%Y-%m-%dT%H:%M:%S") + f".{now.microsecond // 1000:03d}Z"
        level = self.LEVELS.get(record.levelno, "?????")
        msg = record.getMessage()
        return f"{ts} [{level}] [{self.component}] {msg}"


def get_logger(component: str) -> logging.Logger:
    logger = logging.getLogger(f"bridge.{component}")
    if logger.handlers:
        return logger

    level_str = os.environ.get("LOG_LEVEL", "info").upper()
    level = getattr(logging, level_str, logging.INFO)
    logger.setLevel(level)

    stderr_handler = logging.StreamHandler(sys.stderr)
    stderr_handler.setFormatter(BridgeFormatter(component))
    logger.addHandler(stderr_handler)

    log_file = os.environ.get("LOG_FILE")
    if log_file:
        file_handler = logging.FileHandler(log_file, mode="a")
        file_handler.setFormatter(BridgeFormatter(component))
        logger.addHandler(file_handler)

    logger.propagate = False
    return logger
