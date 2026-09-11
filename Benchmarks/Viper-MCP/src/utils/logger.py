import logging
import sys
from pathlib import Path
from typing import Optional

try:
    from pythonjsonlogger import jsonlogger
    _json_formatter = jsonlogger.JsonFormatter("%(asctime)s %(name)s %(levelname)s %(message)s")
except ImportError:
    _json_formatter = None


def setup_logger(config: dict) -> logging.Logger:
    logger = logging.getLogger("viper_mcp")
    # Avoid adding duplicate handlers when setup_logger is called multiple times
    if logger.handlers:
        return logger

    logger.setLevel(getattr(logging, config.get("level", "INFO")))
    formatter = _json_formatter or logging.Formatter("%(asctime)s - %(name)s - %(levelname)s - %(message)s")

    if config.get("console", True):
        console_handler = logging.StreamHandler(sys.stdout)
        console_handler.setFormatter(logging.Formatter("%(asctime)s - %(name)s - %(levelname)s - %(message)s"))
        logger.addHandler(console_handler)

    log_file = config.get("file")
    if log_file:
        log_path = Path(log_file)
        log_path.parent.mkdir(parents=True, exist_ok=True)
        file_handler = logging.FileHandler(log_file, encoding="utf-8")
        file_handler.setFormatter(formatter)
        logger.addHandler(file_handler)

    return logger
