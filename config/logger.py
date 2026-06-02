import logging
import logging.handlers
import os
import sys


def setup_logger(
    log_level: str = "INFO",
    log_file: str = "logs/scanner.log",
    max_bytes: int = 10_485_760,
    backup_count: int = 5,
) -> logging.Logger:
    """
    Configures the application logger with a rotating file handler and a
    colour-aware console handler.  Safe to call multiple times — duplicate
    handlers are never added.
    """
    log_dir = os.path.dirname(log_file)
    if log_dir:
        os.makedirs(log_dir, exist_ok=True)

    logger = logging.getLogger("NetworkSecurityScanner")
    numeric_level = getattr(logging, log_level.upper(), logging.INFO)
    logger.setLevel(numeric_level)

    if logger.handlers:
        return logger

    file_fmt = logging.Formatter(
        "%(asctime)s | %(levelname)-8s | %(module)-20s | %(message)s",
        datefmt="%Y-%m-%d %H:%M:%S",
    )
    console_fmt = _ColourFormatter(
        "%(asctime)s | %(levelname)-8s | %(message)s",
        datefmt="%H:%M:%S",
    )

    # Rotating file handler — never grows unbounded
    fh = logging.handlers.RotatingFileHandler(
        log_file,
        maxBytes=max_bytes,
        backupCount=backup_count,
        encoding="utf-8",
    )
    fh.setLevel(numeric_level)
    fh.setFormatter(file_fmt)

    # Console handler
    ch = logging.StreamHandler(sys.stdout)
    ch.setLevel(numeric_level)
    ch.setFormatter(console_fmt)

    logger.addHandler(fh)
    logger.addHandler(ch)

    return logger


class _ColourFormatter(logging.Formatter):
    """Adds ANSI colour codes to console output on platforms that support it."""

    _RESET = "\033[0m"
    _LEVEL_COLOURS = {
        logging.DEBUG:    "\033[36m",   # cyan
        logging.INFO:     "\033[32m",   # green
        logging.WARNING:  "\033[33m",   # yellow
        logging.ERROR:    "\033[31m",   # red
        logging.CRITICAL: "\033[1;31m", # bold red
    }

    def format(self, record: logging.LogRecord) -> str:
        colour = self._LEVEL_COLOURS.get(record.levelno, self._RESET)
        msg = super().format(record)
        if sys.stdout.isatty():
            return f"{colour}{msg}{self._RESET}"
        return msg
