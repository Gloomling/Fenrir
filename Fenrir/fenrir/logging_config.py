# fenrir/logging_config.py
#
# Provides the centralised logging configuration for the entire Fenrir application.
#
# Design:
#   - A single named logger ("fenrir") is used by all modules via the module-level
#     `log` singleton, obtained through get_logger().
#   - In CLI mode, log records are written to both the console (coloured) and a
#     rotating file (fenrir.log).
#   - In GUI mode, an additional QueueHandler is attached so the GUI thread can
#     safely consume log records and display them in the output widget.
#   - The logger is initialised lazily (on first call to get_logger()) to avoid
#     side-effects such as creating fenrir.log on bare import.

import logging
import logging.handlers
import sys
from typing import Optional

import colorama; from colorama import Fore, Style; colorama.init()

colorama.init(autoreset=True)

# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

LOG_FILE = "fenrir.log"
LOG_MAX_BYTES = 5 * 1024 * 1024   # 5 MB per log file
LOG_BACKUP_COUNT = 5               # Keep up to 5 rotated files
LOG_FORMAT_CONSOLE = "%(levelname)s - %(message)s"
LOG_FORMAT_FILE = "%(asctime)s - %(name)s - %(levelname)s - %(module)s:%(lineno)d - %(message)s"
LOG_FORMAT_QUEUE = "%(levelname)s - %(message)s"  # Format delivered to GUI queue

# ---------------------------------------------------------------------------
# Coloured console formatter
# ---------------------------------------------------------------------------

class _ColoredFormatter(logging.Formatter):
    """Applies terminal colour codes to log level names for console output."""

    _LEVEL_COLORS = {
        logging.DEBUG:    Fore.CYAN,
        logging.INFO:     Fore.GREEN,
        logging.WARNING:  Fore.YELLOW,
        logging.ERROR:    Fore.RED,
        logging.CRITICAL: Fore.MAGENTA + Style.BRIGHT,
    }

    def format(self, record: logging.LogRecord) -> str:
        # Work on a copy so we don't mutate the shared LogRecord object,
        # which would corrupt output for other handlers (e.g. the file handler).
        record_copy = logging.makeLogRecord(record.__dict__)
        color = self._LEVEL_COLORS.get(record_copy.levelno, "")
        record_copy.levelname = f"{color}{record_copy.levelname:<8}{Style.RESET_ALL}"
        return super().format(record_copy)


# ---------------------------------------------------------------------------
# Queue formatter — delivers pre-formatted strings to the GUI
# ---------------------------------------------------------------------------

class _QueueFormatter(logging.Formatter):
    """
    Formatter used by the QueueHandler.

    Records are formatted into plain strings before being placed on the queue
    so the GUI consumer only needs to call queue.get() and insert the string
    directly into the text widget — no further formatting required.

    A 'levelno' attribute is preserved in the formatted message via a prefix
    token so the GUI can apply colour tags without needing to inspect the raw
    LogRecord (which is no longer on the queue after formatting).

    Format delivered: "LEVELNO:<int>|<formatted message>"
    The GUI strips the prefix after reading the colour tag.
    """

    def format(self, record: logging.LogRecord) -> str:
        msg = super().format(record)
        # Prefix with level number so GUI can colour-code without the LogRecord
        return f"LEVELNO:{record.levelno}|{msg}"


# ---------------------------------------------------------------------------
# Lazy singleton logger
# ---------------------------------------------------------------------------

_logger: Optional[logging.Logger] = None


def setup_logging(
    log_level: int = logging.DEBUG,
    log_queue: Optional["queue.Queue"] = None,  # type: ignore[name-defined]
) -> logging.Logger:
    """
    Initialise (or re-initialise) the 'fenrir' logger.

    Args:
        log_level:  Minimum severity level to capture. Defaults to DEBUG so
                    all messages are available; individual handlers may raise
                    their own floor (e.g. file handler at DEBUG, console at INFO).
        log_queue:  If provided (GUI mode), attaches a QueueHandler so log
                    records are forwarded to the GUI text widget via the queue.
                    The caller is responsible for creating and consuming the queue.

    Returns:
        The configured logging.Logger instance.
    """
    global _logger

    logger = logging.getLogger("fenrir")
    logger.setLevel(log_level)
    logger.propagate = False  # Prevent double-logging via the root logger

    # Clear any existing handlers so setup_logging() is safely idempotent
    # (e.g. if called again when the GUI restarts a scan).
    if logger.hasHandlers():
        logger.handlers.clear()

    # ------------------------------------------------------------------
    # 1. Console handler — coloured output, INFO and above
    # ------------------------------------------------------------------
    console_handler = logging.StreamHandler(sys.stdout)
    console_handler.setLevel(logging.INFO)
    console_handler.setFormatter(_ColoredFormatter(LOG_FORMAT_CONSOLE))
    logger.addHandler(console_handler)

    # ------------------------------------------------------------------
    # 2. Rotating file handler — full DEBUG output for post-mortem review
    # ------------------------------------------------------------------
    try:
        file_handler = logging.handlers.RotatingFileHandler(
            LOG_FILE,
            maxBytes=LOG_MAX_BYTES,
            backupCount=LOG_BACKUP_COUNT,
            encoding="utf-8",
        )
        file_handler.setLevel(logging.DEBUG)
        file_handler.setFormatter(logging.Formatter(LOG_FORMAT_FILE))
        logger.addHandler(file_handler)
    except OSError as exc:
        # Non-fatal — warn to console and continue without file logging.
        print(
            f"{Fore.YELLOW}WARNING{Style.RESET_ALL} - Could not open log file "
            f"'{LOG_FILE}': {exc}. File logging disabled."
        )

    # ------------------------------------------------------------------
    # 3. Queue handler — GUI mode only
    # ------------------------------------------------------------------
    if log_queue is not None:
        queue_handler = logging.handlers.QueueHandler(log_queue)
        queue_handler.setLevel(logging.DEBUG)
        queue_handler.setFormatter(_QueueFormatter(LOG_FORMAT_QUEUE))
        logger.addHandler(queue_handler)
        logger.debug("GUI queue handler attached to logger.")

    _logger = logger
    return logger


def get_logger() -> logging.Logger:
    """
    Return the shared 'fenrir' logger, initialising it with defaults if needed.

    All modules should import and use this function:

        from ..logging_config import get_logger
        log = get_logger()

    This guarantees the logger is never used before it is configured, and
    avoids creating fenrir.log on bare import of any module.
    """
    global _logger
    if _logger is None:
        _logger = setup_logging()
    return _logger


# ---------------------------------------------------------------------------
# Convenience alias
# ---------------------------------------------------------------------------
# Modules can do either:
#   from ..logging_config import get_logger; log = get_logger()
# or the shorter:
#   from ..logging_config import log
#
# The second form is safe because `log` is resolved at import time of THIS
# module, not at import time of the importing module — and by the time any
# module imports logging_config, Python has already executed this file.
#
# Using get_logger() is slightly preferable in modules that may be imported
# before the GUI has attached its queue handler, because get_logger() always
# returns the current singleton, which can be re-configured later by a
# subsequent call to setup_logging(log_queue=...).

log = get_logger()