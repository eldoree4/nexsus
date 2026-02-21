"""
nexsus/core/logger.py
~~~~~~~~~~~~~~~~~~~~~
Structured, colourised logger with per-module names, rotating file handler,
and optional JSON output for SIEM integration.
"""
import logging
import logging.handlers
import sys
import time
import json
from pathlib import Path
from colorama import Fore, Back, Style, init as _colorama_init

_colorama_init(autoreset=True)

# ── Severity palette ──────────────────────────────────────────────────────────
_PALETTE = {
    "DEBUG":    Fore.CYAN,
    "INFO":     Fore.WHITE,
    "SUCCESS":  Fore.GREEN + Style.BRIGHT,
    "WARNING":  Fore.YELLOW + Style.BRIGHT,
    "ERROR":    Fore.RED,
    "CRITICAL": Fore.WHITE + Back.RED + Style.BRIGHT,
    "FINDING":  Fore.MAGENTA + Style.BRIGHT,
}

# ── Severity icons ─────────────────────────────────────────────────────────────
_ICONS = {
    "DEBUG":    "·",
    "INFO":     "ℹ",
    "SUCCESS":  "✔",
    "WARNING":  "⚠",
    "ERROR":    "✘",
    "CRITICAL": "☠",
    "FINDING":  "🎯",
}

# Custom level
SUCCESS_LEVEL = 25
FINDING_LEVEL = 26
logging.addLevelName(SUCCESS_LEVEL, "SUCCESS")
logging.addLevelName(FINDING_LEVEL, "FINDING")


class _ColourFormatter(logging.Formatter):
    """Console formatter with colour + icons."""
    FMT = "{time}  {icon} {colour}[{level:<8}]{reset} {dim}{module}{reset}  {colour}{msg}{reset}"

    def format(self, record: logging.LogRecord) -> str:
        level = record.levelname
        colour = _PALETTE.get(level, "")
        icon   = _ICONS.get(level, "•")
        ts     = time.strftime("%H:%M:%S", time.localtime(record.created))
        module = f"{record.name:<18}"
        return self.FMT.format(
            time=Fore.WHITE + Style.DIM + ts,
            icon=colour + icon,
            colour=colour,
            level=level,
            reset=Style.RESET_ALL,
            dim=Style.DIM,
            module=module,
            msg=record.getMessage(),
        )


class _JSONFormatter(logging.Formatter):
    """Machine-readable JSON log line (for SIEM / log aggregators)."""
    def format(self, record: logging.LogRecord) -> str:
        payload = {
            "ts":      int(record.created * 1000),
            "level":   record.levelname,
            "module":  record.name,
            "msg":     record.getMessage(),
        }
        if record.exc_info:
            payload["exception"] = self.formatException(record.exc_info)
        return json.dumps(payload)


class Logger:
    """
    Per-module logger wrapper.

    Usage::
        log = Logger("PassiveRecon")
        log.info("Starting scan")
        log.finding("SQLi found", severity="Critical", url="https://...")
    """

    _root_configured = False
    _root_logger     = logging.getLogger("nexsus")

    def __init__(self, module_name: str = "Core", level: str = "INFO"):
        self._module = module_name
        self._log    = logging.getLogger(f"nexsus.{module_name}")
        if not Logger._root_configured:
            Logger._configure_root(level)

    # ── Root setup (runs once) ─────────────────────────────────────────────────
    @staticmethod
    def _configure_root(level: str):
        from nexsus.config import Config
        root = Logger._root_logger
        root.setLevel(logging.DEBUG)  # let handlers filter

        numeric = getattr(logging, level.upper(), logging.INFO)

        # Console handler
        ch = logging.StreamHandler(sys.stdout)
        ch.setLevel(numeric)
        ch.setFormatter(_ColourFormatter())
        root.addHandler(ch)

        # Rotating file handler (plain text)
        try:
            log_path = Path(Config.LOG_FILE)
            log_path.parent.mkdir(parents=True, exist_ok=True)
            fh = logging.handlers.RotatingFileHandler(
                log_path,
                maxBytes=Config.LOG_MAX_BYTES,
                backupCount=Config.LOG_BACKUP_COUNT,
                encoding="utf-8",
            )
            fh.setLevel(logging.DEBUG)
            fh.setFormatter(logging.Formatter(
                "%(asctime)s  %(levelname)-8s  %(name)-25s  %(message)s"
            ))
            root.addHandler(fh)

            # JSON file handler for SIEM
            jh = logging.handlers.RotatingFileHandler(
                str(log_path).replace(".log", ".jsonl"),
                maxBytes=Config.LOG_MAX_BYTES,
                backupCount=2,
                encoding="utf-8",
            )
            jh.setLevel(logging.INFO)
            jh.setFormatter(_JSONFormatter())
            root.addHandler(jh)
        except Exception:
            pass  # filesystem not available during tests

        Logger._root_configured = True

    # ── Public API ─────────────────────────────────────────────────────────────
    def debug(self, msg: str, **kw):
        self._log.debug(self._format(msg, kw))

    def info(self, msg: str, **kw):
        self._log.info(self._format(msg, kw))

    def success(self, msg: str, **kw):
        self._log.log(SUCCESS_LEVEL, self._format(msg, kw))

    def warning(self, msg: str, **kw):
        self._log.warning(self._format(msg, kw))

    def error(self, msg: str, **kw):
        self._log.error(self._format(msg, kw))

    def critical(self, msg: str, **kw):
        self._log.critical(self._format(msg, kw))

    def finding(self, msg: str, severity: str = "Medium", **kw):
        """Log a confirmed vulnerability finding."""
        prefix = f"[{severity.upper()}] "
        self._log.log(FINDING_LEVEL, self._format(prefix + msg, kw))

    def exception(self, msg: str, **kw):
        self._log.exception(self._format(msg, kw))

    @staticmethod
    def _format(msg: str, extras: dict) -> str:
        if not extras:
            return msg
        parts = "  ".join(f"{k}={v!r}" for k, v in extras.items())
        return f"{msg}  |  {parts}"

    def set_level(self, level: str):
        numeric = getattr(logging, level.upper(), logging.INFO)
        self._log.setLevel(numeric)

    def child(self, sub_module: str) -> "Logger":
        """Return a child logger scoped to a sub-module."""
        return Logger(f"{self._module}.{sub_module}")
