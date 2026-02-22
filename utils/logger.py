"""
nexsus/core/logger.py  (also used as nexsus/utils/logger.py)
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
Unified colourised logger with:
  • Custom severity levels: SUCCESS, FINDING, PROGRESS
  • Triple output: console (coloured), rotating file, JSONL for SIEM
  • Per-module named loggers with hierarchical namespacing
  • Structured extras: log.finding(msg, severity="High", url="...")
  • Thread/async safe
"""
import json
import logging
import logging.handlers
import sys
import time
from datetime import datetime
from pathlib import Path

try:
    from colorama import Fore, Style, init as _cinit
    _cinit(autoreset=True)
    _HAS_COLOR = True
except ImportError:
    class _Stub:
        def __getattr__(self, _): return ""
    Fore = Style = _Stub()
    _HAS_COLOR = False

try:
    from nexsus.config import Config
    _LOG_DIR  = Path(Config.LOG_DIR)
    _LOG_FILE = _LOG_DIR / "nexsus.log"
    _JSONL    = _LOG_DIR / "nexsus.jsonl"
except Exception:
    _LOG_DIR  = Path("/tmp/nexsus/logs")
    _LOG_FILE = _LOG_DIR / "nexsus.log"
    _JSONL    = _LOG_DIR / "nexsus.jsonl"

# ── Custom levels ─────────────────────────────────────────────────────────────
SUCCESS_LEVEL  = 25
FINDING_LEVEL  = 26
PROGRESS_LEVEL = 15

logging.addLevelName(SUCCESS_LEVEL,  "SUCCESS")
logging.addLevelName(FINDING_LEVEL,  "FINDING")
logging.addLevelName(PROGRESS_LEVEL, "PROGRESS")

# ── Colour map ────────────────────────────────────────────────────────────────
_COLORS: dict[str, str] = {
    "PROGRESS": Fore.MAGENTA,
    "DEBUG":    Fore.CYAN,
    "INFO":     Fore.WHITE,
    "SUCCESS":  Fore.GREEN + Style.BRIGHT,
    "WARNING":  Fore.YELLOW + Style.BRIGHT,
    "FINDING":  Fore.RED + Style.BRIGHT,
    "ERROR":    Fore.RED,
    "CRITICAL": Fore.RED + Style.BRIGHT,
}

_ICONS: dict[str, str] = {
    "PROGRESS": "↻", "DEBUG": "·", "INFO": "ℹ",
    "SUCCESS":  "✔", "WARNING": "⚠", "FINDING": "⚡",
    "ERROR":    "✖", "CRITICAL": "☠",
}

# ── JSONL handler ─────────────────────────────────────────────────────────────

class _JSONLHandler(logging.FileHandler):
    def emit(self, record: logging.LogRecord):
        try:
            payload = {
                "ts":      datetime.utcnow().isoformat() + "Z",
                "level":   record.levelname,
                "logger":  record.name,
                "message": record.getMessage(),
            }
            # Attach structured extras
            for key in ("severity", "url", "vuln_type", "module"):
                if hasattr(record, key):
                    payload[key] = getattr(record, key)
            self.stream.write(json.dumps(payload) + "\n")
            self.stream.flush()
        except Exception:
            pass


# ── Global root setup (once) ──────────────────────────────────────────────────

_root_ready = False

def _setup_root():
    global _root_ready
    if _root_ready:
        return
    _root_ready = True

    root = logging.getLogger("nexsus")
    root.setLevel(logging.DEBUG)
    if root.handlers:
        return

    # Rotating file handler
    try:
        _LOG_DIR.mkdir(parents=True, exist_ok=True)
        fh = logging.handlers.RotatingFileHandler(
            _LOG_FILE, maxBytes=10 * 1024 * 1024, backupCount=5, encoding="utf-8"
        )
        fh.setLevel(logging.DEBUG)
        fh.setFormatter(logging.Formatter(
            "%(asctime)s  %(levelname)-8s  [%(name)s]  %(message)s"
        ))
        root.addHandler(fh)
    except Exception:
        pass

    # JSONL handler
    try:
        jh = _JSONLHandler(_JSONL, encoding="utf-8")
        jh.setLevel(SUCCESS_LEVEL)
        root.addHandler(jh)
    except Exception:
        pass


# ── Logger class ──────────────────────────────────────────────────────────────

class Logger:
    """
    Named, colourised logger for a Nexsus module.

    Usage::
        log = Logger("PassiveRecon")
        log.info("Scanning 10 domains…")
        log.finding("SQLi found", severity="Critical", url="https://target.com/api")
        log.success("Done!")
    """

    def __init__(self, name: str = "nexsus", level: str = "DEBUG"):
        _setup_root()
        self._name    = name
        self._log     = logging.getLogger(f"nexsus.{name}")
        self._log.setLevel(getattr(logging, level.upper(), logging.DEBUG))

    # ── Core emit ─────────────────────────────────────────────────────────────

    def _emit(self, level_no: int, level_name: str, msg: str, **extras):
        colour = _COLORS.get(level_name, "")
        icon   = _ICONS.get(level_name, " ")
        ts     = datetime.now().strftime("%H:%M:%S")
        reset  = Style.RESET_ALL if _HAS_COLOR else ""
        print(f"{colour}{icon} [{ts}][{self._name}] {msg}{reset}", flush=True)

        record = self._log.makeRecord(
            self._log.name, level_no, "(nexsus)", 0,
            msg, args=(), exc_info=None,
        )
        for k, v in extras.items():
            setattr(record, k, v)
        self._log.handle(record)

    # ── Public API ─────────────────────────────────────────────────────────────

    def debug(self, msg: str, **extras):
        self._emit(logging.DEBUG, "DEBUG", msg, **extras)

    def info(self, msg: str, **extras):
        self._emit(logging.INFO, "INFO", msg, **extras)

    def success(self, msg: str, **extras):
        self._emit(SUCCESS_LEVEL, "SUCCESS", msg, **extras)

    def warning(self, msg: str, **extras):
        self._emit(logging.WARNING, "WARNING", msg, **extras)

    def error(self, msg: str, **extras):
        self._emit(logging.ERROR, "ERROR", msg, **extras)

    def critical(self, msg: str, **extras):
        self._emit(logging.CRITICAL, "CRITICAL", msg, **extras)

    def progress(self, msg: str, **extras):
        self._emit(PROGRESS_LEVEL, "PROGRESS", msg, **extras)

    def finding(self, msg: str, severity: str = "Medium", **extras):
        """Log a confirmed vulnerability finding (always written to JSONL)."""
        self._emit(FINDING_LEVEL, "FINDING", f"[{severity.upper()}] {msg}",
                   severity=severity, **extras)

    def exception(self, msg: str, **extras):
        self._log.exception(msg, **extras)

    def child(self, sub: str) -> "Logger":
        return Logger(f"{self._name}.{sub}")

    def set_level(self, level: str):
        self._log.setLevel(getattr(logging, level.upper(), logging.DEBUG))

    # Legacy compat
    def log(self, level, msg, **kw):
        self._emit(level, logging.getLevelName(level), str(msg), **kw)


__all__ = ["Logger", "SUCCESS_LEVEL", "FINDING_LEVEL", "PROGRESS_LEVEL"]
