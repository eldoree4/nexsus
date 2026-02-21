import os
import json
from pathlib import Path
from typing import Optional

class Config:
    # ─── Core Settings ────────────────────────────────────────────────────────
    VERSION = "2.3.0"
    TOOL_NAME = "Nexsus"

    # ─── Rate & Concurrency ───────────────────────────────────────────────────
    DEFAULT_RATE_LIMIT      = int(os.getenv("NEXSUS_RATE_LIMIT", 15))
    MAX_CONCURRENT_TASKS    = int(os.getenv("NEXSUS_CONCURRENCY", 30))
    REQUEST_TIMEOUT         = int(os.getenv("NEXSUS_TIMEOUT", 20))
    MAX_RETRIES             = int(os.getenv("NEXSUS_RETRIES", 3))
    RETRY_BACKOFF_BASE      = 1.5          # exponential back-off multiplier
    CONNECTION_POOL_SIZE    = 50           # TCP connections per host
    DNS_CACHE_TTL           = 300          # seconds

    # ─── HTTP Behaviour ────────────────────────────────────────────────────────
    USER_AGENT              = os.getenv(
        "NEXSUS_UA",
        "Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
        "AppleWebKit/537.36 (KHTML, like Gecko) "
        "Chrome/124.0.0.0 Safari/537.36"
    )
    ROTATE_UA               = True         # randomise UA per request
    FOLLOW_REDIRECTS        = True
    MAX_REDIRECTS           = 10
    VERIFY_SSL              = False        # disabled for pentest; flip for prod
    HTTP2_ENABLED           = True         # requires aiohttp-http2

    # ─── Proxy ────────────────────────────────────────────────────────────────
    PROXIES: list[str]      = [p for p in os.getenv("NEXSUS_PROXIES", "").split(",") if p]
    PROXY_ROTATE            = True         # rotate through proxy list

    # ─── Directories ──────────────────────────────────────────────────────────
    DATA_DIR                = Path(os.getenv("NEXSUS_DATA_DIR", Path.home() / ".nexsus"))
    REPORT_DIR              = DATA_DIR / "reports"
    WORDLISTS_DIR           = DATA_DIR / "wordlists"
    SCREENSHOTS_DIR         = DATA_DIR / "screenshots"
    CACHE_DIR               = DATA_DIR / "cache"
    DB_PATH                 = DATA_DIR / "nexsus.db"

    # ─── Logging ──────────────────────────────────────────────────────────────
    LOG_LEVEL               = os.getenv("NEXSUS_LOG_LEVEL", "INFO")
    LOG_FILE                = DATA_DIR / "nexsus.log"
    LOG_MAX_BYTES           = 10 * 1024 * 1024   # 10 MB
    LOG_BACKUP_COUNT        = 5

    # ─── Scanning Behaviour ───────────────────────────────────────────────────
    PASSIVE_ONLY            = False        # never send active probes
    STEALTHY_MODE           = False        # low-n-slow; halves rate limits
    DEEP_SCAN               = False        # exhaustive payloads; slower
    SMART_SCAN              = True         # ML-guided payload selection
    AUTO_WAF_DETECT         = True
    AUTO_BYPASS_WAF         = True

    # ─── Vulnerability Detection ──────────────────────────────────────────────
    VULN_TYPES_ENABLED: list[str] = [
        "sqli", "xss", "ssti", "ssrf", "lfi", "rce",
        "open_redirect", "cors", "idor", "jwt", "xxe",
        "nosqli", "ldapi", "path_traversal", "graphql",
        "csrf", "deserialization", "log4shell",
    ]
    CONFIRM_VULNS           = True         # double-check before reporting
    BLIND_VULN_CALLBACK     = os.getenv("NEXSUS_CALLBACK", "")   # OOB server

    # ─── Active Recon ─────────────────────────────────────────────────────────
    DNS_RESOLVERS: list[str] = ["8.8.8.8", "1.1.1.1", "9.9.9.9", "208.67.222.222"]
    SUBDOMAIN_BRUTEFORCE    = True
    PORT_SCAN_TOP_N         = 1000
    SCREENSHOT_ENABLED      = False        # requires selenium / playwright

    # ─── Reporting ────────────────────────────────────────────────────────────
    REPORT_FORMATS: list[str] = ["json", "html", "markdown"]
    CVSS_SCORING            = True
    DEDUP_FINDINGS          = True

    # ─── Profiles (override with load_profile) ────────────────────────────────
    PROFILES: dict = {
        "stealth": {
            "DEFAULT_RATE_LIMIT": 3,
            "MAX_CONCURRENT_TASKS": 5,
            "ROTATE_UA": True,
            "STEALTHY_MODE": True,
        },
        "aggressive": {
            "DEFAULT_RATE_LIMIT": 50,
            "MAX_CONCURRENT_TASKS": 80,
            "DEEP_SCAN": True,
        },
        "api": {
            "DEFAULT_RATE_LIMIT": 20,
            "VULN_TYPES_ENABLED": [
                "sqli", "xss", "ssti", "ssrf", "idor",
                "jwt", "cors", "graphql", "nosqli",
            ],
        },
    }

    # ─── Class Methods ────────────────────────────────────────────────────────
    @classmethod
    def init_dirs(cls):
        for d in [
            cls.DATA_DIR, cls.REPORT_DIR, cls.WORDLISTS_DIR,
            cls.SCREENSHOTS_DIR, cls.CACHE_DIR,
        ]:
            Path(d).mkdir(parents=True, exist_ok=True)

    @classmethod
    def load_profile(cls, profile_name: str):
        """Apply a named scan profile, overriding class attributes."""
        profile = cls.PROFILES.get(profile_name)
        if not profile:
            raise ValueError(f"Unknown profile '{profile_name}'. "
                             f"Available: {list(cls.PROFILES)}")
        for key, val in profile.items():
            setattr(cls, key, val)

    @classmethod
    def load_file(cls, path: str):
        """Load config from a JSON file and override class attributes."""
        with open(path) as fh:
            data = json.load(fh)
        for key, val in data.items():
            if hasattr(cls, key.upper()):
                setattr(cls, key.upper(), val)

    @classmethod
    def dump(cls) -> dict:
        """Return a serialisable snapshot of all settings."""
        skip = {"PROFILES"}
        return {
            k: (str(v) if isinstance(v, Path) else v)
            for k, v in vars(cls).items()
            if not k.startswith("_") and k.isupper() and k not in skip
        }
