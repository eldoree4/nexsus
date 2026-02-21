"""
nexsus/core/wordlist_manager.py
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
Smart wordlist manager with:
  • Lazy loading (large files only loaded when needed)
  • Bundled high-quality defaults (no external download required)
  • Custom user-supplied wordlists merged at runtime
  • Technology-aware lists (e.g. PHP paths when PHP detected)
  • Wordlist generation (date-based, company-based passwords)
  • Deduplication and sorting by frequency score
"""
import os
import re
from functools import lru_cache
from pathlib import Path
from typing import Optional

from nexsus.config import Config

# ── Bundled defaults ──────────────────────────────────────────────────────────

_DEFAULTS: dict[str, list[str]] = {

    "subdomains": [
        "www", "api", "app", "admin", "mail", "smtp", "pop", "imap",
        "vpn", "remote", "citrix", "owa", "portal", "webmail", "cdn",
        "static", "media", "img", "images", "assets", "upload", "uploads",
        "dev", "staging", "test", "beta", "alpha", "demo", "sandbox",
        "blog", "shop", "store", "pay", "payment", "secure", "ssl",
        "m", "mobile", "wap", "gateway", "ns1", "ns2", "dns",
        "ftp", "sftp", "ssh", "monitor", "status", "health",
        "api-v1", "api-v2", "api-v3", "v1", "v2", "v3",
        "graphql", "rest", "soap", "ws", "websocket",
        "auth", "oauth", "sso", "login", "signup",
        "dashboard", "panel", "cpanel", "phpmyadmin", "wp-admin",
        "jira", "confluence", "jenkins", "gitlab", "github",
        "internal", "intranet", "corp", "office", "corporate",
        "backup", "bak", "old", "legacy", "archive",
        "support", "help", "ticket", "helpdesk",
        "analytics", "tracking", "metrics", "logs",
        "db", "database", "mysql", "postgres", "redis", "mongo",
        "kafka", "rabbit", "queue", "worker", "scheduler",
        "s3", "blob", "storage", "files", "content",
        "preview", "uat", "qa", "ci", "cd",
    ],

    "directories": [
        # Common web paths
        "admin", "administrator", "admin.php", "admin/login",
        "wp-admin", "wp-login.php", "wp-content", "wp-includes",
        "login", "signin", "auth", "oauth", "callback",
        "api", "api/v1", "api/v2", "api/v3", "graphql", "rest",
        "dashboard", "panel", "manage", "management", "control",
        "backend", "backoffice", "internal", "private",
        "upload", "uploads", "media", "static", "assets", "files",
        "images", "img", "css", "js", "fonts",
        "backup", "bak", ".bak", "old", "archive",
        "test", "testing", "dev", "debug",
        # Config / sensitive files
        ".env", ".env.local", ".env.production", ".env.backup",
        "config", "config.php", "config.json", "config.yaml",
        "settings.py", "settings.php", "web.config", "app.config",
        "database.yml", "database.php",
        # CI/CD / deployment artefacts
        ".git", ".git/config", ".git/HEAD",
        ".svn", ".hg", ".DS_Store",
        "Dockerfile", "docker-compose.yml",
        ".github", ".gitlab-ci.yml", "Jenkinsfile",
        # Server status
        "server-status", "server-info", "phpinfo.php", "info.php",
        "status", "health", "healthz", "ping",
        "actuator", "actuator/env", "actuator/health",
        "metrics", "prometheus", "monitoring",
        # PHP common
        "phpmyadmin", "pma", "dbadmin", "adminer", "adminer.php",
        # Java Spring
        "actuator/beans", "actuator/mappings", "actuator/configprops",
        "actuator/httptrace", "actuator/loggers",
        # Python Django
        "django-admin", "__debug__",
        # Node / Express
        "node_modules", "package.json", "package-lock.json",
        # Documentation
        "swagger", "swagger-ui", "swagger-ui.html",
        "api-docs", "api-doc", "openapi.json", "openapi.yaml",
        "redoc", "docs", "documentation",
        # Cloud
        "aws", "azure", ".aws", "credentials",
        "terraform", ".terraform",
    ],

    "files": [
        # Generic
        "robots.txt", "sitemap.xml", "humans.txt", "security.txt",
        ".well-known/security.txt", ".well-known/openid-configuration",
        "crossdomain.xml", "clientaccesspolicy.xml",
        # Env / config
        ".env", ".env.bak", ".env.old", ".env.local", ".env.example",
        ".htaccess", ".htpasswd", "web.config",
        "config.json", "config.yaml", "config.yml",
        "appsettings.json", "appsettings.Development.json",
        "application.properties", "application.yml",
        # Source control
        ".git/config", ".gitignore", ".gitmodules",
        ".svn/entries",
        # Backup / temp
        "backup.zip", "backup.tar.gz", "backup.sql",
        "db.sql", "database.sql", "dump.sql",
        "site.zip", "www.zip",
        "index.php.bak", "config.php.bak",
        # PHP
        "phpinfo.php", "info.php", "test.php", "shell.php",
        "adminer.php", "upload.php",
        # Keys / certs
        "id_rsa", "id_rsa.pub", "private.key", "server.key",
        "*.pem", "*.crt", "*.p12",
        # Logs
        "error.log", "access.log", "debug.log", "app.log",
        # Package files (code disclosure)
        "package.json", "composer.json", "Gemfile", "requirements.txt",
        "Pipfile", "go.mod", "cargo.toml",
    ],

    "parameters": [
        # Injection-prone
        "id", "user", "username", "email", "password",
        "page", "p", "pg", "num", "limit", "offset", "start",
        "file", "path", "dir", "folder",
        "url", "uri", "link", "href", "src", "target", "next",
        "return", "return_url", "redirect", "redirect_to", "redir",
        "continue", "destination", "callback",
        "q", "query", "search", "s", "term", "keyword",
        "token", "key", "api_key", "apikey", "secret", "code",
        "lang", "language", "locale", "l",
        "format", "type", "output", "view", "template",
        "order", "sort", "orderby", "order_by", "sortby",
        "filter", "category", "tag", "label",
        "action", "cmd", "command", "exec", "execute",
        "data", "payload", "body", "content",
        "debug", "test", "dev",
        # API specific
        "fields", "select", "include", "expand",
        "access_token", "refresh_token", "auth_token",
        "session", "sid", "ssid",
        # IDOR / object reference
        "uid", "account_id", "account", "profile_id",
        "order_id", "invoice_id", "ticket_id", "doc_id",
        "message_id", "chat_id", "room_id", "group_id",
    ],

    "api_routes": [
        # REST patterns
        "/api/users", "/api/users/1", "/api/user/1",
        "/api/admin", "/api/admin/users",
        "/api/v1/users", "/api/v2/users", "/api/v3/users",
        "/api/auth/login", "/api/auth/register", "/api/auth/token",
        "/api/auth/refresh", "/api/auth/logout",
        "/api/profile", "/api/account", "/api/settings",
        "/api/orders", "/api/products", "/api/items",
        "/api/payments", "/api/invoices", "/api/billing",
        "/api/admin/settings", "/api/admin/logs",
        # GraphQL
        "/graphql", "/api/graphql", "/v1/graphql",
        # Health checks
        "/health", "/healthz", "/health/live", "/health/ready",
        "/actuator/health", "/actuator/info",
        "/ping", "/status",
        # Internal / debug
        "/debug", "/debug/vars", "/debug/pprof",
        "/internal/api", "/private/api",
    ],

    "passwords": [
        # Common defaults
        "admin", "admin123", "administrator", "password", "password1",
        "123456", "12345678", "1234567890", "qwerty", "abc123",
        "letmein", "welcome", "monkey", "dragon", "master",
        "root", "toor", "test", "guest", "user",
        "changeme", "default", "blank", "",
        "admin@123", "Admin123!", "P@ssw0rd", "P@$$w0rd",
        "Passw0rd!", "Password123!", "Welcome1",
        # Seasonal
        "Winter2024!", "Spring2024!", "Summer2024!", "Fall2024!",
        "Winter2025!", "Spring2025!",
    ],
}

# Technology-specific extra wordlists added when tech is detected
_TECH_EXTRAS: dict[str, dict[str, list[str]]] = {
    "wordpress": {
        "directories": [
            "wp-admin", "wp-login.php", "wp-config.php",
            "wp-content/uploads", "wp-content/plugins",
            "wp-content/themes", "xmlrpc.php", "wp-cron.php",
        ],
    },
    "django": {
        "directories": ["admin/", "admin/login/", "__debug__/", "api/schema/"],
        "files": ["settings.py", "urls.py", "wsgi.py", "manage.py"],
    },
    "spring": {
        "directories": [
            "actuator", "actuator/env", "actuator/beans",
            "actuator/mappings", "actuator/httptrace",
            "actuator/logfile", "actuator/configprops",
        ],
    },
    "laravel": {
        "files": [".env", "artisan", "public/index.php", "storage/logs/laravel.log"],
        "directories": ["telescope", "horizon", "nova"],
    },
    "nodejs": {
        "files": ["package.json", ".env", "config.js", "app.js", "server.js"],
        "directories": ["node_modules", ".well-known"],
    },
}


class WordlistManager:
    """
    Lazy-loading wordlist manager.

    Usage::
        wm = WordlistManager()
        subs = wm.get('subdomains')
        wm.apply_tech('wordpress')
    """

    def __init__(self):
        self._lists: dict[str, list[str]] = {}
        self._loaded: set[str] = set()

    # ── Public API ─────────────────────────────────────────────────────────────

    def get(self, name: str, limit: Optional[int] = None) -> list[str]:
        """Return wordlist by *name*, loading from disk or defaults."""
        if name not in self._loaded:
            self._load(name)
        result = self._lists.get(name, [])
        return result[:limit] if limit else result

    def apply_tech(self, tech: str):
        """
        Merge technology-specific entries into the relevant wordlists.
        Call when a target technology is identified.
        """
        extras = _TECH_EXTRAS.get(tech.lower(), {})
        for list_name, words in extras.items():
            existing = set(self._lists.get(list_name, []))
            new_words = [w for w in words if w not in existing]
            self._lists.setdefault(list_name, []).extend(new_words)

    def merge(self, name: str, words: list[str]):
        """Merge extra words into an existing wordlist (deduped)."""
        existing = set(self._lists.get(name, []))
        self._lists.setdefault(name, []).extend(
            w for w in words if w not in existing
        )

    def generate_company_passwords(self, company: str, year: int = 2025) -> list[str]:
        """
        Generate company-contextual passwords for password-spray attacks.
        e.g. company='Acme' → ['Acme2025!', 'Acme123', ...]
        """
        c = company.strip()
        suffixes = ["!", "@", "#", "123", "1234", "12345", "123!",
                    f"{year}", f"{year}!", f"{year}@",
                    f"{year-1}", f"{year-1}!"]
        base = [c, c.lower(), c.upper(), c.capitalize()]
        passwords = []
        for b in base:
            for s in suffixes:
                passwords.append(b + s)
        # Add defaults too
        passwords.extend(_DEFAULTS["passwords"])
        return list(dict.fromkeys(passwords))   # dedup

    def available(self) -> list[str]:
        return list(_DEFAULTS.keys())

    # ── Loading ────────────────────────────────────────────────────────────────

    def _load(self, name: str):
        self._loaded.add(name)
        # Try file on disk first
        candidates = [
            Config.WORDLISTS_DIR / f"{name}.txt",
            Path(__file__).parent.parent / "wordlists" / f"{name}.txt",
        ]
        for path in candidates:
            if Path(path).exists():
                try:
                    with open(path, encoding="utf-8", errors="ignore") as fh:
                        words = [
                            l.strip() for l in fh
                            if l.strip() and not l.startswith("#")
                        ]
                    self._lists[name] = list(dict.fromkeys(words))
                    return
                except Exception:
                    pass
        # Fall back to bundled defaults
        self._lists[name] = list(_DEFAULTS.get(name, []))
