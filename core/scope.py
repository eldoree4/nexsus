"""
nexsus/core/scope.py
~~~~~~~~~~~~~~~~~~~~
Scope management with:
  • Domains, wildcards, CIDR ranges, and explicit API endpoints
  • Regex-based URL exclusion patterns
  • Port-aware scope checking
  • Trusted third-party hosts for passive recon APIs
  • Thread-safe caching of scope decisions
"""
import ipaddress
import re
from functools import lru_cache
from urllib.parse import urlparse
from typing import Union


_TRUSTED_RECON_HOSTS = frozenset({
    # Certificate transparency / OSINT
    "crt.sh", "web.archive.org", "index.commoncrawl.org",
    "urlscan.io", "otx.alienvault.com", "shodan.io",
    "api.shodan.io", "censys.io", "search.censys.io",
    "www.virustotal.com", "api.github.com", "api.gitlab.com",
    # DNS resolvers used by HTTP client
    "dns.google", "1.1.1.1", "8.8.8.8", "9.9.9.9",
    # Notification / callback OOB servers
    "interact.sh", "burpcollaborator.net", "canarytokens.com",
})

# Protocols that we never want to follow into
_UNSAFE_SCHEMES = frozenset({"javascript", "data", "vbscript"})


class Scope:
    """
    Represents the authorised attack surface for a single engagement.

    Supports:
      - Exact domains          (``example.com``)
      - Wildcard domains       (``*.example.com``)
      - CIDR IP ranges         (``10.0.0.0/8``)
      - Explicit API prefixes  (``https://api.example.com/v2``)
      - Regex exclusions       (``/logout``, ``/admin/delete``)
    """

    def __init__(self):
        self.domains:          set[str]                = set()
        self.wildcard_domains: set[str]                = set()  # stored without '*.'
        self.ip_ranges:        list[ipaddress.IPv4Network | ipaddress.IPv6Network] = []
        self.api_endpoints:    set[str]                = set()
        self.excluded_patterns: list[re.Pattern]       = []
        self.allowed_ports:    set[int]                = {80, 443, 8080, 8443, 8000, 3000}
        self.notes:            str                     = ""

    # ── Population ─────────────────────────────────────────────────────────────

    def add_targets(self, targets: Union[list[str], str]):
        if isinstance(targets, str):
            targets = [targets]
        for raw in targets:
            t = raw.strip()
            if not t or t.startswith("#"):
                continue
            self._classify(t)
        self._is_in_scope_cached.cache_clear()

    def _classify(self, t: str):
        # Wildcard domain
        if t.startswith("*."):
            self.wildcard_domains.add(t[2:].lower())
            return
        # Full URL / API endpoint
        if re.match(r"^https?://", t, re.IGNORECASE):
            parsed = urlparse(t)
            if parsed.hostname:
                host = parsed.hostname.lower()
                self.domains.add(host)
                if parsed.path and parsed.path != "/":
                    self.api_endpoints.add(t.rstrip("/"))
                else:
                    self.api_endpoints.add(t.rstrip("/"))
            return
        # CIDR
        if re.match(r"[\d.:/]+", t) and ("/" in t or ":" in t):
            try:
                net = ipaddress.ip_network(t, strict=False)
                self.ip_ranges.append(net)
                return
            except ValueError:
                pass
        # Plain domain or IP
        try:
            ipaddress.ip_address(t)
            # Single IP → /32 or /128
            net = ipaddress.ip_network(t)
            self.ip_ranges.append(net)
        except ValueError:
            # Domain
            self.domains.add(t.lower().lstrip("www.") if False else t.lower())

    def add_exclusion(self, pattern: str):
        """Add a regex pattern; matching URLs will be excluded from scope."""
        self.excluded_patterns.append(re.compile(pattern, re.IGNORECASE))
        self._is_in_scope_cached.cache_clear()

    # ── Query ──────────────────────────────────────────────────────────────────

    def is_in_scope(self, url: str) -> bool:
        return self._is_in_scope_cached(url)

    @lru_cache(maxsize=4096)
    def _is_in_scope_cached(self, url: str) -> bool:
        try:
            parsed = urlparse(url)
        except Exception:
            return False

        # Reject unsafe schemes
        if parsed.scheme in _UNSAFE_SCHEMES:
            return False

        # Exclusions take priority
        for pat in self.excluded_patterns:
            if pat.search(url):
                return False

        host = (parsed.hostname or "").lower()
        if not host:
            return False

        # Port check (only if explicitly non-standard)
        port = parsed.port
        if port and port not in self.allowed_ports:
            return False

        # Exact domain
        if host in self.domains:
            return True

        # Wildcard
        for wc in self.wildcard_domains:
            if host == wc or host.endswith("." + wc):
                return True

        # IP ranges
        try:
            ip = ipaddress.ip_address(host)
            if any(ip in rng for rng in self.ip_ranges):
                return True
        except ValueError:
            pass

        # API prefix match
        for api in self.api_endpoints:
            if url.startswith(api):
                return True
            parsed_api = urlparse(api)
            if parsed_api.hostname and parsed_api.hostname.lower() == host:
                return True

        return False

    # ── Summary helpers ────────────────────────────────────────────────────────

    def summary(self) -> str:
        lines = []
        if self.domains:
            lines.append(f"Domains       : {', '.join(sorted(self.domains))}")
        if self.wildcard_domains:
            lines.append(f"Wildcards     : {', '.join('*.' + d for d in sorted(self.wildcard_domains))}")
        if self.ip_ranges:
            lines.append(f"IP Ranges     : {', '.join(str(r) for r in self.ip_ranges)}")
        if self.api_endpoints:
            lines.append(f"API Endpoints : {', '.join(sorted(self.api_endpoints))}")
        if self.excluded_patterns:
            lines.append(f"Exclusions    : {len(self.excluded_patterns)} pattern(s)")
        return "\n".join(lines) if lines else "  (empty scope)"

    def summary_short(self) -> str:
        parts = []
        if self.domains:          parts.append(f"{len(self.domains)} domain(s)")
        if self.wildcard_domains: parts.append(f"{len(self.wildcard_domains)} wildcard(s)")
        if self.ip_ranges:        parts.append(f"{len(self.ip_ranges)} CIDR(s)")
        if self.api_endpoints:    parts.append(f"{len(self.api_endpoints)} API(s)")
        return ", ".join(parts) if parts else "empty"

    def __repr__(self) -> str:
        return f"<Scope {self.summary_short()}>"


class ScopeValidator:
    """
    Gate-keeper used by the HTTP client to prevent out-of-scope requests.

    Trusted third-party hosts (crt.sh, Shodan, etc.) are always allowed
    regardless of the engagement scope.
    """

    def __init__(self, scope: Scope):
        self.scope = scope

    def validate(self, url: str) -> bool:
        try:
            host = urlparse(url).hostname or ""
        except Exception:
            return False
        if host in _TRUSTED_RECON_HOSTS:
            return True
        return self.scope.is_in_scope(url)

    def assert_in_scope(self, url: str):
        """Raise ValueError if *url* is out of scope."""
        if not self.validate(url):
            raise ValueError(f"Out-of-scope request blocked: {url}")
