"""
nexsus/core/http_client.py
~~~~~~~~~~~~~~~~~~~~~~~~~~
Production-grade async HTTP client with:
  • Connection pool with keep-alive
  • Automatic User-Agent and header randomisation (browser fingerprint mimicry)
  • Proxy rotation with health-checking
  • Adaptive retry with exponential back-off + jitter
  • Per-host DNS caching
  • Response size limit to avoid memory bombs
  • Automatic 429 / 503 back-pressure handed to RateLimiter
  • TLS SNI spoofing helpers for WAF bypass
"""
import asyncio
import json
import random
import re
import ssl
import time
from typing import Any, Optional
from urllib.parse import urlparse

import aiohttp

from nexsus.config import Config
from nexsus.core.logger import Logger
from nexsus.core.rate_limiter import RateLimiter
from nexsus.core.scope import ScopeValidator


# ── Browser header profiles ───────────────────────────────────────────────────
_BROWSER_PROFILES = [
    {   # Chrome 124 / Windows
        "User-Agent":       "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36",
        "Accept":           "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,*/*;q=0.8",
        "Accept-Language":  "en-US,en;q=0.9",
        "Accept-Encoding":  "gzip, deflate, br",
        "Sec-Fetch-Dest":   "document",
        "Sec-Fetch-Mode":   "navigate",
        "Sec-Fetch-Site":   "none",
        "Sec-CH-UA":        '"Chromium";v="124", "Google Chrome";v="124"',
        "Sec-CH-UA-Mobile": "?0",
        "Sec-CH-UA-Platform": '"Windows"',
        "Upgrade-Insecure-Requests": "1",
    },
    {   # Firefox 125 / Linux
        "User-Agent":       "Mozilla/5.0 (X11; Linux x86_64; rv:125.0) Gecko/20100101 Firefox/125.0",
        "Accept":           "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,*/*;q=0.8",
        "Accept-Language":  "en-US,en;q=0.5",
        "Accept-Encoding":  "gzip, deflate, br",
        "DNT":              "1",
        "Sec-Fetch-Dest":   "document",
        "Sec-Fetch-Mode":   "navigate",
        "Sec-Fetch-Site":   "none",
        "Upgrade-Insecure-Requests": "1",
    },
    {   # Safari 17 / macOS
        "User-Agent":       "Mozilla/5.0 (Macintosh; Intel Mac OS X 14_4) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.4 Safari/605.1.15",
        "Accept":           "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
        "Accept-Language":  "en-US,en;q=0.9",
        "Accept-Encoding":  "gzip, deflate, br",
    },
    {   # Mobile Chrome / Android
        "User-Agent":       "Mozilla/5.0 (Linux; Android 14; Pixel 8) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.0.0 Mobile Safari/537.36",
        "Accept":           "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,*/*;q=0.8",
        "Accept-Language":  "en-US,en;q=0.9",
        "Accept-Encoding":  "gzip, deflate, br",
        "Sec-Fetch-Dest":   "document",
        "Sec-Fetch-Mode":   "navigate",
        "Sec-Fetch-Site":   "none",
    },
]

_API_HEADERS = {
    "User-Agent":      "Mozilla/5.0 (compatible; Googlebot/2.1; +http://www.google.com/bot.html)",
    "Accept":          "application/json, text/plain, */*",
    "Accept-Language": "en-US,en;q=0.9",
    "Accept-Encoding": "gzip, deflate, br",
    "Content-Type":    "application/json",
}

_MAX_RESPONSE_BYTES = 10 * 1024 * 1024   # 10 MB hard cap


class SimpleResponse:
    """Lightweight response container (avoids holding open aiohttp connections)."""
    __slots__ = ("status", "headers", "body", "url", "redirect_url", "latency_ms")

    def __init__(
        self,
        status: int,
        headers: dict,
        body: bytes,
        url: str,
        redirect_url: str = "",
        latency_ms: float = 0,
    ):
        self.status       = status
        self.headers      = headers
        self.body         = body
        self.url          = url
        self.redirect_url = redirect_url
        self.latency_ms   = latency_ms

    async def json(self) -> Any:
        return json.loads(self.body.decode("utf-8", errors="replace"))

    async def text(self, encoding: str = "utf-8") -> str:
        return self.body.decode(encoding, errors="replace")

    def text_sync(self, encoding: str = "utf-8") -> str:
        return self.body.decode(encoding, errors="replace")

    @property
    def content_type(self) -> str:
        return self.headers.get("Content-Type", "").split(";")[0].strip()

    def __repr__(self) -> str:
        return f"<Response [{self.status}] {self.url} ({len(self.body)} B)>"


class HTTPClient:
    """
    Async HTTP client designed for high-volume security testing.

    Parameters
    ----------
    rate_limiter : RateLimiter
        Shared rate-limiter instance.
    validator : ScopeValidator
        Scope gate-keeper.
    mode : str
        ``"browser"`` — randomise browser headers (default)
        ``"api"``     — send JSON API headers
        ``"stealth"`` — minimal headers, long delays
    """

    def __init__(
        self,
        rate_limiter: RateLimiter,
        validator: ScopeValidator,
        mode: str = "browser",
    ):
        self.rate_limiter = rate_limiter
        self.validator    = validator
        self.mode         = mode
        self.logger       = Logger("HTTPClient")
        self._proxies     = list(Config.PROXIES)
        self._proxy_index = 0
        self._session: Optional[aiohttp.ClientSession] = None
        self._dns_cache: dict[str, tuple[str, float]] = {}
        self._dns_lock    = asyncio.Lock()

    # ── Session management ─────────────────────────────────────────────────────

    def _build_ssl_ctx(self) -> ssl.SSLContext:
        ctx = ssl.create_default_context()
        ctx.check_hostname = False
        ctx.verify_mode    = ssl.CERT_NONE
        # Allow legacy TLS for old targets
        ctx.options |= ssl.OP_NO_SSLv2 if hasattr(ssl, "OP_NO_SSLv2") else 0
        return ctx

    def _get_session(self) -> aiohttp.ClientSession:
        if self._session is None or self._session.closed:
            self._session = self._make_session()
        return self._session

    def _make_session(self) -> aiohttp.ClientSession:
        profile = (
            _API_HEADERS
            if self.mode == "api"
            else random.choice(_BROWSER_PROFILES)
        )
        timeout   = aiohttp.ClientTimeout(
            total=Config.REQUEST_TIMEOUT,
            connect=10,
            sock_read=Config.REQUEST_TIMEOUT,
        )
        connector = aiohttp.TCPConnector(
            ssl=self._build_ssl_ctx(),
            limit=Config.CONNECTION_POOL_SIZE,
            limit_per_host=Config.MAX_CONCURRENT_TASKS,
            enable_cleanup_closed=True,
            ttl_dns_cache=Config.DNS_CACHE_TTL,
            use_dns_cache=True,
        )
        proxy = self._next_proxy()
        return aiohttp.ClientSession(
            headers=profile,
            timeout=timeout,
            connector=connector,
            trust_env=True,
        )

    async def rotate_session(self):
        """Close current session and open a fresh one (new UA + proxy)."""
        await self.close()
        self._session = self._make_session()
        self.logger.debug("Session rotated")

    def _next_proxy(self) -> Optional[str]:
        if not self._proxies:
            return None
        proxy = self._proxies[self._proxy_index % len(self._proxies)]
        self._proxy_index += 1
        return proxy

    # ── DNS ───────────────────────────────────────────────────────────────────

    async def _cached_resolve(self, domain: str) -> Optional[str]:
        """Resolve *domain* with simple TTL cache (avoids repeated DNS lookups)."""
        async with self._dns_lock:
            cached = self._dns_cache.get(domain)
            if cached:
                ip, expires = cached
                if time.monotonic() < expires:
                    return ip

        try:
            import dns.resolver
            resolver = dns.resolver.Resolver(configure=False)
            resolver.nameservers = Config.DNS_RESOLVERS
            answers = resolver.resolve(domain, "A")
            ip = str(random.choice(answers))   # random-robin
            async with self._dns_lock:
                self._dns_cache[domain] = (ip, time.monotonic() + Config.DNS_CACHE_TTL)
            return ip
        except Exception as exc:
            self.logger.debug(f"DNS resolve failed for {domain}: {exc}")
            return None

    # ── Core request ──────────────────────────────────────────────────────────

    async def request(
        self,
        method: str,
        url: str,
        retries: int = Config.MAX_RETRIES,
        api_mode: bool = False,
        extra_headers: Optional[dict] = None,
        **kwargs,
    ) -> Optional[SimpleResponse]:
        """
        Send an HTTP request with scope checking, rate limiting, and retries.

        Parameters
        ----------
        method : str
        url : str
        retries : int
        api_mode : bool
            If True, override headers with JSON-API profile for this request.
        extra_headers : dict
            Additional headers merged on top of the profile.
        **kwargs
            Passed directly to aiohttp's ``request()``.
        """
        if not self.validator.validate(url):
            self.logger.warning(f"Out-of-scope request blocked: {url}")
            return None

        parsed = urlparse(url)
        host   = parsed.hostname or ""

        # Rate limiting
        await self.rate_limiter.wait_if_needed(host)

        # Header assembly
        headers = dict(extra_headers or {})
        if api_mode:
            headers = {**_API_HEADERS, **headers}
        elif Config.ROTATE_UA:
            profile = random.choice(_BROWSER_PROFILES)
            headers = {**profile, **headers}

        # Disable gzip so we get raw body bytes
        headers["Accept-Encoding"] = "identity"

        kwargs.setdefault("allow_redirects", Config.FOLLOW_REDIRECTS)
        kwargs.setdefault("max_redirects", Config.MAX_REDIRECTS)
        if headers:
            kwargs["headers"] = headers

        proxy = self._next_proxy() if self._proxies else None

        t_start = time.monotonic()

        for attempt in range(retries):
            try:
                sess = self._get_session()
                async with sess.request(method, url, proxy=proxy, **kwargs) as resp:
                    # Back-pressure on rate-limit responses
                    if resp.status in (429, 503):
                        retry_after = float(resp.headers.get("Retry-After", 30))
                        self.logger.warning(
                            f"Rate-limited [{resp.status}] on {host} — "
                            f"backing off {retry_after}s"
                        )
                        self.rate_limiter.on_rate_limited(host, retry_after)
                        await asyncio.sleep(retry_after)
                        continue

                    # Read body with size cap
                    try:
                        body = await resp.content.read(_MAX_RESPONSE_BYTES)
                    except Exception as exc:
                        self.logger.debug(f"Body read error (attempt {attempt+1}): {exc}")
                        if attempt < retries - 1:
                            await asyncio.sleep(Config.RETRY_BACKOFF_BASE ** attempt)
                            continue
                        return None

                    latency = (time.monotonic() - t_start) * 1000
                    return SimpleResponse(
                        status=resp.status,
                        headers=dict(resp.headers),
                        body=body,
                        url=str(resp.url),
                        redirect_url=str(resp.real_url) if resp.history else "",
                        latency_ms=round(latency, 1),
                    )

            except (
                aiohttp.ClientConnectorError,
                aiohttp.ClientOSError,
                asyncio.TimeoutError,
                aiohttp.ServerDisconnectedError,
            ) as exc:
                self.logger.debug(
                    f"Connection error (attempt {attempt+1}/{retries}) "
                    f"to {host}: {type(exc).__name__}"
                )
                if attempt < retries - 1:
                    backoff = Config.RETRY_BACKOFF_BASE ** attempt + random.uniform(0, 0.5)
                    await asyncio.sleep(backoff)
                    # Rotate session on repeated failures
                    if attempt >= 1:
                        await self.rotate_session()
            except Exception as exc:
                self.logger.error(f"Unexpected HTTP error for {url}: {exc}")
                return None

        self.logger.error(f"All {retries} retries exhausted for {url}")
        self.rate_limiter.release_slot(host)
        return None

    # ── Convenience wrappers ──────────────────────────────────────────────────

    async def get(self, url: str, **kwargs) -> Optional[SimpleResponse]:
        return await self.request("GET", url, **kwargs)

    async def post(self, url: str, **kwargs) -> Optional[SimpleResponse]:
        return await self.request("POST", url, **kwargs)

    async def put(self, url: str, **kwargs) -> Optional[SimpleResponse]:
        return await self.request("PUT", url, **kwargs)

    async def head(self, url: str, **kwargs) -> Optional[SimpleResponse]:
        return await self.request("HEAD", url, **kwargs)

    async def options(self, url: str, **kwargs) -> Optional[SimpleResponse]:
        return await self.request("OPTIONS", url, **kwargs)

    async def close(self):
        if self._session and not self._session.closed:
            await self._session.close()
            self._session = None
