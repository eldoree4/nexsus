"""
nexsus/core/http_client.py
~~~~~~~~~~~~~~~~~~~~~~~~~~~
Production-grade async HTTP client:
  • 4 rotating browser profiles (Chrome/Firefox/Safari/Mobile)
  • Full modern headers: Sec-Fetch-*, Sec-CH-UA-*, DNT, etc.
  • Custom DNS resolver with TTL cache & manual override (preserves SNI)
  • Per-host rate-limiting integration
  • Connection pool (50 connections, keep-alive)
  • Response size cap (10 MB)
  • Exponential backoff + jitter on retry
  • Session rotation on repeated failures
  • Extra-headers / api_mode / allow_redirects pass-through
  • Unified .get() / .post() / .request() API
"""
import asyncio
import json
import random
import socket
import ssl
import time
from typing import Optional
from urllib.parse import urlparse

import aiohttp
from aiohttp.abc import AbstractResolver

from nexsus.config import Config
from nexsus.core.logger import Logger

try:
    import dns.resolver as _dns_resolver
    DNSPYTHON = True
except ImportError:
    DNSPYTHON = False

# ── Browser profiles ──────────────────────────────────────────────────────────

_PROFILES = [
    # Chrome 124 / Windows
    {
        "User-Agent": (
            "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 "
            "(KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36"
        ),
        "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
        "Accept-Language": "en-US,en;q=0.9",
        "Accept-Encoding": "gzip, deflate, br",
        "Sec-Fetch-Dest":  "document",
        "Sec-Fetch-Mode":  "navigate",
        "Sec-Fetch-Site":  "none",
        "Sec-Fetch-User":  "?1",
        "Sec-CH-UA": '"Chromium";v="124", "Google Chrome";v="124", "Not-A.Brand";v="99"',
        "Sec-CH-UA-Mobile":   "?0",
        "Sec-CH-UA-Platform": '"Windows"',
        "DNT": "1",
        "Upgrade-Insecure-Requests": "1",
    },
    # Firefox 125 / Linux
    {
        "User-Agent": (
            "Mozilla/5.0 (X11; Linux x86_64; rv:125.0) Gecko/20100101 Firefox/125.0"
        ),
        "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,*/*;q=0.8",
        "Accept-Language": "en-US,en;q=0.5",
        "Accept-Encoding": "gzip, deflate, br",
        "Sec-Fetch-Dest":  "document",
        "Sec-Fetch-Mode":  "navigate",
        "Sec-Fetch-Site":  "none",
        "DNT": "1",
        "Upgrade-Insecure-Requests": "1",
    },
    # Safari 17 / macOS
    {
        "User-Agent": (
            "Mozilla/5.0 (Macintosh; Intel Mac OS X 14_4) "
            "AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.4 Safari/605.1.15"
        ),
        "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
        "Accept-Language": "en-US,en;q=0.9",
        "Accept-Encoding": "gzip, deflate, br",
    },
    # Mobile Chrome / Android
    {
        "User-Agent": (
            "Mozilla/5.0 (Linux; Android 14) AppleWebKit/537.36 "
            "(KHTML, like Gecko) Chrome/124.0.6367.82 Mobile Safari/537.36"
        ),
        "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
        "Accept-Language": "en-US,en;q=0.9",
        "Accept-Encoding": "gzip, deflate, br",
        "Sec-CH-UA-Mobile": "?1",
    },
]

_MAX_BODY = 10 * 1024 * 1024   # 10 MB hard cap


# ── Custom DNS resolver ────────────────────────────────────────────────────────

class _CustomResolver(AbstractResolver):
    """
    TTL-cached DNS resolver that preserves the original hostname for SNI.
    Supports manual overrides via Config.MANUAL_DNS.
    """

    def __init__(self):
        self._cache: dict[str, tuple[str, float]] = {}
        self._manual = getattr(Config, "MANUAL_DNS", {})
        self._lock   = asyncio.Lock()
        if DNSPYTHON:
            self._resolver = _dns_resolver.Resolver(configure=False)
            self._resolver.nameservers = list(getattr(Config, "DNS_RESOLVERS",
                                                       ["8.8.8.8", "1.1.1.1"]))
        else:
            self._resolver = None

    async def resolve(self, host, port=0, family=socket.AF_INET):
        if host in self._manual:
            ip = self._manual[host]
            return self._result(host, ip, port, family)

        async with self._lock:
            cached = self._cache.get(host)
            if cached and time.monotonic() < cached[1]:
                return self._result(host, cached[0], port, family)

        ip = None
        if DNSPYTHON and self._resolver:
            try:
                answers = self._resolver.resolve(host, "A")
                ip = str(random.choice(list(answers)))
                async with self._lock:
                    ttl = getattr(Config, "DNS_CACHE_TTL", 300)
                    self._cache[host] = (ip, time.monotonic() + ttl)
            except Exception:
                pass

        if ip is None:
            try:
                loop = asyncio.get_event_loop()
                infos = await loop.getaddrinfo(host, port, family=family)
                if infos:
                    ip = infos[0][4][0]
            except Exception:
                pass

        if ip is None:
            raise OSError(f"DNS resolution failed: {host}")

        return self._result(host, ip, port, family)

    @staticmethod
    def _result(hostname, ip, port, family):
        # hostname preserved for SNI — critical for TLS to work correctly
        return [{"hostname": hostname, "host": ip,
                 "port": port, "family": family, "proto": 0, "flags": 0}]

    async def close(self):
        pass


# ── SimpleResponse ────────────────────────────────────────────────────────────

class SimpleResponse:
    __slots__ = ("status", "headers", "_body", "url", "latency_ms")

    def __init__(self, status, headers, body, url, latency_ms=0.0):
        self.status     = status
        self.headers    = headers
        self._body      = body
        self.url        = url
        self.latency_ms = latency_ms

    async def text(self, encoding="utf-8", errors="replace"):
        return self._body.decode(encoding, errors=errors)

    async def json(self):
        return json.loads(self._body.decode("utf-8", errors="replace"))

    async def read(self):
        return self._body

    def __repr__(self):
        return f"<SimpleResponse [{self.status}] {self.url[:60]}>"


# ── Main HTTP client ──────────────────────────────────────────────────────────

class HTTPClient:
    """
    Async HTTP client with browser emulation, rate limiting, and retry logic.

    Provides a unified API:
        resp = await client.get(url)
        resp = await client.post(url, json={...})
        resp = await client.request("PUT", url, data="...", extra_headers={...})
    """

    def __init__(self, rate_limiter=None, validator=None):
        self.rate_limiter = rate_limiter
        self.validator    = validator
        self.logger       = Logger("HTTPClient")
        self._session: Optional[aiohttp.ClientSession] = None
        self._session_failures = 0
        self._ssl_ctx  = self._make_ssl_context()
        self._resolver = _CustomResolver()

    # ── Session management ────────────────────────────────────────────────────

    def _make_ssl_context(self):
        ctx = ssl.create_default_context()
        if getattr(Config, "VERIFY_SSL", False):
            ctx.check_hostname  = True
            ctx.verify_mode     = ssl.CERT_REQUIRED
            ctx.minimum_version = ssl.TLSVersion.TLSv1_2
            ctx.load_default_certs()
        else:
            ctx.check_hostname = False
            ctx.verify_mode    = ssl.CERT_NONE
        return ctx

    def _get_session(self) -> aiohttp.ClientSession:
        if self._session is None or self._session.closed:
            self._session = self._new_session()
        return self._session

    def _new_session(self) -> aiohttp.ClientSession:
        timeout   = aiohttp.ClientTimeout(
            total=getattr(Config, "REQUEST_TIMEOUT", 30),
            connect=10,
            sock_read=25,
        )
        connector = aiohttp.TCPConnector(
            limit=50,
            limit_per_host=10,
            ttl_dns_cache=300,
            ssl=self._ssl_ctx,
            force_close=False,
            enable_cleanup_closed=True,
            resolver=self._resolver,
        )
        proxies   = getattr(Config, "PROXIES", [])
        proxy     = random.choice(proxies) if proxies else None
        return aiohttp.ClientSession(
            timeout=timeout,
            connector=connector,
            trust_env=True,
            **({"proxy": proxy} if proxy else {}),
        )

    def _rotate_session(self):
        if self._session and not self._session.closed:
            asyncio.create_task(self._session.close())
        self._session = self._new_session()
        self._session_failures = 0

    # ── Request method ────────────────────────────────────────────────────────

    async def request(
        self,
        method: str,
        url: str,
        *,
        retries: int = 3,
        extra_headers: Optional[dict] = None,
        allow_redirects: bool = True,
        api_mode: bool = False,
        data=None,
        json: Optional[dict] = None,
        **kwargs,
    ) -> Optional[SimpleResponse]:
        """
        Send an HTTP request.

        Parameters
        ----------
        method          : HTTP verb
        url             : Target URL (must be in scope)
        retries         : Retry attempts on transient errors
        extra_headers   : Headers merged over the browser profile headers
        allow_redirects : Follow 3xx redirects
        api_mode        : Use JSON Accept header instead of HTML
        data            : Raw body bytes / str
        json            : Dict to serialise as JSON body
        """
        # Scope check
        if self.validator and not self.validator.validate(url):
            self.logger.debug(f"Out-of-scope, skipping: {url}")
            return None

        host = urlparse(url).hostname or url

        # Rate limiting
        if self.rate_limiter:
            await self.rate_limiter.wait_if_needed(host)

        # Build headers
        profile = random.choice(_PROFILES).copy()
        if api_mode:
            profile["Accept"] = "application/json"
        if extra_headers:
            profile.update(extra_headers)

        for attempt in range(retries):
            t0 = time.monotonic()
            try:
                sess = self._get_session()
                async with sess.request(
                    method, url,
                    headers=profile,
                    allow_redirects=allow_redirects,
                    data=data,
                    json=json,
                    **kwargs,
                ) as resp:
                    latency = (time.monotonic() - t0) * 1000

                    # Rate limited — adaptive backoff
                    if resp.status == 429:
                        ra   = resp.headers.get("Retry-After", "")
                        wait = float(ra) if ra.isdigit() else (2 ** (attempt + 1))
                        wait += random.uniform(0, 0.5)
                        self.logger.warning(f"429 on {host} — waiting {wait:.1f}s")
                        await asyncio.sleep(wait)
                        if self.rate_limiter:
                            self.rate_limiter.on_throttled(host)
                        continue

                    # Read body with size cap
                    chunks, total = [], 0
                    async for chunk in resp.content.iter_chunked(8192):
                        total += len(chunk)
                        if total > _MAX_BODY:
                            self.logger.debug(f"Body cap hit for {url}")
                            break
                        chunks.append(chunk)
                    body = b"".join(chunks)

                    self._session_failures = 0
                    return SimpleResponse(
                        status=resp.status,
                        headers=dict(resp.headers),
                        body=body,
                        url=str(resp.url),
                        latency_ms=latency,
                    )

            except ssl.SSLError as exc:
                self.logger.debug(f"SSL error {host}: {exc}")
                if attempt == retries - 1:
                    return None
                await asyncio.sleep(2 ** attempt + random.uniform(0, 0.5))

            except (aiohttp.ClientConnectorError,
                    aiohttp.ClientOSError,
                    asyncio.TimeoutError,
                    aiohttp.ServerDisconnectedError) as exc:
                self.logger.debug(f"Connection error {url} (attempt {attempt+1}): {exc}")
                if attempt == retries - 1:
                    self._session_failures += 1
                    if self._session_failures >= 5:
                        self.logger.debug("Rotating HTTP session")
                        self._rotate_session()
                    return None
                await asyncio.sleep(1.5 ** attempt + random.uniform(0, 0.3))

            except Exception as exc:
                self.logger.debug(f"Unexpected error {url}: {exc}")
                return None

        return None

    # ── Convenience wrappers ──────────────────────────────────────────────────

    async def get(self, url: str, **kw) -> Optional[SimpleResponse]:
        return await self.request("GET", url, **kw)

    async def post(self, url: str, **kw) -> Optional[SimpleResponse]:
        return await self.request("POST", url, **kw)

    async def put(self, url: str, **kw) -> Optional[SimpleResponse]:
        return await self.request("PUT", url, **kw)

    async def delete(self, url: str, **kw) -> Optional[SimpleResponse]:
        return await self.request("DELETE", url, **kw)

    # ── Lifecycle ─────────────────────────────────────────────────────────────

    async def close(self):
        if self._session and not self._session.closed:
            await self._session.close()
        await self._resolver.close()


__all__ = ["HTTPClient", "SimpleResponse"]
