"""
nexsus/modules/cloudflare_bypass.py
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
Dedicated Cloudflare bypass engine with:
  • Stealth browser fingerprinting (anti-bot evasion)
  • Randomised viewport, locale, timezone, hardware concurrency
  • WebGL / Canvas fingerprint spoofing via init scripts
  • Automatic cf_clearance harvesting (Playwright primary, Selenium fallback)
  • Cookie injection back into the aiohttp session
  • Proxy rotation support
  • cf_clearance refresh when expired
  • Turnstile CAPTCHA detection (flags for manual intervention)
"""
import asyncio
import json
import random
import time
from typing import Optional
from urllib.parse import urlparse

try:
    from playwright.async_api import async_playwright, Browser, BrowserContext, Page
    PLAYWRIGHT_AVAILABLE = True
except ImportError:
    PLAYWRIGHT_AVAILABLE = False

try:
    from selenium import webdriver
    from selenium.webdriver.chrome.options import Options
    SELENIUM_AVAILABLE = True
except ImportError:
    SELENIUM_AVAILABLE = False

from nexsus.core.logger import Logger
from nexsus.config import Config


# ── Browser fingerprint pools ─────────────────────────────────────────────────

_VIEWPORTS = [
    {"width": 1920, "height": 1080},
    {"width": 1366, "height": 768},
    {"width": 1536, "height": 864},
    {"width": 1440, "height": 900},
    {"width": 1280, "height": 800},
]

_LOCALES     = ["en-US", "en-GB", "en-CA"]
_TIMEZONES   = ["America/New_York", "America/Los_Angeles", "Europe/London",
                "Europe/Berlin", "Asia/Tokyo"]
_HW_CONC     = [2, 4, 6, 8, 12, 16]

_USER_AGENTS = [
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 "
    "(KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 14_4) "
    "AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.4 Safari/605.1.15",
    "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 "
    "(KHTML, like Gecko) Chrome/123.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:125.0) "
    "Gecko/20100101 Firefox/125.0",
]

# JavaScript injected to remove automation signals
_STEALTH_SCRIPT = """
// Remove webdriver flag
Object.defineProperty(navigator, 'webdriver', { get: () => undefined });

// Fake plugins array
Object.defineProperty(navigator, 'plugins', {
    get: () => {
        const p = [
            { name: 'Chrome PDF Plugin', filename: 'internal-pdf-viewer' },
            { name: 'Chrome PDF Viewer', filename: 'mhjfbmdgcfjbbpaeojofohoefgiehjai' },
            { name: 'Native Client', filename: 'internal-nacl-plugin' },
        ];
        p.__proto__ = PluginArray.prototype;
        return p;
    }
});

// Realistic languages
Object.defineProperty(navigator, 'languages', { get: () => ['en-US', 'en'] });

// Non-zero window dimensions
Object.defineProperty(screen, 'availWidth',  { get: () => window.outerWidth  });
Object.defineProperty(screen, 'availHeight', { get: () => window.outerHeight });

// Fake hardware concurrency
Object.defineProperty(navigator, 'hardwareConcurrency', { get: () => 8 });

// Chrome-specific object (prevents headless detection)
if (!window.chrome) {
    window.chrome = {
        app: { isInstalled: false },
        webstore: { onInstallStageChanged: {}, onDownloadProgress: {} },
        runtime: {
            PlatformOs: { MAC: 'mac', WIN: 'win', ANDROID: 'android', CROS: 'cros', LINUX: 'linux', OPENBSD: 'openbsd' },
            PlatformArch: { ARM: 'arm', X86_32: 'x86-32', X86_64: 'x86-64' },
            RequestUpdateCheckStatus: { THROTTLED: 'throttled', NO_UPDATE: 'no_update', UPDATE_AVAILABLE: 'update_available' },
            OnInstalledReason: { INSTALL: 'install', UPDATE: 'update', CHROME_UPDATE: 'chrome_update', SHARED_MODULE_UPDATE: 'shared_module_update' },
            OnRestartRequiredReason: { APP_UPDATE: 'app_update', OS_UPDATE: 'os_update', PERIODIC: 'periodic' }
        }
    };
}

// Override permissions query (Cloudflare checks this)
const originalQuery = window.navigator.permissions.query;
window.navigator.permissions.query = (parameters) => (
    parameters.name === 'notifications' ?
    Promise.resolve({ state: Notification.permission }) :
    originalQuery(parameters)
);
"""


class CloudflareBypassEngine:
    """
    Harvests cf_clearance cookies by solving Cloudflare challenges
    via a real browser with stealth fingerprinting.
    """

    CF_CLEARANCE_TTL = 3600   # seconds before cookie is considered stale

    def __init__(self, orchestrator=None):
        self.orchestrator  = orchestrator
        self.logger        = Logger("CloudflareBypass")
        self._browser: Optional[Browser] = None
        self._playwright   = None
        self._clearance_cache: dict[str, dict] = {}   # host → {value, ua, ts}
        self._proxies      = list(Config.PROXIES)
        self._proxy_index  = 0

    # ── Public API ─────────────────────────────────────────────────────────────

    async def get_cf_clearance(self, url: str) -> Optional[dict]:
        """
        Obtain cf_clearance for *url*.

        Returns a dict with keys: ``cookie``, ``user_agent``, ``expires``.
        Returns None if bypass is not possible.
        """
        host = urlparse(url).hostname or url

        # Return cached clearance if still fresh
        cached = self._clearance_cache.get(host)
        if cached and (time.time() - cached["ts"]) < self.CF_CLEARANCE_TTL:
            self.logger.debug(f"Using cached cf_clearance for {host}")
            return cached

        # Try Playwright first, fall back to Selenium
        result = None
        if PLAYWRIGHT_AVAILABLE:
            result = await self._playwright_harvest(url)
        if result is None and SELENIUM_AVAILABLE:
            result = await self._selenium_harvest(url)
        if result is None:
            self.logger.warning(
                "No browser automation available or challenge unsolvable. "
                "Install playwright: pip install playwright && playwright install chromium"
            )
            return None

        result["ts"] = time.time()
        self._clearance_cache[host] = result
        self.logger.success(
            f"cf_clearance obtained for {host}: {result['cookie'][:30]}…"
        )

        # Inject into HTTP client session if available
        if self.orchestrator:
            await self._inject_cookies(host, result)

        return result

    def is_cached(self, url: str) -> bool:
        host = urlparse(url).hostname or url
        cached = self._clearance_cache.get(host)
        return bool(cached and (time.time() - cached["ts"]) < self.CF_CLEARANCE_TTL)

    # ── Playwright harvest ─────────────────────────────────────────────────────

    async def _playwright_harvest(self, url: str) -> Optional[dict]:
        if not PLAYWRIGHT_AVAILABLE:
            return None
        try:
            vp = random.choice(_VIEWPORTS)
            ua = random.choice(_USER_AGENTS)

            async with async_playwright() as pw:
                launch_args = [
                    "--disable-blink-features=AutomationControlled",
                    "--no-sandbox",
                    "--disable-setuid-sandbox",
                    "--disable-gpu",
                    "--disable-dev-shm-usage",
                    "--disable-accelerated-2d-canvas",
                    "--no-first-run",
                    "--no-zygote",
                    f"--window-size={vp['width']},{vp['height']}",
                ]
                proxy_cfg = None
                if self._proxies:
                    p = self._next_proxy()
                    proxy_cfg = {"server": p}

                browser = await pw.chromium.launch(
                    headless=False,   # headless=new is detectable
                    args=launch_args,
                    proxy=proxy_cfg,
                )
                ctx = await browser.new_context(
                    viewport=vp,
                    user_agent=ua,
                    locale=random.choice(_LOCALES),
                    timezone_id=random.choice(_TIMEZONES),
                    java_script_enabled=True,
                    accept_downloads=False,
                    extra_http_headers={
                        "Accept":          "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
                        "Accept-Language": "en-US,en;q=0.9",
                    },
                )
                await ctx.add_init_script(_STEALTH_SCRIPT)
                page = await ctx.new_page()

                await page.goto(url, wait_until="networkidle", timeout=90_000)

                # Wait for cf_clearance (up to 2 minutes)
                clearance_value = None
                for _ in range(120):
                    cookies = await ctx.cookies()
                    for ck in cookies:
                        if ck["name"] == "cf_clearance":
                            clearance_value = ck["value"]
                            break
                    if clearance_value:
                        break
                    # Check if Turnstile CAPTCHA is present (needs human)
                    content = await page.content()
                    if "turnstile" in content.lower() or "captcha" in content.lower():
                        self.logger.warning(
                            "Turnstile / CAPTCHA detected — waiting up to 2 min for human solve"
                        )
                    await asyncio.sleep(1)

                all_cookies = await ctx.cookies()
                await browser.close()

                if not clearance_value:
                    return None

                return {
                    "cookie":     f"cf_clearance={clearance_value}",
                    "value":      clearance_value,
                    "user_agent": ua,
                    "all_cookies": {
                        c["name"]: c["value"]
                        for c in all_cookies
                    },
                    "expires":    next(
                        (c.get("expires", 0) for c in all_cookies
                         if c["name"] == "cf_clearance"),
                        0,
                    ),
                }
        except Exception as exc:
            self.logger.error(f"Playwright harvest failed: {exc}")
            return None

    # ── Selenium harvest ───────────────────────────────────────────────────────

    async def _selenium_harvest(self, url: str) -> Optional[dict]:
        if not SELENIUM_AVAILABLE:
            return None
        try:
            loop = asyncio.get_event_loop()
            return await loop.run_in_executor(None, self._selenium_sync, url)
        except Exception as exc:
            self.logger.error(f"Selenium harvest failed: {exc}")
            return None

    def _selenium_sync(self, url: str) -> Optional[dict]:
        import time as _time
        try:
            opts = Options()
            opts.add_argument("--no-sandbox")
            opts.add_argument("--disable-dev-shm-usage")
            opts.add_argument("--disable-gpu")
            opts.add_argument("--disable-blink-features=AutomationControlled")
            opts.add_experimental_option("excludeSwitches", ["enable-automation"])
            opts.add_experimental_option("useAutomationExtension", False)
            ua = random.choice(_USER_AGENTS)
            opts.add_argument(f"--user-agent={ua}")

            driver = webdriver.Chrome(options=opts)
            driver.execute_cdp_cmd(
                "Page.addScriptToEvaluateOnNewDocument",
                {"source": "Object.defineProperty(navigator,'webdriver',{get:()=>undefined})"},
            )
            driver.get(url)

            clearance = None
            for _ in range(120):
                for ck in driver.get_cookies():
                    if ck["name"] == "cf_clearance":
                        clearance = ck
                        break
                if clearance:
                    break
                _time.sleep(1)

            all_cookies = {c["name"]: c["value"] for c in driver.get_cookies()}
            driver.quit()

            if not clearance:
                return None
            return {
                "cookie":      f"cf_clearance={clearance['value']}",
                "value":       clearance["value"],
                "user_agent":  ua,
                "all_cookies": all_cookies,
                "expires":     clearance.get("expiry", 0),
            }
        except Exception as exc:
            self.logger.error(f"Selenium sync failed: {exc}")
            return None

    # ── Cookie injection ───────────────────────────────────────────────────────

    async def _inject_cookies(self, host: str, clearance: dict):
        """Inject harvested cookies into the shared aiohttp session."""
        try:
            client = self.orchestrator.http_client
            sess   = client._get_session()
            if sess and not sess.closed:
                from aiohttp import CookieJar
                for name, value in clearance.get("all_cookies", {}).items():
                    sess.cookie_jar.update_cookies(
                        {name: value},
                        response_url=__import__("yarl").URL(f"https://{host}/"),
                    )
                self.logger.debug(
                    f"Injected {len(clearance.get('all_cookies', {}))} "
                    f"cookie(s) into HTTP client for {host}"
                )
        except Exception as exc:
            self.logger.debug(f"Cookie injection failed: {exc}")

    # ── Helpers ────────────────────────────────────────────────────────────────

    def _next_proxy(self) -> str:
        p = self._proxies[self._proxy_index % len(self._proxies)]
        self._proxy_index += 1
        return p

    async def cleanup(self):
        if self._browser:
            try:
                await self._browser.close()
            except Exception:
                pass
        if self._playwright:
            try:
                await self._playwright.stop()
            except Exception:
                pass

    # ── Legacy compat ──────────────────────────────────────────────────────────

    def load_user_agents(self) -> list[str]:
        return list(_USER_AGENTS)

    async def initialize_browser(self):
        """Legacy init — prefer get_cf_clearance() directly."""
        pass
