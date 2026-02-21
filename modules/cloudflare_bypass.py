# nexsus/modules/cloudflare_bypass.py
import asyncio
import random
import time
import json
import ssl
from typing import Dict, List, Optional
from playwright.async_api import async_playwright, Browser, Page
from nexsus.utils.logger import Logger

class CloudflareBypassEngine:
    def __init__(self, orchestrator):
        self.orchestrator = orchestrator
        self.logger = Logger("CloudflareBypass")
        self.browser: Optional[Browser] = None
        self.cf_clearance = None
        self.user_agents = self.load_user_agents()
        self.proxy_rotator = None
        
    async def initialize_browser(self):
        """Inisialisasi browser dengan fingerprint acak"""
        playwright = await async_playwright().start()
        
        # Fingerprint acak untuk menghindari deteksi
        viewport = random.choice([
            {'width': 1920, 'height': 1080},
            {'width': 1366, 'height': 768},
            {'width': 1536, 'height': 864}
        ])
        
        self.browser = await playwright.chromium.launch(
            headless=False,  # Headless mudah terdeteksi
            args=[
                '--disable-blink-features=AutomationControlled',
                '--disable-features=IsolateOrigins,site-per-process',
                '--disable-web-security',
                '--disable-features=BlockInsecurePrivateNetworkRequests',
                '--no-sandbox',
                '--disable-setuid-sandbox',
                f'--window-size={viewport["width"]},{viewport["height"]}'
            ]
        )
        
    async def get_cf_clearance(self, url: str) -> Dict:
        """Mendapatkan cookie cf_clearance dengan menyelesaikan challenge"""
        if not self.browser:
            await self.initialize_browser()
            
        context = await self.browser.new_context(
            viewport=viewport,
            user_agent=random.choice(self.user_agents),
            locale='en-US,en;q=0.9',
            timezone_id='America/New_York',
            permissions=['geolocation'],
            device_scale_factor={'scale': 1}
        )
        
        page = await context.new_page()
        
        # Tambahkan script untuk menghilangkan fingerprint automation
        await page.add_init_script("""
            Object.defineProperty(navigator, 'webdriver', {
                get: () => undefined
            });
            Object.defineProperty(navigator, 'plugins', {
                get: () => [1, 2, 3, 4, 5]
            });
            Object.defineProperty(navigator, 'languages', {
                get: () => ['en-US', 'en']
            });
        """)
        
        try:
            # Navigasi dengan timeout panjang
            response = await page.goto(url, wait_until='networkidle', timeout=60000)
            
            # Deteksi Cloudflare challenge
            page_content = await page.content()
            
            if 'cf-challenge' in page_content or 'cdn-cgi' in page_content:
                self.logger.info("Cloudflare challenge detected, solving...")
                
                # Tunggu challenge selesai (otomatis atau manual)
                await page.wait_for_function(
                    "() => document.cookie.includes('cf_clearance')",
                    timeout=120000
                )
                
                # Ekstrak cookies
                cookies = await context.cookies()
                for cookie in cookies:
                    if cookie['name'] == 'cf_clearance':
                        self.cf_clearance = cookie['value']
                        self.logger.success(f"Got cf_clearance: {cookie['value'][:20]}...")
                        
                        return {
                            'cookie': f"cf_clearance={cookie['value']}",
                            'user_agent': await page.evaluate('navigator.userAgent'),
                            'expires': cookie.get('expires', 0)
                        }
            
            return None
            
        except Exception as e:
            self.logger.error(f"Failed to get cf_clearance: {e}")
            return None
        finally:
            await page.close()
            
    def load_user_agents(self):
        return [
            'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/121.0.0.0 Safari/537.36',
            'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.0 Safari/605.1.15',
            'Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36'
        ]
        
    async def cleanup(self):
        if self.browser:
            await self.browser.close()
