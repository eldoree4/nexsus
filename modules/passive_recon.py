import asyncio
import json
from urllib.parse import urlparse
from nexsus.utils.logger import Logger

class PassiveRecon:
    def __init__(self, orchestrator):
        self.orchestrator = orchestrator
        self.paused = False
        self.logger = Logger("PassiveRecon")

    async def run(self):
        domains = set(self.orchestrator.scope.domains)
        for api in self.orchestrator.scope.api_endpoints:
            parsed = urlparse(api)
            if parsed.hostname:
                domains.add(parsed.hostname)

        if not domains:
            self.logger.warning("No domains or API hostnames found. Skipping passive recon.")
            return

        self.logger.info("Starting Passive Recon...")
        client = self.orchestrator.http_client
        tasks = []
        for domain in domains:
            tasks.extend([
                self.certificate_transparency(client, domain),
                self.wayback_machine(client, domain),
                self.common_crawl(client, domain),
                self.urlscan(client, domain),
                self.alienvault(client, domain)
            ])

        results = await asyncio.gather(*tasks, return_exceptions=True)
        for i, result in enumerate(results):
            if isinstance(result, Exception):
                self.logger.error(f"Task {i} failed: {result}")

        self.orchestrator.data_store.save_assets()
        self.logger.success("Passive Recon completed.")

    async def certificate_transparency(self, client, domain):
        if self.paused: await self.wait_if_paused()
        url = f"https://crt.sh/?q=%.{domain}&output=json"
        try:
            resp = await client.request('GET', url)
            if resp and resp.status == 200:
                data = await resp.json()
                for entry in data:
                    name = entry['name_value'].strip()
                    if name.endswith(domain):
                        self.orchestrator.data_store.assets['subdomains'].add(name)
        except Exception as e:
            self.logger.error(f"Certificate Transparency error for {domain}: {e}")

    async def wayback_machine(self, client, domain):
        if self.paused: await self.wait_if_paused()
        url = f"http://web.archive.org/cdx/search/cdx?url={domain}/*&output=json&fl=original&collapse=urlkey"
        try:
            resp = await client.request('GET', url)
            if resp and resp.status == 200:
                data = await resp.json()
                for row in data[1:]:
                    endpoint = row[0]
                    self.orchestrator.data_store.assets['endpoints'].add(endpoint)
        except Exception as e:
            self.logger.error(f"Wayback Machine error for {domain}: {e}")

    async def common_crawl(self, client, domain):
        if self.paused: await self.wait_if_paused()
        url = f"http://index.commoncrawl.org/CC-MAIN-2024-10-index?url={domain}&output=json"
        try:
            resp = await client.request('GET', url)
            if resp and resp.status == 200:
                text = await resp.text()
                for line in text.strip().split('\n'):
                    if line:
                        data = json.loads(line)
                        endpoint = data['url']
                        self.orchestrator.data_store.assets['endpoints'].add(endpoint)
        except Exception as e:
            self.logger.error(f"Common Crawl error for {domain}: {e}")

    async def urlscan(self, client, domain):
        if self.paused: await self.wait_if_paused()
        url = f"https://urlscan.io/api/v1/search/?q=domain:{domain}"
        try:
            resp = await client.request('GET', url)
            if resp and resp.status == 200:
                data = await resp.json()
                for result in data.get('results', []):
                    page = result.get('page', {})
                    if page.get('domain') and page['domain'].endswith(domain):
                        self.orchestrator.data_store.assets['subdomains'].add(page['domain'])
                    if page.get('url'):
                        self.orchestrator.data_store.assets['endpoints'].add(page['url'])
        except Exception as e:
            self.logger.error(f"URLScan error for {domain}: {e}")

    async def alienvault(self, client, domain):
        if self.paused: await self.wait_if_paused()
        url = f"https://otx.alienvault.com/api/v1/indicators/domain/{domain}/passive_dns"
        try:
            resp = await client.request('GET', url)
            if resp and resp.status == 200:
                data = await resp.json()
                for entry in data.get('passive_dns', []):
                    hostname = entry.get('hostname')
                    if hostname and hostname.endswith(domain):
                        self.orchestrator.data_store.assets['subdomains'].add(hostname)
        except Exception as e:
            self.logger.error(f"AlienVault error for {domain}: {e}")

    async def wait_if_paused(self):
        while self.paused:
            await asyncio.sleep(1)

    def pause(self):
        self.paused = True
        self.logger.debug("Paused")

    def resume(self):
        self.paused = False
        self.logger.debug("Resumed")
