import asyncio
import re
from urllib.parse import urljoin, urlparse
from bs4 import BeautifulSoup
from nexsus.utils.logger import Logger

class ActiveRecon:
    def __init__(self, orchestrator):
        self.orchestrator = orchestrator
        self.paused = False
        self.crawled = set()
        self.to_crawl = []
        self.logger = Logger("ActiveRecon")

    async def run(self):
        self.logger.info("Starting Active Recon...")
        all_endpoints = self.orchestrator.data_store.assets.get('endpoints', [])
        seeds = [url for url in all_endpoints if self.orchestrator.validator.validate(url)]
        if not seeds:
            for domain in self.orchestrator.scope.domains:
                seeds.append(f"https://{domain}")
                seeds.append(f"http://{domain}")
        self.to_crawl = seeds
        client = self.orchestrator.http_client
        while self.to_crawl and not self.paused:
            url = self.to_crawl.pop(0)
            if url in self.crawled:
                continue
            self.crawled.add(url)
            await self.crawl_url(client, url)
        self.logger.success("Active Recon completed.")

    async def crawl_url(self, client, url):
        resp = await client.request('GET', url)
        if not resp:
            return
        final_url = str(resp.url)
        if final_url != url:
            self.logger.debug(f"Redirected from {url} to {final_url}")
            if final_url in self.crawled:
                return
            self.crawled.add(final_url)
            url = final_url
        try:
            text = await resp.text()
        except Exception as e:
            self.logger.debug(f"Failed to read text from {url}: {e}")
            self.orchestrator.data_store.assets['endpoints'].add(url)
            return
        content_type = resp.headers.get('content-type', '').lower()
        is_html = (
            'text/html' in content_type or
            'application/xhtml+xml' in content_type or
            '<html' in text.lower() or
            '<body' in text.lower() or
            '<!doctype html' in text.lower() or
            '<head' in text.lower()
        )
        if not is_html:
            self.logger.debug(f"Skipping non-HTML content: {content_type}")
            self.orchestrator.data_store.assets['endpoints'].add(url)
            return
        soup = BeautifulSoup(text, 'html.parser')
        links = set()
        for a in soup.find_all('a', href=True):
            link = a['href'].strip()
            absolute = urljoin(url, link)
            if self.orchestrator.validator.validate(absolute):
                links.add(absolute)
        for tag in soup.find_all(['link', 'script', 'img', 'iframe'], src=True):
            link = tag['src'].strip()
            absolute = urljoin(url, link)
            if self.orchestrator.validator.validate(absolute):
                links.add(absolute)
        for form in soup.find_all('form', action=True):
            link = form['action'].strip()
            absolute = urljoin(url, link)
            if self.orchestrator.validator.validate(absolute):
                links.add(absolute)
        for frame in soup.find_all('frame', src=True):
            link = frame['src'].strip()
            absolute = urljoin(url, link)
            if self.orchestrator.validator.validate(absolute):
                links.add(absolute)
        for area in soup.find_all('area', href=True):
            link = area['href'].strip()
            absolute = urljoin(url, link)
            if self.orchestrator.validator.validate(absolute):
                links.add(absolute)
        for link in links:
            if link not in self.crawled:
                self.to_crawl.append(link)
        self.orchestrator.data_store.assets['endpoints'].add(url)
        self.logger.debug(f"Crawled {url}, found {len(links)} links")

    async def wait_if_paused(self):
        while self.paused:
            await asyncio.sleep(1)

    def pause(self):
        self.paused = True
        self.logger.debug("Paused")

    def resume(self):
        self.paused = False
        self.logger.debug("Resumed")
