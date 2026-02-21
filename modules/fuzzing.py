import asyncio
from urllib.parse import urlparse, parse_qs, urlencode
from nexsus.utils.logger import Logger

class Fuzzing:
    def __init__(self, orchestrator):
        self.orchestrator = orchestrator
        self.paused = False
        self.logger = Logger("Fuzzing")

    async def run(self):
        self.logger.info("Starting Smart Fuzzing...")
        endpoints = self.orchestrator.data_store.assets.get('endpoints', [])
        client = self.orchestrator.http_client
        for url in endpoints:
            if self.paused: await self.wait_if_paused()
            await self.fuzz_parameters(client, url)
        self.logger.success("Fuzzing completed.")

    async def fuzz_parameters(self, client, url):
        common_params = ['id', 'user', 'file', 'path', 'redirect', 'url', 'next']
        payloads = ["'", "\"", "<script>alert(1)</script>", "../../etc/passwd", "{{7*7}}", "${7*7}"]
        parsed = urlparse(url)
        if not parsed.query:
            return
        params = parse_qs(parsed.query)
        for param in params:
            for payload in payloads:
                new_params = params.copy()
                new_params[param] = [payload]
                new_query = urlencode(new_params, doseq=True)
                test_url = f"{parsed.scheme}://{parsed.netloc}{parsed.path}?{new_query}"
                resp = await client.request('GET', test_url)
                if resp:
                    text = await resp.text()
                    if payload in text:
                        finding = {
                            "id": f"Fuzz-{len(self.orchestrator.findings)+1}",
                            "title": "Reflected Input",
                            "asset": url,
                            "endpoint": test_url,
                            "parameter": param,
                            "severity": "Info",
                            "confidence": 100,
                            "impact_summary": "Parameter reflects input, may lead to XSS if not encoded.",
                            "evidence": {"request": f"GET {test_url}", "response_snippet": text[:200]},
                            "reproduction_steps": f"Set {param}={payload}",
                            "remediation": "Implement proper output encoding."
                        }
                        self.orchestrator.add_finding(finding)

    async def wait_if_paused(self):
        while self.paused:
            await asyncio.sleep(1)

    def pause(self):
        self.paused = True
        self.logger.debug("Paused")

    def resume(self):
        self.paused = False
        self.logger.debug("Resumed")
