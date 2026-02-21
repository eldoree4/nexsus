import asyncio
import aiohttp
from nexsus.utils.logger import Logger

class CloudMisconfig:
    def __init__(self, orchestrator):
        self.orchestrator = orchestrator
        self.paused = False
        self.logger = Logger("CloudMisconfig")

    async def run(self):
        self.logger.info("Starting Cloud Misconfiguration Scan...")
        client = self.orchestrator.http_client
        for domain in self.orchestrator.scope.domains:
            if self.paused: await self.wait_if_paused()
            bucket_name = domain.replace('.', '-')
            urls = [
                f"https://{bucket_name}.s3.amazonaws.com",
                f"https://{bucket_name}.storage.googleapis.com",
                f"https://{bucket_name}.blob.core.windows.net"
            ]
            for url in urls:
                try:
                    resp = await client.request('GET', url)
                    if resp and resp.status == 200:
                        text = await resp.text()
                        if "<ListBucketResult" in text or "Contents" in text or "Blob" in text:
                            finding = {
                                "id": f"Cloud-{len(self.orchestrator.findings)+1}",
                                "title": "Public Cloud Storage",
                                "asset": url,
                                "endpoint": url,
                                "parameter": "",
                                "severity": "High",
                                "confidence": 90,
                                "impact_summary": "Bucket is publicly listable, exposing files.",
                                "evidence": {"request": f"GET {url}", "response_snippet": text[:200]},
                                "reproduction_steps": f"Visit {url}",
                                "remediation": "Disable public listing."
                            }
                            self.orchestrator.add_finding(finding)
                except:
                    pass
        self.logger.success("Cloud scan completed.")

    async def wait_if_paused(self):
        while self.paused:
            await asyncio.sleep(1)

    def pause(self):
        self.paused = True
        self.logger.debug("Paused")

    def resume(self):
        self.paused = False
        self.logger.debug("Resumed")
