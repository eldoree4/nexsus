import asyncio
from nexsus.utils.logger import Logger

class APISecurity:
    def __init__(self, orchestrator):
        self.orchestrator = orchestrator
        self.paused = False
        self.logger = Logger("APISecurity")

    async def run(self):
        self.logger.info("Starting API Security Audit...")
        endpoints = self.orchestrator.data_store.assets.get('endpoints', [])
        api_endpoints = [e for e in endpoints if '/api/' in e or '/v1/' in e or '/graphql' in e]
        client = self.orchestrator.http_client
        for url in api_endpoints:
            if self.paused: await self.wait_if_paused()
            await self.test_mass_assignment(client, url)
            await self.test_method_tampering(client, url)
        self.logger.success("API Audit completed.")

    async def test_mass_assignment(self, client, url):
        data = {"admin": True, "role": "admin", "is_admin": True}
        resp = await client.request('POST', url, json=data)
        if resp and resp.status == 200:
            text = await resp.text()
            if "admin" in text.lower():
                finding = {
                    "id": f"MassAssign-{len(self.orchestrator.findings)+1}",
                    "title": "Potential Mass Assignment",
                    "asset": url,
                    "endpoint": url,
                    "parameter": "admin,role",
                    "severity": "High",
                    "confidence": 50,
                    "impact_summary": "Could allow privilege escalation.",
                    "evidence": {"request": f"POST {url} with {data}", "response_snippet": text[:200]},
                    "reproduction_steps": "Send POST with unexpected fields.",
                    "remediation": "Use whitelist of allowed fields."
                }
                self.orchestrator.add_finding(finding)

    async def test_method_tampering(self, client, url):
        for method in ['PUT', 'DELETE', 'PATCH']:
            resp = await client.request(method, url)
            if resp and resp.status not in [405, 404, 403]:
                text = await resp.text()
                finding = {
                    "id": f"MethodTamper-{len(self.orchestrator.findings)+1}",
                    "title": f"Unexpected {method} Allowed",
                    "asset": url,
                    "endpoint": url,
                    "parameter": "",
                    "severity": "Medium",
                    "confidence": 80,
                    "impact_summary": f"May allow unauthorized modification or deletion.",
                    "evidence": {"request": f"{method} {url}", "response_snippet": text[:200]},
                    "reproduction_steps": f"Send {method} request.",
                    "remediation": "Restrict HTTP methods to intended ones."
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
