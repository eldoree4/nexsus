import asyncio
import re
from urllib.parse import urlparse, parse_qs
from nexsus.utils.logger import Logger
from nexsus.core.payload_manager import PayloadManager

class VulnScan:
    def __init__(self, orchestrator):
        self.orchestrator = orchestrator
        self.paused = False
        self.logger = Logger("VulnScan")
        self.payload_manager = PayloadManager(orchestrator.current_waf)

    async def run(self):
        self.logger.info("Starting Vulnerability Scan...")
        endpoints = self.orchestrator.data_store.assets.get('endpoints', [])
        if not endpoints:
            self.logger.warning("No endpoints found. Run Active Recon first.")
            return
        client = self.orchestrator.http_client
        total = len(endpoints)
        for i, url in enumerate(endpoints):
            if self.paused: await self.wait_if_paused()
            self.logger.progress(f"[{i+1}/{total}] Testing {url}")
            await self.test_idor(client, url)
            await self.test_sqli(client, url)
            await self.test_open_redirect(client, url)
            await self.test_xss(client, url)
            await self.test_path_traversal(client, url)
            await self.test_cmd_injection(client, url)
            await self.test_ssti(client, url)
        self.logger.success("Vulnerability Scan completed.")

    async def test_idor(self, client, url):
        match = re.search(r'/(\d+)', url)
        if match:
            original_id = match.group(1)
            new_id = str(int(original_id) + 1)
            test_url = url.replace(original_id, new_id)
            resp = await client.request('GET', test_url)
            if resp and resp.status == 200:
                try:
                    text = await resp.text()
                except:
                    text = ""
                if "unauthorized" not in text.lower() and "forbidden" not in text.lower():
                    finding = {
                        "id": f"IDOR-{len(self.orchestrator.findings)+1}",
                        "title": "Potential IDOR",
                        "asset": url,
                        "endpoint": test_url,
                        "parameter": "id",
                        "severity": "High",
                        "confidence": 70,
                        "impact_summary": "May allow access to unauthorized resources.",
                        "evidence": {"request": f"GET {test_url}", "response_snippet": text[:200]},
                        "reproduction_steps": f"Change ID from {original_id} to {new_id}.",
                        "remediation": "Implement access control checks."
                    }
                    self.orchestrator.add_finding(finding)

    async def test_sqli(self, client, url):
        payloads = self.payload_manager.get_payloads('sqli')
        if not payloads:
            return
        baseline_resp = await client.request('GET', url)
        if not baseline_resp:
            return
        try:
            baseline_text = await baseline_resp.text()
        except:
            return
        baseline_len = len(baseline_text)

        for payload in payloads:
            test_url = url + "?id=" + payload
            resp = await client.request('GET', test_url)
            if not resp:
                continue
            try:
                text = await resp.text()
            except:
                continue
            if abs(len(text) - baseline_len) > 100 or "sql" in text.lower() or "mysql" in text.lower():
                finding = {
                    "id": f"SQLi-{len(self.orchestrator.findings)+1}",
                    "title": "Potential SQL Injection",
                    "asset": url,
                    "endpoint": test_url,
                    "parameter": "id",
                    "severity": "Critical",
                    "confidence": 60,
                    "impact_summary": "Could lead to data extraction.",
                    "evidence": {"request": f"GET {test_url}", "response_snippet": text[:200]},
                    "reproduction_steps": f"Append payload: {payload}",
                    "remediation": "Use parameterized queries."
                }
                self.orchestrator.add_finding(finding)
                break

    async def test_open_redirect(self, client, url):
        parsed = urlparse(url)
        query = parse_qs(parsed.query)
        for param, values in query.items():
            if param.lower() in ['next', 'redirect', 'url', 'return', 'to', 'out']:
                test_url = url.replace(values[0], "https://evil.com")
                resp = await client.request('GET', test_url, allow_redirects=False)
                if resp and resp.status in [301,302,303] and 'Location' in resp.headers:
                    location = resp.headers['Location']
                    if 'evil.com' in location:
                        finding = {
                            "id": f"OpenRedirect-{len(self.orchestrator.findings)+1}",
                            "title": "Open Redirect",
                            "asset": url,
                            "endpoint": test_url,
                            "parameter": param,
                            "severity": "Medium",
                            "confidence": 90,
                            "impact_summary": "Can be used in phishing attacks.",
                            "evidence": {"request": f"GET {test_url}", "response_snippet": f"Location: {location}"},
                            "reproduction_steps": f"Modify {param} to external URL.",
                            "remediation": "Validate and whitelist redirect targets."
                        }
                        self.orchestrator.add_finding(finding)

    async def test_xss(self, client, url):
        payloads = self.payload_manager.get_payloads('xss')
        for payload in payloads:
            test_url = url + "?q=" + payload
            resp = await client.request('GET', test_url)
            if resp:
                try:
                    text = await resp.text()
                    if payload in text and '<' in payload and '>' in payload:
                        finding = {
                            "id": f"XSS-{len(self.orchestrator.findings)+1}",
                            "title": "Reflected XSS",
                            "asset": url,
                            "endpoint": test_url,
                            "parameter": "q",
                            "severity": "Medium",
                            "confidence": 80,
                            "impact_summary": "Can execute JavaScript in victim's browser.",
                            "evidence": {"request": f"GET {test_url}", "response_snippet": text[:200]},
                            "reproduction_steps": f"Visit {test_url}",
                            "remediation": "Escape user input properly."
                        }
                        self.orchestrator.add_finding(finding)
                        break
                except:
                    continue

    async def test_path_traversal(self, client, url):
        payloads = self.payload_manager.get_payloads('path_traversal')
        for payload in payloads:
            test_url = url + "/" + payload
            resp = await client.request('GET', test_url)
            if resp and resp.status == 200:
                try:
                    text = await resp.text()
                    if "root:x:" in text or "[extensions]" in text:
                        finding = {
                            "id": f"PathTraversal-{len(self.orchestrator.findings)+1}",
                            "title": "Path Traversal",
                            "asset": url,
                            "endpoint": test_url,
                            "parameter": "path",
                            "severity": "High",
                            "confidence": 90,
                            "impact_summary": "Can read arbitrary files.",
                            "evidence": {"request": f"GET {test_url}", "response_snippet": text[:200]},
                            "reproduction_steps": f"Access {test_url}",
                            "remediation": "Validate and sanitize file paths."
                        }
                        self.orchestrator.add_finding(finding)
                        break
                except:
                    continue

    async def test_cmd_injection(self, client, url):
        payloads = self.payload_manager.get_payloads('cmd_injection')
        for payload in payloads:
            test_url = url + "?cmd=" + payload
            resp = await client.request('GET', test_url)
            if resp:
                try:
                    text = await resp.text()
                    if "uid=" in text or "root:" in text or "drwxr" in text:
                        finding = {
                            "id": f"CmdInjection-{len(self.orchestrator.findings)+1}",
                            "title": "Command Injection",
                            "asset": url,
                            "endpoint": test_url,
                            "parameter": "cmd",
                            "severity": "Critical",
                            "confidence": 80,
                            "impact_summary": "Can execute system commands.",
                            "evidence": {"request": f"GET {test_url}", "response_snippet": text[:200]},
                            "reproduction_steps": f"Send payload: {payload}",
                            "remediation": "Avoid system calls with user input."
                        }
                        self.orchestrator.add_finding(finding)
                        break
                except:
                    continue

    async def test_ssti(self, client, url):
        payloads = self.payload_manager.get_payloads('ssti')
        for payload in payloads:
            test_url = url + "?name=" + payload
            resp = await client.request('GET', test_url)
            if resp:
                try:
                    text = await resp.text()
                    if "49" in text and ("{{" in payload or "${" in payload):
                        finding = {
                            "id": f"SSTI-{len(self.orchestrator.findings)+1}",
                            "title": "Server Side Template Injection",
                            "asset": url,
                            "endpoint": test_url,
                            "parameter": "name",
                            "severity": "High",
                            "confidence": 70,
                            "impact_summary": "May lead to RCE.",
                            "evidence": {"request": f"GET {test_url}", "response_snippet": text[:200]},
                            "reproduction_steps": f"Send payload: {payload}",
                            "remediation": "Do not evaluate user input in templates."
                        }
                        self.orchestrator.add_finding(finding)
                        break
                except:
                    continue

    async def wait_if_paused(self):
        while self.paused:
            await asyncio.sleep(1)

    def pause(self):
        self.paused = True
        self.logger.debug("Paused")

    def resume(self):
        self.paused = False
        self.logger.debug("Resumed")
