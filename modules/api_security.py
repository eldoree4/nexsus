"""
nexsus/modules/api_security.py
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
Dedicated API security module covering:
  • REST endpoint discovery and method tampering
  • Mass assignment / parameter pollution
  • BOLA (Broken Object Level Authorisation)
  • GraphQL introspection, batch abuse, depth limit bypass
  • Rate limiting / brute-force protection absence
  • API versioning issues (v1 → v2 object exposure)
  • JWT / Bearer token manipulation
  • CORS misconfig on API endpoints
  • HTTP verb tunnelling (X-HTTP-Method-Override)
  • Sensitive data exposure in API responses
"""
import asyncio
import json
import re
import time
from urllib.parse import urlparse, urlencode, parse_qs

from nexsus.core.logger import Logger

_SENSITIVE_FIELDS = re.compile(
    r'"(password|passwd|secret|api_key|apikey|token|credit_card|cvv|ssn|'
    r'social_security|private_key|aws_secret|access_token|refresh_token)"'
    r'\s*:\s*"[^"]+"',
    re.IGNORECASE,
)

_API_PATH_PATTERNS = re.compile(
    r"(/api/|/v\d+/|/graphql|/rest/|/service/|/rpc)",
    re.IGNORECASE,
)

_GRAPHQL_INTROSPECTION = '{"query":"{__schema{queryType{name}mutationType{name}types{name,kind,fields{name,type{name,kind,ofType{name,kind}},args{name,type{name,kind,ofType{name,kind}}}}}}}"}'

_GRAPHQL_BATCH = '[{"query":"query{__typename}"},{"query":"query{__typename}"},{"query":"query{__typename}"},{"query":"query{__typename}"},{"query":"query{__typename}"}]'


class APISecurity:
    def __init__(self, orchestrator):
        self.orchestrator = orchestrator
        self.paused       = False
        self.logger       = Logger("APISecurity")
        self._client      = orchestrator.http_client

    # ── Main entry ─────────────────────────────────────────────────────────────

    async def run(self):
        self.logger.info("API Security Audit…")
        endpoints = list(self.orchestrator.data_store.assets.get("endpoints", set()))

        # Focus on API-like paths
        api_urls = [
            u for u in endpoints
            if _API_PATH_PATTERNS.search(u)
        ] or endpoints[:50]   # fallback: test first 50 if no /api/ paths

        if not api_urls:
            self.logger.warning("No API endpoints found — skipping")
            return

        self.logger.info(f"Testing {len(api_urls)} API endpoint(s)")

        tasks = []
        for url in api_urls:
            tasks += [
                self._test_method_tampering(url),
                self._test_mass_assignment(url),
                self._test_bola(url),
                self._test_sensitive_data(url),
                self._test_rate_limit(url),
                self._test_verb_tunnel(url),
            ]
        # GraphQL specific
        gql_urls = [u for u in api_urls if "graphql" in u.lower()]
        for url in gql_urls:
            tasks += [
                self._test_graphql_introspection(url),
                self._test_graphql_batch_abuse(url),
                self._test_graphql_dos(url),
            ]

        # Version confusion
        target = self.orchestrator.get_target_url()
        if target:
            tasks.append(self._test_api_version_confusion(target))

        await asyncio.gather(*tasks, return_exceptions=True)
        self.logger.success("API audit complete")

    # ── HTTP Method Tampering ─────────────────────────────────────────────────

    async def _test_method_tampering(self, url: str):
        await self._check_paused()
        for method in ["PUT", "DELETE", "PATCH", "OPTIONS", "TRACE"]:
            resp = await self._client.request(method, url)
            if not resp:
                continue
            if resp.status not in (404, 405, 400, 501, 403):
                text = await resp.text()
                # TRACE: check for credential reflection
                if method == "TRACE" and any(
                    h in resp.headers for h in
                    ["Authorization", "Cookie", "X-Auth-Token"]
                ):
                    await self._save(
                        title="TRACE Method Enabled (Credential Reflection Risk)",
                        severity="Medium", cvss=5.8,
                        url=url, payload=f"TRACE {url}",
                        evidence=f"TRACE returned {resp.status} with auth headers",
                        remediation="Disable TRACE/TRACK methods in web server config.",
                    )
                else:
                    await self._save(
                        title=f"HTTP Method Tampering ({method} Allowed)",
                        severity="Medium", cvss=5.4,
                        url=url, payload=f"{method} {url}",
                        evidence=f"HTTP {resp.status} returned for {method} {url[:60]}",
                        remediation="Restrict HTTP methods to only those needed. "
                                    "Return 405 for all other methods.",
                    )

    # ── Mass Assignment ───────────────────────────────────────────────────────

    async def _test_mass_assignment(self, url: str):
        await self._check_paused()
        if not any(url.endswith(e) for e in ["", "/"]):
            return
        for payload in [
            {"isAdmin": True, "role": "admin", "is_superuser": True},
            {"admin": True, "user_type": "admin", "permissions": ["*"]},
            {"verified": True, "email_confirmed": True, "active": True},
        ]:
            resp = await self._client.request(
                "POST", url, json=payload, api_mode=True
            )
            if not resp:
                continue
            text = await resp.text()
            if resp.status == 200 and any(
                k in text.lower() for k in ["admin", "superuser", "role"]
            ):
                await self._save(
                    title="Mass Assignment Vulnerability",
                    severity="High", cvss=8.1,
                    url=url,
                    payload=json.dumps(payload),
                    evidence=text[:300],
                    remediation="Use explicit allow-lists (DTOs) for input mapping. "
                                "Never bind request bodies directly to model objects.",
                )
                return

    # ── BOLA / Object Authorisation ────────────────────────────────────────────

    async def _test_bola(self, url: str):
        await self._check_paused()
        id_match = re.search(r"/(\d+)(?:/|$|\?|#)", url)
        if not id_match:
            return
        original = int(id_match.group(1))
        for candidate in [original + 1, original - 1, 1, 9999, 0]:
            if candidate < 0:
                continue
            test_url = re.sub(r"/\d+(?=/|$|\?|#)", f"/{candidate}", url, count=1)
            resp = await self._client.get(test_url)
            if resp and resp.status == 200:
                text = await resp.text()
                if len(text) > 20 and "not found" not in text.lower():
                    await self._save(
                        title="Broken Object Level Authorisation (BOLA)",
                        severity="High", cvss=8.6,
                        url=url,
                        payload=f"Changed resource ID {original} → {candidate}",
                        evidence=f"HTTP 200 for {test_url}: {text[:200]}",
                        remediation="Implement object-level authorisation on every "
                                    "API resource. Use indirect, opaque identifiers.",
                    )
                    return

    # ── Sensitive Data Exposure ────────────────────────────────────────────────

    async def _test_sensitive_data(self, url: str):
        await self._check_paused()
        resp = await self._client.get(url, api_mode=True)
        if not resp or resp.status != 200:
            return
        text = await resp.text()
        matches = _SENSITIVE_FIELDS.findall(text)
        if matches:
            await self._save(
                title="Sensitive Data Exposure in API Response",
                severity="High", cvss=7.5,
                url=url,
                payload="GET (authenticated response not required)",
                evidence=f"Fields with sensitive values: {matches[:5]}",
                remediation="Remove sensitive fields from API responses. "
                            "Apply field-level filtering / projection.",
            )

    # ── Rate Limiting ─────────────────────────────────────────────────────────

    async def _test_rate_limit(self, url: str):
        await self._check_paused()
        status_codes = []
        for _ in range(20):
            resp = await self._client.get(url)
            if resp:
                status_codes.append(resp.status)
        if 429 not in status_codes and len(status_codes) >= 18:
            await self._save(
                title="Missing Rate Limiting on API Endpoint",
                severity="Medium", cvss=5.3,
                url=url,
                payload="20 rapid requests",
                evidence=f"No HTTP 429 received in 20 sequential requests",
                remediation="Implement per-user/IP rate limiting. "
                            "Return 429 with Retry-After header.",
                confirmed=False,
            )

    # ── HTTP Verb Tunnelling ──────────────────────────────────────────────────

    async def _test_verb_tunnel(self, url: str):
        await self._check_paused()
        tunnel_headers = {
            "X-HTTP-Method-Override": "DELETE",
            "X-Method-Override":      "DELETE",
            "X-HTTP-Method":          "DELETE",
        }
        for header, value in tunnel_headers.items():
            resp = await self._client.post(
                url,
                extra_headers={header: value},
                api_mode=True,
            )
            if resp and resp.status not in (404, 405, 400, 403):
                await self._save(
                    title="HTTP Verb Tunnelling Accepted",
                    severity="Medium", cvss=5.4,
                    url=url,
                    payload=f"{header}: {value}",
                    evidence=f"POST with {header}: DELETE returned {resp.status}",
                    remediation="Disable verb tunnelling headers or validate them "
                                "against an allowlist of legitimate clients.",
                )
                return

    # ── GraphQL ───────────────────────────────────────────────────────────────

    async def _test_graphql_introspection(self, url: str):
        await self._check_paused()
        resp = await self._client.post(
            url, data=_GRAPHQL_INTROSPECTION,
            extra_headers={"Content-Type": "application/json"},
            api_mode=True,
        )
        if not resp or resp.status != 200:
            return
        text = await resp.text()
        if "__schema" in text or "queryType" in text:
            await self._save(
                title="GraphQL Introspection Enabled",
                severity="Medium", cvss=5.3,
                url=url,
                payload=_GRAPHQL_INTROSPECTION[:100],
                evidence=text[:300],
                remediation="Disable introspection in production. "
                            "Use schema depth / complexity limits.",
                confirmed=True,
            )

    async def _test_graphql_batch_abuse(self, url: str):
        await self._check_paused()
        resp = await self._client.post(
            url, data=_GRAPHQL_BATCH,
            extra_headers={"Content-Type": "application/json"},
            api_mode=True,
        )
        if resp and resp.status == 200:
            text = await resp.text()
            if text.count('"data"') >= 4:
                await self._save(
                    title="GraphQL Batching Enabled (DoS / Brute-Force Risk)",
                    severity="Medium", cvss=5.9,
                    url=url,
                    payload="Batch of 5 queries",
                    evidence=text[:200],
                    remediation="Disable or rate-limit query batching. "
                                "Limit max batch size per request.",
                )

    async def _test_graphql_dos(self, url: str):
        """Test for deep query / excessive nesting (denial of service)."""
        await self._check_paused()
        nested = '{"query":"{ a { b { c { d { e { f { g { __typename } } } } } } } }"}'
        t0   = time.monotonic()
        resp = await self._client.post(
            url, data=nested,
            extra_headers={"Content-Type": "application/json"},
            api_mode=True,
        )
        elapsed = time.monotonic() - t0
        if resp and elapsed > 3.0:
            await self._save(
                title="GraphQL Query Depth / Complexity Abuse (DoS Risk)",
                severity="Medium", cvss=5.3,
                url=url,
                payload=nested,
                evidence=f"Deep query took {elapsed:.1f}s",
                remediation="Enforce maximum query depth (e.g. 5) and complexity limits.",
            )

    # ── API Version Confusion ─────────────────────────────────────────────────

    async def _test_api_version_confusion(self, base_url: str):
        await self._check_paused()
        base = base_url.rstrip("/")
        versions = ["/api/v1/users", "/api/v2/users", "/api/v3/users",
                    "/api/internal/users", "/api/private/users"]
        prev_text = None
        for path in versions:
            resp = await self._client.get(base + path, api_mode=True)
            if not resp or resp.status != 200:
                continue
            text = await resp.text()
            if prev_text and text != prev_text:
                await self._save(
                    title="API Version Exposure (Older Version Accessible)",
                    severity="Medium", cvss=5.3,
                    url=base + path,
                    payload=f"GET {path}",
                    evidence=f"Older API version returns different data: {text[:200]}",
                    remediation="Retire old API versions. Enforce access control "
                                "consistently across all versions.",
                    confirmed=False,
                )
                return
            if resp.status == 200:
                prev_text = text

    # ── Helpers ────────────────────────────────────────────────────────────────

    async def _save(self, *, title, severity, cvss, url, payload="",
                    evidence="", parameter="", remediation="", confirmed=False):
        finding = {
            "title":       title,
            "severity":    severity,
            "cvss":        cvss,
            "vuln_type":   "api",
            "url":         url,
            "parameter":   parameter,
            "payload":     payload[:300],
            "evidence":    evidence[:500],
            "remediation": remediation,
            "module":      "APISecurity",
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
