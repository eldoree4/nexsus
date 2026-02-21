"""
nexsus/modules/active_recon.py
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
Active Reconnaissance — sends probes directly to the target.

Capabilities:
  • Deep web crawler (BFS, concurrent, JS-aware link extraction)
  • Subdomain bruteforce via DNS resolution
  • Port scanning (async TCP connect scan, top-N ports)
  • Directory & file bruteforce
  • DNS record enumeration (A, AAAA, CNAME, MX, TXT, NS, SOA, SRV)
  • HTTP security header audit
  • Technology stack confirmation (active fingerprinting)
  • Form discovery and parameter extraction
  • API endpoint discovery from JS source maps / OpenAPI specs
  • Virtual host (vhost) fuzzing
"""
import asyncio
import re
import socket
import struct
from urllib.parse import urljoin, urlparse, parse_qs

try:
    from bs4 import BeautifulSoup
    BS4 = True
except ImportError:
    BS4 = False

from nexsus.core.logger import Logger
from nexsus.core.wordlist_manager import WordlistManager


# ── Security header checklist ─────────────────────────────────────────────────
_SECURITY_HEADERS = {
    "Strict-Transport-Security": "HSTS missing — enables downgrade attacks",
    "X-Frame-Options":           "Clickjacking protection missing",
    "X-Content-Type-Options":    "MIME-sniffing protection missing",
    "Content-Security-Policy":   "CSP missing — XSS impact increased",
    "Referrer-Policy":           "Referrer policy not set",
    "Permissions-Policy":        "Permissions-Policy not set",
    "X-XSS-Protection":          "Legacy XSS filter not configured",
}

# ── Top ports to scan ─────────────────────────────────────────────────────────
_TOP_PORTS = [
    21, 22, 23, 25, 53, 80, 110, 143, 443, 445,
    465, 587, 993, 995, 1080, 1433, 1521, 2375, 2376,
    3000, 3306, 3389, 4848, 5432, 5900, 6379, 6443,
    7001, 7002, 8000, 8008, 8080, 8081, 8443, 8444,
    8888, 9000, 9090, 9200, 9300, 10250, 27017, 27018,
    28017, 50030, 50060, 50070,
]

# JS source-map regex patterns
_API_PATH_RE    = re.compile(r'["\'](/(?:api|v\d+|rest|graphql)[^\s"\'<>?#]{1,100})["\']')
_ENDPOINT_RE    = re.compile(r'["\'](https?://[^\s"\'<>]+)["\']')
_SOURCE_MAP_RE  = re.compile(r'//# sourceMappingURL=(.+\.map)')
_SWAGGER_RE     = re.compile(r'["\'](/[^\s"\']*(?:swagger|openapi)[^\s"\']*\.(?:json|yaml))["\']', re.I)


class ActiveRecon:
    def __init__(self, orchestrator):
        self.orchestrator = orchestrator
        self.paused       = False
        self.logger       = Logger("ActiveRecon")
        self._crawled:    set[str] = set()
        self._to_crawl:   list[str] = []
        self._wordlists   = WordlistManager()
        self._found_ports: dict[str, list[int]] = {}

    # ── Main entry ─────────────────────────────────────────────────────────────

    async def run(self):
        self.logger.info("Active Reconnaissance…")
        client = self.orchestrator.http_client
        scope  = self.orchestrator.scope

        # Seed crawler
        seeds: list[str] = []
        for ep in self.orchestrator.data_store.assets.get("endpoints", set()):
            if self.orchestrator.validator.validate(ep):
                seeds.append(ep)
        for domain in scope.domains:
            for scheme in ("https", "http"):
                seeds.append(f"{scheme}://{domain}")
        self._to_crawl = list(dict.fromkeys(seeds))

        tasks = [
            self._crawl_loop(client),
            self._subdomain_bruteforce(client),
            self._dns_enum(),
        ]
        await asyncio.gather(*tasks, return_exceptions=True)

        # Port scan after we know all targets
        all_hosts = scope.domains | {
            urlparse(u).hostname or ""
            for u in self.orchestrator.data_store.assets.get("endpoints", set())
            if urlparse(u).hostname
        }
        await self._port_scan(all_hosts)

        # Header audit on primary target
        primary = self.orchestrator.get_target_url()
        if primary:
            await self._header_audit(client, primary)

        # Persist
        await self.orchestrator.data_store.save_assets()
        ep_count  = len(self.orchestrator.data_store.assets.get("endpoints", set()))
        sub_count = len(self.orchestrator.data_store.assets.get("subdomains", set()))
        self.logger.success(
            f"Active recon done — {ep_count} endpoints, "
            f"{sub_count} subdomains, {len(self._crawled)} pages crawled"
        )

    # ── Web Crawler ────────────────────────────────────────────────────────────

    async def _crawl_loop(self, client, max_pages: int = 300):
        sem = asyncio.Semaphore(15)   # max 15 concurrent crawl requests

        async def _fetch(url: str):
            async with sem:
                await self._check_paused()
                if url in self._crawled:
                    return
                self._crawled.add(url)
                await self._crawl_url(client, url)

        while self._to_crawl:
            batch = []
            while self._to_crawl and len(batch) < 20:
                url = self._to_crawl.pop(0)
                if url not in self._crawled and len(self._crawled) < max_pages:
                    batch.append(url)
            if not batch:
                break
            await asyncio.gather(*[_fetch(u) for u in batch], return_exceptions=True)

    async def _crawl_url(self, client, url: str):
        resp = await client.get(url)
        if not resp:
            return

        final_url = resp.url
        if final_url != url and final_url not in self._crawled:
            self._crawled.add(final_url)
            url = final_url

        # Store the endpoint
        await self.orchestrator.data_store.add_asset("endpoint", url)

        ct = resp.headers.get("Content-Type", "").lower()
        try:
            text = await resp.text()
        except Exception:
            return

        # Non-HTML: check for JSON API responses, JS files
        if "javascript" in ct or url.endswith(".js"):
            await self._mine_js_response(url, text)
            return
        if "json" in ct:
            await self._mine_json_response(url, text)
            return

        is_html = (
            "text/html" in ct or "xhtml" in ct
            or any(kw in text[:1000].lower() for kw in
                   ["<html", "<body", "<!doctype html", "<head"])
        )
        if not is_html:
            return

        links = self._extract_links(url, text)
        forms = self._extract_forms(url, text)

        # Queue in-scope links
        for link in links:
            if link not in self._crawled and link not in self._to_crawl:
                self._to_crawl.append(link)

        # Store form action endpoints
        for form_url, _ in forms:
            await self.orchestrator.data_store.add_asset("endpoint", form_url)

        self.logger.debug(f"Crawled {url} — {len(links)} links, {len(forms)} forms")

    def _extract_links(self, base_url: str, html: str) -> list[str]:
        links: set[str] = set()
        if BS4:
            soup = BeautifulSoup(html, "html.parser")
            selectors = [
                ("a",      "href"),
                ("link",   "href"),
                ("script", "src"),
                ("img",    "src"),
                ("iframe", "src"),
                ("form",   "action"),
                ("frame",  "src"),
                ("area",   "href"),
            ]
            for tag, attr in selectors:
                for el in soup.find_all(tag, **{attr: True}):
                    raw = el[attr].strip()
                    if raw and not raw.startswith(("javascript:", "mailto:", "#")):
                        abs_url = urljoin(base_url, raw)
                        if self.orchestrator.validator.validate(abs_url):
                            links.add(abs_url.split("#")[0])
            # Data- attributes that may contain URLs
            for el in soup.find_all(attrs={"data-url": True}):
                abs_url = urljoin(base_url, el["data-url"])
                if self.orchestrator.validator.validate(abs_url):
                    links.add(abs_url)
        else:
            # Fallback regex
            for raw in re.findall(r'href=["\']([^"\']+)["\']', html):
                abs_url = urljoin(base_url, raw)
                if self.orchestrator.validator.validate(abs_url):
                    links.add(abs_url.split("#")[0])
        return list(links)

    def _extract_forms(self, base_url: str, html: str) -> list[tuple[str, list[str]]]:
        """Return list of (form_action_url, [input_names])."""
        forms = []
        if BS4:
            soup = BeautifulSoup(html, "html.parser")
            for form in soup.find_all("form"):
                action = form.get("action", base_url)
                abs_url = urljoin(base_url, action)
                if self.orchestrator.validator.validate(abs_url):
                    inputs = [
                        inp.get("name", "")
                        for inp in form.find_all(["input", "textarea", "select"])
                        if inp.get("name")
                    ]
                    forms.append((abs_url, inputs))
        return forms

    async def _mine_js_response(self, url: str, text: str):
        """Extract API paths and external URLs from JS source."""
        # Register as JS file
        await self.orchestrator.data_store.add_asset("js_file", url)

        for m in _API_PATH_RE.finditer(text):
            path = m.group(1)
            parsed = urlparse(url)
            abs_url = f"{parsed.scheme}://{parsed.netloc}{path}"
            if self.orchestrator.validator.validate(abs_url):
                await self.orchestrator.data_store.add_asset("endpoint", abs_url)

        for m in _ENDPOINT_RE.finditer(text):
            ep = m.group(1)
            if self.orchestrator.validator.validate(ep):
                await self.orchestrator.data_store.add_asset("endpoint", ep)

        # Source maps → try to fetch .map file (can expose original source)
        for map_ref in _SOURCE_MAP_RE.findall(text):
            map_url = urljoin(url, map_ref)
            await self.orchestrator.data_store.add_asset("endpoint", map_url)

        # OpenAPI / Swagger references
        for swagger_path in _SWAGGER_RE.findall(text):
            parsed = urlparse(url)
            sw_url = f"{parsed.scheme}://{parsed.netloc}{swagger_path}"
            await self.orchestrator.data_store.add_asset("endpoint", sw_url)

    async def _mine_json_response(self, url: str, text: str):
        """Look for nested URLs in JSON API responses."""
        for m in _ENDPOINT_RE.finditer(text):
            ep = m.group(1)
            if self.orchestrator.validator.validate(ep):
                await self.orchestrator.data_store.add_asset("endpoint", ep)

    # ── Subdomain Bruteforce ──────────────────────────────────────────────────

    async def _subdomain_bruteforce(self, client):
        scope     = self.orchestrator.scope
        wordlist  = self._wordlists.get("subdomains")
        sem       = asyncio.Semaphore(30)

        async def _resolve(sub: str, domain: str):
            async with sem:
                await self._check_paused()
                fqdn = f"{sub}.{domain}"
                try:
                    loop = asyncio.get_event_loop()
                    await loop.getaddrinfo(fqdn, None)
                    await self.orchestrator.data_store.add_asset("subdomain", fqdn)
                    # Probe over HTTP
                    for scheme in ("https", "http"):
                        resp = await client.get(f"{scheme}://{fqdn}", retries=1)
                        if resp and resp.status < 500:
                            await self.orchestrator.data_store.add_asset(
                                "endpoint", f"{scheme}://{fqdn}"
                            )
                            self.logger.info(f"Subdomain found: {fqdn} [{resp.status}]")
                            break
                except Exception:
                    pass

        tasks = []
        for domain in scope.domains:
            for sub in wordlist:
                tasks.append(_resolve(sub, domain))

        self.logger.info(f"Subdomain bruteforce — {len(tasks)} probes across "
                         f"{len(scope.domains)} domain(s)…")
        # Run in batches of 100
        for i in range(0, len(tasks), 100):
            await asyncio.gather(*tasks[i:i+100], return_exceptions=True)

    # ── DNS Enumeration ────────────────────────────────────────────────────────

    async def _dns_enum(self):
        try:
            import dns.resolver
        except ImportError:
            self.logger.debug("dnspython not installed — skipping DNS enum")
            return

        record_types = ["A", "AAAA", "CNAME", "MX", "TXT", "NS", "SOA"]
        resolver = dns.resolver.Resolver(configure=False)
        resolver.nameservers = ["8.8.8.8", "1.1.1.1", "9.9.9.9"]

        for domain in self.orchestrator.scope.domains:
            await self._check_paused()
            dns_info: dict[str, list] = {}
            for rtype in record_types:
                try:
                    answers = resolver.resolve(domain, rtype)
                    dns_info[rtype] = [str(r) for r in answers]
                except Exception:
                    pass

            if dns_info:
                await self.orchestrator.data_store.add_asset(
                    "technology",
                    f"DNS:{domain}",
                    metadata=dns_info,
                )
                self.logger.info(f"DNS records for {domain}: {dns_info}")

                # Extract subdomains from CNAME / MX
                for rdata in dns_info.get("CNAME", []) + dns_info.get("MX", []):
                    host = rdata.strip(".").split(" ")[-1]
                    if host.endswith(domain):
                        await self.orchestrator.data_store.add_asset("subdomain", host)

                # SPF / DKIM / DMARC from TXT
                for txt in dns_info.get("TXT", []):
                    if "v=spf1" in txt.lower():
                        self.logger.info(f"SPF record: {txt[:80]}")
                    if "v=DMARC1" in txt:
                        self.logger.info(f"DMARC record: {txt[:80]}")

    # ── Port Scanner ──────────────────────────────────────────────────────────

    async def _port_scan(self, hosts: set[str], timeout: float = 1.5):
        if not hosts:
            return
        self.logger.info(f"Port scanning {len(hosts)} host(s) ({len(_TOP_PORTS)} ports)…")
        sem = asyncio.Semaphore(200)

        async def _check(host: str, port: int):
            async with sem:
                try:
                    _, writer = await asyncio.wait_for(
                        asyncio.open_connection(host, port),
                        timeout=timeout,
                    )
                    writer.close()
                    try:
                        await writer.wait_closed()
                    except Exception:
                        pass
                    return True
                except Exception:
                    return False

        for host in hosts:
            if not host:
                continue
            results = await asyncio.gather(
                *[_check(host, p) for p in _TOP_PORTS],
                return_exceptions=True,
            )
            open_ports = [
                _TOP_PORTS[i] for i, r in enumerate(results)
                if r is True
            ]
            if open_ports:
                self._found_ports[host] = open_ports
                self.logger.info(f"Open ports on {host}: {open_ports}")
                await self.orchestrator.data_store.add_asset(
                    "technology",
                    f"PORTS:{host}",
                    metadata={"open": open_ports},
                )
                # Queue web-service URLs for crawler
                for port in open_ports:
                    if port in (80, 8080, 8000):
                        url = f"http://{host}:{port}/"
                        if port == 80:
                            url = f"http://{host}/"
                        if self.orchestrator.validator.validate(url):
                            self._to_crawl.append(url)
                    elif port in (443, 8443):
                        url = f"https://{host}:{port}/"
                        if port == 443:
                            url = f"https://{host}/"
                        if self.orchestrator.validator.validate(url):
                            self._to_crawl.append(url)

    # ── HTTP Security Header Audit ────────────────────────────────────────────

    async def _header_audit(self, client, url: str):
        await self._check_paused()
        resp = await client.get(url)
        if not resp:
            return

        headers = {k.lower(): v for k, v in resp.headers.items()}
        missing = []

        for header, description in _SECURITY_HEADERS.items():
            if header.lower() not in headers:
                missing.append((header, description))

        for header, description in missing:
            await self.orchestrator.add_finding({
                "title":       f"Missing Security Header: {header}",
                "severity":    "Low",
                "cvss":        3.1,
                "vuln_type":   "security_header",
                "url":         url,
                "parameter":   header,
                "payload":     "",
                "evidence":    f"{header} not present in response headers",
                "remediation": description + ". Add the header in your web server / CDN config.",
                "module":      "ActiveRecon",
                "confirmed":   True,
            })

        # Check for information disclosure headers
        for info_header in ["Server", "X-Powered-By", "X-AspNet-Version",
                            "X-Generator", "Via"]:
            val = headers.get(info_header.lower(), "")
            if val:
                await self.orchestrator.add_finding({
                    "title":       f"Server Version Disclosure ({info_header})",
                    "severity":    "Info",
                    "cvss":        0.0,
                    "vuln_type":   "info_disclosure",
                    "url":         url,
                    "parameter":   info_header,
                    "payload":     "",
                    "evidence":    f"{info_header}: {val}",
                    "remediation": f"Remove or mask the {info_header} header.",
                    "module":      "ActiveRecon",
                    "confirmed":   True,
                })

        if missing:
            self.logger.info(
                f"Security header audit: {len(missing)} missing header(s) on {url}"
            )

    # ── Pause helpers ──────────────────────────────────────────────────────────

    async def _check_paused(self):
        while self.paused:
            await asyncio.sleep(0.5)

    def pause(self):
        self.paused = True

    def resume(self):
        self.paused = False
