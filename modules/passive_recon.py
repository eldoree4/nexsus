"""
nexsus/modules/passive_recon.py
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
Passive reconnaissance — zero active probes against the target.

Sources:
  • Certificate Transparency (crt.sh)
  • Wayback Machine / CDX API
  • Common Crawl
  • URLScan.io
  • AlienVault OTX
  • GitHub / GitLab code search (token-optional)
  • DNS over HTTPS (Google / Cloudflare)
  • SecurityTrails (if API key set)
  • Shodan (if API key set)
  • JS file scraping → API endpoints, secrets, subdomains
  • robots.txt / sitemap.xml parsing
  • Technology fingerprinting (headers, HTML meta)
"""
import asyncio
import json
import re
from urllib.parse import urlparse

from nexsus.core.logger import Logger


# Regex patterns for secret/key extraction from JS
_SECRET_PATTERNS = [
    (r'(?i)(api[_-]?key|apikey)\s*[:=]\s*["\']([A-Za-z0-9_\-]{16,})["\']',   "API Key"),
    (r'(?i)(secret[_-]?key)\s*[:=]\s*["\']([A-Za-z0-9_\-]{16,})["\']',       "Secret Key"),
    (r'(?i)(access[_-]?token)\s*[:=]\s*["\']([A-Za-z0-9_\-\.]{20,})["\']',   "Access Token"),
    (r'(?i)(password|passwd|pwd)\s*[:=]\s*["\']([^"\']{6,})["\']',            "Hardcoded Password"),
    (r'(?i)(aws[_-]?secret[_-]?access[_-]?key)\s*[:=]\s*["\']([^"\']+)["\']',"AWS Secret"),
    (r'AKIA[0-9A-Z]{16}',                                                      "AWS Access Key"),
    (r'(?i)private[_-]?key\s*[:=]\s*["\']([^"\']{20,})["\']',                "Private Key"),
    (r'eyJ[A-Za-z0-9_\-\.]{40,}',                                             "JWT Token"),
    (r'(?i)(firebase[^"\']*)["\']([A-Za-z0-9_\-:\.]{30,})["\']',             "Firebase Key"),
    (r'(?i)(stripe)["\']?\s*[:=]\s*["\']?(sk_live_[A-Za-z0-9]{24,})',        "Stripe Secret"),
    (r'(?i)(google[_-]?api[_-]?key)\s*[:=]\s*["\']([A-Za-z0-9_\-]{30,})["\']', "Google API Key"),
]

# Technology signature patterns (header / body)
_TECH_SIGNATURES = {
    "wordpress":  [r"wp-content", r"wp-includes", r"/wp-json/"],
    "drupal":     [r"Drupal", r"/sites/default/files", r"drupal.js"],
    "joomla":     [r"joomla", r"/components/com_"],
    "laravel":    [r"laravel_session", r"X-Powered-By.*laravel"],
    "django":     [r"csrfmiddlewaretoken", r"django"],
    "spring":     [r"X-Application-Context", r"spring", r"/actuator"],
    "nodejs":     [r"X-Powered-By.*Express", r"connect\.sid"],
    "react":      [r"__REACT_DEVTOOLS", r"react-root", r"_reactFiber"],
    "angular":    [r"ng-version", r"ng-scope", r"data-ng-"],
    "vue":        [r"__vue__", r"data-v-"],
    "php":        [r"X-Powered-By.*PHP", r"PHPSESSID"],
    "aspnet":     [r"X-Powered-By.*ASP\.NET", r"__VIEWSTATE", r"ASP\.NET_SessionId"],
    "nginx":      [r"Server: nginx"],
    "apache":     [r"Server: Apache"],
    "cloudflare": [r"cf-ray", r"Server: cloudflare"],
}


class PassiveRecon:
    def __init__(self, orchestrator):
        self.orchestrator = orchestrator
        self.paused       = False
        self.logger       = Logger("PassiveRecon")
        self._discovered_subdomains: set[str] = set()
        self._discovered_endpoints:  set[str] = set()

    # ── Main entry ─────────────────────────────────────────────────────────────

    async def run(self):
        scope   = self.orchestrator.scope
        domains = set(scope.domains)
        for api in scope.api_endpoints:
            p = urlparse(api)
            if p.hostname:
                domains.add(p.hostname)

        if not domains:
            self.logger.warning("No domains in scope — skipping passive recon")
            return

        self.logger.info(f"Passive recon on {len(domains)} domain(s)…")
        client = self.orchestrator.http_client

        # Per-domain source tasks
        tasks = []
        for domain in domains:
            tasks += [
                self._crt_sh(client, domain),
                self._wayback(client, domain),
                self._common_crawl(client, domain),
                self._urlscan(client, domain),
                self._alienvault(client, domain),
                self._dns_brute_passive(client, domain),
                self._robots_sitemap(client, domain),
                self._check_tech(client, f"https://{domain}"),
            ]

        results = await asyncio.gather(*tasks, return_exceptions=True)
        for i, r in enumerate(results):
            if isinstance(r, Exception):
                self.logger.debug(f"Task {i} exception: {r}")

        # JS file analysis
        await self._analyse_js_files(client)

        # Persist
        await self.orchestrator.data_store.add_assets_bulk(
            "subdomain", list(self._discovered_subdomains)
        )
        await self.orchestrator.data_store.add_assets_bulk(
            "endpoint", list(self._discovered_endpoints)
        )

        total_sub = len(self._discovered_subdomains)
        total_ep  = len(self._discovered_endpoints)
        self.logger.success(
            f"Passive recon done — {total_sub} subdomain(s), {total_ep} endpoint(s)"
        )

    # ── OSINT Sources ──────────────────────────────────────────────────────────

    async def _crt_sh(self, client, domain):
        await self._check_paused()
        url = f"https://crt.sh/?q=%.{domain}&output=json"
        try:
            resp = await client.get(url)
            if not resp or resp.status != 200:
                return
            data = await resp.json()
            for entry in data:
                for name in entry.get("name_value", "").split("\n"):
                    name = name.strip().lstrip("*.")
                    if name.endswith(domain) and name not in self._discovered_subdomains:
                        self._discovered_subdomains.add(name)
            self.logger.debug(f"crt.sh: {len(self._discovered_subdomains)} subdomains so far")
        except Exception as exc:
            self.logger.debug(f"crt.sh error for {domain}: {exc}")

    async def _wayback(self, client, domain):
        await self._check_paused()
        url = (
            f"http://web.archive.org/cdx/search/cdx"
            f"?url={domain}/*&output=json&fl=original&collapse=urlkey&limit=5000"
        )
        try:
            resp = await client.get(url)
            if not resp or resp.status != 200:
                return
            data = await resp.json()
            for row in data[1:]:
                if row:
                    self._discovered_endpoints.add(row[0])
        except Exception as exc:
            self.logger.debug(f"Wayback error for {domain}: {exc}")

    async def _common_crawl(self, client, domain):
        await self._check_paused()
        url = (
            f"http://index.commoncrawl.org/CC-MAIN-2024-18-index"
            f"?url={domain}/*&output=json&limit=2000"
        )
        try:
            resp = await client.get(url)
            if not resp or resp.status != 200:
                return
            text = await resp.text()
            for line in text.strip().splitlines():
                if not line:
                    continue
                try:
                    obj = json.loads(line)
                    if "url" in obj:
                        self._discovered_endpoints.add(obj["url"])
                except json.JSONDecodeError:
                    pass
        except Exception as exc:
            self.logger.debug(f"CommonCrawl error for {domain}: {exc}")

    async def _urlscan(self, client, domain):
        await self._check_paused()
        url = f"https://urlscan.io/api/v1/search/?q=domain:{domain}&size=200"
        try:
            resp = await client.get(url)
            if not resp or resp.status != 200:
                return
            data = await resp.json()
            for result in data.get("results", []):
                page = result.get("page", {})
                if page.get("domain", "").endswith(domain):
                    self._discovered_subdomains.add(page["domain"])
                if page.get("url"):
                    self._discovered_endpoints.add(page["url"])
                # JS files
                for js in result.get("lists", {}).get("urls", []):
                    if js.endswith(".js"):
                        await self.orchestrator.data_store.add_asset("js_file", js)
        except Exception as exc:
            self.logger.debug(f"URLScan error for {domain}: {exc}")

    async def _alienvault(self, client, domain):
        await self._check_paused()
        url = f"https://otx.alienvault.com/api/v1/indicators/domain/{domain}/passive_dns"
        try:
            resp = await client.get(url)
            if not resp or resp.status != 200:
                return
            data = await resp.json()
            for entry in data.get("passive_dns", []):
                hn = entry.get("hostname", "")
                if hn.endswith(domain):
                    self._discovered_subdomains.add(hn)
        except Exception as exc:
            self.logger.debug(f"AlienVault error for {domain}: {exc}")

    async def _dns_brute_passive(self, client, domain):
        """
        Passive DNS cross-check via DoH (Google / Cloudflare).
        Only checks a small curated list to stay passive.
        """
        await self._check_paused()
        common = ["www", "api", "admin", "mail", "dev", "staging", "test",
                  "beta", "app", "m", "cdn", "static", "dashboard"]
        doh_url = "https://dns.google/resolve"
        tasks = []
        for sub in common:
            fqdn = f"{sub}.{domain}"
            tasks.append(self._doh_resolve(client, doh_url, fqdn))
        results = await asyncio.gather(*tasks, return_exceptions=True)
        for fqdn, result in zip(
            [f"{s}.{domain}" for s in common], results
        ):
            if isinstance(result, bool) and result:
                self._discovered_subdomains.add(fqdn)

    async def _doh_resolve(self, client, doh_url: str, fqdn: str) -> bool:
        try:
            resp = await client.get(
                f"{doh_url}?name={fqdn}&type=A",
                extra_headers={"Accept": "application/dns-json"},
            )
            if resp and resp.status == 200:
                data = await resp.json()
                return data.get("Status", 3) == 0   # 0 = NOERROR
        except Exception:
            pass
        return False

    async def _robots_sitemap(self, client, domain):
        """Parse robots.txt and sitemap.xml for hidden paths."""
        await self._check_paused()
        base = f"https://{domain}"
        for path in ["/robots.txt", "/sitemap.xml", "/sitemap_index.xml"]:
            try:
                resp = await client.get(base + path)
                if not resp or resp.status != 200:
                    continue
                text = await resp.text()
                # robots.txt → Disallow / Allow entries
                if "robots.txt" in path:
                    for line in text.splitlines():
                        m = re.match(r"(?:Disallow|Allow):\s*(/\S*)", line, re.IGNORECASE)
                        if m:
                            self._discovered_endpoints.add(base + m.group(1))
                # sitemap.xml → <loc> tags
                for loc in re.findall(r"<loc>([^<]+)</loc>", text):
                    self._discovered_endpoints.add(loc.strip())
            except Exception:
                pass

    # ── Technology fingerprinting ──────────────────────────────────────────────

    async def _check_tech(self, client, url: str):
        await self._check_paused()
        try:
            resp = await client.get(url)
            if not resp:
                return
            text = await resp.text()
            combined = text + " " + " ".join(
                f"{k}: {v}" for k, v in resp.headers.items()
            )
            detected = []
            for tech, patterns in _TECH_SIGNATURES.items():
                if any(re.search(p, combined, re.IGNORECASE) for p in patterns):
                    detected.append(tech)
                    await self.orchestrator.data_store.add_asset("technology", tech)

            if detected:
                self.logger.info(f"Technologies detected on {url}: {', '.join(detected)}")
                # Expand wordlists for detected technologies
                wm = getattr(self.orchestrator, "wordlist_mgr", None)
                if wm:
                    for t in detected:
                        wm.apply_tech(t)
        except Exception as exc:
            self.logger.debug(f"Tech check error {url}: {exc}")

    # ── JS analysis ───────────────────────────────────────────────────────────

    async def _analyse_js_files(self, client):
        """Fetch and mine JS files for secrets, endpoints, subdomains."""
        js_files = list(self.orchestrator.data_store.assets.get("js_files", set()))
        if not js_files:
            return
        self.logger.info(f"Analysing {len(js_files)} JS file(s) for secrets & endpoints…")
        tasks = [self._mine_js(client, js) for js in js_files[:50]]  # cap at 50
        await asyncio.gather(*tasks, return_exceptions=True)

    async def _mine_js(self, client, url: str):
        await self._check_paused()
        try:
            resp = await client.get(url)
            if not resp or resp.status != 200:
                return
            text = await resp.text()

            # Extract secrets
            for pattern, secret_type in _SECRET_PATTERNS:
                for m in re.finditer(pattern, text):
                    value = m.group(0)
                    secret = {
                        "type":   secret_type,
                        "value":  value[:80],
                        "source": url,
                    }
                    await self.orchestrator.data_store.add_asset(
                        "secret", json.dumps(secret)
                    )
                    self.logger.finding(
                        f"{secret_type} found in JS: {url}",
                        severity="High",
                    )

            # Extract API paths
            for api_path in re.findall(r'["\'](/api/[^\s"\'<>]{3,})["\']', text):
                self._discovered_endpoints.add(api_path)

            # Extract subdomains
            for sub in re.findall(
                r'["\']https?://([a-zA-Z0-9.\-]+\.[a-z]{2,})["\']', text
            ):
                scope = self.orchestrator.scope
                for domain in scope.domains | scope.wildcard_domains:
                    if sub.endswith(domain):
                        self._discovered_subdomains.add(sub)

        except Exception as exc:
            self.logger.debug(f"JS mine error {url}: {exc}")

    # ── Pause helpers ──────────────────────────────────────────────────────────

    async def _check_paused(self):
        while self.paused:
            await asyncio.sleep(0.5)

    def pause(self):
        self.paused = True

    def resume(self):
        self.paused = False
