import ipaddress
import re
from urllib.parse import urlparse

class Scope:
    def __init__(self):
        self.domains = set()
        self.wildcard_domains = set()
        self.ip_ranges = []
        self.api_endpoints = set()

    def add_targets(self, targets):
        for t in targets:
            t = t.strip()
            if not t:
                continue
            if '*' in t:
                self.wildcard_domains.add(t.replace('*.', ''))
            elif re.match(r'^https?://', t):
                parsed = urlparse(t)
                if parsed.hostname:
                    self.domains.add(parsed.hostname)
                self.api_endpoints.add(t)
            elif '/' in t:
                try:
                    ip_net = ipaddress.ip_network(t, strict=False)
                    self.ip_ranges.append(ip_net)
                except:
                    self.api_endpoints.add(t)
            else:
                self.domains.add(t)

    def is_in_scope(self, url):
        parsed = urlparse(url)
        host = parsed.hostname or ''
        if host in self.domains:
            return True
        for wc in self.wildcard_domains:
            if host.endswith('.' + wc) or host == wc:
                return True
        try:
            ip = ipaddress.ip_address(host)
            for r in self.ip_ranges:
                if ip in r:
                    return True
        except:
            pass
        for api in self.api_endpoints:
            if url.startswith(api):
                return True
        for api in self.api_endpoints:
            parsed_api = urlparse(api)
            if parsed_api.hostname and parsed_api.hostname == host:
                return True
        return False

    def summary(self):
        lines = []
        if self.domains:
            lines.append(f"Domains: {', '.join(self.domains)}")
        if self.wildcard_domains:
            lines.append(f"Wildcard: *.{', *.'.join(self.wildcard_domains)}")
        if self.ip_ranges:
            lines.append(f"IP Ranges: {', '.join(str(r) for r in self.ip_ranges)}")
        if self.api_endpoints:
            lines.append(f"APIs: {', '.join(self.api_endpoints)}")
        return '\n'.join(lines)

    def summary_short(self):
        parts = []
        if self.domains:
            parts.append(f"{len(self.domains)} domains")
        if self.wildcard_domains:
            parts.append(f"{len(self.wildcard_domains)} wildcards")
        if self.ip_ranges:
            parts.append(f"{len(self.ip_ranges)} ranges")
        if self.api_endpoints:
            parts.append(f"{len(self.api_endpoints)} APIs")
        return ', '.join(parts) if parts else "None"

class ScopeValidator:
    def __init__(self, scope):
        self.scope = scope
        self.trusted_hosts = {
            'crt.sh', 'web.archive.org', 'index.commoncrawl.org',
            'urlscan.io', 'otx.alienvault.com', 'api.github.com',
            'dns.google', '1.1.1.1', '8.8.8.8'
        }

    def validate(self, url):
        from urllib.parse import urlparse
        host = urlparse(url).hostname
        if host in self.trusted_hosts:
            return True
        return self.scope.is_in_scope(url)
