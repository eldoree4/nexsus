"""
nexsus/utils/helpers.py
~~~~~~~~~~~~~~~~~~~~~~~~
Shared utility functions used across all modules.
"""
import hashlib
import html
import ipaddress
import re
import time
from urllib.parse import urlparse, urlencode, parse_qs

_RE_DOMAIN  = re.compile(r'(?:[a-zA-Z0-9](?:[a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,}')
_RE_IPV4    = re.compile(r'^(\d{1,3})\.(\d{1,3})\.(\d{1,3})\.(\d{1,3})$')
_RE_URL     = re.compile(r'https?://[^\s"\'<>]+')
_RE_EMAIL   = re.compile(r'[a-zA-Z0-9._%+\-]+@[a-zA-Z0-9.\-]+\.[a-zA-Z]{2,}')
_RE_JWT     = re.compile(r'eyJ[A-Za-z0-9_\-\.]{40,}')
_RE_API_KEY = re.compile(
    r'(?i)(?:api[_-]?key|token|secret|password)\s*[:=]\s*["\']?([A-Za-z0-9_\-\.]{16,})["\']?'
)

# ── Extraction helpers ────────────────────────────────────────────────────────

def extract_domains(text: str) -> list[str]:
    return list(dict.fromkeys(_RE_DOMAIN.findall(text)))

def extract_urls(text: str) -> list[str]:
    return list(dict.fromkeys(_RE_URL.findall(text)))

def extract_emails(text: str) -> list[str]:
    return list(dict.fromkeys(_RE_EMAIL.findall(text)))

def extract_jwts(text: str) -> list[str]:
    return list(dict.fromkeys(_RE_JWT.findall(text)))

def extract_api_keys(text: str) -> list[str]:
    return _RE_API_KEY.findall(text)

# ── IP / domain validation ────────────────────────────────────────────────────

def is_ip(host: str) -> bool:
    m = _RE_IPV4.match(host)
    if m:
        return all(0 <= int(g) <= 255 for g in m.groups())
    try:
        ipaddress.ip_address(host)
        return True
    except ValueError:
        return False

def is_ipv4(host: str) -> bool:
    m = _RE_IPV4.match(host)
    return bool(m) and all(0 <= int(g) <= 255 for g in m.groups())

def is_private_ip(host: str) -> bool:
    try:
        return ipaddress.ip_address(host).is_private
    except ValueError:
        return False

# ── URL helpers ───────────────────────────────────────────────────────────────

def normalise_url(url: str) -> str:
    try:
        p = urlparse(url)
        netloc = p.netloc.lower().replace(":80", "").replace(":443", "")
        path   = p.path.rstrip("/") or "/"
        return f"{p.scheme.lower()}://{netloc}{path}"
    except Exception:
        return url

def base_url(url: str) -> str:
    p = urlparse(url)
    return f"{p.scheme}://{p.netloc}"

def inject_param(url: str, param: str, value: str) -> str:
    p      = urlparse(url)
    params = parse_qs(p.query)
    params[param] = [value]
    return f"{p.scheme}://{p.netloc}{p.path}?{urlencode(params, doseq=True)}"

# ── String helpers ────────────────────────────────────────────────────────────

def truncate(s: str, max_len: int = 200, suffix: str = "…") -> str:
    return s if len(s) <= max_len else s[:max_len - len(suffix)] + suffix

def redact(s: str, keep: int = 4) -> str:
    if len(s) <= keep:
        return "*" * len(s)
    return "*" * (len(s) - keep) + s[-keep:]

def slugify(text: str) -> str:
    text = re.sub(r'[^\w\s\-]', '', text.lower().strip())
    return re.sub(r'[\s\-]+', '-', text)

def html_escape(text: str) -> str:
    return html.escape(text, quote=True)

def strip_html(text: str) -> str:
    return re.sub(r'<[^>]+>', '', text)

# ── Hashing ───────────────────────────────────────────────────────────────────

def md5(text: str) -> str:
    return hashlib.md5(text.encode()).hexdigest()

def sha256(text: str) -> str:
    return hashlib.sha256(text.encode()).hexdigest()

def fingerprint(data: dict, fields: list[str] = None) -> str:
    if fields:
        key = "|".join(str(data.get(f, "")) for f in fields)
    else:
        key = "|".join(f"{k}={v}" for k, v in sorted(data.items()))
    return hashlib.sha256(key.encode()).hexdigest()[:16]

# ── Response analysis ─────────────────────────────────────────────────────────

def response_diff(baseline: str, response: str) -> dict:
    bl, rl  = len(baseline), len(response)
    delta   = abs(rl - bl)
    ratio   = rl / max(bl, 1)
    bw = set(re.findall(r'\w+', baseline.lower()))
    rw = set(re.findall(r'\w+', response.lower()))
    union   = bw | rw
    jaccard = len(bw & rw) / max(len(union), 1)
    return {
        "length_delta": delta,
        "length_ratio": round(ratio, 3),
        "common_ratio": round(jaccard, 3),
        "changed":      delta > 100 or ratio > 1.3 or ratio < 0.7,
    }

def detect_error_page(text: str) -> bool:
    return any(re.search(p, text.lower()) for p in
               [r"404\s*not found", r"page not found", r"does not exist"])

def detect_waf_block(text: str) -> bool:
    return any(re.search(p, text.lower()) for p in
               [r"access denied", r"request blocked", r"cloudflare",
                r"incapsula", r"modsecurity", r"web application firewall"])

# ── CVSS helpers ──────────────────────────────────────────────────────────────

def cvss_to_severity(score: float) -> str:
    if score >= 9.0: return "Critical"
    if score >= 7.0: return "High"
    if score >= 4.0: return "Medium"
    if score >= 0.1: return "Low"
    return "Info"

def severity_to_cvss(severity: str) -> float:
    return {"Critical": 9.5, "High": 7.5, "Medium": 5.0,
            "Low": 2.5, "Info": 0.0}.get(severity, 0.0)

# ── Time helpers ──────────────────────────────────────────────────────────────

def format_duration(seconds: float) -> str:
    s = int(seconds)
    parts = []
    if s >= 3600: parts.append(f"{s // 3600}h"); s %= 3600
    if s >= 60:   parts.append(f"{s // 60}m");   s %= 60
    parts.append(f"{s}s")
    return " ".join(parts)

class Timer:
    def __init__(self): self._start = time.monotonic()
    def elapsed(self) -> float: return time.monotonic() - self._start
    def elapsed_str(self) -> str: return format_duration(self.elapsed())
    def __enter__(self): self._start = time.monotonic(); return self
    def __exit__(self, *_): pass

# ── Tech detection from headers ───────────────────────────────────────────────

def detect_tech_from_headers(headers: dict) -> list[str]:
    combined = " ".join(f"{k.lower()}: {v.lower()}" for k, v in headers.items())
    sigs = {
        "nginx": ["nginx"], "apache": ["apache"], "iis": ["microsoft-iis"],
        "php": ["x-powered-by: php"], "asp.net": ["asp.net"],
        "cloudflare": ["cloudflare"], "express": ["x-powered-by: express"],
    }
    return [tech for tech, patterns in sigs.items()
            if any(p in combined for p in patterns)]

def is_json_response(headers: dict) -> bool:
    return "json" in headers.get("Content-Type", headers.get("content-type", "")).lower()
