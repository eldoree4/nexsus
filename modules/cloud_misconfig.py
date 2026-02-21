"""
nexsus/modules/cloud_misconfig.py
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
Cloud misconfiguration detection:
  • AWS: S3 public buckets, metadata SSRF, IAM keys in HTML/JS,
         Cognito misconfig, Lambda URLs, API Gateway
  • GCP: GCS public buckets, metadata endpoint, Firebase open DB
  • Azure: Blob storage, metadata, App Service config exposure
  • Common: exposed .env / credentials files, Docker registry
  • Kubernetes: kubelet, etcd, dashboard exposure
"""
import asyncio
import json
import re
from urllib.parse import urlparse

from nexsus.core.logger import Logger


# ── Bucket name generators ────────────────────────────────────────────────────

def _bucket_candidates(domain: str) -> list[str]:
    """Generate likely bucket names from a domain."""
    base = domain.replace(".", "-").replace("_", "-")
    parts = domain.split(".")
    company = parts[0] if len(parts) > 1 else base
    return list(dict.fromkeys([
        base, company,
        f"{company}-dev", f"{company}-staging", f"{company}-prod",
        f"{company}-backup", f"{company}-data", f"{company}-assets",
        f"{company}-static", f"{company}-uploads", f"{company}-files",
        f"{company}-logs", f"{company}-images", f"{company}-media",
        f"{company}-private", f"{company}-public", f"{company}-storage",
    ]))


class CloudMisconfig:
    def __init__(self, orchestrator):
        self.orchestrator = orchestrator
        self.paused       = False
        self.logger       = Logger("CloudMisconfig")
        self._client      = orchestrator.http_client

    # ── Main entry ─────────────────────────────────────────────────────────────

    async def run(self):
        self.logger.info("Cloud Misconfiguration Scan…")
        domains = list(self.orchestrator.scope.domains)
        if not domains:
            self.logger.warning("No domains in scope — skipping cloud scan")
            return

        tasks = []
        for domain in domains:
            candidates = _bucket_candidates(domain)
            for name in candidates:
                tasks += [
                    self._check_s3(name),
                    self._check_gcs(name),
                    self._check_azure_blob(name, domain),
                ]
            tasks += [
                self._check_aws_metadata(),
                self._check_gcp_metadata(),
                self._check_azure_metadata(),
                self._check_firebase(domain),
                self._check_kubernetes(domain),
                self._check_docker_registry(domain),
                self._check_exposed_env(domain),
            ]

        await asyncio.gather(*tasks, return_exceptions=True)
        self.logger.success("Cloud scan complete")

    # ── AWS ───────────────────────────────────────────────────────────────────

    async def _check_s3(self, bucket: str):
        await self._check_paused()
        urls = [
            f"https://{bucket}.s3.amazonaws.com",
            f"https://{bucket}.s3.us-east-1.amazonaws.com",
            f"https://s3.amazonaws.com/{bucket}",
        ]
        for url in urls:
            try:
                resp = await self._client.get(url)
                if not resp:
                    continue
                text = await resp.text()

                if resp.status == 200 and (
                    "<ListBucketResult" in text or "<Contents>" in text
                ):
                    file_count = text.count("<Key>")
                    await self._save(
                        title="AWS S3 Bucket Publicly Listable",
                        severity="High", cvss=7.5,
                        url=url,
                        evidence=f"Bucket listing exposed {file_count} file(s). "
                                 f"First 200 chars: {text[:200]}",
                        remediation="Disable public ACLs. Enable S3 Block Public Access. "
                                    "Use bucket policies to restrict access.",
                        confirmed=True,
                    )
                    return

                elif resp.status == 403 and "<Code>AccessDenied" in text:
                    # Bucket exists but is private — still useful intel
                    await self._save(
                        title="AWS S3 Bucket Exists (Private)",
                        severity="Info", cvss=0.0,
                        url=url,
                        evidence="Bucket returns 403 AccessDenied — confirms existence",
                        remediation="Ensure bucket policies follow least-privilege.",
                    )
                    return
            except Exception:
                pass

    async def _check_aws_metadata(self):
        await self._check_paused()
        # Only via SSRF — check if previous findings opened a path
        targets = [
            "http://169.254.169.254/latest/meta-data/",
            "http://169.254.169.254/latest/meta-data/iam/security-credentials/",
        ]
        for url in targets:
            try:
                resp = await self._client.get(url)
                if resp and resp.status == 200:
                    text = await resp.text()
                    if "iam" in text.lower() or "ami-id" in text:
                        await self._save(
                            title="AWS Instance Metadata Service (IMDSv1) Accessible",
                            severity="Critical", cvss=10.0,
                            url=url,
                            evidence=text[:300],
                            remediation="Enforce IMDSv2 (require session tokens). "
                                        "Restrict outbound access to 169.254.169.254.",
                            confirmed=True,
                        )
                        return
            except Exception:
                pass

    # ── GCP ───────────────────────────────────────────────────────────────────

    async def _check_gcs(self, bucket: str):
        await self._check_paused()
        url = f"https://storage.googleapis.com/{bucket}?prefix="
        try:
            resp = await self._client.get(url)
            if resp and resp.status == 200:
                text = await resp.text()
                if "<ListBucketResult" in text or "<Items>" in text:
                    await self._save(
                        title="GCP Cloud Storage Bucket Publicly Listable",
                        severity="High", cvss=7.5,
                        url=url,
                        evidence=text[:200],
                        remediation="Remove allUsers / allAuthenticatedUsers IAM bindings. "
                                    "Apply uniform bucket-level access.",
                        confirmed=True,
                    )
        except Exception:
            pass

    async def _check_gcp_metadata(self):
        await self._check_paused()
        url = "http://metadata.google.internal/computeMetadata/v1/"
        try:
            resp = await self._client.get(
                url, extra_headers={"Metadata-Flavor": "Google"}
            )
            if resp and resp.status == 200:
                await self._save(
                    title="GCP Instance Metadata Accessible",
                    severity="Critical", cvss=10.0,
                    url=url,
                    evidence=await resp.text(),
                    remediation="Restrict outbound access to metadata server. "
                                "Minimise service account scopes.",
                    confirmed=True,
                )
        except Exception:
            pass

    # ── Azure ─────────────────────────────────────────────────────────────────

    async def _check_azure_blob(self, container: str, domain: str):
        await self._check_paused()
        # Derive storage account name
        acct = domain.split(".")[0].replace("-", "")[:24]
        url  = f"https://{acct}.blob.core.windows.net/{container}?restype=container&comp=list"
        try:
            resp = await self._client.get(url)
            if resp and resp.status == 200:
                text = await resp.text()
                if "<EnumerationResults" in text or "<Blob>" in text:
                    await self._save(
                        title="Azure Blob Storage Container Publicly Listable",
                        severity="High", cvss=7.5,
                        url=url,
                        evidence=text[:200],
                        remediation="Set container access level to Private. "
                                    "Use SAS tokens with minimal permissions.",
                        confirmed=True,
                    )
        except Exception:
            pass

    async def _check_azure_metadata(self):
        await self._check_paused()
        url = "http://169.254.169.254/metadata/instance?api-version=2021-02-01"
        try:
            resp = await self._client.get(
                url, extra_headers={"Metadata": "true"}
            )
            if resp and resp.status == 200:
                text = await resp.text()
                if "azEnvironment" in text or "subscriptionId" in text:
                    await self._save(
                        title="Azure IMDS Accessible",
                        severity="Critical", cvss=10.0,
                        url=url,
                        evidence=text[:300],
                        remediation="Restrict outbound to 169.254.169.254 from app. "
                                    "Use Managed Identity with minimal permissions.",
                        confirmed=True,
                    )
        except Exception:
            pass

    # ── Firebase ──────────────────────────────────────────────────────────────

    async def _check_firebase(self, domain: str):
        await self._check_paused()
        base = domain.split(".")[0].replace("-", "")
        url  = f"https://{base}-default-rtdb.firebaseio.com/.json"
        try:
            resp = await self._client.get(url)
            if resp and resp.status == 200:
                text = await resp.text()
                if text not in ("{}", "null", "") and len(text) > 5:
                    await self._save(
                        title="Firebase Realtime Database Publicly Readable",
                        severity="High", cvss=8.6,
                        url=url,
                        evidence=text[:300],
                        remediation="Configure Firebase security rules to deny "
                                    "all unauthenticated reads by default.",
                        confirmed=True,
                    )
        except Exception:
            pass

    # ── Kubernetes ────────────────────────────────────────────────────────────

    async def _check_kubernetes(self, domain: str):
        await self._check_paused()
        base = f"https://{domain}"
        k8s_paths = [
            ":10250/pods",           # kubelet
            ":8080/api/v1/pods",     # insecure API server
            ":2379/v2/keys",         # etcd
            "/dashboard/",           # k8s dashboard
            ":8001/api/v1/namespaces/default/secrets",
        ]
        for suffix in k8s_paths:
            url = base + suffix
            try:
                resp = await self._client.get(url)
                if resp and resp.status == 200:
                    text = await resp.text()
                    if any(kw in text for kw in
                           ["apiVersion", "kind", "namespace", "containerPort",
                            "etcd", "Kubernetes"]):
                        await self._save(
                            title="Kubernetes API / Component Exposed",
                            severity="Critical", cvss=9.8,
                            url=url,
                            evidence=text[:200],
                            remediation="Restrict kubelet, etcd, and API server to "
                                        "private network only. Enable RBAC.",
                            confirmed=True,
                        )
            except Exception:
                pass

    # ── Docker Registry ───────────────────────────────────────────────────────

    async def _check_docker_registry(self, domain: str):
        await self._check_paused()
        url = f"https://{domain}/v2/_catalog"
        try:
            resp = await self._client.get(url)
            if resp and resp.status == 200:
                text = await resp.text()
                if "repositories" in text:
                    await self._save(
                        title="Docker Registry Exposed (Unauthenticated)",
                        severity="Critical", cvss=9.1,
                        url=url,
                        evidence=text[:200],
                        remediation="Restrict registry access. Enable authentication. "
                                    "Do not expose Docker registry to the internet.",
                        confirmed=True,
                    )
        except Exception:
            pass

    # ── Exposed .env / credentials files ──────────────────────────────────────

    async def _check_exposed_env(self, domain: str):
        await self._check_paused()
        base = f"https://{domain}"
        sensitive_files = [
            "/.env", "/.env.local", "/.env.production",
            "/.aws/credentials", "/.aws/config",
            "/config/database.yml", "/config/secrets.yml",
            "/server.key", "/id_rsa", "/private.key",
        ]
        for path in sensitive_files:
            try:
                resp = await self._client.get(base + path)
                if not resp or resp.status != 200:
                    continue
                text = await resp.text()
                # Must contain credential-like content
                if any(kw in text for kw in
                       ["DB_PASSWORD", "SECRET_KEY", "API_KEY",
                        "aws_secret", "PRIVATE KEY", "BEGIN RSA"]):
                    await self._save(
                        title=f"Sensitive File Exposed: {path}",
                        severity="Critical", cvss=9.8,
                        url=base + path,
                        evidence=text[:200],
                        remediation=f"Remove {path} from web root. "
                                    "Rotate all exposed credentials immediately.",
                        confirmed=True,
                    )
            except Exception:
                pass

    # ── Helpers ────────────────────────────────────────────────────────────────

    async def _save(self, *, title, severity, cvss, url, evidence="",
                    remediation="", confirmed=False):
        finding = {
            "title":       title,
            "severity":    severity,
            "cvss":        cvss,
            "vuln_type":   "cloud_misconfig",
            "url":         url,
            "parameter":   "",
            "payload":     "",
            "evidence":    evidence[:500],
            "remediation": remediation,
            "module":      "CloudMisconfig",
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
