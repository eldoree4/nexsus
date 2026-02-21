"""
nexsus/core/orchestrator.py
~~~~~~~~~~~~~~~~~~~~~~~~~~~
Central coordinator for all scan modules.

Features:
  • Parallel module execution with dependency ordering
  • Pause / resume / cancel support
  • WAF detection before active modules (automatic)
  • Real-time progress callbacks
  • Finding deduplication at orchestration level
  • Graceful shutdown with partial result persistence
  • Phase-based scanning: recon → detection → exploitation
"""
import asyncio
import time
import traceback
from collections import defaultdict
from typing import Callable, Optional

from nexsus.config import Config
from nexsus.core.data_store import DataStore
from nexsus.core.logger import Logger
from nexsus.core.payload_manager import PayloadManager
from nexsus.core.rate_limiter import RateLimiter
from nexsus.core.scope import Scope, ScopeValidator
from nexsus.core.waf_detector import WAFDetector
from nexsus.core.http_client import HTTPClient
from nexsus.modules import (
    PassiveRecon, ActiveRecon, VulnScan, Fuzzing,
    APISecurity, AuthTesting, CloudMisconfig,
    CompetitionMode, WAFBypassEngine,
)
from nexsus.reporting.report_generator import ReportGenerator


# ── Scan phases and their module order ────────────────────────────────────────

PHASE_ORDER = ["passive_recon", "active_recon", "vuln_scan",
               "fuzzing", "api_security", "auth_testing",
               "cloud_misconfig", "waf_bypass", "competition_mode"]

# Modules that require WAF detection first
_WAF_AWARE = frozenset({"vuln_scan", "fuzzing", "api_security", "waf_bypass"})

# Modules safe to run in parallel
_PARALLEL_GROUPS = [
    {"passive_recon"},
    {"active_recon"},
    {"vuln_scan", "api_security", "cloud_misconfig"},
    {"fuzzing", "waf_bypass"},
    {"auth_testing"},
    {"competition_mode"},
]


class ScanProgress:
    """Live progress snapshot passed to callbacks."""

    def __init__(self):
        self.phase:          str   = ""
        self.module:         str   = ""
        self.percent:        float = 0.0
        self.elapsed_s:      float = 0.0
        self.finding_counts: dict  = {}
        self.status:         str   = "idle"  # idle | running | paused | done | error

    def to_dict(self) -> dict:
        return {
            "phase":          self.phase,
            "module":         self.module,
            "percent":        round(self.percent, 1),
            "elapsed_s":      round(self.elapsed_s, 1),
            "finding_counts": self.finding_counts,
            "status":         self.status,
        }


class Orchestrator:
    """
    Coordinates all scanning modules for a single engagement.

    Parameters
    ----------
    scope : Scope
    on_progress : callable, optional
        Called with a ScanProgress object after each significant event.
    on_finding : callable, optional
        Called immediately when a new finding is added.
    """

    def __init__(
        self,
        scope: Scope,
        on_progress: Optional[Callable] = None,
        on_finding: Optional[Callable] = None,
    ):
        self.scope         = scope
        self._on_progress  = on_progress
        self._on_finding   = on_finding

        # Core components
        self.validator     = ScopeValidator(scope)
        self.rate_limiter  = RateLimiter(
            default_rate=Config.DEFAULT_RATE_LIMIT,
            max_concurrency=Config.MAX_CONCURRENT_TASKS,
        )
        self.data_store    = DataStore()
        self.http_client   = HTTPClient(self.rate_limiter, self.validator)
        self.logger        = Logger("Orchestrator")
        self.waf_detector  = WAFDetector(self.http_client)
        self.current_waf   = None
        self.payload_mgr   = PayloadManager(self.current_waf)

        # State
        self.running       = False
        self.paused        = False
        self._stop_event   = asyncio.Event()
        self._pause_event  = asyncio.Event()
        self._pause_event.set()   # starts unpaused
        self._start_time   = 0.0
        self._progress     = ScanProgress()

        # Module registry
        self.modules: dict[str, object] = {}
        self._init_modules()

        # Task tracking
        self._active_tasks: list[asyncio.Task] = []

    # ── Initialisation ─────────────────────────────────────────────────────────

    def _init_modules(self):
        self.modules = {
            "passive_recon":   PassiveRecon(self),
            "active_recon":    ActiveRecon(self),
            "vuln_scan":       VulnScan(self),
            "fuzzing":         Fuzzing(self),
            "api_security":    APISecurity(self),
            "auth_testing":    AuthTesting(self),
            "cloud_misconfig": CloudMisconfig(self),
            "competition_mode": CompetitionMode(self),
            "waf_bypass":      WAFBypassEngine(self),
        }

    # ── Target helpers ─────────────────────────────────────────────────────────

    def get_target_url(self) -> Optional[str]:
        """Return the primary target URL for active modules."""
        if self.scope.api_endpoints:
            return sorted(self.scope.api_endpoints)[0]
        if self.scope.domains:
            domain = sorted(self.scope.domains)[0]
            return f"https://{domain}"
        endpoints = self.data_store.assets.get("endpoints", set())
        if endpoints:
            return next(iter(endpoints))
        return None

    def get_all_targets(self) -> list[str]:
        """Return all in-scope URLs discovered so far."""
        endpoints  = list(self.data_store.assets.get("endpoints", set()))
        subdomains = [
            f"https://{s}"
            for s in self.data_store.assets.get("subdomains", set())
        ]
        return list(dict.fromkeys(endpoints + subdomains))

    # ── WAF detection ──────────────────────────────────────────────────────────

    async def detect_waf(self, target_url: Optional[str] = None) -> Optional[str]:
        url = target_url or self.get_target_url()
        if not url:
            return None
        if not Config.AUTO_WAF_DETECT:
            return None
        result = await self.waf_detector.detect(url, active=True)
        if result:
            self.current_waf = result.name
            self.payload_mgr.waf_type = result.name
            self.logger.success(
                f"WAF identified: {result.name} (confidence {result.confidence}%)"
            )
        else:
            self.current_waf = None
            self.payload_mgr.waf_type = None
        return self.current_waf

    # ── Single module run ──────────────────────────────────────────────────────

    async def run_module(self, module_name: str):
        """Run a single named module (blocks until complete)."""
        if self.running:
            self.logger.warning(f"Cannot start {module_name}: another module is running")
            return
        mod = self.modules.get(module_name)
        if not mod:
            self.logger.error(f"Unknown module: {module_name}")
            return

        # Auto WAF detect for active modules
        if module_name in _WAF_AWARE and not self.current_waf:
            await self.detect_waf()

        self.running = True
        self._start_time = time.monotonic()
        self._progress.module = module_name
        self._progress.status = "running"
        self._emit_progress()

        try:
            self.logger.info(f"▶ Starting module: {module_name}")
            await mod.run()
            self.logger.success(f"✔ Module complete: {module_name}")
        except asyncio.CancelledError:
            self.logger.warning(f"Module {module_name} cancelled")
        except Exception as exc:
            self.logger.error(f"Module {module_name} error: {exc}")
            traceback.print_exc()
        finally:
            self.running = False
            self._progress.status = "idle"
            self._emit_progress()

    # ── Full scan pipeline ─────────────────────────────────────────────────────

    async def run_full_scan(self, modules: Optional[list[str]] = None):
        """
        Run a complete scan pipeline.

        Parameters
        ----------
        modules : list[str], optional
            Subset of modules to run (default = PHASE_ORDER).
        """
        requested = set(modules or PHASE_ORDER)
        self._start_time = time.monotonic()
        self.running = True
        self._stop_event.clear()

        self.logger.info("═" * 60)
        self.logger.info(f"  Nexsus {Config.VERSION} — Full Scan Started")
        self.logger.info(f"  Scope: {self.scope.summary_short()}")
        self.logger.info("═" * 60)

        # Phase 0: WAF detection
        primary = self.get_target_url()
        if primary:
            await self.detect_waf(primary)

        # Run phases in order, respecting parallel groups
        for group in _PARALLEL_GROUPS:
            to_run = group & requested
            if not to_run:
                continue
            if self._stop_event.is_set():
                break

            if len(to_run) == 1:
                await self._run_with_guard(next(iter(to_run)))
            else:
                await self._run_parallel(list(to_run))

        # Finalize
        self.running = False
        self._progress.status = "done"
        self._emit_progress()
        self.logger.info("═" * 60)
        counts = self.data_store.findings_count()
        self.logger.success(
            f"Scan complete — {counts.get('total', 0)} finding(s) | "
            f"Critical:{counts.get('Critical', 0)} "
            f"High:{counts.get('High', 0)} "
            f"Medium:{counts.get('Medium', 0)} "
            f"Low:{counts.get('Low', 0)}"
        )

    async def _run_with_guard(self, module_name: str):
        if self._stop_event.is_set():
            return
        await self._pause_event.wait()
        await self.run_module(module_name)

    async def _run_parallel(self, module_names: list[str]):
        """Run multiple modules concurrently."""
        self.logger.info(f"Running in parallel: {module_names}")
        tasks = [
            asyncio.create_task(self._run_with_guard(name), name=name)
            for name in module_names
        ]
        self._active_tasks.extend(tasks)
        await asyncio.gather(*tasks, return_exceptions=True)
        for t in tasks:
            self._active_tasks.discard(t) if hasattr(self._active_tasks, 'discard') else None

    # ── Pause / Resume / Stop ──────────────────────────────────────────────────

    def pause(self):
        if not self.paused:
            self.paused = True
            self._pause_event.clear()
            # Propagate to active module
            for mod in self.modules.values():
                if hasattr(mod, "pause"):
                    mod.pause()
            self.logger.warning("⏸  Scan paused")
            self._progress.status = "paused"
            self._emit_progress()

    def resume(self):
        if self.paused:
            self.paused = False
            self._pause_event.set()
            for mod in self.modules.values():
                if hasattr(mod, "resume"):
                    mod.resume()
            self.logger.info("▶  Scan resumed")
            self._progress.status = "running"
            self._emit_progress()

    async def stop(self):
        """Gracefully stop all running modules and persist results."""
        self._stop_event.set()
        self._pause_event.set()    # unblock any waiting coroutines
        for task in self._active_tasks:
            task.cancel()
        if self._active_tasks:
            await asyncio.gather(*self._active_tasks, return_exceptions=True)
        self.running = False
        self.logger.warning("⏹  Scan stopped by user")
        self.data_store.export_json(Config.REPORT_DIR / "partial_results.json")

    async def shutdown(self):
        """Full shutdown — stop scan and close HTTP client."""
        await self.stop()
        await self.http_client.close()
        self.data_store.close()
        self.logger.info("Shutdown complete")

    # ── Finding management ─────────────────────────────────────────────────────

    async def add_finding(self, finding: dict) -> bool:
        """
        Add a finding. Returns True if it's new (not a duplicate).
        Triggers on_finding callback and emits progress.
        """
        is_new = await self.data_store.save_finding(finding)
        if is_new:
            severity = finding.get("severity", "Info")
            title    = finding.get("title", "Unknown")
            url      = finding.get("url", "")
            self.logger.finding(
                f"{title} — {url}",
                severity=severity,
            )
            if self._on_finding:
                try:
                    self._on_finding(finding)
                except Exception:
                    pass
            self._emit_progress()
        return is_new

    # Sync wrapper for modules that call this without await
    def add_finding_sync(self, finding: dict):
        loop = asyncio.get_event_loop()
        if loop.is_running():
            loop.create_task(self.add_finding(finding))
        else:
            loop.run_until_complete(self.add_finding(finding))

    def get_findings_count(self) -> tuple[int, int, int, int, int]:
        """Return (total, critical, high, medium, low)."""
        counts = self.data_store.findings_count()
        return (
            counts.get("total", 0),
            counts.get("Critical", 0),
            counts.get("High", 0),
            counts.get("Medium", 0),
            counts.get("Low", 0),
        )

    # ── Reporting ──────────────────────────────────────────────────────────────

    async def generate_report(self, formats: Optional[list[str]] = None):
        """Generate reports in the requested formats."""
        findings = self.data_store.findings
        assets   = {
            k: list(v) if isinstance(v, set) else v
            for k, v in self.data_store.assets.items()
        }
        ReportGenerator.generate(
            findings=findings,
            assets=assets,
            formats=formats or Config.REPORT_FORMATS,
            waf=self.current_waf,
            scope=self.scope,
        )
        self.logger.success(f"Reports written to {Config.REPORT_DIR}")

    # ── Progress ───────────────────────────────────────────────────────────────

    def _emit_progress(self):
        self._progress.elapsed_s      = time.monotonic() - self._start_time
        self._progress.finding_counts = self.data_store.findings_count()
        if self._on_progress:
            try:
                self._on_progress(self._progress)
            except Exception:
                pass

    def set_progress(self, percent: float, phase: str = ""):
        """Called by modules to report their own progress."""
        self._progress.percent = percent
        if phase:
            self._progress.phase = phase
        self._emit_progress()
