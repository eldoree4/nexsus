"""
nexsus/modules/competition.py
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
Competition / Full-Auto Mode — runs the entire pipeline end-to-end
with optimised phase ordering and parallel execution for maximum
findings in minimum time.

Ideal for:
  • CTF-style bug bounty competitions
  • Timed engagements
  • Demo / quick-scan mode
"""
import asyncio
import time
from typing import Optional

from nexsus.core.logger import Logger


# Phase order optimised for speed & dependency
_PHASES = [
    "passive_recon",
    "active_recon",
    # Run these three in parallel after recon
    ["vuln_scan", "api_security", "cloud_misconfig"],
    # Then fuzzing and auth in parallel
    ["fuzzing", "auth_testing"],
    # WAF bypass last (needs prior findings context)
    "waf_bypass",
]


class CompetitionMode:
    """
    Full-auto competition mode.
    Runs all modules in an optimised order with parallel execution.
    """

    def __init__(self, orchestrator):
        self.orchestrator = orchestrator
        self.paused       = False
        self.logger       = Logger("CompetitionMode")
        self._start_time  = 0.0

    async def run(self, time_limit_s: Optional[int] = None):
        """
        Run the full pipeline.

        Parameters
        ----------
        time_limit_s : int, optional
            Abort after this many seconds if set (useful for competitions
            with hard time limits).
        """
        self._start_time = time.monotonic()
        self.logger.info("━" * 60)
        self.logger.info("  COMPETITION MODE — Full Auto Scan")
        if time_limit_s:
            self.logger.info(f"  Time limit: {time_limit_s}s")
        self.logger.info("━" * 60)

        for phase in _PHASES:
            await self._check_paused()

            if time_limit_s:
                elapsed = time.monotonic() - self._start_time
                if elapsed >= time_limit_s:
                    self.logger.warning(
                        f"Time limit reached ({elapsed:.0f}s) — stopping"
                    )
                    break

            if isinstance(phase, list):
                # Parallel phase
                self.logger.info(f"▶ Parallel: {phase}")
                tasks = [
                    asyncio.create_task(
                        self.orchestrator.run_module(m), name=m
                    )
                    for m in phase
                ]
                await asyncio.gather(*tasks, return_exceptions=True)
            else:
                self.logger.info(f"▶ Sequential: {phase}")
                await self.orchestrator.run_module(phase)

        elapsed = time.monotonic() - self._start_time
        total, crit, high, med, low = self.orchestrator.get_findings_count()

        self.logger.success("━" * 60)
        self.logger.success(f"  Competition scan complete in {elapsed:.0f}s")
        self.logger.success(
            f"  Findings: {total} total | "
            f"Critical:{crit} High:{high} Medium:{med} Low:{low}"
        )
        self.logger.success("━" * 60)

        # Generate report
        await self.orchestrator.generate_report()

    async def _check_paused(self):
        while self.paused:
            await asyncio.sleep(0.5)

    def pause(self):
        self.paused = True
        self.logger.warning("Competition mode paused")

    def resume(self):
        self.paused = False
        self.logger.info("Competition mode resumed")
