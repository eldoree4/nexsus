import asyncio
from collections import defaultdict
from nexsus.core.scope import ScopeValidator
from nexsus.core.rate_limiter import RateLimiter
from nexsus.core.data_store import DataStore
from nexsus.utils.http_client import HTTPClient
from nexsus.utils.logger import Logger
from nexsus.core.waf_detector import WAFDetector
from nexsus.core.payload_manager import PayloadManager
from nexsus.modules import (
    PassiveRecon, ActiveRecon, VulnScan, Fuzzing,
    APISecurity, AuthTesting, CloudMisconfig, CompetitionMode,
    WAFBypassEngine
)
from nexsus.reporting.report_generator import ReportGenerator

class Orchestrator:
    def __init__(self, scope):
        self.scope = scope
        self.validator = ScopeValidator(scope)
        self.rate_limiter = RateLimiter()
        self.data_store = DataStore()
        self.http_client = HTTPClient(self.rate_limiter, self.validator)
        self.logger = Logger("Orchestrator")
        self.waf_detector = WAFDetector(self.http_client)
        self.current_waf = None
        self.payload_manager = PayloadManager(self.current_waf)
        self.running = False
        self.paused = False
        self.current_module = None
        self.findings = []

        self.modules = {
            'passive_recon': PassiveRecon(self),
            'active_recon': ActiveRecon(self),
            'vuln_scan': VulnScan(self),
            'fuzzing': Fuzzing(self),
            'api_security': APISecurity(self),
            'auth_testing': AuthTesting(self),
            'cloud_misconfig': CloudMisconfig(self),
            'competition_mode': CompetitionMode(self),
            'waf_bypass': WAFBypassEngine(self),
        }
        self.task_queue = asyncio.Queue()
        self.workers = []

    def get_target_url(self):
        if self.scope.api_endpoints:
            return list(self.scope.api_endpoints)[0]
        if self.scope.domains:
            return f"https://{list(self.scope.domains)[0]}"
        endpoints = self.data_store.assets.get('endpoints', [])
        if endpoints:
            return list(endpoints)[0]
        return None

    async def detect_waf(self, target_url=None):
        if not target_url:
            target_url = self.get_target_url()
        if target_url:
            self.current_waf = await self.waf_detector.detect(target_url)
            self.payload_manager.waf_type = self.current_waf
            return self.current_waf
        return None

    async def run_module(self, module_name):
        self.logger.debug(f"run_module called with {module_name}")
        if self.running:
            self.logger.warning("Another module is already running.")
            return
        self.current_module = self.modules.get(module_name)
        if not self.current_module:
            self.logger.error(f"Module {module_name} not found.")
            return
        if module_name in ['vuln_scan', 'fuzzing', 'api_security', 'waf_bypass']:
            target = self.get_target_url()
            if target and not self.current_waf:
                await self.detect_waf(target)
        self.running = True
        self.paused = False
        try:
            self.logger.info(f"Starting module: {module_name}")
            await self.current_module.run()
            self.logger.info(f"Module {module_name} completed.")
        except Exception as e:
            self.logger.error(f"Error in module {module_name}: {e}")
            import traceback
            traceback.print_exc()
        finally:
            self.running = False
            self.current_module = None
            self.logger.debug("Module execution finished.")

    def pause(self):
        self.paused = True
        if self.current_module:
            self.current_module.pause()
        self.logger.info("Paused.")

    def resume(self):
        self.paused = False
        if self.current_module:
            self.current_module.resume()
        self.logger.info("Resumed.")

    async def shutdown(self):
        self.running = False
        self.paused = False
        for w in self.workers:
            w.cancel()
        await asyncio.gather(*self.workers, return_exceptions=True)
        await self.http_client.close()
        self.logger.info("Shutdown complete.")

    def add_finding(self, finding):
        self.findings.append(finding)
        self.data_store.save_finding(finding)
        self.logger.info(f"New finding: {finding['title']} [{finding['severity']}]")

    def get_findings_count(self):
        total = len(self.findings)
        sev = defaultdict(int)
        for f in self.findings:
            sev[f['severity']] += 1
        return total, sev.get('Critical',0), sev.get('High',0), sev.get('Medium',0), sev.get('Low',0)

    def generate_report(self):
        ReportGenerator.generate(self.findings, self.data_store.assets)
        self.logger.success("Report generated.")
