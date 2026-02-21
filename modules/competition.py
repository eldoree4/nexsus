import asyncio
from nexsus.modules import PassiveRecon, ActiveRecon, VulnScan, Fuzzing, APISecurity, AuthTesting, CloudMisconfig
from nexsus.utils.logger import Logger

class CompetitionMode:
    def __init__(self, orchestrator):
        self.orchestrator = orchestrator
        self.paused = False
        self.logger = Logger("CompetitionMode")
        self.modules = [
            PassiveRecon(orchestrator),
            ActiveRecon(orchestrator),
            VulnScan(orchestrator),
            Fuzzing(orchestrator),
            APISecurity(orchestrator),
            AuthTesting(orchestrator),
            CloudMisconfig(orchestrator)
        ]

    async def run(self):
        self.logger.info("Starting Full Auto Competition Mode...")
        for module in self.modules:
            if self.paused: await self.wait_if_paused()
            await module.run()
        self.orchestrator.generate_report()
        self.logger.success("Competition mode completed.")

    async def wait_if_paused(self):
        while self.paused:
            await asyncio.sleep(1)

    def pause(self):
        self.paused = True
        for m in self.modules:
            m.pause()
        self.logger.debug("Paused")

    def resume(self):
        self.paused = False
        for m in self.modules:
            m.resume()
        self.logger.debug("Resumed")
