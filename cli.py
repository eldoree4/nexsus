import asyncio
import sys
import signal
import os
from colorama import init, Fore, Style
from nexsus.core.orchestrator import Orchestrator
from nexsus.core.scope import Scope
from nexsus.config import Config
from nexsus.utils.logger import Logger

init(autoreset=True)

class CLI:
    def __init__(self):
        self.orchestrator = None
        self.scope = Scope()
        self.running = True
        self.logger = Logger("CLI")

    def print_banner(self):
        print(Fore.CYAN + Style.BRIGHT + """
╔══════════════════════════════════════════════════════════╗
║                     NEXSUS v3.0                          ║
║              Advanced Bug Bounty Framework                ║
║                  Anti-WAF • AI-Powered                    ║
╚══════════════════════════════════════════════════════════╝
""")

    def clear_old_data(self):
        assets_file = os.path.join(Config.DATA_DIR, 'assets.json')
        findings_file = os.path.join(Config.DATA_DIR, 'findings.json')
        if os.path.exists(assets_file):
            os.remove(assets_file)
        if os.path.exists(findings_file):
            os.remove(findings_file)

    def get_scope(self):
        print(Fore.YELLOW + "\n[?] Enter authorized targets (space-separated domains, subdomains, IP ranges, APIs):")
        targets = input("> ").strip().split()
        self.scope.add_targets(targets)
        print(Fore.GREEN + f"\nScope Summary:")
        print(self.scope.summary())
        confirm = input("\n[Y]es to proceed, [E]dit, [C]ancel: ").lower()
        if confirm == 'y':
            return True
        elif confirm == 'e':
            return self.get_scope()
        else:
            return False

    def show_menu(self):
        findings = self.orchestrator.get_findings_count() if self.orchestrator else (0,0,0,0,0)
        status = "Running" if self.orchestrator and self.orchestrator.running else "Idle"
        waf = self.orchestrator.current_waf if self.orchestrator else "Unknown"
        print(Fore.CYAN + f"""
========================================== NEXSUS v3.0 ==========================================
[1] Passive Recon          [2] Active Recon            [3] Deep Vulnerability Scan
[4] Smart Fuzzing          [5] API Security Audit      [6] Auth & Access Control
[7] Cloud Misconfig        [8] Report Generation       [9] Full Auto Competition Mode
[10] WAF Bypass Engine     [11] Detect WAF             [12] Advanced Settings
[0] Exit

Current Scope: {self.scope.summary_short()}
Live Findings: {findings[0]} (C:{findings[1]} H:{findings[2]} M:{findings[3]} L:{findings[4]})
Scan Status: {status}   |   WAF Detected: {waf}
===============================================================================================
""")

    async def run_module(self, module_name):
        if not self.orchestrator:
            self.orchestrator = Orchestrator(self.scope)
        await self.orchestrator.run_module(module_name)

    async def main_loop(self):
        self.print_banner()
        if not self.get_scope():
            print(Fore.RED + "Exiting.")
            return
        Config.init_dirs()
        self.clear_old_data()
        self.orchestrator = Orchestrator(self.scope)

        def signal_handler(sig, frame):
            print(Fore.YELLOW + "\n[!] Interrupt received. Pausing...")
            self.orchestrator.pause()
            asyncio.create_task(self.handle_interrupt())
        signal.signal(signal.SIGINT, signal_handler)

        while self.running:
            self.show_menu()
            choice = input("Enter choice: ").strip()
            if choice == '1':
                await self.run_module('passive_recon')
            elif choice == '2':
                await self.run_module('active_recon')
            elif choice == '3':
                await self.run_module('vuln_scan')
            elif choice == '4':
                await self.run_module('fuzzing')
            elif choice == '5':
                await self.run_module('api_security')
            elif choice == '6':
                await self.run_module('auth_testing')
            elif choice == '7':
                await self.run_module('cloud_misconfig')
            elif choice == '8':
                self.orchestrator.generate_report()
            elif choice == '9':
                await self.run_module('competition_mode')
            elif choice == '10':
                await self.run_module('waf_bypass')
            elif choice == '11':
                if self.orchestrator:
                    target = self.orchestrator.get_target_url()
                    if target:
                        waf = await self.orchestrator.detect_waf(target)
                        if waf:
                            print(Fore.GREEN + f"WAF detected: {waf}")
                        else:
                            print(Fore.YELLOW + "No WAF detected.")
                    else:
                        print(Fore.RED + "No target URL available.")
                else:
                    print(Fore.RED + "Orchestrator not initialized.")
            elif choice == '12':
                self.advanced_settings()
            elif choice == '0':
                self.running = False
                await self.orchestrator.shutdown()
                print(Fore.GREEN + "Goodbye!")
            else:
                print(Fore.RED + "Invalid choice.")

    def advanced_settings(self):
        print(Fore.MAGENTA + "\n=== Advanced Settings ===")
        print("1. Set rate limit (current: {})".format(Config.DEFAULT_RATE_LIMIT))
        print("2. Toggle proxy (current: {})".format("enabled" if Config.PROXIES else "disabled"))
        print("3. Change timeout (current: {}s)".format(Config.REQUEST_TIMEOUT))
        print("4. Back to main menu")
        ch = input("Choose: ")
        if ch == '1':
            try:
                new = int(input("New rate limit (req/s): "))
                Config.DEFAULT_RATE_LIMIT = new
                if self.orchestrator:
                    self.orchestrator.rate_limiter.default_rate = new
            except:
                print("Invalid")
        elif ch == '2':
            if Config.PROXIES:
                Config.PROXIES = []
                print("Proxy disabled")
            else:
                proxy = input("Enter proxy URL (e.g., http://user:pass@ip:port): ")
                Config.PROXIES = [proxy]
                print("Proxy enabled")
        elif ch == '3':
            try:
                new = int(input("New timeout (seconds): "))
                Config.REQUEST_TIMEOUT = new
            except:
                print("Invalid")
        elif ch == '4':
            return

    async def handle_interrupt(self):
        print(Fore.YELLOW + "\n[P]ause [R]esume [Q]uit: ", end='')
        cmd = (await asyncio.get_event_loop().run_in_executor(None, sys.stdin.readline)).strip().lower()
        if cmd == 'p':
            self.orchestrator.pause()
        elif cmd == 'r':
            self.orchestrator.resume()
        elif cmd == 'q':
            self.running = False
            await self.orchestrator.shutdown()

def main():
    cli = CLI()
    asyncio.run(cli.main_loop())

if __name__ == "__main__":
    main()
