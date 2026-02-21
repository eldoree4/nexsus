"""
nexsus/cli.py
~~~~~~~~~~~~~
Interactive command-line interface with:
  • Rich terminal UI (banners, tables, live finding counts)
  • Scope wizard with validation and confirmation
  • Interrupt handling (pause / resume / graceful quit)
  • Scan profiles (stealth / aggressive / api)
  • Live progress callback
  • One-shot CLI flags for CI/CD integration
  • Report generation command
"""
import asyncio
import os
import signal
import sys
from pathlib import Path

try:
    from rich.console import Console
    from rich.table import Table
    from rich.panel import Panel
    from rich.live import Live
    from rich.text import Text
    from rich import box
    RICH = True
except ImportError:
    RICH = False

from colorama import init as _colorama_init, Fore, Style

_colorama_init(autoreset=True)

from nexsus.config import Config
from nexsus.core.orchestrator import Orchestrator, ScanProgress
from nexsus.core.scope import Scope
from nexsus.core.logger import Logger

_console = Console() if RICH else None


# ── Banner ────────────────────────────────────────────────────────────────────

_BANNER = r"""
███╗   ██╗███████╗██╗  ██╗███████╗██╗   ██╗███████╗
████╗  ██║██╔════╝╚██╗██╔╝██╔════╝██║   ██║██╔════╝
██╔██╗ ██║█████╗   ╚███╔╝ ███████╗██║   ██║███████╗
██║╚██╗██║██╔══╝   ██╔██╗ ╚════██║██║   ██║╚════██║
██║ ╚████║███████╗██╔╝ ██╗███████║╚██████╔╝███████║
╚═╝  ╚═══╝╚══════╝╚═╝  ╚═╝╚══════╝ ╚═════╝ ╚══════╝
"""

_TAGLINE = "Advanced Bug Hunting Framework  •  v{version}  •  Authorized Use Only"


# ── Helpers ───────────────────────────────────────────────────────────────────

def _c(text: str, color: str = "") -> str:
    """Wrap text in colorama colour code if Rich is unavailable."""
    if RICH:
        return text
    return color + text + Style.RESET_ALL


def _print(msg: str, color: str = ""):
    if RICH:
        _console.print(msg)
    else:
        print(color + msg + Style.RESET_ALL)


def _input(prompt: str) -> str:
    if RICH:
        return _console.input(prompt)
    return input(prompt)


# ── Progress callback ─────────────────────────────────────────────────────────

def _make_progress_line(prog: ScanProgress) -> str:
    counts = prog.finding_counts
    total  = counts.get("total", 0)
    crit   = counts.get("Critical", 0)
    high   = counts.get("High", 0)
    med    = counts.get("Medium", 0)
    low    = counts.get("Low", 0)
    return (
        f"[{prog.status.upper()}] {prog.module or prog.phase}  "
        f"{prog.percent:.0f}%  |  {prog.elapsed_s:.0f}s elapsed  |  "
        f"Findings: {total} "
        f"(C:{crit} H:{high} M:{med} L:{low})"
    )


# ── Main CLI class ────────────────────────────────────────────────────────────

class CLI:
    def __init__(self):
        self.orchestrator: Orchestrator = None
        self.scope   = Scope()
        self.running = True
        self.logger  = Logger("CLI")
        self._last_progress_line = ""

    # ── Banner & intro ─────────────────────────────────────────────────────────

    def print_banner(self):
        version = Config.VERSION
        if RICH:
            _console.print(
                Panel(
                    Text(_BANNER, style="bold cyan", justify="center"),
                    subtitle=_TAGLINE.format(version=version),
                    border_style="bright_blue",
                )
            )
        else:
            print(Fore.CYAN + Style.BRIGHT + _BANNER)
            print(Fore.YELLOW + f"  {_TAGLINE.format(version=version)}\n")

    # ── Scope wizard ──────────────────────────────────────────────────────────

    def get_scope(self) -> bool:
        _print("\n[?] Enter authorised targets (space-separated):", Fore.YELLOW)
        _print("    Examples:  example.com  *.example.com  10.0.0.0/24  https://api.example.com", Fore.WHITE)
        raw = _input("> ").strip()
        if not raw:
            _print("No targets entered.", Fore.RED)
            return False

        self.scope = Scope()
        self.scope.add_targets(raw.split())

        _print("\n  Scope Summary:", Fore.GREEN)
        print(self.scope.summary())

        _print("\n  Exclusions (regex, blank to skip):", Fore.YELLOW)
        excl = _input("> ").strip()
        if excl:
            try:
                self.scope.add_exclusion(excl)
                _print(f"  Exclusion added: {excl}", Fore.GREEN)
            except Exception as exc:
                _print(f"  Invalid regex: {exc}", Fore.RED)

        confirm = _input("\n[Y] Proceed  [E] Edit  [C] Cancel : ").lower().strip()
        if confirm == "y":
            return True
        elif confirm == "e":
            return self.get_scope()
        return False

    # ── Menu ──────────────────────────────────────────────────────────────────

    def show_menu(self):
        counts = self.orchestrator.get_findings_count() if self.orchestrator else (0,) * 5
        status = "Running" if (self.orchestrator and self.orchestrator.running) else "Idle"
        waf    = self.orchestrator.current_waf or "—" if self.orchestrator else "—"
        scope_s = self.scope.summary_short()

        if RICH:
            t = Table(box=box.MINIMAL_DOUBLE_HEAD, show_header=False,
                      style="cyan", border_style="bright_blue")
            t.add_column(width=32)
            t.add_column(width=32)
            t.add_row("[1] Passive Recon",         "[2] Active Recon")
            t.add_row("[3] Deep Vulnerability Scan","[4] Smart Fuzzing")
            t.add_row("[5] API Security Audit",     "[6] Auth & Access Control")
            t.add_row("[7] Cloud Misconfig",        "[8] Report Generation")
            t.add_row("[9] Full Auto Competition",  "[10] WAF Bypass Engine")
            t.add_row("[11] Detect WAF",            "[12] Advanced Settings")
            t.add_row("[13] Load Scan Profile",     "[0]  Exit")
            info = (
                f"Scope: {scope_s}   |   Status: {status}   |   "
                f"WAF: {waf}   |   "
                f"Findings: {counts[0]} "
                f"(C:{counts[1]} H:{counts[2]} M:{counts[3]} L:{counts[4]})"
            )
            _console.print(Panel(t, title="NEXSUS Menu", subtitle=info,
                                 border_style="bright_blue"))
        else:
            print(Fore.CYAN + Style.BRIGHT + """
════════════════════════════ NEXSUS ════════════════════════════
[1] Passive Recon         [2] Active Recon
[3] Vuln Scan             [4] Smart Fuzzing
[5] API Security          [6] Auth Testing
[7] Cloud Misconfig       [8] Report
[9] Full Auto             [10] WAF Bypass
[11] Detect WAF           [12] Settings
[13] Load Profile         [0]  Exit
════════════════════════════════════════════════════════════════""")
            print(Fore.GREEN + f"Scope: {scope_s}  |  Status: {status}  |  WAF: {waf}")
            print(Fore.MAGENTA +
                  f"Findings: {counts[0]} total  "
                  f"(C:{counts[1]} H:{counts[2]} M:{counts[3]} L:{counts[4]})\n")

    # ── Progress callback ─────────────────────────────────────────────────────

    def _on_progress(self, prog: ScanProgress):
        line = _make_progress_line(prog)
        if line != self._last_progress_line:
            self._last_progress_line = line
            sys.stdout.write(f"\r{Fore.CYAN}{line}{Style.RESET_ALL}  ")
            sys.stdout.flush()

    def _on_finding(self, finding: dict):
        sev   = finding.get("severity", "Info")
        title = finding.get("title", "Finding")
        url   = finding.get("url", "")
        colours = {
            "Critical": Fore.RED + Style.BRIGHT,
            "High":     Fore.RED,
            "Medium":   Fore.YELLOW,
            "Low":      Fore.CYAN,
            "Info":     Fore.WHITE,
        }
        colour = colours.get(sev, Fore.WHITE)
        print(f"\n{colour}[{sev}] {title} — {url}{Style.RESET_ALL}")

    # ── Module runner ─────────────────────────────────────────────────────────

    async def _run(self, module_name: str):
        if not self.orchestrator:
            self._init_orchestrator()
        await self.orchestrator.run_module(module_name)

    def _init_orchestrator(self):
        self.orchestrator = Orchestrator(
            self.scope,
            on_progress=self._on_progress,
            on_finding=self._on_finding,
        )

    # ── Advanced settings ─────────────────────────────────────────────────────

    def advanced_settings(self):
        _print("\n=== Advanced Settings ===", Fore.MAGENTA)
        options = [
            f"1. Rate limit          : {Config.DEFAULT_RATE_LIMIT} req/s",
            f"2. Concurrency         : {Config.MAX_CONCURRENT_TASKS} tasks",
            f"3. Request timeout     : {Config.REQUEST_TIMEOUT}s",
            f"4. Proxy               : {Config.PROXIES or 'disabled'}",
            f"5. Passive-only mode   : {Config.PASSIVE_ONLY}",
            f"6. Stealthy mode       : {Config.STEALTHY_MODE}",
            f"7. Deep scan           : {Config.DEEP_SCAN}",
            f"8. OOB callback URL    : {Config.BLIND_VULN_CALLBACK or 'not set'}",
             "9. Back",
        ]
        for o in options:
            print("  " + o)

        ch = _input("Choose: ").strip()
        handlers = {
            "1": self._set_rate_limit,
            "2": self._set_concurrency,
            "3": self._set_timeout,
            "4": self._set_proxy,
            "5": lambda: setattr(Config, "PASSIVE_ONLY", not Config.PASSIVE_ONLY),
            "6": lambda: setattr(Config, "STEALTHY_MODE", not Config.STEALTHY_MODE),
            "7": lambda: setattr(Config, "DEEP_SCAN", not Config.DEEP_SCAN),
            "8": self._set_callback,
        }
        fn = handlers.get(ch)
        if fn:
            fn()
            _print("Settings updated.", Fore.GREEN)

    def _set_rate_limit(self):
        try:
            v = int(_input("New rate limit (req/s): "))
            Config.DEFAULT_RATE_LIMIT = v
            if self.orchestrator:
                self.orchestrator.rate_limiter.default_rate = v
        except ValueError:
            _print("Invalid value.", Fore.RED)

    def _set_concurrency(self):
        try:
            v = int(_input("Max concurrent tasks: "))
            Config.MAX_CONCURRENT_TASKS = v
        except ValueError:
            _print("Invalid value.", Fore.RED)

    def _set_timeout(self):
        try:
            v = int(_input("Request timeout (s): "))
            Config.REQUEST_TIMEOUT = v
        except ValueError:
            _print("Invalid value.", Fore.RED)

    def _set_proxy(self):
        proxy = _input("Proxy URL (blank to disable): ").strip()
        Config.PROXIES = [proxy] if proxy else []
        _print(f"Proxy: {proxy or 'disabled'}", Fore.GREEN)

    def _set_callback(self):
        cb = _input("OOB callback URL (e.g. https://xyz.interactsh.com): ").strip()
        Config.BLIND_VULN_CALLBACK = cb
        _print(f"Callback set: {cb}", Fore.GREEN)

    def load_profile(self):
        _print("\nProfiles: stealth | aggressive | api", Fore.YELLOW)
        name = _input("Profile name: ").strip()
        try:
            Config.load_profile(name)
            _print(f"Profile '{name}' loaded.", Fore.GREEN)
        except ValueError as exc:
            _print(str(exc), Fore.RED)

    # ── Interrupt handler ─────────────────────────────────────────────────────

    async def _handle_interrupt(self):
        print()
        _print("[P]ause  [R]esume  [Q]uit : ", Fore.YELLOW)
        cmd = (await asyncio.get_event_loop().run_in_executor(
            None, sys.stdin.readline
        )).strip().lower()
        if cmd == "p" and self.orchestrator:
            self.orchestrator.pause()
        elif cmd == "r" and self.orchestrator:
            self.orchestrator.resume()
        elif cmd == "q":
            self.running = False
            if self.orchestrator:
                await self.orchestrator.shutdown()

    # ── Main loop ─────────────────────────────────────────────────────────────

    async def main_loop(self):
        self.print_banner()

        if not self.get_scope():
            _print("Exiting.", Fore.RED)
            return

        Config.init_dirs()
        self._init_orchestrator()

        # Signal handler for Ctrl+C
        def _sigint(sig, frame):
            asyncio.get_event_loop().create_task(self._handle_interrupt())

        signal.signal(signal.SIGINT, _sigint)

        while self.running:
            self.show_menu()
            choice = _input("Enter choice: ").strip()

            action_map = {
                "1":  ("passive_recon",   None),
                "2":  ("active_recon",    None),
                "3":  ("vuln_scan",       None),
                "4":  ("fuzzing",         None),
                "5":  ("api_security",    None),
                "6":  ("auth_testing",    None),
                "7":  ("cloud_misconfig", None),
                "9":  ("competition_mode",None),
                "10": ("waf_bypass",      None),
            }

            if choice in action_map:
                module, _ = action_map[choice]
                await self._run(module)

            elif choice == "8":
                await self.orchestrator.generate_report()
                _print("Report generated in " + str(Config.REPORT_DIR), Fore.GREEN)

            elif choice == "11":
                if self.orchestrator:
                    target = self.orchestrator.get_target_url()
                    if target:
                        _print(f"Detecting WAF on {target}…", Fore.YELLOW)
                        waf = await self.orchestrator.detect_waf(target)
                        msg = f"WAF: {waf}" if waf else "No WAF detected"
                        _print(msg, Fore.GREEN if waf else Fore.YELLOW)
                    else:
                        _print("No target URL in scope.", Fore.RED)

            elif choice == "12":
                self.advanced_settings()

            elif choice == "13":
                self.load_profile()

            elif choice == "0":
                self.running = False
                if self.orchestrator:
                    await self.orchestrator.shutdown()
                _print("Goodbye!", Fore.GREEN)

            else:
                _print("Invalid choice.", Fore.RED)


# ── Entry point ────────────────────────────────────────────────────────────────

def main():
    """Entry point registered in setup.py."""
    # Quick one-shot scan mode: nexsus --target example.com --profile aggressive
    if "--target" in sys.argv:
        _quick_scan()
        return
    cli = CLI()
    try:
        asyncio.run(cli.main_loop())
    except KeyboardInterrupt:
        print("\nInterrupted.")


def _quick_scan():
    """Non-interactive one-shot scan for CI/CD integration."""
    import argparse
    parser = argparse.ArgumentParser(prog="nexsus", description="Nexsus Bug Hunter")
    parser.add_argument("--target",    required=True,  help="Target URL or domain")
    parser.add_argument("--modules",   default="passive_recon,active_recon,vuln_scan",
                        help="Comma-separated modules to run")
    parser.add_argument("--profile",   default=None,   help="Scan profile (stealth|aggressive|api)")
    parser.add_argument("--output",    default=None,   help="Report output directory")
    parser.add_argument("--format",    default="json,html", help="Report formats")
    parser.add_argument("--timeout",   type=int, default=30)
    parser.add_argument("--rate",      type=int, default=None)
    args = parser.parse_args()

    if args.profile:
        Config.load_profile(args.profile)
    if args.output:
        Config.REPORT_DIR = Path(args.output)
    if args.timeout:
        Config.REQUEST_TIMEOUT = args.timeout
    if args.rate:
        Config.DEFAULT_RATE_LIMIT = args.rate
    Config.REPORT_FORMATS = [f.strip() for f in args.format.split(",")]

    Config.init_dirs()
    scope = Scope()
    scope.add_targets([args.target])
    modules = [m.strip() for m in args.modules.split(",")]

    async def _run():
        orc = Orchestrator(scope)
        await orc.run_full_scan(modules)
        await orc.generate_report()
        await orc.shutdown()

    asyncio.run(_run())


if __name__ == "__main__":
    main()
