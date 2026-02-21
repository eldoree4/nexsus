import logging
import sys
from datetime import datetime
from colorama import Fore, Style, init

init(autoreset=True)

class Logger:
    COLORS = {
        'DEBUG': Fore.CYAN,
        'INFO': Fore.GREEN,
        'WARNING': Fore.YELLOW,
        'ERROR': Fore.RED,
        'CRITICAL': Fore.RED + Style.BRIGHT,
        'SUCCESS': Fore.GREEN + Style.BRIGHT,
        'PROGRESS': Fore.MAGENTA
    }

    def __init__(self, name):
        self.name = name
        self.logger = logging.getLogger(name)
        self.logger.setLevel(logging.DEBUG)
        if not self.logger.handlers:
            ch = logging.StreamHandler(sys.stdout)
            ch.setLevel(logging.DEBUG)
            formatter = logging.Formatter('%(asctime)s - %(name)s - %(levelname)s - %(message)s')
            ch.setFormatter(formatter)
            self.logger.addHandler(ch)

    def _log(self, level, msg, color=None):
        timestamp = datetime.now().strftime("%H:%M:%S")
        if color:
            print(f"{color}[{timestamp}][{self.name}] {msg}{Style.RESET_ALL}")
        else:
            print(f"[{timestamp}][{self.name}] {msg}")
        self.logger.log(level, msg)

    def debug(self, msg):
        self._log(logging.DEBUG, msg, self.COLORS['DEBUG'])

    def info(self, msg):
        self._log(logging.INFO, msg, self.COLORS['INFO'])

    def warning(self, msg):
        self._log(logging.WARNING, msg, self.COLORS['WARNING'])

    def error(self, msg):
        self._log(logging.ERROR, msg, self.COLORS['ERROR'])

    def critical(self, msg):
        self._log(logging.CRITICAL, msg, self.COLORS['CRITICAL'])

    def success(self, msg):
        self._log(logging.INFO, msg, self.COLORS['SUCCESS'])

    def progress(self, msg):
        self._log(logging.INFO, msg, self.COLORS['PROGRESS'])
