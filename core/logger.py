import logging
from colorama import Fore, Style

class Logger:
    def __init__(self, level=logging.INFO):
        self.logger = logging.getLogger('nexsus')
        self.logger.setLevel(level)
        if not self.logger.handlers:
            ch = logging.StreamHandler()
            ch.setLevel(level)
            formatter = logging.Formatter('%(asctime)s - %(name)s - %(levelname)s - %(message)s')
            ch.setFormatter(formatter)
            self.logger.addHandler(ch)

    def debug(self, msg):
        self.logger.debug(msg)

    def info(self, msg):
        self.logger.info(msg)

    def warning(self, msg):
        self.logger.warning(Fore.YELLOW + msg + Style.RESET_ALL)

    def error(self, msg):
        self.logger.error(Fore.RED + msg + Style.RESET_ALL)

    def success(self, msg):
        self.logger.info(Fore.GREEN + msg + Style.RESET_ALL)

    def critical(self, msg):
        self.logger.critical(Fore.RED + Style.BRIGHT + msg + Style.RESET_ALL)
