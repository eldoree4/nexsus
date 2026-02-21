import os

class Config:
    DEFAULT_RATE_LIMIT = 10
    MAX_CONCURRENT_TASKS = 20
    REQUEST_TIMEOUT = 30
    USER_AGENT = "Nexsus/1.0 (Security Testing)"
    DATA_DIR = os.path.expanduser("~/.nexsus")
    REPORT_DIR = os.path.join(DATA_DIR, "reports")
    WORDLISTS_DIR = os.path.join(DATA_DIR, "wordlists")
    PROXIES = []
    LOG_LEVEL = "INFO"

    @classmethod
    def init_dirs(cls):
        os.makedirs(cls.DATA_DIR, exist_ok=True)
        os.makedirs(cls.REPORT_DIR, exist_ok=True)
        os.makedirs(cls.WORDLISTS_DIR, exist_ok=True)
