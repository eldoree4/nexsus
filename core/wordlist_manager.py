import os
from nexsus.config import Config

class WordlistManager:
    def __init__(self):
        self.wordlists = {}
        self.load_wordlists()

    def load_wordlists(self):
        wordlist_files = {
            'subdomains': 'subdomains.txt',
            'directories': 'directories.txt',
            'parameters': 'parameters.txt',
            'files': 'files.txt'
        }
        for name, filename in wordlist_files.items():
            path = os.path.join(Config.WORDLISTS_DIR, filename)
            if os.path.exists(path):
                with open(path) as f:
                    self.wordlists[name] = [line.strip() for line in f if line.strip()]
            else:
                self.wordlists[name] = self.default_list(name)

    def default_list(self, name):
        defaults = {
            'subdomains': ['www', 'api', 'admin', 'mail', 'ftp', 'test', 'dev', 'staging'],
            'directories': ['admin', 'backup', 'uploads', 'images', 'css', 'js', 'api', 'v1'],
            'parameters': ['id', 'page', 'user', 'file', 'path', 'url', 'redirect', 'return'],
            'files': ['index.php', 'config.php', '.env', 'robots.txt', 'sitemap.xml']
        }
        return defaults.get(name, [])

    def get(self, name):
        return self.wordlists.get(name, [])
