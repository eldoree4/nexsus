import json
import os
from nexsus.config import Config

class DataStore:
    def __init__(self):
        self.assets = {'subdomains': set(), 'endpoints': set(), 'js_files': set(), 'secrets': []}
        self.findings = []
        self.load()

    def load(self):
        assets_file = os.path.join(Config.DATA_DIR, 'assets.json')
        if os.path.exists(assets_file):
            with open(assets_file) as f:
                data = json.load(f)
                self.assets['subdomains'] = set(data.get('subdomains', []))
                self.assets['endpoints'] = set(data.get('endpoints', []))
                self.assets['js_files'] = set(data.get('js_files', []))
                self.assets['secrets'] = data.get('secrets', [])
        findings_file = os.path.join(Config.DATA_DIR, 'findings.json')
        if os.path.exists(findings_file):
            with open(findings_file) as f:
                self.findings = json.load(f)

    def save_assets(self):
        data = {
            'subdomains': list(self.assets['subdomains']),
            'endpoints': list(self.assets['endpoints']),
            'js_files': list(self.assets['js_files']),
            'secrets': self.assets['secrets']
        }
        with open(os.path.join(Config.DATA_DIR, 'assets.json'), 'w') as f:
            json.dump(data, f, indent=2)

    def save_finding(self, finding):
        self.findings.append(finding)
        with open(os.path.join(Config.DATA_DIR, 'findings.json'), 'w') as f:
            json.dump(self.findings, f, indent=2)
