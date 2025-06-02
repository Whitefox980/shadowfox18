#!/usr/bin/env python3
"""
ShadowFox17 - Vulnerability Mapper
Maps, categorizes, and manages vulnerability findings across scans
"""

from enum import Enum, auto
from typing import Dict, List, Optional, Any, TypedDict, Tuple
from datetime import datetime
import json
import os
from pathlib import Path
import aiofiles
import asyncio
from rich.console import Console
from rich.table import Table


class VulnSeverity(Enum):
    """
    Vulnerability severity levels according to industry standards
    """
    CRITICAL = 5
    HIGH = 4
    MEDIUM = 3
    LOW = 2
    INFO = 1
    UNKNOWN = 0


class VulnType(Enum):
    """
    Common vulnerability categories
    """
    XSS = auto()
    SQL_INJECTION = auto()
    CSRF = auto()
    SSRF = auto()
    XXE = auto()
    COMMAND_INJECTION = auto()
    PATH_TRAVERSAL = auto()
    INSECURE_DESERIALIZATION = auto()
    JWT_VULNERABILITY = auto()
    BROKEN_AUTH = auto()
    SENSITIVE_DATA_EXPOSURE = auto()
    BROKEN_ACCESS_CONTROL = auto()
    SECURITY_MISCONFIGURATION = auto()
    OPEN_REDIRECT = auto()
    API_VULNERABILITY = auto()
    BUSINESS_LOGIC = auto()
    RACE_CONDITION = auto()
    DOS = auto()
    INFORMATION_DISCLOSURE = auto()
    OTHER = auto()


class VulnStatus(Enum):
    """
    Status of a vulnerability finding
    """
    CONFIRMED = auto()
    POTENTIAL = auto()
    VERIFIED = auto()
    FALSE_POSITIVE = auto()
    REMEDIATED = auto()
    ACCEPTED_RISK = auto()


class VulnFingerprint(TypedDict):
    """
    Vulnerability fingerprint for deduplication
    """
    vuln_type: str
    url: str
    parameter: str
    payload_hash: str


class Vulnerability(TypedDict, total=False):
    """
    Complete vulnerability data structure
    """
    id: str  # Unique ID
    vuln_type: str  # Type of vulnerability
    severity: str  # Severity level
    url: str  # Affected URL
    parameter: str  # Affected parameter
    payload: str  # Payload used
    description: str  # Description
    status: str  # Status
    discovered_at: float  # Timestamp
    verified_at: Optional[float]  # Verification timestamp
    payload_hash: str  # Hash of payload
    request_data: Dict[str, Any]  # Request details
    response_data: Dict[str, Any]  # Response details
    evidence: List[str]  # Evidence (screenshots, etc.)
    notes: List[Dict[str, Any]]  # Additional notes
    tags: List[str]  # Custom tags
    cve_refs: List[str]  # CVE references
    owasp_refs: List[str]  # OWASP references
    replay_count: int  # How many times replayed
    bypass_score: float  # Evasion capability score 0-1
    impact_details: Dict[str, Any]  # Impact assessment
    recommendation: str  # Remediation recommendation
    mitigations: List[Dict[str, Any]]  # Suggested mitigations


class VulnerabilityMapper:
    """
    Maps and manages vulnerability findings
    """
    
    def __init__(self, base_dir: str = "findings"):
        """
        Initialize the vulnerability mapper
        
        Args:
            base_dir: Directory for storing vulnerability data
        """
        self.base_dir = Path(base_dir)
        self.base_dir.mkdir(exist_ok=True)
        self.vulnerabilities: Dict[str, Vulnerability] = {}
        self.fingerprints: Dict[str, str] = {}  # Maps fingerprints to vuln IDs
        self.current_mission_id: Optional[str] = None
        self.console = Console()
    
    async def initialize(self):
        """Initialize vulnerability mapper"""
        await self._ensure_dirs()
    
    async def _ensure_dirs(self):
        """Ensure required directories exist"""
        self.base_dir.mkdir(exist_ok=True)
    
    async def set_mission(self, mission_id: str):
        """
        Set current mission context
        
        Args:
            mission_id: ID of the current mission
        """
        self.current_mission_id = mission_id
        self.mission_dir = self.base_dir / mission_id
        self.mission_dir.mkdir(exist_ok=True)
        self.vuln_file = self.mission_dir / "vulnerabilities.json"
        
        # Load existing vulnerabilities
        await self._load_vulnerabilities()
    
    async def _load_vulnerabilities(self):
        """Load vulnerabilities from file"""
        if not self.vuln_file.exists():
            self.vulnerabilities = {}
            self.fingerprints = {}
            return
        
        try:
            async with aiofiles.open(self.vuln_file, 'r') as f:
                content = await f.read()
                self.vulnerabilities = json.loads(content)
                
                # Rebuild fingerprint mapping
                self.fingerprints = {}
                for vuln_id, vuln in self.vulnerabilities.items():
                    fingerprint = self._generate_fingerprint(vuln)
                    fingerprint_key = json.dumps(fingerprint)
                    self.fingerprints[fingerprint_key] = vuln_id
                    
        except Exception as e:
            self.console.print(f"[red]Error loading vulnerabilities: {e}[/red]")
            self.vulnerabilities = {}
            self.fingerprints = {}
    
    async def _save_vulnerabilities(self):
        """Save vulnerabilities to file"""
        if not self.current_mission_id:
            return
            
        try:
            async with aiofiles.open(self.vuln_file, 'w') as f:
                await f.write(json.dumps(self.vulnerabilities, indent=2))
        except Exception as e:
            self.console.print(f"[red]Error saving vulnerabilities: {e}[/red]")
    
    def _generate_id(self, vuln_type: str) -> str:
        """
        Generate a unique vulnerability ID
        
        Args:
            vuln_type: Type of vulnerability
            
        Returns:
            Unique ID string
        """
        timestamp = datetime.now().strftime("%Y%m%d%H%M%S")
        count = sum(1 for v in self.vulnerabilities.values() 
                    if v.get("vuln_type") == vuln_type)
        
        # Format: VLN-TYPE-COUNT-TIMESTAMP
        return f"VLN-{vuln_type}-{count+1:03d}-{timestamp}"
    
    def _generate_fingerprint(self, vuln: Vulnerability) -> VulnFingerprint:
        """
        Generate a fingerprint for deduplication
        
        Args:
            vuln: Vulnerability to fingerprint
            
        Returns:
            Fingerprint dictionary
        """
        return {
            "vuln_type": vuln.get("vuln_type", "UNKNOWN"),
            "url": vuln.get("url", ""),
            "parameter": vuln.get("parameter", ""),
            "payload_hash": vuln.get("payload_hash", "")
        }
    
    def _calculate_severity(self, vuln_data: Dict[str, Any]) -> VulnSeverity:
        """
        Calculate vulnerability severity based on various factors
        
        Args:
            vuln_data: Vulnerability data
            
        Returns:
            Calculated severity level
        """
        vuln_type = vuln_data.get("vuln_type")
        bypass_score = vuln_data.get("bypass_score", 0.0)
        
        # Basic severity mapping by vulnerability type
        base_severity = {
            "XSS": VulnSeverity.MEDIUM,
            "SQL_INJECTION": VulnSeverity.HIGH,
            "COMMAND_INJECTION": VulnSeverity.CRITICAL,
            "PATH_TRAVERSAL": VulnSeverity.HIGH,
            "JWT_VULNERABILITY": VulnSeverity.HIGH,
            "SSRF": VulnSeverity.HIGH,
            "XXE": VulnSeverity.HIGH,
            "BROKEN_AUTH": VulnSeverity.CRITICAL,
            "INSECURE_DESERIALIZATION": VulnSeverity.CRITICAL,
            "CSRF": VulnSeverity.MEDIUM,
            "OPEN_REDIRECT": VulnSeverity.LOW,
            "INFORMATION_DISCLOSURE": VulnSeverity.LOW,
        }.get(vuln_type, VulnSeverity.MEDIUM)
        
        # Adjust based on bypass score
        if bypass_score > 0.8:
            # Increase severity by one level if not already CRITICAL
            if base_severity != VulnSeverity.CRITICAL:
                severity_values = list(VulnSeverity)
                current_index = severity_values.index(base_severity)
                if current_index < len(severity_values) - 1:
                    return severity_values[current_index + 1]
        
        return base_severity
    
    async def add_vulnerability(self, vuln_data: Dict[str, Any]) -> Tuple[str, bool]:
        """
        Add a new vulnerability or update existing one
        
        Args:
            vuln_data: Vulnerability data
            
        Returns:
            Tuple of (vulnerability_id, is_new)
        """
        # Create fingerprint for deduplication
        fingerprint = {
            "vuln_type": vuln_data.get("vuln_type", "UNKNOWN"),
            "url": vuln_data.get("url", ""),
            "parameter": vuln_data.get("parameter", ""),
            "payload_hash": vuln_data.get("payload_hash", "")
        }
        
        fingerprint_key = json.dumps(fingerprint)
        
        # Check if vulnerability already exists
        if fingerprint_key in self.fingerprints:
            existing_id = self.fingerprints[fingerprint_key]
            # Update existing vulnerability
            self.vulnerabilities[existing_id].update(vuln_data)
            # Increment replay count
            replay_count = self.vulnerabilities[existing_id].get("replay_count", 0)
            self.vulnerabilities[existing_id]["replay_count"] = replay_count + 1
            # Update timestamp
            self.vulnerabilities[existing_id]["updated_at"] = datetime.now().timestamp()
            
            # Save changes
            await self._save_vulnerabilities()
            
            return existing_id, False
        
        # New vulnerability
        vuln_type = vuln_data.get("vuln_type", "OTHER")
        vuln_id = self._generate_id(vuln_type)
        
        # Calculate severity if not provided
        if "severity" not in vuln_data:
            severity = self._calculate_severity(vuln_data)
            vuln_data["severity"] = severity.name
        
        # Set metadata
        vuln_data["id"] = vuln_id
        vuln_data["discovered_at"] = datetime.now().timestamp()
        vuln_data["status"] = vuln_data.get("status", VulnStatus.POTENTIAL.name)
        vuln_data["replay_count"] = 1
        
        # Add to collection
        self.vulnerabilities[vuln_id] = vuln_data
        self.fingerprints[fingerprint_key] = vuln_id
        
        # Save changes
        await self._save_vulnerabilities()
        
        return vuln_id, True
    
    async def get_vulnerability(self, vuln_id: str) -> Optional[Vulnerability]:
        """
        Get a vulnerability by ID
        
        Args:
            vuln_id: Vulnerability ID
            
        Returns:
            Vulnerability data or None if not found
        """
        return self.vulnerabilities.get(vuln_id)
    
    async def update_vulnerability(self, vuln_id: str, update_data: Dict[str, Any]) -> bool:
        """
        Update a vulnerability
        
        Args:
            vuln_id: Vulnerability ID
            update_data: Data to update
            
        Returns:
            Success status
        """
        if vuln_id not in self.vulnerabilities:
            return False
            
        self.vulnerabilities[vuln_id].update(update_data)
        self.vulnerabilities[vuln_id]["updated_at"] = datetime.now().timestamp()
        
        # Save changes
        await self._save_vulnerabilities()
        
        return True
    
    async def verify_vulnerability(self, vuln_id: str, verified: bool = True) -> bool:
        """
        Mark a vulnerability as verified or not
        
        Args:
            vuln_id: Vulnerability ID
            verified: Verification status
            
        Returns:
            Success status
        """
        if vuln_id not in self.vulnerabilities:
            return False
            
        if verified:
            self.vulnerabilities[vuln_id]["status"] = VulnStatus.VERIFIED.name
            self.vulnerabilities[vuln_id]["verified_at"] = datetime.now().timestamp()
        else:
            self.vulnerabilities[vuln_id]["status"] = VulnStatus.POTENTIAL.name
            
        # Save changes
        await self._save_vulnerabilities()
        
        return True
    
    async def flag_as_false_positive(self, vuln_id: str, reason: str) -> bool:
        """
        Mark a vulnerability as a false positive
        
        Args:
            vuln_id: Vulnerability ID
            reason: Reason for false positive determination
            
        Returns:
            Success status
        """
        if vuln_id not in self.vulnerabilities:
            return False
            
        self.vulnerabilities[vuln_id]["status"] = VulnStatus.FALSE_POSITIVE.name
        
        # Add note
        if "notes" not in self.vulnerabilities[vuln_id]:
            self.vulnerabilities[vuln_id]["notes"] = []
            
        self.vulnerabilities[vuln_id]["notes"].append({
            "type": "false_positive",
            "content": reason,
            "timestamp": datetime.now().timestamp()
        })
            
        # Save changes
        await self._save_vulnerabilities()
        
        return True
    
    async def add_evidence(self, vuln_id: str, evidence: str) -> bool:
        """
        Add evidence to a vulnerability
        
        Args:
            vuln_id: Vulnerability ID
            evidence: Evidence item (screenshot path, log excerpt, etc.)
            
        Returns:
            Success status
        """
        if vuln_id not in self.vulnerabilities:
            return False
            
        if "evidence" not in self.vulnerabilities[vuln_id]:
            self.vulnerabilities[vuln_id]["evidence"] = []
            
        self.vulnerabilities[vuln_id]["evidence"].append(evidence)
            
        # Save changes
        await self._save_vulnerabilities()
        
        return True
    
    async def get_vulnerabilities_by_type(self, vuln_type: str) -> List[Vulnerability]:
        """
        Get vulnerabilities by type
        
        Args:
            vuln_type: Type of vulnerability
            
        Returns:
            List of matching vulnerabilities
        """
        return [v for v in self.vulnerabilities.values() 
                if v.get("vuln_type") == vuln_type]
    
    async def get_vulnerabilities_by_severity(self, severity: VulnSeverity) -> List[Vulnerability]:
        """
        Get vulnerabilities by severity
        
        Args:
            severity: Severity level
            
        Returns:
            List of matching vulnerabilities
        """
        return [v for v in self.vulnerabilities.values() 
                if v.get("severity") == severity.name]
    
    async def get_all_vulnerabilities(self) -> List[Vulnerability]:
        """
        Get all vulnerabilities
        
        Returns:
            List of all vulnerabilities
        """
        return list(self.vulnerabilities.values())
    
    async def get_vulnerability_count_by_severity(self) -> Dict[str, int]:
        """
        Get count of vulnerabilities by severity
        
        Returns:
            Dictionary with severity counts
        """
        counts = {}
        for severity in VulnSeverity:
            counts[severity.name] = len([v for v in self.vulnerabilities.values() 
                                        if v.get("severity") == severity.name])
        return counts
    
    def print_vulnerability_table(self):
        """
        Display vulnerabilities in a table format
        """
        if not self.vulnerabilities:
            self.console.print("[yellow]No vulnerabilities found[/yellow]")
            return
            
        # Create table
        table = Table(title=f"Vulnerabilities ({len(self.vulnerabilities)})")
        
        # Add columns
        table.add_column("ID", style="cyan", no_wrap=True)
        table.add_column("Type", style="green")
        table.add_column("Severity", style="red")
        table.add_column("URL", style="blue")
        table.add_column("Status", style="yellow")
        table.add_column("Bypass Score", justify="right")
        
        # Add rows
        for vuln_id, vuln in self.vulnerabilities.items():
            # Set color based on severity
            severity = vuln.get("severity", "UNKNOWN")
            severity_color = {
                "CRITICAL": "bright_red",
                "HIGH": "red",
                "MEDIUM": "yellow",
                "LOW": "green",
                "INFO": "blue",
                "UNKNOWN": "white"
            }.get(severity, "white")
            
            # Create row
            table.add_row(
                vuln_id,
                vuln.get("vuln_type", "UNKNOWN"),
                f"[{severity_color}]{severity}[/{severity_color}]",
                self._truncate_url(vuln.get("url", "Unknown")),
                vuln.get("status", "UNKNOWN"),
                f"{vuln.get('bypass_score', 0):.2f}"
            )
        
        # Print table
        self.console.print(table)
    
    def _truncate_url(self, url: str, max_length: int = 40) -> str:
        """
        Truncate URL for display
        
        Args:
            url: URL to truncate
            max_length: Maximum length
            
        Returns:
            Truncated URL
        """
        if len(url) <= max_length:
            return url
        
        # Try to preserve domain and part of the path
        parts = url.split("://", 1)
        if len(parts) == 2:
            protocol = parts[0] + "://"
            rest = parts[1]
            
            if len(rest) > max_length - len(protocol) - 3:  # 3 for "..."
                return protocol + rest[:max_length - len(protocol) - 3] + "..."
            
        return url[:max_length-3] + "..."
    
    async def detect_critical_issues(self) -> List[Vulnerability]:
        """
        Detect critical issues that need immediate attention
        
        Checks for:
        - Critical severity vulnerabilities 
        - High bypass scores (> 0.8)
        
        Returns:
            List of critical vulnerabilities
        """
        critical_issues = []
        
        for vuln in self.vulnerabilities.values():
            is_critical = False
            
            # Check severity
            if vuln.get("severity") == "CRITICAL":
                is_critical = True
            
            # Check bypass score
            if vuln.get("bypass_score", 0) > 0.8:
                is_critical = True
                
            if is_critical:
                critical_issues.append(vuln)
                
        return critical_issues
    
    async def generate_owasp_mapping(self) -> Dict[str, List[str]]:
        """
        Map vulnerabilities to OWASP Top 10 categories
        
        Returns:
            Dictionary mapping OWASP categories to vulnerability IDs
        """
        owasp_mapping = {
            "A01:2021-Broken Access Control": [],
            "A02:2021-Cryptographic Failures": [],
            "A03:2021-Injection": [],
            "A04:2021-Insecure Design": [],
            "A05:2021-Security Misconfiguration": [],
            "A06:2021-Vulnerable Components": [],
            "A07:2021-Auth Failures": [],
            "A08:2021-Software and Data Integrity": [],
            "A09:2021-Logging Failures": [],
            "A10:2021-SSRF": [],
        }
        
        # Type to category mapping
        type_to_owasp = {
            "XSS": "A03:2021-Injection",
            "SQL_INJECTION": "A03:2021-Injection",
            "COMMAND_INJECTION": "A03:2021-Injection",
            "BROKEN_AUTH": "A07:2021-Auth Failures",
            "BROKEN_ACCESS_CONTROL": "A01:2021-Broken Access Control",
            "SENSITIVE_DATA_EXPOSURE": "A02:2021-Cryptographic Failures",
            "SECURITY_MISCONFIGURATION": "A05:2021-Security Misconfiguration",
            "SSRF": "A10:2021-SSRF",
            "INSECURE_DESERIALIZATION": "A08:2021-Software and Data Integrity",
        }
        
        # Map vulnerabilities to categories
        for vuln_id, vuln in self.vulnerabilities.items():
            vuln_type = vuln.get("vuln_type", "OTHER")
            
            if vuln_type in type_to_owasp:
                owasp_category = type_to_owasp[vuln_type]
                owasp_mapping[owasp_category].append(vuln_id)
            
            # Add any explicit OWASP references
            owasp_refs = vuln.get("owasp_refs", [])
            for ref in owasp_refs:
                if ref in owasp_mapping:
                    if vuln_id not in owasp_mapping[ref]:
                        owasp_mapping[ref].append(vuln_id)
        
        return owasp_mapping
    
    async def export_vulnerabilities(self, format_type: str = "json") -> str:
        """
        Export vulnerabilities to specified format
        
        Args:
            format_type: Export format (json, csv)
            
        Returns:
            Path to exported file
        """
        if not self.current_mission_id:
            return ""
            
        timestamp = datetime.now().strftime("%Y%m%d%H%M%S")
        
        if format_type == "json":
            export_file = self.mission_dir / f"vulnerabilities_export_{timestamp}.json"
            
            try:
                async with aiofiles.open(export_file, 'w') as f:
                    await f.write(json.dumps(self.vulnerabilities, indent=2))
                return str(export_file)
            except Exception as e:
                self.console.print(f"[red]Error exporting vulnerabilities: {e}[/red]")
                return ""
                
        elif format_type == "csv":
            export_file = self.mission_dir / f"vulnerabilities_export_{timestamp}.csv"
            
            try:
                # Create CSV header
                headers = ["id", "vuln_type", "severity", "url", "parameter", 
                           "status", "discovered_at", "bypass_score"]
                
                lines = [",".join(headers)]
                
                # Add vulnerability data
                for vuln in self.vulnerabilities.values():
                    row = []
                    for header in headers:
                        value = str(vuln.get(header, ""))
                        # Escape commas in values
                        if "," in value:
                            value = f'"{value}"'
                        row.append(value)
                    lines.append(",".join(row))
                
                # Write CSV
                async with aiofiles.open(export_file, 'w') as f:
                    await f.write("\n".join(lines))
                    
                return str(export_file)
            except Exception as e:
                self.console.print(f"[red]Error exporting vulnerabilities: {e}[/red]")
                return ""
                
        return ""
# Na dno logic/vuln_mapper.py (ako ne postoji)
async def map_vulnerabilities(results: dict) -> dict:
    # Ovo je placeholder da ne puca, možeš kasnije dopuniti
    print("[✓] Placeholder 'map_vulnerabilities' pokrenut")
    return {"vuln_summary": "N/A", "details": results}

# Demo function
async def demo_vuln_mapper():
    """Demo the vulnerability mapper"""
    console = Console()
    console.print("[cyan]Testing Vulnerability Mapper...[/cyan]")
    
    mapper = VulnerabilityMapper()
    await mapper.initialize()
    await mapper.set_mission("test-mission-001")
    
    # Add sample vulnerabilities
    vuln1 = {
        "vuln_type": "XSS",
        "url": "https://example.com/search?q=test",
        "parameter": "q",
        "payload": '<span class="cursor">█</span>'
    }
