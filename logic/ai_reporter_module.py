#!/usr/bin/env python3
"""
ShadowFox17 - AI Reporter Module
Analyzes scan results and generates intelligent security reports
"""

import json
import os
import time
import asyncio
from typing import Dict, List, Optional, Any, TypedDict
from pathlib import Path
from datetime import datetime
import aiofiles
from rich.console import Console
from rich.panel import Panel
from rich.table import Table
from rich.markdown import Markdown

# Optional imports for PDF generation
try:
    from fpdf import FPDF
    HAS_FPDF = True
except ImportError:
    HAS_FPDF = False


class AIReporter:
    """
    Generates intelligent security reports from scan data
    Analyzes vulnerabilities and provides recommendations
    """
    
    def __init__(self, 
                 base_dir: str = "reports", 
                 event_bus=None,
                 vuln_mapper=None):
        """
        Initialize AI Reporter
        
        Args:
            base_dir: Directory to store reports
            event_bus: Event bus for publishing events
            vuln_mapper: Reference to vulnerability mapper
        """
        self.base_dir = Path(base_dir)
        self.base_dir.mkdir(exist_ok=True)
        self.event_bus = event_bus
        self.vuln_mapper = vuln_mapper
        self.console = Console()
        self.mission_data = {}
    
    async def initialize(self):
        """Initialize reporter"""
        os.makedirs(self.base_dir, exist_ok=True)
    async def generate_report(self, insights: Dict[str, Any], output_path: str) -> None:
        await self._generate_pdf_report(insights, output_path)
    async def process_mission_data(self, mission_id: str, mission_data: Dict[str, Any]) -> Dict[str, Any]:
        """
        Process mission data and generate insights
        
        Args:
            mission_id: Mission ID
            mission_data: Combined mission data including vulnerabilities
            
        Returns:
            Dictionary of insights and analysis
        """
        self.mission_data = mission_data
        target = mission_data.get("target_url", "Unknown Target")
        timestamp = datetime.now()
        
        # Create mission directory
        mission_dir = self.base_dir / mission_id
        mission_dir.mkdir(exist_ok=True)
        
        # Extract key data
        vulnerabilities = mission_data.get("vulnerabilities", [])
        mutations = mission_data.get("mutations", [])
        recon_results = mission_data.get("recon_results", {})
        jwt_results = mission_data.get("jwt_results", {})
        
        # Generate insights
        insights = {
            "mission_id": mission_id,
            "target": target,
            "timestamp": timestamp.isoformat(),
            "summary": await self._generate_summary(vulnerabilities),
            "risk_assessment": await self._assess_risk_level(vulnerabilities),
            "recommendations": await self._generate_recommendations(vulnerabilities),
            "vulnerability_stats": await self._analyze_vulnerabilities(vulnerabilities),
            "mutation_stats": await self._analyze_mutations(mutations),
            "reconnaissance_insights": await self._analyze_recon(recon_results),
            "authentication_findings": await self._analyze_jwt(jwt_results),
        }
        
        # Save insights as JSON
        insights_file = mission_dir / f"analysis_{timestamp.strftime('%Y%m%d_%H%M%S')}.json"
        async with aiofiles.open(insights_file, "w") as f:
            await f.write(json.dumps(insights, indent=2, default=str))
        
        # Generate markdown report
        markdown_report = await self._generate_markdown_report(insights)
        markdown_file = mission_dir / f"report_{timestamp.strftime('%Y%m%d_%H%M%S')}.md"
        async with aiofiles.open(markdown_file, "w") as f:
            await f.write(markdown_report)
        
        # Generate PDF if fpdf is available
        if HAS_FPDF:
            pdf_file = mission_dir / f"report_{timestamp.strftime('%Y%m%d_%H%M%S')}.pdf"
            await self._generate_pdf_report(insights, str(pdf_file))
            insights["pdf_report_path"] = str(pdf_file)
        
        insights["markdown_report_path"] = str(markdown_file)
        insights["json_report_path"] = str(insights_file)
        
        # Display summary to console
        self._display_console_summary(insights)
        
        return insights
    
    async def _generate_summary(self, vulnerabilities: List[Dict[str, Any]]) -> Dict[str, Any]:
        """
        Generate a summary of findings
        
        Args:
            vulnerabilities: List of vulnerability dictionaries
            
        Returns:
            Summary dictionary
        """
        # Count vulnerabilities by severity
        severity_counts = {
            "CRITICAL": 0,
            "HIGH": 0,
            "MEDIUM": 0,
            "LOW": 0,
            "INFO": 0
        }
        
        vuln_types = set()
        affected_urls = set()
        
        for vuln in vulnerabilities:
            severity = vuln.get("severity", "INFO")
            if severity in severity_counts:
                severity_counts[severity] += 1
            
            vuln_types.add(vuln.get("vuln_type", "UNKNOWN"))
            affected_urls.add(vuln.get("url", ""))
        
        # Calculate risk score (0-100)
        risk_score = (
            severity_counts["CRITICAL"] * 20 +
            severity_counts["HIGH"] * 10 +
            severity_counts["MEDIUM"] * 5 +
            severity_counts["LOW"] * 2 +
            severity_counts["INFO"] * 0.5
        )
        
        # Cap at 100
        risk_score = min(100, risk_score)
        
        return {
            "total_vulnerabilities": len(vulnerabilities),
            "severity_counts": severity_counts,
            "unique_vulnerability_types": len(vuln_types),
            "vulnerability_types": list(vuln_types),
            "affected_urls": len(affected_urls),
            "risk_score": risk_score,
        }
        generate_report = _generate_pdf_report
    async def _assess_risk_level(self, vulnerabilities: List[Dict[str, Any]]) -> Dict[str, Any]:
        """
        Assess overall risk level
        
        Args:
            vulnerabilities: List of vulnerability dictionaries
            
        Returns:
            Risk assessment dictionary
        """
        # Count by severity
        severity_counts = {
            "CRITICAL": 0,
            "HIGH": 0,
            "MEDIUM": 0,
            "LOW": 0,
            "INFO": 0
        }
        
        for vuln in vulnerabilities:
            severity = vuln.get("severity", "INFO")
            if severity in severity_counts:
                severity_counts[severity] += 1
        
        # Determine risk level
        risk_level = "LOW"
        if severity_counts["CRITICAL"] > 0:
            risk_level = "CRITICAL"
        elif severity_counts["HIGH"] > 2:
            risk_level = "HIGH"
        elif severity_counts["HIGH"] > 0 or severity_counts["MEDIUM"] > 3:
            risk_level = "MEDIUM-HIGH"
        elif severity_counts["MEDIUM"] > 0:
            risk_level = "MEDIUM"
        
        # Immediate actions needed?
        immediate_action = (risk_level == "CRITICAL" or risk_level == "HIGH")
        
        # Critical vulnerabilities
        critical_vulns = [v for v in vulnerabilities if v.get("severity") == "CRITICAL"]
        
        return {
            "risk_level": risk_level,
            "immediate_action_required": immediate_action,
            "critical_vulnerabilities": [v.get("vuln_type", "UNKNOWN") for v in critical_vulns],
            "risk_factors": await self._identify_risk_factors(vulnerabilities)
        }
    
    async def _identify_risk_factors(self, vulnerabilities: List[Dict[str, Any]]) -> List[str]:
        """
        Identify key risk factors
        
        Args:
            vulnerabilities: List of vulnerability dictionaries
            
        Returns:
            List of risk factors
        """
        risk_factors = []
        
        # Check for injection vulnerabilities
        if any(v.get("vuln_type") in ["SQL_INJECTION", "COMMAND_INJECTION", "XSS"] for v in vulnerabilities):
            risk_factors.append("Injection vulnerabilities present")
        
        # Check for authentication issues
        if any(v.get("vuln_type") in ["BROKEN_AUTH", "JWT_VULNERABILITY"] for v in vulnerabilities):
            risk_factors.append("Authentication vulnerabilities present")
        
        # Check for high bypass scores
        if any(v.get("bypass_score", 0) > 0.8 for v in vulnerabilities):
            risk_factors.append("High WAF/defense bypass potential")
        
        # Check for sensitive data exposure
        if any(v.get("vuln_type") == "SENSITIVE_DATA_EXPOSURE" for v in vulnerabilities):
            risk_factors.append("Potential for sensitive data exposure")
        
        # Add more factors based on your specific checks
        
        return risk_factors
    
    async def _generate_recommendations(self, vulnerabilities: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        """
        Generate prioritized recommendations
        
        Args:
            vulnerabilities: List of vulnerability dictionaries
            
        Returns:
            List of recommendation dictionaries
        """
        recommendations = []
        seen_types = set()
        
        # First handle critical and high severity
        for severity in ["CRITICAL", "HIGH", "MEDIUM", "LOW"]:
            for vuln in vulnerabilities:
                if vuln.get("severity") != severity:
                    continue
                    
                vuln_type = vuln.get("vuln_type", "UNKNOWN")
                if vuln_type in seen_types:
                    continue
                
                seen_types.add(vuln_type)
                
                # Standard recommendations by type
                rec = {
                    "vulnerability_type": vuln_type,
                    "severity": severity,
                    "priority": ["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"].index(severity) + 1,
                    "recommendation": self._get_recommendation_for_type(vuln_type),
                    "examples": [vuln.get("url", "")]
                }
                
                # Add additional examples
                for other_vuln in vulnerabilities:
                    if (other_vuln.get("vuln_type") == vuln_type and 
                        other_vuln.get("url") != vuln.get("url") and 
                        other_vuln.get("url") not in rec["examples"]):
                        rec["examples"].append(other_vuln.get("url", ""))
                        if len(rec["examples"]) >= 3:  # Limit to 3 examples
                            break
                
                recommendations.append(rec)
        
        # Sort by priority
        recommendations.sort(key=lambda x: x["priority"])
        
        return recommendations
    
    def _get_recommendation_for_type(self, vuln_type: str) -> str:
        """
        Get recommendation for vulnerability type
        
        Args:
            vuln_type: Type of vulnerability
            
        Returns:
            Recommendation text
        """
        recommendations = {
            "XSS": "Implement proper output encoding, use Content-Security-Policy headers, "
                  "and validate all user inputs. Consider using a modern framework that "
                  "automatically escapes output.",
                  
            "SQL_INJECTION": "Use parameterized queries or prepared statements instead of "
                           "string concatenation. Apply the principle of least privilege "
                           "to database accounts.",
                           
            "CSRF": "Implement anti-CSRF tokens for all state-changing operations. "
                   "Use the SameSite cookie attribute and verify Origin/Referer headers.",
                   
            "JWT_VULNERABILITY": "Verify JWT signature properly, use appropriate algorithms (RS256 "
                               "instead of HS256), set proper expiration times, and validate "
                               "all claims.",
                               
            "SSRF": "Implement strict URL validation, use allow-lists for permitted domains, "
                   "and disable support for dangerous protocols like file://.",
                   
            "BROKEN_AUTH": "Implement multi-factor authentication, proper session management, "
                         "and account lockout mechanisms. Use secure password storage with "
                         "strong hashing algorithms.",
                         
            "PATH_TRAVERSAL": "Validate and sanitize file paths, use whitelisting approaches, "
                            "and avoid passing user input directly to file operations.",
                            
            "COMMAND_INJECTION": "Avoid using shell commands with user input. If necessary, "
                               "use appropriate libraries rather than string concatenation "
                               "and strictly validate all inputs.",
        }
        
        return recommendations.get(
            vuln_type,
            "Follow security best practices for input validation, output encoding, "
            "and access controls appropriate for this vulnerability type."
        )
    
    async def _analyze_vulnerabilities(self, vulnerabilities: List[Dict[str, Any]]) -> Dict[str, Any]:
        """
        Analyze vulnerabilities for patterns and insights
        
        Args:
            vulnerabilities: List of vulnerability dictionaries
            
        Returns:
            Analysis dictionary
        """
        if not vulnerabilities:
            return {
                "count": 0,
                "types": {},
                "patterns": [],
                "highest_severity": "NONE"
            }
        
        # Count by type
        types_count = {}
        for vuln in vulnerabilities:
            vuln_type = vuln.get("vuln_type", "UNKNOWN")
            types_count[vuln_type] = types_count.get(vuln_type, 0) + 1
        
        # Identify patterns
        patterns = []
        
        # Check for multiple XSS in same parameter
        xss_params = {}
        for vuln in vulnerabilities:
            if vuln.get("vuln_type") == "XSS":
                param = vuln.get("parameter", "")
                xss_params[param] = xss_params.get(param, 0) + 1
        
        for param, count in xss_params.items():
            if count > 1 and param:
                patterns.append(f"Multiple XSS vulnerabilities in '{param}' parameter")
        
        # Check for injectable parameters across endpoints
        injectable_params = {}
        for vuln in vulnerabilities:
            if vuln.get("vuln_type") in ["SQL_INJECTION", "COMMAND_INJECTION", "XSS"]:
                param = vuln.get("parameter", "")
                if param:
                    if param not in injectable_params:
                        injectable_params[param] = []
                    injectable_params[param].append(vuln.get("url", ""))
        
        for param, urls in injectable_params.items():
            if len(urls) > 1:
                patterns.append(f"Parameter '{param}' is injectable across multiple endpoints")
        
        # Find highest severity
        severities = [vuln.get("severity", "LOW") for vuln in vulnerabilities]
        severity_order = ["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"]
        highest_severity = "NONE"
        
        for sev in severity_order:
            if sev in severities:
                highest_severity = sev
                break
        
        return {
            "count": len(vulnerabilities),
            "types": types_count,
            "patterns": patterns,
            "highest_severity": highest_severity,
            "params_affected": len(set(v.get("parameter", "") for v in vulnerabilities if v.get("parameter"))),
            "urls_affected": len(set(v.get("url", "") for v in vulnerabilities if v.get("url")))
        }
    
    async def _analyze_mutations(self, mutations: List[Dict[str, Any]]) -> Dict[str, Any]:
        """
        Analyze mutation effectiveness
        
        Args:
            mutations: List of mutation dictionaries
            
        Returns:
            Analysis dictionary
        """
        if not mutations:
            return {
                "count": 0,
                "avg_bypass_score": 0,
                "top_mutations": [],
                "techniques": {}
            }
        
        # Average bypass score
        bypass_scores = [m.get("bypass_score", 0) for m in mutations]
        avg_score = sum(bypass_scores) / len(bypass_scores) if bypass_scores else 0
        
        # Top mutations
        sorted_mutations = sorted(
            mutations, 
            key=lambda x: x.get("bypass_score", 0),
            reverse=True
        )
        
        top_mutations = []
        for i, mutation in enumerate(sorted_mutations[:3]):
            top_mutations.append({
                "original": mutation.get("original", ""),
                "mutated": mutation.get("mutated", ""),
                "bypass_score": mutation.get("bypass_score", 0),
                "technique": mutation.get("technique", "unknown")
            })
        
        # Count by technique
        techniques = {}
        for mutation in mutations:
            technique = mutation.get("technique", "unknown")
            techniques[technique] = techniques.get(technique, 0) + 1
        
        return {
            "count": len(mutations),
            "avg_bypass_score": avg_score,
            "top_mutations": top_mutations,
            "techniques": techniques,
            "high_bypass_count": sum(1 for m in mutations if m.get("bypass_score", 0) > 0.8)
        }
    
    async def _analyze_recon(self, recon_results: Dict[str, Any]) -> Dict[str, Any]:
        """
        Analyze reconnaissance results
        
        Args:
            recon_results: Reconnaissance data
            
        Returns:
            Analysis dictionary
        """
        if not recon_results:
            return {
                "info": "No reconnaissance data available"
            }
        
        # Extract key information
        open_ports = recon_results.get("open_ports", [])
        subdomains = recon_results.get("subdomains", [])
        technologies = recon_results.get("technologies", [])
        headers = recon_results.get("headers", {})
        
        # Identify potential security issues
        security_issues = []
        
        # Check for sensitive ports
        sensitive_ports = [21, 22, 23, 25, 53, 445, 1433, 3306, 3389]
        for port in open_ports:
            if port in sensitive_ports:
                security_issues.append(f"Sensitive port {port} is open")
        
        # Check for informative headers
        sensitive_headers = ["Server", "X-Powered-By", "X-AspNet-Version", "X-AspNetMvc-Version"]
        for header in sensitive_headers:
            if header in headers:
                security_issues.append(f"Information disclosure in {header} header")
        
        # Missing security headers
        security_headers = [
            "Content-Security-Policy",
            "X-Content-Type-Options",
            "X-Frame-Options",
            "X-XSS-Protection",
            "Strict-Transport-Security"
        ]
        
        for header in security_headers:
            if header not in headers:
                security_issues.append(f"Missing security header: {header}")
        
        return {
            "open_ports": len(open_ports),
            "subdomains": len(subdomains),
            "technologies_detected": technologies,
            "security_issues": security_issues
        }
    
    async def _analyze_jwt(self, jwt_results: Dict[str, Any]) -> Dict[str, Any]:
        """
        Analyze JWT testing results
        
        Args:
            jwt_results: JWT test data
            
        Returns:
            Analysis dictionary
        """
        if not jwt_results:
            return {
                "info": "No JWT test data available"
            }
        
        # Extract issues
        issues = jwt_results.get("issues", [])
        algorithm = jwt_results.get("algorithm", "unknown")
        
        # Check for common JWT issues
        vulnerabilities = []
        
        if "none_algorithm" in issues or "none_accepted" in issues:
            vulnerabilities.append({
                "name": "JWT Algorithm 'none' Accepted",
                "severity": "CRITICAL",
                "description": "The server accepts tokens with the 'none' algorithm, allowing token forgery."
            })
        
        if "weak_secret" in issues:
            vulnerabilities.append({
                "name": "JWT Weak Secret",
                "severity": "HIGH",
                "description": "The JWT uses a weak secret that could be brute-forced."
            })
        
        if algorithm == "HS256" and "key_confusion" in issues:
            vulnerabilities.append({
                "name": "JWT Key Confusion",
                "severity": "HIGH",
                "description": "The server is vulnerable to algorithm confusion attacks."
            })
        
        if "missing_signature_validation" in issues:
            vulnerabilities.append({
                "name": "Missing Signature Validation",
                "severity": "CRITICAL",
                "description": "The server does not properly validate JWT signatures."
            })
            
        return {
            "algorithm": algorithm,
            "vulnerabilities": vulnerabilities,
            "vulnerable": len(vulnerabilities) > 0
        }
    
    async def _generate_markdown_report(self, insights: Dict[str, Any]) -> str:
        """
        Generate markdown report from insights
        
        Args:
            insights: Analysis insights
            
        Returns:
            Markdown report text
        """
        target = insights.get("target", "Unknown Target")
        timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        summary = insights.get("summary", {})
        risk = insights.get("risk_assessment", {})
        
        # Start with header
        lines = [
            f"# Security Assessment Report for {target}",
            f"**Generated by ShadowFox17 on {timestamp}**\n",
            "## Executive Summary",
            f"During this security assessment of **{target}**, ShadowFox17 identified **{summary.get('total_vulnerabilities', 0)}** vulnerabilities of varying severity.",
            "",
            f"The overall security risk is rated as **{risk.get('risk_level', 'UNKNOWN')}**.",
        ]
        
        # Add risk factors
        if risk.get("risk_factors"):
            lines.extend([
                "",
                "### Key Risk Factors",
                ""
            ])
            
            for factor in risk.get("risk_factors", []):
                lines.append(f"- {factor}")
        
        # Add severity breakdown
        lines.extend([
            "",
            "### Vulnerability Severity Breakdown",
            "",
            "| Severity | Count |",
            "|----------|-------|",
        ])
        
        severity_counts = summary.get("severity_counts", {})
        for severity in ["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"]:
            count = severity_counts.get(severity, 0)
            lines.append(f"| {severity} | {count} |")
        
        # Add recommendations section
        lines.extend([
            "",
            "## Prioritized Recommendations",
            ""
        ])
        
        for i, rec in enumerate(insights.get("recommendations", []), 1):
            lines.extend([
                f"### {i}. Fix {rec.get('vulnerability_type')} Issues ({rec.get('severity')})",
                "",
                f"{rec.get('recommendation', '')}",
                "",
                "**Examples:**",
                ""
            ])
            
            for example in rec.get("examples", [])[:3]:
                lines.append(f"- `{example}`")
            
            lines.append("")
        
        # Add detailed findings sections
        
        # Vulnerabilities
        vuln_stats = insights.get("vulnerability_stats", {})
        lines.extend([
            "## Detailed Findings",
            "",
            "### Vulnerability Analysis",
            "",
            f"- Total vulnerabilities: **{vuln_stats.get('count', 0)}**",
            f"- Highest severity: **{vuln_stats.get('highest_severity', 'NONE')}**",
            f"- URLs affected: **{vuln_stats.get('urls_affected', 0)}**",
            f"- Parameters affected: **{vuln_stats.get('params_affected', 0)}**",
            "",
            "#### Vulnerability Types",
            ""
        ])
        
        for vuln_type, count in vuln_stats.get("types", {}).items():
            lines.append(f"- {vuln_type}: {count}")
        
        # Mutations
        mutation_stats = insights.get("mutation_stats", {})
        if mutation_stats.get("count", 0) > 0:
            lines.extend([
                "",
                "### Payload Mutation Analysis",
                "",
                f"- Mutations tested: **{mutation_stats.get('count', 0)}**",
                f"- Average bypass score: **{mutation_stats.get('avg_bypass_score', 0):.2f}**",
                f"- High-bypass mutations: **{mutation_stats.get('high_bypass_count', 0)}**",
                "",
                "#### Top Performing Mutations",
                ""
            ])
            
            for mutation in mutation_stats.get("top_mutations", []):
                lines.extend([
                    f"- Original: `{mutation.get('original', '')}`",
                    f"  - Mutated: `{mutation.get('mutated', '')}`",
                    f"  - Bypass score: **{mutation.get('bypass_score', 0):.2f}**",
                    f"  - Technique: {mutation.get('technique', 'unknown')}",
                    ""
                ])
        
        # Recon results
        recon = insights.get("reconnaissance_insights", {})
        if recon and recon.get("info") != "No reconnaissance data available":
            lines.extend([
                "### Reconnaissance Findings",
                "",
                f"- Open ports: **{recon.get('open_ports', 0)}**",
                f"- Subdomains discovered: **{recon.get('subdomains', 0)}**",
            ])
            
            if recon.get("technologies_detected"):
                lines.extend([
                    "",
                    "#### Detected Technologies",
                    ""
                ])
                
                for tech in recon.get("technologies_detected", []):
                    lines.append(f"- {tech}")
            
            if recon.get("security_issues"):
                lines.extend([
                    "",
                    "#### Security Configuration Issues",
                    ""
                ])
                
                for issue in recon.get("security_issues", []):
                    lines.append(f"- {issue}")
        
        # JWT findings
        jwt = insights.get("authentication_findings", {})
        if jwt.get("vulnerabilities", []):
            lines.extend([
                "",
                "### Authentication (JWT) Vulnerabilities",
                "",
                f"JWT algorithm in use: **{jwt.get('algorithm', 'unknown')}**",
                "",
            ])
            
            for vuln in jwt.get("vulnerabilities", []):
                lines.extend([
                    f"#### {vuln.get('name')} ({vuln.get('severity')})",
                    "",
                    f"{vuln.get('description')}",
                    ""
                ])
        
        # Footer
        lines.extend([
            "",
            "---",
            "",
            "## About This Report",
            "",
            "This report was automatically generated by ShadowFox17, an AI-driven security testing framework.",
            "The findings should be validated by security professionals before implementing fixes.",
            "",
            f"Mission ID: {insights.get('mission_id', 'Unknown')}",
            f"Report generated: {timestamp}"
        ])
        
        return "\n".join(lines)

    async def _generate_pdf_report(self, insights: Dict[str, Any], output_path: str) -> None:
        """
        Generate PDF report from insights
        
        Args:
            insights: Analysis insights
            output_path: Path to save PDF
        """
        if not HAS_FPDF:
            return
            
        target = insights.get("target", "Unknown Target")
        timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        summary = insights.get("summary", {})
        risk = insights.get("risk_assessment", {})
        
        pdf = FPDF()
        pdf.set_author("ShadowFox17 AI Security")
        pdf.set_title(f"Security Assessment: {target}")
        
        # Add cover page
        pdf.add_page()
        pdf.set_font("Arial", "B", 24)
        pdf.cell(0, 60, "", 0, 1, "C")  # Spacing
        pdf.cell(0, 20, "Security Assessment Report", 0, 1, "C")
        pdf.set_font("Arial", "B", 16)
        pdf.cell(0, 20, target, 0, 1, "C")
        pdf.set_font("Arial", "", 12)
        pdf.cell(0, 10, f"Generated: {timestamp}", 0, 1, "C")
        pdf.cell(0, 10, f"Mission ID: {insights.get('mission_id', 'Unknown')}", 0, 1, "C")
        pdf.set_y(-40)
        pdf.set_font("Arial", "I", 10)
        pdf.cell(0, 10, "ShadowFox17 AI-Driven Penetration Testing Framework", 0, 1, "C")
        
        # Executive summary
        pdf.add_page()
        pdf.set_font("Arial", "B", 16)
        pdf.cell(0, 20, "Executive Summary", 0, 1, "L")
        
        pdf.set_font("Arial", "", 11)
        summary_text = f"""During this security assessment of {target}, ShadowFox17 identified {summary.get('total_vulnerabilities', 0)} vulnerabilities of varying severity.

The overall security risk is rated as {risk.get('risk_level', 'UNKNOWN')}.
"""
        pdf.multi_cell(0, 6, summary_text)
        
        # Risk factors
        if risk.get("risk_factors"):
            pdf.set_font("Arial", "B", 14)
            pdf.cell(0, 15, "Key Risk Factors", 0, 1, "L")
            
            pdf.set_font("Arial", "", 11)
            for factor in risk.get("risk_factors", []):
                pdf.cell(10, 6, "•", 0, 0)
                pdf.multi_cell(0, 6, factor)
        
        # Severity breakdown
        pdf.set_font("Arial", "B", 14)
        pdf.cell(0, 15, "Vulnerability Severity Breakdown", 0, 1, "L")
        
        pdf.set_font("Arial", "B", 11)
        pdf.set_fill_color(220, 220, 220)
        pdf.cell(40, 10, "Severity", 1, 0, "C", True)
        pdf.cell(40, 10, "Count", 1, 1, "C", True)
        
        severity_counts = summary.get("severity_counts", {})
        pdf.set_font("Arial", "", 11)
        
        severity_colors = {
            "CRITICAL": (255, 200, 200),
            "HIGH": (255, 230, 200),
            "MEDIUM": (255, 255, 200),
            "LOW": (255, 255, 230)
        }
reporter = AIReporter()

generate_report = reporter.generate_report
