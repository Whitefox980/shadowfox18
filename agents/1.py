#!/usr/bin/env python3
"""
CL0D Launcher - CLI Interface for Adaptive AI Fuzzing System
===========================================================
Educational penetration testing demonstration tool.
Use only on systems you own or have explicit permission to test.
"""

import asyncio
import os
import sys
import argparse
import json
from datetime import datetime
from typing import Dict, Any
import signal

# Import the main CL0D system
try:
    from agents.cl0d_core import CL0D_MutationEngine, AdaptationLevel, MutationStrategy
except ImportError:
    print("❌ Error: most_advanced.py not found in the same directory!")
    print("Please ensure both files are in the same folder.")
    sys.exit(1)

class CL0D_CLI:
    """Command Line Interface for CL0D.EXE"""
    
    def __init__(self):
        self.mutation_engine = None
        self.session_id = None
        self.output_dir = "clod_reports"
        
    def print_banner(self):
        """Display the application banner"""
        banner = """
╔══════════════════════════════════════════════════════════════╗
║  CL0D.EXE - Adaptive AI Mutation Storm v1.0                 ║
║  Educational Penetration Testing Demonstration Tool          ║
║  ------------------------------------------------------------ ║
║  ⚠️  WARNING: Use only on authorized targets                  ║
║  🎯 Educational and authorized testing purposes only         ║
╚══════════════════════════════════════════════════════════════╝
        """
        print(banner)
    
    def get_target_info(self) -> Dict[str, Any]:
        """Interactive target configuration"""
        print("\n📋 TARGET CONFIGURATION")
        print("=" * 50)
        
        while True:
            target_url = input("🎯 Enter target URL (e.g., http://testphp.vulnweb.com/): ").strip()
            if target_url.startswith(('http://', 'https://')):
                break
            print("❌ Please enter a valid URL starting with http:// or https://")
        
        print("\n🔧 ATTACK CONFIGURATION")
        print("Available strategies:")
        print("1. Reconnaissance (Safe probing)")
        print("2. Standard Testing (Moderate intensity)")
        print("3. Intensive Testing (High intensity)")
        print("4. Custom Configuration")
        
        while True:
            try:
                mode = int(input("\nSelect mode (1-4): "))
                if 1 <= mode <= 4:
                    break
                print("❌ Please enter a number between 1 and 4")
            except ValueError:
                print("❌ Please enter a valid number")
        
        # Configure based on mode
        config = {
            'target_url': target_url,
            'mode': mode,
            'max_iterations': 50,
            'delay_range': (1.0, 3.0),
            'user_agent_rotation': True,
            'report_format': 'detailed'
        }
        
        if mode == 1:  # Reconnaissance
            config.update({
                'max_iterations': 20,
                'delay_range': (2.0, 5.0),
                'aggressive_payloads': False
            })
        elif mode == 2:  # Standard
            config.update({
                'max_iterations': 50,
                'delay_range': (1.0, 3.0),
                'aggressive_payloads': False
            })
        elif mode == 3:  # Intensive
            config.update({
                'max_iterations': 100,
                'delay_range': (0.5, 2.0),
                'aggressive_payloads': True
            })
        elif mode == 4:  # Custom
            config.update(self.get_custom_config())
        
        return config
    
    def get_custom_config(self) -> Dict[str, Any]:
        """Get custom configuration from user"""
        custom = {}
        
        try:
            iterations = int(input("Max iterations (default 50): ") or "50")
            custom['max_iterations'] = max(1, min(iterations, 200))
        except ValueError:
            custom['max_iterations'] = 50
        
        try:
            min_delay = float(input("Minimum delay between requests in seconds (default 1.0): ") or "1.0")
            max_delay = float(input("Maximum delay between requests in seconds (default 3.0): ") or "3.0")
            custom['delay_range'] = (min_delay, max_delay)
        except ValueError:
            custom['delay_range'] = (1.0, 3.0)
        
        aggressive = input("Use aggressive payloads? (y/N): ").lower().startswith('y')
        custom['aggressive_payloads'] = aggressive
        
        return custom
    
    def confirm_execution(self, config: Dict[str, Any]) -> bool:
        """Confirm execution with user"""
        print("\n📊 EXECUTION SUMMARY")
        print("=" * 50)
        print(f"🎯 Target: {config['target_url']}")
        print(f"🔄 Max Iterations: {config['max_iterations']}")
        print(f"⏱️  Delay Range: {config['delay_range'][0]:.1f}s - {config['delay_range'][1]:.1f}s")
        print(f"⚡ Aggressive Mode: {'Yes' if config.get('aggressive_payloads', False) else 'No'}")
        
        print("\n⚠️  IMPORTANT DISCLAIMERS:")
        print("• Only test targets you own or have explicit permission to test")
        print("• This tool is for educational and authorized testing purposes only")
        print("• You are responsible for ensuring legal compliance")
        print("• Unauthorized testing may violate laws and terms of service")
        
        while True:
            confirm = input("\n✅ Do you confirm you have authorization to test this target? (yes/no): ").lower()
            if confirm in ['yes', 'y']:
                return True
            elif confirm in ['no', 'n']:
                return False
            print("Please answer 'yes' or 'no'")
    
    async def execute_attack(self, config: Dict[str, Any]) -> Dict[str, Any]:
        """Execute the attack with progress monitoring"""
        self.session_id = f"clod_session_{datetime.now().strftime('%Y%m%d_%H%M%S')}"
        self.mutation_engine = CL0D_MutationEngine()
        
        print(f"\n🚀 INITIALIZING ATTACK SESSION: {self.session_id}")
        print("=" * 60)
        print("⏹️  Press Ctrl+C to stop the attack safely")
        print()
        
        # Setup signal handler for graceful shutdown
        def signal_handler(signum, frame):
            print("\n\n⏹️  Stopping attack gracefully...")
            raise KeyboardInterrupt()
        
        signal.signal(signal.SIGINT, signal_handler)
        
        try:
            # Execute the adaptive attack
            results = await self.mutation_engine.execute_adaptive_attack(
                target_url=config['target_url'],
                session_id=self.session_id,
                max_iterations=config['max_iterations']
            )
            
            return results
            
        except KeyboardInterrupt:
            print("🛑 Attack stopped by user")
            # Get partial results
            if self.mutation_engine and self.session_id in self.mutation_engine.active_sessions:
                return self.mutation_engine._generate_battle_report(
                    self.mutation_engine.active_sessions[self.session_id]
                )
            return {"status": "interrupted", "message": "Attack stopped by user"}
        
        except Exception as e:
            print(f"❌ Attack failed: {str(e)}")
            return {"status": "error", "message": str(e)}
    
    def generate_report(self, config: Dict[str, Any], results: Dict[str, Any]):
        """Generate detailed report"""
        
        # Create reports directory
        os.makedirs(self.output_dir, exist_ok=True)
        
        timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
        report_filename = f"{self.output_dir}/clod_report_{timestamp}.txt"
        json_filename = f"{self.output_dir}/clod_report_{timestamp}.json"
        
        # Generate text report
        with open(report_filename, 'w', encoding='utf-8') as f:
            f.write("CL0D.EXE - Adaptive AI Penetration Testing Report\n")
            f.write("=" * 60 + "\n\n")
            
            f.write(f"Session ID: {self.session_id}\n")
            f.write(f"Timestamp: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n")
            f.write(f"Target URL: {config['target_url']}\n")
            f.write(f"Attack Mode: {config['mode']}\n\n")
            
            # Executive Summary
            f.write("EXECUTIVE SUMMARY\n")
            f.write("-" * 20 + "\n")
            if 'total_requests' in results:
                f.write(f"Total Requests Sent: {results['total_requests']}\n")
                f.write(f"Successful Bypasses: {len(results.get('successful_bypasses', []))}\n")
                f.write(f"Success Rate: {results.get('success_rate', 0) * 100:.1f}%\n")
                f.write(f"Duration: {results.get('duration', 0):.1f} seconds\n\n")
            
            # Detailed Findings
            f.write("DETAILED FINDINGS\n")
            f.write("-" * 20 + "\n")
            
            successful_bypasses = results.get('successful_bypasses', [])
            if successful_bypasses:
                f.write(f"Found {len(successful_bypasses)} successful bypasses:\n\n")
                for i, bypass in enumerate(successful_bypasses, 1):
                    f.write(f"{i}. Iteration #{bypass['iteration']}\n")
                    f.write(f"   Strategy: {bypass['strategy']}\n")
                    f.write(f"   Payload: {bypass['payload']}\n")
                    f.write(f"   Response Code: {bypass['response']['status_code']}\n\n")
            else:
                f.write("No successful bypasses detected.\n")
                f.write("This could indicate:\n")
                f.write("• Strong security controls are in place\n")
                f.write("• The target may not be vulnerable to tested attacks\n")
                f.write("• Additional testing with different vectors may be needed\n\n")
            
            # Defense Analysis
            f.write("DEFENSE ANALYSIS\n")
            f.write("-" * 20 + "\n")
            defense_signatures = set()
            attempts = results.get('attempts', [])
            for attempt in attempts:
                defense_signatures.update(sig['value'] if isinstance(sig, dict) else str(sig) 
                                        for sig in attempt.get('defense_signatures', []))
            
            if defense_signatures:
                f.write("Detected Defense Mechanisms:\n")
                for defense in defense_signatures:
                    f.write(f"• {defense}\n")
            else:
                f.write("No specific defense mechanisms detected.\n")
            
            f.write("\n")
            
            # Recommendations
            f.write("RECOMMENDATIONS\n")
            f.write("-" * 20 + "\n")
            f.write("Based on the testing results:\n\n")
            
            if successful_bypasses:
                f.write("⚠️  SECURITY ISSUES FOUND:\n")
                f.write("• Review and strengthen input validation\n")
                f.write("• Implement or enhance Web Application Firewall (WAF)\n")
                f.write("• Consider additional security headers\n")
                f.write("• Regular security assessments recommended\n\n")
            else:
                f.write("✅ POSITIVE FINDINGS:\n")
                f.write("• No obvious vulnerabilities detected in tested vectors\n")
                f.write("• Security controls appear to be functioning\n")
                f.write("• Continue regular security assessments\n\n")
            
            f.write("GENERAL RECOMMENDATIONS:\n")
            f.write("• Implement comprehensive input validation\n")
            f.write("• Use parameterized queries for database interactions\n")
            f.write("• Deploy Content Security Policy (CSP) headers\n")
            f.write("• Regular security updates and patches\n")
            f.write("• Security awareness training for developers\n\n")
            
            # Technical Details
            f.write("TECHNICAL DETAILS\n")
            f.write("-" * 20 + "\n")
            f.write("This report was generated by CL0D.EXE, an adaptive AI-driven\n")
            f.write("penetration testing tool designed for educational purposes.\n\n")
            f.write("The tool uses machine learning to adapt its attack strategies\n")
            f.write("based on target responses, simulating advanced threat actors.\n\n")
            
            f.write("Tested Attack Vectors:\n")
            f.write("• Cross-Site Scripting (XSS)\n")
            f.write("• SQL Injection\n")
            f.write("• Command Injection\n")
            f.write("• Path Traversal\n")
            f.write("• Template Injection\n\n")
            
            f.write("Mutation Strategies Used:\n")
            f.write("• Encoding bypass techniques\n")
            f.write("• Payload obfuscation\n")
            f.write("• Request fragmentation\n")
            f.write("• Polyglot payloads\n")
            f.write("• Metamorphic mutations\n\n")
        
        # Generate JSON report for programmatic access
        with open(json_filename, 'w', encoding='utf-8') as f:
            json.dump({
                'session_id': self.session_id,
                'timestamp': datetime.now().isoformat(),
                'config': config,
                'results': results
            }, f, indent=2, default=str)
        
        print(f"\n📄 REPORTS GENERATED:")
        print(f"📋 Detailed Report: {report_filename}")
        print(f"🔧 JSON Data: {json_filename}")
        
        return report_filename, json_filename
    
    def display_summary(self, results: Dict[str, Any]):
        """Display execution summary"""
        print("\n" + "=" * 60)
        print("🎯 ATTACK EXECUTION SUMMARY")
        print("=" * 60)
        
        if 'total_requests' in results:
            print(f"📊 Total Requests: {results['total_requests']}")
            print(f"✅ Successful Bypasses: {len(results.get('successful_bypasses', []))}")
            print(f"📈 Success Rate: {results.get('success_rate', 0) * 100:.1f}%")
            print(f"⏱️  Duration: {results.get('duration', 0):.1f} seconds")
            
            if results.get('successful_bypasses'):
                print(f"\n🎯 CRITICAL FINDINGS:")
                for bypass in results['successful_bypasses']:
                    print(f"  • {bypass['strategy'].upper()}: {bypass['payload'][:50]}...")
            else:
                print(f"\n🛡️  No vulnerabilities detected in tested vectors")
        else:
            print(f"⚠️  Attack incomplete or interrupted")

async def main():
    """Main application entry point"""
    parser = argparse.ArgumentParser(description='CL0D.EXE - Adaptive AI Penetration Testing Tool')
    parser.add_argument('--target', help='Target URL to test')
    parser.add_argument('--mode', type=int, choices=[1,2,3,4], help='Attack mode (1-4)')
    parser.add_argument('--iterations', type=int, help='Maximum iterations')
    parser.add_argument('--quiet', action='store_true', help='Minimal output mode')
    
    args = parser.parse_args()
    
    cli = CL0D_CLI()
    
    if not args.quiet:
        cli.print_banner()
    
    try:
        # Get configuration
        if args.target and args.mode:
            # Command line mode
            config = {
                'target_url': args.target,
                'mode': args.mode,
                'max_iterations': args.iterations or 50,
                'delay_range': (1.0, 3.0),
                'user_agent_rotation': True,
                'report_format': 'detailed'
            }
        else:
            # Interactive mode
            config = cli.get_target_info()
        
        # Confirm execution
        if not cli.confirm_execution(config):
            print("❌ Execution cancelled by user")
            return
        
        # Execute attack
        results = await cli.execute_attack(config)
        
        # Display summary
        cli.display_summary(results)
        
        # Generate reports
        cli.generate_report(config, results)
        
        print(f"\n✅ CL0D.EXE execution completed successfully!")
        
    except KeyboardInterrupt:
        print(f"\n🛑 Application terminated by user")
    except Exception as e:
        print(f"\n❌ Unexpected error: {e}")
        return 1
    
    return 0

if __name__ == "__main__":
    try:
        exit_code = asyncio.run(main())
        sys.exit(exit_code)
    except KeyboardInterrupt:
        print("\n🛑 Interrupted")
        sys.exit(1)
