#!/usr/bin/env python3
"""
CyberToolkit - Multi-Purpose Security Suite
==========================================

A comprehensive cybersecurity toolkit for penetration testing,
security analysis, and educational purposes.

Author: Your Name
Version: 1.0.0
"""

import argparse
import sys
from modules.password_tools import PasswordTools
from modules.network_tools import NetworkTools
from modules.crypto_tools import CryptoTools
from modules.web_scanner import WebScanner
from modules.log_analyzer import LogAnalyzer

def print_banner():
    """Display the tool banner"""
    banner = """
    ╔══════════════════════════════════════════════════════════════╗
    ║                        CyberToolkit                          ║
    ║                Multi-Purpose Security Suite                  ║
    ║                                                              ║
    ║  🔐 Password Security  🌐 Network Recon  🔍 Crypto Tools    ║
    ║  🕷️  Web Scanning     📊 Log Analysis   🔒 File Integrity   ║
    ╚══════════════════════════════════════════════════════════════╝
    """
    print(banner)

def main():
    print_banner()
    
    parser = argparse.ArgumentParser(
        description="CyberToolkit - Multi-Purpose Security Suite",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  python main.py password --analyze "MyPassword123!"
  python main.py network --scan 192.168.1.1 -p 1-1000
  python main.py hash --file document.pdf --algorithm sha256
  python main.py web --url https://example.com --ssl-check
  python main.py logs --file /var/log/auth.log --anomaly-detect
        """
    )
    
    subparsers = parser.add_subparsers(dest='tool', help='Available tools')
    
    # Password Tools
    pass_parser = subparsers.add_parser('password', help='Password security tools')
    pass_group = pass_parser.add_mutually_exclusive_group(required=True)
    pass_group.add_argument('--analyze', help='Analyze password strength')
    pass_group.add_argument('--generate', action='store_true', help='Generate secure password')
    pass_group.add_argument('--check-breach', help='Check if password was breached')
    pass_parser.add_argument('--length', type=int, default=16, help='Password length (default: 16)')
    pass_parser.add_argument('--complexity', choices=['low', 'medium', 'high'], default='high', help='Password complexity')
    
    # Network Tools
    net_parser = subparsers.add_parser('network', help='Network reconnaissance tools')
    net_group = net_parser.add_mutually_exclusive_group(required=True)
    net_group.add_argument('--scan', help='Target IP or hostname to scan')
    net_group.add_argument('--ping-sweep', help='Network range for ping sweep (e.g., 192.168.1.0/24)')
    net_parser.add_argument('-p', '--ports', default='1-1000', help='Port range (default: 1-1000)')
    net_parser.add_argument('--timeout', type=float, default=1.0, help='Connection timeout (default: 1.0)')
    net_parser.add_argument('--threads', type=int, default=100, help='Number of threads (default: 100)')
    
    # Crypto Tools
    crypto_parser = subparsers.add_parser('hash', help='Cryptographic tools')
    crypto_group = crypto_parser.add_mutually_exclusive_group(required=True)
    crypto_group.add_argument('--file', help='File to hash')
    crypto_group.add_argument('--text', help='Text to hash')
    crypto_group.add_argument('--verify', nargs=2, metavar=('FILE', 'HASH'), help='Verify file integrity')
    crypto_parser.add_argument('--algorithm', choices=['md5', 'sha1', 'sha256', 'sha512'], default='sha256', help='Hash algorithm')
    
    # Web Scanner
    web_parser = subparsers.add_parser('web', help='Web security scanner')
    web_parser.add_argument('--url', required=True, help='Target URL')
    web_parser.add_argument('--ssl-check', action='store_true', help='Check SSL/TLS certificate')
    web_parser.add_argument('--headers', action='store_true', help='Analyze security headers')
    web_parser.add_argument('--directories', action='store_true', help='Directory enumeration')
    web_parser.add_argument('--vulnerabilities', action='store_true', help='Basic vulnerability scan')
    
    # Log Analyzer
    log_parser = subparsers.add_parser('logs', help='Log analysis tools')
    log_parser.add_argument('--file', required=True, help='Log file to analyze')
    log_parser.add_argument('--anomaly-detect', action='store_true', help='Detect anomalies')
    log_parser.add_argument('--failed-logins', action='store_true', help='Find failed login attempts')
    log_parser.add_argument('--suspicious-ips', action='store_true', help='Identify suspicious IP addresses')
    log_parser.add_argument('--time-range', nargs=2, help='Filter by time range (start, end)')
    
    if len(sys.argv) == 1:
        parser.print_help()
        return
    
    args = parser.parse_args()
    
    try:
        if args.tool == 'password':
            pwd_tools = PasswordTools()
            if args.analyze:
                pwd_tools.analyze_strength(args.analyze)
            elif args.generate:
                pwd_tools.generate_password(args.length, args.complexity)
            elif args.check_breach:
                pwd_tools.check_breach(args.check_breach)
                
        elif args.tool == 'network':
            net_tools = NetworkTools()
            if args.scan:
                net_tools.port_scan(args.scan, args.ports, args.timeout, args.threads)
            elif args.ping_sweep:
                net_tools.ping_sweep(args.ping_sweep)
                
        elif args.tool == 'hash':
            crypto_tools = CryptoTools()
            if args.file:
                crypto_tools.hash_file(args.file, args.algorithm)
            elif args.text:
                crypto_tools.hash_text(args.text, args.algorithm)
            elif args.verify:
                crypto_tools.verify_integrity(args.verify[0], args.verify[1], args.algorithm)
                
        elif args.tool == 'web':
            web_scanner = WebScanner()
            web_scanner.scan_website(args.url, args.ssl_check, args.headers, 
                                   args.directories, args.vulnerabilities)
                                   
        elif args.tool == 'logs':
            log_analyzer = LogAnalyzer()
            log_analyzer.analyze_logs(args.file, args.anomaly_detect, args.failed_logins,
                                    args.suspicious_ips, args.time_range)
            
    except KeyboardInterrupt:
        print("\n[!] Operation interrupted by user")
    except Exception as e:
        print(f"[!] Error: {e}")

if __name__ == "__main__":
    main()