"""
Network Security Tools
=====================

Tools for network reconnaissance, port scanning, and security assessment.
"""

import socket
import threading
import subprocess
import ipaddress
import time
import sys
from concurrent.futures import ThreadPoolExecutor, as_completed
from typing import List, Dict, Tuple

class NetworkTools:
    def __init__(self):
        self.open_ports = []
        self.lock = threading.Lock()
        
        # Common services and their default ports
        self.common_services = {
            21: 'FTP', 22: 'SSH', 23: 'Telnet', 25: 'SMTP',
            53: 'DNS', 80: 'HTTP', 110: 'POP3', 111: 'RPC',
            135: 'RPC', 139: 'NetBIOS', 143: 'IMAP', 443: 'HTTPS',
            993: 'IMAPS', 995: 'POP3S', 1723: 'PPTP', 3306: 'MySQL',
            3389: 'RDP', 5432: 'PostgreSQL', 5900: 'VNC', 8080: 'HTTP-Proxy'
        }
    
    def port_scan(self, target: str, port_range: str, timeout: float, threads: int) -> None:
        """Perform port scan on target"""
        print(f"\n[+] Starting port scan on {target}")
        print(f"[+] Port range: {port_range}")
        print(f"[+] Timeout: {timeout}s | Threads: {threads}")
        print("=" * 60)
        
        # Parse port range
        ports = self._parse_port_range(port_range)
        if not ports:
            print("✗ Invalid port range")
            return
        
        # Resolve hostname to IP
        try:
            target_ip = socket.gethostbyname(target)
            if target != target_ip:
                print(f"[+] Resolved {target} to {target_ip}")
        except socket.gaierror:
            print(f"✗ Could not resolve hostname: {target}")
            return
        
        start_time = time.time()
        self.open_ports = []
        
        # Threading for faster scanning
        with ThreadPoolExecutor(max_workers=threads) as executor:
            futures = {executor.submit(self._scan_port, target_ip, port, timeout): port for port in ports}
            
            completed = 0
            total = len(ports)
            
            for future in as_completed(futures):
                port = futures[future]
                try:
                    result = future.result()
                    if result:
                        with self.lock:
                            self.open_ports.append(result)
                except Exception as e:
                    pass
                
                completed += 1
                if completed % 100 == 0 or completed == total:
                    progress = (completed / total) * 100
                    print(f"\r[+] Progress: {progress:.1f}% ({completed}/{total})", end='', flush=True)
        
        print()  # New line after progress
        end_time = time.time()
        
        # Sort and display results
        self.open_ports.sort(key=lambda x: x[0])
        
        print(f"\n[+] Scan completed in {end_time - start_time:.2f} seconds")
        print(f"[+] Found {len(self.open_ports)} open ports:")
        print("-" * 60)
        
        if self.open_ports:
            print(f"{'PORT':<8} {'STATE':<8} {'SERVICE':<15} {'BANNER'}")
            print("-" * 60)
            
            for port, state, banner in self.open_ports:
                service = self.common_services.get(port, 'Unknown')
                banner_text = banner[:30] + "..." if len(banner) > 30 else banner
                print(f"{port:<8} {state:<8} {service:<15} {banner_text}")
                
            # Security analysis
            self._analyze_open_ports()
        else:
            print("No open ports found.")
    
    def _scan_port(self, target_ip: str, port: int, timeout: float) -> Tuple[int, str, str] or None:
        """Scan a single port"""
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(timeout)
            result = sock.connect_ex((target_ip, port))
            
            if result == 0:
                # Try to grab banner
                banner = self._grab_banner(sock, port)
                sock.close()
                return (port, 'Open', banner)
            else:
                sock.close()
                return None
                
        except Exception:
            return None
    
    def _grab_banner(self, sock: socket.socket, port: int) -> str:
        """Attempt to grab service banner"""
        try:
            # Send appropriate probe based on port
            if port == 80:
                sock.send(b"GET / HTTP/1.1\r\nHost: target\r\n\r\n")
            elif port == 25:
                sock.send(b"EHLO test\r\n")
            elif port == 21:
                pass  # FTP usually sends banner automatically
            elif port == 22:
                pass  # SSH sends version automatically
            else:
                sock.send(b"\r\n")
            
            sock.settimeout(2)
            banner = sock.recv(1024).decode('utf-8', errors='ignore').strip()
            return banner[:100]  # Limit banner length
            
        except:
            return ""
    
    def _parse_port_range(self, port_range: str) -> List[int]:
        """Parse port range string into list of ports"""
        ports = []
        
        try:
            if '-' in port_range:
                start, end = map(int, port_range.split('-'))
                if start > end or start < 1 or end > 65535:
                    return []
                ports = list(range(start, end + 1))
            elif ',' in port_range:
                ports = [int(p.strip()) for p in port_range.split(',')]
            else:
                ports = [int(port_range)]
                
            # Validate port numbers
            ports = [p for p in ports if 1 <= p <= 65535]
            return ports
            
        except ValueError:
            return []
    
    def _analyze_open_ports(self) -> None:
        """Analyze open ports for security issues"""
        print(f"\n[+] Security Analysis:")
        print("-" * 30)
        
        risky_ports = {
            21: "FTP - Often uses plaintext authentication",
            23: "Telnet - Unencrypted remote access",
            25: "SMTP - May allow email relay",
            53: "DNS - Could be used for amplification attacks",
            135: "RPC - Windows service, often targeted",
            139: "NetBIOS - Windows file sharing, security risk",
            445: "SMB - Windows file sharing, frequently exploited",
            1433: "MSSQL - Database access",
            3306: "MySQL - Database access",
            3389: "RDP - Remote desktop, brute force target",
            5432: "PostgreSQL - Database access",
            5900: "VNC - Remote desktop, often weak passwords"
        }
        
        security_issues = []
        
        for port, state, banner in self.open_ports:
            if port in risky_ports:
                security_issues.append(f"  ⚠ Port {port}: {risky_ports[port]}")
            
            # Check for outdated software versions
            if banner and any(old_ver in banner.lower() for old_ver in ['1.0', '2.0', '2003', '2008']):
                security_issues.append(f"  ⚠ Port {port}: Potentially outdated software")
        
        if security_issues:
            print("Potential security concerns:")
            for issue in security_issues:
                print(issue)
        else:
            print("✓ No obvious security concerns detected")
        
        # Recommendations
        print(f"\n[+] Recommendations:")
        print("  • Close unnecessary ports")
        print("  • Use strong authentication")
        print("  • Keep software updated")
        print("  • Consider firewall rules")
        print("  • Monitor for suspicious activity")
    
    def ping_sweep(self, network: str) -> None:
        """Perform ping sweep on network range"""
        print(f"\n[+] Starting ping sweep on {network}")
        print("=" * 50)
        
        try:
            net = ipaddress.ip_network(network, strict=False)
        except ValueError:
            print("✗ Invalid network range")
            return
        
        if net.num_addresses > 256:
            print("⚠ Large network detected. This may take a while.")
            response = input("Continue? (y/N): ")
            if response.lower() != 'y':
                return
        
        alive_hosts = []
        total_hosts = net.num_addresses
        
        def ping_host(ip):
            try:
                if sys.platform.startswith('win'):
                    result = subprocess.run(['ping', '-n', '1', '-w', '1000', str(ip)],
                                          capture_output=True, timeout=3)
                else:
                    result = subprocess.run(['ping', '-c', '1', '-W', '1', str(ip)],
                                          capture_output=True, timeout=3)
                
                if result.returncode == 0:
                    return str(ip)
            except:
                pass
            return None
        
        print(f"[+] Pinging {total_hosts} hosts...")
        
        with ThreadPoolExecutor(max_workers=50) as executor:
            futures = {executor.submit(ping_host, ip): ip for ip in net.hosts()}
            
            completed = 0
            for future in as_completed(futures):
                result = future.result()
                if result:
                    alive_hosts.append(result)
                
                completed += 1
                if completed % 20 == 0:
                    progress = (completed / len(futures)) * 100
                    print(f"\r[+] Progress: {progress:.1f}%", end='', flush=True)
        
        print(f"\n\n[+] Ping sweep completed")
        print(f"[+] Found {len(alive_hosts)} alive hosts:")
        print("-" * 30)
        
        for host in sorted(alive_hosts, key=lambda x: ipaddress.ip_address(x)):
            try:
                hostname = socket.gethostbyaddr(host)[0]
                print(f"{host:<15} ({hostname})")
            except:
                print(f"{host:<15}")
        
        if not alive_hosts:
            print("No hosts responded to ping")