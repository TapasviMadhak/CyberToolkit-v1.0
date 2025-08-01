"""
Web Security Scanner
===================

Tools for web application security assessment.
"""

import requests
import ssl
import socket
import urllib.parse
from urllib.parse import urljoin, urlparse
import re
import time
from typing import List, Dict, Tuple
import warnings

# Suppress SSL warnings
warnings.filterwarnings('ignore', message='Unverified HTTPS request')

class WebScanner:
    def __init__(self):
        self.session = requests.Session()
        self.session.headers.update({
            'User-Agent': 'CyberToolkit-WebScanner/1.0'
        })
        
        # Common directories to check
        self.common_dirs = [
            'admin', 'administrator', 'login', 'wp-admin', 'phpmyadmin',
            'backup', 'backups', 'config', 'uploads', 'files', 'images',
            'docs', 'documentation', 'test', 'tests', 'dev', 'development',
            'staging', 'api', 'robots.txt', 'sitemap.xml', '.git', '.env'
        ]
        
        # Security headers to check
        self.security_headers = {
            'X-Frame-Options': 'Prevents clickjacking attacks',
            'X-XSS-Protection': 'XSS protection',
            'X-Content-Type-Options': 'MIME type sniffing protection',
            'Strict-Transport-Security': 'HTTPS enforcement',
            'Content-Security-Policy': 'Content injection protection',
            'X-Permitted-Cross-Domain-Policies': 'Cross-domain policy',
            'Referrer-Policy': 'Referrer information control',
            'Feature-Policy': 'Browser feature control'
        }
    
    def scan_website(self, url: str, ssl_check: bool = False, headers: bool = False, 
                    directories: bool = False, vulnerabilities: bool = False) -> None:
        """Perform comprehensive web security scan"""
        print(f"\n[+] Starting web security scan for: {url}")
        print("=" * 70)
        
        # Normalize URL
        if not url.startswith(('http://', 'https://')):
            url = 'https://' + url
        
        try:
            # Basic connectivity test
            print("[+] Testing connectivity...")
            response = self.session.get(url, timeout=10, verify=False)
            print(f"✓ Server responding (HTTP {response.status_code})")
            
            # Parse URL for further analysis
            parsed_url = urlparse(url)
            base_url = f"{parsed_url.scheme}://{parsed_url.netloc}"
            
            if ssl_check:
                self._check_ssl_certificate(parsed_url.netloc, parsed_url.port or (443 if parsed_url.scheme == 'https' else 80))
            
            if headers:
                self._analyze_security_headers(response)
            
            if directories:
                self._directory_enumeration(base_url)
            
            if vulnerabilities:
                self._vulnerability_scan(url, response)
                
        except requests.RequestException as e:
            print(f"✗ Connection failed: {e}")
        except Exception as e:
            print(f"✗ Error: {e}")
    
    def _check_ssl_certificate(self, hostname: str, port: int) -> None:
        """Check SSL/TLS certificate details"""
        print(f"\n[+] SSL/TLS Certificate Analysis")
        print("-" * 40)
        
        try:
            # Get certificate info
            context = ssl.create_default_context()
            
            with socket.create_connection((hostname, port), timeout=10) as sock:
                with context.wrap_socket(sock, server_hostname=hostname) as secure_sock:
                    cert = secure_sock.getpeercert()
                    
            # Analyze certificate
            print(f"Subject: {dict(x[0] for x in cert['subject'])['commonName']}")
            print(f"Issuer: {dict(x[0] for x in cert['issuer'])['commonName']}")
            print(f"Version: {cert['version']}")
            print(f"Serial Number: {cert['serialNumber']}")
            print(f"Not Before: {cert['notBefore']}")
            print(f"Not After: {cert['notAfter']}")
            
            # Check for security issues
            import datetime
            not_after = datetime.datetime.strptime(cert['notAfter'], '%b %d %H:%M:%S %Y %Z')
            days_until_expiry = (not_after - datetime.datetime.now()).days
            
            if days_until_expiry < 30:
                print(f"⚠ Certificate expires in {days_until_expiry} days!")
            else:
                print(f"✓ Certificate valid for {days_until_expiry} days")
            
            # Check Subject Alternative Names
            if 'subjectAltName' in cert:
                san = [name[1] for name in cert['subjectAltName']]
                print(f"Alt Names: {', '.join(san[:5])}{'...' if len(san) > 5 else ''}")
            
            # Check signature algorithm
            print(f"Signature Algorithm: {cert.get('signatureAlgorithm', 'Unknown')}")
            
            # Test SSL/TLS versions
            self._test_ssl_versions(hostname, port)
            
        except Exception as e:
            print(f"✗ SSL check failed: {e}")
    
    def _test_ssl_versions(self, hostname: str, port: int) -> None:
        """Test supported SSL/TLS versions"""
        print(f"\n[+] Testing SSL/TLS versions:")
        
        protocols = {
            'SSLv2': ssl.PROTOCOL_SSLv23,  # This will be rejected by modern systems
            'SSLv3': ssl.PROTOCOL_SSLv23,
            'TLSv1.0': ssl.PROTOCOL_TLSv1,
            'TLSv1.1': ssl.PROTOCOL_TLSv1_1,
            'TLSv1.2': ssl.PROTOCOL_TLSv1_2,
        }
        
        # Try TLSv1.3 if available
        if hasattr(ssl, 'PROTOCOL_TLSv1_3'):
            protocols['TLSv1.3'] = ssl.PROTOCOL_TLSv1_3
        
        for protocol_name, protocol in protocols.items():
            try:
                context = ssl.SSLContext(protocol)
                context.check_hostname = False
                context.verify_mode = ssl.CERT_NONE
                
                with socket.create_connection((hostname, port), timeout=5) as sock:
                    with context.wrap_socket(sock) as secure_sock:
                        print(f"  {protocol_name}: ✓ Supported")
                        
            except Exception:
                print(f"  {protocol_name}: ✗ Not supported")
    
    def _analyze_security_headers(self, response: requests.Response) -> None:
        """Analyze HTTP security headers"""
        print(f"\n[+] Security Headers Analysis")
        print("-" * 40)
        
        headers = response.headers
        score = 0
        max_score = len(self.security_headers)
        
        for header, description in self.security_headers.items():
            if header in headers:
                print(f"✓ {header}: {headers[header][:50]}{'...' if len(headers[header]) > 50 else ''}")
                score += 1
            else:
                print(f"✗ {header}: Missing - {description}")
        
        print(f"\nSecurity Score: {score}/{max_score} ({(score/max_score)*100:.1f}%)")
        
        # Additional header analysis
        print(f"\n[+] Additional Headers:")
        
        # Server banner
        server = headers.get('Server', 'Not disclosed')
        print(f"Server: {server}")
        if any(tech in server.lower() for tech in ['apache/2.2', 'nginx/1.0', 'iis/6.0']):
            print("  ⚠ Potentially outdated server version")
        
        # Powered by
        powered_by = headers.get('X-Powered-By', 'Not disclosed')
        print(f"X-Powered-By: {powered_by}")
        
        # Cookies analysis
        cookies = response.cookies
        if cookies:
            print(f"\n[+] Cookie Analysis:")
            for cookie in cookies:
                secure = 'Secure' if cookie.secure else 'Not Secure'
                httponly = 'HttpOnly' if cookie.has_nonstandard_attr('HttpOnly') else 'No HttpOnly'
                print(f"  {cookie.name}: {secure}, {httponly}")
        
    def _directory_enumeration(self, base_url: str) -> None:
        """Perform directory enumeration"""
        print(f"\n[+] Directory Enumeration")
        print("-" * 30)
        
        found_dirs = []
        
        for directory in self.common_dirs:
            try:
                url = urljoin(base_url, directory)
                response = self.session.get(url, timeout=5, verify=False, allow_redirects=False)
                
                if response.status_code in [200, 301, 302, 403]:
                    status_text = {
                        200: 'Found',
                        301: 'Redirect',
                        302: 'Redirect', 
                        403: 'Forbidden'
                    }[response.status_code]
                    
                    found_dirs.append((directory, response.status_code, status_text))
                    print(f"  {response.status_code} {url} ({status_text})")
                    
            except requests.RequestException:
                pass
        
        if not found_dirs:
            print("  No interesting directories found")
        else:
            print(f"\nFound {len(found_dirs)} interesting paths")
    
    def _vulnerability_scan(self, url: str, response: requests.Response) -> None:
        """Basic vulnerability scanning"""
        print(f"\n[+] Vulnerability Assessment")
        print("-" * 35)
        
        vulnerabilities = []
        
        # Check for common vulnerabilities
        content = response.text.lower()
        
        # SQL Injection indicators
        sql_indicators = ['mysql_error', 'ora-', 'microsoft jet database', 'odbc', 'sql syntax']
        for indicator in sql_indicators:
            if indicator in content:
                vulnerabilities.append(f"Potential SQL injection indicator: {indicator}")
        
        # XSS vulnerability check
        xss_payload = "<script>alert('xss')</script>"
        try:
            test_response = self.session.get(f"{url}?test={xss_payload}", timeout=5, verify=False)
            if xss_payload in test_response.text:
                vulnerabilities.append("Potential XSS vulnerability")
        except:
            pass
        
        # Directory traversal
        try:
            traversal_response = self.session.get(f"{url}/../../../etc/passwd", timeout=5, verify=False)
            if 'root:' in traversal_response.text:
                vulnerabilities.append("Potential directory traversal vulnerability")
        except:
            pass
        
        # Check for sensitive files
        sensitive_files = ['.env', 'config.php', 'wp-config.php', '.git/config', 'backup.sql']
        for file in sensitive_files:
            try:
                file_url = urljoin(url, file)
                file_response = self.session.get(file_url, timeout=5, verify=False)
                if file_response.status_code == 200 and len(file_response.text) > 0:
                    vulnerabilities.append(f"Sensitive file exposed: {file}")
            except:
                pass
        
        # Check for admin interfaces
        admin_paths = ['/admin', '/administrator', '/wp-admin', '/phpmyadmin']
        for path in admin_paths:
            try:
                admin_url = urljoin(url, path)
                admin_response = self.session.get(admin_url, timeout=5, verify=False)
                if admin_response.status_code == 200:
                    vulnerabilities.append(f"Admin interface found: {path}")
            except:
                pass
        
        # Check for default credentials
        self._check_default_credentials(url)
        
        # Report vulnerabilities
        if vulnerabilities:
            print("Potential vulnerabilities found:")
            for vuln in vulnerabilities:
                print(f"  ⚠ {vuln}")
        else:
            print("✓ No obvious vulnerabilities detected")
        
        # Security recommendations
        print(f"\n[+] Security Recommendations:")
        print("  • Keep software updated")
        print("  • Use strong authentication")
        print("  • Implement proper input validation")
        print("  • Configure security headers")
        print("  • Regular security testing")
        print("  • Monitor for suspicious activity")
    
    def _check_default_credentials(self, url: str) -> None:
        """Check for default credentials"""
        print(f"\n[+] Testing for default credentials:")
        
        default_creds = [
            ('admin', 'admin'),
            ('admin', 'password'),
            ('admin', ''),
            ('root', 'root'),
            ('test', 'test')
        ]
        
        # Try to find login page
        login_paths = ['/login', '/admin', '/wp-login.php', '/signin']
        
        for path in login_paths:
            try:
                login_url = urljoin(url, path)
                response = self.session.get(login_url, timeout=5, verify=False)
                
                if response.status_code == 200 and any(term in response.text.lower() for term in ['login', 'password', 'username']):
                    print(f"  Login page found: {path}")
                    
                    # Simple credential test (be careful with this in production!)
                    for username, password in default_creds[:2]:  # Limit attempts
                        try:
                            data = {'username': username, 'password': password}
                            auth_response = self.session.post(login_url, data=data, timeout=5, verify=False)
                            
                            if 'dashboard' in auth_response.text.lower() or auth_response.status_code in [302, 301]:
                                print(f"  ⚠ Possible default credentials: {username}:{password}")
                            
                        except:
                            pass
                    break
                    
            except:
                pass