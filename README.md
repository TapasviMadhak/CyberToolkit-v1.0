
# 🛡️ CyberToolkit - Multi-Purpose Security Suite

A comprehensive cybersecurity toolkit for penetration testing, security analysis, and educational purposes. Built with Python, this toolkit combines multiple security tools into a single, easy-to-use command-line interface.

![Python](https://img.shields.io/badge/python-3.7+-blue.svg)
![License](https://img.shields.io/badge/license-MIT-green.svg)
![Security](https://img.shields.io/badge/security-toolkit-red.svg)

## 🚀 Features

### 🔐 Password Security Suite
- **Password Strength Analysis**: Comprehensive analysis with entropy calculation
- **Secure Password Generation**: Customizable length and complexity
- **Breach Detection**: Check against HaveIBeenPwned database
- **Pattern Recognition**: Detect weak patterns and dictionary words

### 🌐 Network Reconnaissance Tools
- **Port Scanner**: Multi-threaded scanning with banner grabbing
- **Ping Sweep**: Network discovery and host enumeration
- **Service Detection**: Identify running services and versions
- **Security Assessment**: Analyze open ports for security risks

### 🔍 Cryptographic Tools
- **Hash Generation**: Support for MD5, SHA1, SHA256, SHA512, SHA3
- **File Integrity Verification**: Compare file hashes
- **HMAC Generation**: Message authentication codes
- **Entropy Analysis**: Detect encryption/compression patterns

### 🕷️ Web Security Scanner
- **SSL/TLS Analysis**: Certificate validation and protocol testing
- **Security Headers**: Check for missing security headers
- **Directory Enumeration**: Discover hidden files and directories
- **Vulnerability Assessment**: Basic XSS, SQL injection, and traversal checks

### 📊 Log Analysis & Monitoring
- **Log Parser**: Support for multiple log formats (Apache, Nginx, SSH, Syslog)
- **Anomaly Detection**: Identify unusual patterns and activities
- **Failed Login Analysis**: Detect brute force attempts
- **Suspicious IP Detection**: Behavioral analysis and threat intelligence

## 📦 Installation

1. **Clone the repository:**
   ```bash
   git clone https://github.com/yourusername/cybertoolkit.git
   cd cybertoolkit
   ```

2. **Install dependencies:**
   ```bash
   pip install -r requirements.txt
   ```

3. **Make executable (Linux/Mac):**
   ```bash
   chmod +x main.py
   ```

## 🛠️ Usage

### Basic Syntax
```bash
python main.py <tool> [options]
```

### Password Security Tools

#### Analyze Password Strength
```bash
python main.py password --analyze "MyPassword123!"
```

#### Generate Secure Password
```bash
python main.py password --generate --length 20 --complexity high
```

#### Check for Data Breaches
```bash
python main.py password --check-breach "password123"
```

### Network Reconnaissance

#### Port Scan
```bash
python main.py network --scan 192.168.1.1 -p 1-1000 --threads 100
```

#### Ping Sweep
```bash
python main.py network --ping-sweep 192.168.1.0/24
```

### Cryptographic Operations

#### Hash a File
```bash
python main.py hash --file document.pdf --algorithm sha256
```

#### Hash Text
```bash
python main.py hash --text "Hello World" --algorithm sha512
```

#### Verify File Integrity
```bash
python main.py hash --verify document.pdf e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855
```

### Web Security Scanning

#### Comprehensive Web Scan
```bash
python main.py web --url https://example.com --ssl-check --headers --directories --vulnerabilities
```

#### SSL Certificate Analysis
```bash
python main.py web --url https://example.com --ssl-check
```

### Log Analysis

#### Analyze Security Logs
```bash
python main.py logs --file /var/log/auth.log --anomaly-detect --failed-logins --suspicious-ips
```

#### Filter by Time Range
```bash
python main.py logs --file access.log --time-range "2024-01-01" "2024-01-02"
```

## 🔧 Advanced Examples

### Security Audit Workflow
```bash
# 1. Scan network for live hosts
python main.py network --ping-sweep 10.0.0.0/24

# 2. Port scan discovered hosts
python main.py network --scan 10.0.0.100 -p 1-65535

# 3. Web security assessment
python main.py web --url http://10.0.0.100 --ssl-check --headers --vulnerabilities

# 4. Analyze logs for suspicious activity
python main.py logs --file /var/log/apache2/access.log --anomaly-detect --suspicious-ips
```

### Password Security Assessment
```bash
# Generate secure passwords for different purposes
python main.py password --generate --length 16 --complexity high
python main.py password --generate --length 32 --complexity high

# Test existing passwords
python main.py password --analyze "CurrentPassword2024!"
python main.py password --check-breach "CurrentPassword2024!"
```

## 🛡️ Security Features

### Built-in Protections
- **Rate Limiting**: Prevents aggressive scanning
- **Timeout Controls**: Avoids hanging connections
- **Error Handling**: Graceful failure management
- **Non-invasive**: Read-only operations by default

### Ethical Use Guidelines
- ✅ Only scan systems you own or have permission to test
- ✅ Use for educational and authorized security testing
- ✅ Respect rate limits and system resources
- ❌ Do not use for malicious purposes
- ❌ Do not test systems without permission

## 📊 Output Examples

### Password Analysis
```
[+] Analyzing password: **************
==================================================
Password Score: 85/100
Strength Rating: VERY STRONG 🟢

Detailed Analysis:
  ✓ Good length (16 characters)
  ✓ Excellent character variety (lowercase, uppercase, digits, symbols)
  ✓ Not a common password
  ✓ No weak patterns detected
  ✓ No common dictionary words
  ✓ High entropy (64.2 bits)
```

### Network Scan
```
[+] Starting port scan on 192.168.1.1
[+] Port range: 1-1000
[+] Timeout: 1.0s | Threads: 100
============================================================
[+] Progress: 100.0% (1000/1000)

[+] Scan completed in 15.32 seconds
[+] Found 5 open ports:
------------------------------------------------------------
PORT     STATE    SERVICE         BANNER
22       Open     SSH             SSH-2.0-OpenSSH_8.9p1
80       Open     HTTP            Apache/2.4.41 (Ubuntu)
443      Open     HTTPS           Apache/2.4.41 (Ubuntu)
```

### Web Security Scan
```
[+] Security Headers Analysis
----------------------------------------
✓ X-Frame-Options: SAMEORIGIN
✓ X-XSS-Protection: 1; mode=block
✗ X-Content-Type-Options: Missing - MIME type sniffing protection
✓ Strict-Transport-Security: max-age=31536000
✗ Content-Security-Policy: Missing - Content injection protection

Security Score: 3/8 (37.5%)
```

## 🤝 Contributing

1. Fork the repository
2. Create a feature branch (`git checkout -b feature/amazing-feature`)
3. Commit your changes (`git commit -m 'Add amazing feature'`)
4. Push to the branch (`git push origin feature/amazing-feature`)
5. Open a Pull Request

## 📝 License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

## ⚠️ Disclaimer

This tool is for educational and authorized security testing purposes only. Users are responsible for complying with applicable laws and regulations. The authors are not responsible for any misuse of this software.

## 🔗 Resources

- [OWASP Testing Guide](https://owasp.org/www-project-web-security-testing-guide/)
- [NIST Cybersecurity Framework](https://www.nist.gov/cyberframework)
- [SANS Security Resources](https://www.sans.org/security-resources/)
- [CVE Database](https://cve.mitre.org/)

## 📞 Support

If you have questions or need help:
- 📧 Email: your.email@example.com
- 💬 Create an issue on GitHub
- 📖 Check the documentation

---

**Made with ❤️ for the cybersecurity community**
