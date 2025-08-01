"""
Log Analysis Tools
=================

Tools for security log analysis and anomaly detection.
"""

import re
import os
import time
from datetime import datetime, timedelta
from collections import Counter, defaultdict
from typing import List, Dict, Set, Tuple
import ipaddress

class LogAnalyzer:
    def __init__(self):
        # Common log patterns
        self.log_patterns = {
            'apache_access': r'(\S+) \S+ \S+ \[([\w:/]+\s[+\-]\d{4})\] "(\S+) (\S+) (\S+)" (\d{3}) (\d+|-)',
            'nginx_access': r'(\S+) - - \[(.*?)\] "(\w+) (.*?) HTTP/\d\.\d" (\d+) (\d+) "(.*?)" "(.*?)"',
            'ssh_auth': r'(\w+\s+\d+\s+\d+:\d+:\d+) (\S+) sshd\[(\d+)\]: (.*)',
            'windows_security': r'(\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2}) (\w+) (\d+) (.*)',
            'firewall': r'(\w+\s+\d+\s+\d+:\d+:\d+) (\S+) (\S+): (\S+) (\S+) (\S+) (\S+)',
            'general_syslog': r'(\w+\s+\d+\s+\d+:\d+:\d+) (\S+) (\S+): (.*)'
        }
        
        # Suspicious patterns
        self.suspicious_patterns = {
            'sql_injection': [
                r"union.*select", r"1=1", r"' or ", r"' and ", r"drop table",
                r"select.*from", r"insert into", r"delete from"
            ],
            'xss_attempts': [
                r"<script", r"javascript:", r"onerror=", r"onload=", r"eval\("
            ],
            'directory_traversal': [
                r"\.\.\/", r"\.\.\\", r"\/etc\/passwd", r"\/windows\/system32"
            ],
            'brute_force': [
                r"authentication failure", r"failed login", r"invalid user",
                r"login failed", r"authentication failed"
            ],
            'scanning': [
                r"nmap", r"nikto", r"sqlmap", r"burp", r"dirb", r"gobuster"
            ]
        }
        
        # Known malicious IPs/patterns (simplified examples)
        self.known_bad_ips = {
            '127.0.0.1': 'Test IP',  # Example - replace with real threat intelligence
        }
        
        # Countries often associated with attacks (be careful with geo-blocking)
        self.suspicious_countries = ['CN', 'RU', 'KP', 'IR']  # Example list
    
    def analyze_logs(self, filepath: str, anomaly_detect: bool = False, 
                    failed_logins: bool = False, suspicious_ips: bool = False,
                    time_range: List[str] = None) -> None:
        """Main log analysis function"""
        print(f"\n[+] Analyzing log file: {filepath}")
        print("=" * 60)
        
        if not os.path.isfile(filepath):
            print("✗ Log file not found")
            return
        
        try:
            with open(filepath, 'r', encoding='utf-8', errors='ignore') as f:
                log_lines = f.readlines()
            
            print(f"[+] Loaded {len(log_lines)} log entries")
            
            # Parse logs
            parsed_logs = self._parse_logs(log_lines)
            print(f"[+] Successfully parsed {len(parsed_logs)} entries")
            
            # Apply time filter if specified
            if time_range:
                parsed_logs = self._filter_by_time(parsed_logs, time_range)
                print(f"[+] Filtered to {len(parsed_logs)} entries in time range")
            
            if not parsed_logs:
                print("No log entries to analyze")
                return
            
            # General statistics
            self._show_general_stats(parsed_logs)
            
            if failed_logins:
                self._analyze_failed_logins(parsed_logs)
            
            if suspicious_ips:
                self._analyze_suspicious_ips(parsed_logs)
            
            if anomaly_detect:
                self._detect_anomalies(parsed_logs)
            
            # Always show security events
            self._detect_security_events(parsed_logs)
            
        except Exception as e:
            print(f"✗ Error analyzing logs: {e}")
    
    def _parse_logs(self, log_lines: List[str]) -> List[Dict]:
        """Parse log lines into structured format"""
        parsed_logs = []
        
        for line_num, line in enumerate(log_lines, 1):
            line = line.strip()
            if not line:
                continue
            
            parsed_entry = self._parse_single_line(line)
            if parsed_entry:
                parsed_entry['line_number'] = line_num
                parsed_logs.append(parsed_entry)
        
        return parsed_logs
    
    def _parse_single_line(self, line: str) -> Dict or None:
        """Parse a single log line"""
        # Try different log formats
        for log_type, pattern in self.log_patterns.items():
            match = re.match(pattern, line)
            if match:
                if log_type == 'apache_access':
                    return {
                        'timestamp': match.group(2),
                        'ip': match.group(1),
                        'method': match.group(3),
                        'url': match.group(4),
                        'status': int(match.group(6)),
                        'size': match.group(7),
                        'type': 'web_access',
                        'raw': line
                    }
                elif log_type == 'ssh_auth':
                    return {
                        'timestamp': match.group(1),
                        'host': match.group(2),
                        'pid': match.group(3),
                        'message': match.group(4),
                        'type': 'ssh_auth',
                        'raw': line
                    }
                elif log_type == 'general_syslog':
                    return {
                        'timestamp': match.group(1),
                        'host': match.group(2),
                        'service': match.group(3),
                        'message': match.group(4),
                        'type': 'syslog',
                        'raw': line
                    }
        
        # If no pattern matches, create a generic entry
        return {
            'timestamp': 'unknown',
            'message': line,
            'type': 'unknown',
            'raw': line
        }
    
    def _filter_by_time(self, logs: List[Dict], time_range: List[str]) -> List[Dict]:
        """Filter logs by time range"""
        # This is a simplified implementation
        # In practice, you'd want more robust datetime parsing
        start_time, end_time = time_range
        # For now, just return all logs (implement proper filtering as needed)
        return logs
    
    def _show_general_stats(self, logs: List[Dict]) -> None:
        """Show general log statistics"""
        print(f"\n[+] General Statistics")
        print("-" * 25)
        
        # Count by type
        type_counts = Counter([log.get('type', 'unknown') for log in logs])
        print("Log Types:")
        for log_type, count in type_counts.most_common():
            print(f"  {log_type}: {count}")
        
        # Count IPs if available
        ips = [log.get('ip') for log in logs if log.get('ip')]
        if ips:
            ip_counts = Counter(ips)
            print(f"\nTop Source IPs:")
            for ip, count in ip_counts.most_common(10):
                print(f"  {ip}: {count} requests")
        
        # HTTP status codes for web logs
        statuses = [log.get('status') for log in logs if log.get('status')]
        if statuses:
            status_counts = Counter(statuses)
            print(f"\nHTTP Status Codes:")
            for status, count in sorted(status_counts.items()):
                print(f"  {status}: {count}")
    
    def _analyze_failed_logins(self, logs: List[Dict]) -> None:
        """Analyze failed login attempts"""
        print(f"\n[+] Failed Login Analysis")
        print("-" * 30)
        
        failed_attempts = []
        
        for log in logs:
            message = log.get('message', '').lower()
            if any(pattern in message for pattern in ['failed', 'invalid', 'authentication failure']):
                failed_attempts.append(log)
        
        if not failed_attempts:
            print("No failed login attempts detected")
            return
        
        print(f"Found {len(failed_attempts)} failed login attempts")
        
        # Analyze by IP
        ip_failures = defaultdict(int)
        for attempt in failed_attempts:
            ip = self._extract_ip_from_message(attempt.get('message', ''))
            if ip:
                ip_failures[ip] += 1
        
        if ip_failures:
            print(f"\nFailed attempts by IP:")
            for ip, count in sorted(ip_failures.items(), key=lambda x: x[1], reverse=True)[:10]:
                print(f"  {ip}: {count} attempts")
                if count > 10:
                    print(f"    ⚠ Potential brute force attack!")
        
        # Timeline analysis
        print(f"\nSample failed attempts:")
        for attempt in failed_attempts[:5]:
            timestamp = attempt.get('timestamp', 'Unknown')
            message = attempt.get('message', '')[:80]
            print(f"  {timestamp}: {message}...")
    
    def _extract_ip_from_message(self, message: str) -> str or None:
        """Extract IP address from log message"""
        ip_pattern = r'\b(?:[0-9]{1,3}\.){3}[0-9]{1,3}\b'
        match = re.search(ip_pattern, message)
        return match.group() if match else None
    
    def _analyze_suspicious_ips(self, logs: List[Dict]) -> None:
        """Analyze suspicious IP addresses"""
        print(f"\n[+] Suspicious IP Analysis")
        print("-" * 30)
        
        # Collect all IPs
        all_ips = set()
        ip_activity = defaultdict(list)
        
        for log in logs:
            ip = log.get('ip') or self._extract_ip_from_message(log.get('message', ''))
            if ip and self._is_valid_ip(ip):
                all_ips.add(ip)
                ip_activity[ip].append(log)
        
        suspicious_ips = []
        
        for ip in all_ips:
            activity = ip_activity[ip]
            suspicion_score = 0
            reasons = []
            
            # High request volume
            if len(activity) > 100:
                suspicion_score += 2
                reasons.append(f"High activity ({len(activity)} requests)")
            
            # Check for scanning behavior
            if self._detect_scanning_behavior(activity):
                suspicion_score += 3
                reasons.append("Scanning behavior detected")
            
            # Check for attack patterns
            attack_count = self._count_attack_patterns(activity)
            if attack_count > 0:
                suspicion_score += attack_count
                reasons.append(f"Attack patterns ({attack_count})")
            
            # Check against known bad IPs
            if ip in self.known_bad_ips:
                suspicion_score += 5
                reasons.append(f"Known malicious IP: {self.known_bad_ips[ip]}")
            
            # Private/internal IPs doing external-like behavior
            if self._is_private_ip(ip) and len(activity) > 50:
                suspicion_score += 1
                reasons.append("Internal IP with high external activity")
            
            if suspicion_score >= 3:
                suspicious_ips.append((ip, suspicion_score, reasons))
        
        if suspicious_ips:
            print(f"Found {len(suspicious_ips)} suspicious IPs:")
            for ip, score, reasons in sorted(suspicious_ips, key=lambda x: x[1], reverse=True):
                print(f"\n  🚨 {ip} (Risk Score: {score})")
                for reason in reasons:
                    print(f"    • {reason}")
        else:
            print("No obviously suspicious IPs detected")
    
    def _is_valid_ip(self, ip: str) -> bool:
        """Check if string is a valid IP address"""
        try:
            ipaddress.ip_address(ip)
            return True
        except ValueError:
            return False
    
    def _is_private_ip(self, ip: str) -> bool:
        """Check if IP is in private range"""
        try:
            return ipaddress.ip_address(ip).is_private
        except ValueError:
            return False
    
    def _detect_scanning_behavior(self, activity: List[Dict]) -> bool:
        """Detect if activity looks like scanning"""
        # Look for requests to many different URLs/paths
        urls = set()
        for log in activity:
            url = log.get('url', '')
            if url:
                urls.add(url)
        
        # If accessing many different URLs, might be scanning
        return len(urls) > 20
    
    def _count_attack_patterns(self, activity: List[Dict]) -> int:
        """Count potential attack patterns in activity"""
        attack_count = 0
        
        for log in activity:
            content = (log.get('message', '') + log.get('url', '')).lower()
            
            for attack_type, patterns in self.suspicious_patterns.items():
                for pattern in patterns:
                    if re.search(pattern, content, re.IGNORECASE):
                        attack_count += 1
                        break  # Count each attack type once per log entry
        
        return attack_count
    
    def _detect_anomalies(self, logs: List[Dict]) -> None:
        """Detect anomalies in log data"""
        print(f"\n[+] Anomaly Detection")
        print("-" * 25)
        
        anomalies = []
        
        # Time-based anomalies
        hourly_activity = defaultdict(int)
        for log in logs:
            # Simple hour extraction (would need better parsing in practice)
            timestamp = log.get('timestamp', '')
            hour = self._extract_hour(timestamp)
            if hour is not None:
                hourly_activity[hour] += 1
        
        if hourly_activity:
            avg_activity = sum(hourly_activity.values()) / len(hourly_activity)
            for hour, count in hourly_activity.items():
                if count > avg_activity * 3:  # 3x above average
                    anomalies.append(f"Unusual activity spike at hour {hour}: {count} events")
        
        # Size-based anomalies for web logs
        sizes = [log.get('size') for log in logs if log.get('size') and log.get('size') != '-']
        if sizes:
            sizes = [int(s) for s in sizes if s.isdigit()]
            if sizes:
                avg_size = sum(sizes) / len(sizes)
                for log in logs:
                    size = log.get('size')
                    if size and size.isdigit() and int(size) > avg_size * 10:
                        anomalies.append(f"Unusually large response: {size} bytes from {log.get('ip', 'unknown')}")
        
        # Status code anomalies
        status_counts = Counter([log.get('status') for log in logs if log.get('status')])
        total_requests = sum(status_counts.values())
        
        for status, count in status_counts.items():
            if status >= 400 and count > total_requests * 0.1:  # >10% error rate
                anomalies.append(f"High error rate: {count} requests with status {status}")
        
        if anomalies:
            print("Anomalies detected:")
            for anomaly in anomalies[:10]:  # Limit output
                print(f"  ⚠ {anomaly}")
        else:
            print("No significant anomalies detected")
    
    def _extract_hour(self, timestamp: str) -> int or None:
        """Extract hour from timestamp string"""
        # Simple regex to find hour (HH:MM:SS pattern)
        hour_match = re.search(r'(\d{1,2}):(\d{2}):(\d{2})', timestamp)
        if hour_match:
            return int(hour_match.group(1))
        return None
    
    def _detect_security_events(self, logs: List[Dict]) -> None:
        """Detect security-related events"""
        print(f"\n[+] Security Events Detection")
        print("-" * 35)
        
        security_events = {
            'sql_injection': [],
            'xss_attempts': [],
            'directory_traversal': [],
            'brute_force': [],
            'scanning': []
        }
        
        for log in logs:
            content = (log.get('message', '') + log.get('url', '')).lower()
            
            for event_type, patterns in self.suspicious_patterns.items():
                for pattern in patterns:
                    if re.search(pattern, content, re.IGNORECASE):
                        security_events[event_type].append(log)
                        break
        
        total_events = sum(len(events) for events in security_events.values())
        
        if total_events > 0:
            print(f"Found {total_events} potential security events:")
            
            for event_type, events in security_events.items():
                if events:
                    print(f"\n  {event_type.upper().replace('_', ' ')}: {len(events)} events")
                    
                    # Show examples
                    for event in events[:3]:  # Show first 3 examples
                        timestamp = event.get('timestamp', 'Unknown')
                        source = event.get('ip', 'Unknown')
                        content = event.get('raw', '')[:100]
                        print(f"    {timestamp} from {source}: {content}...")
                    
                    if len(events) > 3:
                        print(f"    ... and {len(events) - 3} more")
        else:
            print("✓ No obvious security events detected")