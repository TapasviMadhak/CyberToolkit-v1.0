"""
Password Security Tools
======================

Tools for password analysis, generation, and breach checking.
"""

import re
import random
import string
import hashlib
import requests
import time
from typing import Dict, List, Tuple

class PasswordTools:
    def __init__(self):
        self.common_passwords = [
            'password', '123456', 'password123', 'admin', 'qwerty',
            'letmein', 'welcome', 'monkey', '1234567890', 'abc123'
        ]
        
        self.password_patterns = {
            'weak_patterns': [
                r'(.)\1{2,}',  # Repeated characters
                r'(012|123|234|345|456|567|678|789|890)',  # Sequential numbers
                r'(abc|bcd|cde|def|efg|fgh|ghi|hij|ijk|jkl|klm|lmn|mno|nop|opq|pqr|qrs|rst|stu|tuv|uvw|vwx|wxy|xyz)',  # Sequential letters
                r'(qwe|wer|ert|rty|tyu|yui|uio|iop|asd|sdf|dfg|fgh|ghj|hjk|jkl|zxc|xcv|cvb|vbn|bnm)',  # Keyboard patterns
            ]
        }
    
    def analyze_strength(self, password: str) -> None:
        """Analyze password strength and provide detailed feedback"""
        print(f"\n[+] Analyzing password: {'*' * len(password)}")
        print("=" * 50)
        
        score = 0
        feedback = []
        
        # Length check
        if len(password) >= 12:
            score += 25
            feedback.append("✓ Good length (12+ characters)")
        elif len(password) >= 8:
            score += 15
            feedback.append("⚠ Moderate length (8-11 characters)")
        else:
            feedback.append("✗ Too short (< 8 characters)")
        
        # Character variety
        has_lower = bool(re.search(r'[a-z]', password))
        has_upper = bool(re.search(r'[A-Z]', password))
        has_digit = bool(re.search(r'\d', password))
        has_special = bool(re.search(r'[!@#$%^&*()_+\-=\[\]{};\':"\\|,.<>\/?]', password))
        
        char_types = sum([has_lower, has_upper, has_digit, has_special])
        
        if char_types == 4:
            score += 25
            feedback.append("✓ Excellent character variety (lowercase, uppercase, digits, symbols)")
        elif char_types == 3:
            score += 20
            feedback.append("⚠ Good character variety (3 types)")
        elif char_types == 2:
            score += 10
            feedback.append("⚠ Moderate character variety (2 types)")
        else:
            feedback.append("✗ Poor character variety (1 type)")
        
        # Common password check
        if password.lower() in [p.lower() for p in self.common_passwords]:
            feedback.append("✗ Common password detected!")
        else:
            score += 15
            feedback.append("✓ Not a common password")
        
        # Pattern analysis
        weak_patterns_found = []
        for pattern in self.password_patterns['weak_patterns']:
            if re.search(pattern, password.lower()):
                weak_patterns_found.append(pattern)
        
        if not weak_patterns_found:
            score += 15
            feedback.append("✓ No weak patterns detected")
        else:
            feedback.append(f"✗ Weak patterns detected: {len(weak_patterns_found)}")
        
        # Dictionary words check
        common_words = ['password', 'admin', 'user', 'login', 'welcome', 'hello', 'world']
        has_common_words = any(word in password.lower() for word in common_words)
        
        if not has_common_words:
            score += 10
            feedback.append("✓ No common dictionary words")
        else:
            feedback.append("✗ Contains common dictionary words")
        
        # Entropy calculation
        entropy = self._calculate_entropy(password)
        if entropy >= 60:
            score += 10
            feedback.append(f"✓ High entropy ({entropy:.1f} bits)")
        elif entropy >= 40:
            score += 5
            feedback.append(f"⚠ Moderate entropy ({entropy:.1f} bits)")
        else:
            feedback.append(f"✗ Low entropy ({entropy:.1f} bits)")
        
        # Display results
        print(f"Password Score: {score}/100")
        
        if score >= 80:
            strength = "VERY STRONG 🟢"
        elif score >= 60:
            strength = "STRONG 🟡"
        elif score >= 40:
            strength = "MODERATE 🟠"
        elif score >= 20:
            strength = "WEAK 🔴"
        else:
            strength = "VERY WEAK ⛔"
        
        print(f"Strength Rating: {strength}")
        print("\nDetailed Analysis:")
        for item in feedback:
            print(f"  {item}")
        
        # Recommendations
        print("\nRecommendations:")
        if len(password) < 12:
            print("  • Use at least 12 characters")
        if not has_upper:
            print("  • Add uppercase letters")
        if not has_lower:
            print("  • Add lowercase letters")
        if not has_digit:
            print("  • Add numbers")
        if not has_special:
            print("  • Add special characters (!@#$%^&*)")
        if weak_patterns_found:
            print("  • Avoid predictable patterns")
        if has_common_words:
            print("  • Avoid common dictionary words")
    
    def _calculate_entropy(self, password: str) -> float:
        """Calculate password entropy in bits"""
        charset_size = 0
        
        if re.search(r'[a-z]', password):
            charset_size += 26
        if re.search(r'[A-Z]', password):
            charset_size += 26
        if re.search(r'\d', password):
            charset_size += 10
        if re.search(r'[!@#$%^&*()_+\-=\[\]{};\':"\\|,.<>\/?]', password):
            charset_size += 32
        
        if charset_size == 0:
            return 0
        
        import math
        return len(password) * math.log2(charset_size)
    
    def generate_password(self, length: int = 16, complexity: str = 'high') -> None:
        """Generate a secure password"""
        print(f"\n[+] Generating {complexity} complexity password ({length} characters)")
        print("=" * 50)
        
        if complexity == 'low':
            charset = string.ascii_letters + string.digits
        elif complexity == 'medium':
            charset = string.ascii_letters + string.digits + "!@#$%^&*"
        else:  # high
            charset = string.ascii_letters + string.digits + "!@#$%^&*()_+-=[]{}|;:,.<>?"
        
        # Ensure at least one character from each required set
        password = []
        
        if complexity in ['medium', 'high']:
            password.append(random.choice(string.ascii_lowercase))
            password.append(random.choice(string.ascii_uppercase))
            password.append(random.choice(string.digits))
            password.append(random.choice("!@#$%^&*"))
        
        # Fill the rest randomly
        remaining_length = length - len(password)
        for _ in range(remaining_length):
            password.append(random.choice(charset))
        
        # Shuffle to avoid predictable patterns
        random.shuffle(password)
        final_password = ''.join(password)
        
        print(f"Generated Password: {final_password}")
        
        # Quick strength analysis
        self.analyze_strength(final_password)
    
    def check_breach(self, password: str) -> None:
        """Check if password appears in known data breaches using HaveIBeenPwned API"""
        print(f"\n[+] Checking password against known breaches...")
        print("=" * 50)
        
        # Hash the password
        sha1_hash = hashlib.sha1(password.encode('utf-8')).hexdigest().upper()
        prefix = sha1_hash[:5]
        suffix = sha1_hash[5:]
        
        try:
            # Query HaveIBeenPwned API
            url = f"https://api.pwnedpasswords.com/range/{prefix}"
            response = requests.get(url, timeout=10)
            
            if response.status_code == 200:
                hashes = response.text.splitlines()
                
                for hash_line in hashes:
                    hash_suffix, count = hash_line.split(':')
                    if hash_suffix == suffix:
                        print(f"⚠ WARNING: Password found in {count} known breaches!")
                        print("This password has been compromised and should NOT be used.")
                        return
                
                print("✓ Good news! This password was not found in known breaches.")
                print("However, this doesn't guarantee it's secure - use strong, unique passwords.")
            
            else:
                print(f"✗ Error checking breach database (HTTP {response.status_code})")
                
        except requests.RequestException as e:
            print(f"✗ Network error: {e}")
        except Exception as e:
            print(f"✗ Error: {e}")