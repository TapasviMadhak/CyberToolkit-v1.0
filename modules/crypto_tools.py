"""
Cryptographic Tools
==================

Tools for hashing, encryption, and file integrity verification.
"""

import hashlib
import hmac
import os
import base64
import binascii
import time
from typing import Dict, Optional
from pathlib import Path

class CryptoTools:
    def __init__(self):
        self.supported_algorithms = {
            'md5': hashlib.md5,
            'sha1': hashlib.sha1,
            'sha224': hashlib.sha224,
            'sha256': hashlib.sha256,
            'sha384': hashlib.sha384,
            'sha512': hashlib.sha512,
            'sha3_224': hashlib.sha3_224,
            'sha3_256': hashlib.sha3_256,
            'sha3_384': hashlib.sha3_384,
            'sha3_512': hashlib.sha3_512,
        }
    
    def hash_file(self, filepath: str, algorithm: str = 'sha256') -> None:
        """Calculate hash of a file"""
        print(f"\n[+] Calculating {algorithm.upper()} hash for: {filepath}")
        print("=" * 60)
        
        if not os.path.isfile(filepath):
            print("✗ File not found")
            return
        
        if algorithm not in self.supported_algorithms:
            print(f"✗ Unsupported algorithm. Supported: {', '.join(self.supported_algorithms.keys())}")
            return
        
        try:
            hash_func = self.supported_algorithms[algorithm]()
            file_size = os.path.getsize(filepath)
            
            start_time = time.time()
            
            with open(filepath, 'rb') as f:
                # Read file in chunks for large files
                chunk_size = 65536  # 64KB chunks
                bytes_read = 0
                
                while chunk := f.read(chunk_size):
                    hash_func.update(chunk)
                    bytes_read += len(chunk)
                    
                    # Show progress for large files
                    if file_size > 1024 * 1024:  # > 1MB
                        progress = (bytes_read / file_size) * 100
                        print(f"\r[+] Progress: {progress:.1f}%", end='', flush=True)
            
            if file_size > 1024 * 1024:
                print()  # New line after progress
            
            end_time = time.time()
            hash_value = hash_func.hexdigest()
            
            print(f"File: {filepath}")
            print(f"Size: {self._format_file_size(file_size)}")
            print(f"Algorithm: {algorithm.upper()}")
            print(f"Hash: {hash_value}")
            print(f"Time: {end_time - start_time:.2f} seconds")
            
            # Save hash to file
            hash_filename = f"{filepath}.{algorithm}"
            with open(hash_filename, 'w') as hash_file:
                hash_file.write(f"{hash_value}  {os.path.basename(filepath)}\n")
            print(f"Hash saved to: {hash_filename}")
            
        except Exception as e:
            print(f"✗ Error: {e}")
    
    def hash_text(self, text: str, algorithm: str = 'sha256') -> None:
        """Calculate hash of text string"""
        print(f"\n[+] Calculating {algorithm.upper()} hash for text")
        print("=" * 50)
        
        if algorithm not in self.supported_algorithms:
            print(f"✗ Unsupported algorithm. Supported: {', '.join(self.supported_algorithms.keys())}")
            return
        
        try:
            hash_func = self.supported_algorithms[algorithm]()
            hash_func.update(text.encode('utf-8'))
            hash_value = hash_func.hexdigest()
            
            print(f"Text: {text[:50]}{'...' if len(text) > 50 else ''}")
            print(f"Length: {len(text)} characters")
            print(f"Algorithm: {algorithm.upper()}")
            print(f"Hash: {hash_value}")
            
            # Also show base64 encoding
            hash_b64 = base64.b64encode(binascii.unhexlify(hash_value)).decode()
            print(f"Base64: {hash_b64}")
            
        except Exception as e:
            print(f"✗ Error: {e}")
    
    def verify_integrity(self, filepath: str, expected_hash: str, algorithm: str = 'sha256') -> None:
        """Verify file integrity against expected hash"""
        print(f"\n[+] Verifying file integrity: {filepath}")
        print("=" * 60)
        
        if not os.path.isfile(filepath):
            print("✗ File not found")
            return
        
        if algorithm not in self.supported_algorithms:
            print(f"✗ Unsupported algorithm. Supported: {', '.join(self.supported_algorithms.keys())}")
            return
        
        try:
            # Calculate current hash
            hash_func = self.supported_algorithms[algorithm]()
            
            with open(filepath, 'rb') as f:
                while chunk := f.read(65536):
                    hash_func.update(chunk)
            
            current_hash = hash_func.hexdigest().lower()
            expected_hash = expected_hash.lower().strip()
            
            print(f"File: {filepath}")
            print(f"Algorithm: {algorithm.upper()}")
            print(f"Expected:  {expected_hash}")
            print(f"Calculated: {current_hash}")
            
            if current_hash == expected_hash:
                print("✓ INTEGRITY VERIFIED - File is intact")
            else:
                print("✗ INTEGRITY FAILED - File has been modified or corrupted!")
                
                # Calculate similarity
                matching_chars = sum(1 for a, b in zip(current_hash, expected_hash) if a == b)
                similarity = (matching_chars / len(current_hash)) * 100
                print(f"Hash similarity: {similarity:.1f}%")
                
        except Exception as e:
            print(f"✗ Error: {e}")
    
    def generate_hmac(self, message: str, key: str, algorithm: str = 'sha256') -> None:
        """Generate HMAC for message authentication"""
        print(f"\n[+] Generating HMAC-{algorithm.upper()}")
        print("=" * 40)
        
        if algorithm not in self.supported_algorithms:
            print(f"✗ Unsupported algorithm. Supported: {', '.join(self.supported_algorithms.keys())}")
            return
        
        try:
            key_bytes = key.encode('utf-8')
            message_bytes = message.encode('utf-8')
            
            hmac_obj = hmac.new(key_bytes, message_bytes, self.supported_algorithms[algorithm])
            hmac_hex = hmac_obj.hexdigest()
            hmac_b64 = base64.b64encode(hmac_obj.digest()).decode()
            
            print(f"Message: {message[:50]}{'...' if len(message) > 50 else ''}")
            print(f"Key: {'*' * len(key)} ({len(key)} chars)")
            print(f"Algorithm: HMAC-{algorithm.upper()}")
            print(f"HMAC (hex): {hmac_hex}")
            print(f"HMAC (base64): {hmac_b64}")
            
        except Exception as e:
            print(f"✗ Error: {e}")
    
    def compare_files(self, file1: str, file2: str, algorithm: str = 'sha256') -> None:
        """Compare two files using cryptographic hashes"""
        print(f"\n[+] Comparing files using {algorithm.upper()}")
        print("=" * 50)
        
        if not os.path.isfile(file1):
            print(f"✗ File not found: {file1}")
            return
        
        if not os.path.isfile(file2):
            print(f"✗ File not found: {file2}")
            return
        
        try:
            # Calculate hash for file1
            hash1 = self._calculate_file_hash(file1, algorithm)
            hash2 = self._calculate_file_hash(file2, algorithm)
            
            print(f"File 1: {file1}")
            print(f"Hash 1: {hash1}")
            print(f"Size 1: {self._format_file_size(os.path.getsize(file1))}")
            print()
            print(f"File 2: {file2}")
            print(f"Hash 2: {hash2}")
            print(f"Size 2: {self._format_file_size(os.path.getsize(file2))}")
            print()
            
            if hash1 == hash2:
                print("✓ FILES ARE IDENTICAL")
            else:
                print("✗ FILES ARE DIFFERENT")
                
                # Show where they differ
                diff_chars = sum(1 for a, b in zip(hash1, hash2) if a != b)
                similarity = ((len(hash1) - diff_chars) / len(hash1)) * 100
                print(f"Hash similarity: {similarity:.1f}%")
                
        except Exception as e:
            print(f"✗ Error: {e}")
    
    def _calculate_file_hash(self, filepath: str, algorithm: str) -> str:
        """Calculate hash of a file (helper method)"""
        hash_func = self.supported_algorithms[algorithm]()
        
        with open(filepath, 'rb') as f:
            while chunk := f.read(65536):
                hash_func.update(chunk)
        
        return hash_func.hexdigest()
    
    def _format_file_size(self, size_bytes: int) -> str:
        """Format file size in human readable format"""
        for unit in ['B', 'KB', 'MB', 'GB', 'TB']:
            if size_bytes < 1024:
                return f"{size_bytes:.1f} {unit}"
            size_bytes /= 1024
        return f"{size_bytes:.1f} PB"
    
    def analyze_entropy(self, data: str) -> None:
        """Analyze entropy of data (useful for detecting encryption/compression)"""
        print(f"\n[+] Entropy Analysis")
        print("=" * 30)
        
        try:
            import math
            from collections import Counter
            
            # Convert to bytes if string
            if isinstance(data, str):
                data_bytes = data.encode('utf-8')
            else:
                data_bytes = data
            
            # Calculate frequency of each byte
            freq = Counter(data_bytes)
            data_len = len(data_bytes)
            
            # Calculate Shannon entropy
            entropy = 0
            for count in freq.values():
                probability = count / data_len
                if probability > 0:
                    entropy -= probability * math.log2(probability)
            
            # Maximum possible entropy for this data
            unique_bytes = len(freq)
            max_entropy = math.log2(unique_bytes) if unique_bytes > 1 else 0
            
            # Entropy ratio
            entropy_ratio = entropy / 8.0 if max_entropy > 0 else 0
            
            print(f"Data length: {data_len} bytes")
            print(f"Unique bytes: {unique_bytes}")
            print(f"Shannon entropy: {entropy:.4f} bits")
            print(f"Max possible entropy: {max_entropy:.4f} bits")
            print(f"Entropy ratio: {entropy_ratio:.4f} (0-1 scale)")
            
            # Interpretation
            if entropy_ratio > 0.9:
                print("📊 Assessment: High entropy - likely encrypted/compressed")
            elif entropy_ratio > 0.7:
                print("📊 Assessment: Medium-high entropy - possibly encoded")
            elif entropy_ratio > 0.5:
                print("📊 Assessment: Medium entropy - mixed content")
            else:
                print("📊 Assessment: Low entropy - likely plain text")
                
        except Exception as e:
            print(f"✗ Error: {e}")