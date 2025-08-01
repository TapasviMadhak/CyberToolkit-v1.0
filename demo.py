#!/usr/bin/env python3
"""
CyberToolkit Demo
================

Quick demonstration of CyberToolkit features.
"""

import subprocess
import sys
import time

def run_demo():
    """Run a demonstration of various CyberToolkit features"""
    
    print("""
    ╔══════════════════════════════════════════════════════════════╗
    ║                    CyberToolkit Demo                         ║
    ║              Quick Feature Demonstration                     ║
    ╚══════════════════════════════════════════════════════════════╝
    """)
    
    demos = [
        {
            'title': '🔐 Password Strength Analysis',
            'command': ['python', 'main.py', 'password', '--analyze', 'MyPassword123!'],
            'description': 'Analyzing password strength with detailed feedback'
        },
        {
            'title': '🔐 Secure Password Generation',
            'command': ['python', 'main.py', 'password', '--generate', '--length', '16', '--complexity', 'high'],
            'description': 'Generating a secure 16-character password'
        },
        {
            'title': '🔍 Text Hashing',
            'command': ['python', 'main.py', 'hash', '--text', 'Hello CyberToolkit!', '--algorithm', 'sha256'],
            'description': 'Computing SHA256 hash of sample text'
        },
        {
            'title': '🌐 Web Security Headers Check',
            'command': ['python', 'main.py', 'web', '--url', 'https://github.com', '--headers'],
            'description': 'Checking security headers for GitHub (safe demo target)'
        }
    ]
    
    print("This demo will showcase key features of CyberToolkit:")
    print("(Note: Network and log analysis features require specific targets/files)")
    print("\nPress Enter to continue with each demo, or Ctrl+C to exit...")
    
    for i, demo in enumerate(demos, 1):
        try:
            input(f"\n[{i}/4] Press Enter to run: {demo['title']}")
            print(f"\n{demo['description']}")
            print("Command:", " ".join(demo['command']))
            print("-" * 60)
            
            # Run the command
            result = subprocess.run(demo['command'], capture_output=True, text=True, timeout=30)
            
            if result.returncode == 0:
                print(result.stdout)
            else:
                print(f"Command failed with error: {result.stderr}")
                
        except KeyboardInterrupt:
            print("\n\nDemo interrupted by user. Thanks for trying CyberToolkit!")
            sys.exit(0)
        except subprocess.TimeoutExpired:
            print("Command timed out (this can happen with network operations)")
        except Exception as e:
            print(f"Error running demo: {e}")
    
    print("""
    ╔══════════════════════════════════════════════════════════════╗
    ║                      Demo Complete!                          ║
    ║                                                              ║
    ║  🎉 You've seen CyberToolkit in action!                     ║
    ║                                                              ║
    ║  Next steps:                                                 ║
    ║  • Try: python main.py --help                               ║
    ║  • Explore different modules                                 ║
    ║  • Read the README.md for full documentation                ║
    ║  • Customize for your security testing needs                ║
    ╚══════════════════════════════════════════════════════════════╝
    """)

if __name__ == "__main__":
    run_demo()