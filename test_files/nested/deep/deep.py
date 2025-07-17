#!/usr/bin/env python3
"""
Test file in deep nested directory
"""

def deep_vulnerability():
    """Deep nested vulnerability"""
    password = "deep_nested_password"  # CWE-798: Hard-coded Password
    command = "rm -rf " + input("Enter path: ")  # CWE-78: Command Injection
    import os
    os.system(command)
    return password

if __name__ == "__main__":
    deep_vulnerability()