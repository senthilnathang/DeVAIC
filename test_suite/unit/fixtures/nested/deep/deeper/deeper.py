#!/usr/bin/env python3
"""
Test file in very deep nested directory
"""

def deeper_vulnerability():
    """Very deep nested vulnerability"""
    import hashlib
    
    # CWE-327: Weak hash algorithm
    weak_hash = hashlib.md5(b"password").hexdigest()
    
    # CWE-798: Hard-coded API key
    api_key = "sk-very-deep-nested-key-123"
    
    return weak_hash, api_key

if __name__ == "__main__":
    deeper_vulnerability()