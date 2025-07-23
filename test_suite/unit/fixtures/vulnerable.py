#!/usr/bin/env python3
"""
Test file with various vulnerabilities to demonstrate performance improvements.
"""

import os
import sqlite3
import subprocess
import hashlib

def sql_injection_vulnerability():
    """SQL injection vulnerability - CWE-89"""
    user_id = input("Enter user ID: ")
    # Vulnerable: direct string concatenation
    query = "SELECT * FROM users WHERE id = " + user_id
    
    conn = sqlite3.connect('database.db')
    cursor = conn.cursor()
    cursor.execute(query)  # CWE-89: SQL Injection
    return cursor.fetchall()

def command_injection_vulnerability():
    """Command injection vulnerability - CWE-78"""
    filename = input("Enter filename: ")
    # Vulnerable: direct command execution
    os.system("cat " + filename)  # CWE-78: OS Command Injection
    
    # Also vulnerable through subprocess
    subprocess.run("ping " + filename, shell=True)  # CWE-78

def hardcoded_credentials():
    """Hard-coded credentials - CWE-798"""
    password = "admin123"  # CWE-798: Hard-coded Password
    api_key = "sk-1234567890abcdef"  # CWE-798: Hard-coded API Key
    db_connection = "mongodb://admin:password@localhost:27017/db"  # CWE-798
    
    return password, api_key, db_connection

def weak_cryptography():
    """Weak cryptographic algorithms - CWE-327"""
    import hashlib
    
    # Vulnerable: using MD5
    weak_hash = hashlib.md5(b"password").hexdigest()  # CWE-327: Weak Hash
    
    # Vulnerable: using SHA1
    weak_hash2 = hashlib.sha1(b"password").hexdigest()  # CWE-327: Weak Hash
    
    return weak_hash, weak_hash2

def path_traversal_vulnerability():
    """Path traversal vulnerability - CWE-22"""
    filename = input("Enter filename: ")
    # Vulnerable: no path validation
    with open(filename, 'r') as f:  # CWE-22: Path Traversal
        return f.read()

def xss_vulnerability():
    """Cross-site scripting simulation - CWE-79"""
    user_input = input("Enter comment: ")
    # Vulnerable: direct HTML output without encoding
    html_output = f"<div>{user_input}</div>"  # CWE-79: XSS
    return html_output

def improper_input_validation():
    """Improper input validation - CWE-20"""
    user_age = input("Enter age: ")
    # Vulnerable: no validation
    age = int(user_age)  # CWE-20: Could crash on invalid input
    
    user_email = input("Enter email: ")
    # Vulnerable: no email validation
    return age, user_email

def use_of_eval():
    """Code injection through eval - CWE-94"""
    user_code = input("Enter Python expression: ")
    # Vulnerable: eval with user input
    result = eval(user_code)  # CWE-94: Code Injection
    return result

def weak_random_numbers():
    """Weak random number generation - CWE-330"""
    import random
    
    # Vulnerable: using weak random for security
    session_id = random.randint(1000, 9999)  # CWE-330: Weak Random
    csrf_token = str(random.random())  # CWE-330: Weak Random
    
    return session_id, csrf_token

def main():
    """Main function demonstrating various vulnerabilities"""
    print("Testing various vulnerability patterns...")
    
    try:
        # Test each vulnerability type
        sql_injection_vulnerability()
        command_injection_vulnerability()
        hardcoded_credentials()
        weak_cryptography()
        path_traversal_vulnerability()
        xss_vulnerability()
        improper_input_validation()
        use_of_eval()
        weak_random_numbers()
        
    except Exception as e:
        print(f"Error: {e}")

if __name__ == "__main__":
    main()