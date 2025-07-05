#!/usr/bin/env python3
"""
Test file to demonstrate enhanced vulnerability detection patterns
based on ShiftLeftSecurity/sast-scan.
"""

import requests
import subprocess
import os
import pickle
import yaml

# SQL Injection vulnerabilities
def vulnerable_sql_query(user_id):
    query = f"SELECT * FROM users WHERE id = {user_id}"
    return execute_query(query)

# Command injection vulnerability  
def execute_user_command(user_input):
    subprocess.call(f"echo {user_input}", shell=True)

# Hardcoded credentials (new pattern from sast-scan)
API_KEY = "sk-1234567890abcdef1234567890abcdef"
DATABASE_PASSWORD = "mySecretPassword123"

# SSRF vulnerability
def fetch_user_url(url):
    response = requests.get(url)
    return response.text

# Path traversal vulnerability
def read_user_file(filename):
    with open(f"uploads/{filename}", 'r') as f:
        return f.read()

# Information exposure
def debug_user_data(user_data):
    print(f"DEBUG: User data: {user_data}")

# Unsafe deserialization
def load_user_data(data):
    return pickle.loads(data)

# Unsafe YAML loading
def load_config(config_data):
    return yaml.load(config_data)

# Weak authentication (new pattern)
def simple_login(username, password):
    # Login without MFA
    if username == "admin" and password == "admin":
        return True
    return False

if __name__ == "__main__":
    # Test vulnerability patterns
    user_id = "1; DROP TABLE users; --"
    vulnerable_sql_query(user_id)
    
    user_command = "test; rm -rf /"
    execute_user_command(user_command)
    
    malicious_url = "http://localhost:22/admin"
    fetch_user_url(malicious_url)
    
    dangerous_file = "../../../etc/passwd"
    read_user_file(dangerous_file)