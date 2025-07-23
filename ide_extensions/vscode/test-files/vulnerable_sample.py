#!/usr/bin/env python3
"""
Sample vulnerable Python file for testing DeVAIC VS Code Extension
This file contains various security vulnerabilities for demonstration
"""

import os
import subprocess
import sqlite3
import random
from flask import Flask, request, render_template_string

app = Flask(__name__)

# 1. Hardcoded secret (CWE-798)
API_KEY = "sk-1234567890abcdef"
DATABASE_PASSWORD = "admin123"

# 2. SQL Injection vulnerability (CWE-89)
@app.route('/user/<user_id>')
def get_user(user_id):
    conn = sqlite3.connect('users.db')
    cursor = conn.cursor()
    
    # Vulnerable: Direct string concatenation
    query = f"SELECT * FROM users WHERE id = {user_id}"
    cursor.execute(query)
    
    result = cursor.fetchone()
    conn.close()
    return str(result)

# 3. Command Injection vulnerability (CWE-78)
@app.route('/execute')
def execute_command():
    cmd = request.args.get('cmd', '')
    
    # Vulnerable: Direct command execution
    result = subprocess.run(f"ls {cmd}", shell=True, capture_output=True)
    return result.stdout.decode()

# 4. Cross-Site Scripting (XSS) vulnerability (CWE-79)
@app.route('/greet')
def greet():
    name = request.args.get('name', 'Guest')
    
    # Vulnerable: Unescaped user input in template
    template = f"<h1>Hello {name}!</h1>"
    return render_template_string(template)

# 5. Weak random number generation (CWE-338)
def generate_session_token():
    # Vulnerable: Using predictable random
    return str(random.randint(1000000, 9999999))

# 6. Information disclosure (CWE-200)
@app.route('/debug')
def debug_info():
    # Vulnerable: Exposing sensitive system information
    return {
        'environment': dict(os.environ),
        'python_path': os.sys.path,
        'current_directory': os.getcwd(),
        'database_password': DATABASE_PASSWORD
    }

# 7. Path traversal vulnerability (CWE-22)
@app.route('/file')
def read_file():
    filename = request.args.get('file', '')
    
    # Vulnerable: No path validation
    try:
        with open(filename, 'r') as f:
            return f.read()
    except Exception as e:
        return str(e)

# 8. Insecure deserialization (CWE-502)
import pickle

@app.route('/load_data', methods=['POST'])
def load_data():
    data = request.get_data()
    
    # Vulnerable: Deserializing untrusted data
    obj = pickle.loads(data)
    return str(obj)

# 9. Missing authentication
@app.route('/admin/delete_user/<user_id>')
def delete_user(user_id):
    # Vulnerable: No authentication check
    conn = sqlite3.connect('users.db')
    cursor = conn.cursor()
    cursor.execute(f"DELETE FROM users WHERE id = {user_id}")
    conn.commit()
    conn.close()
    return "User deleted"

# 10. Weak cryptographic practices (CWE-327)
import hashlib

def hash_password(password):
    # Vulnerable: Using MD5 for password hashing
    return hashlib.md5(password.encode()).hexdigest()

# 11. Race condition (CWE-362)
import threading

balance = 1000
lock = threading.Lock()

def withdraw(amount):
    global balance
    # Vulnerable: No proper locking
    if balance >= amount:
        # Race condition possible here
        balance -= amount
        return True
    return False

# 12. Buffer overflow potential (in Python it's less common, but shown for demo)
def process_data(data):
    # Vulnerable: No length validation
    buffer = [0] * 1024
    
    # This could cause issues if data is too long
    for i, byte in enumerate(data):
        buffer[i] = byte
    
    return buffer

if __name__ == '__main__':
    # Vulnerable: Debug mode in production
    app.run(debug=True, host='0.0.0.0')