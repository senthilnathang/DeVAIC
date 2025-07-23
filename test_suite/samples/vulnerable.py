import os
import subprocess
import sqlite3
import pickle
import hashlib
import random

# Hardcoded credentials - security vulnerability
API_KEY = "sk-1234567890abcdef1234567890abcdef"
DATABASE_PASSWORD = "admin123"
SECRET_TOKEN = "very_secret_token_12345"

# SQL injection vulnerability
def get_user_data(user_id):
    conn = sqlite3.connect('users.db')
    cursor = conn.cursor()
    # Vulnerable: string formatting in SQL query
    query = f"SELECT * FROM users WHERE id = {user_id}"
    cursor.execute(query)
    return cursor.fetchone()

# Command injection vulnerability
def execute_command(user_input):
    # Vulnerable: user input directly in system command
    command = f"ls -la {user_input}"
    os.system(command)

# More command injection with subprocess
def run_script(script_name):
    # Vulnerable: unvalidated input in subprocess call
    subprocess.run(f"python {script_name}", shell=True)

# Unsafe deserialization
def load_data(data):
    # Vulnerable: pickle.loads with untrusted data
    return pickle.loads(data)

# Weak cryptography
def hash_password(password):
    # Vulnerable: MD5 is cryptographically broken
    return hashlib.md5(password.encode()).hexdigest()

# Another weak hash
def create_signature(data):
    # Vulnerable: SHA1 is weak
    return hashlib.sha1(data.encode()).hexdigest()

# Eval/exec vulnerabilities
def dynamic_calculation(expression):
    # Vulnerable: eval with user input
    result = eval(expression)
    return result

def execute_code(code):
    # Vulnerable: exec with user input
    exec(code)

# Debug mode enabled
DEBUG = True

# Insecure random for security purposes
def generate_token():
    # Vulnerable: using random instead of secrets for security
    token = ""
    for _ in range(32):
        token += str(random.randint(0, 9))
    return token

def generate_password():
    # Vulnerable: predictable random for password
    chars = "abcdefghijklmnopqrstuvwxyz"
    password = ""
    for _ in range(8):
        password += random.choice(chars)
    return password

if __name__ == "__main__":
    # Example usage that would trigger vulnerabilities
    user_id = input("Enter user ID: ")
    user_data = get_user_data(user_id)
    
    command = input("Enter directory to list: ")
    execute_command(command)
    
    expression = input("Enter math expression: ")
    result = dynamic_calculation(expression)
    print(f"Result: {result}")
    
    token = generate_token()
    print(f"Generated token: {token}")