#!/usr/bin/env python3
"""
Test file in nested directory
"""

def nested_vulnerability():
    """SQL injection in nested file"""
    user_id = input("Enter user ID: ")
    query = "SELECT * FROM users WHERE id = " + user_id  # CWE-89: SQL Injection
    return query

def nested_hardcoded_password():
    """Hard-coded password in nested file"""
    password = "nested_password_123"  # CWE-798: Hard-coded Password
    return password

if __name__ == "__main__":
    nested_vulnerability()
    nested_hardcoded_password()