# Privacy Risk Detection Test File
# This file contains various privacy-related vulnerabilities for testing

import logging
import hashlib

# PII Data Exposure Examples
ssn = "123-45-6789"  # Social Security Number detected
credit_card = "4532-1234-5678-9012"  # Credit card number detected
email = "user@example.com"  # Email address hardcoded
phone = "555-123-4567"  # Phone number detected
passport = "A1234567"  # Passport number detected

# PHI Data Examples  
mrn = "MRN12345678"  # Medical record number detected
insurance_number = "INS123456789"  # Health insurance number detected

# Database Queries with PII
def get_user_data():
    query = "SELECT ssn, credit_card, email FROM users WHERE id = 1"  # PII in query
    return query

# Logging Sensitive Data
def process_user():
    user_ssn = "123-45-6789"
    logging.info(f"Processing user with SSN: {user_ssn}")  # Sensitive data logged
    print(f"Credit card: {credit_card}")  # Sensitive data in print

# API Response with PII
def get_user_profile():
    return {
        "name": "John Doe",
        "ssn": "123-45-6789",  # PII in API response
        "credit_card": "4532-1234-5678-9012"
    }

# Weak Hashing of Sensitive Data
def hash_ssn(ssn):
    return hashlib.md5(ssn.encode()).hexdigest()  # Weak hash for PII

# File Operations with Sensitive Data
def save_user_data():
    with open("user_data.txt", "w") as f:
        f.write(f"SSN: {ssn}\n")  # PII written to file
        f.write(f"Credit Card: {credit_card}\n")

# Database Connection with Embedded Credentials
db_url = "postgresql://admin:password123@localhost/userdb"  # Credentials in URL

# Medical Data Processing
def process_patient():
    patient_data = {
        "mrn": "MRN12345678",
        "insurance": "INS987654321",
        "diagnosis": "Confidential medical condition"
    }
    logging.debug(f"Patient data: {patient_data}")  # PHI in logs
    
if __name__ == "__main__":
    process_user()
    save_user_data()
    process_patient()