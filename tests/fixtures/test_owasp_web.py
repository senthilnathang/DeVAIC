# Test file for OWASP Web Application vulnerabilities

# A01: Broken Access Control
bypass_auth = True
admin = True
force_browse = "/admin/users"

# A02: Cryptographic Failures
import hashlib
hash = hashlib.md5(password.encode())
hardcoded_key = "secret123"
plaintext_password = "admin123"

# A03: Injection
eval(user_input)
exec(system_command)
sql_injection = "SELECT * FROM users WHERE id = " + user_id

# A04: Insecure Design
security_by_obscurity = True
insufficient_validation = check_input(data)

# A05: Security Misconfiguration
debug = True
default_password = "admin"
error_disclosure = True

# A06: Vulnerable and Outdated Components
outdated_library = "jquery-1.4.2.min.js"
deprecated_framework = "flask-0.10"

# A07: Identification and Authentication Failures
weak_password = "123456"
session_fixation = True

# A08: Software and Data Integrity Failures
unsigned_code = load_plugin()
supply_chain = untrusted_dependency

# A09: Security Logging and Monitoring Failures
insufficient_logging = True
log_injection = log_entry + user_data

# A10: Server-Side Request Forgery (SSRF)
request_url = "http://localhost:8080/admin"
internal_network = "192.168.1.1"