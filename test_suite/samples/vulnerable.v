module main

import os
import net.http
import db.sqlite
import json

// Memory safety vulnerabilities
fn unsafe_memory_operations() {
    unsafe {
        ptr := voidptr(0x12345678) // Raw pointer usage
        println('Unsafe pointer: ${ptr}')
    }
}

// Web security vulnerabilities (vweb)
fn xss_vulnerability(user_input string) string {
    html := '<div>${user_input}</div>' // XSS risk - unescaped interpolation
    return html
}

fn sql_injection_vulnerability(db sqlite.DB, user_id string) {
    query := "SELECT * FROM users WHERE id = " + user_id // SQL injection
    db.exec(query)
}

// Database credentials
fn database_connection() {
    config := sqlite.Config{
        path: '/tmp/test.db'
        password: 'hardcoded_db_password_123' // Hardcoded database password
        user: 'admin'
        host: 'localhost'
    }
    println('Database config: ${config}')
}

// Network security vulnerabilities
fn insecure_http_request(url string) {
    // Dynamic URL construction - SSRF risk
    full_url := 'https://api.example.com/data?url=' + url
    response := http.get(full_url) or {
        println('Request failed')
        return
    }
    println('Response: ${response.body}')
}

fn insecure_tls_connection() {
    config := http.FetchConfig{
        url: 'https://example.com'
        verify_ssl: false // Disabled SSL verification
    }
    response := http.fetch(config) or {
        println('Request failed')
        return
    }
    println('Response: ${response.body}')
}

// File operation vulnerabilities
fn unsafe_file_operations(filename string) {
    // Path traversal vulnerability
    content := os.read_file('../../../etc/passwd' + filename) or {
        println('File read failed')
        return
    }
    
    os.write_file('./output/' + filename, content) or {
        println('File write failed')
        return
    }
    
    os.rm('../sensitive/' + filename) or {
        println('File removal failed')
        return
    }
}

fn path_traversal_example() {
    malicious_path := '../../../etc/passwd'
    content := os.read_file(malicious_path) or {
        println('Access denied')
        return
    }
    println('Sensitive content: ${content}')
}

// Error handling vulnerabilities
fn ignored_error_handling() {
    risky_operation() or {} // Ignored error
    
    another_risky_operation() or {
        panic('This will crash the program') // Panic on error
    }
}

// FFI and C interop vulnerabilities
#include <stdio.h>

fn C.dangerous_function(data &char) int

fn unsafe_c_interop() {
    data := 'unsafe data'.str
    result := C.dangerous_function(data) // External C function call
    println('C function result: ${result}')
}

// Hardcoded secrets
const api_key = 'sk_live_1234567890abcdef' // Hardcoded API key
const secret_token = 'ghp_xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx' // Hardcoded GitHub token
const password = 'super_secret_password_123' // Hardcoded password

// Command injection vulnerabilities
fn command_injection_risk(user_input string) {
    command := 'ls -la ' + user_input // Command injection
    result := os.execute(command)
    println('Command result: ${result}')
    
    os.system('rm -rf ' + user_input) or {
        println('System command failed')
    }
}

// Debug code
fn debug_statements() {
    println('Debug: API key is ${api_key}') // Debug statement with secrets
    eprintln('Error debug: Password is ${password}')
    dump(secret_token) // Debug dump of sensitive data
}

// JSON security vulnerabilities
fn unsafe_json_parsing(json_data string) {
    // Unsafe JSON decoding without validation
    data := json.decode(map[string]string, json_data) or {
        println('JSON decode failed')
        return
    }
    println('Parsed data: ${data}')
}

// Module import security
import unsafe_module { unsafe_function, dangerous_operation }

fn use_unsafe_imports() {
    unsafe_function()
    dangerous_operation()
}

// Cross-platform unsafe code
fn platform_specific_unsafe() {
    $if windows {
        unsafe {
            // Windows-specific unsafe operations
            ptr := voidptr(0x7FFE0000)
            println('Windows unsafe: ${ptr}')
        }
    }
    
    $if linux {
        unsafe {
            // Linux-specific unsafe operations  
            ptr := voidptr(0x08048000)
            println('Linux unsafe: ${ptr}')
        }
    }
}

// Web framework vulnerabilities (vweb)
['/api/user/:id']
pub fn get_user(mut ctx vweb.Context) vweb.Result {
    user_id := ctx.query['id']
    
    // SQL injection in route handler
    query := "SELECT * FROM users WHERE id = " + user_id
    // Missing input validation and SQL injection protection
    
    return ctx.text('User data for: ${user_id}')
}

['/upload']
pub fn upload_file(mut ctx vweb.Context) vweb.Result {
    filename := ctx.form['filename']
    
    // Path traversal in file upload
    file_path := './uploads/' + filename
    content := ctx.form['content']
    
    os.write_file(file_path, content) or {
        return ctx.server_error('Upload failed')
    }
    
    return ctx.text('File uploaded: ${filename}')
}

// Helper functions
fn risky_operation() !string {
    return error('Something went wrong')
}

fn another_risky_operation() !int {
    return error('Another error occurred')
}

// Main function demonstrating vulnerabilities
fn main() {
    println('V Language Security Test')
    
    unsafe_memory_operations()
    
    html := xss_vulnerability('<script>alert("XSS")</script>')
    println('Generated HTML: ${html}')
    
    // Database operations
    db := sqlite.connect(':memory:') or {
        println('Database connection failed')
        return
    }
    defer {
        db.close()
    }
    
    sql_injection_vulnerability(db, "1 OR 1=1")
    database_connection()
    
    // Network operations
    insecure_http_request('http://evil.com')
    insecure_tls_connection()
    
    // File operations
    unsafe_file_operations('test.txt')
    path_traversal_example()
    
    // Error handling
    ignored_error_handling()
    
    // C interop
    unsafe_c_interop()
    
    // Command injection
    command_injection_risk('; rm -rf /')
    
    // Debug and development
    debug_statements()
    
    // JSON parsing
    unsafe_json_parsing('{"key": "value"}')
    
    // Unsafe imports
    use_unsafe_imports()
    
    // Platform-specific code
    platform_specific_unsafe()
}