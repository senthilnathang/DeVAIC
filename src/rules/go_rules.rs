use crate::{
    error::Result,
    parsers::{ParsedAst, SourceFile},
    rules::{create_vulnerability, RuleSet},
    Severity, Vulnerability,
};
use regex::Regex;
use lazy_static::lazy_static;

pub struct GoRules;

impl GoRules {
    pub fn new() -> Self {
        Self
    }
}

lazy_static! {
    static ref SQL_INJECTION_PATTERNS: Vec<Regex> = vec![
        Regex::new(r#"\.Query\s*\(\s*[^?]{1,200}\+.{1,100}\)"#).expect("Invalid SQL injection regex"),
        Regex::new(r#"\.Exec\s*\(\s*[^?]{1,200}\+.{1,100}\)"#).expect("Invalid SQL injection regex"),
        Regex::new(r#"\.QueryRow\s*\(\s*[^?]{1,200}\+.{1,100}\)"#).expect("Invalid SQL injection regex"),
    ];
    
    static ref COMMAND_INJECTION_PATTERNS: Vec<Regex> = vec![
        Regex::new(r#"exec\.Command\s*\([^)]{1,500}\$\{[^}]{1,100}\}[^)]{0,200}\)"#).expect("Invalid command injection regex"),
        Regex::new(r#"exec\.CommandContext\s*\([^)]{1,500}\$\{[^}]{1,100}\}[^)]{0,200}\)"#).expect("Invalid command injection regex"),
    ];
    
    static ref PATH_TRAVERSAL_PATTERNS: Vec<Regex> = vec![
        Regex::new(r#"filepath\.Join\s*\([^)]*\$\{[^}]*\}[^)]*\)"#).unwrap(),
        Regex::new(r#"os\.Open\s*\([^)]*\$\{[^}]*\}[^)]*\)"#).unwrap(),
    ];
    
    static ref SSRF_PATTERNS: Vec<Regex> = vec![
        Regex::new(r#"http\.Get\s*\([^)]*\$\{[^}]*\}[^)]*\)"#).unwrap(),
        Regex::new(r#"http\.Post\s*\([^)]*\$\{[^}]*\}[^)]*\)"#).unwrap(),
    ];
    
    static ref CRYPTO_WEAK_PATTERNS: Vec<Regex> = vec![
        Regex::new(r#"md5\.New\(\)"#).unwrap(),
        Regex::new(r#"sha1\.New\(\)"#).unwrap(),
        Regex::new(r#"des\.NewCipher"#).unwrap(),
        Regex::new(r#"rc4\.NewCipher"#).unwrap(),
    ];
    
    static ref HARDCODED_SECRET_PATTERNS: Vec<Regex> = vec![
        Regex::new(r#"(?i)(password|secret|key|token)\s*:?=\s*"[^"]{8,100}""#).expect("Invalid secret detection regex"),
        Regex::new(r#"(?i)(api_key|apikey)\s*:?=\s*"[^"]{20,200}""#).expect("Invalid API key detection regex"),
    ];
    
    // Enhanced Go security patterns
    static ref GOROUTINE_PATTERNS: Vec<Regex> = vec![
        Regex::new(r#"go\s+func\s*\([^)]*\)\s*\{"#).unwrap(),
        Regex::new(r#"go\s+[a-zA-Z_][a-zA-Z0-9_]*\s*\("#).unwrap(),
    ];
    
    static ref RACE_CONDITION_PATTERNS: Vec<Regex> = vec![
        Regex::new(r#"var\s+\w+\s+\w+.*//.*shared"#).unwrap(),
        Regex::new(r#"map\[[^\]]+\][^{]*\{[^}]*\}.*//.*concurrent"#).unwrap(),
    ];
    
    static ref UNSAFE_PATTERNS: Vec<Regex> = vec![
        Regex::new(r#"unsafe\."#).unwrap(),
        Regex::new(r#"reflect\.UnsafeAddr"#).unwrap(),
        Regex::new(r#"uintptr\("#).unwrap(),
    ];
    
    static ref NETWORK_SECURITY_PATTERNS: Vec<Regex> = vec![
        Regex::new(r#"InsecureSkipVerify:\s*true"#).unwrap(),
        Regex::new(r#"http\.DefaultTransport"#).unwrap(),
        Regex::new(r#"tls\.Config\{[^}]*InsecureSkipVerify:\s*true[^}]*\}"#).unwrap(),
    ];
    
    static ref PERFORMANCE_PATTERNS: Vec<Regex> = vec![
        Regex::new(r#"fmt\.Sprintf\s*\(\s*"[^"]*%s[^"]*"\s*,\s*[^)]+\)"#).unwrap(), // String concatenation
        Regex::new(r#"strings\.Join\s*\(\[\]string\{[^}]+\},"#).unwrap(), // Inefficient join
        Regex::new(r#"time\.Sleep\s*\(\s*time\.(Second|Minute)"#).unwrap(), // Long sleeps
    ];
    
    static ref MEMORY_PATTERNS: Vec<Regex> = vec![
        Regex::new(r#"make\s*\(\[\]byte,\s*[0-9]{6,}\)"#).unwrap(), // Large allocations
        Regex::new(r#"runtime\.GC\(\)"#).unwrap(), // Manual GC calls
        Regex::new(r#"runtime\.KeepAlive"#).unwrap(), // Memory management
    ];
}

impl RuleSet for GoRules {
    fn analyze(&self, source_file: &SourceFile, _ast: &ParsedAst) -> Result<Vec<Vulnerability>> {
        let mut vulnerabilities = Vec::new();
        let content = &source_file.content;
        
        // Prevent DoS by limiting content size for regex operations
        if content.len() > 10 * 1024 * 1024 { // 10MB limit for regex
            return Err(crate::error::DevaicError::Analysis("File too large for regex analysis".to_string()));
        }
        
        let lines: Vec<&str> = content.lines().take(50000).collect(); // Limit lines processed

        for (line_number, line) in lines.iter().enumerate() {
            let line_num = line_number + 1;

            // SQL Injection Detection
            for pattern in SQL_INJECTION_PATTERNS.iter() {
                if pattern.is_match(line) {
                    vulnerabilities.push(create_vulnerability(
                        "GO-SQL-001",
                        Some("CWE-89"),
                        "SQL Injection",
                        Severity::High,
                        "injection",
                        "SQL injection vulnerability detected in Go database query",
                        &source_file.path.to_string_lossy(),
                        line_num,
                        0,
                        line,
                        "Use parameterized queries with placeholders: db.Query(\"SELECT * FROM users WHERE id = ?\", userID)",
                    ));
                }
            }

            // Command Injection Detection
            for pattern in COMMAND_INJECTION_PATTERNS.iter() {
                if pattern.is_match(line) {
                    vulnerabilities.push(create_vulnerability(
                        "GO-CMD-001",
                        Some("CWE-78"),
                        "Command Injection",
                        Severity::High,
                        "injection",
                        "Command injection vulnerability detected in Go exec call",
                        &source_file.path.to_string_lossy(),
                        line_num,
                        0,
                        line,
                        "Validate and sanitize all user inputs before using in system commands",
                    ));
                }
            }

            // Path Traversal Detection
            for pattern in PATH_TRAVERSAL_PATTERNS.iter() {
                if pattern.is_match(line) {
                    vulnerabilities.push(create_vulnerability(
                        "GO-PATH-001",
                        Some("CWE-22"),
                        "Path Traversal",
                        Severity::Medium,
                        "validation",
                        "Path traversal vulnerability detected in Go file operation",
                        &source_file.path.to_string_lossy(),
                        line_num,
                        0,
                        line,
                        "Validate file paths and use filepath.Clean() to prevent directory traversal",
                    ));
                }
            }

            // SSRF Detection
            for pattern in SSRF_PATTERNS.iter() {
                if pattern.is_match(line) {
                    vulnerabilities.push(create_vulnerability(
                        "GO-SSRF-001",
                        Some("CWE-918"),
                        "Server-Side Request Forgery",
                        Severity::High,
                        "validation",
                        "SSRF vulnerability detected in Go HTTP request",
                        &source_file.path.to_string_lossy(),
                        line_num,
                        0,
                        line,
                        "Validate and whitelist URLs before making HTTP requests",
                    ));
                }
            }

            // Weak Cryptography Detection
            for pattern in CRYPTO_WEAK_PATTERNS.iter() {
                if pattern.is_match(line) {
                    vulnerabilities.push(create_vulnerability(
                        "GO-CRYPTO-001",
                        Some("CWE-327"),
                        "Weak Cryptography",
                        Severity::Medium,
                        "cryptography",
                        "Weak cryptographic algorithm detected in Go code",
                        &source_file.path.to_string_lossy(),
                        line_num,
                        0,
                        line,
                        "Use strong cryptographic algorithms like SHA-256, AES, or RSA",
                    ));
                }
            }

            // Hardcoded Secrets Detection
            for pattern in HARDCODED_SECRET_PATTERNS.iter() {
                if pattern.is_match(line) {
                    vulnerabilities.push(create_vulnerability(
                        "GO-SECRET-001",
                        Some("CWE-798"),
                        "Hardcoded Credentials",
                        Severity::High,
                        "secrets",
                        "Hardcoded secret detected in Go code",
                        &source_file.path.to_string_lossy(),
                        line_num,
                        0,
                        line,
                        "Store secrets in environment variables or secure configuration files",
                    ));
                }
            }

            // Goroutine Safety Issues
            for pattern in GOROUTINE_PATTERNS.iter() {
                if pattern.is_match(line) {
                    vulnerabilities.push(create_vulnerability(
                        "GO-GOROUTINE-001",
                        Some("CWE-362"),
                        "Goroutine Safety",
                        Severity::Medium,
                        "concurrency",
                        "Goroutine usage detected - ensure proper synchronization",
                        &source_file.path.to_string_lossy(),
                        line_num,
                        0,
                        line,
                        "Use channels, mutexes, or sync package for safe concurrent access",
                    ));
                }
            }

            // Race Condition Detection
            for pattern in RACE_CONDITION_PATTERNS.iter() {
                if pattern.is_match(line) {
                    vulnerabilities.push(create_vulnerability(
                        "GO-RACE-001",
                        Some("CWE-362"),
                        "Race Condition",
                        Severity::High,
                        "concurrency",
                        "Potential race condition detected in Go code",
                        &source_file.path.to_string_lossy(),
                        line_num,
                        0,
                        line,
                        "Use proper synchronization mechanisms to prevent race conditions",
                    ));
                }
            }

            // Unsafe Operations
            for pattern in UNSAFE_PATTERNS.iter() {
                if pattern.is_match(line) {
                    vulnerabilities.push(create_vulnerability(
                        "GO-UNSAFE-001",
                        Some("CWE-119"),
                        "Unsafe Operation",
                        Severity::High,
                        "memory",
                        "Unsafe operation detected in Go code",
                        &source_file.path.to_string_lossy(),
                        line_num,
                        0,
                        line,
                        "Avoid unsafe operations or ensure proper memory safety",
                    ));
                }
            }

            // Network Security Issues
            for pattern in NETWORK_SECURITY_PATTERNS.iter() {
                if pattern.is_match(line) {
                    vulnerabilities.push(create_vulnerability(
                        "GO-TLS-001",
                        Some("CWE-295"),
                        "TLS Security Issue",
                        Severity::High,
                        "network",
                        "Insecure TLS configuration detected",
                        &source_file.path.to_string_lossy(),
                        line_num,
                        0,
                        line,
                        "Enable proper certificate verification and use secure TLS settings",
                    ));
                }
            }

            // Performance Issues
            for pattern in PERFORMANCE_PATTERNS.iter() {
                if pattern.is_match(line) {
                    vulnerabilities.push(create_vulnerability(
                        "GO-PERF-001",
                        Some("CWE-400"),
                        "Performance Issue",
                        Severity::Low,
                        "performance",
                        "Performance anti-pattern detected in Go code",
                        &source_file.path.to_string_lossy(),
                        line_num,
                        0,
                        line,
                        "Optimize code for better performance and resource usage",
                    ));
                }
            }

            // Memory Management Issues
            for pattern in MEMORY_PATTERNS.iter() {
                if pattern.is_match(line) {
                    vulnerabilities.push(create_vulnerability(
                        "GO-MEMORY-001",
                        Some("CWE-401"),
                        "Memory Management",
                        Severity::Medium,
                        "memory",
                        "Memory management issue detected in Go code",
                        &source_file.path.to_string_lossy(),
                        line_num,
                        0,
                        line,
                        "Review memory allocation patterns and avoid unnecessary allocations",
                    ));
                }
            }
        }

        Ok(vulnerabilities)
    }
}