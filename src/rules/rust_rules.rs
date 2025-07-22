use crate::{
    error::Result,
    parsers::{ParsedAst, SourceFile},
    rules::{create_vulnerability, RuleSet},
    Severity, Vulnerability,
};
use regex::Regex;
use lazy_static::lazy_static;

pub struct RustRules;

impl RustRules {
    pub fn new() -> Self {
        Self
    }
}

lazy_static! {
    static ref UNSAFE_PATTERNS: Vec<Regex> = vec![
        Regex::new(r#"unsafe\s*\{"#).unwrap(),
        Regex::new(r#"unsafe\s+fn"#).unwrap(),
        Regex::new(r#"unsafe\s+impl"#).unwrap(),
        Regex::new(r#"unsafe\s+trait"#).unwrap(),
    ];
    
    static ref UNSAFE_OPERATIONS: Vec<Regex> = vec![
        Regex::new(r#"\*\s*[a-zA-Z_][a-zA-Z0-9_]*"#).unwrap(), // Pointer dereference
        Regex::new(r#"std::ptr::"#).unwrap(),
        Regex::new(r#"std::mem::transmute"#).unwrap(),
        Regex::new(r#"std::mem::uninitialized"#).unwrap(),
        Regex::new(r#"std::mem::zeroed"#).unwrap(),
    ];
    
    static ref WEAK_CRYPTO_PATTERNS: Vec<Regex> = vec![
        Regex::new(r#"md5::"#).unwrap(),
        Regex::new(r#"sha1::"#).unwrap(),
        Regex::new(r#"Md5::"#).unwrap(),
        Regex::new(r#"Sha1::"#).unwrap(),
        Regex::new(r#"rc4::"#).unwrap(),
        Regex::new(r#"des::"#).unwrap(),
    ];
    
    static ref HARDCODED_SECRET_PATTERNS: Vec<Regex> = vec![
        Regex::new(r#"(?i)(password|secret|key|token)\s*=\s*"[^"]{8,}""#).unwrap(),
        Regex::new(r#"(?i)(api_key|apikey)\s*=\s*"[^"]{20,}""#).unwrap(),
        Regex::new(r#"const\s+[A-Z_]*(?:PASSWORD|SECRET|KEY|TOKEN)[A-Z_]*\s*:\s*&str\s*=\s*"[^"]{8,}""#).unwrap(),
    ];
    
    static ref PANIC_PATTERNS: Vec<Regex> = vec![
        Regex::new(r#"\.unwrap\(\)"#).unwrap(),
        Regex::new(r#"\.expect\("[^"]*"\)"#).unwrap(),
        Regex::new(r#"panic!\("#).unwrap(),
        Regex::new(r#"unimplemented!\("#).unwrap(),
        Regex::new(r#"unreachable!\("#).unwrap(),
    ];
    
    static ref COMMAND_INJECTION_PATTERNS: Vec<Regex> = vec![
        Regex::new(r#"Command::new\s*\([^)]*\$\{[^}]*\}[^)]*\)"#).unwrap(),
        Regex::new(r#"\.arg\s*\([^)]*\$\{[^}]*\}[^)]*\)"#).unwrap(),
        Regex::new(r#"std::process::Command"#).unwrap(),
    ];
    
    static ref PATH_TRAVERSAL_PATTERNS: Vec<Regex> = vec![
        Regex::new(r#"std::fs::File::open\s*\([^)]*\$\{[^}]*\}[^)]*\)"#).unwrap(),
        Regex::new(r#"std::fs::read\s*\([^)]*\$\{[^}]*\}[^)]*\)"#).unwrap(),
        Regex::new(r#"std::fs::write\s*\([^)]*\$\{[^}]*\}[^)]*\)"#).unwrap(),
    ];
    
    static ref NETWORK_PATTERNS: Vec<Regex> = vec![
        Regex::new(r#"reqwest::get\s*\([^)]*\$\{[^}]*\}[^)]*\)"#).unwrap(),
        Regex::new(r#"reqwest::post\s*\([^)]*\$\{[^}]*\}[^)]*\)"#).unwrap(),
        Regex::new(r#"http://"#).unwrap(),
    ];
    
    static ref SERIALIZATION_PATTERNS: Vec<Regex> = vec![
        Regex::new(r#"serde_pickle::"#).unwrap(),
        Regex::new(r#"bincode::deserialize"#).unwrap(),
        Regex::new(r#"rmp_serde::from_slice"#).unwrap(),
    ];
    
    // Performance and memory patterns
    static ref PERFORMANCE_PATTERNS: Vec<Regex> = vec![
        Regex::new(r#"\.clone\(\)\.clone\(\)"#).unwrap(), // Double clone
        Regex::new(r#"String::from\s*\(\s*&"#).unwrap(), // Unnecessary String::from
        Regex::new(r#"\.to_string\(\)\.as_str\(\)"#).unwrap(), // Unnecessary conversion
    ];
    
    static ref MEMORY_LEAK_PATTERNS: Vec<Regex> = vec![
        Regex::new(r#"Box::leak"#).unwrap(),
        Regex::new(r#"std::mem::forget"#).unwrap(),
        Regex::new(r#"ManuallyDrop::new"#).unwrap(),
    ];
}

impl RuleSet for RustRules {
    fn analyze(&self, source_file: &SourceFile, _ast: &ParsedAst) -> Result<Vec<Vulnerability>> {
        let mut vulnerabilities = Vec::new();
        let content = &source_file.content;
        let lines: Vec<&str> = content.lines().collect();

        for (line_number, line) in lines.iter().enumerate() {
            let line_num = line_number + 1;

            // Unsafe Code Detection
            for pattern in UNSAFE_PATTERNS.iter() {
                if pattern.is_match(line) {
                    vulnerabilities.push(create_vulnerability(
                        "RUST-UNSAFE-001",
                        Some("CWE-119"),
                        "Unsafe Code Block",
                        Severity::Medium,
                        "memory",
                        "Unsafe code block detected in Rust code",
                        &source_file.path.to_string_lossy(),
                        line_num,
                        0,
                        line,
                        "Review unsafe code carefully and ensure memory safety guarantees",
                    ));
                }
            }

            // Unsafe Operations Detection
            for pattern in UNSAFE_OPERATIONS.iter() {
                if pattern.is_match(line) && line.contains("unsafe") {
                    vulnerabilities.push(create_vulnerability(
                        "RUST-UNSAFE-002",
                        Some("CWE-476"),
                        "Unsafe Operation",
                        Severity::High,
                        "memory",
                        "Potentially dangerous unsafe operation detected",
                        &source_file.path.to_string_lossy(),
                        line_num,
                        0,
                        line,
                        "Validate pointer safety and consider safe alternatives",
                    ));
                }
            }

            // Weak Cryptography Detection
            for pattern in WEAK_CRYPTO_PATTERNS.iter() {
                if pattern.is_match(line) {
                    vulnerabilities.push(create_vulnerability(
                        "RUST-CRYPTO-001",
                        Some("CWE-327"),
                        "Weak Cryptography",
                        Severity::Medium,
                        "cryptography",
                        "Weak cryptographic algorithm detected in Rust code",
                        &source_file.path.to_string_lossy(),
                        line_num,
                        0,
                        line,
                        "Use strong cryptographic algorithms like SHA-256, AES, or ring crate",
                    ));
                }
            }

            // Hardcoded Secrets Detection
            for pattern in HARDCODED_SECRET_PATTERNS.iter() {
                if pattern.is_match(line) {
                    vulnerabilities.push(create_vulnerability(
                        "RUST-SECRET-001",
                        Some("CWE-798"),
                        "Hardcoded Credentials",
                        Severity::High,
                        "secrets",
                        "Hardcoded secret detected in Rust code",
                        &source_file.path.to_string_lossy(),
                        line_num,
                        0,
                        line,
                        "Store secrets in environment variables or secure configuration",
                    ));
                }
            }

            // Panic Patterns Detection
            for pattern in PANIC_PATTERNS.iter() {
                if pattern.is_match(line) && !line.trim_start().starts_with("//") {
                    vulnerabilities.push(create_vulnerability(
                        "RUST-PANIC-001",
                        Some("CWE-248"),
                        "Potential Panic",
                        Severity::Low,
                        "reliability",
                        "Code that can panic detected in Rust code",
                        &source_file.path.to_string_lossy(),
                        line_num,
                        0,
                        line,
                        "Use proper error handling with Result<T, E> instead of panicking",
                    ));
                }
            }

            // Command Injection Detection
            for pattern in COMMAND_INJECTION_PATTERNS.iter() {
                if pattern.is_match(line) {
                    vulnerabilities.push(create_vulnerability(
                        "RUST-CMD-001",
                        Some("CWE-78"),
                        "Command Injection",
                        Severity::High,
                        "injection",
                        "Potential command injection detected in Rust code",
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
                        "RUST-PATH-001",
                        Some("CWE-22"),
                        "Path Traversal",
                        Severity::Medium,
                        "validation",
                        "Potential path traversal vulnerability detected",
                        &source_file.path.to_string_lossy(),
                        line_num,
                        0,
                        line,
                        "Validate file paths and use Path::canonicalize() to prevent directory traversal",
                    ));
                }
            }

            // Network Security Issues
            for pattern in NETWORK_PATTERNS.iter() {
                if pattern.is_match(line) {
                    vulnerabilities.push(create_vulnerability(
                        "RUST-NETWORK-001",
                        Some("CWE-319"),
                        "Insecure Network Communication",
                        Severity::Medium,
                        "network",
                        "Insecure network communication detected",
                        &source_file.path.to_string_lossy(),
                        line_num,
                        0,
                        line,
                        "Use HTTPS and validate certificates for secure communication",
                    ));
                }
            }

            // Unsafe Serialization Detection
            for pattern in SERIALIZATION_PATTERNS.iter() {
                if pattern.is_match(line) {
                    vulnerabilities.push(create_vulnerability(
                        "RUST-SERIAL-001",
                        Some("CWE-502"),
                        "Unsafe Deserialization",
                        Severity::High,
                        "validation",
                        "Potentially unsafe deserialization detected",
                        &source_file.path.to_string_lossy(),
                        line_num,
                        0,
                        line,
                        "Validate serialized data and use safe serialization formats",
                    ));
                }
            }

            // Performance Issues
            for pattern in PERFORMANCE_PATTERNS.iter() {
                if pattern.is_match(line) {
                    vulnerabilities.push(create_vulnerability(
                        "RUST-PERF-001",
                        Some("CWE-400"),
                        "Performance Issue",
                        Severity::Low,
                        "performance",
                        "Performance anti-pattern detected in Rust code",
                        &source_file.path.to_string_lossy(),
                        line_num,
                        0,
                        line,
                        "Optimize code to avoid unnecessary allocations and conversions",
                    ));
                }
            }

            // Memory Leak Patterns
            for pattern in MEMORY_LEAK_PATTERNS.iter() {
                if pattern.is_match(line) {
                    vulnerabilities.push(create_vulnerability(
                        "RUST-MEMORY-001",
                        Some("CWE-401"),
                        "Memory Leak Risk",
                        Severity::Medium,
                        "memory",
                        "Potential memory leak detected in Rust code",
                        &source_file.path.to_string_lossy(),
                        line_num,
                        0,
                        line,
                        "Ensure proper memory management and avoid intentional leaks",
                    ));
                }
            }
        }

        Ok(vulnerabilities)
    }
}