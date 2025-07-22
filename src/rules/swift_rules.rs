use crate::{
    error::Result,
    parsers::{ParsedAst, SourceFile},
    rules::{create_vulnerability, RuleSet},
    Severity, Vulnerability,
};
use regex::Regex;
use lazy_static::lazy_static;

pub struct SwiftRules;

impl SwiftRules {
    pub fn new() -> Self {
        Self
    }
}

lazy_static! {
    static ref SQL_INJECTION_PATTERNS: Vec<Regex> = vec![
        Regex::new(r#"sqlite3_exec\s*\([^,]*,\s*"[^"]*\\\([^)]*\)"#).unwrap(),
        Regex::new(r#"sqlite3_prepare_v2\s*\([^,]*,\s*"[^"]*\\\([^)]*\)"#).unwrap(),
        Regex::new(r#"\.executeQuery\s*\(\s*"[^"]*\\\([^)]*\)"#).unwrap(),
    ];
    
    static ref URL_INJECTION_PATTERNS: Vec<Regex> = vec![
        Regex::new(r#"URL\s*\(\s*string:\s*"[^"]*\\\([^)]*\)"#).unwrap(),
        Regex::new(r#"URLRequest\s*\(\s*url:\s*URL\s*\(\s*string:\s*"[^"]*\\\([^)]*\)"#).unwrap(),
        Regex::new(r#"URLComponents\s*\(\s*string:\s*"[^"]*\\\([^)]*\)"#).unwrap(),
    ];
    
    static ref WEBVIEW_PATTERNS: Vec<Regex> = vec![
        Regex::new(r#"loadHTMLString\s*\(\s*"[^"]*\\\([^)]*\)"#).unwrap(),
        Regex::new(r#"evaluateJavaScript\s*\(\s*"[^"]*\\\([^)]*\)"#).unwrap(),
        Regex::new(r#"loadRequest\s*\(\s*URLRequest\s*\([^)]*\\\([^)]*\)"#).unwrap(),
    ];
    
    static ref CRYPTO_WEAK_PATTERNS: Vec<Regex> = vec![
        Regex::new(r#"CC_MD5\s*\("#).unwrap(),
        Regex::new(r#"CC_SHA1\s*\("#).unwrap(),
        Regex::new(r#"kCCAlgorithmDES"#).unwrap(),
        Regex::new(r#"Insecure\.MD5"#).unwrap(),
        Regex::new(r#"Insecure\.SHA1"#).unwrap(),
    ];
    
    static ref HARDCODED_SECRET_PATTERNS: Vec<Regex> = vec![
        Regex::new(r#"(?i)(password|secret|key|token)\s*=\s*"[^"]{8,}""#).unwrap(),
        Regex::new(r#"(?i)(api_key|apikey)\s*=\s*"[^"]{20,}""#).unwrap(),
    ];
    
    static ref KEYCHAIN_INSECURE_PATTERNS: Vec<Regex> = vec![
        Regex::new(r#"kSecAttrAccessibleAlways"#).unwrap(),
        Regex::new(r#"kSecAttrAccessibleAlwaysThisDeviceOnly"#).unwrap(),
    ];
    
    static ref UNSAFE_POINTER_PATTERNS: Vec<Regex> = vec![
        Regex::new(r#"UnsafePointer"#).unwrap(),
        Regex::new(r#"UnsafeMutablePointer"#).unwrap(),
        Regex::new(r#"withUnsafePointer"#).unwrap(),
    ];
    
    static ref FORCE_UNWRAP_PATTERNS: Vec<Regex> = vec![
        Regex::new(r#"\b\w+!"#).unwrap(),
    ];
    
    // Mobile-specific security patterns
    static ref IOS_SECURITY_PATTERNS: Vec<Regex> = vec![
        Regex::new(r#"kSecAttrAccessibleAlwaysThisDeviceOnly"#).unwrap(),
        Regex::new(r#"allowsArbitraryLoads\s*=\s*true"#).unwrap(),
        Regex::new(r#"NSAllowsArbitraryLoads"#).unwrap(),
    ];
    
    static ref BIOMETRIC_BYPASS_PATTERNS: Vec<Regex> = vec![
        Regex::new(r#"LAPolicy\.deviceOwnerAuthentication"#).unwrap(),
        Regex::new(r#"\.deviceOwnerAuthentication"#).unwrap(),
    ];
    
    static ref CERTIFICATE_PINNING_PATTERNS: Vec<Regex> = vec![
        Regex::new(r#"URLSessionDelegate.*didReceive.*challenge"#).unwrap(),
        Regex::new(r#"\.default\.performDefaultHandling"#).unwrap(),
    ];
    
    static ref JAILBREAK_DETECTION_BYPASS: Vec<Regex> = vec![
        Regex::new(r#"FileManager\.default\.fileExists.*Applications/Cydia"#).unwrap(),
        Regex::new(r#"/usr/sbin/sshd"#).unwrap(),
        Regex::new(r#"/bin/bash"#).unwrap(),
    ];
    
    // Performance-related patterns
    static ref PERFORMANCE_PATTERNS: Vec<Regex> = vec![
        Regex::new(r#"for\s+\w+\s+in\s+.*\.enumerated\(\)"#).unwrap(),
        Regex::new(r#"\.map\s*\{[^}]*\}\.filter\s*\{[^}]*\}"#).unwrap(),
        Regex::new(r#"String\s*\(\s*format:"#).unwrap(),
    ];
    
    static ref MEMORY_LEAK_PATTERNS: Vec<Regex> = vec![
        Regex::new(r#"\[weak\s+self\]"#).unwrap(),
        Regex::new(r#"\[unowned\s+self\]"#).unwrap(),
        Regex::new(r#"Timer\.scheduledTimer"#).unwrap(),
    ];
}

impl RuleSet for SwiftRules {
    fn analyze(&self, source_file: &SourceFile, _ast: &ParsedAst) -> Result<Vec<Vulnerability>> {
        let mut vulnerabilities = Vec::new();
        let content = &source_file.content;
        let lines: Vec<&str> = content.lines().collect();

        for (line_number, line) in lines.iter().enumerate() {
            let line_num = line_number + 1;

            // SQL Injection Detection
            for pattern in SQL_INJECTION_PATTERNS.iter() {
                if pattern.is_match(line) {
                    vulnerabilities.push(create_vulnerability(
                        "SWIFT-SQL-001",
                        Some("CWE-89"),
                        "SQL Injection",
                        Severity::High,
                        "injection",
                        "SQL injection vulnerability detected in Swift database query",
                        &source_file.path.to_string_lossy(),
                        line_num,
                        0,
                        line,
                        "Use parameterized queries or prepared statements",
                    ));
                }
            }

            // URL Injection Detection
            for pattern in URL_INJECTION_PATTERNS.iter() {
                if pattern.is_match(line) {
                    vulnerabilities.push(create_vulnerability(
                        "SWIFT-URL-001",
                        Some("CWE-20"),
                        "URL Injection",
                        Severity::Medium,
                        "validation",
                        "URL injection vulnerability detected in Swift networking code",
                        &source_file.path.to_string_lossy(),
                        line_num,
                        0,
                        line,
                        "Validate and sanitize URL inputs before use",
                    ));
                }
            }

            // WebView Security Issues
            for pattern in WEBVIEW_PATTERNS.iter() {
                if pattern.is_match(line) {
                    vulnerabilities.push(create_vulnerability(
                        "SWIFT-WEBVIEW-001",
                        Some("CWE-79"),
                        "WebView Security",
                        Severity::Medium,
                        "configuration",
                        "WebView security issue detected in Swift iOS code",
                        &source_file.path.to_string_lossy(),
                        line_num,
                        0,
                        line,
                        "Sanitize HTML content and disable JavaScript if not needed",
                    ));
                }
            }

            // Weak Cryptography Detection
            for pattern in CRYPTO_WEAK_PATTERNS.iter() {
                if pattern.is_match(line) {
                    vulnerabilities.push(create_vulnerability(
                        "SWIFT-CRYPTO-001",
                        Some("CWE-327"),
                        "Weak Cryptography",
                        Severity::Medium,
                        "cryptography",
                        "Weak cryptographic algorithm detected in Swift code",
                        &source_file.path.to_string_lossy(),
                        line_num,
                        0,
                        line,
                        "Use strong cryptographic algorithms like SHA-256, AES, or CryptoKit",
                    ));
                }
            }

            // Hardcoded Secrets Detection
            for pattern in HARDCODED_SECRET_PATTERNS.iter() {
                if pattern.is_match(line) {
                    vulnerabilities.push(create_vulnerability(
                        "SWIFT-SECRET-001",
                        Some("CWE-798"),
                        "Hardcoded Credentials",
                        Severity::High,
                        "secrets",
                        "Hardcoded secret detected in Swift code",
                        &source_file.path.to_string_lossy(),
                        line_num,
                        0,
                        line,
                        "Store secrets in iOS Keychain or secure configuration",
                    ));
                }
            }

            // Insecure Keychain Access
            for pattern in KEYCHAIN_INSECURE_PATTERNS.iter() {
                if pattern.is_match(line) {
                    vulnerabilities.push(create_vulnerability(
                        "SWIFT-KEYCHAIN-001",
                        Some("CWE-922"),
                        "Insecure Keychain Access",
                        Severity::Medium,
                        "configuration",
                        "Insecure keychain accessibility detected in Swift code",
                        &source_file.path.to_string_lossy(),
                        line_num,
                        0,
                        line,
                        "Use more secure keychain accessibility options like kSecAttrAccessibleWhenUnlockedThisDeviceOnly",
                    ));
                }
            }

            // Unsafe Pointer Usage
            for pattern in UNSAFE_POINTER_PATTERNS.iter() {
                if pattern.is_match(line) {
                    vulnerabilities.push(create_vulnerability(
                        "SWIFT-POINTER-001",
                        Some("CWE-119"),
                        "Unsafe Pointer Usage",
                        Severity::Medium,
                        "memory",
                        "Unsafe pointer usage detected in Swift code",
                        &source_file.path.to_string_lossy(),
                        line_num,
                        0,
                        line,
                        "Use safe Swift alternatives or ensure proper bounds checking",
                    ));
                }
            }

            // Force Unwrapping (potential crash)
            for pattern in FORCE_UNWRAP_PATTERNS.iter() {
                if pattern.is_match(line) && !line.trim_start().starts_with("//") {
                    vulnerabilities.push(create_vulnerability(
                        "SWIFT-UNWRAP-001",
                        Some("CWE-476"),
                        "Force Unwrapping",
                        Severity::Low,
                        "reliability",
                        "Force unwrapping detected in Swift code - potential crash risk",
                        &source_file.path.to_string_lossy(),
                        line_num,
                        0,
                        line,
                        "Use optional binding (if let) or guard statements instead of force unwrapping",
                    ));
                }
            }

            // iOS Security Issues
            for pattern in IOS_SECURITY_PATTERNS.iter() {
                if pattern.is_match(line) {
                    vulnerabilities.push(create_vulnerability(
                        "SWIFT-IOS-001",
                        Some("CWE-295"),
                        "iOS Security Configuration",
                        Severity::Medium,
                        "configuration",
                        "Insecure iOS security configuration detected",
                        &source_file.path.to_string_lossy(),
                        line_num,
                        0,
                        line,
                        "Review iOS security settings and disable arbitrary network loads",
                    ));
                }
            }

            // Biometric Authentication Bypass
            for pattern in BIOMETRIC_BYPASS_PATTERNS.iter() {
                if pattern.is_match(line) {
                    vulnerabilities.push(create_vulnerability(
                        "SWIFT-BIOMETRIC-001",
                        Some("CWE-287"),
                        "Weak Biometric Authentication",
                        Severity::Medium,
                        "authentication",
                        "Weak biometric authentication policy detected",
                        &source_file.path.to_string_lossy(),
                        line_num,
                        0,
                        line,
                        "Use LAPolicy.deviceOwnerAuthenticationWithBiometrics for stronger security",
                    ));
                }
            }

            // Certificate Pinning Issues
            for pattern in CERTIFICATE_PINNING_PATTERNS.iter() {
                if pattern.is_match(line) {
                    vulnerabilities.push(create_vulnerability(
                        "SWIFT-CERT-001",
                        Some("CWE-295"),
                        "Certificate Validation",
                        Severity::High,
                        "network",
                        "Weak certificate validation detected",
                        &source_file.path.to_string_lossy(),
                        line_num,
                        0,
                        line,
                        "Implement proper certificate pinning and validation",
                    ));
                }
            }

            // Performance Issues
            for pattern in PERFORMANCE_PATTERNS.iter() {
                if pattern.is_match(line) {
                    vulnerabilities.push(create_vulnerability(
                        "SWIFT-PERF-001",
                        Some("CWE-400"),
                        "Performance Issue",
                        Severity::Low,
                        "performance",
                        "Performance anti-pattern detected in Swift code",
                        &source_file.path.to_string_lossy(),
                        line_num,
                        0,
                        line,
                        "Optimize code for better performance - avoid chained operations and inefficient enumeration",
                    ));
                }
            }

            // Memory Leak Detection
            if line.contains("Timer.scheduledTimer") && !line.contains("[weak self]") && !line.contains("[unowned self]") {
                vulnerabilities.push(create_vulnerability(
                    "SWIFT-MEMORY-001",
                    Some("CWE-401"),
                    "Memory Leak Risk",
                    Severity::Medium,
                    "memory",
                    "Potential memory leak detected - missing weak reference",
                    &source_file.path.to_string_lossy(),
                    line_num,
                    0,
                    line,
                    "Use [weak self] or [unowned self] to prevent retain cycles",
                ));
            }
        }

        Ok(vulnerabilities)
    }
}