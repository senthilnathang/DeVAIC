use crate::{
    error::Result,
    parsers::{ParsedAst, SourceFile},
    rules::{create_vulnerability, RuleSet},
    Severity, Vulnerability,
};
use regex::Regex;
use lazy_static::lazy_static;

pub struct KotlinRules;

impl KotlinRules {
    pub fn new() -> Self {
        Self
    }
}

lazy_static! {
    static ref SQL_INJECTION_PATTERNS: Vec<Regex> = vec![
        Regex::new(r#"\.execSQL\s*\([^)]*\$\{[^}]*\}[^)]*\)"#).unwrap(),
        Regex::new(r#"\.rawQuery\s*\([^)]*\$\{[^}]*\}[^)]*\)"#).unwrap(),
    ];
    
    static ref INTENT_INJECTION_PATTERNS: Vec<Regex> = vec![
        Regex::new(r#"Intent\s*\([^)]*getStringExtra[^)]*\)"#).unwrap(),
        Regex::new(r#"startActivity\s*\([^)]*getStringExtra[^)]*\)"#).unwrap(),
    ];
    
    static ref WEBVIEW_PATTERNS: Vec<Regex> = vec![
        Regex::new(r#"webView\.loadUrl\s*\([^)]*\$\{[^}]*\}[^)]*\)"#).unwrap(),
        Regex::new(r#"setJavaScriptEnabled\s*\(\s*true\s*\)"#).unwrap(),
    ];
    
    static ref CRYPTO_WEAK_PATTERNS: Vec<Regex> = vec![
        Regex::new(r#"MessageDigest\.getInstance\s*\(\s*"MD5"\s*\)"#).unwrap(),
        Regex::new(r#"MessageDigest\.getInstance\s*\(\s*"SHA1"\s*\)"#).unwrap(),
        Regex::new(r#"Cipher\.getInstance\s*\(\s*"DES"[^)]*\)"#).unwrap(),
    ];
    
    static ref HARDCODED_SECRET_PATTERNS: Vec<Regex> = vec![
        Regex::new(r#"(?i)(password|secret|key|token)\s*=\s*"[^"]{8,}""#).unwrap(),
        Regex::new(r#"(?i)(api_key|apikey)\s*=\s*"[^"]{20,}""#).unwrap(),
    ];
    
    static ref UNSAFE_REFLECTION_PATTERNS: Vec<Regex> = vec![
        Regex::new(r#"Class\.forName\s*\([^)]*\$\{[^}]*\}[^)]*\)"#).unwrap(),
        Regex::new(r#"\.newInstance\s*\(\s*\)"#).unwrap(),
    ];
}

impl RuleSet for KotlinRules {
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
                        "KOTLIN-SQL-001",
                        Some("CWE-89"),
                        "SQL Injection",
                        Severity::High,
                        "injection",
                        "SQL injection vulnerability detected in Kotlin database query",
                        &source_file.path.to_string_lossy(),
                        line_num,
                        0,
                        line,
                        "Use parameterized queries: db.rawQuery(\"SELECT * FROM users WHERE id = ?\", arrayOf(userId))",
                    ));
                }
            }

            // Intent Injection Detection
            for pattern in INTENT_INJECTION_PATTERNS.iter() {
                if pattern.is_match(line) {
                    vulnerabilities.push(create_vulnerability(
                        "KOTLIN-INTENT-001",
                        Some("CWE-926"),
                        "Intent Injection",
                        Severity::Medium,
                        "validation",
                        "Intent injection vulnerability detected in Kotlin Android code",
                        &source_file.path.to_string_lossy(),
                        line_num,
                        0,
                        line,
                        "Validate intent data and use explicit intents when possible",
                    ));
                }
            }

            // WebView Security Issues
            for pattern in WEBVIEW_PATTERNS.iter() {
                if pattern.is_match(line) {
                    vulnerabilities.push(create_vulnerability(
                        "KOTLIN-WEBVIEW-001",
                        Some("CWE-79"),
                        "WebView Security",
                        Severity::Medium,
                        "configuration",
                        "WebView security issue detected in Kotlin Android code",
                        &source_file.path.to_string_lossy(),
                        line_num,
                        0,
                        line,
                        "Disable JavaScript if not needed, validate URLs, and use HTTPS",
                    ));
                }
            }

            // Weak Cryptography Detection
            for pattern in CRYPTO_WEAK_PATTERNS.iter() {
                if pattern.is_match(line) {
                    vulnerabilities.push(create_vulnerability(
                        "KOTLIN-CRYPTO-001",
                        Some("CWE-327"),
                        "Weak Cryptography",
                        Severity::Medium,
                        "cryptography",
                        "Weak cryptographic algorithm detected in Kotlin code",
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
                        "KOTLIN-SECRET-001",
                        Some("CWE-798"),
                        "Hardcoded Credentials",
                        Severity::High,
                        "secrets",
                        "Hardcoded secret detected in Kotlin code",
                        &source_file.path.to_string_lossy(),
                        line_num,
                        0,
                        line,
                        "Store secrets in Android Keystore or secure configuration",
                    ));
                }
            }

            // Unsafe Reflection Detection
            for pattern in UNSAFE_REFLECTION_PATTERNS.iter() {
                if pattern.is_match(line) {
                    vulnerabilities.push(create_vulnerability(
                        "KOTLIN-REFLECT-001",
                        Some("CWE-470"),
                        "Unsafe Reflection",
                        Severity::Medium,
                        "validation",
                        "Unsafe reflection usage detected in Kotlin code",
                        &source_file.path.to_string_lossy(),
                        line_num,
                        0,
                        line,
                        "Validate class names against a whitelist before using reflection",
                    ));
                }
            }
        }

        Ok(vulnerabilities)
    }
}