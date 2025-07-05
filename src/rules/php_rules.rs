use crate::{
    error::Result,
    parsers::{ParsedAst, SourceFile},
    rules::{create_vulnerability, RuleSet},
    Severity, Vulnerability,
};
use regex::Regex;
use lazy_static::lazy_static;

pub struct PhpRules;

impl PhpRules {
    pub fn new() -> Self {
        Self
    }
}

lazy_static! {
    static ref SQL_INJECTION_PATTERNS: Vec<Regex> = vec![
        Regex::new(r#"mysql_query\s*\([^)]*\$_(GET|POST|REQUEST)\[[^]]*\][^)]*\)"#).unwrap(),
        Regex::new(r#"mysqli_query\s*\([^)]*\$_(GET|POST|REQUEST)\[[^]]*\][^)]*\)"#).unwrap(),
        Regex::new(r#"\$pdo->query\s*\([^)]*\$_(GET|POST|REQUEST)\[[^]]*\][^)]*\)"#).unwrap(),
    ];
    
    static ref COMMAND_INJECTION_PATTERNS: Vec<Regex> = vec![
        Regex::new(r#"(exec|system|shell_exec|passthru)\s*\(\s*\$_(GET|POST|REQUEST)\[[^]]*\]"#).unwrap(),
        Regex::new(r#"eval\s*\(\s*\$_(GET|POST|REQUEST)\[[^]]*\]"#).unwrap(),
    ];
    
    static ref FILE_INCLUSION_PATTERNS: Vec<Regex> = vec![
        Regex::new(r#"(include|require|include_once|require_once)\s*\(\s*\$_(GET|POST|REQUEST)\[[^]]*\]"#).unwrap(),
    ];
    
    static ref XSS_PATTERNS: Vec<Regex> = vec![
        Regex::new(r#"echo\s+\$_(GET|POST|REQUEST)\[[^]]*\]"#).unwrap(),
        Regex::new(r#"print\s+\$_(GET|POST|REQUEST)\[[^]]*\]"#).unwrap(),
        Regex::new(r#"printf\s*\(\s*\$_(GET|POST|REQUEST)\[[^]]*\]"#).unwrap(),
    ];
    
    static ref PATH_TRAVERSAL_PATTERNS: Vec<Regex> = vec![
        Regex::new(r#"(file_get_contents|file_put_contents|fopen|readfile)\s*\(\s*\$_(GET|POST|REQUEST)\[[^]]*\]"#).unwrap(),
    ];
    
    static ref WEAK_CRYPTO_PATTERNS: Vec<Regex> = vec![
        Regex::new(r#"md5\s*\("#).unwrap(),
        Regex::new(r#"sha1\s*\("#).unwrap(),
        Regex::new(r#"crypt\s*\([^,)]*\)"#).unwrap(),
    ];
    
    static ref HARDCODED_SECRET_PATTERNS: Vec<Regex> = vec![
        Regex::new(r#"(?i)\$(password|secret|key|token)\s*=\s*['"][^'"]{8,}['"]"#).unwrap(),
        Regex::new(r#"(?i)\$(api_key|apikey)\s*=\s*['"][^'"]{20,}['"]"#).unwrap(),
    ];
}

impl RuleSet for PhpRules {
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
                        "PHP-SQL-001",
                        Some("CWE-89"),
                        "SQL Injection",
                        Severity::Critical,
                        "injection",
                        "SQL injection vulnerability detected in PHP database query",
                        &source_file.path.to_string_lossy(),
                        line_num,
                        0,
                        line,
                        "Use prepared statements with parameter binding: $stmt = $pdo->prepare('SELECT * FROM users WHERE id = ?'); $stmt->execute([$id]);",
                    ));
                }
            }

            // Command Injection Detection
            for pattern in COMMAND_INJECTION_PATTERNS.iter() {
                if pattern.is_match(line) {
                    vulnerabilities.push(create_vulnerability(
                        "PHP-CMD-001",
                        Some("CWE-78"),
                        "Command Injection",
                        Severity::Critical,
                        "injection",
                        "Command injection vulnerability detected in PHP exec call",
                        &source_file.path.to_string_lossy(),
                        line_num,
                        0,
                        line,
                        "Validate and sanitize all user inputs before using in system commands. Use escapeshellarg() for arguments.",
                    ));
                }
            }

            // File Inclusion Detection
            for pattern in FILE_INCLUSION_PATTERNS.iter() {
                if pattern.is_match(line) {
                    vulnerabilities.push(create_vulnerability(
                        "PHP-FILE-001",
                        Some("CWE-98"),
                        "File Inclusion",
                        Severity::Critical,
                        "injection",
                        "File inclusion vulnerability detected in PHP include/require",
                        &source_file.path.to_string_lossy(),
                        line_num,
                        0,
                        line,
                        "Validate file paths against a whitelist and use realpath() to resolve paths",
                    ));
                }
            }

            // XSS Detection
            for pattern in XSS_PATTERNS.iter() {
                if pattern.is_match(line) {
                    vulnerabilities.push(create_vulnerability(
                        "PHP-XSS-001",
                        Some("CWE-79"),
                        "Cross-Site Scripting",
                        Severity::High,
                        "injection",
                        "XSS vulnerability detected in PHP output",
                        &source_file.path.to_string_lossy(),
                        line_num,
                        0,
                        line,
                        "Use htmlspecialchars() or htmlentities() to escape output: echo htmlspecialchars($userInput, ENT_QUOTES, 'UTF-8');",
                    ));
                }
            }

            // Path Traversal Detection
            for pattern in PATH_TRAVERSAL_PATTERNS.iter() {
                if pattern.is_match(line) {
                    vulnerabilities.push(create_vulnerability(
                        "PHP-PATH-001",
                        Some("CWE-22"),
                        "Path Traversal",
                        Severity::High,
                        "validation",
                        "Path traversal vulnerability detected in PHP file operation",
                        &source_file.path.to_string_lossy(),
                        line_num,
                        0,
                        line,
                        "Validate file paths and use basename() to prevent directory traversal",
                    ));
                }
            }

            // Weak Cryptography Detection
            for pattern in WEAK_CRYPTO_PATTERNS.iter() {
                if pattern.is_match(line) {
                    vulnerabilities.push(create_vulnerability(
                        "PHP-CRYPTO-001",
                        Some("CWE-327"),
                        "Weak Cryptography",
                        Severity::Medium,
                        "cryptography",
                        "Weak cryptographic algorithm detected in PHP code",
                        &source_file.path.to_string_lossy(),
                        line_num,
                        0,
                        line,
                        "Use strong hashing algorithms like password_hash() for passwords or hash('sha256', $data) for data integrity",
                    ));
                }
            }

            // Hardcoded Secrets Detection
            for pattern in HARDCODED_SECRET_PATTERNS.iter() {
                if pattern.is_match(line) {
                    vulnerabilities.push(create_vulnerability(
                        "PHP-SECRET-001",
                        Some("CWE-798"),
                        "Hardcoded Credentials",
                        Severity::High,
                        "secrets",
                        "Hardcoded secret detected in PHP code",
                        &source_file.path.to_string_lossy(),
                        line_num,
                        0,
                        line,
                        "Store secrets in environment variables or secure configuration files",
                    ));
                }
            }
        }

        Ok(vulnerabilities)
    }
}