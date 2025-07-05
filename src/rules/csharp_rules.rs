use crate::{
    error::Result,
    parsers::{ParsedAst, SourceFile},
    rules::{create_vulnerability, RuleSet},
    Severity, Vulnerability,
};
use regex::Regex;
use lazy_static::lazy_static;

pub struct CSharpRules;

impl CSharpRules {
    pub fn new() -> Self {
        Self
    }
}

lazy_static! {
    static ref SQL_INJECTION_PATTERNS: Vec<Regex> = vec![
        Regex::new(r#"\.ExecuteQuery\s*\([^)]*\+[^)]*\)"#).unwrap(),
        Regex::new(r#"\.ExecuteNonQuery\s*\([^)]*\+[^)]*\)"#).unwrap(),
        Regex::new(r#"new SqlCommand\s*\([^)]*\+[^)]*\)"#).unwrap(),
    ];
    
    static ref COMMAND_INJECTION_PATTERNS: Vec<Regex> = vec![
        Regex::new(r#"Process\.Start\s*\([^)]*\+[^)]*\)"#).unwrap(),
        Regex::new(r#"ProcessStartInfo\s*\([^)]*\+[^)]*\)"#).unwrap(),
    ];
    
    static ref DESERIALIZATION_PATTERNS: Vec<Regex> = vec![
        Regex::new(r#"BinaryFormatter\.Deserialize"#).unwrap(),
        Regex::new(r#"XmlSerializer\.Deserialize"#).unwrap(),
        Regex::new(r#"JsonConvert\.DeserializeObject"#).unwrap(),
    ];
    
    static ref PATH_TRAVERSAL_PATTERNS: Vec<Regex> = vec![
        Regex::new(r#"File\.ReadAllText\s*\([^)]*Request\[[^]]*\][^)]*\)"#).unwrap(),
        Regex::new(r#"File\.WriteAllText\s*\([^)]*Request\[[^]]*\][^)]*\)"#).unwrap(),
    ];
    
    static ref WEAK_CRYPTO_PATTERNS: Vec<Regex> = vec![
        Regex::new(r#"MD5\.Create\(\)"#).unwrap(),
        Regex::new(r#"SHA1\.Create\(\)"#).unwrap(),
        Regex::new(r#"DESCryptoServiceProvider"#).unwrap(),
    ];
    
    static ref HARDCODED_SECRET_PATTERNS: Vec<Regex> = vec![
        Regex::new(r#"(?i)(password|secret|key|token)\s*=\s*"[^"]{8,}""#).unwrap(),
        Regex::new(r#"(?i)(connectionstring)\s*=\s*"[^"]*password=[^"]*""#).unwrap(),
    ];
    
    static ref LDAP_INJECTION_PATTERNS: Vec<Regex> = vec![
        Regex::new(r#"DirectorySearcher\s*\([^)]*\+[^)]*\)"#).unwrap(),
        Regex::new(r#"\.Filter\s*=\s*[^;]*\+[^;]*"#).unwrap(),
    ];
}

impl RuleSet for CSharpRules {
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
                        "CSHARP-SQL-001",
                        Some("CWE-89"),
                        "SQL Injection",
                        Severity::High,
                        "injection",
                        "SQL injection vulnerability detected in C# database query",
                        &source_file.path.to_string_lossy(),
                        line_num,
                        0,
                        line,
                        "Use parameterized queries: cmd.Parameters.AddWithValue(\"@id\", userId)",
                    ));
                }
            }

            // Command Injection Detection
            for pattern in COMMAND_INJECTION_PATTERNS.iter() {
                if pattern.is_match(line) {
                    vulnerabilities.push(create_vulnerability(
                        "CSHARP-CMD-001",
                        Some("CWE-78"),
                        "Command Injection",
                        Severity::High,
                        "injection",
                        "Command injection vulnerability detected in C# process execution",
                        &source_file.path.to_string_lossy(),
                        line_num,
                        0,
                        line,
                        "Validate and sanitize all user inputs before using in process execution",
                    ));
                }
            }

            // Unsafe Deserialization Detection
            for pattern in DESERIALIZATION_PATTERNS.iter() {
                if pattern.is_match(line) {
                    vulnerabilities.push(create_vulnerability(
                        "CSHARP-DESER-001",
                        Some("CWE-502"),
                        "Unsafe Deserialization",
                        Severity::High,
                        "deserialization",
                        "Unsafe deserialization detected in C# code",
                        &source_file.path.to_string_lossy(),
                        line_num,
                        0,
                        line,
                        "Validate serialized data and use safe serialization methods",
                    ));
                }
            }

            // Path Traversal Detection
            for pattern in PATH_TRAVERSAL_PATTERNS.iter() {
                if pattern.is_match(line) {
                    vulnerabilities.push(create_vulnerability(
                        "CSHARP-PATH-001",
                        Some("CWE-22"),
                        "Path Traversal",
                        Severity::Medium,
                        "validation",
                        "Path traversal vulnerability detected in C# file operation",
                        &source_file.path.to_string_lossy(),
                        line_num,
                        0,
                        line,
                        "Use Path.GetFileName() and validate file paths against a whitelist",
                    ));
                }
            }

            // Weak Cryptography Detection
            for pattern in WEAK_CRYPTO_PATTERNS.iter() {
                if pattern.is_match(line) {
                    vulnerabilities.push(create_vulnerability(
                        "CSHARP-CRYPTO-001",
                        Some("CWE-327"),
                        "Weak Cryptography",
                        Severity::Medium,
                        "cryptography",
                        "Weak cryptographic algorithm detected in C# code",
                        &source_file.path.to_string_lossy(),
                        line_num,
                        0,
                        line,
                        "Use strong cryptographic algorithms like SHA256 or AES",
                    ));
                }
            }

            // Hardcoded Secrets Detection
            for pattern in HARDCODED_SECRET_PATTERNS.iter() {
                if pattern.is_match(line) {
                    vulnerabilities.push(create_vulnerability(
                        "CSHARP-SECRET-001",
                        Some("CWE-798"),
                        "Hardcoded Credentials",
                        Severity::High,
                        "secrets",
                        "Hardcoded secret detected in C# code",
                        &source_file.path.to_string_lossy(),
                        line_num,
                        0,
                        line,
                        "Store secrets in configuration files or Azure Key Vault",
                    ));
                }
            }

            // LDAP Injection Detection
            for pattern in LDAP_INJECTION_PATTERNS.iter() {
                if pattern.is_match(line) {
                    vulnerabilities.push(create_vulnerability(
                        "CSHARP-LDAP-001",
                        Some("CWE-90"),
                        "LDAP Injection",
                        Severity::Medium,
                        "injection",
                        "LDAP injection vulnerability detected in C# code",
                        &source_file.path.to_string_lossy(),
                        line_num,
                        0,
                        line,
                        "Escape LDAP special characters and validate input",
                    ));
                }
            }
        }

        Ok(vulnerabilities)
    }
}