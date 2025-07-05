use crate::{
    error::Result,
    parsers::{ParsedAst, SourceFile},
    rules::{create_vulnerability, RuleSet},
    security_utils::safe_regex_match,
    Severity, Vulnerability,
};
use regex::Regex;
use lazy_static::lazy_static;

pub struct BashRules;

impl BashRules {
    pub fn new() -> Self {
        Self
    }
}

lazy_static! {
    static ref COMMAND_INJECTION_PATTERNS: Vec<Regex> = vec![
        Regex::new(r#"\$\([^)]{1,200}\$\{[^}]{1,100}\}[^)]{0,100}\)"#).expect("Invalid command substitution regex"),
        Regex::new(r#"`[^`]{1,200}\$\{[^}]{1,100}\}[^`]{0,100}`"#).expect("Invalid backtick command regex"),
        Regex::new(r#"eval\s+[^;]{1,200}\$\{[^}]{1,100}\}[^;]{0,100}"#).expect("Invalid eval regex"),
    ];
    
    static ref PATH_TRAVERSAL_PATTERNS: Vec<Regex> = vec![
        Regex::new(r#"(cat|less|more|head|tail)\s+[^;]{1,200}\$\{[^}]{1,100}\}[^;]{0,100}"#).expect("Invalid file read regex"),
        Regex::new(r#"(cp|mv|rm)\s+[^;]{1,200}\$\{[^}]{1,100}\}[^;]{0,100}"#).expect("Invalid file operation regex"),
    ];
    
    static ref CURL_SSRF_PATTERNS: Vec<Regex> = vec![
        Regex::new(r#"curl\s+[^;]{1,200}\$\{[^}]{1,100}\}[^;]{0,100}"#).expect("Invalid curl regex"),
        Regex::new(r#"wget\s+[^;]{1,200}\$\{[^}]{1,100}\}[^;]{0,100}"#).expect("Invalid wget regex"),
    ];
    
    static ref HARDCODED_SECRET_PATTERNS: Vec<Regex> = vec![
        Regex::new(r#"(?i)(password|secret|key|token)=['"][^'"]{8,100}['"]"#).expect("Invalid secret detection regex"),
        Regex::new(r#"(?i)(api_key|apikey)=['"][^'"]{20,200}['"]"#).expect("Invalid API key detection regex"),
    ];
    
    static ref UNSAFE_PERMISSIONS_PATTERNS: Vec<Regex> = vec![
        Regex::new(r#"chmod\s+(777|666|755)\s+"#).expect("Invalid chmod regex"),
        Regex::new(r#"umask\s+0{3,4}"#).expect("Invalid umask regex"),
    ];
}

impl RuleSet for BashRules {
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

            // Command Injection Detection
            for pattern in COMMAND_INJECTION_PATTERNS.iter() {
                if safe_regex_match(pattern, line, 100)? {
                    vulnerabilities.push(create_vulnerability(
                        "BASH-CMD-001",
                        Some("CWE-78"),
                        "Command Injection",
                        Severity::Critical,
                        "injection",
                        "Command injection vulnerability detected in Bash script",
                        &source_file.path.to_string_lossy(),
                        line_num,
                        0,
                        line,
                        "Validate and sanitize all user inputs, use proper quoting and parameter expansion",
                    ));
                }
            }

            // Path Traversal Detection
            for pattern in PATH_TRAVERSAL_PATTERNS.iter() {
                if safe_regex_match(pattern, line, 100)? {
                    vulnerabilities.push(create_vulnerability(
                        "BASH-PATH-001",
                        Some("CWE-22"),
                        "Path Traversal",
                        Severity::High,
                        "validation",
                        "Path traversal vulnerability detected in Bash file operation",
                        &source_file.path.to_string_lossy(),
                        line_num,
                        0,
                        line,
                        "Validate file paths and use realpath to resolve paths safely",
                    ));
                }
            }

            // SSRF Detection
            for pattern in CURL_SSRF_PATTERNS.iter() {
                if safe_regex_match(pattern, line, 100)? {
                    vulnerabilities.push(create_vulnerability(
                        "BASH-SSRF-001",
                        Some("CWE-918"),
                        "Server-Side Request Forgery",
                        Severity::High,
                        "validation",
                        "SSRF vulnerability detected in Bash HTTP request",
                        &source_file.path.to_string_lossy(),
                        line_num,
                        0,
                        line,
                        "Validate and whitelist URLs before making HTTP requests",
                    ));
                }
            }

            // Hardcoded Secrets Detection
            for pattern in HARDCODED_SECRET_PATTERNS.iter() {
                if safe_regex_match(pattern, line, 100)? {
                    vulnerabilities.push(create_vulnerability(
                        "BASH-SECRET-001",
                        Some("CWE-798"),
                        "Hardcoded Credentials",
                        Severity::High,
                        "secrets",
                        "Hardcoded secret detected in Bash script",
                        &source_file.path.to_string_lossy(),
                        line_num,
                        0,
                        line,
                        "Store secrets in environment variables or secure configuration files",
                    ));
                }
            }

            // Unsafe Permissions Detection
            for pattern in UNSAFE_PERMISSIONS_PATTERNS.iter() {
                if safe_regex_match(pattern, line, 100)? {
                    vulnerabilities.push(create_vulnerability(
                        "BASH-PERM-001",
                        Some("CWE-732"),
                        "Incorrect Permission Assignment",
                        Severity::Medium,
                        "authorization",
                        "Unsafe file permissions detected in Bash script",
                        &source_file.path.to_string_lossy(),
                        line_num,
                        0,
                        line,
                        "Use restrictive file permissions and avoid world-writable files",
                    ));
                }
            }
        }

        Ok(vulnerabilities)
    }
}