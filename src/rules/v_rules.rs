/// V Language Security Rules for DeVAIC
/// 
/// This module defines security rules and patterns for analyzing V language code.
/// These rules complement the V parser to provide comprehensive security analysis.

use crate::{Vulnerability, Severity, Language};
use crate::error::Result;
use std::collections::HashMap;
use regex::Regex;

pub struct VRules {
    patterns: HashMap<String, Regex>,
}

impl VRules {
    pub fn new() -> Self {
        let mut patterns = HashMap::new();
        
        // Memory safety patterns
        patterns.insert(
            "unsafe_memory_block".to_string(),
            Regex::new(r"(?i)unsafe\s*\{").unwrap()
        );
        
        patterns.insert(
            "raw_pointer_usage".to_string(),
            Regex::new(r"(?i)\bvoidptr\b").unwrap()
        );
        
        // Web security patterns (vweb)
        patterns.insert(
            "vweb_xss_vulnerability".to_string(),
            Regex::new(r"(?i)\$\{[^}]*\}").unwrap()
        );
        
        patterns.insert(
            "sql_injection_risk".to_string(),
            Regex::new(r"(?i)db\.(?:exec|query)\s*\([^)]*\+" ).unwrap()
        );
        
        patterns.insert(
            "unsafe_route_handler".to_string(),
            Regex::new(r"(?i)\[.*\]\s*pub\s+fn\s+[A-Za-z_][A-Za-z0-9_]*\s*\([^)]*ctx\s+vweb\.Context").unwrap()
        );
        
        // Database security
        patterns.insert(
            "hardcoded_db_credentials".to_string(),
            Regex::new(r#"(?i)(?:password|user|host|db)\s*:\s*['""][^'"]{3,}['"]"#).unwrap()
        );
        
        // Network security
        patterns.insert(
            "insecure_http_request".to_string(),
            Regex::new(r"(?i)http\.(?:get|post)\s*\([^)]*\+").unwrap()
        );
        
        patterns.insert(
            "disabled_ssl_verification".to_string(),
            Regex::new(r"(?i)verify_ssl\s*:\s*false").unwrap()
        );
        
        // File operations
        patterns.insert(
            "unsafe_file_operation".to_string(),
            Regex::new(r"(?i)os\.(?:read_file|write_file|create|rm)\s*\([^)]*\+").unwrap()
        );
        
        patterns.insert(
            "path_traversal_pattern".to_string(),
            Regex::new(r"(?i)\.\.[\\/]").unwrap()
        );
        
        // Error handling
        patterns.insert(
            "ignored_error_result".to_string(),
            Regex::new(r"(?i)or\s*\{\s*\}").unwrap()
        );
        
        patterns.insert(
            "panic_on_error".to_string(),
            Regex::new(r"(?i)or\s*\{\s*panic\s*\(").unwrap()
        );
        
        // FFI security
        patterns.insert(
            "c_interop_usage".to_string(),
            Regex::new(r"(?i)#include\s+|C\.").unwrap()
        );
        
        patterns.insert(
            "external_library_call".to_string(),
            Regex::new(r"(?i)fn\s+C\.[A-Za-z_][A-Za-z0-9_]*").unwrap()
        );
        
        // Command execution
        patterns.insert(
            "command_injection_risk".to_string(),
            Regex::new(r"(?i)os\.(?:execute|system)\s*\([^)]*\+").unwrap()
        );
        
        // Hardcoded secrets
        patterns.insert(
            "hardcoded_secrets".to_string(),
            Regex::new(r#"(?i)(?:api_key|secret|token|password)\s*:=\s*['"][^'"]{8,}['""]"#).unwrap()
        );
        
        // Debug code
        patterns.insert(
            "debug_statements".to_string(),
            Regex::new(r"(?i)println\s*\(|eprintln\s*\(|dump\s*\(").unwrap()
        );
        
        // JSON security
        patterns.insert(
            "unsafe_json_decode".to_string(),
            Regex::new(r"(?i)json\.decode\s*\(").unwrap()
        );

        Self { patterns }
    }

    pub fn analyze(&self, content: &str, file_path: &str) -> Result<Vec<Vulnerability>> {
        let mut vulnerabilities = Vec::new();
        let lines: Vec<&str> = content.lines().collect();

        for (line_number, line) in lines.iter().enumerate() {
            let line_num = line_number + 1;
            let trimmed_line = line.trim();

            // Skip empty lines and comments
            if trimmed_line.is_empty() || trimmed_line.starts_with("//") {
                continue;
            }

            // Check for unsafe memory blocks
            if let Some(captures) = self.patterns["unsafe_memory_block"].captures(line) {
                vulnerabilities.push(Vulnerability {
                    id: "V-UNSAFE-001".to_string(),
                    cwe: Some("CWE-119".to_string()),
                    vulnerability_type: "Unsafe Memory Access".to_string(),
                    severity: Severity::High,
                    category: "memory".to_string(),
                    description: "Unsafe memory block detected".to_string(),
                    file_path: file_path.to_string(),
                    line_number: line_num,
                    column: captures.get(0).map(|m| m.start()).unwrap_or(0),
                    source_code: trimmed_line.to_string(),
                    recommendation: "Review unsafe operations and ensure memory safety".to_string(),
                });
            }

            // Check for XSS vulnerabilities in vweb
            if let Some(captures) = self.patterns["vweb_xss_vulnerability"].captures(line) {
                vulnerabilities.push(Vulnerability {
                    id: "V-XSS-001".to_string(),
                    cwe: Some("CWE-79".to_string()),
                    vulnerability_type: "Cross-Site Scripting".to_string(),
                    severity: Severity::High,
                    category: "web".to_string(),
                    description: "Template interpolation without escaping - XSS risk".to_string(),
                    file_path: file_path.to_string(),
                    line_number: line_num,
                    column: captures.get(0).map(|m| m.start()).unwrap_or(0),
                    source_code: trimmed_line.to_string(),
                    recommendation: "Use proper HTML escaping for user input in templates".to_string(),
                });
            }

            // Check for SQL injection
            if let Some(captures) = self.patterns["sql_injection_risk"].captures(line) {
                vulnerabilities.push(Vulnerability {
                    id: "V-SQL-001".to_string(),
                    cwe: Some("CWE-89".to_string()),
                    vulnerability_type: "SQL Injection".to_string(),
                    severity: Severity::Critical,
                    category: "database".to_string(),
                    description: "SQL query with string concatenation - injection risk".to_string(),
                    file_path: file_path.to_string(),
                    line_number: line_num,
                    column: captures.get(0).map(|m| m.start()).unwrap_or(0),
                    source_code: trimmed_line.to_string(),
                    recommendation: "Use parameterized queries or ORM methods".to_string(),
                });
            }

            // Check for hardcoded database credentials
            if let Some(captures) = self.patterns["hardcoded_db_credentials"].captures(line) {
                vulnerabilities.push(Vulnerability {
                    id: "V-DB-001".to_string(),
                    cwe: Some("CWE-798".to_string()),
                    vulnerability_type: "Hardcoded Database Credentials".to_string(),
                    severity: Severity::Critical,
                    category: "authentication".to_string(),
                    description: "Hardcoded database credentials detected".to_string(),
                    file_path: file_path.to_string(),
                    line_number: line_num,
                    column: captures.get(0).map(|m| m.start()).unwrap_or(0),
                    source_code: trimmed_line.to_string(),
                    recommendation: "Move credentials to environment variables".to_string(),
                });
            }

            // Check for insecure HTTP requests
            if let Some(captures) = self.patterns["insecure_http_request"].captures(line) {
                vulnerabilities.push(Vulnerability {
                    id: "V-HTTP-001".to_string(),
                    cwe: Some("CWE-918".to_string()),
                    vulnerability_type: "Server-Side Request Forgery".to_string(),
                    severity: Severity::High,
                    category: "network".to_string(),
                    description: "HTTP request with dynamic URL - SSRF risk".to_string(),
                    file_path: file_path.to_string(),
                    line_number: line_num,
                    column: captures.get(0).map(|m| m.start()).unwrap_or(0),
                    source_code: trimmed_line.to_string(),
                    recommendation: "Validate and whitelist URLs before making requests".to_string(),
                });
            }

            // Check for disabled SSL verification
            if let Some(captures) = self.patterns["disabled_ssl_verification"].captures(line) {
                vulnerabilities.push(Vulnerability {
                    id: "V-TLS-001".to_string(),
                    cwe: Some("CWE-295".to_string()),
                    vulnerability_type: "Improper Certificate Validation".to_string(),
                    severity: Severity::High,
                    category: "cryptography".to_string(),
                    description: "SSL certificate verification disabled".to_string(),
                    file_path: file_path.to_string(),
                    line_number: line_num,
                    column: captures.get(0).map(|m| m.start()).unwrap_or(0),
                    source_code: trimmed_line.to_string(),
                    recommendation: "Enable proper SSL certificate validation".to_string(),
                });
            }

            // Check for unsafe file operations
            if let Some(captures) = self.patterns["unsafe_file_operation"].captures(line) {
                vulnerabilities.push(Vulnerability {
                    id: "V-FILE-001".to_string(),
                    cwe: Some("CWE-22".to_string()),
                    vulnerability_type: "Path Traversal".to_string(),
                    severity: Severity::High,
                    category: "file_system".to_string(),
                    description: "File operation with dynamic path - traversal risk".to_string(),
                    file_path: file_path.to_string(),
                    line_number: line_num,
                    column: captures.get(0).map(|m| m.start()).unwrap_or(0),
                    source_code: trimmed_line.to_string(),
                    recommendation: "Validate and sanitize file paths".to_string(),
                });
            }

            // Check for ignored errors
            if let Some(captures) = self.patterns["ignored_error_result"].captures(line) {
                vulnerabilities.push(Vulnerability {
                    id: "V-ERR-001".to_string(),
                    cwe: Some("CWE-252".to_string()),
                    vulnerability_type: "Unchecked Error Condition".to_string(),
                    severity: Severity::Medium,
                    category: "error_handling".to_string(),
                    description: "Error result ignored in or block".to_string(),
                    file_path: file_path.to_string(),
                    line_number: line_num,
                    column: captures.get(0).map(|m| m.start()).unwrap_or(0),
                    source_code: trimmed_line.to_string(),
                    recommendation: "Handle errors appropriately or log for debugging".to_string(),
                });
            }

            // Check for command injection
            if let Some(captures) = self.patterns["command_injection_risk"].captures(line) {
                vulnerabilities.push(Vulnerability {
                    id: "V-CMD-001".to_string(),
                    cwe: Some("CWE-78".to_string()),
                    vulnerability_type: "Command Injection".to_string(),
                    severity: Severity::Critical,
                    category: "command_execution".to_string(),
                    description: "Command execution with dynamic input".to_string(),
                    file_path: file_path.to_string(),
                    line_number: line_num,
                    column: captures.get(0).map(|m| m.start()).unwrap_or(0),
                    source_code: trimmed_line.to_string(),
                    recommendation: "Validate and sanitize command arguments".to_string(),
                });
            }

            // Check for hardcoded secrets
            if let Some(captures) = self.patterns["hardcoded_secrets"].captures(line) {
                vulnerabilities.push(Vulnerability {
                    id: "V-SECRET-001".to_string(),
                    cwe: Some("CWE-798".to_string()),
                    vulnerability_type: "Hardcoded Credentials".to_string(),
                    severity: Severity::Critical,
                    category: "authentication".to_string(),
                    description: "Hardcoded secret detected".to_string(),
                    file_path: file_path.to_string(),
                    line_number: line_num,
                    column: captures.get(0).map(|m| m.start()).unwrap_or(0),
                    source_code: trimmed_line.to_string(),
                    recommendation: "Move secrets to environment variables".to_string(),
                });
            }

            // Check for debug statements
            if let Some(captures) = self.patterns["debug_statements"].captures(line) {
                vulnerabilities.push(Vulnerability {
                    id: "V-DEBUG-001".to_string(),
                    cwe: Some("CWE-489".to_string()),
                    vulnerability_type: "Debug Code in Production".to_string(),
                    severity: Severity::Low,
                    category: "information_disclosure".to_string(),
                    description: "Debug statement detected".to_string(),
                    file_path: file_path.to_string(),
                    line_number: line_num,
                    column: captures.get(0).map(|m| m.start()).unwrap_or(0),
                    source_code: trimmed_line.to_string(),
                    recommendation: "Remove debug statements from production code".to_string(),
                });
            }
        }

        Ok(vulnerabilities)
    }

    pub fn get_language() -> Language {
        Language::V
    }
}

impl Default for VRules {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_v_sql_injection() {
        let rules = VRules::new();
        let code = r#"
            query := "SELECT * FROM users WHERE id = " + user_id
            db.exec(query)
        "#;
        
        let vulnerabilities = rules.analyze(code, "test.v").unwrap();
        assert!(vulnerabilities.iter().any(|v| v.id == "V-SQL-001"));
    }

    #[test]
    fn test_v_xss_vulnerability() {
        let rules = VRules::new();
        let code = r#"
            html := '<div>${user_input}</div>'
        "#;
        
        let vulnerabilities = rules.analyze(code, "test.v").unwrap();
        assert!(vulnerabilities.iter().any(|v| v.id == "V-XSS-001"));
    }

    #[test]
    fn test_v_hardcoded_credentials() {
        let rules = VRules::new();
        let code = r#"
            api_key := "sk_live_1234567890abcdef"
        "#;
        
        let vulnerabilities = rules.analyze(code, "test.v").unwrap();
        assert!(vulnerabilities.iter().any(|v| v.id == "V-SECRET-001"));
    }
}