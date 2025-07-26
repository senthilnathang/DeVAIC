/// V Language Parser for DeVAIC
/// 
/// This module provides parsing support for V programming language files.
/// V is a simple, fast, safe, compiled language for developing maintainable software.
/// 
/// Security concerns for V include:
/// - Memory safety with automatic memory management
/// - Cross-platform compilation security
/// - FFI (Foreign Function Interface) safety
/// - Web framework security (vweb)
/// - Database interaction security
/// - Network programming security
/// - Module system security

use crate::parsers::{SourceFile, ParsedAst, AstMetadata, Parser};
use crate::{Language, Vulnerability, Severity};
use crate::error::Result;
use std::collections::HashMap;
use regex::Regex;

/// V-specific parser implementation
pub struct VParser {
    /// Common V security patterns for analysis
    patterns: HashMap<String, Regex>,
}

impl VParser {
    pub fn new() -> Self {
        let mut patterns = HashMap::new();
        
        // Initialize V security patterns
        
        // Memory safety patterns
        patterns.insert(
            "unsafe_memory_access".to_string(),
            Regex::new(r"(?i)unsafe\s*\{").unwrap()
        );
        
        patterns.insert(
            "raw_pointer_usage".to_string(),
            Regex::new(r"(?i)\bvoidptr\b|\b&[A-Za-z_][A-Za-z0-9_]*\b").unwrap()
        );
        
        // FFI security patterns
        patterns.insert(
            "unsafe_c_interop".to_string(),
            Regex::new(r#"(?i)#include\s+['"]|C\."#).unwrap()
        );
        
        patterns.insert(
            "external_function_call".to_string(),
            Regex::new(r"(?i)fn\s+C\.[A-Za-z_][A-Za-z0-9_]*").unwrap()
        );
        
        // Web security patterns (vweb)
        patterns.insert(
            "vweb_xss_risk".to_string(),
            Regex::new(r"\$\{[^}]*\}").unwrap()
        );
        
        patterns.insert(
            "vweb_sql_injection".to_string(),
            Regex::new(r"(?i)db\.(exec|query)\s*\(|query\s*:=.*\+.*(?:SELECT|INSERT|UPDATE|DELETE)").unwrap()
        );
        
        patterns.insert(
            "vweb_unsafe_route".to_string(),
            Regex::new(r"(?i)\[.*\]\s*pub\s+fn\s+[A-Za-z_][A-Za-z0-9_]*\s*\([^)]*ctx\s+vweb\.Context").unwrap()
        );
        
        // Database security patterns
        patterns.insert(
            "hardcoded_database_credentials".to_string(),
            Regex::new(r#"(?i)(?:password|user|host|db)\s*:\s*['"][^'"]{3,}['"]"#).unwrap()
        );
        
        patterns.insert(
            "sql_injection_risk".to_string(),
            Regex::new(r"(?i)(?:SELECT|INSERT|UPDATE|DELETE).*\+|.*\+.*(?:SELECT|INSERT|UPDATE|DELETE)").unwrap()
        );
        
        // Network security patterns
        patterns.insert(
            "unsafe_http_client".to_string(),
            Regex::new(r"(?i)http\.(get|post)\s*\([^)]*\+").unwrap()
        );
        
        patterns.insert(
            "insecure_tls".to_string(),
            Regex::new(r"(?i)verify_ssl\s*:\s*false|tls_config\s*:\s*none").unwrap()
        );
        
        // File operations
        patterns.insert(
            "unsafe_file_operations".to_string(),
            Regex::new(r"(?i)os\.(read_file|write_file|create|rm)\s*\([^)]*\+").unwrap()
        );
        
        patterns.insert(
            "path_traversal_risk".to_string(),
            Regex::new(r"(?i)\.\.[/\\]").unwrap()
        );
        
        // Error handling patterns
        patterns.insert(
            "ignored_error".to_string(),
            Regex::new(r"(?i)or\s*\{\s*\}").unwrap()
        );
        
        patterns.insert(
            "panic_on_error".to_string(),
            Regex::new(r"(?i)or\s*\{\s*panic\s*\(").unwrap()
        );
        
        // Hardcoded secrets
        patterns.insert(
            "hardcoded_secrets".to_string(),
            Regex::new(r#"(?i)(?:api_key|secret|token|password)\s*:=\s*['"][^'"]{8,}['"]"#).unwrap()
        );
        
        // Module security
        patterns.insert(
            "unsafe_module_import".to_string(),
            Regex::new(r"(?i)import\s+[A-Za-z_][A-Za-z0-9_]*\s*\{[^}]*unsafe").unwrap()
        );
        
        // JSON/Serialization security
        patterns.insert(
            "unsafe_json_decode".to_string(),
            Regex::new(r"(?i)json\.decode\s*\([^)]*,\s*[^)]*\)").unwrap()
        );
        
        // Cross-platform security
        patterns.insert(
            "platform_specific_unsafe".to_string(),
            Regex::new(r"(?i)\$if\s+(?:windows|linux|macos)\s*\{[^}]*unsafe").unwrap()
        );
        
        // Debug and development patterns
        patterns.insert(
            "debug_code".to_string(),
            Regex::new(r"(?i)println\s*\(|eprintln\s*\(|dump\s*\(").unwrap()
        );
        
        // Command execution
        patterns.insert(
            "command_injection".to_string(),
            Regex::new(r"(?i)os\.(execute|system)\s*\([^)]*\+").unwrap()
        );

        Self { patterns }
    }

    /// Parse V source code and extract AST information
    pub fn parse(&self, source_file: &SourceFile) -> Result<ParsedAst> {
        let start_time = std::time::Instant::now();
        
        let mut metadata = AstMetadata::default();
        metadata.parse_time_ms = Some(start_time.elapsed().as_millis() as u64);
        
        Ok(ParsedAst {
            tree: None, // No AST tree for pattern-based parsing
            source: source_file.content.clone(),
            language: Some(Language::V),
            parse_errors: Vec::new(),
            metadata,
        })
    }

    /// Analyze V code for security vulnerabilities
    pub fn analyze_security(&self, source_file: &SourceFile) -> Result<Vec<Vulnerability>> {
        let mut vulnerabilities = Vec::new();
        let lines: Vec<&str> = source_file.content.lines().collect();

        for (line_number, line) in lines.iter().enumerate() {
            let line_num = line_number + 1;
            let trimmed_line = line.trim();

            // Skip empty lines and comments
            if trimmed_line.is_empty() || trimmed_line.starts_with("//") {
                continue;
            }

            // Check for unsafe memory access
            if let Some(captures) = self.patterns["unsafe_memory_access"].captures(line) {
                vulnerabilities.push(Vulnerability {
                    id: "V-UNSAFE-001".to_string(),
                    cwe: Some("CWE-119".to_string()),
                    title: "Unsafe Memory Access".to_string(),
                    severity: Severity::High,
                    category: "vulnerability".to_string(),
                    description: "Unsafe block detected - potential memory safety issues".to_string(),
                    file_path: source_file.path.to_string_lossy().to_string(),
                    line_number: line_num,
                    column_start: captures.get(0).map(|m| m.start()).unwrap_or(0),
                    column_end: captures.get(0).map(|m| m.end()).unwrap_or(0),
                    source_code: trimmed_line.to_string(),
                    recommendation: "Review unsafe operations and ensure memory safety".to_string(),
                    owasp: None,
                    references: vec![],
                    confidence: 0.8,
                });
            }

            // Check for unsafe C interop
            if let Some(captures) = self.patterns["unsafe_c_interop"].captures(line) {
                vulnerabilities.push(Vulnerability {
                    id: "V-FFI-001".to_string(),
                    cwe: Some("CWE-829".to_string()),
                    title: "Unsafe C Interop".to_string(),
                    severity: Severity::High,
                    category: "security".to_string(),
                    description: "C interop detected - potential security risks from external code".to_string(),
                    file_path: source_file.path.to_string_lossy().to_string(),
                    line_number: line_num,
                    column_start: captures.get(0).map(|m| m.start()).unwrap_or(0),
                    column_end: captures.get(0).map(|m| m.end()).unwrap_or(0),
                    source_code: trimmed_line.to_string(),
                    recommendation: "Validate C function calls and ensure input sanitization".to_string(),
                    owasp: None,
                    references: vec![],
                    confidence: 0.8,
                });
            }

            // Check for vweb XSS risks
            if let Some(captures) = self.patterns["vweb_xss_risk"].captures(line) {
                vulnerabilities.push(Vulnerability {
                    id: "V-WEB-001".to_string(),
                    cwe: Some("CWE-79".to_string()),
                    title: "Cross-Site Scripting (XSS)".to_string(),
                    severity: Severity::High,
                    category: "security".to_string(),
                    description: "Template interpolation without escaping - XSS risk".to_string(),
                    file_path: source_file.path.to_string_lossy().to_string(),
                    line_number: line_num,
                    column_start: captures.get(0).map(|m| m.start()).unwrap_or(0),
                    column_end: captures.get(0).map(|m| m.end()).unwrap_or(0),
                    source_code: trimmed_line.to_string(),
                    recommendation: "Use proper HTML escaping for user input in templates".to_string(),
                    owasp: None,
                    references: vec![],
                    confidence: 0.8,
                });
            }

            // Check for SQL injection
            if let Some(captures) = self.patterns["vweb_sql_injection"].captures(line) {
                vulnerabilities.push(Vulnerability {
                    id: "V-SQL-001".to_string(),
                    cwe: Some("CWE-89".to_string()),
                    title: "SQL Injection".to_string(),
                    severity: Severity::Critical,
                    category: "security".to_string(),
                    description: "SQL query with string concatenation - SQL injection risk".to_string(),
                    file_path: source_file.path.to_string_lossy().to_string(),
                    line_number: line_num,
                    column_start: captures.get(0).map(|m| m.start()).unwrap_or(0),
                    column_end: captures.get(0).map(|m| m.end()).unwrap_or(0),
                    source_code: trimmed_line.to_string(),
                    recommendation: "Use parameterized queries or prepared statements".to_string(),
                    owasp: None,
                    references: vec![],
                    confidence: 0.9,
                });
            }

            // Check for hardcoded database credentials
            if let Some(captures) = self.patterns["hardcoded_database_credentials"].captures(line) {
                vulnerabilities.push(Vulnerability {
                    id: "V-DB-001".to_string(),
                    cwe: Some("CWE-798".to_string()),
                    title: "Hardcoded Database Credentials".to_string(),
                    severity: Severity::Critical,
                    category: "authentication".to_string(),
                    description: "Hardcoded database credentials detected".to_string(),
                    file_path: source_file.path.to_string_lossy().to_string(),
                    line_number: line_num,
                    column_start: captures.get(0).map(|m| m.start()).unwrap_or(0),
                    column_end: captures.get(0).map(|m| m.end()).unwrap_or(0),
                    source_code: trimmed_line.to_string(),
                    recommendation: "Move database credentials to environment variables".to_string(),
                    owasp: None,
                    references: vec![],
                    confidence: 0.9,
                });
            }

            // Check for unsafe HTTP client usage
            if let Some(captures) = self.patterns["unsafe_http_client"].captures(line) {
                vulnerabilities.push(Vulnerability {
                    id: "V-HTTP-001".to_string(),
                    cwe: Some("CWE-918".to_string()),
                    title: "Server-Side Request Forgery (SSRF)".to_string(),
                    severity: Severity::High,
                    category: "security".to_string(),
                    description: "HTTP request with dynamic URL - SSRF risk".to_string(),
                    file_path: source_file.path.to_string_lossy().to_string(),
                    line_number: line_num,
                    column_start: captures.get(0).map(|m| m.start()).unwrap_or(0),
                    column_end: captures.get(0).map(|m| m.end()).unwrap_or(0),
                    source_code: trimmed_line.to_string(),
                    recommendation: "Validate and whitelist URLs before making HTTP requests".to_string(),
                    owasp: None,
                    references: vec![],
                    confidence: 0.8,
                });
            }

            // Check for insecure TLS
            if let Some(captures) = self.patterns["insecure_tls"].captures(line) {
                vulnerabilities.push(Vulnerability {
                    id: "V-TLS-001".to_string(),
                    cwe: Some("CWE-295".to_string()),
                    title: "Improper Certificate Validation".to_string(),
                    severity: Severity::High,
                    category: "cryptographic".to_string(),
                    description: "TLS certificate verification disabled - man-in-the-middle risk".to_string(),
                    file_path: source_file.path.to_string_lossy().to_string(),
                    line_number: line_num,
                    column_start: captures.get(0).map(|m| m.start()).unwrap_or(0),
                    column_end: captures.get(0).map(|m| m.end()).unwrap_or(0),
                    source_code: trimmed_line.to_string(),
                    recommendation: "Enable proper TLS certificate validation".to_string(),
                    owasp: None,
                    references: vec![],
                    confidence: 0.8,
                });
            }

            // Check for unsafe file operations
            if let Some(captures) = self.patterns["unsafe_file_operations"].captures(line) {
                vulnerabilities.push(Vulnerability {
                    id: "V-FILE-001".to_string(),
                    cwe: Some("CWE-22".to_string()),
                    title: "Path Traversal".to_string(),
                    severity: Severity::High,
                    category: "security".to_string(),
                    description: "File operation with dynamic path - path traversal risk".to_string(),
                    file_path: source_file.path.to_string_lossy().to_string(),
                    line_number: line_num,
                    column_start: captures.get(0).map(|m| m.start()).unwrap_or(0),
                    column_end: captures.get(0).map(|m| m.end()).unwrap_or(0),
                    source_code: trimmed_line.to_string(),
                    recommendation: "Validate and sanitize file paths before operations".to_string(),
                    owasp: None,
                    references: vec![],
                    confidence: 0.8,
                });
            }

            // Check for ignored errors
            if let Some(captures) = self.patterns["ignored_error"].captures(line) {
                vulnerabilities.push(Vulnerability {
                    id: "V-ERROR-001".to_string(),
                    cwe: Some("CWE-252".to_string()),
                    title: "Unchecked Error Condition".to_string(),
                    severity: Severity::Medium,
                    category: "vulnerability".to_string(),
                    description: "Error ignored in or block - may hide failures".to_string(),
                    file_path: source_file.path.to_string_lossy().to_string(),
                    line_number: line_num,
                    column_start: captures.get(0).map(|m| m.start()).unwrap_or(0),
                    column_end: captures.get(0).map(|m| m.end()).unwrap_or(0),
                    source_code: trimmed_line.to_string(),
                    recommendation: "Handle errors appropriately or log for debugging".to_string(),
                    owasp: None,
                    references: vec![],
                    confidence: 0.75,
                });
            }

            // Check for hardcoded secrets
            if let Some(captures) = self.patterns["hardcoded_secrets"].captures(line) {
                vulnerabilities.push(Vulnerability {
                    id: "V-SECRET-001".to_string(),
                    cwe: Some("CWE-798".to_string()),
                    title: "Hardcoded Credentials".to_string(),
                    severity: Severity::Critical,
                    category: "authentication".to_string(),
                    description: "Hardcoded secret detected in V code".to_string(),
                    file_path: source_file.path.to_string_lossy().to_string(),
                    line_number: line_num,
                    column_start: captures.get(0).map(|m| m.start()).unwrap_or(0),
                    column_end: captures.get(0).map(|m| m.end()).unwrap_or(0),
                    source_code: trimmed_line.to_string(),
                    recommendation: "Move secrets to environment variables or secure configuration".to_string(),
                    owasp: None,
                    references: vec![],
                    confidence: 0.9,
                });
            }

            // Check for command injection
            if let Some(captures) = self.patterns["command_injection"].captures(line) {
                vulnerabilities.push(Vulnerability {
                    id: "V-CMD-001".to_string(),
                    cwe: Some("CWE-78".to_string()),
                    title: "Command Injection".to_string(),
                    severity: Severity::Critical,
                    category: "security".to_string(),
                    description: "Command execution with dynamic input - command injection risk".to_string(),
                    file_path: source_file.path.to_string_lossy().to_string(),
                    line_number: line_num,
                    column_start: captures.get(0).map(|m| m.start()).unwrap_or(0),
                    column_end: captures.get(0).map(|m| m.end()).unwrap_or(0),
                    source_code: trimmed_line.to_string(),
                    recommendation: "Validate and sanitize command arguments or use safe alternatives".to_string(),
                    owasp: None,
                    references: vec![],
                    confidence: 0.9,
                });
            }

            // Check for debug code
            if let Some(captures) = self.patterns["debug_code"].captures(line) {
                vulnerabilities.push(Vulnerability {
                    id: "V-DEBUG-001".to_string(),
                    cwe: Some("CWE-489".to_string()),
                    title: "Debug Code in Production".to_string(),
                    severity: Severity::Low,
                    category: "security".to_string(),
                    description: "Debug code detected - may leak sensitive information".to_string(),
                    file_path: source_file.path.to_string_lossy().to_string(),
                    line_number: line_num,
                    column_start: captures.get(0).map(|m| m.start()).unwrap_or(0),
                    column_end: captures.get(0).map(|m| m.end()).unwrap_or(0),
                    source_code: trimmed_line.to_string(),
                    recommendation: "Remove debug statements from production code".to_string(),
                    owasp: None,
                    references: vec![],
                    confidence: 0.7,
                });
            }
        }

        Ok(vulnerabilities)
    }

    /// Check if this is a valid V file
    pub fn is_v_file(file_path: &std::path::Path) -> bool {
        if let Some(ext) = file_path.extension() {
            if let Some(ext_str) = ext.to_str() {
                ext_str.to_lowercase() == "v"
            } else {
                false
            }
        } else {
            false
        }
    }
}

impl Default for VParser {
    fn default() -> Self {
        Self::new()
    }
}

impl Parser for VParser {
    fn parse(&mut self, source_file: &SourceFile) -> Result<ParsedAst> {
        VParser::parse(self, source_file)
    }

    fn language(&self) -> Language {
        Language::V
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::Language;
    use std::path::PathBuf;

    #[test]
    fn test_v_parser_basic() {
        let parser = VParser::new();
        let source_file = SourceFile {
            path: PathBuf::from("test.v"),
            content: r#"
module main

import db.sqlite

fn main() {
    unsafe {
        ptr := voidptr(0)
    }
    api_key := "sk_live_1234567890abcdef"
    println("Debug: ${api_key}")
}
"#.to_string(),
            language: Language::V,
        };

        let result = parser.analyze_security(&source_file);
        assert!(result.is_ok());
        let vulnerabilities = result.unwrap();
        assert!(!vulnerabilities.is_empty());
    }

    #[test]
    fn test_v_sql_injection() {
        let parser = VParser::new();
        let source_file = SourceFile {
            path: PathBuf::from("test.v"),
            content: r#"
fn get_user(db sqlite.DB, user_id string) {
    query := "SELECT * FROM users WHERE id = " + user_id
    db.exec(query)
}
"#.to_string(),
            language: Language::V,
        };

        let result = parser.analyze_security(&source_file);
        assert!(result.is_ok());
        let vulnerabilities = result.unwrap();
        assert!(vulnerabilities.iter().any(|v| v.id == "V-SQL-001"));
    }

    #[test]
    fn test_v_file_detection() {
        assert!(VParser::is_v_file(&PathBuf::from("test.v")));
        assert!(!VParser::is_v_file(&PathBuf::from("test.rs")));
    }
}