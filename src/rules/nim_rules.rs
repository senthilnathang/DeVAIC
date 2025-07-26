/// Nim Language Security Rules for DeVAIC
/// 
/// This module defines security rules and patterns for analyzing Nim language code.
/// These rules complement the Nim parser to provide comprehensive security analysis.

use crate::{Vulnerability, Severity, Language};
use crate::error::Result;
use std::collections::HashMap;
use regex::Regex;

pub struct NimRules {
    patterns: HashMap<String, Regex>,
}

impl NimRules {
    pub fn new() -> Self {
        let mut patterns = HashMap::new();
        
        // Memory safety patterns
        patterns.insert(
            "unsafe_memory_operations".to_string(),
            Regex::new(r"(?i)\bunsafeAddr\b|\bcast\[|\bunsafeNew\b").unwrap()
        );
        
        patterns.insert(
            "manual_memory_management".to_string(),
            Regex::new(r"(?i)\balloc\b|\bdealloc\b|\brealloc\b").unwrap()
        );
        
        patterns.insert(
            "pointer_arithmetic".to_string(),
            Regex::new(r"(?i)ptr\s+[A-Za-z_][A-Za-z0-9_]*\s*[\+\-]|\bptr\b.*[\+\-]").unwrap()
        );
        
        // FFI security patterns
        patterns.insert(
            "c_interop_pragmas".to_string(),
            Regex::new(r"(?i)\{\.(?:importc|exportc|cdecl|stdcall)\.\}").unwrap()
        );
        
        patterns.insert(
            "external_library_binding".to_string(),
            Regex::new(r"(?i)\{\.(?:dynlib|link)\.\}").unwrap()
        );
        
        patterns.insert(
            "unsafe_c_header_include".to_string(),
            Regex::new(r#"(?i)\{\.header:\s*".*\.h"\s*\.\}"#).unwrap()
        );
        
        // Macro system security
        patterns.insert(
            "unsafe_macro_definition".to_string(),
            Regex::new(r"(?i)macro\s+[A-Za-z_][A-Za-z0-9_]*.*=\s*quote").unwrap()
        );
        
        patterns.insert(
            "compile_time_code_execution".to_string(),
            Regex::new(r#"(?i)\{\.compile:\s*".*"\.\}"#).unwrap()
        );
        
        patterns.insert(
            "untyped_template_parameter".to_string(),
            Regex::new(r"(?i)template\s+[A-Za-z_][A-Za-z0-9_]*.*untyped").unwrap()
        );
        
        // Threading and concurrency
        patterns.insert(
            "unsafe_threading_pragma".to_string(),
            Regex::new(r"(?i)\{\.thread\.\}|\{\.gcsafe\.\}").unwrap()
        );
        
        patterns.insert(
            "global_shared_state".to_string(),
            Regex::new(r"(?i)var\s+[A-Za-z_][A-Za-z0-9_]*\s*\{\.global\.\}").unwrap()
        );
        
        patterns.insert(
            "unsafe_channel_operations".to_string(),
            Regex::new(r"(?i)Channel\[[^\]]*\]\.(?:send|recv)\s*\(").unwrap()
        );
        
        // Error handling patterns
        patterns.insert(
            "ignored_exception_handling".to_string(),
            Regex::new(r"(?i)try:\s*.*except\s*:\s*discard").unwrap()
        );
        
        patterns.insert(
            "unsafe_assertion_failure".to_string(),
            Regex::new(r"(?i)assert\s+false").unwrap()
        );
        
        patterns.insert(
            "unchecked_option_access".to_string(),
            Regex::new(r"(?i)\.get\s*\(\s*\)").unwrap()
        );
        
        // File system operations
        patterns.insert(
            "unsafe_file_operations".to_string(),
            Regex::new(r"(?i)(?:open|readFile|writeFile|removeFile)\s*\([^)]*&").unwrap()
        );
        
        patterns.insert(
            "path_traversal_vulnerability".to_string(),
            Regex::new(r"(?i)\.\.[\\/]").unwrap()
        );
        
        patterns.insert(
            "temp_file_race_condition".to_string(),
            Regex::new(r"(?i)getTempDir\s*\(\s*\)|createTempFile\s*\(").unwrap()
        );
        
        // Network security
        patterns.insert(
            "insecure_network_socket".to_string(),
            Regex::new(r"(?i)newSocket\s*\([^)]*verify\s*=\s*false").unwrap()
        );
        
        patterns.insert(
            "unencrypted_network_communication".to_string(),
            Regex::new(r"(?i)net\.(connect|listen)\s*\(").unwrap()
        );
        
        // String and buffer operations
        patterns.insert(
            "buffer_overflow_risk".to_string(),
            Regex::new(r"(?i)copyMem\s*\(|moveMem\s*\(|zeroMem\s*\(").unwrap()
        );
        
        patterns.insert(
            "unsafe_string_operations".to_string(),
            Regex::new(r"(?i)cstring\s*\([^)]*\)\.(?:len|isNil)").unwrap()
        );
        
        // Hardcoded secrets and credentials
        patterns.insert(
            "hardcoded_secrets".to_string(),
            Regex::new(r#"(?i)(?:password|secret|key|token|api[_-]?key)\s*=\s*"[^"]{8,}""#).unwrap()
        );
        
        patterns.insert(
            "database_connection_string".to_string(),
            Regex::new(r#"(?i)(?:host|server|database|user|password)\s*=\s*"[^"]+""#).unwrap()
        );
        
        // Debug and development patterns
        patterns.insert(
            "debug_output_statements".to_string(),
            Regex::new(r"(?i)(?:echo|debugEcho|dump)\s*\(").unwrap()
        );
        
        patterns.insert(
            "debug_pragma_usage".to_string(),
            Regex::new(r"(?i)\{\.(?:debugger|lineTrace)\.\}").unwrap()
        );
        
        // Unsafe pragmas and compiler directives
        patterns.insert(
            "disabled_safety_checks".to_string(),
            Regex::new(r"(?i)\{\.(?:checks:off|optimization:none|boundchecks:off)\.\}").unwrap()
        );
        
        patterns.insert(
            "unsafe_code_generation".to_string(),
            Regex::new(r#"(?i)\{\.emit:\s*".*"\s*\.\}"#).unwrap()
        );
        
        // Command execution and system calls
        patterns.insert(
            "command_injection_risk".to_string(),
            Regex::new(r"(?i)(?:execCmd|execProcess|startProcess)\s*\([^)]*&").unwrap()
        );
        
        patterns.insert(
            "system_call_without_validation".to_string(),
            Regex::new(r"(?i)os\.(?:execv|system)\s*\(").unwrap()
        );
        
        // Serialization and deserialization security
        patterns.insert(
            "unsafe_deserialization".to_string(),
            Regex::new(r"(?i)(?:marshal|unmarshal|parseJson|loads)\s*\(").unwrap()
        );
        
        patterns.insert(
            "pickle_deserialization".to_string(),
            Regex::new(r"(?i)pickle\.(?:load|loads)\s*\(").unwrap()
        );
        
        // Generic programming security
        patterns.insert(
            "unconstrained_generic_type".to_string(),
            Regex::new(r"(?i)proc\s+[A-Za-z_][A-Za-z0-9_]*\s*\[\s*[A-Za-z_][A-Za-z0-9_]*\s*\]").unwrap()
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
            if trimmed_line.is_empty() || trimmed_line.starts_with("#") {
                continue;
            }

            // Check for unsafe memory operations
            if let Some(captures) = self.patterns["unsafe_memory_operations"].captures(line) {
                vulnerabilities.push(Vulnerability {
id: "NIM-MEM-001".to_string(),
                    cwe: Some("CWE-119".to_string()),
                    title: "Unsafe Memory Access".to_string(),
                    severity: Severity::High,
                    category: "memory".to_string(),
                    description: "Unsafe memory operation detected - potential memory corruption".to_string(),
                    file_path: file_path.to_string(),
                    line_number: line_num,
                    column_start: captures.get(0).map(|m| m.start()).unwrap_or(0),
                    column_end: captures.get(0).map(|m| m.end()).unwrap_or(0),
                    source_code: trimmed_line.to_string(),
                    recommendation: "Use safe memory operations or add proper bounds checking".to_string(),
                    owasp: None,
                    references: vec![],
                    confidence: 0.8,
                });
            }

            // Check for C interop pragmas
            if let Some(captures) = self.patterns["c_interop_pragmas"].captures(line) {
                vulnerabilities.push(Vulnerability {
id: "NIM-FFI-001".to_string(),
                    cwe: Some("CWE-829".to_string()),
                    title: "Unsafe C Interop".to_string(),
                    severity: Severity::High,
                    category: "interop".to_string(),
                    description: "C interop pragma detected - potential security risks from external code".to_string(),
                    file_path: file_path.to_string(),
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

            // Check for unsafe macro definitions
            if let Some(captures) = self.patterns["unsafe_macro_definition"].captures(line) {
                vulnerabilities.push(Vulnerability {
id: "NIM-MACRO-001".to_string(),
                    cwe: Some("CWE-94".to_string()),
                    title: "Code Injection via Macros".to_string(),
                    severity: Severity::Medium,
                    category: "code_injection".to_string(),
                    description: "Unsafe macro definition - potential code injection risk".to_string(),
                    file_path: file_path.to_string(),
                    line_number: line_num,
                    column_start: captures.get(0).map(|m| m.start()).unwrap_or(0),
                    column_end: captures.get(0).map(|m| m.end()).unwrap_or(0),
                    source_code: trimmed_line.to_string(),
                    recommendation: "Validate macro inputs and use typed alternatives".to_string(),
                    owasp: None,
                    references: vec![],
                    confidence: 0.75,
                });
            }

            // Check for unsafe threading pragmas
            if let Some(captures) = self.patterns["unsafe_threading_pragma"].captures(line) {
                vulnerabilities.push(Vulnerability {
id: "NIM-THREAD-001".to_string(),
                    cwe: Some("CWE-362".to_string()),
                    title: "Race Condition".to_string(),
                    severity: Severity::High,
                    category: "concurrency".to_string(),
                    description: "Threading pragma detected - potential race condition risk".to_string(),
                    file_path: file_path.to_string(),
                    line_number: line_num,
                    column_start: captures.get(0).map(|m| m.start()).unwrap_or(0),
                    column_end: captures.get(0).map(|m| m.end()).unwrap_or(0),
                    source_code: trimmed_line.to_string(),
                    recommendation: "Use proper synchronization mechanisms".to_string(),
                    owasp: None,
                    references: vec![],
                    confidence: 0.8,
                });
            }

            // Check for unsafe file operations
            if let Some(captures) = self.patterns["unsafe_file_operations"].captures(line) {
                vulnerabilities.push(Vulnerability {
id: "NIM-FILE-001".to_string(),
                    cwe: Some("CWE-22".to_string()),
                    title: "Path Traversal".to_string(),
                    severity: Severity::High,
                    category: "file_system".to_string(),
                    description: "File operation with dynamic path - path traversal risk".to_string(),
                    file_path: file_path.to_string(),
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

            // Check for buffer overflow risks
            if let Some(captures) = self.patterns["buffer_overflow_risk"].captures(line) {
                vulnerabilities.push(Vulnerability {
id: "NIM-BUF-001".to_string(),
                    cwe: Some("CWE-120".to_string()),
                    title: "Buffer Overflow".to_string(),
                    severity: Severity::High,
                    category: "buffer".to_string(),
                    description: "Memory copy operation - potential buffer overflow".to_string(),
                    file_path: file_path.to_string(),
                    line_number: line_num,
                    column_start: captures.get(0).map(|m| m.start()).unwrap_or(0),
                    column_end: captures.get(0).map(|m| m.end()).unwrap_or(0),
                    source_code: trimmed_line.to_string(),
                    recommendation: "Use safe memory operations with bounds checking".to_string(),
                    owasp: None,
                    references: vec![],
                    confidence: 0.8,
                });
            }

            // Check for hardcoded secrets
            if let Some(captures) = self.patterns["hardcoded_secrets"].captures(line) {
                vulnerabilities.push(Vulnerability {
id: "NIM-SECRET-001".to_string(),
                    cwe: Some("CWE-798".to_string()),
                    title: "Hardcoded Credentials".to_string(),
                    severity: Severity::Critical,
                    category: "authentication".to_string(),
                    description: "Hardcoded credentials detected in Nim code".to_string(),
                    file_path: file_path.to_string(),
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

            // Check for command injection risks
            if let Some(captures) = self.patterns["command_injection_risk"].captures(line) {
                vulnerabilities.push(Vulnerability {
id: "NIM-CMD-001".to_string(),
                    cwe: Some("CWE-78".to_string()),
                    title: "Command Injection".to_string(),
                    severity: Severity::Critical,
                    category: "command_execution".to_string(),
                    description: "Command execution with dynamic input - injection risk".to_string(),
                    file_path: file_path.to_string(),
                    line_number: line_num,
                    column_start: captures.get(0).map(|m| m.start()).unwrap_or(0),
                    column_end: captures.get(0).map(|m| m.end()).unwrap_or(0),
                    source_code: trimmed_line.to_string(),
                    recommendation: "Validate and sanitize command arguments".to_string(),
                    owasp: None,
                    references: vec![],
                    confidence: 0.9,
                });
            }

            // Check for disabled safety checks
            if let Some(captures) = self.patterns["disabled_safety_checks"].captures(line) {
                vulnerabilities.push(Vulnerability {
id: "NIM-PRAGMA-001".to_string(),
                    cwe: Some("CWE-665".to_string()),
                    title: "Unsafe Configuration".to_string(),
                    severity: Severity::Medium,
                    category: "configuration".to_string(),
                    description: "Safety checks disabled - removes important protections".to_string(),
                    file_path: file_path.to_string(),
                    line_number: line_num,
                    column_start: captures.get(0).map(|m| m.start()).unwrap_or(0),
                    column_end: captures.get(0).map(|m| m.end()).unwrap_or(0),
                    source_code: trimmed_line.to_string(),
                    recommendation: "Enable safety checks in production code".to_string(),
                    owasp: None,
                    references: vec![],
                    confidence: 0.75,
                });
            }

            // Check for ignored exception handling
            if let Some(captures) = self.patterns["ignored_exception_handling"].captures(line) {
                vulnerabilities.push(Vulnerability {
id: "NIM-ERROR-001".to_string(),
                    cwe: Some("CWE-252".to_string()),
                    title: "Unchecked Error Condition".to_string(),
                    severity: Severity::Medium,
                    category: "error_handling".to_string(),
                    description: "Exception ignored - may hide failures".to_string(),
                    file_path: file_path.to_string(),
                    line_number: line_num,
                    column_start: captures.get(0).map(|m| m.start()).unwrap_or(0),
                    column_end: captures.get(0).map(|m| m.end()).unwrap_or(0),
                    source_code: trimmed_line.to_string(),
                    recommendation: "Handle exceptions appropriately or log for debugging".to_string(),
                    owasp: None,
                    references: vec![],
                    confidence: 0.75,
                });
            }

            // Check for unsafe deserialization
            if let Some(captures) = self.patterns["unsafe_deserialization"].captures(line) {
                vulnerabilities.push(Vulnerability {
id: "NIM-DESER-001".to_string(),
                    cwe: Some("CWE-502".to_string()),
                    title: "Unsafe Deserialization".to_string(),
                    severity: Severity::High,
                    category: "serialization".to_string(),
                    description: "Unsafe deserialization operation detected".to_string(),
                    file_path: file_path.to_string(),
                    line_number: line_num,
                    column_start: captures.get(0).map(|m| m.start()).unwrap_or(0),
                    column_end: captures.get(0).map(|m| m.end()).unwrap_or(0),
                    source_code: trimmed_line.to_string(),
                    recommendation: "Validate and sanitize deserialized data".to_string(),
                    owasp: None,
                    references: vec![],
                    confidence: 0.8,
                });
            }

            // Check for debug output statements
            if let Some(captures) = self.patterns["debug_output_statements"].captures(line) {
                vulnerabilities.push(Vulnerability {
id: "NIM-DEBUG-001".to_string(),
                    cwe: Some("CWE-489".to_string()),
                    title: "Debug Code in Production".to_string(),
                    severity: Severity::Low,
                    category: "information_disclosure".to_string(),
                    description: "Debug output statement detected - may leak sensitive information".to_string(),
                    file_path: file_path.to_string(),
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

    pub fn get_language() -> Language {
        Language::Nim
    }
}

impl Default for NimRules {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_nim_unsafe_memory() {
        let rules = NimRules::new();
        let code = r#"
            proc unsafeFunction() =
                var ptr = cast[ptr int](unsafeAddr(someVar))
        "#;
        
        let vulnerabilities = rules.analyze(code, "test.nim").unwrap();
        assert!(vulnerabilities.iter().any(|v| v.id == "NIM-MEM-001"));
    }

    #[test]
    fn test_nim_c_interop() {
        let rules = NimRules::new();
        let code = r#"
            proc cFunction() {.importc.} =
                discard
        "#;
        
        let vulnerabilities = rules.analyze(code, "test.nim").unwrap();
        assert!(vulnerabilities.iter().any(|v| v.id == "NIM-FFI-001"));
    }

    #[test]
    fn test_nim_hardcoded_secrets() {
        let rules = NimRules::new();
        let code = r#"
            let secret = "api_key_12345_secret"
        "#;
        
        let vulnerabilities = rules.analyze(code, "test.nim").unwrap();
        assert!(vulnerabilities.iter().any(|v| v.id == "NIM-SECRET-001"));
    }
}