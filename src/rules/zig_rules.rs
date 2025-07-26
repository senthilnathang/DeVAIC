/// Zig Security Rules for DeVAIC
/// 
/// This module defines security rules and patterns for analyzing Zig code.
/// These rules complement the Zig parser to provide comprehensive security analysis.

use crate::{Vulnerability, Severity, Language};
use crate::error::Result;
use std::collections::HashMap;
use regex::Regex;

pub struct ZigRules {
    patterns: HashMap<String, Regex>,
}

impl ZigRules {
    pub fn new() -> Self {
        let mut patterns = HashMap::new();
        
        // Memory safety patterns
        patterns.insert(
            "unsafe_pointer_cast".to_string(),
            Regex::new(r"(?i)@ptrCast\s*\(").unwrap()
        );
        
        patterns.insert(
            "undefined_behavior".to_string(),
            Regex::new(r"(?i)\bundefined\b").unwrap()
        );
        
        patterns.insert(
            "memory_leak_potential".to_string(),
            Regex::new(r"(?i)allocator\.(alloc|create)\s*\(").unwrap()
        );
        
        // Integer safety patterns
        patterns.insert(
            "wrapping_arithmetic".to_string(),
            Regex::new(r"(?i)[\+\-\*]%").unwrap()
        );
        
        patterns.insert(
            "unchecked_integer_conversion".to_string(),
            Regex::new(r"(?i)@intCast\s*\(").unwrap()
        );
        
        // Error handling patterns
        patterns.insert(
            "ignored_error_union".to_string(),
            Regex::new(r"(?i)catch\s*\|[^|]*\|\s*\{\s*\}").unwrap()
        );
        
        patterns.insert(
            "unreachable_panic".to_string(),
            Regex::new(r"(?i)\bunreachable\b").unwrap()
        );
        
        // Unsafe operations
        patterns.insert(
            "raw_memory_access".to_string(),
            Regex::new(r"(?i)@ptrToInt|@intToPtr").unwrap()
        );
        
        patterns.insert(
            "bit_manipulation".to_string(),
            Regex::new(r"(?i)@bitCast\s*\(").unwrap()
        );
        
        // C interop security
        patterns.insert(
            "c_import_usage".to_string(),
            Regex::new(r"(?i)@cImport\s*\(").unwrap()
        );
        
        patterns.insert(
            "extern_function_call".to_string(),
            Regex::new(r"(?i)extern\s+fn").unwrap()
        );
        
        // Debug and development
        patterns.insert(
            "debug_print_statements".to_string(),
            Regex::new(r"(?i)std\.debug\.(?:print|warn|panic)").unwrap()
        );
        
        // Hardcoded values
        patterns.insert(
            "hardcoded_credentials".to_string(),
            Regex::new(r#"(?i)(?:password|secret|key|token)\s*=\s*"[^"]{8,}""#).unwrap()
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

            // Check for unsafe pointer casts
            if let Some(captures) = self.patterns["unsafe_pointer_cast"].captures(line) {
                vulnerabilities.push(Vulnerability {
id: "ZIG-PTR-001".to_string(),
                    cwe: Some("CWE-119".to_string()),
                    title: "Unsafe Pointer Cast".to_string(),
                    severity: Severity::High,
                    category: "memory".to_string(),
                    description: "Unsafe pointer cast operation detected".to_string(),
                    file_path: file_path.to_string(),
                    line_number: line_num,
                    column_start: captures.get(0).map(|m| m.start()).unwrap_or(0),
                    column_end: captures.get(0).map(|m| m.end()).unwrap_or(0),
                    source_code: trimmed_line.to_string(),
                    recommendation: "Validate pointer cast safety and consider safe alternatives".to_string(),
                    owasp: None,
                    references: vec![],
                    confidence: 0.8,
                });
            }

            // Check for undefined behavior
            if let Some(captures) = self.patterns["undefined_behavior"].captures(line) {
                vulnerabilities.push(Vulnerability {
id: "ZIG-UB-001".to_string(),
                    cwe: Some("CWE-758".to_string()),
                    title: "Undefined Behavior".to_string(),
                    severity: Severity::Critical,
                    category: "safety".to_string(),
                    description: "Undefined behavior usage detected".to_string(),
                    file_path: file_path.to_string(),
                    line_number: line_num,
                    column_start: captures.get(0).map(|m| m.start()).unwrap_or(0),
                    column_end: captures.get(0).map(|m| m.end()).unwrap_or(0),
                    source_code: trimmed_line.to_string(),
                    recommendation: "Replace undefined behavior with safe error handling".to_string(),
                    owasp: None,
                    references: vec![],
                    confidence: 0.9,
                });
            }

            // Check for potential memory leaks
            if let Some(captures) = self.patterns["memory_leak_potential"].captures(line) {
                vulnerabilities.push(Vulnerability {
id: "ZIG-MEM-001".to_string(),
                    cwe: Some("CWE-401".to_string()),
                    title: "Memory Leak".to_string(),
                    severity: Severity::Medium,
                    category: "memory".to_string(),
                    description: "Potential memory leak - allocation without cleanup".to_string(),
                    file_path: file_path.to_string(),
                    line_number: line_num,
                    column_start: captures.get(0).map(|m| m.start()).unwrap_or(0),
                    column_end: captures.get(0).map(|m| m.end()).unwrap_or(0),
                    source_code: trimmed_line.to_string(),
                    recommendation: "Use defer or errdefer to ensure memory cleanup".to_string(),
                    owasp: None,
                    references: vec![],
                    confidence: 0.75,
                });
            }

            // Check for wrapping arithmetic
            if let Some(captures) = self.patterns["wrapping_arithmetic"].captures(line) {
                vulnerabilities.push(Vulnerability {
id: "ZIG-INT-001".to_string(),
                    cwe: Some("CWE-190".to_string()),
                    title: "Integer Overflow".to_string(),
                    severity: Severity::Medium,
                    category: "arithmetic".to_string(),
                    description: "Wrapping arithmetic operation - potential overflow".to_string(),
                    file_path: file_path.to_string(),
                    line_number: line_num,
                    column_start: captures.get(0).map(|m| m.start()).unwrap_or(0),
                    column_end: captures.get(0).map(|m| m.end()).unwrap_or(0),
                    source_code: trimmed_line.to_string(),
                    recommendation: "Use checked arithmetic or validate input ranges".to_string(),
                    owasp: None,
                    references: vec![],
                    confidence: 0.75,
                });
            }

            // Check for ignored error unions
            if let Some(captures) = self.patterns["ignored_error_union"].captures(line) {
                vulnerabilities.push(Vulnerability {
id: "ZIG-ERR-001".to_string(),
                    cwe: Some("CWE-252".to_string()),
                    title: "Ignored Error".to_string(),
                    severity: Severity::Medium,
                    category: "error_handling".to_string(),
                    description: "Error union result ignored in catch block".to_string(),
                    file_path: file_path.to_string(),
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

            // Check for C imports
            if let Some(captures) = self.patterns["c_import_usage"].captures(line) {
                vulnerabilities.push(Vulnerability {
id: "ZIG-C-001".to_string(),
                    cwe: Some("CWE-829".to_string()),
                    title: "Unsafe C Interop".to_string(),
                    severity: Severity::High,
                    category: "interop".to_string(),
                    description: "C import detected - external code security risk".to_string(),
                    file_path: file_path.to_string(),
                    line_number: line_num,
                    column_start: captures.get(0).map(|m| m.start()).unwrap_or(0),
                    column_end: captures.get(0).map(|m| m.end()).unwrap_or(0),
                    source_code: trimmed_line.to_string(),
                    recommendation: "Validate C library security and sanitize inputs".to_string(),
                    owasp: None,
                    references: vec![],
                    confidence: 0.8,
                });
            }

            // Check for debug statements
            if let Some(captures) = self.patterns["debug_print_statements"].captures(line) {
                vulnerabilities.push(Vulnerability {
id: "ZIG-DEBUG-001".to_string(),
                    cwe: Some("CWE-489".to_string()),
                    title: "Debug Code".to_string(),
                    severity: Severity::Low,
                    category: "information_disclosure".to_string(),
                    description: "Debug print statement detected".to_string(),
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

            // Check for hardcoded credentials
            if let Some(captures) = self.patterns["hardcoded_credentials"].captures(line) {
                vulnerabilities.push(Vulnerability {
id: "ZIG-CRED-001".to_string(),
                    cwe: Some("CWE-798".to_string()),
                    title: "Hardcoded Credentials".to_string(),
                    severity: Severity::Critical,
                    category: "authentication".to_string(),
                    description: "Hardcoded credentials detected".to_string(),
                    file_path: file_path.to_string(),
                    line_number: line_num,
                    column_start: captures.get(0).map(|m| m.start()).unwrap_or(0),
                    column_end: captures.get(0).map(|m| m.end()).unwrap_or(0),
                    source_code: trimmed_line.to_string(),
                    recommendation: "Move credentials to environment variables or secure storage".to_string(),
                    owasp: None,
                    references: vec![],
                    confidence: 0.9,
                });
            }
        }

        Ok(vulnerabilities)
    }

    pub fn get_language() -> Language {
        Language::Zig
    }
}

impl Default for ZigRules {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_zig_unsafe_pointer_cast() {
        let rules = ZigRules::new();
        let code = r#"
            const ptr = @ptrCast(*u32, some_address);
        "#;
        
        let vulnerabilities = rules.analyze(code, "test.zig").unwrap();
        assert!(vulnerabilities.iter().any(|v| v.id == "ZIG-PTR-001"));
    }

    #[test]
    fn test_zig_undefined_behavior() {
        let rules = ZigRules::new();
        let code = r#"
            const value = undefined;
        "#;
        
        let vulnerabilities = rules.analyze(code, "test.zig").unwrap();
        assert!(vulnerabilities.iter().any(|v| v.id == "ZIG-UB-001"));
    }

    #[test]
    fn test_zig_memory_leak() {
        let rules = ZigRules::new();
        let code = r#"
            const memory = allocator.alloc(u8, 1024);
            // Missing defer allocator.free(memory);
        "#;
        
        let vulnerabilities = rules.analyze(code, "test.zig").unwrap();
        assert!(vulnerabilities.iter().any(|v| v.id == "ZIG-MEM-001"));
    }
}