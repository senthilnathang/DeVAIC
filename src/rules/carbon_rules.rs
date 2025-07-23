/// Carbon Language Security Rules for DeVAIC
/// 
/// This module defines security rules and patterns for analyzing Carbon language code.
/// These rules complement the Carbon parser to provide comprehensive security analysis.

use crate::{Vulnerability, Severity, Language};
use crate::error::Result;
use std::collections::HashMap;
use regex::Regex;

pub struct CarbonRules {
    patterns: HashMap<String, Regex>,
}

impl CarbonRules {
    pub fn new() -> Self {
        let mut patterns = HashMap::new();
        
        // Memory safety patterns
        patterns.insert(
            "unsafe_block_usage".to_string(),
            Regex::new(r"(?i)unsafe\s*\{").unwrap()
        );
        
        patterns.insert(
            "raw_pointer_access".to_string(),
            Regex::new(r"(?i)\*\s*const\s+|UnsafePointer\s*\(").unwrap()
        );
        
        patterns.insert(
            "unchecked_array_access".to_string(),
            Regex::new(r"(?i)UnsafeArrayAccess\s*\(").unwrap()
        );
        
        // C++ interop security
        patterns.insert(
            "cpp_interop_call".to_string(),
            Regex::new(r"(?i)Cpp\.").unwrap()
        );
        
        patterns.insert(
            "extern_cpp_impl".to_string(),
            Regex::new(r"(?i)extern\s+impl\s+.*as\s+Cpp\.").unwrap()
        );
        
        // Type safety patterns
        patterns.insert(
            "unsafe_type_cast".to_string(),
            Regex::new(r"(?i)UnsafeCast\s*\(|unsafe_cast\s*\(").unwrap()
        );
        
        patterns.insert(
            "bit_cast_operation".to_string(),
            Regex::new(r"(?i)BitCast\s*\(").unwrap()
        );
        
        // Generic programming security
        patterns.insert(
            "unconstrained_generic_function".to_string(),
            Regex::new(r"(?i)fn\s+[A-Za-z_][A-Za-z0-9_]*\s*\[\s*[A-Za-z_][A-Za-z0-9_]*\s*:\s*type\s*\]").unwrap()
        );
        
        patterns.insert(
            "unsafe_template_specialization".to_string(),
            Regex::new(r"(?i)specialization\s+.*unsafe").unwrap()
        );
        
        // API design security
        patterns.insert(
            "public_unsafe_api_function".to_string(),
            Regex::new(r"(?i)api\s+fn\s+[A-Za-z_][A-Za-z0-9_]*\s*\([^)]*\).*unsafe").unwrap()
        );
        
        patterns.insert(
            "mutable_global_variable".to_string(),
            Regex::new(r"(?i)var\s+[A-Za-z_][A-Za-z0-9_]*\s*:\s*.*=").unwrap()
        );
        
        // Package security
        patterns.insert(
            "wildcard_import".to_string(),
            Regex::new(r"(?i)import\s+.*\.\*").unwrap()
        );
        
        patterns.insert(
            "unsafe_library_import".to_string(),
            Regex::new(r"(?i)library\s+.*unsafe").unwrap()
        );
        
        // Error handling patterns
        patterns.insert(
            "unhandled_error_expectation".to_string(),
            Regex::new(r"(?i)\.Expect\s*\(\s*\)|\\.ExpectOk\s*\(\s*\)").unwrap()
        );
        
        patterns.insert(
            "error_suppression".to_string(),
            Regex::new(r"(?i)\.IgnoreError\s*\(\s*\)").unwrap()
        );
        
        // Resource management
        patterns.insert(
            "manual_memory_allocation".to_string(),
            Regex::new(r"(?i)Heap\.New\s*\(|Heap\.Delete\s*\(").unwrap()
        );
        
        patterns.insert(
            "resource_leak_potential".to_string(),
            Regex::new(r"(?i)(File|Socket|Handle)\.Open\s*\(").unwrap()
        );
        
        // Arithmetic safety
        patterns.insert(
            "integer_overflow_operations".to_string(),
            Regex::new(r"(?i)UnsafeAdd\s*\(|UnsafeMul\s*\(|UnsafeSub\s*\(").unwrap()
        );
        
        patterns.insert(
            "division_by_zero_risk".to_string(),
            Regex::new(r"(?i)/(?!\*)").unwrap()
        );
        
        // Hardcoded values
        patterns.insert(
            "hardcoded_credentials".to_string(),
            Regex::new(r#"(?i)(?:password|secret|key|token|api[_-]?key)\s*:\s*StringLiteral\(\".*[^\"]+\".*\)"#).unwrap()
        );
        
        // Concurrency patterns
        patterns.insert(
            "unsafe_shared_access".to_string(),
            Regex::new(r"(?i)UnsafeShared\s*\(|UnsafeMutable\s*\(").unwrap()
        );
        
        patterns.insert(
            "race_condition_potential".to_string(),
            Regex::new(r"(?i)Thread\.Spawn\s*\(").unwrap()
        );
        
        // Network and I/O security
        patterns.insert(
            "unsafe_io_operations".to_string(),
            Regex::new(r"(?i)UnsafeIo\.|RawIo\.").unwrap()
        );
        
        patterns.insert(
            "unencrypted_network_connection".to_string(),
            Regex::new(r"(?i)Http\.Connect\s*\(").unwrap()
        );
        
        // Debug and development patterns
        patterns.insert(
            "debug_print_statements".to_string(),
            Regex::new(r"(?i)Print\s*\(|Debug\.Print\s*\(|Console\.WriteLine\s*\(").unwrap()
        );
        
        patterns.insert(
            "todo_fixme_comments".to_string(),
            Regex::new(r"(?i)Todo\s*\(|__TODO__|FIXME").unwrap()
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

            // Check for unsafe blocks
            if let Some(captures) = self.patterns["unsafe_block_usage"].captures(line) {
                vulnerabilities.push(Vulnerability {
                    id: "CARBON-UNSAFE-001".to_string(),
                    cwe: Some("CWE-119".to_string()),
                    vulnerability_type: "Unsafe Memory Access".to_string(),
                    severity: Severity::High,
                    category: "memory".to_string(),
                    description: "Unsafe block detected - potential memory safety violation".to_string(),
                    file_path: file_path.to_string(),
                    line_number: line_num,
                    column: captures.get(0).map(|m| m.start()).unwrap_or(0),
                    source_code: trimmed_line.to_string(),
                    recommendation: "Review unsafe operations and ensure memory safety guarantees".to_string(),
                });
            }

            // Check for C++ interop risks
            if let Some(captures) = self.patterns["cpp_interop_call"].captures(line) {
                vulnerabilities.push(Vulnerability {
                    id: "CARBON-CPP-001".to_string(),
                    cwe: Some("CWE-829".to_string()),
                    vulnerability_type: "Unsafe C++ Interop".to_string(),
                    severity: Severity::High,
                    category: "interop".to_string(),
                    description: "C++ interop call - potential security risks from legacy code".to_string(),
                    file_path: file_path.to_string(),
                    line_number: line_num,
                    column: captures.get(0).map(|m| m.start()).unwrap_or(0),
                    source_code: trimmed_line.to_string(),
                    recommendation: "Validate C++ function calls and ensure safe boundaries".to_string(),
                });
            }

            // Check for unsafe type casts
            if let Some(captures) = self.patterns["unsafe_type_cast"].captures(line) {
                vulnerabilities.push(Vulnerability {
                    id: "CARBON-CAST-001".to_string(),
                    cwe: Some("CWE-704".to_string()),
                    vulnerability_type: "Unsafe Type Cast".to_string(),
                    severity: Severity::Medium,
                    category: "type_safety".to_string(),
                    description: "Unsafe type cast operation detected".to_string(),
                    file_path: file_path.to_string(),
                    line_number: line_num,
                    column: captures.get(0).map(|m| m.start()).unwrap_or(0),
                    source_code: trimmed_line.to_string(),
                    recommendation: "Use safe casting alternatives or validate cast safety".to_string(),
                });
            }

            // Check for public unsafe APIs
            if let Some(captures) = self.patterns["public_unsafe_api_function"].captures(line) {
                vulnerabilities.push(Vulnerability {
                    id: "CARBON-API-001".to_string(),
                    cwe: Some("CWE-668".to_string()),
                    vulnerability_type: "Unsafe Public API".to_string(),
                    severity: Severity::High,
                    category: "api_design".to_string(),
                    description: "Public API with unsafe operations - security boundary violation".to_string(),
                    file_path: file_path.to_string(),
                    line_number: line_num,
                    column: captures.get(0).map(|m| m.start()).unwrap_or(0),
                    source_code: trimmed_line.to_string(),
                    recommendation: "Ensure public APIs maintain safety invariants".to_string(),
                });
            }

            // Check for unhandled errors
            if let Some(captures) = self.patterns["unhandled_error_expectation"].captures(line) {
                vulnerabilities.push(Vulnerability {
                    id: "CARBON-ERROR-001".to_string(),
                    cwe: Some("CWE-252".to_string()),
                    vulnerability_type: "Unchecked Error Condition".to_string(),
                    severity: Severity::Medium,
                    category: "error_handling".to_string(),
                    description: "Error expectation without proper handling".to_string(),
                    file_path: file_path.to_string(),
                    line_number: line_num,
                    column: captures.get(0).map(|m| m.start()).unwrap_or(0),
                    source_code: trimmed_line.to_string(),
                    recommendation: "Handle errors appropriately or document safety assumptions".to_string(),
                });
            }

            // Check for manual memory management
            if let Some(captures) = self.patterns["manual_memory_allocation"].captures(line) {
                vulnerabilities.push(Vulnerability {
                    id: "CARBON-MEM-001".to_string(),
                    cwe: Some("CWE-401".to_string()),
                    vulnerability_type: "Manual Memory Management".to_string(),
                    severity: Severity::Medium,
                    category: "memory".to_string(),
                    description: "Manual memory management - potential memory leak".to_string(),
                    file_path: file_path.to_string(),
                    line_number: line_num,
                    column: captures.get(0).map(|m| m.start()).unwrap_or(0),
                    source_code: trimmed_line.to_string(),
                    recommendation: "Use RAII or automatic memory management alternatives".to_string(),
                });
            }

            // Check for integer overflow risks
            if let Some(captures) = self.patterns["integer_overflow_operations"].captures(line) {
                vulnerabilities.push(Vulnerability {
                    id: "CARBON-INT-001".to_string(),
                    cwe: Some("CWE-190".to_string()),
                    vulnerability_type: "Integer Overflow".to_string(),
                    severity: Severity::Medium,
                    category: "arithmetic".to_string(),
                    description: "Unsafe arithmetic operation - potential integer overflow".to_string(),
                    file_path: file_path.to_string(),
                    line_number: line_num,
                    column: captures.get(0).map(|m| m.start()).unwrap_or(0),
                    source_code: trimmed_line.to_string(),
                    recommendation: "Use checked arithmetic or validate input ranges".to_string(),
                });
            }

            // Check for hardcoded secrets
            if let Some(captures) = self.patterns["hardcoded_credentials"].captures(line) {
                vulnerabilities.push(Vulnerability {
                    id: "CARBON-SECRET-001".to_string(),
                    cwe: Some("CWE-798".to_string()),
                    vulnerability_type: "Hardcoded Credentials".to_string(),
                    severity: Severity::Critical,
                    category: "authentication".to_string(),
                    description: "Hardcoded credentials detected in Carbon code".to_string(),
                    file_path: file_path.to_string(),
                    line_number: line_num,
                    column: captures.get(0).map(|m| m.start()).unwrap_or(0),
                    source_code: trimmed_line.to_string(),
                    recommendation: "Move secrets to environment variables or secure configuration".to_string(),
                });
            }

            // Check for unsafe concurrency
            if let Some(captures) = self.patterns["unsafe_shared_access"].captures(line) {
                vulnerabilities.push(Vulnerability {
                    id: "CARBON-THREAD-001".to_string(),
                    cwe: Some("CWE-362".to_string()),
                    vulnerability_type: "Race Condition".to_string(),
                    severity: Severity::High,
                    category: "concurrency".to_string(),
                    description: "Unsafe shared data access - potential race condition".to_string(),
                    file_path: file_path.to_string(),
                    line_number: line_num,
                    column: captures.get(0).map(|m| m.start()).unwrap_or(0),
                    source_code: trimmed_line.to_string(),
                    recommendation: "Use safe concurrency primitives".to_string(),
                });
            }

            // Check for unencrypted network connections
            if let Some(captures) = self.patterns["unencrypted_network_connection"].captures(line) {
                vulnerabilities.push(Vulnerability {
                    id: "CARBON-NET-001".to_string(),
                    cwe: Some("CWE-319".to_string()),
                    vulnerability_type: "Cleartext Transmission".to_string(),
                    severity: Severity::Medium,
                    category: "network".to_string(),
                    description: "HTTP connection without TLS - cleartext transmission risk".to_string(),
                    file_path: file_path.to_string(),
                    line_number: line_num,
                    column: captures.get(0).map(|m| m.start()).unwrap_or(0),
                    source_code: trimmed_line.to_string(),
                    recommendation: "Use HTTPS/TLS for secure network communication".to_string(),
                });
            }

            // Check for debug code
            if let Some(captures) = self.patterns["debug_print_statements"].captures(line) {
                vulnerabilities.push(Vulnerability {
                    id: "CARBON-DEBUG-001".to_string(),
                    cwe: Some("CWE-489".to_string()),
                    vulnerability_type: "Debug Code in Production".to_string(),
                    severity: Severity::Low,
                    category: "information_disclosure".to_string(),
                    description: "Debug code detected - may leak sensitive information".to_string(),
                    file_path: file_path.to_string(),
                    line_number: line_num,
                    column: captures.get(0).map(|m| m.start()).unwrap_or(0),
                    source_code: trimmed_line.to_string(),
                    recommendation: "Remove debug statements from production code".to_string(),
                });
            }

            // Check for TODO/FIXME comments
            if let Some(captures) = self.patterns["todo_fixme_comments"].captures(line) {
                vulnerabilities.push(Vulnerability {
                    id: "CARBON-TODO-001".to_string(),
                    cwe: Some("CWE-489".to_string()),
                    vulnerability_type: "Incomplete Implementation".to_string(),
                    severity: Severity::Medium,
                    category: "development".to_string(),
                    description: "TODO/FIXME comment - incomplete implementation".to_string(),
                    file_path: file_path.to_string(),
                    line_number: line_num,
                    column: captures.get(0).map(|m| m.start()).unwrap_or(0),
                    source_code: trimmed_line.to_string(),
                    recommendation: "Complete implementation before production deployment".to_string(),
                });
            }
        }

        Ok(vulnerabilities)
    }

    pub fn get_language() -> Language {
        Language::Carbon
    }
}

impl Default for CarbonRules {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_carbon_unsafe_block() {
        let rules = CarbonRules::new();
        let code = r#"
            fn UnsafeFunction() -> i32 {
                unsafe {
                    return UnsafeCast(i32, ptr);
                }
            }
        "#;
        
        let vulnerabilities = rules.analyze(code, "test.carbon").unwrap();
        assert!(vulnerabilities.iter().any(|v| v.id == "CARBON-UNSAFE-001"));
    }

    #[test]
    fn test_carbon_cpp_interop() {
        let rules = CarbonRules::new();
        let code = r#"
            fn CallCppFunction() {
                Cpp.unsafe_legacy_function();
            }
        "#;
        
        let vulnerabilities = rules.analyze(code, "test.carbon").unwrap();
        assert!(vulnerabilities.iter().any(|v| v.id == "CARBON-CPP-001"));
    }

    #[test]
    fn test_carbon_hardcoded_credentials() {
        let rules = CarbonRules::new();
        let code = r#"
            var global_secret: StringLiteral = "api_key_12345_secret";
        "#;
        
        let vulnerabilities = rules.analyze(code, "test.carbon").unwrap();
        assert!(vulnerabilities.iter().any(|v| v.id == "CARBON-SECRET-001"));
    }
}