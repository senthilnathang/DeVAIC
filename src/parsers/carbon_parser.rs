/// Carbon Language Parser for DeVAIC
/// 
/// This module provides parsing support for Carbon programming language files.
/// Carbon is an experimental successor to C++ with modern language design,
/// memory safety, and performance-oriented features.
/// 
/// Security concerns for Carbon include:
/// - Memory safety with modern C++ interoperability
/// - Type safety and bounds checking
/// - Safe/unsafe boundary management
/// - Generic programming security
/// - Package and API design security
/// - Migration from C++ security considerations

use crate::parsers::{SourceFile, ParsedAst, AstMetadata, Parser};
use crate::{Language, Vulnerability, Severity};
use crate::error::Result;
use std::collections::HashMap;
use regex::Regex;

/// Carbon-specific parser implementation
pub struct CarbonParser {
    /// Common Carbon security patterns for analysis
    patterns: HashMap<String, Regex>,
}

impl CarbonParser {
    pub fn new() -> Self {
        let mut patterns = HashMap::new();
        
        // Initialize Carbon security patterns
        
        // Memory safety patterns
        patterns.insert(
            "unsafe_block".to_string(),
            Regex::new(r"(?i)unsafe\s*\{").unwrap()
        );
        
        patterns.insert(
            "raw_pointer_usage".to_string(),
            Regex::new(r"(?i)\*\s*const\s+|UnsafePointer\s*\(").unwrap()
        );
        
        patterns.insert(
            "unchecked_array_access".to_string(),
            Regex::new(r"(?i)UnsafeArrayAccess\s*\(").unwrap()
        );
        
        // C++ interop security
        patterns.insert(
            "cpp_interop_unsafe".to_string(),
            Regex::new(r"(?i)Cpp\.").unwrap()
        );
        
        patterns.insert(
            "extern_cpp".to_string(),
            Regex::new(r"(?i)extern\s+impl\s+.*as\s+Cpp\.").unwrap()
        );
        
        // Type safety patterns
        patterns.insert(
            "unsafe_cast".to_string(),
            Regex::new(r"(?i)UnsafeCast\s*\(|unsafe_cast\s*\(").unwrap()
        );
        
        patterns.insert(
            "bit_cast_usage".to_string(),
            Regex::new(r"(?i)BitCast\s*\(").unwrap()
        );
        
        // Generic programming security
        patterns.insert(
            "unconstrained_generic".to_string(),
            Regex::new(r"(?i)fn\s+[A-Za-z_][A-Za-z0-9_]*\s*\[\s*[A-Za-z_][A-Za-z0-9_]*\s*:\s*type\s*\]").unwrap()
        );
        
        patterns.insert(
            "unsafe_template_specialization".to_string(),
            Regex::new(r"(?i)specialization\s+.*unsafe").unwrap()
        );
        
        // API design security
        patterns.insert(
            "public_unsafe_api".to_string(),
            Regex::new(r"(?i)api\s+fn\s+[A-Za-z_][A-Za-z0-9_]*\s*\([^)]*\)\s*.*unsafe").unwrap()
        );
        
        patterns.insert(
            "mutable_global_state".to_string(),
            Regex::new(r"(?i)var\s+[A-Za-z_][A-Za-z0-9_]*\s*:\s*.*=").unwrap()
        );
        
        // Package security patterns
        patterns.insert(
            "package_import_wildcard".to_string(),
            Regex::new(r"(?i)import\s+.*\.\*").unwrap()
        );
        
        patterns.insert(
            "library_import_unsafe".to_string(),
            Regex::new(r"(?i)library\s+.*unsafe").unwrap()
        );
        
        // Error handling patterns
        patterns.insert(
            "unhandled_error".to_string(),
            Regex::new(r"(?i)\.Expect\s*\(\s*\)|\.ExpectOk\s*\(\s*\)").unwrap()
        );
        
        patterns.insert(
            "error_suppression".to_string(),
            Regex::new(r"(?i)\.IgnoreError\s*\(\s*\)").unwrap()
        );
        
        // Resource management
        patterns.insert(
            "manual_memory_management".to_string(),
            Regex::new(r"(?i)Heap\.New\s*\(|Heap\.Delete\s*\(").unwrap()
        );
        
        patterns.insert(
            "resource_leak_risk".to_string(),
            Regex::new(r"(?i)(File|Socket|Handle)\.Open\s*\(").unwrap()
        );
        
        // Arithmetic safety
        patterns.insert(
            "integer_overflow_risk".to_string(),
            Regex::new(r"(?i)UnsafeAdd\s*\(|UnsafeMul\s*\(|UnsafeSub\s*\(").unwrap()
        );
        
        patterns.insert(
            "division_by_zero".to_string(),
            Regex::new(r"(?i)\s/\s").unwrap()
        );
        
        // Hardcoded values
        patterns.insert(
            "hardcoded_secrets".to_string(),
            Regex::new(r#"(?i)(?:password|secret|key|token|api[_-]?key)\s*:\s*StringLiteral\(".*[^"]+".*\)"#).unwrap()
        );
        
        // Concurrency patterns
        patterns.insert(
            "unsafe_concurrency".to_string(),
            Regex::new(r"(?i)UnsafeShared\s*\(|UnsafeMutable\s*\(").unwrap()
        );
        
        patterns.insert(
            "race_condition_risk".to_string(),
            Regex::new(r"(?i)Thread\.Spawn\s*\(").unwrap()
        );
        
        // Network and I/O security
        patterns.insert(
            "unsafe_io".to_string(),
            Regex::new(r"(?i)UnsafeIo\.|RawIo\.").unwrap()
        );
        
        patterns.insert(
            "network_without_tls".to_string(),
            Regex::new(r"(?i)Http\.Connect\s*\(").unwrap()
        );
        
        // Debug and development patterns
        patterns.insert(
            "debug_code".to_string(),
            Regex::new(r"(?i)Print\s*\(|Debug\.Print\s*\(|Console\.WriteLine\s*\(").unwrap()
        );
        
        patterns.insert(
            "todo_in_production".to_string(),
            Regex::new(r"(?i)Todo\s*\(|__TODO__|FIXME").unwrap()
        );

        Self { patterns }
    }

    /// Parse Carbon source code and extract AST information
    pub fn parse(&self, source_file: &SourceFile) -> Result<ParsedAst> {
        let start_time = std::time::Instant::now();
        
        let mut metadata = AstMetadata::default();
        metadata.parse_time_ms = Some(start_time.elapsed().as_millis() as u64);
        
        Ok(ParsedAst {
            tree: None, // No AST tree for pattern-based parsing
            source: source_file.content.clone(),
            language: Some(Language::Carbon),
            parse_errors: Vec::new(),
            metadata,
        })
    }

    /// Analyze Carbon code for security vulnerabilities
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

            // Check for unsafe blocks
            if let Some(captures) = self.patterns["unsafe_block"].captures(line) {
                vulnerabilities.push(Vulnerability {
                    id: "CARBON-UNSAFE-001".to_string(),
                    cwe: Some("CWE-119".to_string()),
                    vulnerability_type: "Unsafe Memory Access".to_string(),
                    severity: Severity::High,
                    category: "vulnerability".to_string(),
                    description: "Unsafe block detected - potential memory safety issues".to_string(),
                    file_path: source_file.path.to_string_lossy().to_string(),
                    line_number: line_num,
                    column: captures.get(0).map(|m| m.start()).unwrap_or(0),
                    source_code: trimmed_line.to_string(),
                    recommendation: "Review unsafe operations and ensure memory safety guarantees".to_string(),
                });
            }

            // Check for C++ interop risks
            if let Some(captures) = self.patterns["cpp_interop_unsafe"].captures(line) {
                vulnerabilities.push(Vulnerability {
                    id: "CARBON-CPP-001".to_string(),
                    cwe: Some("CWE-829".to_string()),
                    vulnerability_type: "Unsafe C++ Interop".to_string(),
                    severity: Severity::High,
                    category: "security".to_string(),
                    description: "C++ interop detected - potential security risks from legacy code".to_string(),
                    file_path: source_file.path.to_string_lossy().to_string(),
                    line_number: line_num,
                    column: captures.get(0).map(|m| m.start()).unwrap_or(0),
                    source_code: trimmed_line.to_string(),
                    recommendation: "Validate C++ function calls and ensure safe boundaries".to_string(),
                });
            }

            // Check for unsafe casts
            if let Some(captures) = self.patterns["unsafe_cast"].captures(line) {
                vulnerabilities.push(Vulnerability {
                    id: "CARBON-CAST-001".to_string(),
                    cwe: Some("CWE-704".to_string()),
                    vulnerability_type: "Unsafe Type Cast".to_string(),
                    severity: Severity::Medium,
                    category: "vulnerability".to_string(),
                    description: "Unsafe type cast detected - may cause data corruption".to_string(),
                    file_path: source_file.path.to_string_lossy().to_string(),
                    line_number: line_num,
                    column: captures.get(0).map(|m| m.start()).unwrap_or(0),
                    source_code: trimmed_line.to_string(),
                    recommendation: "Use safe casting alternatives or validate cast safety".to_string(),
                });
            }

            // Check for public unsafe APIs
            if let Some(captures) = self.patterns["public_unsafe_api"].captures(line) {
                vulnerabilities.push(Vulnerability {
                    id: "CARBON-API-001".to_string(),
                    cwe: Some("CWE-668".to_string()),
                    vulnerability_type: "Unsafe Public API".to_string(),
                    severity: Severity::High,
                    category: "security".to_string(),
                    description: "Public API with unsafe operations - security boundary violation".to_string(),
                    file_path: source_file.path.to_string_lossy().to_string(),
                    line_number: line_num,
                    column: captures.get(0).map(|m| m.start()).unwrap_or(0),
                    source_code: trimmed_line.to_string(),
                    recommendation: "Ensure public APIs maintain safety invariants or mark as unsafe".to_string(),
                });
            }

            // Check for unhandled errors
            if let Some(captures) = self.patterns["unhandled_error"].captures(line) {
                vulnerabilities.push(Vulnerability {
                    id: "CARBON-ERROR-001".to_string(),
                    cwe: Some("CWE-252".to_string()),
                    vulnerability_type: "Unchecked Error Condition".to_string(),
                    severity: Severity::Medium,
                    category: "vulnerability".to_string(),
                    description: "Error expectation without handling - may cause unexpected failures".to_string(),
                    file_path: source_file.path.to_string_lossy().to_string(),
                    line_number: line_num,
                    column: captures.get(0).map(|m| m.start()).unwrap_or(0),
                    source_code: trimmed_line.to_string(),
                    recommendation: "Handle errors appropriately or document why expectation is safe".to_string(),
                });
            }

            // Check for manual memory management
            if let Some(captures) = self.patterns["manual_memory_management"].captures(line) {
                vulnerabilities.push(Vulnerability {
                    id: "CARBON-MEM-001".to_string(),
                    cwe: Some("CWE-401".to_string()),
                    vulnerability_type: "Manual Memory Management".to_string(),
                    severity: Severity::Medium,
                    category: "vulnerability".to_string(),
                    description: "Manual memory management detected - potential memory leak".to_string(),
                    file_path: source_file.path.to_string_lossy().to_string(),
                    line_number: line_num,
                    column: captures.get(0).map(|m| m.start()).unwrap_or(0),
                    source_code: trimmed_line.to_string(),
                    recommendation: "Use RAII or automatic memory management alternatives".to_string(),
                });
            }

            // Check for integer overflow risks
            if let Some(captures) = self.patterns["integer_overflow_risk"].captures(line) {
                vulnerabilities.push(Vulnerability {
                    id: "CARBON-INT-001".to_string(),
                    cwe: Some("CWE-190".to_string(),),
                    vulnerability_type: "Integer Overflow".to_string(),
                    severity: Severity::Medium,
                    category: "vulnerability".to_string(),
                    description: "Unsafe arithmetic operation - potential integer overflow".to_string(),
                    file_path: source_file.path.to_string_lossy().to_string(),
                    line_number: line_num,
                    column: captures.get(0).map(|m| m.start()).unwrap_or(0),
                    source_code: trimmed_line.to_string(),
                    recommendation: "Use checked arithmetic or validate input ranges".to_string(),
                });
            }

            // Check for hardcoded secrets
            if let Some(captures) = self.patterns["hardcoded_secrets"].captures(line) {
                vulnerabilities.push(Vulnerability {
                    id: "CARBON-SECRET-001".to_string(),
                    cwe: Some("CWE-798".to_string()),
                    vulnerability_type: "Hardcoded Credentials".to_string(),
                    severity: Severity::Critical,
                    category: "authentication".to_string(),
                    description: "Hardcoded secret detected in Carbon code".to_string(),
                    file_path: source_file.path.to_string_lossy().to_string(),
                    line_number: line_num,
                    column: captures.get(0).map(|m| m.start()).unwrap_or(0),
                    source_code: trimmed_line.to_string(),
                    recommendation: "Move secrets to environment variables or secure configuration".to_string(),
                });
            }

            // Check for unsafe concurrency
            if let Some(captures) = self.patterns["unsafe_concurrency"].captures(line) {
                vulnerabilities.push(Vulnerability {
                    id: "CARBON-THREAD-001".to_string(),
                    cwe: Some("CWE-362".to_string()),
                    vulnerability_type: "Race Condition".to_string(),
                    severity: Severity::High,
                    category: "vulnerability".to_string(),
                    description: "Unsafe shared data access - potential race condition".to_string(),
                    file_path: source_file.path.to_string_lossy().to_string(),
                    line_number: line_num,
                    column: captures.get(0).map(|m| m.start()).unwrap_or(0),
                    source_code: trimmed_line.to_string(),
                    recommendation: "Use safe concurrency primitives like Mutex or atomic operations".to_string(),
                });
            }

            // Check for network without TLS  
            if let Some(captures) = self.patterns["network_without_tls"].captures(line) {
                vulnerabilities.push(Vulnerability {
                    id: "CARBON-NET-001".to_string(),
                    cwe: Some("CWE-319".to_string()),
                    vulnerability_type: "Cleartext Transmission".to_string(),
                    severity: Severity::Medium,
                    category: "cryptographic".to_string(),
                    description: "HTTP connection without TLS - cleartext transmission risk".to_string(),
                    file_path: source_file.path.to_string_lossy().to_string(),
                    line_number: line_num,
                    column: captures.get(0).map(|m| m.start()).unwrap_or(0),
                    source_code: trimmed_line.to_string(),
                    recommendation: "Use HTTPS/TLS for secure network communications".to_string(),
                });
            }

            // Check for debug code
            if let Some(captures) = self.patterns["debug_code"].captures(line) {
                vulnerabilities.push(Vulnerability {
                    id: "CARBON-DEBUG-001".to_string(),
                    cwe: Some("CWE-489".to_string()),
                    vulnerability_type: "Debug Code in Production".to_string(),
                    severity: Severity::Low,
                    category: "security".to_string(),
                    description: "Debug code detected - may leak sensitive information".to_string(),
                    file_path: source_file.path.to_string_lossy().to_string(),
                    line_number: line_num,
                    column: captures.get(0).map(|m| m.start()).unwrap_or(0),
                    source_code: trimmed_line.to_string(),
                    recommendation: "Remove debug statements from production code".to_string(),
                });
            }

            // Check for TODO in production
            if let Some(captures) = self.patterns["todo_in_production"].captures(line) {
                vulnerabilities.push(Vulnerability {
                    id: "CARBON-TODO-001".to_string(),
                    cwe: Some("CWE-489".to_string()),
                    vulnerability_type: "Incomplete Implementation".to_string(),
                    severity: Severity::Medium,
                    category: "security".to_string(),
                    description: "TODO/FIXME comment - incomplete implementation".to_string(),
                    file_path: source_file.path.to_string_lossy().to_string(),
                    line_number: line_num,
                    column: captures.get(0).map(|m| m.start()).unwrap_or(0),
                    source_code: trimmed_line.to_string(),
                    recommendation: "Complete implementation or remove TODO comments before production".to_string(),
                });
            }
        }

        Ok(vulnerabilities)
    }

    /// Check if this is a valid Carbon file
    pub fn is_carbon_file(file_path: &std::path::Path) -> bool {
        if let Some(ext) = file_path.extension() {
            if let Some(ext_str) = ext.to_str() {
                ext_str.to_lowercase() == "carbon"
            } else {
                false
            }
        } else {
            false
        }
    }
}

impl Default for CarbonParser {
    fn default() -> Self {
        Self::new()
    }
}

impl Parser for CarbonParser {
    fn parse(&mut self, source_file: &SourceFile) -> Result<ParsedAst> {
        CarbonParser::parse(self, source_file)
    }

    fn language(&self) -> Language {
        Language::Carbon
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::Language;
    use std::path::PathBuf;

    #[test]
    fn test_carbon_parser_basic() {
        let parser = CarbonParser::new();
        let source_file = SourceFile {
            path: PathBuf::from("test.carbon"),
            content: r#"
package Sample api;

fn UnsafeFunction() -> i32 {
    unsafe {
        var ptr: UnsafePointer(i32) = UnsafePointer(i32).Null();
        return UnsafeCast(i32, ptr);
    }
}

var global_secret: StringLiteral = "api_key_12345_secret";
"#.to_string(),
            language: Language::Carbon,
        };

        let result = parser.analyze_security(&source_file);
        assert!(result.is_ok());
        let vulnerabilities = result.unwrap();
        assert!(!vulnerabilities.is_empty());
    }

    #[test]
    fn test_carbon_cpp_interop() {
        let parser = CarbonParser::new();
        let source_file = SourceFile {
            path: PathBuf::from("test.carbon"),
            content: r#"
fn CallCppFunction() {
    Cpp.unsafe_legacy_function();
}
"#.to_string(),
            language: Language::Carbon,
        };

        let result = parser.analyze_security(&source_file);
        assert!(result.is_ok());
        let vulnerabilities = result.unwrap();
        assert!(vulnerabilities.iter().any(|v| v.id == "CARBON-CPP-001"));
    }

    #[test]
    fn test_carbon_file_detection() {
        assert!(CarbonParser::is_carbon_file(&PathBuf::from("test.carbon")));
        assert!(!CarbonParser::is_carbon_file(&PathBuf::from("test.rs")));
    }
}