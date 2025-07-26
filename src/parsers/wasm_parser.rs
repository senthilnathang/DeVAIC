/// WebAssembly (WASM) Parser for DeVAIC
/// 
/// This module provides parsing support for WebAssembly modules and WebAssembly Text Format (WAT) files.
/// WebAssembly is a binary instruction format for a stack-based virtual machine designed for portable
/// compilation targets, commonly used for web applications, serverless functions, and performance-critical code.
/// 
/// Security concerns for WASM include:
/// - Memory safety issues despite sandboxing
/// - Side-channel attacks and timing vulnerabilities
/// - Import/export interface security
/// - Host function call validation
/// - Memory allocation and bounds checking
/// - Cryptographic implementations in WASM

use crate::parsers::{SourceFile, ParsedAst, AstMetadata};
use crate::{Language, Vulnerability, Severity};
use crate::error::Result;
use std::collections::HashMap;
use regex::Regex;

/// WebAssembly-specific parser implementation
pub struct WasmParser {
    /// Common WASM security patterns for analysis
    patterns: HashMap<String, Regex>,
}

impl WasmParser {
    pub fn new() -> Self {
        let mut patterns = HashMap::new();
        
        // Initialize WASM security patterns
        
        // Memory safety patterns
        patterns.insert(
            "unrestricted_memory_grow".to_string(),
            Regex::new(r"(?i)\bmemory\.grow\b").unwrap()
        );
        
        patterns.insert(
            "unsafe_memory_access".to_string(),
            Regex::new(r"(?i)\b(i32|i64|f32|f64)\.(load|store)\d*\b").unwrap()
        );
        
        // Import/export security patterns
        patterns.insert(
            "dangerous_host_imports".to_string(),
            Regex::new(r#"(?i)\(import\s+"[^"]*"\s+"(eval|exec|system|fs\.|process\.|crypto\.subtle\.)"#).unwrap()
        );
        
        patterns.insert(
            "unrestricted_exports".to_string(),
            Regex::new(r#"(?i)\(export\s+"(memory|__wasm_)"#).unwrap()
        );
        
        // Timing attack vulnerabilities
        patterns.insert(
            "timing_sensitive_operations".to_string(),
            Regex::new(r"(?i)\b(f32|f64)\.(div|sqrt|sin|cos|exp|log)\s+").unwrap()
        );
        
        // Cryptographic weaknesses
        patterns.insert(
            "weak_random_generation".to_string(),
            Regex::new(r"(?i)\b(Math\.random|Date\.now|performance\.now)\s*\(").unwrap()
        );
        
        // Control flow patterns
        patterns.insert(
            "unrestricted_indirect_calls".to_string(),
            Regex::new(r"(?i)\bcall_indirect\s+").unwrap()
        );
        
        // Stack manipulation patterns
        patterns.insert(
            "stack_overflow_risk".to_string(),
            Regex::new(r"(?i)\b(call|call_indirect)\s+").unwrap()
        );
        
        // Data section security
        patterns.insert(
            "hardcoded_secrets".to_string(),
            Regex::new(r#"(?i)\(data.*(?:password|secret|key|token|credential|auth|api)"#).unwrap()
        );
        
        // Function table security
        patterns.insert(
            "function_table_manipulation".to_string(),
            Regex::new(r"(?i)\b(table\.(get|set)|elem\.drop)\s+").unwrap()
        );
        
        // Import validation patterns  
        patterns.insert(
            "unsafe_host_bindings".to_string(),
            Regex::new(r#"(?i)\(import\s+"[^"]*"\s+"[^"]*"\s+\(func[^)]*\)\s*\)"#).unwrap()
        );
        
        // Performance timing patterns
        patterns.insert(
            "constant_time_violation".to_string(),
            Regex::new(r"(?i)\b(select|br_if|br_table)\s+.*\b(password|secret|key|token)\b").unwrap()
        );

        Self { patterns }
    }

    /// Parse WASM source code and extract AST information
    pub fn parse(&self, source_file: &SourceFile) -> Result<ParsedAst> {
        let start_time = std::time::Instant::now();
        
        // WASM analysis uses pattern-based parsing for both binary and text formats
        // For binary WASM, we would need specialized binary parsing
        // For WAT (WebAssembly Text), we use regex-based pattern matching
        
        let mut metadata = AstMetadata::default();
        metadata.parse_time_ms = Some(start_time.elapsed().as_millis() as u64);
        
        Ok(ParsedAst {
            tree: None, // No AST tree for pattern-based parsing
            source: source_file.content.clone(),
            language: Some(Language::Wasm),
            parse_errors: Vec::new(),
            metadata,
        })
    }

    /// Analyze WASM code for security vulnerabilities
    pub fn analyze_security(&self, source_file: &SourceFile) -> Result<Vec<Vulnerability>> {
        let mut vulnerabilities = Vec::new();
        let lines: Vec<&str> = source_file.content.lines().collect();

        for (line_number, line) in lines.iter().enumerate() {
            let line_num = line_number + 1;
            let trimmed_line = line.trim();

            // Skip empty lines and comments
            if trimmed_line.is_empty() || trimmed_line.starts_with(";;") {
                continue;
            }

            // Check for unrestricted memory growth
            if let Some(captures) = self.patterns["unrestricted_memory_grow"].captures(line) {
                vulnerabilities.push(Vulnerability {
                    id: "WASM-MEM-001".to_string(),
                    cwe: Some("CWE-770".to_string()),
                    title: "Resource Exhaustion".to_string(),
                    severity: Severity::High,
                    category: "vulnerability".to_string(),
                    description: "Unrestricted memory growth detected - may lead to resource exhaustion".to_string(),
                    file_path: source_file.path.to_string_lossy().to_string(),
                    line_number: line_num,
                    column_start: captures.get(0).map(|m| m.start()).unwrap_or(0),
                    column_end: captures.get(0).map(|m| m.end()).unwrap_or(0),
                    source_code: trimmed_line.to_string(),
                    recommendation: "Implement bounds checking and memory limits for memory.grow operations".to_string(),
                    owasp: Some("A04:2021 – Insecure Design".to_string()),
                    references: vec!["https://cwe.mitre.org/data/definitions/770.html".to_string()],
                    confidence: 0.8,
                });
            }

            // Check for unsafe memory access patterns
            if let Some(captures) = self.patterns["unsafe_memory_access"].captures(line) {
                vulnerabilities.push(Vulnerability {
                    id: "WASM-MEM-002".to_string(),
                    cwe: Some("CWE-119".to_string()),
                    title: "Buffer Overflow Risk".to_string(),
                    severity: Severity::Medium,
                    category: "vulnerability".to_string(),
                    description: "Unsafe memory access pattern detected - validate bounds and alignment".to_string(),
                    file_path: source_file.path.to_string_lossy().to_string(),
                    line_number: line_num,
                    column_start: captures.get(0).map(|m| m.start()).unwrap_or(0),
                    column_end: captures.get(0).map(|m| m.end()).unwrap_or(0),
                    source_code: trimmed_line.to_string(),
                    recommendation: "Ensure proper bounds checking and alignment validation for memory operations".to_string(),
                    owasp: Some("A06:2021 – Vulnerable and Outdated Components".to_string()),
                    references: vec!["https://cwe.mitre.org/data/definitions/119.html".to_string()],
                    confidence: 0.7,
                });
            }

            // Check for dangerous host imports
            if let Some(captures) = self.patterns["dangerous_host_imports"].captures(line) {
                vulnerabilities.push(Vulnerability {
                    id: "WASM-IMPORT-001".to_string(),
                    cwe: Some("CWE-829".to_string()),
                    title: "Dangerous Host Import".to_string(),
                    severity: Severity::Critical,
                    category: "security".to_string(),
                    description: "Dangerous host function import detected - may allow code execution or sensitive operations".to_string(),
                    file_path: source_file.path.to_string_lossy().to_string(),
                    line_number: line_num,
                    column_start: captures.get(0).map(|m| m.start()).unwrap_or(0),
                    column_end: captures.get(0).map(|m| m.end()).unwrap_or(0),
                    source_code: trimmed_line.to_string(),
                    recommendation: "Review and validate all host function imports, implement input validation and sandboxing".to_string(),
                    owasp: Some("A08:2021 – Software and Data Integrity Failures".to_string()),
                    references: vec!["https://cwe.mitre.org/data/definitions/829.html".to_string()],
                    confidence: 0.9,
                });
            }

            // Check for unrestricted exports
            if let Some(captures) = self.patterns["unrestricted_exports"].captures(line) {
                vulnerabilities.push(Vulnerability {
                    id: "WASM-EXPORT-001".to_string(),
                    cwe: Some("CWE-200".to_string()),
                    title: "Information Exposure".to_string(),
                    severity: Severity::Medium,
                    category: "security".to_string(),
                    description: "Potentially sensitive export detected - may expose internal memory or functions".to_string(),
                    file_path: source_file.path.to_string_lossy().to_string(),
                    line_number: line_num,
                    column_start: captures.get(0).map(|m| m.start()).unwrap_or(0),
                    column_end: captures.get(0).map(|m| m.end()).unwrap_or(0),
                    source_code: trimmed_line.to_string(),
                    recommendation: "Review exported functions and memory, ensure only necessary interfaces are exposed".to_string(),
                    owasp: Some("A03:2021 – Injection".to_string()),
                    references: vec!["https://cwe.mitre.org/data/definitions/200.html".to_string()],
                    confidence: 0.7,
                });
            }

            // Check for timing-sensitive operations
            if let Some(captures) = self.patterns["timing_sensitive_operations"].captures(line) {
                vulnerabilities.push(Vulnerability {
                    id: "WASM-TIMING-001".to_string(),
                    cwe: Some("CWE-208".to_string()),
                    title: "Timing Attack Vulnerability".to_string(),
                    severity: Severity::Medium,
                    category: "cryptographic".to_string(),
                    description: "Timing-sensitive floating-point operation detected - may be vulnerable to timing attacks".to_string(),
                    file_path: source_file.path.to_string_lossy().to_string(),
                    line_number: line_num,
                    column_start: captures.get(0).map(|m| m.start()).unwrap_or(0),
                    column_end: captures.get(0).map(|m| m.end()).unwrap_or(0),
                    source_code: trimmed_line.to_string(),
                    recommendation: "Use constant-time implementations for cryptographic operations or add timing randomization".to_string(),
                    owasp: Some("A02:2021 – Cryptographic Failures".to_string()),
                    references: vec!["https://cwe.mitre.org/data/definitions/208.html".to_string()],
                    confidence: 0.7,
                });
            }

            // Check for weak random generation
            if let Some(captures) = self.patterns["weak_random_generation"].captures(line) {
                vulnerabilities.push(Vulnerability {
                    id: "WASM-CRYPTO-001".to_string(),
                    cwe: Some("CWE-338".to_string()),
                    owasp: Some("A02:2021".to_string()),
                    title: "Weak Random Number Generation".to_string(),
                    severity: Severity::High,
                    category: "cryptographic".to_string(),
                    description: "Weak random number generation detected - not suitable for cryptographic purposes".to_string(),
                    file_path: source_file.path.to_string_lossy().to_string(),
                    line_number: line_num,
                    column_start: captures.get(0).map(|m| m.start()).unwrap_or(0),
                    column_end: captures.get(0).map(|m| m.end()).unwrap_or(0),
                    source_code: trimmed_line.to_string(),
                    recommendation: "Use cryptographically secure random number generators (crypto.getRandomValues or secure host functions)".to_string(),
                    references: vec![],
                    confidence: 0.8,
                });
            }

            // Check for unrestricted indirect calls
            if let Some(captures) = self.patterns["unrestricted_indirect_calls"].captures(line) {
                vulnerabilities.push(Vulnerability {
                    id: "WASM-CONTROL-001".to_string(),
                    cwe: Some("CWE-691".to_string()),
                    owasp: Some("A03:2021".to_string()),
                    title: "Control Flow Vulnerability".to_string(),
                    severity: Severity::Medium,
                    category: "vulnerability".to_string(),
                    description: "Unrestricted indirect call detected - may allow control flow hijacking".to_string(),
                    file_path: source_file.path.to_string_lossy().to_string(),
                    line_number: line_num,
                    column_start: captures.get(0).map(|m| m.start()).unwrap_or(0),
                    column_end: captures.get(0).map(|m| m.end()).unwrap_or(0),
                    source_code: trimmed_line.to_string(),
                    recommendation: "Validate function table indices and implement call site verification".to_string(),
                    references: vec![],
                    confidence: 0.7,
                });
            }

            // Check for hardcoded secrets in data sections
            if let Some(captures) = self.patterns["hardcoded_secrets"].captures(line) {
                vulnerabilities.push(Vulnerability {
                    id: "WASM-SECRET-001".to_string(),
                    cwe: Some("CWE-798".to_string()),
                    owasp: Some("A07:2021".to_string()),
                    title: "Hardcoded Credentials".to_string(),
                    severity: Severity::Critical,
                    category: "authentication".to_string(),
                    description: "Hardcoded secret detected in WASM data section".to_string(),
                    file_path: source_file.path.to_string_lossy().to_string(),
                    line_number: line_num,
                    column_start: captures.get(0).map(|m| m.start()).unwrap_or(0),
                    column_end: captures.get(0).map(|m| m.end()).unwrap_or(0),
                    source_code: trimmed_line.to_string(),
                    recommendation: "Remove hardcoded secrets, use secure configuration or environment variables".to_string(),
                    references: vec![],
                    confidence: 0.9,
                });
            }

            // Check for function table manipulation
            if let Some(captures) = self.patterns["function_table_manipulation"].captures(line) {
                vulnerabilities.push(Vulnerability {
                    id: "WASM-TABLE-001".to_string(),
                    cwe: Some("CWE-913".to_string()),
                    title: "Resource Management Vulnerability".to_string(),
                    severity: Severity::Medium,
                    category: "vulnerability".to_string(),
                    description: "Function table manipulation detected - ensure proper access control".to_string(),
                    file_path: source_file.path.to_string_lossy().to_string(),
                    line_number: line_num,
                    column_start: captures.get(0).map(|m| m.start()).unwrap_or(0),
                    column_end: captures.get(0).map(|m| m.end()).unwrap_or(0),
                    source_code: trimmed_line.to_string(),
                    recommendation: "Implement proper bounds checking and access control for table operations".to_string(),
                    owasp: None,
                    references: vec![],
                    confidence: 0.8,
                });
            }

            // Check for unsafe host bindings
            if let Some(captures) = self.patterns["unsafe_host_bindings"].captures(line) {
                vulnerabilities.push(Vulnerability {
                    id: "WASM-HOST-001".to_string(),
                    cwe: Some("CWE-20".to_string()),
                    title: "Insufficient Input Validation".to_string(),
                    severity: Severity::High,
                    category: "security".to_string(),
                    description: "Host function import without validation comments - may lack input validation".to_string(),
                    file_path: source_file.path.to_string_lossy().to_string(),
                    line_number: line_num,
                    column_start: captures.get(0).map(|m| m.start()).unwrap_or(0),
                    column_end: captures.get(0).map(|m| m.end()).unwrap_or(0),
                    source_code: trimmed_line.to_string(),
                    recommendation: "Document and implement input validation for all host function bindings".to_string(),
                    owasp: None,
                    references: vec![],
                    confidence: 0.9,
                });
            }

            // Check for constant-time violations
            if let Some(captures) = self.patterns["constant_time_violation"].captures(line) {
                vulnerabilities.push(Vulnerability {
                    id: "WASM-TIMING-002".to_string(),
                    cwe: Some("CWE-208".to_string()),
                    title: "Timing Attack Vulnerability".to_string(),
                    severity: Severity::High,
                    category: "cryptographic".to_string(),
                    description: "Potential constant-time violation in cryptographic operation".to_string(),
                    file_path: source_file.path.to_string_lossy().to_string(),
                    line_number: line_num,
                    column_start: captures.get(0).map(|m| m.start()).unwrap_or(0),
                    column_end: captures.get(0).map(|m| m.end()).unwrap_or(0),
                    source_code: trimmed_line.to_string(),
                    recommendation: "Ensure cryptographic operations execute in constant time regardless of input values".to_string(),
                    owasp: None,
                    references: vec![],
                    confidence: 0.85,
                });
            }
        }

        Ok(vulnerabilities)
    }

    /// Check if this is a valid WASM file
    pub fn is_wasm_file(file_path: &std::path::Path) -> bool {
        if let Some(ext) = file_path.extension() {
            if let Some(ext_str) = ext.to_str() {
                matches!(ext_str.to_lowercase().as_str(), "wasm" | "wat" | "wast")
            } else {
                false
            }
        } else {
            false
        }
    }
}

impl Default for WasmParser {
    fn default() -> Self {
        Self::new()
    }
}

/// Implementation of the Parser trait for WASM
impl crate::parsers::Parser for WasmParser {
    fn parse(&mut self, source_file: &SourceFile) -> Result<ParsedAst> {
        WasmParser::parse(self, source_file)
    }

    fn language(&self) -> Language {
        Language::Wasm
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::Language;
    use std::path::PathBuf;

    #[test]
    fn test_wasm_parser_basic() {
        let parser = WasmParser::new();
        let source_file = SourceFile {
            path: PathBuf::from("test.wat"),
            content: r#"
(module
  (memory 1)
  (func $unsafe_memory_grow
    i32.const 100
    memory.grow
    drop
  )
  (export "grow_memory" (func $unsafe_memory_grow))
)
"#.to_string(),
            language: Language::Wasm,
        };

        let result = parser.analyze_security(&source_file);
        assert!(result.is_ok());
        let vulnerabilities = result.unwrap();
        
        // Note: Since this uses the rules engine patterns, we expect vulnerabilities
        // The actual parsing works through the RuleSet implementation
        assert!(!vulnerabilities.is_empty());
    }

    #[test]
    fn test_wasm_dangerous_imports() {
        let parser = WasmParser::new();
        let source_file = SourceFile {
            path: PathBuf::from("test.wat"),
            content: r#"
(module
  (import "env" "eval" (func $eval (param i32) (result i32)))
  (import "fs" "readFile" (func $readFile (param i32 i32) (result i32)))
)
"#.to_string(),
            language: Language::Wasm,
        };

        let result = parser.analyze_security(&source_file);
        assert!(result.is_ok());
        let vulnerabilities = result.unwrap();
        
        // Should detect dangerous imports (pattern based detection)
        assert!(!vulnerabilities.is_empty());
    }

    #[test]
    fn test_wasm_hardcoded_secrets() {
        let parser = WasmParser::new();
        let source_file = SourceFile {
            path: PathBuf::from("test.wat"),
            content: r#"
(module
  (data (i32.const 0) "api_key_12345_secret")
  (memory 1)
)
"#.to_string(),
            language: Language::Wasm,
        };

        let result = parser.analyze_security(&source_file);
        assert!(result.is_ok());
        let vulnerabilities = result.unwrap();
        
        // Should detect hardcoded secrets (pattern based detection)
        assert!(!vulnerabilities.is_empty());
    }

    #[test]
    fn test_wasm_file_detection() {
        assert!(WasmParser::is_wasm_file(&PathBuf::from("test.wasm")));
        assert!(WasmParser::is_wasm_file(&PathBuf::from("module.wat")));
        assert!(WasmParser::is_wasm_file(&PathBuf::from("test.wast")));
        assert!(!WasmParser::is_wasm_file(&PathBuf::from("test.js")));
    }
}