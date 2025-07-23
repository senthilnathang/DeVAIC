/// WebAssembly (WASM) Security Rules for DeVAIC
/// 
/// This module implements security analysis rules specific to WebAssembly,
/// covering both binary WASM modules and WebAssembly Text Format (WAT) files.
/// 
/// WASM security concerns include:
/// - Memory safety despite sandboxing
/// - Side-channel and timing attacks
/// - Host function import validation
/// - Export interface security
/// - Resource exhaustion attacks
/// - Cryptographic implementation security

use crate::parsers::{SourceFile, ParsedAst};
use crate::{Vulnerability, Severity};
use crate::error::Result;
use super::RuleSet;
use regex::Regex;
use std::collections::HashMap;
use lazy_static::lazy_static;

lazy_static! {
    /// WASM-specific security patterns
    static ref WASM_PATTERNS: HashMap<&'static str, Regex> = {
        let mut m = HashMap::new();
        
        // Memory security patterns
        m.insert("memory_grow_without_limits", 
            Regex::new(r"(?i)\bmemory\.grow\b").unwrap()
        );
        
        m.insert("unsafe_memory_operations",
            Regex::new(r"(?i)\b(i32|i64|f32|f64)\.(load|store)\d*\b").unwrap()
        );
        
        m.insert("unaligned_memory_access",
            Regex::new(r"(?i)\b(i32|i64|f32|f64)\.(load|store)\d*\s+offset=\d+\s+align=[02468]").unwrap()
        );
        
        // Import/Export security
        m.insert("dangerous_env_imports",
            Regex::new(r#"(?i)\(import\s+"env"\s+"(eval|system|exec|spawn|fork|__wasm_call_ctors)""#).unwrap()
        );
        
        m.insert("filesystem_imports",
            Regex::new(r#"(?i)\(import\s+"[^"]*"\s+"[^"]*(?:read|write|open|close|file)""#).unwrap()
        );
        
        m.insert("network_imports",
            Regex::new(r#"(?i)\(import\s+"[^"]*"\s+"(fetch|http\.|socket\.|net\.|tcp\.|udp\.)""#).unwrap()
        );
        
        m.insert("crypto_imports",
            Regex::new(r#"(?i)\(import\s+"[^"]*"\s+"(crypto\.|random|encrypt|decrypt|hash|sign)""#).unwrap()
        );
        
        m.insert("memory_exports",
            Regex::new(r#"(?i)\(export\s+"(memory|__heap_base|__data_end|malloc|free)""#).unwrap()
        );
        
        m.insert("internal_function_exports",
            Regex::new(r#"(?i)\(export\s+"(main|_start|__wasm_|_init)""#).unwrap()
        );
        
        // Control flow security
        m.insert("unrestricted_indirect_calls",
            Regex::new(r"(?i)\bcall_indirect\s+").unwrap()
        );
        
        m.insert("dynamic_function_table",
            Regex::new(r"(?i)\btable\.(get|set)\s+").unwrap()
        );
        
        m.insert("elem_segment_manipulation",
            Regex::new(r"(?i)\b(elem\.drop|table\.init|table\.copy)\s+").unwrap()
        );
        
        // Data security
        m.insert("hardcoded_credentials",
            Regex::new(r#"(?i)\(data.*(?:password|secret|key|token|credential|auth|api)"#).unwrap()
        );
        
        m.insert("hardcoded_urls",
            Regex::new(r#"(?i)\(data[^)]*"[^"]*https?://[^"]*""#).unwrap()
        );
        
        m.insert("sensitive_data_globals",
            Regex::new(r"(?i)\(global[^)]*\(mut[^)]*\).*(?:password|secret|key|token)").unwrap()
        );
        
        // Timing attack patterns
        m.insert("variable_time_crypto",
            Regex::new(r"(?i)\b(br_if|select)\s.*password").unwrap()
        );
        
        m.insert("timing_sensitive_branches",
            Regex::new(r"(?i)\bbr_table\s+[^;]*(?:auth|login|verify|check)").unwrap()
        );
        
        // Resource exhaustion
        m.insert("recursive_calls",
            Regex::new(r"(?i)\bcall\s+\$\w+").unwrap()
        );
        
        m.insert("large_memory_allocation",
            Regex::new(r"(?i)\(memory\s+\d{3,}\)|\bmemory\.grow\s+(?:i32\.const\s+)?\d{3,}").unwrap()
        );
        
        m.insert("infinite_loop_risk",
            Regex::new(r"(?i)\bloop\s+\$\w+").unwrap()
        );
        
        // Host environment security
        m.insert("unchecked_host_calls",
            Regex::new(r"(?i)\bcall\s+\$(?:import_|host_)").unwrap()
        );
        
        m.insert("performance_now_timing",
            Regex::new(r#"(?i)\(import[^)]*"performance\.now""#).unwrap()
        );
        
        // Stack overflow protection
        m.insert("deep_recursion_risk",
            Regex::new(r"(?i)\bcall\s+\$\w+.*\bcall\s+\$\w+.*\bcall\s+\$\w+").unwrap()
        );

        m
    };
}

/// WASM security rules implementation
pub struct WasmRules;

impl WasmRules {
    pub fn new() -> Self {
        Self
    }

    /// Analyze WASM source code for security vulnerabilities
    pub fn analyze_source(&self, source_file: &SourceFile) -> Result<Vec<Vulnerability>> {
        let mut vulnerabilities = Vec::new();
        let lines: Vec<&str> = source_file.content.lines().collect();

        for (line_number, line) in lines.iter().enumerate() {
            let line_num = line_number + 1;
            let trimmed_line = line.trim();

            // Skip empty lines and comments
            if trimmed_line.is_empty() || trimmed_line.starts_with(";;") {
                continue;
            }

            // Check for memory growth without limits
            if let Some(captures) = WASM_PATTERNS["memory_grow_without_limits"].captures(line) {
                vulnerabilities.push(Vulnerability {
                    id: "WASM-MEM-001".to_string(),
                    cwe: Some("CWE-770".to_string()),
                    vulnerability_type: "Resource Exhaustion".to_string(),
                    severity: Severity::High,
                    category: "vulnerability".to_string(),
                    description: "Memory growth without bounds checking - may lead to resource exhaustion".to_string(),
                    file_path: source_file.path.to_string_lossy().to_string(),
                    line_number: line_num,
                    column: captures.get(0).map(|m| m.start()).unwrap_or(0),
                    source_code: trimmed_line.to_string(),
                    recommendation: "Implement bounds checking and memory limits for memory.grow operations".to_string(),
                });
            }

            // Check for unsafe memory operations
            if let Some(captures) = WASM_PATTERNS["unsafe_memory_operations"].captures(line) {
                vulnerabilities.push(Vulnerability {
                    id: "WASM-MEM-002".to_string(),
                    cwe: Some("CWE-119".to_string()),
                    vulnerability_type: "Buffer Overflow Risk".to_string(),
                    severity: Severity::Medium,
                    category: "vulnerability".to_string(),
                    description: "Memory operation without validation comment - ensure bounds checking".to_string(),
                    file_path: source_file.path.to_string_lossy().to_string(),
                    line_number: line_num,
                    column: captures.get(0).map(|m| m.start()).unwrap_or(0),
                    source_code: trimmed_line.to_string(),
                    recommendation: "Add validation comments and ensure proper bounds checking for memory operations".to_string(),
                });
            }

            // Check for unaligned memory access
            if let Some(captures) = WASM_PATTERNS["unaligned_memory_access"].captures(line) {
                vulnerabilities.push(Vulnerability {
                    id: "WASM-MEM-003".to_string(),
                    cwe: Some("CWE-704".to_string()),
                    vulnerability_type: "Unaligned Memory Access".to_string(),
                    severity: Severity::Medium,
                    category: "vulnerability".to_string(),
                    description: "Potentially unaligned memory access detected - may cause performance issues or crashes".to_string(),
                    file_path: source_file.path.to_string_lossy().to_string(),
                    line_number: line_num,
                    column: captures.get(0).map(|m| m.start()).unwrap_or(0),
                    source_code: trimmed_line.to_string(),
                    recommendation: "Ensure memory access alignment matches data type requirements".to_string(),
                });
            }

            // Check for dangerous environment imports
            if let Some(captures) = WASM_PATTERNS["dangerous_env_imports"].captures(line) {
                vulnerabilities.push(Vulnerability {
                    id: "WASM-IMPORT-001".to_string(),
                    cwe: Some("CWE-829".to_string()),
                    vulnerability_type: "Dangerous Host Import".to_string(),
                    severity: Severity::Critical,
                    category: "security".to_string(),
                    description: "Dangerous environment function import - may allow code execution".to_string(),
                    file_path: source_file.path.to_string_lossy().to_string(),
                    line_number: line_num,
                    column: captures.get(0).map(|m| m.start()).unwrap_or(0),
                    source_code: trimmed_line.to_string(),
                    recommendation: "Avoid dangerous imports or implement strict input validation and sandboxing".to_string(),
                });
            }

            // Check for filesystem imports
            if let Some(captures) = WASM_PATTERNS["filesystem_imports"].captures(line) {
                vulnerabilities.push(Vulnerability {
                    id: "WASM-IMPORT-002".to_string(),
                    cwe: Some("CWE-200".to_string()),
                    vulnerability_type: "File System Access".to_string(),
                    severity: Severity::High,
                    category: "security".to_string(),
                    description: "File system access import detected - ensure proper access controls".to_string(),
                    file_path: source_file.path.to_string_lossy().to_string(),
                    line_number: line_num,
                    column: captures.get(0).map(|m| m.start()).unwrap_or(0),
                    source_code: trimmed_line.to_string(),
                    recommendation: "Implement path validation, access controls, and audit logging for file operations".to_string(),
                });
            }

            // Check for network imports
            if let Some(captures) = WASM_PATTERNS["network_imports"].captures(line) {
                vulnerabilities.push(Vulnerability {
                    id: "WASM-IMPORT-003".to_string(),
                    cwe: Some("CWE-918".to_string()),
                    vulnerability_type: "Network Access Risk".to_string(),
                    severity: Severity::High,
                    category: "security".to_string(),
                    description: "Network function import detected - may allow SSRF or data exfiltration".to_string(),
                    file_path: source_file.path.to_string_lossy().to_string(),
                    line_number: line_num,
                    column: captures.get(0).map(|m| m.start()).unwrap_or(0),
                    source_code: trimmed_line.to_string(),
                    recommendation: "Implement URL validation, rate limiting, and network access controls".to_string(),
                });
            }

            // Check for crypto imports
            if let Some(captures) = WASM_PATTERNS["crypto_imports"].captures(line) {
                vulnerabilities.push(Vulnerability {
                    id: "WASM-CRYPTO-001".to_string(),
                    cwe: Some("CWE-327".to_string()),
                    vulnerability_type: "Cryptographic Function Import".to_string(),
                    severity: Severity::Medium,
                    category: "cryptographic".to_string(),
                    description: "Cryptographic function import - ensure secure implementation and key management".to_string(),
                    file_path: source_file.path.to_string_lossy().to_string(),
                    line_number: line_num,
                    column: captures.get(0).map(|m| m.start()).unwrap_or(0),
                    source_code: trimmed_line.to_string(),
                    recommendation: "Verify cryptographic implementation security and proper key management practices".to_string(),
                });
            }

            // Check for memory exports
            if let Some(captures) = WASM_PATTERNS["memory_exports"].captures(line) {
                vulnerabilities.push(Vulnerability {
                    id: "WASM-EXPORT-001".to_string(),
                    cwe: Some("CWE-200".to_string()),
                    vulnerability_type: "Memory Export".to_string(),
                    severity: Severity::Medium,
                    category: "security".to_string(),
                    description: "Memory or heap information exported - may expose sensitive data or memory layout".to_string(),
                    file_path: source_file.path.to_string_lossy().to_string(),
                    line_number: line_num,
                    column: captures.get(0).map(|m| m.start()).unwrap_or(0),
                    source_code: trimmed_line.to_string(),
                    recommendation: "Review memory exports and ensure no sensitive data is exposed".to_string(),
                });
            }

            // Check for internal function exports
            if let Some(captures) = WASM_PATTERNS["internal_function_exports"].captures(line) {
                vulnerabilities.push(Vulnerability {
                    id: "WASM-EXPORT-002".to_string(),
                    cwe: Some("CWE-668".to_string()),
                    vulnerability_type: "Internal Function Export".to_string(),
                    severity: Severity::Low,
                    category: "security".to_string(),
                    description: "Internal function exported - may expose implementation details".to_string(),
                    file_path: source_file.path.to_string_lossy().to_string(),
                    line_number: line_num,
                    column: captures.get(0).map(|m| m.start()).unwrap_or(0),
                    source_code: trimmed_line.to_string(),
                    recommendation: "Review exported functions and only expose necessary public interfaces".to_string(),
                });
            }

            // Check for unrestricted indirect calls
            if let Some(captures) = WASM_PATTERNS["unrestricted_indirect_calls"].captures(line) {
                vulnerabilities.push(Vulnerability {
                    id: "WASM-CONTROL-001".to_string(),
                    cwe: Some("CWE-691".to_string()),
                    vulnerability_type: "Control Flow Vulnerability".to_string(),
                    severity: Severity::High,
                    category: "vulnerability".to_string(),
                    description: "Indirect call without validation comment - may allow control flow hijacking".to_string(),
                    file_path: source_file.path.to_string_lossy().to_string(),
                    line_number: line_num,
                    column: captures.get(0).map(|m| m.start()).unwrap_or(0),
                    source_code: trimmed_line.to_string(),
                    recommendation: "Validate function table indices and add validation comments for indirect calls".to_string(),
                });
            }

            // Check for dynamic function table operations
            if let Some(captures) = WASM_PATTERNS["dynamic_function_table"].captures(line) {
                vulnerabilities.push(Vulnerability {
                    id: "WASM-TABLE-001".to_string(),
                    cwe: Some("CWE-913".to_string()),
                    vulnerability_type: "Function Table Manipulation".to_string(),
                    severity: Severity::Medium,
                    category: "vulnerability".to_string(),
                    description: "Function table manipulation without bounds checking comment".to_string(),
                    file_path: source_file.path.to_string_lossy().to_string(),
                    line_number: line_num,
                    column: captures.get(0).map(|m| m.start()).unwrap_or(0),
                    source_code: trimmed_line.to_string(),
                    recommendation: "Implement bounds checking and add validation comments for table operations".to_string(),
                });
            }

            // Check for hardcoded credentials
            if let Some(captures) = WASM_PATTERNS["hardcoded_credentials"].captures(line) {
                vulnerabilities.push(Vulnerability {
                    id: "WASM-SECRET-001".to_string(),
                    cwe: Some("CWE-798".to_string()),
                    vulnerability_type: "Hardcoded Credentials".to_string(),
                    severity: Severity::Critical,
                    category: "authentication".to_string(),
                    description: "Hardcoded credentials detected in WASM data section".to_string(),
                    file_path: source_file.path.to_string_lossy().to_string(),
                    line_number: line_num,
                    column: captures.get(0).map(|m| m.start()).unwrap_or(0),
                    source_code: trimmed_line.to_string(),
                    recommendation: "Remove hardcoded credentials and use secure configuration management".to_string(),
                });
            }

            // Check for hardcoded URLs
            if let Some(captures) = WASM_PATTERNS["hardcoded_urls"].captures(line) {
                vulnerabilities.push(Vulnerability {
                    id: "WASM-CONFIG-001".to_string(),
                    cwe: Some("CWE-200".to_string()),
                    vulnerability_type: "Information Exposure".to_string(),
                    severity: Severity::Low,
                    category: "security".to_string(),
                    description: "Hardcoded URL detected in WASM data - may expose endpoints".to_string(),
                    file_path: source_file.path.to_string_lossy().to_string(),
                    line_number: line_num,
                    column: captures.get(0).map(|m| m.start()).unwrap_or(0),
                    source_code: trimmed_line.to_string(),
                    recommendation: "Use configuration files or environment variables for URLs".to_string(),
                });
            }

            // Check for variable-time crypto operations
            if let Some(captures) = WASM_PATTERNS["variable_time_crypto"].captures(line) {
                vulnerabilities.push(Vulnerability {
                    id: "WASM-TIMING-001".to_string(),
                    cwe: Some("CWE-208".to_string()),
                    vulnerability_type: "Timing Attack Vulnerability".to_string(),
                    severity: Severity::High,
                    category: "cryptographic".to_string(),
                    description: "Variable-time operation on cryptographic data - vulnerable to timing attacks".to_string(),
                    file_path: source_file.path.to_string_lossy().to_string(),
                    line_number: line_num,
                    column: captures.get(0).map(|m| m.start()).unwrap_or(0),
                    source_code: trimmed_line.to_string(),
                    recommendation: "Use constant-time operations for cryptographic computations".to_string(),
                });
            }

            // Check for large memory allocation
            if let Some(captures) = WASM_PATTERNS["large_memory_allocation"].captures(line) {
                vulnerabilities.push(Vulnerability {
                    id: "WASM-RESOURCE-001".to_string(),
                    cwe: Some("CWE-770".to_string()),
                    vulnerability_type: "Resource Exhaustion".to_string(),
                    severity: Severity::Medium,
                    category: "vulnerability".to_string(),
                    description: "Large memory allocation detected - may lead to resource exhaustion".to_string(),
                    file_path: source_file.path.to_string_lossy().to_string(),
                    line_number: line_num,
                    column: captures.get(0).map(|m| m.start()).unwrap_or(0),
                    source_code: trimmed_line.to_string(),
                    recommendation: "Implement memory limits and validate allocation sizes".to_string(),
                });
            }

            // Check for performance.now timing imports
            if let Some(captures) = WASM_PATTERNS["performance_now_timing"].captures(line) {
                vulnerabilities.push(Vulnerability {
                    id: "WASM-TIMING-002".to_string(),
                    cwe: Some("CWE-208".to_string()),
                    vulnerability_type: "High-Resolution Timing".to_string(),
                    severity: Severity::Medium,
                    category: "security".to_string(),
                    description: "High-resolution timing import - may enable timing-based side-channel attacks".to_string(),
                    file_path: source_file.path.to_string_lossy().to_string(),
                    line_number: line_num,
                    column: captures.get(0).map(|m| m.start()).unwrap_or(0),
                    source_code: trimmed_line.to_string(),
                    recommendation: "Consider using lower-resolution timing or add timing jitter for security-sensitive operations".to_string(),
                });
            }
        }

        Ok(vulnerabilities)
    }
}

impl Default for WasmRules {
    fn default() -> Self {
        Self::new()
    }
}

impl RuleSet for WasmRules {
    fn analyze(&self, source_file: &SourceFile, _ast: &ParsedAst) -> Result<Vec<Vulnerability>> {
        self.analyze_source(source_file)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::Language;
    use std::path::PathBuf;

    #[test]
    fn test_wasm_memory_growth_detection() {
        let rules = WasmRules::new();
        let source_file = SourceFile {
            path: PathBuf::from("test.wat"),
            content: r#"
(module
  (memory 1)
  (func $grow
    i32.const 100
    memory.grow
    drop
  )
)
"#.to_string(),
            language: Language::Wasm,
        };

        let result = rules.analyze_source(&source_file).unwrap();
        assert!(result.iter().any(|v| v.id == "WASM-MEM-001"));
    }

    #[test]
    fn test_wasm_dangerous_imports_detection() {
        let rules = WasmRules::new();
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

        let result = rules.analyze_source(&source_file).unwrap();
        assert!(result.iter().any(|v| v.id == "WASM-IMPORT-001"));
        assert!(result.iter().any(|v| v.id == "WASM-IMPORT-002"));
    }

    #[test]
    fn test_wasm_hardcoded_secrets_detection() {
        let rules = WasmRules::new();
        let source_file = SourceFile {
            path: PathBuf::from("test.wat"),
            content: r#"
(module
  (data (i32.const 0) "api_key_secret_12345")
  (memory 1)
)
"#.to_string(),
            language: Language::Wasm,
        };

        let result = rules.analyze_source(&source_file).unwrap();
        assert!(result.iter().any(|v| v.id == "WASM-SECRET-001"));
    }

    #[test]
    fn test_wasm_timing_attack_detection() {
        let rules = WasmRules::new();
        let source_file = SourceFile {
            path: PathBuf::from("test.wat"),
            content: r#"
(module
  (func $crypto_check (param $password i32) (result i32)
    local.get $password
    i32.const 0
    select  ;; Variable-time operation on password
  )
)
"#.to_string(),
            language: Language::Wasm,
        };

        let result = rules.analyze_source(&source_file).unwrap();
        assert!(result.iter().any(|v| v.id == "WASM-TIMING-001"));
    }
}