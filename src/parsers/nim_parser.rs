/// Nim Language Parser for DeVAIC
/// 
/// This module provides parsing support for Nim programming language files.
/// Nim is a statically typed compiled systems programming language. 
/// It combines successful concepts from mature languages like Python, Ada and Modula.
/// 
/// Security concerns for Nim include:
/// - Memory safety with garbage collection and manual memory management options
/// - FFI (Foreign Function Interface) safety with C/C++
/// - Macro system security and code generation
/// - Compile-time evaluation security
/// - Thread safety and concurrency
/// - Template and generic programming security
/// - Package management security

use crate::parsers::{SourceFile, ParsedAst, AstMetadata, Parser};
use crate::{Language, Vulnerability, Severity};
use crate::error::Result;
use std::collections::HashMap;
use regex::Regex;

/// Nim-specific parser implementation
pub struct NimParser {
    /// Common Nim security patterns for analysis
    patterns: HashMap<String, Regex>,
}

impl NimParser {
    pub fn new() -> Self {
        let mut patterns = HashMap::new();
        
        // Initialize Nim security patterns
        
        // Memory safety patterns
        patterns.insert(
            "unsafe_memory_access".to_string(),
            Regex::new(r"(?i)\bunsafeAddr\b|\bcast\[|\bunsafeNew\b").unwrap()
        );
        
        patterns.insert(
            "manual_memory_management".to_string(),
            Regex::new(r"(?i)\balloc\b|\bdealloc\b|\brealloc\b").unwrap()
        );
        
        patterns.insert(
            "ptr_arithmetic".to_string(),
            Regex::new(r"(?i)ptr\s+[A-Za-z_][A-Za-z0-9_]*\s*\+|\bptr\b.*\+").unwrap()
        );
        
        // FFI security patterns
        patterns.insert(
            "unsafe_c_interop".to_string(),
            Regex::new(r"(?i)\{\.(?:importc|exportc|cdecl|stdcall)\.\}").unwrap()
        );
        
        patterns.insert(
            "external_library_call".to_string(),
            Regex::new(r"(?i)\{\.(?:dynlib|link)\.\}").unwrap()
        );
        
        // Macro system security
        patterns.insert(
            "unsafe_macro_usage".to_string(),
            Regex::new(r"(?i)macro\s+[A-Za-z_][A-Za-z0-9_]*.*=\s*quote").unwrap()
        );
        
        patterns.insert(
            "compile_time_eval".to_string(),
            Regex::new(r#"(?i)\{\.compile:\s*".*"\.\}"#).unwrap()
        );
        
        // Threading and concurrency
        patterns.insert(
            "unsafe_threading".to_string(),
            Regex::new(r"(?i)\{\.thread\.\}|\{\.gcsafe\.\}").unwrap()
        );
        
        patterns.insert(
            "shared_memory_access".to_string(),
            Regex::new(r"(?i)var\s+[A-Za-z_][A-Za-z0-9_]*\s*\{\.global\.\}").unwrap()
        );
        
        // Template security
        patterns.insert(
            "unsafe_template".to_string(),
            Regex::new(r"(?i)template\s+[A-Za-z_][A-Za-z0-9_]*.*=.*untyped").unwrap()
        );
        
        // Error handling
        patterns.insert(
            "ignored_exception".to_string(),
            Regex::new(r"(?i)try:\s*.*except\s*:\s*discard").unwrap()
        );
        
        patterns.insert(
            "unsafe_assert".to_string(),
            Regex::new(r"(?i)assert\s+false").unwrap()
        );
        
        // File operations
        patterns.insert(
            "unsafe_file_operations".to_string(),
            Regex::new(r"(?i)(?:open|readFile|writeFile|removeFile)\s*\([^)]*&").unwrap()
        );
        
        patterns.insert(
            "path_traversal_risk".to_string(),
            Regex::new(r"(?i)\.\.[\\/]").unwrap()
        );
        
        // Network security
        patterns.insert(
            "unsafe_network".to_string(),
            Regex::new(r"(?i)newSocket\s*\([^)]*verify\s*=\s*false").unwrap()
        );
        
        // String operations
        patterns.insert(
            "buffer_overflow_risk".to_string(),
            Regex::new(r"(?i)copyMem\s*\(|moveMem\s*\(|zeroMem\s*\(").unwrap()
        );
        
        // Hardcoded secrets
        patterns.insert(
            "hardcoded_secrets".to_string(),
            Regex::new(r#"(?i)(?:password|secret|key|token|api[_-]?key)\s*=\s*"[^"]{8,}""#).unwrap()
        );
        
        // Debug and development patterns
        patterns.insert(
            "debug_code".to_string(),
            Regex::new(r"(?i)(?:echo|debugEcho|dump)\s*\(").unwrap()
        );
        
        patterns.insert(
            "debug_pragma".to_string(),
            Regex::new(r"(?i)\{\.(?:debugger|lineTrace)\.\}").unwrap()
        );
        
        // Unsafe pragmas
        patterns.insert(
            "unsafe_pragma".to_string(),
            Regex::new(r"(?i)\{\.(?:checks:off|optimization:none|boundchecks:off)\.\}").unwrap()
        );
        
        // Command execution
        patterns.insert(
            "command_injection".to_string(),
            Regex::new(r"(?i)(?:execCmd|execProcess|startProcess)\s*\([^)]*&").unwrap()
        );
        
        // Serialization security
        patterns.insert(
            "unsafe_serialization".to_string(),
            Regex::new(r"(?i)(?:marshal|unmarshal|parseJson)\s*\(").unwrap()
        );
        
        // Generic programming security
        patterns.insert(
            "unconstrained_generic".to_string(),
            Regex::new(r"(?i)proc\s+[A-Za-z_][A-Za-z0-9_]*\s*\[\s*[A-Za-z_][A-Za-z0-9_]*\s*\]").unwrap()
        );

        Self { patterns }
    }

    /// Parse Nim source code and extract AST information
    pub fn parse(&self, source_file: &SourceFile) -> Result<ParsedAst> {
        let start_time = std::time::Instant::now();
        
        let mut metadata = AstMetadata::default();
        metadata.parse_time_ms = Some(start_time.elapsed().as_millis() as u64);
        
        Ok(ParsedAst {
            tree: None, // No AST tree for pattern-based parsing
            source: source_file.content.clone(),
            language: Some(Language::Nim),
            parse_errors: Vec::new(),
            metadata,
        })
    }

    /// Analyze Nim code for security vulnerabilities
    pub fn analyze_security(&self, source_file: &SourceFile) -> Result<Vec<Vulnerability>> {
        let mut vulnerabilities = Vec::new();
        let lines: Vec<&str> = source_file.content.lines().collect();

        for (line_number, line) in lines.iter().enumerate() {
            let line_num = line_number + 1;
            let trimmed_line = line.trim();

            // Skip empty lines and comments
            if trimmed_line.is_empty() || trimmed_line.starts_with("#") {
                continue;
            }

            // Check for unsafe memory access
            if let Some(captures) = self.patterns["unsafe_memory_access"].captures(line) {
                vulnerabilities.push(Vulnerability {
                    id: "NIM-MEM-001".to_string(),
                    cwe: Some("CWE-119".to_string()),
                    vulnerability_type: "Unsafe Memory Access".to_string(),
                    severity: Severity::High,
                    category: "vulnerability".to_string(),
                    description: "Unsafe memory operation detected - potential memory corruption".to_string(),
                    file_path: source_file.path.to_string_lossy().to_string(),
                    line_number: line_num,
                    column: captures.get(0).map(|m| m.start()).unwrap_or(0),
                    source_code: trimmed_line.to_string(),
                    recommendation: "Use safe memory operations or add proper bounds checking".to_string(),
                });
            }

            // Check for unsafe C interop
            if let Some(captures) = self.patterns["unsafe_c_interop"].captures(line) {
                vulnerabilities.push(Vulnerability {
                    id: "NIM-FFI-001".to_string(),
                    cwe: Some("CWE-829".to_string()),
                    vulnerability_type: "Unsafe C Interop".to_string(),
                    severity: Severity::High,
                    category: "security".to_string(),
                    description: "C interop detected - potential security risks from external code".to_string(),
                    file_path: source_file.path.to_string_lossy().to_string(),
                    line_number: line_num,
                    column: captures.get(0).map(|m| m.start()).unwrap_or(0),
                    source_code: trimmed_line.to_string(),
                    recommendation: "Validate C function calls and ensure input sanitization".to_string(),
                });
            }

            // Check for unsafe macro usage
            if let Some(captures) = self.patterns["unsafe_macro_usage"].captures(line) {
                vulnerabilities.push(Vulnerability {
                    id: "NIM-MACRO-001".to_string(),
                    cwe: Some("CWE-94".to_string()),
                    vulnerability_type: "Code Injection via Macros".to_string(),
                    severity: Severity::Medium,
                    category: "security".to_string(),
                    description: "Unsafe macro usage - potential code injection risk".to_string(),
                    file_path: source_file.path.to_string_lossy().to_string(),
                    line_number: line_num,
                    column: captures.get(0).map(|m| m.start()).unwrap_or(0),
                    source_code: trimmed_line.to_string(),
                    recommendation: "Validate macro inputs and use typed alternatives where possible".to_string(),
                });
            }

            // Check for unsafe threading
            if let Some(captures) = self.patterns["unsafe_threading"].captures(line) {
                vulnerabilities.push(Vulnerability {
                    id: "NIM-THREAD-001".to_string(),
                    cwe: Some("CWE-362".to_string()),
                    vulnerability_type: "Race Condition".to_string(),
                    severity: Severity::High,
                    category: "vulnerability".to_string(),
                    description: "Threading pragma detected - potential race condition risk".to_string(),
                    file_path: source_file.path.to_string_lossy().to_string(),
                    line_number: line_num,
                    column: captures.get(0).map(|m| m.start()).unwrap_or(0),
                    source_code: trimmed_line.to_string(),
                    recommendation: "Use proper synchronization mechanisms and thread-safe operations".to_string(),
                });
            }

            // Check for unsafe file operations
            if let Some(captures) = self.patterns["unsafe_file_operations"].captures(line) {
                vulnerabilities.push(Vulnerability {
                    id: "NIM-FILE-001".to_string(),
                    cwe: Some("CWE-22".to_string()),
                    vulnerability_type: "Path Traversal".to_string(),
                    severity: Severity::High,
                    category: "security".to_string(),
                    description: "File operation with dynamic path - path traversal risk".to_string(),
                    file_path: source_file.path.to_string_lossy().to_string(),
                    line_number: line_num,
                    column: captures.get(0).map(|m| m.start()).unwrap_or(0),
                    source_code: trimmed_line.to_string(),
                    recommendation: "Validate and sanitize file paths before operations".to_string(),
                });
            }

            // Check for buffer overflow risks
            if let Some(captures) = self.patterns["buffer_overflow_risk"].captures(line) {
                vulnerabilities.push(Vulnerability {
                    id: "NIM-BUF-001".to_string(),
                    cwe: Some("CWE-120".to_string()),
                    vulnerability_type: "Buffer Overflow".to_string(),
                    severity: Severity::High,
                    category: "vulnerability".to_string(),
                    description: "Memory copy operation - potential buffer overflow".to_string(),
                    file_path: source_file.path.to_string_lossy().to_string(),
                    line_number: line_num,
                    column: captures.get(0).map(|m| m.start()).unwrap_or(0),
                    source_code: trimmed_line.to_string(),
                    recommendation: "Use safe memory operations with bounds checking".to_string(),
                });
            }

            // Check for hardcoded secrets
            if let Some(captures) = self.patterns["hardcoded_secrets"].captures(line) {
                vulnerabilities.push(Vulnerability {
                    id: "NIM-SECRET-001".to_string(),
                    cwe: Some("CWE-798".to_string()),
                    vulnerability_type: "Hardcoded Credentials".to_string(),
                    severity: Severity::Critical,
                    category: "authentication".to_string(),
                    description: "Hardcoded secret detected in Nim code".to_string(),
                    file_path: source_file.path.to_string_lossy().to_string(),
                    line_number: line_num,
                    column: captures.get(0).map(|m| m.start()).unwrap_or(0),
                    source_code: trimmed_line.to_string(),
                    recommendation: "Move secrets to environment variables or secure configuration".to_string(),
                });
            }

            // Check for command injection
            if let Some(captures) = self.patterns["command_injection"].captures(line) {
                vulnerabilities.push(Vulnerability {
                    id: "NIM-CMD-001".to_string(),
                    cwe: Some("CWE-78".to_string()),
                    vulnerability_type: "Command Injection".to_string(),
                    severity: Severity::Critical,
                    category: "security".to_string(),
                    description: "Command execution with dynamic input - command injection risk".to_string(),
                    file_path: source_file.path.to_string_lossy().to_string(),
                    line_number: line_num,
                    column: captures.get(0).map(|m| m.start()).unwrap_or(0),
                    source_code: trimmed_line.to_string(),
                    recommendation: "Validate and sanitize command arguments or use safe alternatives".to_string(),
                });
            }

            // Check for unsafe pragmas
            if let Some(captures) = self.patterns["unsafe_pragma"].captures(line) {
                vulnerabilities.push(Vulnerability {
                    id: "NIM-PRAGMA-001".to_string(),
                    cwe: Some("CWE-665".to_string()),
                    vulnerability_type: "Unsafe Configuration".to_string(),
                    severity: Severity::Medium,
                    category: "security".to_string(),
                    description: "Unsafe pragma detected - disables important safety checks".to_string(),
                    file_path: source_file.path.to_string_lossy().to_string(),
                    line_number: line_num,
                    column: captures.get(0).map(|m| m.start()).unwrap_or(0),
                    source_code: trimmed_line.to_string(),
                    recommendation: "Enable safety checks in production code".to_string(),
                });
            }

            // Check for ignored exceptions
            if let Some(captures) = self.patterns["ignored_exception"].captures(line) {
                vulnerabilities.push(Vulnerability {
                    id: "NIM-ERROR-001".to_string(),
                    cwe: Some("CWE-252".to_string()),
                    vulnerability_type: "Unchecked Error Condition".to_string(),
                    severity: Severity::Medium,
                    category: "vulnerability".to_string(),
                    description: "Exception ignored - may hide failures".to_string(),
                    file_path: source_file.path.to_string_lossy().to_string(),
                    line_number: line_num,
                    column: captures.get(0).map(|m| m.start()).unwrap_or(0),
                    source_code: trimmed_line.to_string(),
                    recommendation: "Handle exceptions appropriately or log for debugging".to_string(),
                });
            }

            // Check for debug code
            if let Some(captures) = self.patterns["debug_code"].captures(line) {
                vulnerabilities.push(Vulnerability {
                    id: "NIM-DEBUG-001".to_string(),
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
        }

        Ok(vulnerabilities)
    }

    /// Check if this is a valid Nim file
    pub fn is_nim_file(file_path: &std::path::Path) -> bool {
        if let Some(ext) = file_path.extension() {
            if let Some(ext_str) = ext.to_str() {
                matches!(ext_str.to_lowercase().as_str(), "nim" | "nims" | "nimble")
            } else {
                false
            }
        } else {
            false
        }
    }
}

impl Default for NimParser {
    fn default() -> Self {
        Self::new()
    }
}

impl Parser for NimParser {
    fn parse(&mut self, source_file: &SourceFile) -> Result<ParsedAst> {
        NimParser::parse(self, source_file)
    }

    fn language(&self) -> Language {
        Language::Nim
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::Language;
    use std::path::PathBuf;

    #[test]
    fn test_nim_parser_basic() {
        let parser = NimParser::new();
        let source_file = SourceFile {
            path: PathBuf::from("test.nim"),
            content: r#"
import os, strutils

proc unsafeFunction() =
    var ptr = cast[ptr int](unsafeAddr(someVar))
    let secret = "api_key_12345_secret"
    echo "Debug: ", secret

{.checks:off.}
proc compileTimeUnsafe() {.importc.} =
    copyMem(dest, src, 1024)
"#.to_string(),
            language: Language::Nim,
        };

        let result = parser.analyze_security(&source_file);
        assert!(result.is_ok());
        let vulnerabilities = result.unwrap();
        assert!(!vulnerabilities.is_empty());
    }

    #[test]
    fn test_nim_memory_safety() {
        let parser = NimParser::new();
        let source_file = SourceFile {
            path: PathBuf::from("test.nim"),
            content: r#"
proc memoryUnsafe() =
    let allocMem = alloc(1024)
    # Missing dealloc
    var dangerousPtr = cast[ptr int](allocMem)
"#.to_string(),
            language: Language::Nim,
        };

        let result = parser.analyze_security(&source_file);
        assert!(result.is_ok());
        let vulnerabilities = result.unwrap();
        assert!(vulnerabilities.iter().any(|v| v.id == "NIM-MEM-001"));
    }

    #[test]
    fn test_nim_file_detection() {
        assert!(NimParser::is_nim_file(&PathBuf::from("test.nim")));
        assert!(NimParser::is_nim_file(&PathBuf::from("config.nims")));
        assert!(NimParser::is_nim_file(&PathBuf::from("package.nimble")));
        assert!(!NimParser::is_nim_file(&PathBuf::from("test.rs")));
    }
}