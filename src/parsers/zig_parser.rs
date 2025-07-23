/// Zig Language Parser for DeVAIC
/// 
/// This module provides parsing support for Zig programming language files.
/// Zig is a general-purpose programming language and toolchain for maintaining
/// robust, optimal, and reusable software.
/// 
/// Security concerns for Zig include:
/// - Memory safety despite manual memory management
/// - Undefined behavior detection and prevention
/// - Compile-time safety analysis
/// - Integer overflow and underflow detection
/// - Cross-platform security considerations
/// - Allocator security and resource management

use crate::parsers::{SourceFile, ParsedAst, AstMetadata, Parser};
use crate::{Language, Vulnerability, Severity};
use crate::error::Result;
use std::collections::HashMap;
use regex::Regex;

/// Zig-specific parser implementation
pub struct ZigParser {
    /// Common Zig security patterns for analysis
    patterns: HashMap<String, Regex>,
}

impl ZigParser {
    pub fn new() -> Self {
        let mut patterns = HashMap::new();
        
        // Initialize Zig security patterns
        
        // Memory safety patterns
        patterns.insert(
            "unsafe_memory_access".to_string(),
            Regex::new(r"(?i)\b@ptrCast\s*\(").unwrap()
        );
        
        patterns.insert(
            "undefined_behavior".to_string(),
            Regex::new(r"(?i)\bundefined\b").unwrap()
        );
        
        patterns.insert(
            "unreachable_code".to_string(),
            Regex::new(r"(?i)\bunreachable\b").unwrap()
        );
        
        // Allocator security patterns
        patterns.insert(
            "unsafe_allocator_usage".to_string(),
            Regex::new(r"(?i)allocator\.(?:alloc|realloc|free)\s*\(").unwrap()
        );
        
        patterns.insert(
            "memory_leak_risk".to_string(),
            Regex::new(r"(?i)allocator\.alloc\s*\(").unwrap()
        );
        
        // Integer overflow patterns
        patterns.insert(
            "integer_overflow_risk".to_string(),
            Regex::new(r"(?i)\+%|\*%|-%").unwrap()
        );
        
        patterns.insert(
            "unchecked_arithmetic".to_string(),
            Regex::new(r"(?i)@addWithOverflow|@subWithOverflow|@mulWithOverflow").unwrap()
        );
        
        // Unsafe operations
        patterns.insert(
            "unsafe_pointer_arithmetic".to_string(),
            Regex::new(r"(?i)@ptrToInt|@intToPtr").unwrap()
        );
        
        patterns.insert(
            "unsafe_cast".to_string(),
            Regex::new(r"(?i)@bitCast|@ptrCast|@intCast").unwrap()
        );
        
        // Error handling patterns
        patterns.insert(
            "ignored_error".to_string(),
            Regex::new(r"(?i)catch\s+\|[^|]*\|\s*\{\s*\}").unwrap()
        );
        
        patterns.insert(
            "unsafe_unwrap".to_string(),
            Regex::new(r"(?i)\.\?|\bunwrap\b").unwrap()
        );
        
        // Compile-time safety
        patterns.insert(
            "comptime_unsafe".to_string(),
            Regex::new(r"(?i)comptime\s+.*@ptrCast").unwrap()
        );
        
        // Cross-platform security
        patterns.insert(
            "platform_specific_unsafe".to_string(),
            Regex::new(r"(?i)@cImport|@cInclude").unwrap()
        );
        
        // Hardcoded values
        patterns.insert(
            "hardcoded_secrets".to_string(),
            Regex::new(r#"(?i)(?:password|secret|key|token|api[_-]?key)\s*=\s*"[^"]{8,}""#).unwrap()
        );
        
        // File operations
        patterns.insert(
            "unsafe_file_operations".to_string(),
            Regex::new(r"(?i)std\.fs\.(?:createFile|openFile|deleteFile)").unwrap()
        );
        
        // Network operations
        patterns.insert(
            "unsafe_network".to_string(),
            Regex::new(r"(?i)std\.net\.(?:tcpConnectToHost|tcpConnectToAddress)").unwrap()
        );
        
        // Testing and debug code
        patterns.insert(
            "debug_code".to_string(),
            Regex::new(r"(?i)std\.debug\.(?:print|warn|panic)").unwrap()
        );

        Self { patterns }
    }

    /// Parse Zig source code and extract AST information
    pub fn parse(&self, source_file: &SourceFile) -> Result<ParsedAst> {
        let start_time = std::time::Instant::now();
        
        let mut metadata = AstMetadata::default();
        metadata.parse_time_ms = Some(start_time.elapsed().as_millis() as u64);
        
        Ok(ParsedAst {
            tree: None, // No AST tree for pattern-based parsing
            source: source_file.content.clone(),
            language: Some(Language::Zig),
            parse_errors: Vec::new(),
            metadata,
        })
    }

    /// Analyze Zig code for security vulnerabilities
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
                    id: "ZIG-MEM-001".to_string(),
                    cwe: Some("CWE-119".to_string()),
                    vulnerability_type: "Unsafe Memory Access".to_string(),
                    severity: Severity::High,
                    category: "vulnerability".to_string(),
                    description: "Unsafe pointer cast detected - may lead to memory corruption".to_string(),
                    file_path: source_file.path.to_string_lossy().to_string(),
                    line_number: line_num,
                    column: captures.get(0).map(|m| m.start()).unwrap_or(0),
                    source_code: trimmed_line.to_string(),
                    recommendation: "Use safe alternatives or add proper bounds checking and validation".to_string(),
                });
            }

            // Check for undefined behavior
            if let Some(captures) = self.patterns["undefined_behavior"].captures(line) {
                vulnerabilities.push(Vulnerability {
                    id: "ZIG-UB-001".to_string(),
                    cwe: Some("CWE-758".to_string()),
                    vulnerability_type: "Undefined Behavior".to_string(),
                    severity: Severity::Critical,
                    category: "vulnerability".to_string(),
                    description: "Undefined behavior detected - unpredictable program behavior".to_string(),
                    file_path: source_file.path.to_string_lossy().to_string(),
                    line_number: line_num,
                    column: captures.get(0).map(|m| m.start()).unwrap_or(0),
                    source_code: trimmed_line.to_string(),
                    recommendation: "Replace undefined behavior with safe alternatives or proper error handling".to_string(),
                });
            }

            // Check for unsafe allocator usage
            if let Some(captures) = self.patterns["unsafe_allocator_usage"].captures(line) {
                vulnerabilities.push(Vulnerability {
                    id: "ZIG-ALLOC-001".to_string(),
                    cwe: Some("CWE-401".to_string()),
                    vulnerability_type: "Memory Management Issue".to_string(),
                    severity: Severity::Medium,
                    category: "vulnerability".to_string(),
                    description: "Direct allocator usage without defer - potential memory leak".to_string(),
                    file_path: source_file.path.to_string_lossy().to_string(),
                    line_number: line_num,
                    column: captures.get(0).map(|m| m.start()).unwrap_or(0),
                    source_code: trimmed_line.to_string(),
                    recommendation: "Use defer or errdefer to ensure proper memory cleanup".to_string(),
                });
            }

            // Check for integer overflow risk
            if let Some(captures) = self.patterns["integer_overflow_risk"].captures(line) {
                vulnerabilities.push(Vulnerability {
                    id: "ZIG-INT-001".to_string(),
                    cwe: Some("CWE-190".to_string()),
                    vulnerability_type: "Integer Overflow".to_string(),
                    severity: Severity::Medium,
                    category: "vulnerability".to_string(),
                    description: "Wrapping arithmetic operation - potential integer overflow".to_string(),
                    file_path: source_file.path.to_string_lossy().to_string(),
                    line_number: line_num,
                    column: captures.get(0).map(|m| m.start()).unwrap_or(0),
                    source_code: trimmed_line.to_string(),
                    recommendation: "Use checked arithmetic or validate input ranges".to_string(),
                });
            }

            // Check for unsafe casts
            if let Some(captures) = self.patterns["unsafe_cast"].captures(line) {
                vulnerabilities.push(Vulnerability {
                    id: "ZIG-CAST-001".to_string(),
                    cwe: Some("CWE-704".to_string()),
                    vulnerability_type: "Unsafe Type Cast".to_string(),
                    severity: Severity::Medium,
                    category: "vulnerability".to_string(),
                    description: "Unsafe type cast detected - may cause data corruption".to_string(),
                    file_path: source_file.path.to_string_lossy().to_string(),
                    line_number: line_num,
                    column: captures.get(0).map(|m| m.start()).unwrap_or(0),
                    source_code: trimmed_line.to_string(),
                    recommendation: "Validate cast safety or use safe alternatives".to_string(),
                });
            }

            // Check for ignored errors
            if let Some(captures) = self.patterns["ignored_error"].captures(line) {
                vulnerabilities.push(Vulnerability {
                    id: "ZIG-ERROR-001".to_string(),
                    cwe: Some("CWE-252".to_string()),
                    vulnerability_type: "Unchecked Error Condition".to_string(),
                    severity: Severity::Medium,
                    category: "vulnerability".to_string(),
                    description: "Error ignored in catch block - may hide failures".to_string(),
                    file_path: source_file.path.to_string_lossy().to_string(),
                    line_number: line_num,
                    column: captures.get(0).map(|m| m.start()).unwrap_or(0),
                    source_code: trimmed_line.to_string(),
                    recommendation: "Handle errors appropriately or log for debugging".to_string(),
                });
            }

            // Check for hardcoded secrets
            if let Some(captures) = self.patterns["hardcoded_secrets"].captures(line) {
                vulnerabilities.push(Vulnerability {
                    id: "ZIG-SECRET-001".to_string(),
                    cwe: Some("CWE-798".to_string()),
                    vulnerability_type: "Hardcoded Credentials".to_string(),
                    severity: Severity::Critical,
                    category: "authentication".to_string(),
                    description: "Hardcoded secret detected in Zig code".to_string(),
                    file_path: source_file.path.to_string_lossy().to_string(),
                    line_number: line_num,
                    column: captures.get(0).map(|m| m.start()).unwrap_or(0),
                    source_code: trimmed_line.to_string(),
                    recommendation: "Move secrets to environment variables or secure configuration".to_string(),
                });
            }

            // Check for unsafe file operations
            if let Some(captures) = self.patterns["unsafe_file_operations"].captures(line) {
                vulnerabilities.push(Vulnerability {
                    id: "ZIG-FILE-001".to_string(),
                    cwe: Some("CWE-22".to_string()),
                    vulnerability_type: "Path Traversal Risk".to_string(),
                    severity: Severity::High,
                    category: "security".to_string(),
                    description: "File operation without path validation - path traversal risk".to_string(),
                    file_path: source_file.path.to_string_lossy().to_string(),
                    line_number: line_num,
                    column: captures.get(0).map(|m| m.start()).unwrap_or(0),
                    source_code: trimmed_line.to_string(),
                    recommendation: "Validate and sanitize file paths before operations".to_string(),
                });
            }

            // Check for debug code
            if let Some(captures) = self.patterns["debug_code"].captures(line) {
                vulnerabilities.push(Vulnerability {
                    id: "ZIG-DEBUG-001".to_string(),
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

    /// Check if this is a valid Zig file
    pub fn is_zig_file(file_path: &std::path::Path) -> bool {
        if let Some(ext) = file_path.extension() {
            if let Some(ext_str) = ext.to_str() {
                ext_str.to_lowercase() == "zig"
            } else {
                false
            }
        } else {
            false
        }
    }
}

impl Default for ZigParser {
    fn default() -> Self {
        Self::new()
    }
}

impl Parser for ZigParser {
    fn parse(&mut self, source_file: &SourceFile) -> Result<ParsedAst> {
        ZigParser::parse(self, source_file)
    }

    fn language(&self) -> Language {
        Language::Zig
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::Language;
    use std::path::PathBuf;

    #[test]
    fn test_zig_parser_basic() {
        let parser = ZigParser::new();
        let source_file = SourceFile {
            path: PathBuf::from("test.zig"),
            content: r#"
const std = @import("std");

pub fn main() void {
    var ptr = @ptrCast(*u32, some_ptr);
    const result = undefined;
    std.debug.print("Debug info\n", .{});
}
"#.to_string(),
            language: Language::Zig,
        };

        let result = parser.analyze_security(&source_file);
        assert!(result.is_ok());
        let vulnerabilities = result.unwrap();
        assert!(!vulnerabilities.is_empty());
    }

    #[test]
    fn test_zig_memory_safety() {
        let parser = ZigParser::new();
        let source_file = SourceFile {
            path: PathBuf::from("test.zig"),
            content: r#"
const allocator = std.heap.page_allocator;
const memory = allocator.alloc(u8, 1024);
// Missing defer allocator.free(memory);
"#.to_string(),
            language: Language::Zig,
        };

        let result = parser.analyze_security(&source_file);
        assert!(result.is_ok());
        let vulnerabilities = result.unwrap();
        assert!(vulnerabilities.iter().any(|v| v.id == "ZIG-ALLOC-001"));
    }

    #[test]
    fn test_zig_file_detection() {
        assert!(ZigParser::is_zig_file(&PathBuf::from("test.zig")));
        assert!(!ZigParser::is_zig_file(&PathBuf::from("test.rs")));
    }
}