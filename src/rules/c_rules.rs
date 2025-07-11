use super::{create_vulnerability, RuleSet};
use crate::{
    error::Result,
    parsers::{ParsedAst, SourceFile},
    Severity, Vulnerability,
};
use regex::Regex;
use tree_sitter::Node;

pub struct CRules {
    buffer_overflow_patterns: Vec<Regex>,
    format_string_patterns: Vec<Regex>,
    unsafe_functions: Vec<&'static str>,
}

impl CRules {
    pub fn new() -> Self {
        Self {
            buffer_overflow_patterns: vec![
                Regex::new(r"\bstrcpy\s*\(").unwrap(),
                Regex::new(r"\bstrcat\s*\(").unwrap(),
                Regex::new(r"\bsprintf\s*\(").unwrap(),
                Regex::new(r"\bgets\s*\(").unwrap(),
            ],
            format_string_patterns: vec![
                Regex::new(r"\bprintf\s*\(\s*[^,)]*\s*\)").unwrap(),
                Regex::new(r"\bfprintf\s*\(\s*[^,)]*\s*,\s*[^,)]*\s*\)").unwrap(),
            ],
            unsafe_functions: vec![
                "strcpy", "strcat", "sprintf", "gets", "scanf", "vsprintf",
                "strncpy", "strncat", "snprintf", "vsnprintf",
            ],
        }
    }

    fn check_buffer_overflow(&self, source_file: &SourceFile, ast: &ParsedAst) -> Result<Vec<Vulnerability>> {
        let mut vulnerabilities = Vec::new();
        let lines: Vec<&str> = ast.source.lines().collect();

        for (line_num, line) in lines.iter().enumerate() {
            for pattern in &self.buffer_overflow_patterns {
                if pattern.is_match(line) {
                    vulnerabilities.push(create_vulnerability(
                        "C001",
                        Some("CWE-120"),
                        "Buffer Overflow",
                        Severity::High,
                        "injection",
                        "Potential buffer overflow vulnerability detected",
                        &source_file.path.to_string_lossy(),
                        line_num + 1,
                        0,
                        line,
                        "Use safe string functions like strncpy, strncat, or snprintf with proper bounds checking",
                    ));
                }
            }
        }

        Ok(vulnerabilities)
    }

    fn check_format_string(&self, source_file: &SourceFile, ast: &ParsedAst) -> Result<Vec<Vulnerability>> {
        let mut vulnerabilities = Vec::new();
        let lines: Vec<&str> = ast.source.lines().collect();

        for (line_num, line) in lines.iter().enumerate() {
            for pattern in &self.format_string_patterns {
                if pattern.is_match(line) {
                    vulnerabilities.push(create_vulnerability(
                        "C002",
                        Some("CWE-134"),
                        "Format String Vulnerability",
                        Severity::Medium,
                        "injection",
                        "Potential format string vulnerability detected",
                        &source_file.path.to_string_lossy(),
                        line_num + 1,
                        0,
                        line,
                        "Always use format specifiers with printf family functions",
                    ));
                }
            }
        }

        Ok(vulnerabilities)
    }

    fn check_integer_overflow(&self, source_file: &SourceFile, ast: &ParsedAst) -> Result<Vec<Vulnerability>> {
        let mut vulnerabilities = Vec::new();
        
        if let Some(root_node) = ast.root_node() {
            self.traverse_node(&root_node, &ast.source, |node, source_slice| {
            if node.kind() == "binary_expression" {
                if let Some(operator_node) = node.child_by_field_name("operator") {
                    let operator = &source_slice[operator_node.byte_range()];
                    if matches!(operator, "+" | "*" | "-") {
                        // Simple heuristic: check if we're dealing with user input
                        let expr_text = &source_slice[node.byte_range()];
                        if expr_text.contains("atoi") || expr_text.contains("scanf") {
                            let start_pos = node.start_position();
                            vulnerabilities.push(create_vulnerability(
                                "C003",
                                Some("CWE-190"),
                                "Integer Overflow",
                                Severity::Medium,
                                "validation",
                                "Potential integer overflow in arithmetic operation with user input",
                                &source_file.path.to_string_lossy(),
                                start_pos.row + 1,
                                start_pos.column,
                                expr_text,
                                "Validate input ranges and use safe arithmetic functions",
                            ));
                        }
                    }
                }
            }
            });
        }

        Ok(vulnerabilities)
    }

    fn check_null_pointer_dereference(&self, source_file: &SourceFile, ast: &ParsedAst) -> Result<Vec<Vulnerability>> {
        let mut vulnerabilities = Vec::new();
        
        if let Some(root_node) = ast.root_node() {
            self.traverse_node(&root_node, &ast.source, |node, source_slice| {
            // Look for pointer dereferences without null checks
            if node.kind() == "pointer_expression" {
                let start_pos = node.start_position();
                let expr_text = &source_slice[node.byte_range()];
                
                // Simple heuristic: if we see a dereference, check if there's a null check nearby
                let line_start = source_slice[..node.start_byte()]
                    .rfind('\n')
                    .map(|pos| pos + 1)
                    .unwrap_or(0);
                let line_end = source_slice[node.end_byte()..]
                    .find('\n')
                    .map(|pos| node.end_byte() + pos)
                    .unwrap_or(source_slice.len());
                
                let context = &source_slice[line_start..line_end];
                
                if !context.contains("if") && !context.contains("NULL") && !context.contains("nullptr") {
                    vulnerabilities.push(create_vulnerability(
                        "C004",
                        Some("CWE-476"),
                        "NULL Pointer Dereference",
                        Severity::High,
                        "validation",
                        "Potential null pointer dereference",
                        &source_file.path.to_string_lossy(),
                        start_pos.row + 1,
                        start_pos.column,
                        expr_text,
                        "Add null pointer checks before dereferencing pointers",
                    ));
                }
            }
            });
        }

        Ok(vulnerabilities)
    }

    fn check_unsafe_functions(&self, source_file: &SourceFile, ast: &ParsedAst) -> Result<Vec<Vulnerability>> {
        let mut vulnerabilities = Vec::new();
        let lines: Vec<&str> = ast.source.lines().collect();

        for (line_num, line) in lines.iter().enumerate() {
            for &unsafe_func in &self.unsafe_functions {
                if line.contains(unsafe_func) && line.contains("(") {
                    vulnerabilities.push(create_vulnerability(
                        "C005",
                        Some("CWE-120"),
                        "Unsafe Function Usage",
                        Severity::High,
                        "injection",
                        &format!("Usage of unsafe function: {}", unsafe_func),
                        &source_file.path.to_string_lossy(),
                        line_num + 1,
                        0,
                        line,
                        "Use safe alternatives like strncpy, strncat, snprintf, or fgets instead of unsafe C functions",
                    ));
                }
            }
        }

        Ok(vulnerabilities)
    }

    fn traverse_node<F>(&self, node: &Node, source: &str, mut callback: F)
    where
        F: FnMut(&Node, &str),
    {
        let mut cursor = node.walk();
        
        loop {
            callback(&cursor.node(), source);
            
            if cursor.goto_first_child() {
                continue;
            }
            
            if cursor.goto_next_sibling() {
                continue;
            }
            
            loop {
                if !cursor.goto_parent() {
                    return;
                }
                
                if cursor.goto_next_sibling() {
                    break;
                }
            }
        }
    }
}

impl RuleSet for CRules {
    fn analyze(&self, source_file: &SourceFile, ast: &ParsedAst) -> Result<Vec<Vulnerability>> {
        let mut all_vulnerabilities = Vec::new();

        all_vulnerabilities.extend(self.check_buffer_overflow(source_file, ast)?);
        all_vulnerabilities.extend(self.check_format_string(source_file, ast)?);
        all_vulnerabilities.extend(self.check_integer_overflow(source_file, ast)?);
        all_vulnerabilities.extend(self.check_null_pointer_dereference(source_file, ast)?);
        all_vulnerabilities.extend(self.check_unsafe_functions(source_file, ast)?);

        Ok(all_vulnerabilities)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{parsers::{c_parser::CParser, Parser}, Language};
    use std::path::PathBuf;

    #[test]
    fn test_buffer_overflow_detection() {
        let rules = CRules::new();
        let mut parser = CParser::new().unwrap();
        
        let source = r#"
#include <string.h>

void vulnerable_function(char* input) {
    char buffer[10];
    strcpy(buffer, input);  // Buffer overflow vulnerability
}
"#;
        
        let source_file = SourceFile::new(
            PathBuf::from("test.c"),
            source.to_string(),
            Language::C,
        );
        
        let ast = parser.parse(&source_file).unwrap();
        let vulnerabilities = rules.analyze(&source_file, &ast).unwrap();
        
        assert!(!vulnerabilities.is_empty());
        assert!(vulnerabilities.iter().any(|v| v.id == "C001"));
    }

    #[test]
    fn test_unsafe_functions_detection() {
        let rules = CRules::new();
        let mut parser = CParser::new().unwrap();
        
        let source = r#"
#include <stdio.h>
#include <string.h>

void vulnerable_function() {
    char buffer[100];
    gets(buffer);  // Unsafe function
    scanf("%s", buffer);  // Another unsafe function
}
"#;
        
        let source_file = SourceFile::new(
            PathBuf::from("test.c"),
            source.to_string(),
            Language::C,
        );
        
        let ast = parser.parse(&source_file).unwrap();
        let vulnerabilities = rules.analyze(&source_file, &ast).unwrap();
        
        assert!(!vulnerabilities.is_empty());
        assert!(vulnerabilities.iter().any(|v| v.id == "C005"));
    }
}