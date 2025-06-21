use super::{create_vulnerability, RuleSet};
use crate::{
    error::Result,
    parsers::{ParsedAst, SourceFile},
    Severity, Vulnerability,
};
use regex::Regex;
use tree_sitter::Node;

pub struct CppRules {
    memory_management_patterns: Vec<Regex>,
    unsafe_functions: Vec<Regex>,
    exception_safety_patterns: Vec<Regex>,
    smart_pointer_patterns: Vec<Regex>,
}

impl CppRules {
    pub fn new() -> Self {
        Self {
            memory_management_patterns: vec![
                Regex::new(r"\bnew\s+\w+(?:\s*\[.*?\])?\s*;").unwrap(),
                Regex::new(r"\bdelete\s+\w+\s*;").unwrap(),
                Regex::new(r"\bdelete\s*\[\s*\]\s*\w+\s*;").unwrap(),
                Regex::new(r"\bmalloc\s*\(").unwrap(),
                Regex::new(r"\bfree\s*\(").unwrap(),
            ],
            unsafe_functions: vec![
                Regex::new(r"\bstrcpy\s*\(").unwrap(),
                Regex::new(r"\bstrcat\s*\(").unwrap(),
                Regex::new(r"\bsprintf\s*\(").unwrap(),
                Regex::new(r"\bgets\s*\(").unwrap(),
                Regex::new(r"\bscanf\s*\(").unwrap(),
            ],
            exception_safety_patterns: vec![
                Regex::new(r"\bthrow\s+\w+\s*\(").unwrap(),
                Regex::new(r"\bcatch\s*\(\s*\.\.\.\s*\)").unwrap(),
            ],
            smart_pointer_patterns: vec![
                Regex::new(r"\bstd::unique_ptr\s*<.*?>\s*\(").unwrap(),
                Regex::new(r"\bstd::shared_ptr\s*<.*?>\s*\(").unwrap(),
                Regex::new(r"\bstd::weak_ptr\s*<.*?>\s*\(").unwrap(),
            ],
        }
    }

    fn check_memory_management(&self, source_file: &SourceFile, ast: &ParsedAst) -> Result<Vec<Vulnerability>> {
        let mut vulnerabilities = Vec::new();
        let lines: Vec<&str> = ast.source.lines().collect();
        
        let mut new_allocations = Vec::new();
        let mut delete_deallocations = Vec::new();

        for (line_num, line) in lines.iter().enumerate() {
            if line.contains("new ") && !line.contains("delete") {
                new_allocations.push((line_num, line));
            }
            if line.contains("delete ") {
                delete_deallocations.push((line_num, line));
            }

            for pattern in &self.memory_management_patterns {
                if pattern.is_match(line) {
                    if line.contains("new ") && !line.contains("std::") {
                        vulnerabilities.push(create_vulnerability(
                            "CPP001",
                            Some("CWE-401"),
                            "Memory Management Error",
                            Severity::High,
                            "cryptographic",
                            "Raw pointer allocation detected - consider using smart pointers",
                            &source_file.path.to_string_lossy(),
                            line_num + 1,
                            0,
                            line,
                            "Use std::unique_ptr, std::shared_ptr, or RAII patterns instead of raw new/delete",
                        ));
                    }
                    
                    if line.contains("malloc") || line.contains("free") {
                        vulnerabilities.push(create_vulnerability(
                            "CPP002",
                            Some("CWE-401"),
                            "Memory Management Error",
                            Severity::Medium,
                            "validation",
                            "C-style memory management in C++ code",
                            &source_file.path.to_string_lossy(),
                            line_num + 1,
                            0,
                            line,
                            "Use C++ memory management (new/delete) or preferably smart pointers",
                        ));
                    }
                }
            }
        }

        if new_allocations.len() != delete_deallocations.len() {
            vulnerabilities.push(create_vulnerability(
                "CPP003",
                Some("CWE-401"),
                "Memory Leak",
                Severity::High,
                "validation",
                "Potential memory leak - mismatched new/delete calls",
                &source_file.path.to_string_lossy(),
                1,
                0,
                "Memory allocation/deallocation mismatch",
                "Ensure every 'new' has a corresponding 'delete' or use RAII/smart pointers",
            ));
        }

        Ok(vulnerabilities)
    }

    fn check_unsafe_functions(&self, source_file: &SourceFile, ast: &ParsedAst) -> Result<Vec<Vulnerability>> {
        let mut vulnerabilities = Vec::new();
        let lines: Vec<&str> = ast.source.lines().collect();

        for (line_num, line) in lines.iter().enumerate() {
            for pattern in &self.unsafe_functions {
                if pattern.is_match(line) {
                    vulnerabilities.push(create_vulnerability(
                        "CPP004",
                        Some("CWE-120"),
                        "Buffer Overflow",
                        Severity::High,
                        "injection",
                        "Unsafe C function used in C++ code",
                        &source_file.path.to_string_lossy(),
                        line_num + 1,
                        0,
                        line,
                        "Use C++ standard library alternatives like std::string, std::vector, or safe C functions",
                    ));
                }
            }
        }

        Ok(vulnerabilities)
    }

    fn check_exception_safety(&self, source_file: &SourceFile, ast: &ParsedAst) -> Result<Vec<Vulnerability>> {
        let mut vulnerabilities = Vec::new();
        let lines: Vec<&str> = ast.source.lines().collect();

        for (line_num, line) in lines.iter().enumerate() {
            if line.contains("catch(...)") || line.contains("catch (...)") {
                vulnerabilities.push(create_vulnerability(
                    "CPP005",
                    Some("CWE-754"),
                    "Improper Check for Unusual Conditions",
                    Severity::Medium,
                    "logging",
                    "Generic exception catch block - potential information loss",
                    &source_file.path.to_string_lossy(),
                    line_num + 1,
                    0,
                    line,
                    "Catch specific exception types to handle errors appropriately",
                ));
            }

            if line.contains("throw ") && !line.contains("noexcept") {
                vulnerabilities.push(create_vulnerability(
                    "CPP006",
                    Some("CWE-755"),
                    "Improper Exception Handling",
                    Severity::Low,
                    "validation",
                    "Exception thrown without noexcept specification",
                    &source_file.path.to_string_lossy(),
                    line_num + 1,
                    0,
                    line,
                    "Consider using noexcept specification for functions that don't throw",
                ));
            }
        }

        Ok(vulnerabilities)
    }

    fn check_iterator_safety(&self, source_file: &SourceFile, ast: &ParsedAst) -> Result<Vec<Vulnerability>> {
        let mut vulnerabilities = Vec::new();
        
        if let Some(root_node) = ast.root_node() {
            self.traverse_node(&root_node, &ast.source, |node, source_slice| {
            if node.kind() == "call_expression" {
                let expr_text = &source_slice[node.byte_range()];
                
                if expr_text.contains(".erase(") || expr_text.contains(".remove(") {
                    let start_pos = node.start_position();
                    vulnerabilities.push(create_vulnerability(
                        "CPP007",
                        Some("CWE-416"),
                        "Use After Free",
                        Severity::Medium,
                        "validation",
                        "Potential iterator invalidation",
                        &source_file.path.to_string_lossy(),
                        start_pos.row + 1,
                        start_pos.column,
                        expr_text,
                        "Be careful with iterator invalidation when modifying containers",
                    ));
                }
                
                if expr_text.contains("std::find") && !expr_text.contains("!= ") {
                    let start_pos = node.start_position();
                    vulnerabilities.push(create_vulnerability(
                        "CPP008",
                        Some("CWE-252"),
                        "Unchecked Return Value",
                        Severity::Medium,
                        "validation",
                        "std::find result not checked against end() iterator",
                        &source_file.path.to_string_lossy(),
                        start_pos.row + 1,
                        start_pos.column,
                        expr_text,
                        "Always check if find() result equals container.end() before using",
                    ));
                }
            }
            });
        }

        Ok(vulnerabilities)
    }

    fn check_template_issues(&self, source_file: &SourceFile, ast: &ParsedAst) -> Result<Vec<Vulnerability>> {
        let mut vulnerabilities = Vec::new();
        let lines: Vec<&str> = ast.source.lines().collect();

        for (line_num, line) in lines.iter().enumerate() {
            if line.contains("static_cast") && line.contains("*") {
                vulnerabilities.push(create_vulnerability(
                    "CPP009",
                    Some("CWE-704"),
                    "Incorrect Type Conversion",
                    Severity::Medium,
                    "validation",
                    "Potentially unsafe static_cast with pointers",
                    &source_file.path.to_string_lossy(),
                    line_num + 1,
                    0,
                    line,
                    "Consider using dynamic_cast for polymorphic types or safer alternatives",
                ));
            }
            
            if line.contains("reinterpret_cast") {
                vulnerabilities.push(create_vulnerability(
                    "CPP010",
                    Some("CWE-704"),
                    "Incorrect Type Conversion",
                    Severity::High,
                    "validation",
                    "Dangerous reinterpret_cast usage",
                    &source_file.path.to_string_lossy(),
                    line_num + 1,
                    0,
                    line,
                    "reinterpret_cast is dangerous and should be avoided. Use safer alternatives",
                ));
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

impl RuleSet for CppRules {
    fn analyze(&self, source_file: &SourceFile, ast: &ParsedAst) -> Result<Vec<Vulnerability>> {
        let mut all_vulnerabilities = Vec::new();

        all_vulnerabilities.extend(self.check_memory_management(source_file, ast)?);
        all_vulnerabilities.extend(self.check_unsafe_functions(source_file, ast)?);
        all_vulnerabilities.extend(self.check_exception_safety(source_file, ast)?);
        all_vulnerabilities.extend(self.check_iterator_safety(source_file, ast)?);
        all_vulnerabilities.extend(self.check_template_issues(source_file, ast)?);

        Ok(all_vulnerabilities)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{parsers::cpp_parser::CppParser, Language};
    use std::path::PathBuf;

    #[test]
    fn test_memory_management_detection() {
        let rules = CppRules::new();
        let parser = CppParser::new();
        
        let source = r#"
#include <iostream>

void vulnerable_function() {
    int* ptr = new int[10];
    // Missing delete[] - memory leak
}
"#;
        
        let source_file = SourceFile::new(
            PathBuf::from("test.cpp"),
            source.to_string(),
            Language::Cpp,
        );
        
        let ast = parser.parse(&source_file).unwrap();
        let vulnerabilities = rules.analyze(&source_file, &ast).unwrap();
        
        assert!(!vulnerabilities.is_empty());
        assert!(vulnerabilities.iter().any(|v| v.id == "CPP001" || v.id == "CPP003"));
    }
}