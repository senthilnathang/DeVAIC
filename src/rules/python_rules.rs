use super::{create_vulnerability, RuleSet};
use crate::{
    error::Result,
    parsers::{ParsedAst, Parser, SourceFile},
    Severity, Vulnerability,
};
use regex::Regex;
use tree_sitter::Node;

pub struct PythonRules {
    hardcoded_secrets_patterns: Vec<Regex>,
    sql_injection_patterns: Vec<Regex>,
    command_injection_patterns: Vec<Regex>,
    unsafe_deserialization_patterns: Vec<Regex>,
    weak_crypto_patterns: Vec<Regex>,
}

impl PythonRules {
    pub fn new() -> Self {
        Self {
            hardcoded_secrets_patterns: vec![
                Regex::new(r#"(?i)(password|pwd|secret|key|token)\s*=\s*["'][^"']{8,}["']"#).unwrap(),
                Regex::new(r#"(?i)api[_-]?key\s*=\s*["'][^"']{20,}["']"#).unwrap(),
                Regex::new(r#"(?i)(access[_-]?token|auth[_-]?token)\s*=\s*["'][^"']{20,}["']"#).unwrap(),
            ],
            sql_injection_patterns: vec![
                Regex::new(r#"(?i)execute\s*\(\s*["'].*%.*["'].*%"#).unwrap(),
                Regex::new(r#"(?i)cursor\.execute\s*\(\s*f?["'].*\{.*\}.*["']"#).unwrap(),
                Regex::new(r#"(?i)query\s*=\s*f?["'].*\{.*\}.*["']"#).unwrap(),
            ],
            command_injection_patterns: vec![
                Regex::new(r#"(?i)os\.system\s*\(\s*f?["'].*\{.*\}.*["']"#).unwrap(),
                Regex::new(r#"(?i)subprocess\.(call|run|Popen)\s*\(\s*f?["'].*\{.*\}.*["']"#).unwrap(),
                Regex::new(r#"(?i)eval\s*\("#).unwrap(),
                Regex::new(r#"(?i)exec\s*\("#).unwrap(),
            ],
            unsafe_deserialization_patterns: vec![
                Regex::new(r#"(?i)pickle\.loads?\s*\("#).unwrap(),
                Regex::new(r#"(?i)cPickle\.loads?\s*\("#).unwrap(),
                Regex::new(r#"(?i)yaml\.load\s*\("#).unwrap(),
            ],
            weak_crypto_patterns: vec![
                Regex::new(r#"(?i)hashlib\.(md5|sha1)\s*\("#).unwrap(),
                Regex::new(r#"(?i)Crypto\.Hash\.(MD5|SHA1)"#).unwrap(),
            ],
        }
    }

    fn check_hardcoded_secrets(&self, source_file: &SourceFile, ast: &ParsedAst) -> Result<Vec<Vulnerability>> {
        let mut vulnerabilities = Vec::new();
        let lines: Vec<&str> = ast.source.lines().collect();

        for (line_num, line) in lines.iter().enumerate() {
            for pattern in &self.hardcoded_secrets_patterns {
                if pattern.is_match(line) {
                    vulnerabilities.push(create_vulnerability(
                        "PY001",
                        Severity::Critical,
                        "authentication",
                        "Hardcoded secret or credential detected",
                        &source_file.path.to_string_lossy(),
                        line_num + 1,
                        0,
                        line.trim(),
                        "Use environment variables or secure credential management systems",
                    ));
                }
            }
        }

        Ok(vulnerabilities)
    }

    fn check_sql_injection(&self, source_file: &SourceFile, ast: &ParsedAst) -> Result<Vec<Vulnerability>> {
        let mut vulnerabilities = Vec::new();
        let lines: Vec<&str> = ast.source.lines().collect();

        for (line_num, line) in lines.iter().enumerate() {
            for pattern in &self.sql_injection_patterns {
                if pattern.is_match(line) {
                    vulnerabilities.push(create_vulnerability(
                        "PY002",
                        Severity::High,
                        "injection",
                        "Potential SQL injection vulnerability detected",
                        &source_file.path.to_string_lossy(),
                        line_num + 1,
                        0,
                        line.trim(),
                        "Use parameterized queries or prepared statements",
                    ));
                }
            }
        }

        Ok(vulnerabilities)
    }

    fn check_command_injection(&self, source_file: &SourceFile, ast: &ParsedAst) -> Result<Vec<Vulnerability>> {
        let mut vulnerabilities = Vec::new();
        let lines: Vec<&str> = ast.source.lines().collect();

        for (line_num, line) in lines.iter().enumerate() {
            for pattern in &self.command_injection_patterns {
                if pattern.is_match(line) {
                    let severity = if line.contains("eval") || line.contains("exec") {
                        Severity::Critical
                    } else {
                        Severity::High
                    };

                    vulnerabilities.push(create_vulnerability(
                        "PY003",
                        severity,
                        "injection",
                        "Potential command injection vulnerability detected",
                        &source_file.path.to_string_lossy(),
                        line_num + 1,
                        0,
                        line.trim(),
                        "Validate and sanitize input, use subprocess with shell=False",
                    ));
                }
            }
        }

        Ok(vulnerabilities)
    }

    fn check_unsafe_deserialization(&self, source_file: &SourceFile, ast: &ParsedAst) -> Result<Vec<Vulnerability>> {
        let mut vulnerabilities = Vec::new();
        let lines: Vec<&str> = ast.source.lines().collect();

        for (line_num, line) in lines.iter().enumerate() {
            for pattern in &self.unsafe_deserialization_patterns {
                if pattern.is_match(line) {
                    let severity = if line.contains("pickle") {
                        Severity::Critical
                    } else {
                        Severity::High
                    };

                    vulnerabilities.push(create_vulnerability(
                        "PY004",
                        severity,
                        "deserialization",
                        "Unsafe deserialization detected",
                        &source_file.path.to_string_lossy(),
                        line_num + 1,
                        0,
                        line.trim(),
                        "Use safe serialization formats like JSON, avoid pickle with untrusted data",
                    ));
                }
            }
        }

        Ok(vulnerabilities)
    }

    fn check_weak_cryptography(&self, source_file: &SourceFile, ast: &ParsedAst) -> Result<Vec<Vulnerability>> {
        let mut vulnerabilities = Vec::new();
        let lines: Vec<&str> = ast.source.lines().collect();

        for (line_num, line) in lines.iter().enumerate() {
            for pattern in &self.weak_crypto_patterns {
                if pattern.is_match(line) {
                    vulnerabilities.push(create_vulnerability(
                        "PY005",
                        Severity::Medium,
                        "cryptographic",
                        "Weak cryptographic algorithm detected",
                        &source_file.path.to_string_lossy(),
                        line_num + 1,
                        0,
                        line.trim(),
                        "Use stronger hashing algorithms like SHA-256 or SHA-3",
                    ));
                }
            }
        }

        Ok(vulnerabilities)
    }

    fn check_debug_mode(&self, source_file: &SourceFile, ast: &ParsedAst) -> Result<Vec<Vulnerability>> {
        let mut vulnerabilities = Vec::new();
        let root_node = ast.root_node();
        
        self.traverse_node(&root_node, &ast.source, |node, source_slice| {
            if node.kind() == "assignment" {
                let node_text = &source_slice[node.byte_range()];
                if node_text.contains("DEBUG") && node_text.contains("True") {
                    let start_pos = node.start_position();
                    vulnerabilities.push(create_vulnerability(
                        "PY006",
                        Severity::Medium,
                        "logging",
                        "Debug mode enabled in production code",
                        &source_file.path.to_string_lossy(),
                        start_pos.row + 1,
                        start_pos.column,
                        node_text,
                        "Disable debug mode in production environments",
                    ));
                }
            }
        });

        Ok(vulnerabilities)
    }

    fn check_insecure_random(&self, source_file: &SourceFile, ast: &ParsedAst) -> Result<Vec<Vulnerability>> {
        let mut vulnerabilities = Vec::new();
        let root_node = ast.root_node();
        
        self.traverse_node(&root_node, &ast.source, |node, source_slice| {
            if node.kind() == "call" {
                let node_text = &source_slice[node.byte_range()];
                if node_text.contains("random.") && !node_text.contains("secrets.") {
                    // Check if it's being used for security purposes
                    let context_start = source_slice[..node.start_byte()]
                        .rfind('\n')
                        .map(|pos| pos + 1)
                        .unwrap_or(0);
                    let context_end = source_slice[node.end_byte()..]
                        .find('\n')
                        .map(|pos| node.end_byte() + pos)
                        .unwrap_or(source_slice.len());
                    let context = &source_slice[context_start..context_end];
                    
                    if context.contains("token") || context.contains("password") || context.contains("key") {
                        let start_pos = node.start_position();
                        vulnerabilities.push(create_vulnerability(
                            "PY007",
                            Severity::High,
                            "cryptographic",
                            "Insecure random number generator used for security purposes",
                            &source_file.path.to_string_lossy(),
                            start_pos.row + 1,
                            start_pos.column,
                            node_text,
                            "Use secrets module for cryptographically secure random numbers",
                        ));
                    }
                }
            }
        });

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

impl RuleSet for PythonRules {
    fn analyze(&self, source_file: &SourceFile, ast: &ParsedAst) -> Result<Vec<Vulnerability>> {
        let mut all_vulnerabilities = Vec::new();

        all_vulnerabilities.extend(self.check_hardcoded_secrets(source_file, ast)?);
        all_vulnerabilities.extend(self.check_sql_injection(source_file, ast)?);
        all_vulnerabilities.extend(self.check_command_injection(source_file, ast)?);
        all_vulnerabilities.extend(self.check_unsafe_deserialization(source_file, ast)?);
        all_vulnerabilities.extend(self.check_weak_cryptography(source_file, ast)?);
        all_vulnerabilities.extend(self.check_debug_mode(source_file, ast)?);
        all_vulnerabilities.extend(self.check_insecure_random(source_file, ast)?);

        Ok(all_vulnerabilities)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{parsers::python_parser::PythonParser, Language};
    use std::path::PathBuf;

    #[test]
    fn test_hardcoded_secrets_detection() {
        let rules = PythonRules::new();
        let parser = PythonParser::new();
        
        let source = r#"
import os

# Hardcoded secrets - should be detected
API_KEY = "sk-1234567890abcdef1234567890abcdef"
password = "super_secret_password123"

def connect_db():
    return connect(password=password)
"#;
        
        let source_file = SourceFile::new(
            PathBuf::from("test.py"),
            source.to_string(),
            Language::Python,
        );
        
        let ast = parser.parse(&source_file).unwrap();
        let vulnerabilities = rules.analyze(&source_file, &ast).unwrap();
        
        assert!(!vulnerabilities.is_empty());
        assert!(vulnerabilities.iter().any(|v| v.id == "PY001"));
    }

    #[test]
    fn test_sql_injection_detection() {
        let rules = PythonRules::new();
        let parser = PythonParser::new();
        
        let source = r#"
import sqlite3

def get_user(user_id):
    conn = sqlite3.connect('db.sqlite')
    cursor = conn.cursor()
    # SQL injection vulnerability
    cursor.execute(f"SELECT * FROM users WHERE id = {user_id}")
    return cursor.fetchone()
"#;
        
        let source_file = SourceFile::new(
            PathBuf::from("test.py"),
            source.to_string(),
            Language::Python,
        );
        
        let ast = parser.parse(&source_file).unwrap();
        let vulnerabilities = rules.analyze(&source_file, &ast).unwrap();
        
        assert!(vulnerabilities.iter().any(|v| v.id == "PY002"));
    }
}