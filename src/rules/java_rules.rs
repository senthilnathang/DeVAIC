use super::{create_vulnerability, RuleSet};
use crate::{
    error::Result,
    parsers::{ParsedAst, SourceFile},
    Severity, Vulnerability,
};
use regex::Regex;
use tree_sitter::Node;

pub struct JavaRules {
    sql_injection_patterns: Vec<Regex>,
    deserialization_patterns: Vec<Regex>,
    xxe_patterns: Vec<Regex>,
    crypto_patterns: Vec<Regex>,
    reflection_patterns: Vec<Regex>,
    path_traversal_patterns: Vec<Regex>,
}

impl JavaRules {
    pub fn new() -> Self {
        Self {
            sql_injection_patterns: vec![
                Regex::new(r#"\.createStatement\(\)\.execute(?:Query|Update)?\s*\(\s*"[^"]*"\s*\+[^)]*\)"#).unwrap(),
                Regex::new(r#"Statement\.execute(?:Query|Update)?\s*\(\s*[^)]*\+[^)]*\)"#).unwrap(),
                Regex::new(r#"Connection\.prepareStatement\s*\(\s*"[^"]*"\s*\+[^)]*\)"#).unwrap(),
            ],
            deserialization_patterns: vec![
                Regex::new(r"ObjectInputStream\s*\(\s*new\s+FileInputStream").unwrap(),
                Regex::new(r"\.readObject\s*\(\s*\)").unwrap(),
                Regex::new(r"XMLDecoder\s*\(\s*new\s+FileInputStream").unwrap(),
                Regex::new(r"Yaml\.load\s*\(").unwrap(),
            ],
            xxe_patterns: vec![
                Regex::new(r"DocumentBuilderFactory\.newInstance\s*\(\s*\)").unwrap(),
                Regex::new(r"SAXParserFactory\.newInstance\s*\(\s*\)").unwrap(),
                Regex::new(r"XMLInputFactory\.newInstance\s*\(\s*\)").unwrap(),
                Regex::new(r"TransformerFactory\.newInstance\s*\(\s*\)").unwrap(),
            ],
            crypto_patterns: vec![
                Regex::new(r#"MessageDigest\.getInstance\s*\(\s*"MD5"\s*\)"#).unwrap(),
                Regex::new(r#"MessageDigest\.getInstance\s*\(\s*"SHA1"\s*\)"#).unwrap(),
                Regex::new(r#"Cipher\.getInstance\s*\(\s*"DES[^"]*"\s*\)"#).unwrap(),
                Regex::new(r"new\s+Random\s*\(\s*\)").unwrap(),
            ],
            reflection_patterns: vec![
                Regex::new(r"Class\.forName\s*\(").unwrap(),
                Regex::new(r"\.newInstance\s*\(\s*\)").unwrap(),
                Regex::new(r"Method\.invoke\s*\(").unwrap(),
            ],
            path_traversal_patterns: vec![
                Regex::new(r"new\s+File\s*\(\s*[^)]*\+[^)]*\)").unwrap(),
                Regex::new(r"FileInputStream\s*\(\s*[^)]*\+[^)]*\)").unwrap(),
                Regex::new(r"Files\.newInputStream\s*\(\s*Paths\.get\s*\([^)]*\+[^)]*\)\s*\)").unwrap(),
            ],
        }
    }

    fn check_sql_injection(&self, source_file: &SourceFile, ast: &ParsedAst) -> Result<Vec<Vulnerability>> {
        let mut vulnerabilities = Vec::new();
        let lines: Vec<&str> = ast.source.lines().collect();

        for (line_num, line) in lines.iter().enumerate() {
            for pattern in &self.sql_injection_patterns {
                if pattern.is_match(line) {
                    vulnerabilities.push(create_vulnerability(
                        "JAVA001",
                        Some("CWE-89"),
                        "SQL Injection",
                        Severity::High,
                        "injection",
                        "Potential SQL injection vulnerability",
                        &source_file.path.to_string_lossy(),
                        line_num + 1,
                        0,
                        line,
                        "Use PreparedStatement with parameterized queries instead of string concatenation",
                    ));
                }
            }

            if line.contains("getParameter(") && line.contains("execute") {
                vulnerabilities.push(create_vulnerability(
                    "JAVA002",
                    Some("CWE-89"),
                    "SQL Injection",
                    Severity::High,
                    "injection",
                    "User input directly used in SQL execution",
                    &source_file.path.to_string_lossy(),
                    line_num + 1,
                    0,
                    line,
                    "Sanitize and validate user input before using in SQL queries",
                ));
            }
        }

        Ok(vulnerabilities)
    }

    fn check_deserialization(&self, source_file: &SourceFile, ast: &ParsedAst) -> Result<Vec<Vulnerability>> {
        let mut vulnerabilities = Vec::new();
        let lines: Vec<&str> = ast.source.lines().collect();

        for (line_num, line) in lines.iter().enumerate() {
            for pattern in &self.deserialization_patterns {
                if pattern.is_match(line) {
                    vulnerabilities.push(create_vulnerability(
                        "JAVA003",
                        Some("CWE-502"),
                        "Unsafe Deserialization",
                        Severity::High,
                        "deserialization",
                        "Unsafe deserialization detected",
                        &source_file.path.to_string_lossy(),
                        line_num + 1,
                        0,
                        line,
                        "Avoid deserializing untrusted data. Use safe serialization formats like JSON",
                    ));
                }
            }
        }

        Ok(vulnerabilities)
    }

    fn check_xxe_vulnerabilities(&self, source_file: &SourceFile, ast: &ParsedAst) -> Result<Vec<Vulnerability>> {
        let mut vulnerabilities = Vec::new();
        let lines: Vec<&str> = ast.source.lines().collect();

        for (line_num, line) in lines.iter().enumerate() {
            for pattern in &self.xxe_patterns {
                if pattern.is_match(line) {
                    let next_lines = &lines[line_num..std::cmp::min(line_num + 5, lines.len())];
                    let context = next_lines.join("\n");
                    
                    if !context.contains("setFeature") || !context.contains("XMLConstants.FEATURE_SECURE_PROCESSING") {
                        vulnerabilities.push(create_vulnerability(
                            "JAVA004",
                            Some("CWE-611"),
                            "XML External Entity (XXE)",
                            Severity::High,
                            "injection",
                            "XML External Entity (XXE) vulnerability - XML parser not configured securely",
                            &source_file.path.to_string_lossy(),
                            line_num + 1,
                            0,
                            line,
                            "Configure XML parser to disable external entity processing and DTD processing",
                        ));
                    }
                }
            }
        }

        Ok(vulnerabilities)
    }

    fn check_weak_cryptography(&self, source_file: &SourceFile, ast: &ParsedAst) -> Result<Vec<Vulnerability>> {
        let mut vulnerabilities = Vec::new();
        let lines: Vec<&str> = ast.source.lines().collect();

        for (line_num, line) in lines.iter().enumerate() {
            for pattern in &self.crypto_patterns {
                if pattern.is_match(line) {
                    let severity = if line.contains("MD5") || line.contains("SHA1") {
                        Severity::High
                    } else if line.contains("DES") {
                        Severity::High
                    } else if line.contains("new Random()") {
                        Severity::Medium
                    } else {
                        Severity::Medium
                    };

                    let recommendation = if line.contains("MD5") || line.contains("SHA1") {
                        "Use SHA-256 or stronger hashing algorithms"
                    } else if line.contains("DES") {
                        "Use AES encryption instead of DES"
                    } else if line.contains("new Random()") {
                        "Use SecureRandom for cryptographic operations"
                    } else {
                        "Use strong cryptographic algorithms and secure implementations"
                    };

                    vulnerabilities.push(create_vulnerability(
                        "JAVA005",
                        Some("CWE-327"),
                        "Weak Cryptography",
                        severity,
                        "cryptographic",
                        "Weak cryptographic algorithm or implementation",
                        &source_file.path.to_string_lossy(),
                        line_num + 1,
                        0,
                        line,
                        recommendation,
                    ));
                }
            }
        }

        Ok(vulnerabilities)
    }

    fn check_unsafe_reflection(&self, source_file: &SourceFile, ast: &ParsedAst) -> Result<Vec<Vulnerability>> {
        let mut vulnerabilities = Vec::new();
        let lines: Vec<&str> = ast.source.lines().collect();

        for (line_num, line) in lines.iter().enumerate() {
            for pattern in &self.reflection_patterns {
                if pattern.is_match(line) {
                    if line.contains("getParameter(") || line.contains("user") || line.contains("input") {
                        vulnerabilities.push(create_vulnerability(
                            "JAVA006",
                            Some("CWE-470"),
                            "Unsafe Reflection",
                            Severity::High,
                            "validation",
                            "Unsafe reflection with user-controlled input",
                            &source_file.path.to_string_lossy(),
                            line_num + 1,
                            0,
                            line,
                            "Avoid using reflection with user input. Validate and whitelist allowed classes/methods",
                        ));
                    }
                }
            }
        }

        Ok(vulnerabilities)
    }

    fn check_path_traversal(&self, source_file: &SourceFile, ast: &ParsedAst) -> Result<Vec<Vulnerability>> {
        let mut vulnerabilities = Vec::new();
        let lines: Vec<&str> = ast.source.lines().collect();

        for (line_num, line) in lines.iter().enumerate() {
            for pattern in &self.path_traversal_patterns {
                if pattern.is_match(line) {
                    vulnerabilities.push(create_vulnerability(
                        "JAVA007",
                        Some("CWE-22"),
                        "Path Traversal",
                        Severity::High,
                        "validation",
                        "Potential path traversal vulnerability",
                        &source_file.path.to_string_lossy(),
                        line_num + 1,
                        0,
                        line,
                        "Validate and sanitize file paths. Use Path.normalize() and check against allowed directories",
                    ));
                }
            }
        }

        Ok(vulnerabilities)
    }

    fn check_hardcoded_credentials(&self, source_file: &SourceFile, ast: &ParsedAst) -> Result<Vec<Vulnerability>> {
        let mut vulnerabilities = Vec::new();
        let lines: Vec<&str> = ast.source.lines().collect();

        for (line_num, line) in lines.iter().enumerate() {
            let lower_line = line.to_lowercase();
            
            if (lower_line.contains("password") || lower_line.contains("pwd") || 
                lower_line.contains("secret") || lower_line.contains("key")) &&
               (lower_line.contains("\"") || lower_line.contains("'")) &&
               lower_line.contains("=") {
                
                vulnerabilities.push(create_vulnerability(
                    "JAVA008",
                    Some("CWE-798"),
                    "Hardcoded Credentials",
                    Severity::High,
                    "authentication",
                    "Hardcoded credentials detected",
                    &source_file.path.to_string_lossy(),
                    line_num + 1,
                    0,
                    line,
                    "Store credentials in environment variables or secure configuration files",
                ));
            }
        }

        Ok(vulnerabilities)
    }

    fn check_insecure_random(&self, source_file: &SourceFile, ast: &ParsedAst) -> Result<Vec<Vulnerability>> {
        let mut vulnerabilities = Vec::new();
        
        if let Some(root_node) = ast.root_node() {
            self.traverse_node(&root_node, &ast.source, |node, source_slice| {
            if node.kind() == "object_creation_expression" {
                let expr_text = &source_slice[node.byte_range()];
                
                if expr_text.contains("new Random()") && !expr_text.contains("SecureRandom") {
                    let start_pos = node.start_position();
                    vulnerabilities.push(create_vulnerability(
                        "JAVA009",
                        Some("CWE-330"),
                        "Weak Random Number Generation",
                        Severity::Medium,
                        "cryptographic",
                        "Insecure random number generation",
                        &source_file.path.to_string_lossy(),
                        start_pos.row + 1,
                        start_pos.column,
                        expr_text,
                        "Use SecureRandom for security-sensitive random number generation",
                    ));
                }
            }
            });
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

impl RuleSet for JavaRules {
    fn analyze(&self, source_file: &SourceFile, ast: &ParsedAst) -> Result<Vec<Vulnerability>> {
        let mut all_vulnerabilities = Vec::new();

        all_vulnerabilities.extend(self.check_sql_injection(source_file, ast)?);
        all_vulnerabilities.extend(self.check_deserialization(source_file, ast)?);
        all_vulnerabilities.extend(self.check_xxe_vulnerabilities(source_file, ast)?);
        all_vulnerabilities.extend(self.check_weak_cryptography(source_file, ast)?);
        all_vulnerabilities.extend(self.check_unsafe_reflection(source_file, ast)?);
        all_vulnerabilities.extend(self.check_path_traversal(source_file, ast)?);
        all_vulnerabilities.extend(self.check_hardcoded_credentials(source_file, ast)?);
        all_vulnerabilities.extend(self.check_insecure_random(source_file, ast)?);

        Ok(all_vulnerabilities)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{parsers::{java_parser::JavaParser, Parser}, Language};
    use std::path::PathBuf;

    #[test]
    fn test_sql_injection_detection() {
        let rules = JavaRules::new();
        let mut parser = JavaParser::new().unwrap();
        
        let source = r#"
import java.sql.*;

public class VulnerableDAO {
    private static final String API_KEY = "secret_api_key_12345";
    private Connection connection;
    
    public void getUserData(String userId) {
        Statement stmt = connection.createStatement();
        stmt.executeQuery("SELECT * FROM users WHERE id = " + userId);
    }
}
"#;
        
        let source_file = SourceFile::new(
            PathBuf::from("VulnerableDAO.java"),
            source.to_string(),
            Language::Java,
        );
        
        let ast = parser.parse(&source_file).unwrap();
        let vulnerabilities = rules.analyze(&source_file, &ast).unwrap();
        
        assert!(!vulnerabilities.is_empty());
        assert!(vulnerabilities.iter().any(|v| v.id.starts_with("JAVA")));
    }
}