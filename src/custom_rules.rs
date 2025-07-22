use crate::{
    error::Result,
    parsers::{ParsedAst, SourceFile},
    rules::create_vulnerability,
    Language, Severity, Vulnerability,
};
use regex::Regex;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::path::Path;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CustomRule {
    pub id: String,
    pub name: String,
    pub description: String,
    pub severity: Severity,
    pub category: String,
    pub languages: Vec<Language>,
    pub pattern_type: PatternType,
    pub patterns: Vec<String>,
    pub cwe: Option<String>,
    pub recommendation: String,
    pub enabled: bool,
    pub confidence: f64,
    pub tags: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum PatternType {
    Regex,
    Substring,
    AST,
    Semantic,
    Composite,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CustomRuleSet {
    pub name: String,
    pub version: String,
    pub description: String,
    pub author: String,
    pub rules: Vec<CustomRule>,
    pub metadata: HashMap<String, String>,
}

pub struct CustomRuleEngine {
    rule_sets: Vec<CustomRuleSet>,
    compiled_patterns: HashMap<String, Vec<Regex>>,
    enabled: bool,
}

impl CustomRuleEngine {
    pub fn new() -> Self {
        Self {
            rule_sets: Vec::new(),
            compiled_patterns: HashMap::new(),
            enabled: false,
        }
    }
    
    pub fn load_rule_set(&mut self, rule_set_path: &Path) -> Result<()> {
        let content = std::fs::read_to_string(rule_set_path)?;
        
        // Support multiple formats
        let rule_set: CustomRuleSet = if rule_set_path.extension().unwrap_or_default() == "yaml" {
            serde_yaml::from_str(&content)?
        } else {
            serde_json::from_str(&content)?
        };
        
        // Compile regex patterns
        for rule in &rule_set.rules {
            if matches!(rule.pattern_type, PatternType::Regex) {
                let mut compiled = Vec::new();
                for pattern in &rule.patterns {
                    match Regex::new(pattern) {
                        Ok(regex) => compiled.push(regex),
                        Err(e) => eprintln!("Warning: Invalid regex in rule {}: {}", rule.id, e),
                    }
                }
                self.compiled_patterns.insert(rule.id.clone(), compiled);
            }
        }
        
        self.rule_sets.push(rule_set);
        self.enabled = true;
        Ok(())
    }
    
    pub fn load_rule_directory(&mut self, rules_dir: &Path) -> Result<()> {
        if !rules_dir.exists() {
            return Ok(());
        }
        
        for entry in std::fs::read_dir(rules_dir)? {
            let entry = entry?;
            let path = entry.path();
            
            if path.is_file() {
                if let Some(ext) = path.extension() {
                    if ext == "json" || ext == "yaml" || ext == "yml" {
                        if let Err(e) = self.load_rule_set(&path) {
                            eprintln!("Warning: Failed to load rule set {:?}: {}", path, e);
                        }
                    }
                }
            }
        }
        
        Ok(())
    }
    
    pub fn analyze_with_custom_rules(&self, source_file: &SourceFile, ast: &ParsedAst) -> Result<Vec<Vulnerability>> {
        if !self.enabled {
            return Ok(Vec::new());
        }
        
        let mut vulnerabilities = Vec::new();
        
        for rule_set in &self.rule_sets {
            for rule in &rule_set.rules {
                if !rule.enabled {
                    continue;
                }
                
                // Check if rule applies to this language
                if !rule.languages.is_empty() && !rule.languages.contains(&source_file.language) {
                    continue;
                }
                
                // Apply rule based on pattern type
                let rule_vulns = match rule.pattern_type {
                    PatternType::Regex => self.apply_regex_rule(rule, source_file)?,
                    PatternType::Substring => self.apply_substring_rule(rule, source_file)?,
                    PatternType::AST => self.apply_ast_rule(rule, source_file, ast)?,
                    PatternType::Semantic => self.apply_semantic_rule(rule, source_file, ast)?,
                    PatternType::Composite => self.apply_composite_rule(rule, source_file, ast)?,
                };
                
                vulnerabilities.extend(rule_vulns);
            }
        }
        
        Ok(vulnerabilities)
    }
    
    fn apply_regex_rule(&self, rule: &CustomRule, source_file: &SourceFile) -> Result<Vec<Vulnerability>> {
        let mut vulnerabilities = Vec::new();
        let lines: Vec<&str> = source_file.content.lines().collect();
        
        if let Some(compiled_patterns) = self.compiled_patterns.get(&rule.id) {
            for (line_number, line) in lines.iter().enumerate() {
                for pattern in compiled_patterns {
                    if pattern.is_match(line) {
                        vulnerabilities.push(create_vulnerability(
                            &rule.id,
                            rule.cwe.as_deref(),
                            &rule.name,
                            rule.severity.clone(),
                            &rule.category,
                            &rule.description,
                            &source_file.path.to_string_lossy(),
                            line_number + 1,
                            0,
                            line,
                            &rule.recommendation,
                        ));
                    }
                }
            }
        }
        
        Ok(vulnerabilities)
    }
    
    fn apply_substring_rule(&self, rule: &CustomRule, source_file: &SourceFile) -> Result<Vec<Vulnerability>> {
        let mut vulnerabilities = Vec::new();
        let lines: Vec<&str> = source_file.content.lines().collect();
        
        for (line_number, line) in lines.iter().enumerate() {
            for pattern in &rule.patterns {
                if line.contains(pattern) {
                    vulnerabilities.push(create_vulnerability(
                        &rule.id,
                        rule.cwe.as_deref(),
                        &rule.name,
                        rule.severity.clone(),
                        &rule.category,
                        &rule.description,
                        &source_file.path.to_string_lossy(),
                        line_number + 1,
                        0,
                        line,
                        &rule.recommendation,
                    ));
                }
            }
        }
        
        Ok(vulnerabilities)
    }
    
    fn apply_ast_rule(&self, rule: &CustomRule, source_file: &SourceFile, ast: &ParsedAst) -> Result<Vec<Vulnerability>> {
        let mut vulnerabilities = Vec::new();
        
        // AST-based pattern matching would require tree-sitter queries
        // For now, implement basic AST node type matching
        if let Some(tree_ref) = &ast.tree {
            let tree = tree_ref.borrow();
            let root_node = tree.root_node();
            
            for pattern in &rule.patterns {
                if self.ast_contains_pattern(&root_node, pattern, &ast.source) {
                    vulnerabilities.push(create_vulnerability(
                        &rule.id,
                        rule.cwe.as_deref(),
                        &rule.name,
                        rule.severity.clone(),
                        &rule.category,
                        &rule.description,
                        &source_file.path.to_string_lossy(),
                        1, // Would need to extract actual line from AST
                        0,
                        pattern,
                        &rule.recommendation,
                    ));
                }
            }
        }
        
        Ok(vulnerabilities)
    }
    
    fn apply_semantic_rule(&self, rule: &CustomRule, source_file: &SourceFile, ast: &ParsedAst) -> Result<Vec<Vulnerability>> {
        let mut vulnerabilities = Vec::new();
        
        // Semantic analysis would involve understanding code flow, data dependencies, etc.
        // For now, implement basic semantic patterns
        for pattern in &rule.patterns {
            if self.semantic_pattern_matches(pattern, source_file, ast) {
                vulnerabilities.push(create_vulnerability(
                    &rule.id,
                    rule.cwe.as_deref(),
                    &rule.name,
                    rule.severity.clone(),
                    &rule.category,
                    &rule.description,
                    &source_file.path.to_string_lossy(),
                    1,
                    0,
                    pattern,
                    &rule.recommendation,
                ));
            }
        }
        
        Ok(vulnerabilities)
    }
    
    fn apply_composite_rule(&self, rule: &CustomRule, source_file: &SourceFile, _ast: &ParsedAst) -> Result<Vec<Vulnerability>> {
        let mut vulnerabilities = Vec::new();
        
        // Composite rules combine multiple pattern types
        let mut matches = 0;
        let required_matches = rule.patterns.len();
        
        // Check each pattern (simplified implementation)
        for pattern in &rule.patterns {
            if source_file.content.contains(pattern) {
                matches += 1;
            }
        }
        
        // Require all patterns to match for composite rule
        if matches >= required_matches {
            vulnerabilities.push(create_vulnerability(
                &rule.id,
                rule.cwe.as_deref(),
                &rule.name,
                rule.severity.clone(),
                &rule.category,
                &format!("{} (Composite rule: {}/{} patterns matched)", rule.description, matches, required_matches),
                &source_file.path.to_string_lossy(),
                1,
                0,
                &rule.patterns.join(" + "),
                &rule.recommendation,
            ));
        }
        
        Ok(vulnerabilities)
    }
    
    fn ast_contains_pattern(&self, node: &tree_sitter::Node, pattern: &str, source: &str) -> bool {
        // Check if current node matches pattern
        if node.kind() == pattern {
            return true;
        }
        
        // Check node text content
        let start_byte = node.start_byte();
        let end_byte = node.end_byte();
        if end_byte <= source.len() {
            let node_text = &source[start_byte..end_byte];
            if node_text.contains(pattern) {
                return true;
            }
        }
        
        // Recursively check children
        let mut cursor = node.walk();
        for child in node.children(&mut cursor) {
            if self.ast_contains_pattern(&child, pattern, source) {
                return true;
            }
        }
        
        false
    }
    
    fn semantic_pattern_matches(&self, pattern: &str, source_file: &SourceFile, _ast: &ParsedAst) -> bool {
        // Simplified semantic pattern matching
        // Real implementation would analyze data flow, control flow, etc.
        
        match pattern {
            "user_input_to_sql" => {
                source_file.content.contains("input") && 
                source_file.content.contains("SELECT") &&
                source_file.content.contains("+")
            }
            "unvalidated_redirect" => {
                source_file.content.contains("redirect") &&
                source_file.content.contains("request") &&
                !source_file.content.contains("validate")
            }
            "weak_session_management" => {
                source_file.content.contains("session") &&
                !source_file.content.contains("secure") &&
                !source_file.content.contains("httponly")
            }
            _ => false,
        }
    }
    
    pub fn create_rule_template() -> CustomRule {
        CustomRule {
            id: "CUSTOM-001".to_string(),
            name: "Custom Security Rule".to_string(),
            description: "Description of the security issue".to_string(),
            severity: Severity::Medium,
            category: "custom".to_string(),
            languages: vec![Language::Python], // Example
            pattern_type: PatternType::Regex,
            patterns: vec![r"dangerous_function\s*\(".to_string()],
            cwe: Some("CWE-20".to_string()),
            recommendation: "Replace with secure alternative".to_string(),
            enabled: true,
            confidence: 0.8,
            tags: vec!["security".to_string(), "custom".to_string()],
        }
    }
    
    pub fn validate_rule(&self, rule: &CustomRule) -> Result<Vec<String>> {
        let mut errors = Vec::new();
        
        // Validate required fields
        if rule.id.is_empty() {
            errors.push("Rule ID cannot be empty".to_string());
        }
        
        if rule.name.is_empty() {
            errors.push("Rule name cannot be empty".to_string());
        }
        
        if rule.patterns.is_empty() {
            errors.push("Rule must have at least one pattern".to_string());
        }
        
        // Validate regex patterns
        if matches!(rule.pattern_type, PatternType::Regex) {
            for pattern in &rule.patterns {
                if let Err(e) = Regex::new(pattern) {
                    errors.push(format!("Invalid regex pattern '{}': {}", pattern, e));
                }
            }
        }
        
        // Validate confidence
        if rule.confidence < 0.0 || rule.confidence > 1.0 {
            errors.push("Confidence must be between 0.0 and 1.0".to_string());
        }
        
        Ok(errors)
    }
}