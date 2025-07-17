use super::{create_vulnerability, RuleSet};
use crate::{
    error::Result,
    parsers::{ParsedAst, SourceFile},
    pattern_loader::PatternLoader,
    Vulnerability,
};

/// Rule set that uses custom imported patterns
pub struct CustomPatternRules {
    pattern_loader: PatternLoader,
}

impl CustomPatternRules {
    pub fn new(pattern_loader: PatternLoader) -> Self {
        Self { pattern_loader }
    }

    pub fn with_empty_loader() -> Self {
        Self {
            pattern_loader: PatternLoader::new(),
        }
    }

    pub fn load_patterns_from_file<P: AsRef<std::path::Path>>(&mut self, file_path: P) -> Result<usize> {
        self.pattern_loader.load_from_file(file_path)
    }

    pub fn load_patterns_from_directory<P: AsRef<std::path::Path>>(&mut self, dir_path: P) -> Result<usize> {
        self.pattern_loader.load_from_directory(dir_path)
    }

    pub fn get_pattern_statistics(&self) -> crate::pattern_loader::PatternStatistics {
        self.pattern_loader.get_statistics()
    }

    fn check_patterns_for_language(&self, source_file: &SourceFile, _ast: &ParsedAst) -> Result<Vec<Vulnerability>> {
        let mut vulnerabilities = Vec::new();
        let patterns = self.pattern_loader.get_patterns_for_language(&source_file.language);
        
        if patterns.is_empty() {
            return Ok(vulnerabilities);
        }

        // Get all lines for pattern matching
        let lines: Vec<&str> = source_file.content.lines().collect();
        
        for pattern in patterns {
            for compiled_regex in &pattern.compiled_regex {
                // Search through each line
                for (line_num, line) in lines.iter().enumerate() {
                    if let Some(captures) = compiled_regex.regex.captures(line) {
                        let full_match = captures.get(0).unwrap();
                        
                        // Create vulnerability from matched pattern
                        let vulnerability = create_vulnerability(
                            &pattern.pattern.id,
                            pattern.pattern.cwe.as_deref(),
                            &pattern.pattern.name,
                            pattern.pattern.severity.clone(),
                            &pattern.pattern.category,
                            &pattern.pattern.description,
                            &source_file.path.to_string_lossy(),
                            line_num + 1,
                            full_match.start(),
                            line.trim(),
                            pattern.pattern.fix_suggestion.as_deref().unwrap_or("Review and fix security issue"),
                        );
                        
                        vulnerabilities.push(vulnerability);
                    }
                }
                
                // Also search the entire file content for multi-line patterns
                if let Some(captures) = compiled_regex.regex.captures(&source_file.content) {
                    let full_match = captures.get(0).unwrap();
                    
                    // Calculate line number from byte position
                    let line_num = source_file.content[..full_match.start()]
                        .chars()
                        .filter(|&c| c == '\n')
                        .count() + 1;
                    
                    // Extract the line containing the match
                    let line_start = source_file.content[..full_match.start()]
                        .rfind('\n')
                        .map(|pos| pos + 1)
                        .unwrap_or(0);
                    let line_end = source_file.content[full_match.end()..]
                        .find('\n')
                        .map(|pos| full_match.end() + pos)
                        .unwrap_or(source_file.content.len());
                    
                    let matched_line = &source_file.content[line_start..line_end];
                    
                    // Check if we already found this vulnerability (avoid duplicates)
                    let duplicate = vulnerabilities.iter().any(|v| {
                        v.file_path == source_file.path.to_string_lossy() &&
                        v.line_number == line_num &&
                        v.id == pattern.pattern.id
                    });
                    
                    if !duplicate {
                        let vulnerability = create_vulnerability(
                            &pattern.pattern.id,
                            pattern.pattern.cwe.as_deref(),
                            &pattern.pattern.name,
                            pattern.pattern.severity.clone(),
                            &pattern.pattern.category,
                            &pattern.pattern.description,
                            &source_file.path.to_string_lossy(),
                            line_num,
                            full_match.start() - line_start,
                            matched_line.trim(),
                            pattern.pattern.fix_suggestion.as_deref().unwrap_or("Review and fix security issue"),
                        );
                        
                        vulnerabilities.push(vulnerability);
                    }
                }
            }
        }
        
        Ok(vulnerabilities)
    }
}

impl RuleSet for CustomPatternRules {
    fn analyze(&self, source_file: &SourceFile, ast: &ParsedAst) -> Result<Vec<Vulnerability>> {
        self.check_patterns_for_language(source_file, ast)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{Language, parsers::SourceFile};
    use std::path::PathBuf;
    use tempfile::NamedTempFile;
    use std::io::Write;

    #[test]
    fn test_custom_pattern_rules_empty() {
        let rules = CustomPatternRules::with_empty_loader();
        let source_file = SourceFile::new(
            PathBuf::from("test.java"),
            "System.out.println(\"Hello World\");".to_string(),
            Language::Java,
        );
        let ast = crate::parsers::ParsedAst::new_source_only(source_file.content.clone());
        
        let vulnerabilities = rules.analyze(&source_file, &ast).unwrap();
        assert_eq!(vulnerabilities.len(), 0);
    }

    #[test]
    fn test_custom_pattern_rules_with_patterns() {
        let yaml_content = r#"
version: "1.0"
name: "Test Security Patterns"
patterns:
  - id: "test-sql-injection"
    name: "SQL Injection Risk"
    description: "Detects potential SQL injection vulnerabilities"
    severity: "High"
    category: "injection"
    languages: ["java"]
    patterns:
      - regex: "SELECT.*FROM.*WHERE.*\\+.*"
        description: "String concatenation in SQL query"
        confidence: 0.9
    fix_suggestion: "Use parameterized queries instead of string concatenation"
    cwe: "CWE-89"
"#;

        let mut temp_file = NamedTempFile::new().unwrap();
        temp_file.write_all(yaml_content.as_bytes()).unwrap();
        
        let mut rules = CustomPatternRules::with_empty_loader();
        let loaded_count = rules.load_patterns_from_file(temp_file.path()).unwrap();
        assert_eq!(loaded_count, 1);
        
        let source_file = SourceFile::new(
            PathBuf::from("test.java"),
            r#"String query = "SELECT * FROM users WHERE id = " + userId;"#.to_string(),
            Language::Java,
        );
        let ast = crate::parsers::ParsedAst::new_source_only(source_file.content.clone());
        
        let vulnerabilities = rules.analyze(&source_file, &ast).unwrap();
        assert_eq!(vulnerabilities.len(), 1);
        assert_eq!(vulnerabilities[0].id, "test-sql-injection");
        assert_eq!(vulnerabilities[0].vulnerability_type, "SQL Injection Risk");
    }

    #[test]
    fn test_pattern_statistics() {
        let yaml_content = r#"
version: "1.0"
name: "Test Security Patterns"
patterns:
  - id: "test-001"
    name: "Test Pattern 1"
    description: "Test pattern"
    severity: "High"
    category: "injection"
    languages: ["java", "python"]
    patterns:
      - regex: "test.*pattern"
    fix_suggestion: "Fix the issue"
  - id: "test-002"
    name: "Test Pattern 2"
    description: "Another test pattern"
    severity: "Medium"
    category: "validation"
    languages: ["javascript"]
    patterns:
      - regex: "another.*test"
    fix_suggestion: "Fix this too"
"#;

        let mut temp_file = NamedTempFile::new().unwrap();
        temp_file.write_all(yaml_content.as_bytes()).unwrap();
        
        let mut rules = CustomPatternRules::with_empty_loader();
        let loaded_count = rules.load_patterns_from_file(temp_file.path()).unwrap();
        assert_eq!(loaded_count, 2);
        
        let stats = rules.get_pattern_statistics();
        assert_eq!(stats.total_patterns, 2);
        assert_eq!(stats.patterns_by_category.get("injection"), Some(&1));
        assert_eq!(stats.patterns_by_category.get("validation"), Some(&1));
    }
}