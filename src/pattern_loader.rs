use crate::{
    error::{DevaicError, Result},
    Language, Severity,
};
use regex::Regex;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::fs;
use std::path::Path;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SecurityPattern {
    pub id: String,
    pub name: String,
    pub description: String,
    pub severity: Severity,
    pub category: String,
    pub languages: Vec<String>,
    pub patterns: Vec<RegexPattern>,
    pub fix_suggestion: Option<String>,
    pub cwe: Option<String>,
    pub owasp: Option<String>,
    pub references: Option<Vec<String>>,
    pub metadata: Option<HashMap<String, String>>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RegexPattern {
    pub regex: String,
    pub flags: Option<String>,
    pub description: Option<String>,
    pub confidence: Option<f32>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PatternFile {
    pub version: String,
    pub name: String,
    pub description: Option<String>,
    pub author: Option<String>,
    pub license: Option<String>,
    pub patterns: Vec<SecurityPattern>,
}

#[derive(Debug, Clone)]
pub struct CompiledPattern {
    pub pattern: SecurityPattern,
    pub compiled_regex: Vec<CompiledRegex>,
}

#[derive(Debug, Clone)]
pub struct CompiledRegex {
    pub regex: Regex,
    pub original_pattern: String,
    pub description: Option<String>,
    pub confidence: f32,
}

pub struct PatternLoader {
    loaded_patterns: HashMap<String, Vec<CompiledPattern>>,
}

impl PatternLoader {
    pub fn new() -> Self {
        Self {
            loaded_patterns: HashMap::new(),
        }
    }

    /// Load patterns from a YAML file
    pub fn load_from_file<P: AsRef<Path>>(&mut self, file_path: P) -> Result<usize> {
        let content = fs::read_to_string(&file_path)?;
        let pattern_file: PatternFile = serde_yaml::from_str(&content)
            .map_err(|e| DevaicError::Config(format!("Failed to parse YAML: {}", e)))?;

        self.validate_pattern_file(&pattern_file)?;
        let loaded_count = self.compile_and_store_patterns(pattern_file)?;
        
        Ok(loaded_count)
    }

    /// Load patterns from a directory containing YAML files
    pub fn load_from_directory<P: AsRef<Path>>(&mut self, dir_path: P) -> Result<usize> {
        let mut total_loaded = 0;
        
        for entry in fs::read_dir(&dir_path)? {
            let entry = entry?;
            let path = entry.path();
            
            if path.is_file() && path.extension().map_or(false, |ext| ext == "yml" || ext == "yaml") {
                match self.load_from_file(&path) {
                    Ok(count) => {
                        total_loaded += count;
                        log::info!("Loaded {} patterns from {}", count, path.display());
                    }
                    Err(e) => {
                        log::warn!("Failed to load patterns from {}: {}", path.display(), e);
                    }
                }
            }
        }
        
        Ok(total_loaded)
    }

    /// Get all loaded patterns for a specific language
    pub fn get_patterns_for_language(&self, language: &Language) -> Vec<&CompiledPattern> {
        let language_str = language.to_string().to_lowercase();
        
        self.loaded_patterns
            .get(&language_str)
            .map(|patterns| patterns.iter().collect())
            .unwrap_or_default()
    }

    /// Get all loaded patterns
    pub fn get_all_patterns(&self) -> Vec<&CompiledPattern> {
        self.loaded_patterns
            .values()
            .flat_map(|patterns| patterns.iter())
            .collect()
    }

    /// Get statistics about loaded patterns
    pub fn get_statistics(&self) -> PatternStatistics {
        let mut stats = PatternStatistics::new();
        let mut seen_patterns = std::collections::HashSet::new();
        
        for patterns in self.loaded_patterns.values() {
            for pattern in patterns {
                // Only count each unique pattern ID once
                if seen_patterns.insert(pattern.pattern.id.clone()) {
                    stats.total_patterns += 1;
                    stats.patterns_by_severity.entry(pattern.pattern.severity.clone()).and_modify(|e| *e += 1).or_insert(1);
                    stats.patterns_by_category.entry(pattern.pattern.category.clone()).and_modify(|e| *e += 1).or_insert(1);
                    
                    for lang in &pattern.pattern.languages {
                        stats.patterns_by_language.entry(lang.clone()).and_modify(|e| *e += 1).or_insert(1);
                    }
                }
            }
        }
        
        stats
    }

    /// Validate a pattern file structure
    fn validate_pattern_file(&self, pattern_file: &PatternFile) -> Result<()> {
        if pattern_file.patterns.is_empty() {
            return Err(DevaicError::Config("Pattern file contains no patterns".to_string()));
        }

        for pattern in &pattern_file.patterns {
            self.validate_pattern(pattern)?;
        }

        Ok(())
    }

    /// Validate a single pattern
    fn validate_pattern(&self, pattern: &SecurityPattern) -> Result<()> {
        if pattern.id.is_empty() {
            return Err(DevaicError::Config("Pattern ID cannot be empty".to_string()));
        }

        if pattern.name.is_empty() {
            return Err(DevaicError::Config("Pattern name cannot be empty".to_string()));
        }

        if pattern.languages.is_empty() {
            return Err(DevaicError::Config(format!("Pattern '{}' must specify at least one language", pattern.id)));
        }

        if pattern.patterns.is_empty() {
            return Err(DevaicError::Config(format!("Pattern '{}' must have at least one regex pattern", pattern.id)));
        }

        // Validate that all languages are supported
        for lang in &pattern.languages {
            let lang_lower = lang.to_lowercase();
            let supported = match lang_lower.as_str() {
                "all" => true,
                "c" => true,
                "cpp" | "c++" => true,
                "python" | "py" => true,
                "java" => true,
                "javascript" | "js" => true,
                "typescript" | "ts" => true,
                "go" => true,
                "php" => true,
                "ruby" | "rb" => true,
                "kotlin" | "kt" => true,
                "csharp" | "cs" | "c#" => true,
                "bash" | "sh" => true,
                "scada" | "st" => true,
                "cobol" | "cob" => true,
                "pascal" | "pas" => true,
                "rust" | "rs" => true,
                _ => false,
            };
            
            if !supported {
                return Err(DevaicError::Config(format!("Unsupported language '{}' in pattern '{}'", lang, pattern.id)));
            }
        }

        // Validate regex patterns
        for (i, regex_pattern) in pattern.patterns.iter().enumerate() {
            if let Err(e) = Regex::new(&regex_pattern.regex) {
                return Err(DevaicError::Config(format!(
                    "Invalid regex in pattern '{}' at index {}: {}",
                    pattern.id, i, e
                )));
            }
        }

        Ok(())
    }

    /// Compile and store patterns
    fn compile_and_store_patterns(&mut self, pattern_file: PatternFile) -> Result<usize> {
        let mut loaded_count = 0;

        for pattern in pattern_file.patterns {
            let compiled_pattern = self.compile_pattern(pattern)?;
            
            // Store pattern for each language it applies to
            for lang in &compiled_pattern.pattern.languages {
                if lang == "all" {
                    // Add to all supported languages
                    for language in Language::all() {
                        let lang_key = language.to_string().to_lowercase();
                        self.loaded_patterns
                            .entry(lang_key)
                            .or_insert_with(Vec::new)
                            .push(compiled_pattern.clone());
                    }
                } else {
                    // Map language aliases to standard names
                    let lang_lower = lang.to_lowercase();
                    let lang_key = match lang_lower.as_str() {
                        "py" => "python",
                        "js" => "javascript",
                        "ts" => "typescript",
                        "rb" => "ruby",
                        "kt" => "kotlin",
                        "cs" | "c#" => "csharp",
                        "sh" => "bash",
                        "st" => "scada",
                        "cob" => "cobol",
                        "pas" => "pascal",
                        "c++" => "cpp",
                        "rs" => "rust",
                        other => other,
                    };
                    
                    self.loaded_patterns
                        .entry(lang_key.to_string())
                        .or_insert_with(Vec::new)
                        .push(compiled_pattern.clone());
                }
            }
            
            loaded_count += 1;
        }

        Ok(loaded_count)
    }

    /// Compile a single pattern
    fn compile_pattern(&self, pattern: SecurityPattern) -> Result<CompiledPattern> {
        let mut compiled_regex = Vec::new();

        for regex_pattern in &pattern.patterns {
            let regex = Regex::new(&regex_pattern.regex)
                .map_err(|e| DevaicError::Config(format!("Failed to compile regex '{}': {}", regex_pattern.regex, e)))?;

            compiled_regex.push(CompiledRegex {
                regex,
                original_pattern: regex_pattern.regex.clone(),
                description: regex_pattern.description.clone(),
                confidence: regex_pattern.confidence.unwrap_or(0.8),
            });
        }

        Ok(CompiledPattern {
            pattern,
            compiled_regex,
        })
    }
}

#[derive(Debug, Clone)]
pub struct PatternStatistics {
    pub total_patterns: usize,
    pub patterns_by_language: HashMap<String, usize>,
    pub patterns_by_severity: HashMap<Severity, usize>,
    pub patterns_by_category: HashMap<String, usize>,
}

impl PatternStatistics {
    pub fn new() -> Self {
        Self {
            total_patterns: 0,
            patterns_by_language: HashMap::new(),
            patterns_by_severity: HashMap::new(),
            patterns_by_category: HashMap::new(),
        }
    }

    pub fn print_summary(&self) {
        println!("Pattern Statistics:");
        println!("  Total patterns: {}", self.total_patterns);
        
        println!("  By language:");
        let mut lang_stats: Vec<_> = self.patterns_by_language.iter().collect();
        lang_stats.sort_by_key(|(_, count)| std::cmp::Reverse(**count));
        for (lang, count) in lang_stats {
            println!("    {}: {}", lang, count);
        }
        
        println!("  By severity:");
        let mut sev_stats: Vec<_> = self.patterns_by_severity.iter().collect();
        sev_stats.sort_by_key(|(_, count)| std::cmp::Reverse(**count));
        for (severity, count) in sev_stats {
            println!("    {:?}: {}", severity, count);
        }
        
        println!("  By category:");
        let mut cat_stats: Vec<_> = self.patterns_by_category.iter().collect();
        cat_stats.sort_by_key(|(_, count)| std::cmp::Reverse(**count));
        for (category, count) in cat_stats {
            println!("    {}: {}", category, count);
        }
    }
}

impl Default for PatternLoader {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::NamedTempFile;
    use std::io::Write;

    #[test]
    fn test_pattern_file_parsing() {
        let yaml_content = r#"
version: "1.0"
name: "Test Security Patterns"
description: "Test patterns for security analysis"
author: "Test Author"
license: "MIT"
patterns:
  - id: "test-001"
    name: "SQL Injection Test"
    description: "Detects potential SQL injection vulnerabilities"
    severity: "High"
    category: "injection"
    languages: ["java", "python"]
    patterns:
      - regex: "SELECT.*FROM.*WHERE.*\\$\\{.*\\}"
        description: "Direct SQL string interpolation"
        confidence: 0.9
    fix_suggestion: "Use parameterized queries"
    cwe: "CWE-89"
    owasp: "A03:2021"
    references:
      - "https://owasp.org/www-community/attacks/SQL_Injection"
"#;

        let pattern_file: PatternFile = serde_yaml::from_str(yaml_content).unwrap();
        assert_eq!(pattern_file.version, "1.0");
        assert_eq!(pattern_file.name, "Test Security Patterns");
        assert_eq!(pattern_file.patterns.len(), 1);
        
        let pattern = &pattern_file.patterns[0];
        assert_eq!(pattern.id, "test-001");
        assert_eq!(pattern.name, "SQL Injection Test");
        assert_eq!(pattern.severity, Severity::High);
        assert_eq!(pattern.languages, vec!["java", "python"]);
        assert_eq!(pattern.patterns.len(), 1);
    }

    #[test]
    fn test_pattern_validation() {
        let loader = PatternLoader::new();
        
        let valid_pattern = SecurityPattern {
            id: "test-001".to_string(),
            name: "Test Pattern".to_string(),
            description: "A test pattern".to_string(),
            severity: Severity::Medium,
            category: "test".to_string(),
            languages: vec!["java".to_string()],
            patterns: vec![RegexPattern {
                regex: r"test.*pattern".to_string(),
                flags: None,
                description: None,
                confidence: Some(0.8),
            }],
            fix_suggestion: None,
            cwe: None,
            owasp: None,
            references: None,
            metadata: None,
        };

        assert!(loader.validate_pattern(&valid_pattern).is_ok());
        
        let invalid_pattern = SecurityPattern {
            id: "".to_string(), // Empty ID
            name: "Test Pattern".to_string(),
            description: "A test pattern".to_string(),
            severity: Severity::Medium,
            category: "test".to_string(),
            languages: vec!["java".to_string()],
            patterns: vec![RegexPattern {
                regex: r"test.*pattern".to_string(),
                flags: None,
                description: None,
                confidence: Some(0.8),
            }],
            fix_suggestion: None,
            cwe: None,
            owasp: None,
            references: None,
            metadata: None,
        };

        assert!(loader.validate_pattern(&invalid_pattern).is_err());
    }

    #[test]
    fn test_pattern_loading_from_file() {
        let yaml_content = r#"
version: "1.0"
name: "Test Patterns"
patterns:
  - id: "test-001"
    name: "Test Pattern"
    description: "A test pattern"
    severity: "Medium"
    category: "test"
    languages: ["java"]
    patterns:
      - regex: "test.*pattern"
        confidence: 0.8
"#;

        let mut temp_file = NamedTempFile::new().unwrap();
        temp_file.write_all(yaml_content.as_bytes()).unwrap();
        
        let mut loader = PatternLoader::new();
        let result = loader.load_from_file(temp_file.path());
        
        assert!(result.is_ok());
        assert_eq!(result.unwrap(), 1);
        
        let patterns = loader.get_patterns_for_language(&Language::Java);
        assert_eq!(patterns.len(), 1);
        assert_eq!(patterns[0].pattern.id, "test-001");
    }
}