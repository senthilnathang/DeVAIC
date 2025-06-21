use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use crate::{Language, Severity};
use super::pattern::{Pattern, PatternOperator};
use super::autofix::AutoFix;
use super::metavariable::MetavariableBinding;

#[derive(Debug, Clone, PartialEq, Serialize)]
pub struct SemgrepRule {
    /// Unique identifier for the rule
    pub id: String,
    
    /// Human-readable message describing what the rule detects
    pub message: String,
    
    /// Severity level of the vulnerability
    pub severity: SemgrepSeverity,
    
    /// Programming languages this rule applies to
    pub languages: Vec<Language>,
    
    /// The main pattern to match
    pub pattern: PatternOperator,
    
    /// Optional metadata about the rule
    #[serde(default)]
    pub metadata: HashMap<String, serde_yaml::Value>,
    
    /// Optional automatic fix suggestion
    #[serde(skip_serializing_if = "Option::is_none")]
    pub fix: Option<AutoFix>,
    
    /// Optional path filtering
    #[serde(skip_serializing_if = "Option::is_none")]
    pub paths: Option<PathFilter>,
    
    /// Optional rule options
    #[serde(default)]
    pub options: RuleOptions,
    
    /// Minimum Semgrep version required
    #[serde(skip_serializing_if = "Option::is_none")]
    pub min_version: Option<String>,
    
    /// Maximum Semgrep version supported
    #[serde(skip_serializing_if = "Option::is_none")]
    pub max_version: Option<String>,
}

impl<'de> Deserialize<'de> for SemgrepRule {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        use serde::de::Error;
        
        #[derive(Deserialize)]
        struct RuleHelper {
            id: String,
            message: String,
            severity: SemgrepSeverity,
            languages: Vec<Language>,
            #[serde(default)]
            metadata: HashMap<String, serde_yaml::Value>,
            fix: Option<String>,
            paths: Option<PathFilter>,
            #[serde(default)]
            options: RuleOptions,
            min_version: Option<String>,
            max_version: Option<String>,
            // Pattern fields - only one should be present
            pattern: Option<String>,
            #[serde(rename = "pattern-regex")]
            pattern_regex: Option<String>,
            patterns: Option<Vec<serde_yaml::Value>>,
            #[serde(rename = "pattern-either")]
            pattern_either: Option<Vec<serde_yaml::Value>>,
        }
        
        let helper = RuleHelper::deserialize(deserializer)?;
        
        // Determine the pattern type
        let pattern = if let Some(p) = helper.pattern {
            PatternOperator::Pattern(p)
        } else if let Some(p) = helper.pattern_regex {
            PatternOperator::PatternRegex(p)
        } else if let Some(patterns) = helper.patterns {
            // Convert patterns array to PatternOperator::Patterns
            let mut pattern_ops = Vec::new();
            for pattern_val in patterns {
                if let Some(pattern_str) = pattern_val.get("pattern").and_then(|v| v.as_str()) {
                    // Check if this pattern has an associated metavariable-regex
                    if let Some(metavar_regex) = pattern_val.get("metavariable-regex") {
                        if let (Some(metavar), Some(regex)) = (
                            metavar_regex.get("metavariable").and_then(|v| v.as_str()),
                            metavar_regex.get("regex").and_then(|v| v.as_str())
                        ) {
                            // Create a combined pattern with both the base pattern and metavariable constraint
                            let base_pattern = PatternOperator::Pattern(pattern_str.to_string());
                            let metavar_constraint = PatternOperator::MetavariableRegex {
                                metavariable: metavar.to_string(),
                                regex: regex.to_string(),
                            };
                            pattern_ops.push(PatternOperator::Patterns(vec![base_pattern, metavar_constraint]));
                        } else {
                            pattern_ops.push(PatternOperator::Pattern(pattern_str.to_string()));
                        }
                    } else {
                        pattern_ops.push(PatternOperator::Pattern(pattern_str.to_string()));
                    }
                } else if let Some(pattern_regex) = pattern_val.get("pattern-regex").and_then(|v| v.as_str()) {
                    pattern_ops.push(PatternOperator::PatternRegex(pattern_regex.to_string()));
                } else if let Some(_metavar_regex) = pattern_val.get("metavariable-regex") {
                    // Handle standalone metavariable-regex patterns
                    if let (Some(metavar), Some(regex)) = (
                        pattern_val.get("metavariable").and_then(|v| v.as_str()),
                        pattern_val.get("regex").and_then(|v| v.as_str())
                    ) {
                        pattern_ops.push(PatternOperator::MetavariableRegex {
                            metavariable: metavar.to_string(),
                            regex: regex.to_string(),
                        });
                    }
                } else if pattern_val.is_mapping() {
                    // Handle other complex pattern structures
                    let pattern_obj = parse_pattern_object(&pattern_val)?;
                    pattern_ops.push(pattern_obj);
                }
            }
            PatternOperator::Patterns(pattern_ops)
        } else if let Some(pattern_either) = helper.pattern_either {
            // Convert pattern-either array
            let mut pattern_ops = Vec::new();
            for pattern_val in pattern_either {
                if let Some(pattern_str) = pattern_val.get("pattern").and_then(|v| v.as_str()) {
                    pattern_ops.push(PatternOperator::Pattern(pattern_str.to_string()));
                } else if let Some(pattern_regex) = pattern_val.get("pattern-regex").and_then(|v| v.as_str()) {
                    pattern_ops.push(PatternOperator::PatternRegex(pattern_regex.to_string()));
                }
            }
            PatternOperator::PatternEither(pattern_ops)
        } else {
            return Err(D::Error::custom("Rule must have a pattern, pattern-regex, patterns, or pattern-either field"));
        };
        
        // Convert fix string to AutoFix if present
        let autofix = helper.fix.map(|fix_str| AutoFix::new(fix_str));
        
        Ok(SemgrepRule {
            id: helper.id,
            message: helper.message,
            severity: helper.severity,
            languages: helper.languages,
            pattern,
            metadata: helper.metadata,
            fix: autofix,
            paths: helper.paths,
            options: helper.options,
            min_version: helper.min_version,
            max_version: helper.max_version,
        })
    }
}

fn parse_pattern_object<E>(pattern_val: &serde_yaml::Value) -> Result<PatternOperator, E>
where
    E: serde::de::Error,
{
    if let Some(pattern_str) = pattern_val.get("pattern").and_then(|v| v.as_str()) {
        Ok(PatternOperator::Pattern(pattern_str.to_string()))
    } else if let Some(pattern_regex) = pattern_val.get("pattern-regex").and_then(|v| v.as_str()) {
        Ok(PatternOperator::PatternRegex(pattern_regex.to_string()))
    } else if let Some(_metavar_regex) = pattern_val.get("metavariable-regex") {
        if let (Some(metavar), Some(regex)) = (
            pattern_val.get("metavariable").and_then(|v| v.as_str()),
            pattern_val.get("regex").and_then(|v| v.as_str())
        ) {
            Ok(PatternOperator::MetavariableRegex {
                metavariable: metavar.to_string(),
                regex: regex.to_string(),
            })
        } else {
            Err(E::custom("metavariable-regex must have both metavariable and regex fields"))
        }
    } else {
        Err(E::custom("Unknown pattern structure"))
    }
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum SemgrepSeverity {
    Info,
    Warning,
    Error,
}

impl From<SemgrepSeverity> for Severity {
    fn from(severity: SemgrepSeverity) -> Self {
        match severity {
            SemgrepSeverity::Info => Severity::Info,
            SemgrepSeverity::Warning => Severity::Medium,
            SemgrepSeverity::Error => Severity::High,
        }
    }
}

impl From<Severity> for SemgrepSeverity {
    fn from(severity: Severity) -> Self {
        match severity {
            Severity::Info | Severity::Low => SemgrepSeverity::Info,
            Severity::Medium => SemgrepSeverity::Warning,
            Severity::High | Severity::Critical => SemgrepSeverity::Error,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, Default)]
pub struct PathFilter {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub include: Option<Vec<String>>,
    
    #[serde(skip_serializing_if = "Option::is_none")]
    pub exclude: Option<Vec<String>>,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, Default)]
pub struct RuleOptions {
    /// Enable/disable symbolic execution
    #[serde(default)]
    pub symbolic_execution: bool,
    
    /// Enable/disable taint analysis
    #[serde(default)]
    pub taint_analysis: bool,
    
    /// Generic pattern matching options
    #[serde(default)]
    pub generic: bool,
    
    /// Maximum depth for nested pattern matching
    #[serde(default = "default_max_depth")]
    pub max_depth: usize,
}

fn default_max_depth() -> usize {
    10
}

impl SemgrepRule {
    pub fn new(
        id: String,
        message: String,
        severity: SemgrepSeverity,
        languages: Vec<Language>,
        pattern: PatternOperator,
    ) -> Self {
        Self {
            id,
            message,
            severity,
            languages,
            pattern,
            metadata: HashMap::new(),
            fix: None,
            paths: None,
            options: RuleOptions::default(),
            min_version: None,
            max_version: None,
        }
    }
    
    pub fn with_metadata(mut self, metadata: HashMap<String, serde_yaml::Value>) -> Self {
        self.metadata = metadata;
        self
    }
    
    pub fn with_fix(mut self, fix: AutoFix) -> Self {
        self.fix = Some(fix);
        self
    }
    
    pub fn with_paths(mut self, paths: PathFilter) -> Self {
        self.paths = Some(paths);
        self
    }
    
    pub fn with_options(mut self, options: RuleOptions) -> Self {
        self.options = options;
        self
    }
    
    /// Check if this rule applies to the given language
    pub fn applies_to_language(&self, language: &Language) -> bool {
        self.languages.contains(language)
    }
    
    /// Check if this rule applies to the given file path
    pub fn applies_to_path(&self, path: &std::path::Path) -> bool {
        if let Some(path_filter) = &self.paths {
            let path_str = path.to_string_lossy();
            
            // Check exclude patterns first
            if let Some(exclude_patterns) = &path_filter.exclude {
                for pattern in exclude_patterns {
                    if glob_match(pattern, &path_str) {
                        return false;
                    }
                }
            }
            
            // Check include patterns
            if let Some(include_patterns) = &path_filter.include {
                for pattern in include_patterns {
                    if glob_match(pattern, &path_str) {
                        return true;
                    }
                }
                // If include patterns are specified and none match, exclude the file
                return false;
            }
        }
        
        // No path filtering or path matches criteria
        true
    }
    
    /// Get CWE ID from metadata if available
    pub fn get_cwe(&self) -> Option<String> {
        self.metadata.get("cwe")
            .and_then(|v| v.as_str())
            .map(|s| s.to_string())
    }
    
    /// Get OWASP category from metadata if available
    pub fn get_owasp_category(&self) -> Option<String> {
        self.metadata.get("owasp")
            .and_then(|v| v.as_str())
            .map(|s| s.to_string())
    }
    
    /// Get security category from metadata
    pub fn get_category(&self) -> String {
        self.metadata.get("category")
            .and_then(|v| v.as_str())
            .unwrap_or("security")
            .to_string()
    }
    
    /// Interpolate message with metavariable bindings
    pub fn interpolate_message(&self, bindings: &MetavariableBinding) -> String {
        bindings.interpolate_message(&self.message)
    }
    
    /// Validate the rule
    pub fn validate(&self) -> Result<(), String> {
        if self.id.is_empty() {
            return Err("Rule ID cannot be empty".to_string());
        }
        
        if self.message.is_empty() {
            return Err("Rule message cannot be empty".to_string());
        }
        
        if self.languages.is_empty() {
            return Err("Rule must specify at least one language".to_string());
        }
        
        // Validate pattern
        let pattern = Pattern::new(self.pattern.clone(), self.languages[0]);
        pattern.validate()?;
        
        Ok(())
    }
}

#[derive(Debug, Clone)]
pub struct SemgrepRuleSet {
    pub rules: Vec<SemgrepRule>,
}

impl SemgrepRuleSet {
    pub fn new() -> Self {
        Self {
            rules: Vec::new(),
        }
    }
    
    pub fn add_rule(&mut self, rule: SemgrepRule) {
        self.rules.push(rule);
    }
    
    pub fn get_rules_for_language(&self, language: &Language) -> Vec<&SemgrepRule> {
        self.rules.iter()
            .filter(|rule| rule.applies_to_language(language))
            .collect()
    }
    
    pub fn get_rules_for_path(&self, path: &std::path::Path, language: &Language) -> Vec<&SemgrepRule> {
        self.rules.iter()
            .filter(|rule| rule.applies_to_language(language) && rule.applies_to_path(path))
            .collect()
    }
    
    pub fn load_from_yaml(content: &str) -> Result<Self, serde_yaml::Error> {
        #[derive(Deserialize)]
        struct RuleFile {
            rules: Vec<SemgrepRule>,
        }
        
        let rule_file: RuleFile = serde_yaml::from_str(content)?;
        Ok(Self {
            rules: rule_file.rules,
        })
    }
    
    pub fn load_from_file(path: &std::path::Path) -> Result<Self, Box<dyn std::error::Error>> {
        let content = std::fs::read_to_string(path)?;
        Ok(Self::load_from_yaml(&content)?)
    }
    
    pub fn validate_all(&self) -> Result<(), Vec<String>> {
        let mut errors = Vec::new();
        
        for (index, rule) in self.rules.iter().enumerate() {
            if let Err(error) = rule.validate() {
                errors.push(format!("Rule {} (index {}): {}", rule.id, index, error));
            }
        }
        
        if errors.is_empty() {
            Ok(())
        } else {
            Err(errors)
        }
    }
    
    pub fn len(&self) -> usize {
        self.rules.len()
    }
    
    pub fn is_empty(&self) -> bool {
        self.rules.is_empty()
    }
}

impl Default for SemgrepRuleSet {
    fn default() -> Self {
        Self::new()
    }
}

/// Simple glob pattern matching
fn glob_match(pattern: &str, text: &str) -> bool {
    // Simple implementation - could be enhanced with a proper glob library
    if pattern.contains('*') {
        let parts: Vec<&str> = pattern.split('*').collect();
        if parts.len() == 2 {
            let prefix = parts[0];
            let suffix = parts[1];
            return text.starts_with(prefix) && text.ends_with(suffix);
        }
    }
    
    pattern == text
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::Language;
    
    #[test]
    fn test_rule_creation() {
        let rule = SemgrepRule::new(
            "test-rule".to_string(),
            "Test rule".to_string(),
            SemgrepSeverity::Error,
            vec![Language::Javascript],
            PatternOperator::Pattern("console.log(...)".to_string()),
        );
        
        assert_eq!(rule.id, "test-rule");
        assert_eq!(rule.message, "Test rule");
        assert_eq!(rule.severity, SemgrepSeverity::Error);
        assert!(rule.applies_to_language(&Language::Javascript));
        assert!(!rule.applies_to_language(&Language::Python));
    }
    
    #[test]
    fn test_path_filtering() {
        use std::path::PathBuf;
        
        let mut rule = SemgrepRule::new(
            "test-rule".to_string(),
            "Test rule".to_string(),
            SemgrepSeverity::Error,
            vec![Language::Javascript],
            PatternOperator::Pattern("console.log(...)".to_string()),
        );
        
        rule.paths = Some(PathFilter {
            include: Some(vec!["*.js".to_string()]),
            exclude: Some(vec!["node_modules/*".to_string()]),
        });
        
        assert!(rule.applies_to_path(&PathBuf::from("src/main.js")));
        assert!(!rule.applies_to_path(&PathBuf::from("node_modules/lib.js")));
        assert!(!rule.applies_to_path(&PathBuf::from("src/main.py")));
    }
    
    #[test]
    fn test_severity_conversion() {
        assert_eq!(Severity::from(SemgrepSeverity::Info), Severity::Info);
        assert_eq!(Severity::from(SemgrepSeverity::Warning), Severity::Medium);
        assert_eq!(Severity::from(SemgrepSeverity::Error), Severity::High);
        
        assert_eq!(SemgrepSeverity::from(Severity::Low), SemgrepSeverity::Info);
        assert_eq!(SemgrepSeverity::from(Severity::Medium), SemgrepSeverity::Warning);
        assert_eq!(SemgrepSeverity::from(Severity::Critical), SemgrepSeverity::Error);
    }
    
    #[test]
    fn test_rule_validation() {
        let valid_rule = SemgrepRule::new(
            "valid-rule".to_string(),
            "Valid rule message".to_string(),
            SemgrepSeverity::Error,
            vec![Language::Javascript],
            PatternOperator::Pattern("console.log(...)".to_string()),
        );
        
        assert!(valid_rule.validate().is_ok());
        
        let invalid_rule = SemgrepRule::new(
            "".to_string(), // Empty ID
            "Valid rule message".to_string(),
            SemgrepSeverity::Error,
            vec![Language::Javascript],
            PatternOperator::Pattern("console.log(...)".to_string()),
        );
        
        assert!(invalid_rule.validate().is_err());
    }
    
    #[test]
    fn test_yaml_serialization() {
        let rule = SemgrepRule::new(
            "test-rule".to_string(),
            "Test rule for console.log".to_string(),
            SemgrepSeverity::Warning,
            vec![Language::Javascript],
            PatternOperator::Pattern("console.log(...)".to_string()),
        );
        
        let yaml = serde_yaml::to_string(&rule).unwrap();
        assert!(yaml.contains("id: test-rule"));
        assert!(yaml.contains("message: Test rule for console.log"));
        assert!(yaml.contains("severity: warning"));
    }
}