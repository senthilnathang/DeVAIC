use std::collections::HashMap;
use std::path::{Path, PathBuf};
use walkdir::WalkDir;

use crate::{Language, Severity, Vulnerability, parsers::{SourceFile, ParsedAst}};
use super::{
    rule::{SemgrepRule, SemgrepRuleSet},
    matcher::{SemgrepMatcher, SemgrepMatch},
    output::{SarifOutput, SarifReporter},
};

// Trait to abstract over different AST representations
pub trait AstLike {
    fn source(&self) -> &str;
    fn root_node(&self) -> (); // Simplified - in real implementation would return tree-sitter Node
}

impl AstLike for ParsedAst {
    fn source(&self) -> &str {
        &self.source
    }
    
    fn root_node(&self) -> () {
        // Would return self.tree.as_ref().map(|t| t.root_node()) in real implementation
    }
}

pub struct SemgrepEngine {
    rules: SemgrepRuleSet,
    matchers: HashMap<Language, SemgrepMatcher>,
}

impl SemgrepEngine {
    pub fn new() -> Self {
        let mut matchers = HashMap::new();
        matchers.insert(Language::Javascript, SemgrepMatcher::new(Language::Javascript));
        matchers.insert(Language::TypeScript, SemgrepMatcher::new(Language::TypeScript));
        matchers.insert(Language::Python, SemgrepMatcher::new(Language::Python));
        matchers.insert(Language::Java, SemgrepMatcher::new(Language::Java));
        matchers.insert(Language::C, SemgrepMatcher::new(Language::C));
        matchers.insert(Language::Cpp, SemgrepMatcher::new(Language::Cpp));
        
        Self {
            rules: SemgrepRuleSet::new(),
            matchers,
        }
    }
    
    /// Load rules from a directory containing YAML rule files
    pub fn load_rules_from_directory(&mut self, rules_dir: &Path) -> Result<usize, Box<dyn std::error::Error>> {
        let mut loaded_count = 0;
        
        for entry in WalkDir::new(rules_dir)
            .into_iter()
            .filter_map(|e| e.ok())
            .filter(|e| e.file_type().is_file())
            .filter(|e| e.path().extension().map_or(false, |ext| ext == "yml" || ext == "yaml"))
        {
            match self.load_rules_from_file(entry.path()) {
                Ok(count) => {
                    loaded_count += count;
                    println!("Loaded {} rules from {}", count, entry.path().display());
                }
                Err(e) => {
                    eprintln!("Failed to load rules from {}: {}", entry.path().display(), e);
                }
            }
        }
        
        Ok(loaded_count)
    }
    
    /// Load rules from a single YAML file
    pub fn load_rules_from_file(&mut self, file_path: &Path) -> Result<usize, Box<dyn std::error::Error>> {
        let ruleset = SemgrepRuleSet::load_from_file(file_path)?;
        let count = ruleset.len();
        
        for rule in ruleset.rules {
            self.rules.add_rule(rule);
        }
        
        Ok(count)
    }
    
    /// Add a single rule to the engine
    pub fn add_rule(&mut self, rule: SemgrepRule) {
        self.rules.add_rule(rule);
    }
    
    /// Analyze a source file with Semgrep rules
    pub fn analyze_file<T: AstLike>(
        &self,
        source_file: &SourceFile,
        ast: &T,
    ) -> Result<Vec<SemgrepVulnerability>, String> {
        let applicable_rules = self.rules.get_rules_for_path(&source_file.path, &source_file.language);
        let mut vulnerabilities = Vec::new();
        
        if let Some(matcher) = self.matchers.get(&source_file.language) {
            for rule in applicable_rules {
                let matches = matcher.find_matches(rule, source_file, ast)?;
                
                for semgrep_match in matches {
                    let vulnerability = SemgrepVulnerability::from_match_and_rule(semgrep_match, rule);
                    vulnerabilities.push(vulnerability);
                }
            }
        }
        
        Ok(vulnerabilities)
    }
    
    /// Analyze multiple files
    pub fn analyze_files<T: AstLike>(
        &self,
        files: &[(SourceFile, T)],
    ) -> Result<Vec<SemgrepVulnerability>, String> {
        let mut all_vulnerabilities = Vec::new();
        
        for (source_file, ast) in files {
            let vulnerabilities = self.analyze_file(source_file, ast)?;
            all_vulnerabilities.extend(vulnerabilities);
        }
        
        Ok(all_vulnerabilities)
    }
    
    /// Get all loaded rules
    pub fn get_rules(&self) -> &SemgrepRuleSet {
        &self.rules
    }
    
    /// Get rules for a specific language
    pub fn get_rules_for_language(&self, language: &Language) -> Vec<&SemgrepRule> {
        self.rules.get_rules_for_language(language)
    }
    
    /// Validate all loaded rules
    pub fn validate_rules(&self) -> Result<(), Vec<String>> {
        self.rules.validate_all()
    }
    
    /// Generate SARIF output from vulnerabilities
    pub fn generate_sarif_output(
        &self,
        vulnerabilities: &[SemgrepVulnerability],
        analysis_duration: std::time::Duration,
    ) -> SarifOutput {
        let classic_vulnerabilities: Vec<Vulnerability> = vulnerabilities
            .iter()
            .map(|v| v.to_vulnerability())
            .collect();
        
        SarifReporter::create_report(&classic_vulnerabilities, analysis_duration)
    }
    
    /// Get statistics about loaded rules
    pub fn get_rule_statistics(&self) -> RuleStatistics {
        let mut stats = RuleStatistics::new();
        
        for rule in &self.rules.rules {
            stats.total_rules += 1;
            
            // Count by language
            for language in &rule.languages {
                *stats.rules_by_language.entry(*language).or_insert(0) += 1;
            }
            
            // Count by severity
            match rule.severity {
                super::rule::SemgrepSeverity::Info => stats.info_rules += 1,
                super::rule::SemgrepSeverity::Warning => stats.warning_rules += 1,
                super::rule::SemgrepSeverity::Error => stats.error_rules += 1,
            }
            
            // Count by category
            let category = rule.get_category();
            *stats.rules_by_category.entry(category).or_insert(0) += 1;
        }
        
        stats
    }
}

impl Default for SemgrepEngine {
    fn default() -> Self {
        Self::new()
    }
}

#[derive(Debug, Clone)]
pub struct SemgrepVulnerability {
    pub rule_id: String,
    pub message: String,
    pub severity: Severity,
    pub file_path: PathBuf,
    pub line_number: usize,
    pub column: usize,
    pub matched_text: String,
    pub bindings: super::metavariable::MetavariableBinding,
    pub category: String,
    pub cwe: Option<String>,
    pub recommendation: String,
}

impl SemgrepVulnerability {
    pub fn from_match_and_rule(semgrep_match: SemgrepMatch, rule: &SemgrepRule) -> Self {
        let interpolated_message = rule.interpolate_message(&semgrep_match.bindings);
        
        Self {
            rule_id: rule.id.clone(),
            message: interpolated_message,
            severity: rule.severity.clone().into(),
            file_path: semgrep_match.file_path,
            line_number: semgrep_match.line_number,
            column: semgrep_match.range.start_point.column,
            matched_text: semgrep_match.matched_text.clone(),
            bindings: semgrep_match.bindings.clone(),
            category: rule.get_category(),
            cwe: rule.get_cwe(),
            recommendation: rule.fix.as_ref()
                .and_then(|fix| fix.get_message(&semgrep_match.bindings))
                .unwrap_or_else(|| "Review and fix this security issue".to_string()),
        }
    }
    
    pub fn to_vulnerability(&self) -> Vulnerability {
        Vulnerability {
            id: self.rule_id.clone(),
            cwe: self.cwe.clone(),
            vulnerability_type: format!("Semgrep: {}", self.rule_id),
            severity: self.severity.clone(),
            category: self.category.clone(),
            description: self.message.clone(),
            file_path: self.file_path.to_string_lossy().to_string(),
            line_number: self.line_number,
            column: self.column,
            source_code: self.matched_text.clone(),
            recommendation: self.recommendation.clone(),
        }
    }
    
    pub fn get_interpolated_fix(&self, rule: &SemgrepRule) -> Option<String> {
        rule.fix.as_ref()
            .and_then(|fix| fix.apply(&self.matched_text, &self.bindings))
    }
}

#[derive(Debug, Default)]
pub struct RuleStatistics {
    pub total_rules: usize,
    pub info_rules: usize,
    pub warning_rules: usize,
    pub error_rules: usize,
    pub rules_by_language: HashMap<Language, usize>,
    pub rules_by_category: HashMap<String, usize>,
}

impl RuleStatistics {
    pub fn new() -> Self {
        Self::default()
    }
    
    pub fn print_summary(&self) {
        println!("Rule Statistics:");
        println!("  Total rules: {}", self.total_rules);
        println!("  By severity:");
        println!("    Info: {}", self.info_rules);
        println!("    Warning: {}", self.warning_rules);
        println!("    Error: {}", self.error_rules);
        
        println!("  By language:");
        for (language, count) in &self.rules_by_language {
            println!("    {:?}: {}", language, count);
        }
        
        println!("  By category:");
        for (category, count) in &self.rules_by_category {
            println!("    {}: {}", category, count);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::semgrep::{pattern::PatternOperator, rule::SemgrepSeverity};
    use std::collections::HashMap;
    
    #[test]
    fn test_engine_creation() {
        let engine = SemgrepEngine::new();
        assert_eq!(engine.rules.len(), 0);
        assert!(engine.matchers.contains_key(&Language::Javascript));
        assert!(engine.matchers.contains_key(&Language::TypeScript));
        assert!(engine.matchers.contains_key(&Language::Python));
    }
    
    #[test]
    fn test_add_rule() {
        let mut engine = SemgrepEngine::new();
        
        let rule = SemgrepRule::new(
            "test-rule".to_string(),
            "Test rule".to_string(),
            SemgrepSeverity::Error,
            vec![Language::Javascript],
            PatternOperator::Pattern("eval(...)".to_string()),
        );
        
        engine.add_rule(rule);
        assert_eq!(engine.rules.len(), 1);
        
        let js_rules = engine.get_rules_for_language(&Language::Javascript);
        assert_eq!(js_rules.len(), 1);
        assert_eq!(js_rules[0].id, "test-rule");
    }
    
    #[test]
    fn test_rule_statistics() {
        let mut engine = SemgrepEngine::new();
        
        // Add some test rules
        engine.add_rule(SemgrepRule::new(
            "js-rule-1".to_string(),
            "JS Rule 1".to_string(),
            SemgrepSeverity::Error,
            vec![Language::Javascript],
            PatternOperator::Pattern("eval(...)".to_string()),
        ));
        
        engine.add_rule(SemgrepRule::new(
            "py-rule-1".to_string(),
            "Python Rule 1".to_string(),
            SemgrepSeverity::Warning,
            vec![Language::Python],
            PatternOperator::Pattern("exec(...)".to_string()),
        ));
        
        let stats = engine.get_rule_statistics();
        assert_eq!(stats.total_rules, 2);
        assert_eq!(stats.error_rules, 1);
        assert_eq!(stats.warning_rules, 1);
        assert_eq!(stats.rules_by_language[&Language::Javascript], 1);
        assert_eq!(stats.rules_by_language[&Language::Python], 1);
    }
    
    #[test]
    fn test_vulnerability_conversion() {
        let rule = SemgrepRule::new(
            "test-rule".to_string(),
            "Test vulnerability in $FUNC".to_string(),
            SemgrepSeverity::Error,
            vec![Language::Javascript],
            PatternOperator::Pattern("eval($ARG)".to_string()),
        );
        
        let mut bindings = super::super::metavariable::MetavariableBinding::new();
        let range = tree_sitter::Range {
            start_byte: 0,
            end_byte: 10,
            start_point: tree_sitter::Point { row: 5, column: 10 },
            end_point: tree_sitter::Point { row: 5, column: 20 },
        };
        
        bindings.bind("$FUNC".to_string(), "dangerousFunction".to_string(), range);
        bindings.bind("$ARG".to_string(), "userInput".to_string(), range);
        
        let semgrep_match = SemgrepMatch {
            range,
            bindings,
            matched_text: "eval(userInput)".to_string(),
            file_path: PathBuf::from("test.js"),
            line_number: 6,
        };
        
        let vulnerability = SemgrepVulnerability::from_match_and_rule(semgrep_match, &rule);
        
        assert_eq!(vulnerability.rule_id, "test-rule");
        assert_eq!(vulnerability.message, "Test vulnerability in dangerousFunction");
        assert_eq!(vulnerability.line_number, 6);
        assert_eq!(vulnerability.matched_text, "eval(userInput)");
        
        let classic_vuln = vulnerability.to_vulnerability();
        assert_eq!(classic_vuln.id, "test-rule");
        assert_eq!(classic_vuln.description, "Test vulnerability in dangerousFunction");
    }
}