pub mod c_rules;
pub mod cpp_rules;
pub mod python_rules;
pub mod java_rules;
pub mod javascript_rules;
pub mod typescript_rules;
pub mod scada_rules;

use crate::{
    config::RulesConfig,
    error::Result,
    parsers::{ParsedAst, SourceFile},
    Language, Severity, Vulnerability,
};

pub struct RuleEngine {
    config: RulesConfig,
    c_rules: c_rules::CRules,
    cpp_rules: cpp_rules::CppRules,
    python_rules: python_rules::PythonRules,
    java_rules: java_rules::JavaRules,
    javascript_rules: javascript_rules::JavascriptRules,
    typescript_rules: typescript_rules::TypeScriptRules,
    scada_rules: scada_rules::ScadaRules,
}

impl RuleEngine {
    pub fn new(config: &RulesConfig) -> Self {
        Self {
            config: config.clone(),
            c_rules: c_rules::CRules::new(),
            cpp_rules: cpp_rules::CppRules::new(),
            python_rules: python_rules::PythonRules::new(),
            java_rules: java_rules::JavaRules::new(),
            javascript_rules: javascript_rules::JavascriptRules::new(),
            typescript_rules: typescript_rules::TypeScriptRules::new(),
            scada_rules: scada_rules::ScadaRules::new(),
        }
    }

    pub fn analyze(&self, source_file: &SourceFile, ast: &ParsedAst) -> Result<Vec<Vulnerability>> {
        let mut vulnerabilities = Vec::new();

        match source_file.language {
            Language::C => {
                vulnerabilities.extend(self.c_rules.analyze(source_file, ast)?);
            }
            Language::Cpp => {
                vulnerabilities.extend(self.cpp_rules.analyze(source_file, ast)?);
            }
            Language::Python => {
                vulnerabilities.extend(self.python_rules.analyze(source_file, ast)?);
            }
            Language::Java => {
                vulnerabilities.extend(self.java_rules.analyze(source_file, ast)?);
            }
            Language::Javascript => {
                vulnerabilities.extend(self.javascript_rules.analyze(source_file, ast)?);
            }
            Language::TypeScript => {
                vulnerabilities.extend(self.typescript_rules.analyze(source_file, ast)?);
            }
            Language::Scada => {
                vulnerabilities.extend(self.scada_rules.analyze(source_file, ast)?);
            }
        }

        // Filter by severity threshold
        let threshold_severity = self.parse_severity(&self.config.severity_threshold);
        vulnerabilities.retain(|v| self.severity_meets_threshold(&v.severity, &threshold_severity));

        // Filter by enabled categories
        vulnerabilities.retain(|v| self.config.enabled_categories.contains(&v.category));

        Ok(vulnerabilities)
    }

    fn parse_severity(&self, severity_str: &str) -> Severity {
        match severity_str.to_uppercase().as_str() {
            "CRITICAL" => Severity::Critical,
            "HIGH" => Severity::High,
            "MEDIUM" => Severity::Medium,
            "LOW" => Severity::Low,
            "INFO" => Severity::Info,
            _ => Severity::Low,
        }
    }

    fn severity_meets_threshold(&self, severity: &Severity, threshold: &Severity) -> bool {
        let severity_value = match severity {
            Severity::Critical => 5,
            Severity::High => 4,
            Severity::Medium => 3,
            Severity::Low => 2,
            Severity::Info => 1,
        };

        let threshold_value = match threshold {
            Severity::Critical => 5,
            Severity::High => 4,
            Severity::Medium => 3,
            Severity::Low => 2,
            Severity::Info => 1,
        };

        severity_value >= threshold_value
    }
}

pub trait RuleSet {
    fn analyze(&self, source_file: &SourceFile, ast: &ParsedAst) -> Result<Vec<Vulnerability>>;
}

pub fn create_vulnerability(
    id: &str,
    severity: Severity,
    category: &str,
    description: &str,
    file_path: &str,
    line_number: usize,
    column: usize,
    source_code: &str,
    recommendation: &str,
) -> Vulnerability {
    Vulnerability {
        id: id.to_string(),
        severity,
        category: category.to_string(),
        description: description.to_string(),
        file_path: file_path.to_string(),
        line_number,
        column,
        source_code: source_code.to_string(),
        recommendation: recommendation.to_string(),
    }
}