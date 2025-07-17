pub mod c_rules;
pub mod cpp_rules;
pub mod python_rules;
pub mod java_rules;
pub mod javascript_rules;
pub mod typescript_rules;
pub mod go_rules;
pub mod php_rules;
pub mod ruby_rules;
pub mod kotlin_rules;
pub mod csharp_rules;
pub mod bash_rules;
pub mod scada_rules;
pub mod cobol_rules;
pub mod pascal_rules;
pub mod owasp_llm_rules;
pub mod owasp_web_rules;
pub mod privacy_rules;
pub mod security_risk_rules;
pub mod vulnerability_scanner_rules;
pub mod sanitizer_rules;
pub mod dependency_scanner_rules;
pub mod custom_pattern_rules;

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
    go_rules: go_rules::GoRules,
    php_rules: php_rules::PhpRules,
    ruby_rules: ruby_rules::RubyRules,
    kotlin_rules: kotlin_rules::KotlinRules,
    csharp_rules: csharp_rules::CSharpRules,
    bash_rules: bash_rules::BashRules,
    scada_rules: scada_rules::ScadaRules,
    cobol_rules: cobol_rules::CobolRules,
    pascal_rules: pascal_rules::PascalRules,
    owasp_llm_rules: owasp_llm_rules::OwaspLlmRules,
    owasp_web_rules: owasp_web_rules::OwaspWebRules,
    privacy_rules: privacy_rules::PrivacyRules,
    security_risk_rules: security_risk_rules::SecurityRiskRules,
    vulnerability_scanner_rules: vulnerability_scanner_rules::VulnerabilityScannerRules,
    sanitizer_rules: sanitizer_rules::SanitizerRules,
    dependency_scanner_rules: dependency_scanner_rules::DependencyScannerRules,
    custom_pattern_rules: Option<custom_pattern_rules::CustomPatternRules>,
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
            go_rules: go_rules::GoRules::new(),
            php_rules: php_rules::PhpRules::new(),
            ruby_rules: ruby_rules::RubyRules::new(),
            kotlin_rules: kotlin_rules::KotlinRules::new(),
            csharp_rules: csharp_rules::CSharpRules::new(),
            bash_rules: bash_rules::BashRules::new(),
            scada_rules: scada_rules::ScadaRules::new(),
            cobol_rules: cobol_rules::CobolRules::new(),
            pascal_rules: pascal_rules::PascalRules::new(),
            owasp_llm_rules: owasp_llm_rules::OwaspLlmRules::new(),
            owasp_web_rules: owasp_web_rules::OwaspWebRules::new(),
            privacy_rules: privacy_rules::PrivacyRules::new(),
            security_risk_rules: security_risk_rules::SecurityRiskRules::new(),
            vulnerability_scanner_rules: vulnerability_scanner_rules::VulnerabilityScannerRules::new(),
            sanitizer_rules: sanitizer_rules::SanitizerRules::new(),
            dependency_scanner_rules: dependency_scanner_rules::DependencyScannerRules::new(),
            custom_pattern_rules: None,
        }
    }

    pub fn set_custom_pattern_rules(&mut self, custom_rules: custom_pattern_rules::CustomPatternRules) {
        self.custom_pattern_rules = Some(custom_rules);
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
            Language::Go => {
                vulnerabilities.extend(self.go_rules.analyze(source_file, ast)?);
            }
            Language::Php => {
                vulnerabilities.extend(self.php_rules.analyze(source_file, ast)?);
            }
            Language::Ruby => {
                vulnerabilities.extend(self.ruby_rules.analyze(source_file, ast)?);
            }
            Language::Kotlin => {
                vulnerabilities.extend(self.kotlin_rules.analyze(source_file, ast)?);
            }
            Language::CSharp => {
                vulnerabilities.extend(self.csharp_rules.analyze(source_file, ast)?);
            }
            Language::Bash => {
                vulnerabilities.extend(self.bash_rules.analyze(source_file, ast)?);
            }
            Language::Scada => {
                vulnerabilities.extend(self.scada_rules.analyze(source_file, ast)?);
            }
            Language::Cobol => {
                vulnerabilities.extend(self.cobol_rules.analyze(source_file, ast)?);
            }
            Language::Pascal => {
                vulnerabilities.extend(self.pascal_rules.analyze(source_file, ast)?);
            }
        }

        // Run OWASP rules on all files regardless of language
        vulnerabilities.extend(self.owasp_llm_rules.analyze(source_file, ast)?);
        vulnerabilities.extend(self.owasp_web_rules.analyze(source_file, ast)?);

        // Run Bearer-inspired security, privacy, and vulnerability rules on all files
        vulnerabilities.extend(self.privacy_rules.analyze(source_file, ast)?);
        vulnerabilities.extend(self.security_risk_rules.analyze(source_file, ast)?);
        vulnerabilities.extend(self.vulnerability_scanner_rules.analyze(source_file, ast)?);

        // Run Google Sanitizers-inspired memory safety and concurrency rules
        vulnerabilities.extend(self.sanitizer_rules.analyze(source_file, ast)?);

        // Run dependency scanning rules inspired by sast-scan
        vulnerabilities.extend(self.dependency_scanner_rules.analyze(source_file, ast)?);

        // Run custom pattern rules if available
        if let Some(custom_rules) = &self.custom_pattern_rules {
            vulnerabilities.extend(custom_rules.analyze(source_file, ast)?);
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
    cwe: Option<&str>,
    vulnerability_type: &str,
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
        cwe: cwe.map(|s| s.to_string()),
        vulnerability_type: vulnerability_type.to_string(),
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