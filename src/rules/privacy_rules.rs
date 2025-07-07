use crate::{
    error::Result,
    parsers::{ParsedAst, SourceFile},
    rules::{create_vulnerability, RuleSet},
    Severity, Vulnerability,
};
use regex::Regex;

pub struct PrivacyRules {
    pii_patterns: Vec<PrivacyPattern>,
    phi_patterns: Vec<PrivacyPattern>,
    data_flow_patterns: Vec<PrivacyPattern>,
}

#[derive(Clone)]
struct PrivacyPattern {
    id: String,
    name: String,
    pattern: Regex,
    category: String,
    severity: Severity,
    description: String,
    recommendation: String,
}


impl PrivacyRules {
    pub fn new() -> Self {
        let mut pii_patterns = Vec::new();
        let mut phi_patterns = Vec::new();
        let mut data_flow_patterns = Vec::new();

        // PII Patterns
        pii_patterns.extend(vec![
            PrivacyPattern {
                id: "social-security-number".to_string(),
                name: "Social Security Number".to_string(),
                pattern: Regex::new(r#"(?i)ssn\s*=\s*"(\d{3}-\d{2}-\d{4})""#).unwrap(),
                category: "privacy".to_string(),
                severity: Severity::Critical,
                description: "Social Security Number detected in source code".to_string(),
                recommendation: "Remove hardcoded SSN. Use tokenization or encryption for sensitive data storage.".to_string(),
            },
            PrivacyPattern {
                id: "credit-card-number".to_string(),
                name: "Credit Card Number".to_string(),
                pattern: Regex::new(r#"(?i)credit_card\s*=\s*"(\d{4}-\d{4}-\d{4}-\d{4})""#).unwrap(),
                category: "privacy".to_string(),
                severity: Severity::Critical,
                description: "Credit card number detected in source code".to_string(),
                recommendation: "Remove hardcoded credit card data. Use PCI-compliant tokenization services.".to_string(),
            },
            PrivacyPattern {
                id: "email-address".to_string(),
                name: "Email Address".to_string(),
                pattern: Regex::new(r#"(?i)email\s*=\s*"([a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,})""#).unwrap(),
                category: "privacy".to_string(),
                severity: Severity::Medium,
                description: "Email address detected in source code".to_string(),
                recommendation: "Avoid hardcoding email addresses. Use configuration or environment variables.".to_string(),
            },
            PrivacyPattern {
                id: "phone-number".to_string(),
                name: "Phone Number".to_string(),
                pattern: Regex::new(r#"(?i)phone\s*=\s*"(\d{3}-\d{3}-\d{4})""#).unwrap(),
                category: "privacy".to_string(),
                severity: Severity::Medium,
                description: "Phone number detected in source code".to_string(),
                recommendation: "Avoid hardcoding phone numbers. Use configuration or masked data for testing.".to_string(),
            },
            PrivacyPattern {
                id: "passport-number".to_string(),
                name: "Passport Number".to_string(),
                pattern: Regex::new(r#"(?i)passport\s*=\s*"([A-Z]{1,2}[0-9]{6,9})""#).unwrap(),
                category: "privacy".to_string(),
                severity: Severity::Critical,
                description: "Passport number detected in source code".to_string(),
                recommendation: "Remove hardcoded passport data. Use anonymized test data.".to_string(),
            },
        ]);

        // PHI Patterns
        phi_patterns.extend(vec![
            PrivacyPattern {
                id: "medical-record-number".to_string(),
                name: "Medical Record Number".to_string(),
                pattern: Regex::new(r#"(?i)mrn\s*=\s*"([0-9]{6,12})""#).unwrap(),
                category: "privacy".to_string(),
                severity: Severity::Critical,
                description: "Medical record number detected in source code".to_string(),
                recommendation: "Remove hardcoded medical data. Ensure HIPAA compliance for PHI handling.".to_string(),
            },
            PrivacyPattern {
                id: "health-insurance-number".to_string(),
                name: "Health Insurance Number".to_string(),
                pattern: Regex::new(r#"(?i)insurance_number\s*=\s*"([A-Z0-9]{8,15})""#).unwrap(),
                category: "privacy".to_string(),
                severity: Severity::Critical,
                description: "Health insurance number detected in source code".to_string(),
                recommendation: "Remove hardcoded insurance data. Use synthetic data for testing.".to_string(),
            },
        ]);

        // Data Flow Patterns
        data_flow_patterns.extend(vec![
            PrivacyPattern {
                id: "database-select-pii".to_string(),
                name: "Database PII Query".to_string(),
                pattern: Regex::new(r"(?i)select.*ssn.*from").unwrap(),
                category: "privacy".to_string(),
                severity: Severity::High,
                description: "Database query selecting PII data detected".to_string(),
                recommendation: "Ensure proper access controls and auditing for PII data queries.".to_string(),
            },
            PrivacyPattern {
                id: "logging-sensitive-data".to_string(),
                name: "Logging Sensitive Data".to_string(),
                pattern: Regex::new(r"(?i)print.*ssn").unwrap(),
                category: "privacy".to_string(),
                severity: Severity::High,
                description: "Sensitive data being logged detected".to_string(),
                recommendation: "Avoid logging sensitive data. Use data masking or redaction.".to_string(),
            },
            PrivacyPattern {
                id: "api-response-pii".to_string(),
                name: "API Response with PII".to_string(),
                pattern: Regex::new(r"(?i)return.*ssn").unwrap(),
                category: "privacy".to_string(),
                severity: Severity::High,
                description: "API response containing PII data detected".to_string(),
                recommendation: "Filter sensitive data from API responses. Use data transformation layers.".to_string(),
            },
        ]);

        Self {
            pii_patterns,
            phi_patterns,
            data_flow_patterns,
        }
    }

    fn check_patterns(&self, source_file: &SourceFile, patterns: &[PrivacyPattern]) -> Result<Vec<Vulnerability>> {
        let mut vulnerabilities = Vec::new();
        let lines: Vec<&str> = source_file.content.lines().collect();

        for (line_index, line) in lines.iter().enumerate() {
            for pattern in patterns {
                if let Some(captures) = pattern.pattern.captures(line) {
                    if let Some(matched) = captures.get(0) {
                        let vulnerability = create_vulnerability(
                            &pattern.id,
                            Some("CWE-200"), // Information Exposure
                            &pattern.name,
                            pattern.severity.clone(),
                            &pattern.category,
                            &pattern.description,
                            &source_file.path.to_string_lossy(),
                            line_index + 1,
                            matched.start(),
                            line.trim(),
                            &pattern.recommendation,
                        );
                        vulnerabilities.push(vulnerability);
                    }
                }
            }
        }

        Ok(vulnerabilities)
    }
}

impl RuleSet for PrivacyRules {
    fn analyze(&self, source_file: &SourceFile, _ast: &ParsedAst) -> Result<Vec<Vulnerability>> {
        let mut vulnerabilities = Vec::new();

        // Check PII patterns
        vulnerabilities.extend(self.check_patterns(source_file, &self.pii_patterns)?);

        // Check PHI patterns
        vulnerabilities.extend(self.check_patterns(source_file, &self.phi_patterns)?);

        // Check data flow patterns
        vulnerabilities.extend(self.check_patterns(source_file, &self.data_flow_patterns)?);

        Ok(vulnerabilities)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{Language, parsers::SourceFile};
    use std::path::PathBuf;

    #[test]
    fn test_ssn_detection() {
        let rules = PrivacyRules::new();
        let source = SourceFile::new(
            PathBuf::from("test.py"),
            r#"ssn = "123-45-6789""#.to_string(),
            Language::Python,
        );
        let ast = crate::parsers::ParsedAst::new_source_only(source.content.clone());
        let vulnerabilities = rules.analyze(&source, &ast).unwrap();
        assert!(!vulnerabilities.is_empty());
        assert_eq!(vulnerabilities[0].id, "social-security-number");
    }

    #[test]
    fn test_credit_card_detection() {
        let rules = PrivacyRules::new();
        let source = SourceFile::new(
            PathBuf::from("test.js"),
            r#"credit_card = "4532-1234-5678-9012""#.to_string(),
            Language::Javascript,
        );
        let ast = crate::parsers::ParsedAst::new_source_only(source.content.clone());
        let vulnerabilities = rules.analyze(&source, &ast).unwrap();
        assert!(!vulnerabilities.is_empty());
        assert_eq!(vulnerabilities[0].id, "credit-card-number");
    }

    #[test]
    fn test_email_detection() {
        let rules = PrivacyRules::new();
        let source = SourceFile::new(
            PathBuf::from("test.py"),
            r#"email = "user@example.com""#.to_string(),
            Language::Python,
        );
        let ast = crate::parsers::ParsedAst::new_source_only(source.content.clone());
        let vulnerabilities = rules.analyze(&source, &ast).unwrap();
        assert!(!vulnerabilities.is_empty());
        assert_eq!(vulnerabilities[0].id, "email-address");
    }
}