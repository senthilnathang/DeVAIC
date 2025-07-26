use crate::{Severity, Vulnerability};
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ComplianceReport {
    pub framework: ComplianceFramework,
    pub overall_score: f64,
    pub compliance_level: ComplianceLevel,
    pub requirements: Vec<ComplianceRequirement>,
    pub summary: ComplianceSummary,
    pub recommendations: Vec<String>,
    pub generated_at: chrono::DateTime<chrono::Utc>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub enum ComplianceFramework {
    OWASP,
    NIST,
    ISO27001,
    PciDss,
    HIPAA,
    SOX,
    GDPR,
    CIS,
    SANS,
    Custom(String),
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum ComplianceLevel {
    FullyCompliant,
    MostlyCompliant,
    PartiallyCompliant,
    NonCompliant,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ComplianceRequirement {
    pub id: String,
    pub title: String,
    pub description: String,
    pub category: String,
    pub status: RequirementStatus,
    pub score: f64,
    pub violations: Vec<ComplianceViolation>,
    pub evidence: Vec<String>,
    pub remediation: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum RequirementStatus {
    Compliant,
    NonCompliant,
    PartiallyCompliant,
    NotApplicable,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ComplianceViolation {
    pub vulnerability_id: String,
    pub file_path: String,
    pub line_number: usize,
    pub severity: Severity,
    pub description: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ComplianceSummary {
    pub total_requirements: usize,
    pub compliant_requirements: usize,
    pub non_compliant_requirements: usize,
    pub partially_compliant_requirements: usize,
    pub not_applicable_requirements: usize,
    pub critical_violations: usize,
    pub high_violations: usize,
    pub medium_violations: usize,
    pub low_violations: usize,
}

pub struct ComplianceEngine;

impl ComplianceEngine {
    pub fn new() -> Self {
        Self
    }
    
    pub fn generate_owasp_report(&self, vulnerabilities: &[Vulnerability]) -> ComplianceReport {
        let requirements = self.get_owasp_top10_requirements();
        let mut compliant_reqs = Vec::new();
        
        for mut requirement in requirements {
            let violations = self.find_owasp_violations(&requirement.id, vulnerabilities);
            requirement.violations = violations.clone();
            requirement.status = if violations.is_empty() {
                RequirementStatus::Compliant
            } else if violations.len() < 3 {
                RequirementStatus::PartiallyCompliant
            } else {
                RequirementStatus::NonCompliant
            };
            requirement.score = self.calculate_requirement_score(&violations);
            compliant_reqs.push(requirement);
        }
        
        let summary = self.calculate_summary(&compliant_reqs);
        let overall_score = self.calculate_overall_score(&summary);
        let compliance_level = self.determine_compliance_level(overall_score);
        let recommendations = self.generate_owasp_recommendations(&compliant_reqs);
        
        ComplianceReport {
            framework: ComplianceFramework::OWASP,
            overall_score,
            compliance_level,
            requirements: compliant_reqs,
            summary,
            recommendations,
            generated_at: chrono::Utc::now(),
        }
    }
    
    pub fn generate_nist_report(&self, vulnerabilities: &[Vulnerability]) -> ComplianceReport {
        let requirements = self.get_nist_cybersecurity_framework();
        let mut compliant_reqs = Vec::new();
        
        for mut requirement in requirements {
            let violations = self.find_nist_violations(&requirement.id, vulnerabilities);
            requirement.violations = violations.clone();
            requirement.status = if violations.is_empty() {
                RequirementStatus::Compliant
            } else {
                RequirementStatus::NonCompliant
            };
            requirement.score = self.calculate_requirement_score(&violations);
            compliant_reqs.push(requirement);
        }
        
        let summary = self.calculate_summary(&compliant_reqs);
        let overall_score = self.calculate_overall_score(&summary);
        let compliance_level = self.determine_compliance_level(overall_score);
        let recommendations = self.generate_nist_recommendations(&compliant_reqs);
        
        ComplianceReport {
            framework: ComplianceFramework::NIST,
            overall_score,
            compliance_level,
            requirements: compliant_reqs,
            summary,
            recommendations,
            generated_at: chrono::Utc::now(),
        }
    }
    
    pub fn generate_pci_dss_report(&self, vulnerabilities: &[Vulnerability]) -> ComplianceReport {
        let requirements = self.get_pci_dss_requirements();
        let mut compliant_reqs = Vec::new();
        
        for mut requirement in requirements {
            let violations = self.find_pci_violations(&requirement.id, vulnerabilities);
            requirement.violations = violations.clone();
            requirement.status = if violations.is_empty() {
                RequirementStatus::Compliant
            } else {
                RequirementStatus::NonCompliant
            };
            requirement.score = self.calculate_requirement_score(&violations);
            compliant_reqs.push(requirement);
        }
        
        let summary = self.calculate_summary(&compliant_reqs);
        let overall_score = self.calculate_overall_score(&summary);
        let compliance_level = self.determine_compliance_level(overall_score);
        let recommendations = self.generate_pci_recommendations(&compliant_reqs);
        
        ComplianceReport {
            framework: ComplianceFramework::PciDss,
            overall_score,
            compliance_level,
            requirements: compliant_reqs,
            summary,
            recommendations,
            generated_at: chrono::Utc::now(),
        }
    }
    
    fn get_owasp_top10_requirements(&self) -> Vec<ComplianceRequirement> {
        vec![
            ComplianceRequirement {
                id: "A01:2021".to_string(),
                title: "Broken Access Control".to_string(),
                description: "Access control enforces policy such that users cannot act outside of their intended permissions".to_string(),
                category: "Access Control".to_string(),
                status: RequirementStatus::Compliant,
                score: 0.0,
                violations: Vec::new(),
                evidence: Vec::new(),
                remediation: "Implement proper access controls and authorization checks".to_string(),
            },
            ComplianceRequirement {
                id: "A02:2021".to_string(),
                title: "Cryptographic Failures".to_string(),
                description: "Protect data in transit and at rest with strong cryptography".to_string(),
                category: "Cryptography".to_string(),
                status: RequirementStatus::Compliant,
                score: 0.0,
                violations: Vec::new(),
                evidence: Vec::new(),
                remediation: "Use strong encryption algorithms and proper key management".to_string(),
            },
            ComplianceRequirement {
                id: "A03:2021".to_string(),
                title: "Injection".to_string(),
                description: "Prevent injection flaws such as SQL, NoSQL, OS, and LDAP injection".to_string(),
                category: "Input Validation".to_string(),
                status: RequirementStatus::Compliant,
                score: 0.0,
                violations: Vec::new(),
                evidence: Vec::new(),
                remediation: "Use parameterized queries and input validation".to_string(),
            },
            ComplianceRequirement {
                id: "A04:2021".to_string(),
                title: "Insecure Design".to_string(),
                description: "Secure design patterns and principles must be used".to_string(),
                category: "Design".to_string(),
                status: RequirementStatus::Compliant,
                score: 0.0,
                violations: Vec::new(),
                evidence: Vec::new(),
                remediation: "Implement secure design patterns and threat modeling".to_string(),
            },
            ComplianceRequirement {
                id: "A05:2021".to_string(),
                title: "Security Misconfiguration".to_string(),
                description: "Secure configuration must be implemented across all components".to_string(),
                category: "Configuration".to_string(),
                status: RequirementStatus::Compliant,
                score: 0.0,
                violations: Vec::new(),
                evidence: Vec::new(),
                remediation: "Review and harden all configurations".to_string(),
            },
            ComplianceRequirement {
                id: "A06:2021".to_string(),
                title: "Vulnerable and Outdated Components".to_string(),
                description: "Components with known vulnerabilities must be updated".to_string(),
                category: "Dependencies".to_string(),
                status: RequirementStatus::Compliant,
                score: 0.0,
                violations: Vec::new(),
                evidence: Vec::new(),
                remediation: "Keep all components updated and monitor for vulnerabilities".to_string(),
            },
            ComplianceRequirement {
                id: "A07:2021".to_string(),
                title: "Identification and Authentication Failures".to_string(),
                description: "Implement strong authentication and session management".to_string(),
                category: "Authentication".to_string(),
                status: RequirementStatus::Compliant,
                score: 0.0,
                violations: Vec::new(),
                evidence: Vec::new(),
                remediation: "Implement multi-factor authentication and secure session management".to_string(),
            },
            ComplianceRequirement {
                id: "A08:2021".to_string(),
                title: "Software and Data Integrity Failures".to_string(),
                description: "Ensure software updates and critical data are integrity protected".to_string(),
                category: "Integrity".to_string(),
                status: RequirementStatus::Compliant,
                score: 0.0,
                violations: Vec::new(),
                evidence: Vec::new(),
                remediation: "Implement integrity checks and secure update mechanisms".to_string(),
            },
            ComplianceRequirement {
                id: "A09:2021".to_string(),
                title: "Security Logging and Monitoring Failures".to_string(),
                description: "Implement comprehensive logging and monitoring".to_string(),
                category: "Monitoring".to_string(),
                status: RequirementStatus::Compliant,
                score: 0.0,
                violations: Vec::new(),
                evidence: Vec::new(),
                remediation: "Implement comprehensive security logging and monitoring".to_string(),
            },
            ComplianceRequirement {
                id: "A10:2021".to_string(),
                title: "Server-Side Request Forgery (SSRF)".to_string(),
                description: "Prevent SSRF attacks by validating and sanitizing user input".to_string(),
                category: "Input Validation".to_string(),
                status: RequirementStatus::Compliant,
                score: 0.0,
                violations: Vec::new(),
                evidence: Vec::new(),
                remediation: "Validate all user-supplied URLs and implement network segmentation".to_string(),
            },
        ]
    }
    
    fn get_nist_cybersecurity_framework(&self) -> Vec<ComplianceRequirement> {
        vec![
            ComplianceRequirement {
                id: "ID.AM".to_string(),
                title: "Asset Management".to_string(),
                description: "Identify and manage assets within the organization".to_string(),
                category: "Identify".to_string(),
                status: RequirementStatus::Compliant,
                score: 0.0,
                violations: Vec::new(),
                evidence: Vec::new(),
                remediation: "Maintain an inventory of all software assets".to_string(),
            },
            ComplianceRequirement {
                id: "PR.AC".to_string(),
                title: "Identity Management and Access Control".to_string(),
                description: "Manage access to assets and associated facilities".to_string(),
                category: "Protect".to_string(),
                status: RequirementStatus::Compliant,
                score: 0.0,
                violations: Vec::new(),
                evidence: Vec::new(),
                remediation: "Implement proper access controls and authentication".to_string(),
            },
            ComplianceRequirement {
                id: "PR.DS".to_string(),
                title: "Data Security".to_string(),
                description: "Protect data-in-transit and data-at-rest".to_string(),
                category: "Protect".to_string(),
                status: RequirementStatus::Compliant,
                score: 0.0,
                violations: Vec::new(),
                evidence: Vec::new(),
                remediation: "Implement strong encryption for data protection".to_string(),
            },
            ComplianceRequirement {
                id: "DE.CM".to_string(),
                title: "Security Continuous Monitoring".to_string(),
                description: "Monitor information systems and assets".to_string(),
                category: "Detect".to_string(),
                status: RequirementStatus::Compliant,
                score: 0.0,
                violations: Vec::new(),
                evidence: Vec::new(),
                remediation: "Implement continuous security monitoring".to_string(),
            },
            ComplianceRequirement {
                id: "RS.RP".to_string(),
                title: "Response Planning".to_string(),
                description: "Develop and implement appropriate response plans".to_string(),
                category: "Respond".to_string(),
                status: RequirementStatus::Compliant,
                score: 0.0,
                violations: Vec::new(),
                evidence: Vec::new(),
                remediation: "Develop incident response procedures".to_string(),
            },
        ]
    }
    
    fn get_pci_dss_requirements(&self) -> Vec<ComplianceRequirement> {
        vec![
            ComplianceRequirement {
                id: "PCI-6.5.1".to_string(),
                title: "Injection Flaws".to_string(),
                description: "Prevent injection flaws, particularly SQL injection".to_string(),
                category: "Secure Development".to_string(),
                status: RequirementStatus::Compliant,
                score: 0.0,
                violations: Vec::new(),
                evidence: Vec::new(),
                remediation: "Use parameterized queries and input validation".to_string(),
            },
            ComplianceRequirement {
                id: "PCI-6.5.3".to_string(),
                title: "Insecure Cryptographic Storage".to_string(),
                description: "Protect stored cardholder data with strong cryptography".to_string(),
                category: "Data Protection".to_string(),
                status: RequirementStatus::Compliant,
                score: 0.0,
                violations: Vec::new(),
                evidence: Vec::new(),
                remediation: "Use strong encryption for sensitive data storage".to_string(),
            },
            ComplianceRequirement {
                id: "PCI-6.5.4".to_string(),
                title: "Insecure Communications".to_string(),
                description: "Protect sensitive data during transmission".to_string(),
                category: "Data Protection".to_string(),
                status: RequirementStatus::Compliant,
                score: 0.0,
                violations: Vec::new(),
                evidence: Vec::new(),
                remediation: "Use TLS/SSL for all sensitive communications".to_string(),
            },
            ComplianceRequirement {
                id: "PCI-6.5.8".to_string(),
                title: "Improper Access Control".to_string(),
                description: "Implement proper access controls for cardholder data".to_string(),
                category: "Access Control".to_string(),
                status: RequirementStatus::Compliant,
                score: 0.0,
                violations: Vec::new(),
                evidence: Vec::new(),
                remediation: "Implement role-based access controls".to_string(),
            },
        ]
    }
    
    fn find_owasp_violations(&self, requirement_id: &str, vulnerabilities: &[Vulnerability]) -> Vec<ComplianceViolation> {
        let mut violations = Vec::new();
        
        for vuln in vulnerabilities {
            let matches = match requirement_id {
                "A01:2021" => vuln.category == "access_control" || vuln.title.contains("Access"),
                "A02:2021" => vuln.category == "cryptography" || vuln.title.contains("Crypto"),
                "A03:2021" => vuln.category == "injection" || vuln.title.contains("Injection"),
                "A04:2021" => vuln.category == "design" || vuln.title.contains("Design"),
                "A05:2021" => vuln.category == "configuration" || vuln.title.contains("Configuration"),
                "A06:2021" => vuln.category == "dependencies" || vuln.title.contains("Component"),
                "A07:2021" => vuln.category == "authentication" || vuln.title.contains("Authentication"),
                "A08:2021" => vuln.category == "integrity" || vuln.title.contains("Integrity"),
                "A09:2021" => vuln.category == "logging" || vuln.title.contains("Logging"),
                "A10:2021" => vuln.category == "ssrf" || vuln.title.contains("SSRF"),
                _ => false,
            };
            
            if matches {
                violations.push(ComplianceViolation {
                    vulnerability_id: vuln.id.clone(),
                    file_path: vuln.file_path.clone(),
                    line_number: vuln.line_number,
                    severity: vuln.severity.clone(),
                    description: vuln.description.clone(),
                });
            }
        }
        
        violations
    }
    
    fn find_nist_violations(&self, requirement_id: &str, vulnerabilities: &[Vulnerability]) -> Vec<ComplianceViolation> {
        let mut violations = Vec::new();
        
        for vuln in vulnerabilities {
            let matches = match requirement_id {
                "ID.AM" => vuln.category == "dependencies" || vuln.title.contains("Component"),
                "PR.AC" => vuln.category == "access_control" || vuln.category == "authentication",
                "PR.DS" => vuln.category == "cryptography" || vuln.title.contains("Crypto"),
                "DE.CM" => vuln.category == "logging" || vuln.title.contains("Monitoring"),
                "RS.RP" => false, // Response planning is not directly detectable in code
                _ => false,
            };
            
            if matches {
                violations.push(ComplianceViolation {
                    vulnerability_id: vuln.id.clone(),
                    file_path: vuln.file_path.clone(),
                    line_number: vuln.line_number,
                    severity: vuln.severity.clone(),
                    description: vuln.description.clone(),
                });
            }
        }
        
        violations
    }
    
    fn find_pci_violations(&self, requirement_id: &str, vulnerabilities: &[Vulnerability]) -> Vec<ComplianceViolation> {
        let mut violations = Vec::new();
        
        for vuln in vulnerabilities {
            let matches = match requirement_id {
                "PCI-6.5.1" => vuln.category == "injection",
                "PCI-6.5.3" => vuln.category == "cryptography" && vuln.description.contains("storage"),
                "PCI-6.5.4" => vuln.category == "network" || vuln.title.contains("TLS"),
                "PCI-6.5.8" => vuln.category == "access_control",
                _ => false,
            };
            
            if matches {
                violations.push(ComplianceViolation {
                    vulnerability_id: vuln.id.clone(),
                    file_path: vuln.file_path.clone(),
                    line_number: vuln.line_number,
                    severity: vuln.severity.clone(),
                    description: vuln.description.clone(),
                });
            }
        }
        
        violations
    }
    
    fn calculate_requirement_score(&self, violations: &[ComplianceViolation]) -> f64 {
        if violations.is_empty() {
            return 100.0;
        }
        
        let penalty: f64 = violations.iter().map(|v| match v.severity {
            Severity::Critical => 25.0,
            Severity::High => 15.0,
            Severity::Medium => 8.0,
            Severity::Low => 3.0,
            Severity::Info => 1.0,
        }).sum();
        
        (100.0 - penalty).max(0.0)
    }
    
    fn calculate_summary(&self, requirements: &[ComplianceRequirement]) -> ComplianceSummary {
        let total_requirements = requirements.len();
        let mut compliant_requirements = 0;
        let mut non_compliant_requirements = 0;
        let mut partially_compliant_requirements = 0;
        let mut not_applicable_requirements = 0;
        
        let mut critical_violations = 0;
        let mut high_violations = 0;
        let mut medium_violations = 0;
        let mut low_violations = 0;
        
        for req in requirements {
            match req.status {
                RequirementStatus::Compliant => compliant_requirements += 1,
                RequirementStatus::NonCompliant => non_compliant_requirements += 1,
                RequirementStatus::PartiallyCompliant => partially_compliant_requirements += 1,
                RequirementStatus::NotApplicable => not_applicable_requirements += 1,
            }
            
            for violation in &req.violations {
                match violation.severity {
                    Severity::Critical => critical_violations += 1,
                    Severity::High => high_violations += 1,
                    Severity::Medium => medium_violations += 1,
                    Severity::Low => low_violations += 1,
                    Severity::Info => {},
                }
            }
        }
        
        ComplianceSummary {
            total_requirements,
            compliant_requirements,
            non_compliant_requirements,
            partially_compliant_requirements,
            not_applicable_requirements,
            critical_violations,
            high_violations,
            medium_violations,
            low_violations,
        }
    }
    
    fn calculate_overall_score(&self, summary: &ComplianceSummary) -> f64 {
        if summary.total_requirements == 0 {
            return 100.0;
        }
        
        let compliance_rate = summary.compliant_requirements as f64 / summary.total_requirements as f64;
        let partial_compliance_rate = summary.partially_compliant_requirements as f64 / summary.total_requirements as f64;
        
        (compliance_rate * 100.0) + (partial_compliance_rate * 50.0)
    }
    
    fn determine_compliance_level(&self, score: f64) -> ComplianceLevel {
        match score {
            s if s >= 95.0 => ComplianceLevel::FullyCompliant,
            s if s >= 80.0 => ComplianceLevel::MostlyCompliant,
            s if s >= 60.0 => ComplianceLevel::PartiallyCompliant,
            _ => ComplianceLevel::NonCompliant,
        }
    }
    
    fn generate_owasp_recommendations(&self, requirements: &[ComplianceRequirement]) -> Vec<String> {
        let mut recommendations = Vec::new();
        
        for req in requirements {
            if matches!(req.status, RequirementStatus::NonCompliant | RequirementStatus::PartiallyCompliant) {
                recommendations.push(format!("{}: {}", req.title, req.remediation));
            }
        }
        
        if recommendations.is_empty() {
            recommendations.push("All OWASP Top 10 requirements are compliant. Maintain current security practices.".to_string());
        }
        
        recommendations
    }
    
    fn generate_nist_recommendations(&self, requirements: &[ComplianceRequirement]) -> Vec<String> {
        let mut recommendations = Vec::new();
        
        for req in requirements {
            if matches!(req.status, RequirementStatus::NonCompliant | RequirementStatus::PartiallyCompliant) {
                recommendations.push(format!("{}: {}", req.title, req.remediation));
            }
        }
        
        if recommendations.is_empty() {
            recommendations.push("All NIST Cybersecurity Framework requirements are compliant.".to_string());
        }
        
        recommendations
    }
    
    fn generate_pci_recommendations(&self, requirements: &[ComplianceRequirement]) -> Vec<String> {
        let mut recommendations = Vec::new();
        
        for req in requirements {
            if matches!(req.status, RequirementStatus::NonCompliant | RequirementStatus::PartiallyCompliant) {
                recommendations.push(format!("{}: {}", req.title, req.remediation));
            }
        }
        
        if recommendations.is_empty() {
            recommendations.push("All PCI DSS requirements are compliant for secure development.".to_string());
        }
        
        recommendations
    }
}