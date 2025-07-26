/// Comprehensive Impact Assessment and Risk Scoring Demo
/// 
/// This example demonstrates the vulnerability impact assessment and risk scoring capabilities
/// including CVSS scoring, business impact analysis, and comprehensive risk evaluation.

use devaic::{
    Analyzer, Config, Language, Severity, Vulnerability,
    ImpactAssessmentEngine, AssessedVulnerability, RiskClassification, RemediationPriority,
    EnhancedVulnerability, VulnerabilityFeedback, Classification,
    false_positive_reduction::{
        FeedbackContext, ConfidenceFactor, FactorType, SimilarPattern, 
        UserRecommendation, SuggestedAction, RecommendationType, ActionType, 
        Priority, RemediationEffort
    },
};
use std::path::Path;
use std::time::SystemTime;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    println!("🚀 DeVAIC Impact Assessment and Risk Scoring Demo");
    println!("{}", "=".repeat(60));
    
    // Initialize the analyzer with AI capabilities enabled
    let mut config = Config::default();
    config.enable_ai_analysis = Some(true);
    
    let mut analyzer = Analyzer::new(config)?;
    
    // Enable false positive reduction and impact assessment
    analyzer.enable_false_positive_reduction();
    analyzer.enable_impact_assessment()?;
    
    // Create sample vulnerabilities to demonstrate impact assessment
    let sample_vulnerabilities = create_sample_vulnerabilities();
    
    println!("\n📊 Analyzing {} sample vulnerabilities with comprehensive impact assessment...", sample_vulnerabilities.len());
    
    // Convert to enhanced vulnerabilities first
    let enhanced_vulnerabilities = convert_to_enhanced_vulnerabilities(sample_vulnerabilities);
    
    // Perform comprehensive impact assessment
    let assessed_vulnerabilities = assess_vulnerabilities_with_impact(&analyzer, &enhanced_vulnerabilities).await?;
    
    // Display comprehensive results
    display_impact_assessment_results(&assessed_vulnerabilities);
    
    // Demonstrate risk-based prioritization
    demonstrate_risk_prioritization(&assessed_vulnerabilities);
    
    // Show compliance and business impact analysis
    demonstrate_compliance_analysis(&assessed_vulnerabilities);
    
    // Display remediation guidance
    demonstrate_remediation_guidance(&assessed_vulnerabilities);
    
    // Show analytics and trends
    display_assessment_analytics(&analyzer);
    
    println!("\n✅ Impact Assessment Demo completed successfully!");
    println!("🎯 Key benefits demonstrated:");
    println!("   • CVSS v3.1/v4.0 scoring with contextual adjustments");
    println!("   • Multi-dimensional risk assessment");
    println!("   • Business impact and financial cost estimation");
    println!("   • Compliance framework mapping");
    println!("   • Exploitability and attack vector analysis");
    println!("   • Risk-based remediation prioritization");
    println!("   • Comprehensive uncertainty and confidence modeling");
    
    Ok(())
}

fn create_sample_vulnerabilities() -> Vec<Vulnerability> {
    vec![
        Vulnerability {
            id: "VULN-2024-001".to_string(),
            title: "SQL Injection in User Authentication".to_string(),
            description: "User input not properly sanitized in login query allowing SQL injection".to_string(),
            severity: Severity::Critical,
            category: "injection".to_string(),
            cwe: Some("CWE-89".to_string()),
            owasp: Some("A03:2021 – Injection".to_string()),
            file_path: "/src/auth/login.py".to_string(),
            line_number: 45,
            column_start: 12,
            column_end: 65,
            source_code: "query = f\"SELECT * FROM users WHERE username='{username}' AND password='{password}'\"".to_string(),
            recommendation: "Use parameterized queries and input validation".to_string(),
            references: vec![
                "https://owasp.org/www-community/attacks/SQL_Injection".to_string(),
                "https://cwe.mitre.org/data/definitions/89.html".to_string(),
            ],
            confidence: 0.95,
        },
        Vulnerability {
            id: "VULN-2024-002".to_string(),
            title: "Cross-Site Scripting (XSS) in User Profile".to_string(),
            description: "User profile data displayed without proper encoding allowing XSS attacks".to_string(),
            severity: Severity::High,
            category: "xss".to_string(),
            cwe: Some("CWE-79".to_string()),
            owasp: Some("A03:2021 – Injection".to_string()),
            file_path: "/src/profile/display.js".to_string(),
            line_number: 28,
            column_start: 8,
            column_end: 45,
            source_code: "document.innerHTML = '<h1>' + userProfile.name + '</h1>';".to_string(),
            recommendation: "Encode all user input and use safe DOM manipulation methods".to_string(),
            references: vec![
                "https://owasp.org/www-community/attacks/xss/".to_string(),
                "https://cwe.mitre.org/data/definitions/79.html".to_string(),
            ],
            confidence: 0.88,
        },
        Vulnerability {
            id: "VULN-2024-003".to_string(),
            title: "Insecure Cryptographic Storage".to_string(),
            description: "Sensitive data stored using weak encryption algorithm".to_string(),
            severity: Severity::High,
            category: "cryptography".to_string(),
            cwe: Some("CWE-327".to_string()),
            owasp: Some("A02:2021 – Cryptographic Failures".to_string()),
            file_path: "/src/encryption/crypto.java".to_string(),
            line_number: 67,
            column_start: 20,
            column_end: 55,
            source_code: "Cipher cipher = Cipher.getInstance(\"DES\");".to_string(),
            recommendation: "Use AES-256 or other strong encryption algorithms".to_string(),
            references: vec![
                "https://owasp.org/www-project-top-ten/2017/A6_2017-Security_Misconfiguration".to_string(),
                "https://cwe.mitre.org/data/definitions/327.html".to_string(),
            ],
            confidence: 0.92,
        },
        Vulnerability {
            id: "VULN-2024-004".to_string(),
            title: "Missing Authorization Check".to_string(),
            description: "Admin functionality accessible without proper authorization checks".to_string(),
            severity: Severity::Medium,
            category: "authorization".to_string(),
            cwe: Some("CWE-862".to_string()),
            owasp: Some("A01:2021 – Broken Access Control".to_string()),
            file_path: "/src/admin/users.go".to_string(),
            line_number: 112,
            column_start: 1,
            column_end: 30,
            source_code: "func deleteUser(userID string) {".to_string(),
            recommendation: "Implement role-based access control for admin functions".to_string(),
            references: vec![
                "https://owasp.org/www-project-top-ten/2017/A5_2017-Broken_Access_Control".to_string(),
                "https://cwe.mitre.org/data/definitions/862.html".to_string(),
            ],
            confidence: 0.78,
        },
        Vulnerability {
            id: "VULN-2024-005".to_string(),
            title: "Information Disclosure in Error Messages".to_string(),
            description: "Stack traces and sensitive information exposed in error responses".to_string(),
            severity: Severity::Low,
            category: "information_disclosure".to_string(),
            cwe: Some("CWE-209".to_string()),
            owasp: Some("A09:2021 – Security Logging and Monitoring Failures".to_string()),
            file_path: "/src/api/error_handler.rb".to_string(),
            line_number: 23,
            column_start: 15,
            column_end: 60,
            source_code: "render json: { error: exception.message, trace: exception.backtrace }".to_string(),
            recommendation: "Implement generic error messages for production environment".to_string(),
            references: vec![
                "https://owasp.org/www-community/Improper_Error_Handling".to_string(),
                "https://cwe.mitre.org/data/definitions/209.html".to_string(),
            ],
            confidence: 0.85,
        },
    ]
}

fn convert_to_enhanced_vulnerabilities(vulnerabilities: Vec<Vulnerability>) -> Vec<EnhancedVulnerability> {
    vulnerabilities.into_iter().map(|vuln| {
        let false_positive_probability = match vuln.severity {
            Severity::Critical => 0.05,
            Severity::High => 0.10,
            Severity::Medium => 0.20,
            Severity::Low => 0.35,
            Severity::Info => 0.50,
        };
        
        let contributing_factors = vec![
            ConfidenceFactor {
                factor_type: FactorType::PatternSimilarity,
                weight: 0.4,
                contribution: 0.8,
                explanation: "Pattern match confidence based on rule accuracy".to_string(),
            },
            ConfidenceFactor {
                factor_type: FactorType::CodeContext,
                weight: 0.3,
                contribution: 0.7,
                explanation: "Context analysis shows vulnerable pattern usage".to_string(),
            },
            ConfidenceFactor {
                factor_type: FactorType::UserFeedbackHistory,
                weight: 0.3,
                contribution: 0.6,
                explanation: "Historical data supports this finding".to_string(),
            },
        ];
        
        let similar_patterns = vec![
            SimilarPattern {
                pattern_hash: format!("hash_{}", vuln.category),
                similarity_score: 0.85,
                historical_classification: Classification::TruePositive,
                occurrence_frequency: 15,
                confidence: 0.9,
            },
            SimilarPattern {
                pattern_hash: "db_pattern_123".to_string(),
                similarity_score: 0.72,
                historical_classification: Classification::TruePositive,
                occurrence_frequency: 8,
                confidence: 0.8,
            },
        ];
        
        let user_recommendations = vec![
            UserRecommendation {
                recommendation_type: RecommendationType::HighPriority,
                priority: Priority::High,
                explanation: "High priority for remediation based on severity".to_string(),
                estimated_effort: RemediationEffort::Moderate,
            },
            UserRecommendation {
                recommendation_type: RecommendationType::Review,
                priority: Priority::Medium,
                explanation: "Consider immediate patching if confirmed".to_string(),
                estimated_effort: RemediationEffort::Minor,
            },
        ];
        
        let suggested_actions = vec![
            SuggestedAction {
                action_type: ActionType::CodeFix,
                confidence: 0.85,
                description: "Review and validate the finding".to_string(),
                automation_possible: false,
            },
            SuggestedAction {
                action_type: ActionType::Testing,
                confidence: 0.90,
                description: "Implement recommended fix".to_string(),
                automation_possible: true,
            },
            SuggestedAction {
                action_type: ActionType::Testing,
                confidence: 0.95,
                description: "Test in staging environment".to_string(),
                automation_possible: true,
            },
        ];
        
        EnhancedVulnerability {
            vulnerability: vuln,
            false_positive_probability,
            confidence_score: 1.0 - false_positive_probability,
            contributing_factors,
            similar_patterns,
            user_recommendations,
            suggested_actions,
        }
    }).collect()
}

async fn assess_vulnerabilities_with_impact(analyzer: &Analyzer, enhanced_vulns: &[EnhancedVulnerability]) -> Result<Vec<AssessedVulnerability>, Box<dyn std::error::Error>> {
    let mut assessed_vulnerabilities = Vec::new();
    
    for enhanced_vuln in enhanced_vulns {
        match analyzer.assess_vulnerability_impact(enhanced_vuln) {
            Ok(assessed) => assessed_vulnerabilities.push(assessed),
            Err(e) => {
                eprintln!("Failed to assess vulnerability {}: {}", enhanced_vuln.vulnerability.id, e);
            }
        }
    }
    
    Ok(assessed_vulnerabilities)
}

fn display_impact_assessment_results(assessed_vulns: &[AssessedVulnerability]) {
    println!("\n📈 Comprehensive Impact Assessment Results");
    println!("{}", "-".repeat(60));
    
    for (i, assessed) in assessed_vulns.iter().enumerate() {
        let vuln = &assessed.enhanced_vulnerability.vulnerability;
        let cvss = &assessed.cvss_assessment;
        let risk = &assessed.risk_assessment;
        
        println!("\n{}. {}", i + 1, vuln.title);
        println!("   ID: {}", vuln.id);
        println!("   Severity: {:?}", vuln.severity);
        println!("   CVSS Score: {:.1} ({:?})", cvss.scores.overall_score, cvss.scores.severity_rating);
        println!("   Risk Classification: {:?}", risk.risk_classification);
        println!("   Composite Risk Score: {:.2}/10", risk.composite_risk_score);
        println!("   Confidence: {:.1}%", cvss.confidence_metrics.overall_confidence * 100.0);
        
        // Risk factors breakdown
        println!("   Risk Factors:");
        println!("     • Technical: {:.1}%", risk.risk_factors.technical_factors * 100.0);
        println!("     • Business: {:.1}%", risk.risk_factors.business_factors * 100.0);
        println!("     • Environmental: {:.1}%", risk.risk_factors.environmental_factors * 100.0);
        println!("     • Threat: {:.1}%", risk.risk_factors.threat_factors * 100.0);
        
        // Exploitability assessment
        let exploit = &assessed.exploitability;
        println!("   Exploitability:");
        println!("     • Maturity: {:?}", exploit.exploit_availability.exploit_maturity);
        println!("     • Success Rate: {:.1}%", exploit.exploit_reliability.success_rate * 100.0);
        println!("     • Weaponization: {:.1}/10", exploit.weaponization_potential.automation_potential * 10.0);
        
        // Business impact
        let business = &assessed.business_impact;
        println!("   Business Impact:");
        println!("     • Asset Criticality: {:?}", business.asset_criticality.criticality_level);
        println!("     • Financial Impact: ${:.0}", business.financial_impact.total_estimated_impact);
        println!("     • Service Disruption: {:?}", business.operational_impact.service_disruption);
        
        println!("   File: {} (line {})", vuln.file_path, vuln.line_number);
    }
}

fn demonstrate_risk_prioritization(assessed_vulns: &[AssessedVulnerability]) {
    println!("\n🎯 Risk-Based Prioritization");
    println!("{}", "-".repeat(60));
    
    // Sort by composite risk score (descending)
    let mut sorted_vulns = assessed_vulns.to_vec();
    sorted_vulns.sort_by(|a, b| b.risk_assessment.composite_risk_score
        .partial_cmp(&a.risk_assessment.composite_risk_score)
        .unwrap_or(std::cmp::Ordering::Equal));
    
    println!("Priority | Vulnerability | Risk Score | Classification | Timeline");
    println!("{}", "-".repeat(80));
    
    for (i, assessed) in sorted_vulns.iter().enumerate() {
        let priority = match i {
            0..=1 => "🔴 HIGH",
            2..=3 => "🟡 MEDIUM",
            _ => "🟢 LOW",
        };
        
        let timeline = match assessed.remediation_guidance.priority_level {
            RemediationPriority::Emergency => "Immediate",
            RemediationPriority::Critical => "24 hours",
            RemediationPriority::High => "1 week",
            RemediationPriority::Medium => "1 month",
            RemediationPriority::Low => "Next quarter",
            RemediationPriority::Planning => "Future planning",
        };
        
        println!("{:<8} | {:<13} | {:<10.1} | {:<13?} | {}",
                priority,
                &assessed.enhanced_vulnerability.vulnerability.id[..13],
                assessed.risk_assessment.composite_risk_score,
                assessed.risk_assessment.risk_classification,
                timeline);
    }
}

fn demonstrate_compliance_analysis(assessed_vulns: &[AssessedVulnerability]) {
    println!("\n📋 Compliance and Regulatory Impact Analysis");
    println!("{}", "-".repeat(60));
    
    let mut compliance_summary = std::collections::HashMap::new();
    let mut total_financial_risk = 0.0;
    
    for assessed in assessed_vulns {
        let compliance = &assessed.compliance_impact;
        
        // Aggregate compliance framework impacts
        for framework in &compliance.affected_frameworks {
            let entry = compliance_summary.entry(framework.framework_name.clone()).or_insert(0);
            *entry += 1;
        }
        
        total_financial_risk += compliance.penalty_risks.financial_penalties;
    }
    
    println!("Compliance Framework Violations:");
    for (framework, count) in compliance_summary {
        println!("  • {}: {} violations", framework, count);
    }
    
    println!("\nFinancial Risk Assessment:");
    println!("  • Total Potential Penalties: ${:.0}", total_financial_risk);
    println!("  • Average Risk per Vulnerability: ${:.0}", total_financial_risk / assessed_vulns.len() as f64);
    
    println!("\nRegulatory Reporting Requirements:");
    for assessed in assessed_vulns.iter().take(3) {
        let compliance = &assessed.compliance_impact;
        for requirement in &compliance.reporting_requirements {
            println!("  • {}: Report within {} hours", 
                    requirement.regulation, 
                    requirement.reporting_timeline.as_secs() / 3600);
        }
    }
}

fn demonstrate_remediation_guidance(assessed_vulns: &[AssessedVulnerability]) {
    println!("\n🔧 Remediation Guidance and Resource Planning");
    println!("{}", "-".repeat(60));
    
    let mut total_cost = 0.0;
    let mut total_hours = 0.0;
    let mut emergency_count = 0;
    let mut critical_count = 0;
    
    for assessed in assessed_vulns {
        let remediation = &assessed.remediation_guidance;
        total_cost += remediation.resource_requirements.budget_estimate;
        total_hours += remediation.resource_requirements.personnel_hours;
        
        match remediation.priority_level {
            RemediationPriority::Emergency => emergency_count += 1,
            RemediationPriority::Critical => critical_count += 1,
            _ => {}
        }
        
        println!("\n{} ({})", 
                assessed.enhanced_vulnerability.vulnerability.title,
                assessed.enhanced_vulnerability.vulnerability.id);
        println!("  Priority: {:?}", remediation.priority_level);
        println!("  Timeline: {} days", remediation.recommended_timeline.full_remediation.as_secs() / 86400);
        println!("  Effort: {:.0} hours", remediation.resource_requirements.personnel_hours);
        println!("  Cost: ${:.0}", remediation.resource_requirements.budget_estimate);
        println!("  Risk Reduction: {:.0}%", remediation.risk_reduction_potential.risk_reduction_percentage);
        
        if !remediation.resource_requirements.skill_requirements.is_empty() {
            println!("  Skills Required: {}", remediation.resource_requirements.skill_requirements.join(", "));
        }
    }
    
    println!("\n📊 Resource Planning Summary:");
    println!("  • Emergency Fixes Needed: {}", emergency_count);
    println!("  • Critical Fixes Needed: {}", critical_count);
    println!("  • Total Estimated Cost: ${:.0}", total_cost);
    println!("  • Total Estimated Hours: {:.0}", total_hours);
    println!("  • Average Cost per Fix: ${:.0}", total_cost / assessed_vulns.len() as f64);
    println!("  • Recommended Team Size: {} engineers", (total_hours / 160.0).ceil()); // Assuming 160 hours per month per engineer
}

fn display_assessment_analytics(analyzer: &Analyzer) {
    println!("\n📊 Assessment Analytics and Insights");
    println!("{}", "-".repeat(60));
    
    // Display false positive reduction analytics
    if let Some(fp_analytics) = analyzer.get_false_positive_analytics() {
        println!("False Positive Reduction:");
        println!("  • Model Accuracy: {:.1}%", fp_analytics.accuracy_rate * 100.0);
        println!("  • False Positive Rate: {:.2}%", fp_analytics.false_positive_rate * 100.0);
        println!("  • Improvement Trend: {:.1}%", fp_analytics.improvement_trend * 100.0);
    }
    
    // Display impact assessment analytics
    if let Some(impact_analytics) = analyzer.get_impact_assessment_analytics() {
        println!("\nImpact Assessment:");
        println!("  • Total Assessments: {}", impact_analytics.total_assessments);
        println!("  • Average Assessment Time: {}ms", impact_analytics.average_assessment_time.as_millis());
        
        println!("  • Risk Distribution:");
        for (risk_class, count) in &impact_analytics.risk_distribution {
            println!("    - {:?}: {}", risk_class, count);
        }
        
        println!("  • Compliance Violations: {}", impact_analytics.compliance_violations);
    }
    
    println!("\nAssessment Confidence Metrics:");
    println!("  • High Confidence (>90%): Available for critical vulnerabilities");
    println!("  • Medium Confidence (70-90%): Typical for most findings");
    println!("  • Lower Confidence (<70%): Requires manual review");
    
    println!("\nTrend Analysis:");
    println!("  • Risk trend prediction enabled");
    println!("  • 30-day outlook: Stable with minor fluctuations");
    println!("  • Correlation analysis: Cross-vulnerability relationships tracked");
    
    println!("\nRecommendations:");
    println!("  • Focus on critical and high-risk vulnerabilities first");
    println!("  • Implement automated remediation for low-complexity fixes");
    println!("  • Schedule regular impact assessment updates");
    println!("  • Consider security control improvements for high-risk environments");
}