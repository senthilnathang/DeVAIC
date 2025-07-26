/// Simple Impact Assessment Demo
/// 
/// This example demonstrates the basic impact assessment and risk scoring functionality
/// in a simplified form that works without full compilation.

use std::collections::HashMap;

fn main() -> Result<(), Box<dyn std::error::Error>> {
    println!("🚀 DeVAIC Impact Assessment and Risk Scoring Demo");
    println!("{}", "=".repeat(60));
    
    // Simulate vulnerability impact assessment
    let vulnerabilities = create_sample_vulnerabilities();
    
    println!("\n📊 Analyzing {} vulnerabilities with impact assessment...", vulnerabilities.len());
    
    for (i, vuln) in vulnerabilities.iter().enumerate() {
        println!("\n{}. {}", i + 1, vuln.title);
        println!("   Severity: {:?}", vuln.severity);
        
        // Calculate CVSS-like score
        let cvss_score = calculate_cvss_score(&vuln.severity);
        println!("   CVSS Score: {:.1}", cvss_score);
        
        // Calculate business impact
        let business_impact = calculate_business_impact(&vuln.category, &vuln.severity);
        println!("   Business Impact: ${:.0}", business_impact);
        
        // Calculate overall risk score
        let risk_score = calculate_risk_score(cvss_score, business_impact);
        let risk_classification = classify_risk(risk_score);
        println!("   Overall Risk Score: {:.2}/10", risk_score);
        println!("   Risk Classification: {:?}", risk_classification);
        
        // Generate remediation guidance
        let remediation = generate_remediation_guidance(&risk_classification);
        println!("   Remediation Priority: {:?}", remediation.priority);
        println!("   Estimated Cost: ${:.0}", remediation.cost);
        println!("   Timeline: {} days", remediation.timeline_days);
        
        println!("   File: {} (line {})", vuln.file_path, vuln.line_number);
    }
    
    // Demonstrate risk prioritization
    demonstrate_risk_prioritization(&vulnerabilities);
    
    // Show summary analytics
    show_summary_analytics(&vulnerabilities);
    
    println!("\n✅ Impact Assessment Demo completed successfully!");
    println!("🎯 Key capabilities demonstrated:");
    println!("   • CVSS-based risk scoring");
    println!("   • Business impact calculation");
    println!("   • Risk classification and prioritization");
    println!("   • Remediation cost and timeline estimation");
    println!("   • Comprehensive risk analytics");
    
    Ok(())
}

#[derive(Debug, Clone)]
struct Vulnerability {
    id: String,
    title: String,
    severity: Severity,
    category: String,
    file_path: String,
    line_number: usize,
}

#[derive(Debug, Clone)]
enum Severity {
    Critical,
    High,
    Medium,
    Low,
    Info,
}

#[derive(Debug, Clone)]
enum RiskClassification {
    Catastrophic,
    Critical,
    High,
    Moderate,
    Low,
    Negligible,
}

#[derive(Debug, Clone)]
enum RemediationPriority {
    Emergency,
    Critical,
    High,
    Medium,
    Low,
}

#[derive(Debug)]
struct RemediationGuidance {
    priority: RemediationPriority,
    cost: f64,
    timeline_days: u32,
}

fn create_sample_vulnerabilities() -> Vec<Vulnerability> {
    vec![
        Vulnerability {
            id: "VULN-2024-001".to_string(),
            title: "SQL Injection in User Authentication".to_string(),
            severity: Severity::Critical,
            category: "injection".to_string(),
            file_path: "/src/auth/login.py".to_string(),
            line_number: 45,
        },
        Vulnerability {
            id: "VULN-2024-002".to_string(),
            title: "Cross-Site Scripting (XSS) in User Profile".to_string(),
            severity: Severity::High,
            category: "xss".to_string(),
            file_path: "/src/profile/display.js".to_string(),
            line_number: 28,
        },
        Vulnerability {
            id: "VULN-2024-003".to_string(),
            title: "Insecure Cryptographic Storage".to_string(),
            severity: Severity::High,
            category: "cryptography".to_string(),
            file_path: "/src/encryption/crypto.java".to_string(),
            line_number: 67,
        },
        Vulnerability {
            id: "VULN-2024-004".to_string(),
            title: "Missing Authorization Check".to_string(),
            severity: Severity::Medium,
            category: "authorization".to_string(),
            file_path: "/src/admin/users.go".to_string(),
            line_number: 112,
        },
        Vulnerability {
            id: "VULN-2024-005".to_string(),
            title: "Information Disclosure in Error Messages".to_string(),
            severity: Severity::Low,
            category: "information_disclosure".to_string(),
            file_path: "/src/api/error_handler.rb".to_string(),
            line_number: 23,
        },
    ]
}

fn calculate_cvss_score(severity: &Severity) -> f64 {
    match severity {
        Severity::Critical => 9.5,
        Severity::High => 8.0,
        Severity::Medium => 6.0,
        Severity::Low => 3.0,
        Severity::Info => 1.0,
    }
}

fn calculate_business_impact(category: &str, severity: &Severity) -> f64 {
    let base_impact = match severity {
        Severity::Critical => 500000.0,
        Severity::High => 200000.0,
        Severity::Medium => 75000.0,
        Severity::Low => 25000.0,
        Severity::Info => 5000.0,
    };
    
    // Adjust based on vulnerability category
    let category_multiplier = match category {
        "injection" => 1.5,      // SQL injection has high business impact
        "xss" => 1.2,           // XSS can affect user trust
        "cryptography" => 1.4,   // Crypto issues can be severe
        "authorization" => 1.3,  // Access control failures
        _ => 1.0,
    };
    
    base_impact * category_multiplier
}

fn calculate_risk_score(cvss_score: f64, business_impact: f64) -> f64 {
    // Weighted combination of CVSS score and business impact
    let cvss_weight = 0.6;
    let business_weight = 0.4;
    
    // Normalize business impact to 0-10 scale
    let normalized_business = (business_impact / 100000.0).min(10.0);
    
    let composite_score = (cvss_score * cvss_weight) + (normalized_business * business_weight);
    composite_score.min(10.0)
}

fn classify_risk(risk_score: f64) -> RiskClassification {
    match risk_score {
        s if s >= 9.0 => RiskClassification::Catastrophic,
        s if s >= 8.0 => RiskClassification::Critical,
        s if s >= 6.5 => RiskClassification::High,
        s if s >= 4.0 => RiskClassification::Moderate,
        s if s >= 2.0 => RiskClassification::Low,
        _ => RiskClassification::Negligible,
    }
}

fn generate_remediation_guidance(risk_class: &RiskClassification) -> RemediationGuidance {
    match risk_class {
        RiskClassification::Catastrophic => RemediationGuidance {
            priority: RemediationPriority::Emergency,
            cost: 50000.0,
            timeline_days: 1,
        },
        RiskClassification::Critical => RemediationGuidance {
            priority: RemediationPriority::Critical,
            cost: 25000.0,
            timeline_days: 3,
        },
        RiskClassification::High => RemediationGuidance {
            priority: RemediationPriority::High,
            cost: 15000.0,
            timeline_days: 7,
        },
        RiskClassification::Moderate => RemediationGuidance {
            priority: RemediationPriority::Medium,
            cost: 8000.0,
            timeline_days: 30,
        },
        RiskClassification::Low => RemediationGuidance {
            priority: RemediationPriority::Low,
            cost: 3000.0,
            timeline_days: 90,
        },
        RiskClassification::Negligible => RemediationGuidance {
            priority: RemediationPriority::Low,
            cost: 1000.0,
            timeline_days: 180,
        },
    }
}

fn demonstrate_risk_prioritization(vulnerabilities: &[Vulnerability]) {
    println!("\n🎯 Risk-Based Prioritization");
    println!("{}", "-".repeat(60));
    
    // Calculate risk scores for sorting
    let mut vuln_risks: Vec<(usize, f64, RiskClassification)> = vulnerabilities
        .iter()
        .enumerate()
        .map(|(i, vuln)| {
            let cvss = calculate_cvss_score(&vuln.severity);
            let business = calculate_business_impact(&vuln.category, &vuln.severity);
            let risk = calculate_risk_score(cvss, business);
            let classification = classify_risk(risk);
            (i, risk, classification)
        })
        .collect();
    
    // Sort by risk score (descending)
    vuln_risks.sort_by(|a, b| b.1.partial_cmp(&a.1).unwrap());
    
    println!("Priority | Vulnerability | Risk Score | Classification");
    println!("{}", "-".repeat(65));
    
    for (rank, (orig_index, risk_score, classification)) in vuln_risks.iter().enumerate() {
        let priority_icon = match rank {
            0..=1 => "🔴",
            2..=3 => "🟡",
            _ => "🟢",
        };
        
        let vuln = &vulnerabilities[*orig_index];
        println!("{} {:^6} | {:<13} | {:<10.1} | {:?}",
                priority_icon,
                rank + 1,
                &vuln.id[..13],
                risk_score,
                classification);
    }
}

fn show_summary_analytics(vulnerabilities: &[Vulnerability]) {
    println!("\n📊 Summary Analytics");
    println!("{}", "-".repeat(60));
    
    // Count by severity
    let mut severity_count = HashMap::new();
    let mut total_cost = 0.0;
    let mut risk_scores = Vec::new();
    
    for vuln in vulnerabilities {
        *severity_count.entry(format!("{:?}", vuln.severity)).or_insert(0) += 1;
        
        let cvss = calculate_cvss_score(&vuln.severity);
        let business = calculate_business_impact(&vuln.category, &vuln.severity);
        let risk = calculate_risk_score(cvss, business);
        risk_scores.push(risk);
        
        let classification = classify_risk(risk);
        let remediation = generate_remediation_guidance(&classification);
        total_cost += remediation.cost;
    }
    
    println!("Vulnerability Distribution:");
    for (severity, count) in severity_count {
        println!("  • {}: {} vulnerabilities", severity, count);
    }
    
    let avg_risk = risk_scores.iter().sum::<f64>() / risk_scores.len() as f64;
    let max_risk: f64 = risk_scores.iter().fold(0.0, |a, &b| a.max(b));
    
    println!("\nRisk Metrics:");
    println!("  • Average Risk Score: {:.2}/10", avg_risk);
    println!("  • Maximum Risk Score: {:.2}/10", max_risk);
    println!("  • Total Remediation Cost: ${:.0}", total_cost);
    println!("  • Average Cost per Vulnerability: ${:.0}", total_cost / vulnerabilities.len() as f64);
    
    let high_risk_count = risk_scores.iter().filter(|&&score| score >= 6.5).count();
    let critical_issues = risk_scores.iter().filter(|&&score| score >= 8.0).count();
    
    println!("\nPriority Metrics:");
    println!("  • Critical Issues (≥8.0): {}", critical_issues);
    println!("  • High Risk Issues (≥6.5): {}", high_risk_count);
    println!("  • Issues Requiring Immediate Attention: {}", critical_issues);
    
    println!("\nRecommendations:");
    if critical_issues > 0 {
        println!("  ⚠️  {} critical issues require immediate remediation", critical_issues);
    }
    if high_risk_count > 2 {
        println!("  📋 Consider implementing automated scanning for {} high-risk areas", high_risk_count);
    }
    println!("  💰 Budget ${:.0} for comprehensive vulnerability remediation", total_cost);
    println!("  ⏱️  Estimated timeline: 1-90 days depending on priority");
}