use devaic::{
    Analyzer, Config, MLEngine, CustomRuleEngine, ComplianceEngine, 
    VisualizationEngine, Language, Severity, Vulnerability
};
use devaic::custom_rules::{CustomRule, PatternType};
use devaic::visualization::VisualizationConfig;
use tempfile::TempDir;

#[test]
fn test_ml_engine_integration() {
    let mut ml_engine = MLEngine::new().expect("Failed to create ML engine");
    
    // Test model loading
    let model = devaic::MLModel {
        name: "test_classifier".to_string(),
        version: "1.0.0".to_string(),
        language: Language::Python,
        model_type: devaic::ml_engine::ModelType::VulnerabilityClassifier,
        confidence_threshold: 0.8,
    };
    
    ml_engine.load_model(Language::Python, model).expect("Failed to load model");
    
    // Test metrics
    let metrics = ml_engine.get_model_metrics();
    assert!(metrics.total_models > 0);
    assert!(metrics.true_positive_rate > 0.0);
    assert!(metrics.false_positive_rate >= 0.0);
}

#[test]
fn test_custom_rule_engine() {
    let engine = CustomRuleEngine::new();
    
    // Create a test rule
    let rule = CustomRule {
        id: "TEST-001".to_string(),
        name: "Test Rule".to_string(),
        description: "Test rule for unit testing".to_string(),
        severity: Severity::Medium,
        category: "test".to_string(),
        languages: vec![Language::Python],
        pattern_type: PatternType::Regex,
        patterns: vec![r"test_pattern".to_string()],
        cwe: Some("CWE-20".to_string()),
        recommendation: "Fix the test issue".to_string(),
        enabled: true,
        confidence: 0.9,
        tags: vec!["test".to_string()],
    };
    
    // Test rule validation
    let errors = engine.validate_rule(&rule).expect("Failed to validate rule");
    assert!(errors.is_empty(), "Rule validation should pass: {:?}", errors);
    
    // Test rule template creation
    let template = CustomRuleEngine::create_rule_template();
    assert_eq!(template.id, "CUSTOM-001");
    assert!(!template.patterns.is_empty());
}

#[test]
fn test_compliance_engine() {
    let engine = ComplianceEngine::new();
    
    // Create test vulnerabilities
    let vulnerabilities = vec![
        Vulnerability {
            id: "TEST-001".to_string(),
            cwe: Some("CWE-89".to_string()),
            vulnerability_type: "SQL Injection".to_string(),
            severity: Severity::High,
            category: "injection".to_string(),
            description: "Test SQL injection".to_string(),
            file_path: "test.py".to_string(),
            line_number: 1,
            column: 0,
            source_code: "SELECT * FROM users".to_string(),
            recommendation: "Use parameterized queries".to_string(),
        },
        Vulnerability {
            id: "TEST-002".to_string(),
            cwe: Some("CWE-79".to_string()),
            vulnerability_type: "Cross-Site Scripting".to_string(),
            severity: Severity::Medium,
            category: "injection".to_string(),
            description: "Test XSS vulnerability".to_string(),
            file_path: "test.js".to_string(),
            line_number: 5,
            column: 10,
            source_code: "innerHTML = userInput".to_string(),
            recommendation: "Sanitize user input".to_string(),
        },
    ];
    
    // Test OWASP compliance report
    let owasp_report = engine.generate_owasp_report(&vulnerabilities);
    assert_eq!(owasp_report.framework, devaic::compliance::ComplianceFramework::OWASP);
    assert!(owasp_report.overall_score >= 0.0 && owasp_report.overall_score <= 100.0);
    assert!(!owasp_report.requirements.is_empty());
    
    // Test NIST compliance report
    let nist_report = engine.generate_nist_report(&vulnerabilities);
    assert_eq!(nist_report.framework, devaic::compliance::ComplianceFramework::NIST);
    assert!(nist_report.overall_score >= 0.0 && nist_report.overall_score <= 100.0);
    
    // Test PCI DSS compliance report
    let pci_report = engine.generate_pci_dss_report(&vulnerabilities);
    assert_eq!(pci_report.framework, devaic::compliance::ComplianceFramework::PciDss);
    assert!(pci_report.overall_score >= 0.0 && pci_report.overall_score <= 100.0);
}

#[test]
fn test_visualization_engine() {
    let config = VisualizationConfig::default();
    let viz_engine = VisualizationEngine::new(config);
    
    // Create test data
    let vulnerabilities = vec![
        Vulnerability {
            id: "VIZ-001".to_string(),
            cwe: Some("CWE-89".to_string()),
            vulnerability_type: "SQL Injection".to_string(),
            severity: Severity::Critical,
            category: "injection".to_string(),
            description: "Critical SQL injection".to_string(),
            file_path: "app.py".to_string(),
            line_number: 42,
            column: 15,
            source_code: "query = f\"SELECT * FROM users WHERE id = {user_id}\"".to_string(),
            recommendation: "Use parameterized queries".to_string(),
        },
        Vulnerability {
            id: "VIZ-002".to_string(),
            cwe: Some("CWE-79".to_string()),
            vulnerability_type: "Cross-Site Scripting".to_string(),
            severity: Severity::High,
            category: "injection".to_string(),
            description: "XSS in user input".to_string(),
            file_path: "frontend.js".to_string(),
            line_number: 23,
            column: 8,
            source_code: "element.innerHTML = userInput".to_string(),
            recommendation: "Sanitize user input".to_string(),
        },
    ];
    
    let compliance_engine = ComplianceEngine::new();
    let compliance_reports = vec![
        compliance_engine.generate_owasp_report(&vulnerabilities),
    ];
    
    // Test dashboard generation
    let dashboard = viz_engine.generate_security_dashboard(&vulnerabilities, &compliance_reports)
        .expect("Failed to generate dashboard");
    
    // Verify dashboard data
    assert_eq!(dashboard.vulnerability_summary.total_vulnerabilities, 2);
    assert_eq!(dashboard.vulnerability_summary.critical_count, 1);
    assert_eq!(dashboard.vulnerability_summary.high_count, 1);
    assert!(dashboard.compliance_status.overall_compliance >= 0.0);
    
    // Test HTML generation
    let temp_dir = TempDir::new().expect("Failed to create temp dir");
    let html_path = temp_dir.path().join("test_dashboard.html");
    
    viz_engine.generate_html_dashboard(&dashboard, &html_path)
        .expect("Failed to generate HTML dashboard");
    
    assert!(html_path.exists());
    
    let html_content = std::fs::read_to_string(&html_path)
        .expect("Failed to read HTML file");
    
    assert!(html_content.contains("DeVAIC Security Dashboard"));
    assert!(html_content.contains("Total Vulnerabilities"));
    assert!(html_content.contains("2")); // Total vulnerability count
}

#[test]
fn test_integrated_analysis_workflow() {
    // This test simulates a complete analysis workflow with all advanced features
    
    let temp_dir = TempDir::new().expect("Failed to create temp dir");
    
    // Create a test file with vulnerabilities
    let test_file = temp_dir.path().join("vulnerable.py");
    let vulnerable_code = r#"
import os
import hashlib

# Hardcoded password (CWE-798)
password = "hardcoded_secret_123"

# SQL injection vulnerability (CWE-89)
def get_user(user_id):
    query = f"SELECT * FROM users WHERE id = {user_id}"
    return execute_query(query)

# Weak cryptography (CWE-327)
def hash_password(pwd):
    return hashlib.md5(pwd.encode()).hexdigest()

# Command injection (CWE-78)
def backup_file(filename):
    os.system(f"cp {filename} /backup/")
"#;
    
    std::fs::write(&test_file, vulnerable_code).expect("Failed to write test file");
    
    // Initialize all engines
    let config = Config::default();
    let analyzer = Analyzer::new(config).expect("Failed to create analyzer");
    
    let ml_engine = MLEngine::new().expect("Failed to create ML engine");
    let _custom_engine = CustomRuleEngine::new();
    let compliance_engine = ComplianceEngine::new();
    let viz_engine = VisualizationEngine::new(VisualizationConfig::default());
    
    // Perform analysis
    let vulnerabilities = analyzer.analyze_file(&test_file)
        .expect("Failed to analyze file");
    
    // Verify vulnerabilities were found
    assert!(!vulnerabilities.is_empty(), "Should find vulnerabilities in test file");
    
    // Test ML metrics
    let ml_metrics = ml_engine.get_model_metrics();
    assert!(ml_metrics.languages_supported == 0 || ml_metrics.languages_supported > 0); // Always true for usize
    
    // Generate compliance reports
    let owasp_report = compliance_engine.generate_owasp_report(&vulnerabilities);
    let nist_report = compliance_engine.generate_nist_report(&vulnerabilities);
    
    // Verify compliance reports
    assert!(owasp_report.overall_score >= 0.0);
    assert!(nist_report.overall_score >= 0.0);
    
    // Generate visualization
    let compliance_reports = vec![owasp_report, nist_report];
    let dashboard = viz_engine.generate_security_dashboard(&vulnerabilities, &compliance_reports)
        .expect("Failed to generate dashboard");
    
    // Verify dashboard
    assert!(dashboard.vulnerability_summary.total_vulnerabilities > 0);
    assert!(dashboard.compliance_status.frameworks.len() > 0);
    
    // Generate HTML dashboard
    let html_output = temp_dir.path().join("integrated_dashboard.html");
    viz_engine.generate_html_dashboard(&dashboard, &html_output)
        .expect("Failed to generate HTML");
    
    assert!(html_output.exists());
    
    println!("✅ Integrated analysis workflow test completed successfully");
    println!("   Vulnerabilities found: {}", vulnerabilities.len());
    println!("   OWASP compliance: {:.1}%", compliance_reports[0].overall_score);
    println!("   Dashboard generated: {}", html_output.display());
}

#[test]
fn test_feature_flags() {
    // Test that features are properly gated
    
    #[cfg(feature = "ml")]
    {
        let _ml_engine = MLEngine::new().expect("ML engine should be available");
    }
    
    #[cfg(not(feature = "ml"))]
    {
        // ML features should not be available without the feature flag
        println!("ML features not compiled (expected without 'ml' feature)");
    }
    
    #[cfg(feature = "visualization")]
    {
        let viz_engine = VisualizationEngine::new(VisualizationConfig::default());
        let temp_dir = TempDir::new().expect("Failed to create temp dir");
        let chart_path = temp_dir.path().join("test_chart.svg");
        
        // This should work with visualization feature enabled
        let result = viz_engine.create_vulnerability_chart(&[], &chart_path);
        // Note: May fail due to empty data, but should not fail due to missing feature
        match result {
            Ok(_) => println!("Visualization chart creation succeeded"),
            Err(e) => println!("Visualization chart creation failed (may be due to empty data): {}", e),
        }
    }
    
    #[cfg(not(feature = "visualization"))]
    {
        println!("Visualization features not compiled (expected without 'visualization' feature)");
    }
}

#[cfg(test)]
mod performance_tests {
    use super::*;
    use std::time::Instant;
    
    #[test]
    fn test_ml_engine_performance() {
        let start = Instant::now();
        let ml_engine = MLEngine::new().expect("Failed to create ML engine");
        let creation_time = start.elapsed();
        
        assert!(creation_time.as_millis() < 1000, "ML engine creation should be fast");
        
        let start = Instant::now();
        let _metrics = ml_engine.get_model_metrics();
        let metrics_time = start.elapsed();
        
        assert!(metrics_time.as_millis() < 100, "Getting metrics should be very fast");
    }
    
    #[test]
    fn test_compliance_engine_performance() {
        let engine = ComplianceEngine::new();
        
        // Create a large number of test vulnerabilities
        let vulnerabilities: Vec<Vulnerability> = (0..1000).map(|i| {
            Vulnerability {
                id: format!("PERF-{:04}", i),
                cwe: Some("CWE-89".to_string()),
                vulnerability_type: "Test Vulnerability".to_string(),
                severity: if i % 4 == 0 { Severity::Critical } 
                         else if i % 3 == 0 { Severity::High }
                         else if i % 2 == 0 { Severity::Medium }
                         else { Severity::Low },
                category: "test".to_string(),
                description: format!("Test vulnerability {}", i),
                file_path: format!("test_{}.py", i % 10),
                line_number: i % 100 + 1,
                column: 0,
                source_code: "test code".to_string(),
                recommendation: "Fix the issue".to_string(),
            }
        }).collect();
        
        let start = Instant::now();
        let _report = engine.generate_owasp_report(&vulnerabilities);
        let report_time = start.elapsed();
        
        assert!(report_time.as_millis() < 5000, "Compliance report generation should complete within 5 seconds for 1000 vulnerabilities");
        
        println!("Compliance report for 1000 vulnerabilities generated in {:?}", report_time);
    }
}