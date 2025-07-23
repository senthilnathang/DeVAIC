use devaic::{Analyzer, Config, Language, Severity};
use tempfile::TempDir;

#[test]
fn test_basic_analysis() {
    let config = Config::default();
    let analyzer = Analyzer::new(config).expect("Failed to create analyzer");
    
    // Create a temporary test file
    let temp_dir = TempDir::new().expect("Failed to create temp dir");
    let test_file = temp_dir.path().join("test.py");
    
    let vulnerable_code = r#"
import os
import subprocess

# Command injection vulnerability
def run_command(user_input):
    os.system("ls " + user_input)
    
# SQL injection pattern
def get_user(user_id):
    query = "SELECT * FROM users WHERE id = " + user_id
    return query

# Hardcoded secret
api_key = "sk-1234567890abcdef"
password = "hardcoded_password_123"
"#;
    
    std::fs::write(&test_file, vulnerable_code).expect("Failed to write test file");
    
    // Analyze the file
    let vulnerabilities = analyzer.analyze_file(&test_file).expect("Failed to analyze file");
    
    // Verify vulnerabilities were found
    assert!(!vulnerabilities.is_empty(), "Should find vulnerabilities in test file");
    
    // Check for specific vulnerability types
    let has_command_injection = vulnerabilities.iter().any(|v| 
        v.description.to_lowercase().contains("command") || 
        v.description.to_lowercase().contains("injection") ||
        v.vulnerability_type.to_lowercase().contains("injection")
    );
    
    let has_hardcoded_secret = vulnerabilities.iter().any(|v| 
        v.description.to_lowercase().contains("secret") || 
        v.description.to_lowercase().contains("password") ||
        v.description.to_lowercase().contains("hardcoded")
    );
    
    println!("Found {} vulnerabilities", vulnerabilities.len());
    for vuln in &vulnerabilities {
        println!("- {}: {} ({})", vuln.id, vuln.description, vuln.severity);
    }
    
    // We should find at least some security issues
    assert!(has_command_injection || has_hardcoded_secret, 
           "Should detect command injection or hardcoded secrets");
}

#[test]
fn test_directory_analysis() {
    let config = Config::default();
    let analyzer = Analyzer::new(config).expect("Failed to create analyzer");
    
    // Create a temporary directory with multiple files
    let temp_dir = TempDir::new().expect("Failed to create temp dir");
    
    // Create multiple test files
    let test_files = vec![
        ("test1.py", r#"
import os
def unsafe_exec(cmd):
    os.system(cmd)  # Command injection
"#),
        ("test2.js", r#"
function unsafeEval(userInput) {
    eval(userInput);  // Code injection
}
"#),
        ("test3.java", r#"
public class Test {
    private String password = "hardcoded123";  // Hardcoded password
}
"#),
    ];
    
    for (filename, content) in test_files {
        let file_path = temp_dir.path().join(filename);
        std::fs::write(&file_path, content).expect("Failed to write test file");
    }
    
    // Analyze the directory
    let vulnerabilities = analyzer.analyze_directory(temp_dir.path())
        .expect("Failed to analyze directory");
    
    // Should find vulnerabilities across multiple files
    assert!(!vulnerabilities.is_empty(), "Should find vulnerabilities in directory");
    
    println!("Found {} vulnerabilities across directory", vulnerabilities.len());
    
    // Check that we found vulnerabilities in different files
    let unique_files: std::collections::HashSet<_> = vulnerabilities.iter()
        .map(|v| &v.file_path)
        .collect();
    
    assert!(unique_files.len() > 1, "Should find vulnerabilities in multiple files");
}

#[test]
fn test_language_detection() {
    // Test language detection from file extensions
    assert_eq!(Language::from_extension("py"), Some(Language::Python));
    assert_eq!(Language::from_extension("js"), Some(Language::Javascript));
    assert_eq!(Language::from_extension("java"), Some(Language::Java));
    assert_eq!(Language::from_extension("rs"), Some(Language::Rust));
    assert_eq!(Language::from_extension("go"), Some(Language::Go));
    assert_eq!(Language::from_extension("php"), Some(Language::Php));
    assert_eq!(Language::from_extension("rb"), Some(Language::Ruby));
    assert_eq!(Language::from_extension("kt"), Some(Language::Kotlin));
    assert_eq!(Language::from_extension("cs"), Some(Language::CSharp));
    assert_eq!(Language::from_extension("dart"), Some(Language::Dart));
    assert_eq!(Language::from_extension("swift"), Some(Language::Swift));
    
    // Test unknown extension
    assert_eq!(Language::from_extension("unknown"), None);
}

#[test]
fn test_severity_levels() {
    // Test severity ordering and display
    let severities = vec![
        Severity::Critical,
        Severity::High,
        Severity::Medium,
        Severity::Low,
        Severity::Info,
    ];
    
    for severity in severities {
        let display = format!("{}", severity);
        assert!(!display.is_empty());
        println!("Severity: {}", display);
    }
}

#[test]
fn test_report_generation() {
    let vulnerabilities = vec![
        devaic::Vulnerability {
            id: "TEST-001".to_string(),
            cwe: Some("CWE-78".to_string()),
            vulnerability_type: "Command Injection".to_string(),
            severity: Severity::High,
            category: "injection".to_string(),
            description: "Potential command injection vulnerability".to_string(),
            file_path: "test.py".to_string(),
            line_number: 5,
            column: 10,
            source_code: "os.system(user_input)".to_string(),
            recommendation: "Use subprocess with shell=False".to_string(),
        },
        devaic::Vulnerability {
            id: "TEST-002".to_string(),
            cwe: Some("CWE-798".to_string()),
            vulnerability_type: "Hardcoded Credentials".to_string(),
            severity: Severity::Medium,
            category: "secrets".to_string(),
            description: "Hardcoded password detected".to_string(),
            file_path: "test.py".to_string(),
            line_number: 10,
            column: 15,
            source_code: "password = \"secret123\"".to_string(),
            recommendation: "Use environment variables for secrets".to_string(),
        },
    ];
    
    let report = devaic::Report::new(vulnerabilities, 1);
    
    // Test JSON generation
    let json_output = report.to_json().expect("Failed to generate JSON");
    assert!(!json_output.is_empty());
    assert!(json_output.contains("TEST-001"));
    assert!(json_output.contains("Command Injection"));
    
    // Test table generation
    let table_output = report.to_table(false); // No colors for testing
    assert!(!table_output.is_empty());
    assert!(table_output.contains("TEST-001"));
    assert!(table_output.contains("Command Injection"));
    
    println!("JSON output length: {}", json_output.len());
    println!("Table output length: {}", table_output.len());
}

#[cfg(feature = "ml")]
#[test]
fn test_ml_engine() {
    let ml_engine = devaic::MLEngine::new().expect("Failed to create ML engine");
    let metrics = ml_engine.get_model_metrics();
    
    assert!(metrics.total_models >= 0);
    assert!(metrics.languages_supported >= 0);
    assert!(metrics.average_confidence >= 0.0);
    assert!(metrics.false_positive_rate >= 0.0);
    assert!(metrics.true_positive_rate >= 0.0);
    
    println!("ML Engine metrics: {:?}", metrics);
}

#[test]
fn test_custom_rules_engine() {
    let engine = devaic::CustomRuleEngine::new();
    
    // Test rule template creation
    let template = devaic::CustomRuleEngine::create_rule_template();
    assert_eq!(template.id, "CUSTOM-001");
    assert!(!template.patterns.is_empty());
    assert!(template.enabled);
    
    // Test rule validation
    let errors = engine.validate_rule(&template).expect("Failed to validate rule");
    assert!(errors.is_empty(), "Template rule should be valid: {:?}", errors);
    
    println!("Custom rule template: {:?}", template);
}

#[test]
fn test_compliance_engine() {
    let engine = devaic::ComplianceEngine::new();
    
    let test_vulnerabilities = vec![
        devaic::Vulnerability {
            id: "COMP-001".to_string(),
            cwe: Some("CWE-89".to_string()),
            vulnerability_type: "SQL Injection".to_string(),
            severity: Severity::High,
            category: "injection".to_string(),
            description: "SQL injection vulnerability".to_string(),
            file_path: "app.py".to_string(),
            line_number: 42,
            column: 10,
            source_code: "query = \"SELECT * FROM users WHERE id = \" + user_id".to_string(),
            recommendation: "Use parameterized queries".to_string(),
        },
    ];
    
    // Test OWASP compliance report
    let owasp_report = engine.generate_owasp_report(&test_vulnerabilities);
    assert_eq!(owasp_report.framework, devaic::compliance::ComplianceFramework::OWASP);
    assert!(owasp_report.overall_score >= 0.0 && owasp_report.overall_score <= 100.0);
    assert!(!owasp_report.requirements.is_empty());
    
    // Test NIST compliance report
    let nist_report = engine.generate_nist_report(&test_vulnerabilities);
    assert_eq!(nist_report.framework, devaic::compliance::ComplianceFramework::NIST);
    assert!(nist_report.overall_score >= 0.0 && nist_report.overall_score <= 100.0);
    
    println!("OWASP compliance score: {:.1}%", owasp_report.overall_score);
    println!("NIST compliance score: {:.1}%", nist_report.overall_score);
}

#[test]
fn test_visualization_engine() {
    let config = devaic::visualization::VisualizationConfig::default();
    let viz_engine = devaic::VisualizationEngine::new(config);
    
    let test_vulnerabilities = vec![
        devaic::Vulnerability {
            id: "VIZ-001".to_string(),
            cwe: Some("CWE-79".to_string()),
            vulnerability_type: "Cross-Site Scripting".to_string(),
            severity: Severity::High,
            category: "injection".to_string(),
            description: "XSS vulnerability".to_string(),
            file_path: "app.js".to_string(),
            line_number: 15,
            column: 5,
            source_code: "element.innerHTML = userInput".to_string(),
            recommendation: "Sanitize user input".to_string(),
        },
    ];
    
    let compliance_engine = devaic::ComplianceEngine::new();
    let compliance_reports = vec![
        compliance_engine.generate_owasp_report(&test_vulnerabilities),
    ];
    
    // Test dashboard generation
    let dashboard = viz_engine.generate_security_dashboard(&test_vulnerabilities, &compliance_reports)
        .expect("Failed to generate dashboard");
    
    assert_eq!(dashboard.vulnerability_summary.total_vulnerabilities, 1);
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
    
    println!("Generated HTML dashboard with {} bytes", html_content.len());
}