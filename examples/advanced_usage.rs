use devaic::{
    Analyzer, Config, MLEngine, CustomRuleEngine, ComplianceEngine, 
    VisualizationEngine, Language, Severity
};
use std::path::PathBuf;

#[tokio::main]
async fn main() -> devaic::Result<()> {
    // Example 1: Basic analysis with ML enhancement
    basic_ml_analysis().await?;
    
    // Example 2: Custom rules with compliance reporting
    custom_rules_compliance_example().await?;
    
    // Example 3: Full featured analysis with visualization
    full_featured_analysis().await?;
    
    Ok(())
}

async fn basic_ml_analysis() -> devaic::Result<()> {
    println!("=== Example 1: ML-Enhanced Analysis ===");
    
    // Initialize ML engine
    let mut ml_engine = MLEngine::new()?;
    
    // Load a pre-trained model (simulated)
    let model = devaic::MLModel {
        name: "vulnerability_classifier".to_string(),
        version: "1.0.0".to_string(),
        language: Language::Python,
        model_type: devaic::ml_engine::ModelType::VulnerabilityClassifier,
        confidence_threshold: 0.8,
    };
    ml_engine.load_model(Language::Python, model)?;
    
    // Initialize analyzer
    let config = Config::default();
    let analyzer = Analyzer::new(config)?;
    
    // Analyze a file
    let target = PathBuf::from("tests/fixtures/vulnerable.py");
    if target.exists() {
        let vulnerabilities = analyzer.analyze_file(&target).await?;
        println!("Found {} vulnerabilities", vulnerabilities.len());
        
        // Get ML metrics
        let metrics = ml_engine.get_model_metrics();
        println!("ML Engine: {} models, {:.1}% accuracy", 
                metrics.total_models, metrics.true_positive_rate * 100.0);
    } else {
        println!("Test file not found, skipping analysis");
    }
    
    Ok(())
}

async fn custom_rules_compliance_example() -> devaic::Result<()> {
    println!("\n=== Example 2: Custom Rules + Compliance ===");
    
    // Initialize custom rule engine
    let custom_engine = CustomRuleEngine::new();
    
    // Create a custom rule
    let custom_rule = devaic::CustomRule {
        id: "CUSTOM-001".to_string(),
        name: "Hardcoded API Key".to_string(),
        description: "Detects hardcoded API keys in source code".to_string(),
        severity: Severity::High,
        category: "secrets".to_string(),
        languages: vec![Language::Python, Language::Javascript],
        pattern_type: devaic::custom_rules::PatternType::Regex,
        patterns: vec![r#"api[_-]?key\s*=\s*["'][a-zA-Z0-9]{20,}["']"#.to_string()],
        cwe: Some("CWE-798".to_string()),
        recommendation: "Store API keys in environment variables or secure configuration".to_string(),
        enabled: true,
        confidence: 0.9,
        tags: vec!["security".to_string(), "secrets".to_string()],
    };
    
    // Validate the rule
    let validation_errors = custom_engine.validate_rule(&custom_rule)?;
    if validation_errors.is_empty() {
        println!("Custom rule validation passed");
    } else {
        println!("Custom rule validation errors: {:?}", validation_errors);
    }
    
    // Initialize compliance engine
    let compliance_engine = ComplianceEngine::new();
    
    // Simulate some vulnerabilities for compliance testing
    let vulnerabilities = vec![
        devaic::Vulnerability {
            id: "TEST-001".to_string(),
            cwe: Some("CWE-89".to_string()),
            title: "SQL Injection".to_string(),
            severity: Severity::High,
            category: "injection".to_string(),
            description: "Potential SQL injection vulnerability".to_string(),
            file_path: "test.py".to_string(),
            line_number: 42,
            column_start: 10,
            column_end: 50,
            source_code: "query = \"SELECT * FROM users WHERE id = \" + user_id".to_string(),
            recommendation: "Use parameterized queries".to_string(),
            owasp: Some("A03:2021".to_string()),
            references: vec!["https://owasp.org/www-project-top-ten/2017/A1_2017-Injection".to_string()],
            confidence: 0.9,
        }
    ];
    
    // Generate OWASP compliance report
    let owasp_report = compliance_engine.generate_owasp_report(&vulnerabilities);
    println!("OWASP Compliance Score: {:.1}%", owasp_report.overall_score);
    println!("Compliance Level: {:?}", owasp_report.compliance_level);
    
    Ok(())
}

async fn full_featured_analysis() -> devaic::Result<()> {
    println!("\n=== Example 3: Full Featured Analysis ===");
    
    // Initialize all engines
    let mut ml_engine = MLEngine::new()?;
    let _custom_engine = CustomRuleEngine::new();
    let compliance_engine = ComplianceEngine::new();
    let viz_engine = VisualizationEngine::new(devaic::visualization::VisualizationConfig::default());
    
    // Simulate analysis results
    let vulnerabilities = vec![
        devaic::Vulnerability {
            id: "VULN-001".to_string(),
            cwe: Some("CWE-79".to_string()),
            title: "Cross-Site Scripting".to_string(),
            severity: Severity::High,
            category: "injection".to_string(),
            description: "Potential XSS vulnerability".to_string(),
            file_path: "app.js".to_string(),
            line_number: 15,
            column_start: 5,
            column_end: 35,
            source_code: "document.innerHTML = userInput".to_string(),
            recommendation: "Sanitize user input before rendering".to_string(),
            owasp: Some("A03:2021".to_string()),
            references: vec!["https://owasp.org/www-project-top-ten/2017/A7_2017-Cross-Site_Scripting_(XSS)".to_string()],
            confidence: 0.85,
        },
        devaic::Vulnerability {
            id: "VULN-002".to_string(),
            cwe: Some("CWE-327".to_string()),
            title: "Weak Cryptography".to_string(),
            severity: Severity::Medium,
            category: "cryptography".to_string(),
            description: "Use of weak cryptographic algorithm".to_string(),
            file_path: "crypto.py".to_string(),
            line_number: 23,
            column_start: 8,
            column_end: 29,
            source_code: "hashlib.md5(password)".to_string(),
            recommendation: "Use SHA-256 or stronger hashing algorithm".to_string(),
            owasp: Some("A02:2021".to_string()),
            references: vec!["https://cwe.mitre.org/data/definitions/327.html".to_string()],
            confidence: 0.75,
        },
    ];
    
    // Generate compliance reports
    let owasp_report = compliance_engine.generate_owasp_report(&vulnerabilities);
    let nist_report = compliance_engine.generate_nist_report(&vulnerabilities);
    let compliance_reports = vec![owasp_report, nist_report];
    
    // Generate security dashboard
    let dashboard = viz_engine.generate_security_dashboard(&vulnerabilities, &compliance_reports)?;
    
    // Print dashboard summary
    println!("Security Dashboard Summary:");
    println!("  Total Vulnerabilities: {}", dashboard.vulnerability_summary.total_vulnerabilities);
    println!("  Critical: {}", dashboard.vulnerability_summary.critical_count);
    println!("  High: {}", dashboard.vulnerability_summary.high_count);
    println!("  Medium: {}", dashboard.vulnerability_summary.medium_count);
    println!("  Low: {}", dashboard.vulnerability_summary.low_count);
    println!("  Overall Compliance: {:.1}%", dashboard.compliance_status.overall_compliance);
    
    // Generate HTML dashboard
    let output_dir = PathBuf::from("reports");
    std::fs::create_dir_all(&output_dir)?;
    
    let html_output = output_dir.join("example_dashboard.html");
    viz_engine.generate_html_dashboard(&dashboard, &html_output)?;
    println!("Dashboard saved to: {}", html_output.display());
    
    // Train ML model with example data (simulated)
    let training_data = vec![
        devaic::ml_engine::TrainingExample {
            source_code: "SELECT * FROM users WHERE id = 123".to_string(),
            language: Language::Python,
            vulnerabilities: vec![vulnerabilities[0].clone()],
            is_vulnerable: true,
        }
    ];
    
    ml_engine.train_model(&training_data)?;
    println!("ML model training completed");
    
    Ok(())
}