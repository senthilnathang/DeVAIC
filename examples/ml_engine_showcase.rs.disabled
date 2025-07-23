use devaic::ml_engine::{MLEngine, MLModel, ModelType, TrainingExample};
use devaic::{Language, Severity, parsers::SourceFile, Vulnerability};
use std::path::Path;

/// Showcase of the enhanced ML-based vulnerability detection engine
fn main() -> Result<(), Box<dyn std::error::Error>> {
    println!("🤖 Enhanced ML-Based Vulnerability Detection Engine Showcase");
    println!("===========================================================");
    
    // Initialize the ML engine with advanced features
    let mut ml_engine = MLEngine::new()?;
    
    // Load different types of ML models
    let models = vec![
        MLModel {
            name: "Advanced Vulnerability Classifier".to_string(),
            version: "2.0.0".to_string(),
            language: Language::Rust,
            model_type: ModelType::VulnerabilityClassifier,
            confidence_threshold: 0.75,
        },
        MLModel {
            name: "Anomaly Detection Engine".to_string(),
            version: "1.0.0".to_string(),
            language: Language::Rust,
            model_type: ModelType::AnomalyDetector,
            confidence_threshold: 0.70,
        },
        MLModel {
            name: "Contextual Security Analyzer".to_string(),
            version: "1.0.0".to_string(),
            language: Language::Rust,
            model_type: ModelType::ContextualAnalyzer,
            confidence_threshold: 0.80,
        },
        MLModel {
            name: "Behavioral Pattern Detector".to_string(),
            version: "1.0.0".to_string(),
            language: Language::Rust,
            model_type: ModelType::BehavioralAnalyzer,
            confidence_threshold: 0.85,
        },
        MLModel {
            name: "Security Pattern Matcher".to_string(),
            version: "1.0.0".to_string(),
            language: Language::Rust,
            model_type: ModelType::SecurityPatternMatcher,
            confidence_threshold: 0.75,
        },
    ];
    
    // Load all models
    for model in models {
        ml_engine.load_model(Language::Rust, model)?;
    }
    
    println!("✅ Loaded {} ML models for vulnerability detection", 5);
    
    // Create test source files with various security issues
    let test_cases = vec![
        (
            "unsafe_memory_access.rs",
            r#"
use std::ptr;

fn dangerous_function(user_input: &str) {
    unsafe {
        let raw_ptr = user_input.as_ptr();
        let dangerous_data = ptr::read(raw_ptr.add(100)); // Buffer overflow potential
        system(format!("rm -rf {}", dangerous_data).as_ptr() as *const i8);
    }
    
    // Potential memory leak
    let leaked_memory = Box::new([0u8; 1024]);
    std::mem::forget(leaked_memory);
    
    // Unsafe unwrap that could panic
    let result = std::env::var("SECRET_KEY").unwrap();
    eval(&result); // Dynamic code execution
}
"#
        ),
        (
            "obfuscated_code.rs",
            r#"
fn mysterious_function() {
    let ¢ɦɑɾɴɦɑ©ɦ = "§¥§†€м";
    let ӄɛʟӄɛֆ = "єχє¢";
    let combined = ¢ɦɑɾɴɦɑ©ɦ + ӄɛʟӄɛֆ + ӄɛʟӄɛֆ + ¢ɦɑɾɴɦɑ©ɦ + "ʀɛₘøѵɛ_ǟʟʟ_ʄɨʟɛֆ" + "ǟռɖ_ֆɦʊȶɖօառ" + "+" + "+" + "+" + "+" + "+";
}
"#
        ),
        (
            "behavioral_patterns.rs",
            r#"
fn suspicious_behavior() {
    let user_input = get_user_input();
    
    // Suspicious data flow - user input directly to system command
    system(&format!("ls {}", user_input));
    
    // Privilege escalation attempt
    if is_admin() {
        setuid(0);
        sudo_execute("dangerous_command");
    }
    
    // Network + execution combination
    let socket = create_socket();
    let command = receive_from_socket(socket);
    exec(&command);
}
"#
        ),
    ];
    
    println!("\n🔍 Testing ML-based vulnerability detection on sample code...\n");
    
    for (filename, source_code) in test_cases {
        println!("📁 Analyzing: {}", filename);
        println!("{}", "=".repeat(50));
        
        let source_file = SourceFile {
            path: Path::new(filename).to_path_buf(),
            content: source_code.to_string(),
            language: Language::Rust,
        };
        
        // Create a dummy AST (in real implementation, this would be parsed)
        let parsed_ast = create_dummy_ast();
        
        // Run ML-based analysis
        match ml_engine.analyze_with_ml(&source_file, &parsed_ast) {
            Ok(vulnerabilities) => {
                println!("🔍 Found {} ML-detected vulnerabilities:", vulnerabilities.len());
                
                for (i, vuln) in vulnerabilities.iter().enumerate() {
                    println!("\n{}. 🚨 {} ({})", i + 1, vuln.vulnerability_type, vuln.id);
                    println!("   Severity: {:?}", vuln.severity);
                    println!("   Category: {}", vuln.category);
                    println!("   Description: {}", vuln.description);
                    if let Some(cwe) = &vuln.cwe {
                        println!("   CWE: {}", cwe);
                    }
                }
                
                if vulnerabilities.is_empty() {
                    println!("   ✅ No vulnerabilities detected by ML models");
                }
            }
            Err(e) => println!("❌ Error during ML analysis: {}", e),
        }
        
        println!();
    }
    
    // Display enhanced ML metrics
    println!("📊 Enhanced ML Engine Metrics");
    println!("{}", "=".repeat(40));
    let enhanced_metrics = ml_engine.get_enhanced_metrics();
    println!("🎯 Anomaly Detection Accuracy: {:.2}%", enhanced_metrics.anomaly_detection_accuracy * 100.0);
    println!("📍 Contextual Analysis Coverage: {:.2}%", enhanced_metrics.contextual_analysis_coverage * 100.0);
    println!("🔍 Behavioral Pattern Detection: {:.2}%", enhanced_metrics.behavioral_pattern_detection * 100.0);
    println!("📏 Confidence Calibration Error: {:.2}%", enhanced_metrics.confidence_calibration_error * 100.0);
    println!("🎯 Pattern Matching Precision: {:.2}%", enhanced_metrics.pattern_matching_precision * 100.0);
    
    let basic_metrics = enhanced_metrics.basic_metrics;
    println!("\n📈 Basic Model Metrics:");
    println!("  Total Models: {}", basic_metrics.total_models);
    println!("  Languages Supported: {}", basic_metrics.languages_supported);
    println!("  Average Confidence: {:.2}", basic_metrics.average_confidence);
    println!("  False Positive Rate: {:.2}%", basic_metrics.false_positive_rate * 100.0);
    println!("  True Positive Rate: {:.2}%", basic_metrics.true_positive_rate * 100.0);
    
    println!("\n🎉 Enhanced ML-based vulnerability detection showcase completed!");
    println!("   This demonstrates advanced AI-powered security analysis with:");
    println!("   • Anomaly detection for unusual patterns");
    println!("   • Contextual analysis for security implications");
    println!("   • Behavioral pattern recognition");
    println!("   • Calibrated confidence scoring");
    println!("   • False positive reduction");
    
    Ok(())
}

// Dummy AST creation for demonstration
fn create_dummy_ast() -> devaic::parsers::ParsedAst {
    // In real implementation, this would be created by the AST parser
    devaic::parsers::ParsedAst {
        // This would contain the actual AST structure
    }
}

// Dummy functions for the test code
fn get_user_input() -> String { "user_input".to_string() }
fn system(_cmd: &str) {}
fn is_admin() -> bool { false }
fn setuid(_uid: u32) {}
fn sudo_execute(_cmd: &str) {}
fn create_socket() -> i32 { 0 }
fn receive_from_socket(_socket: i32) -> String { "command".to_string() }
fn exec(_cmd: &str) {}
fn eval(_code: &str) {}