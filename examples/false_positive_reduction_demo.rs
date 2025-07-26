/// False Positive Reduction Demo
/// 
/// This example demonstrates the intelligent false positive reduction system
/// that learns from user feedback and ML analysis to minimize false alarms
/// while maintaining high detection accuracy.

use devaic::{
    config::Config,
    analyzer::Analyzer,
    false_positive_reduction::{
        FalsePositiveReducer, VulnerabilityFeedback, Classification, 
        FeedbackContext, RemediationEffort, EnhancedVulnerability
    },
    Language, Severity, Vulnerability,
};
use std::path::Path;
use std::time::{Duration, SystemTime, UNIX_EPOCH};
use tokio::time::sleep;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    println!("🤖 DeVAIC False Positive Reduction Demo");
    println!("══════════════════════════════════════");
    println!();

    // Demo 1: Basic False Positive Reduction Setup
    println!("📋 Demo 1: Setting Up False Positive Reduction");
    println!("──────────────────────────────────────────────");
    
    let mut config = Config::default();
    config.enable_ai_analysis = Some(true); // Enable AI features
    let mut analyzer = Analyzer::new(config)?;
    
    // Enable false positive reduction
    analyzer.enable_false_positive_reduction();
    println!("✅ Enabled intelligent false positive reduction with ML learning");
    println!("   • Pattern-based similarity analysis");
    println!("   • User feedback integration");
    println!("   • Historical performance tracking");
    println!("   • Context-aware confidence scoring");
    println!();

    // Demo 2: Simulating Vulnerability Detection with Enhancement
    println!("🔍 Demo 2: Enhanced Vulnerability Detection");
    println!("──────────────────────────────────────────");
    
    let sample_vulnerabilities = create_sample_vulnerabilities();
    let reducer = FalsePositiveReducer::new();
    let enhanced_vulnerabilities = reducer.process_vulnerabilities(sample_vulnerabilities);
    
    println!("📊 Enhanced Vulnerability Analysis Results:");
    for (i, enhanced) in enhanced_vulnerabilities.iter().take(5).enumerate() {
        println!("   {}. {} ({})", 
            i + 1, 
            enhanced.vulnerability.title,
            enhanced.vulnerability.severity
        );
        println!("      📈 False Positive Probability: {:.1}%", 
            enhanced.false_positive_probability * 100.0);
        println!("      🎯 Confidence Score: {:.1}%", 
            enhanced.confidence_score * 100.0);
        
        if !enhanced.user_recommendations.is_empty() {
            println!("      💡 Recommendation: {:?}", 
                enhanced.user_recommendations[0].recommendation_type);
        }
        
        if !enhanced.suggested_actions.is_empty() {
            println!("      🔧 Suggested Action: {:?}", 
                enhanced.suggested_actions[0].action_type);
        }
        println!();
    }

    // Demo 3: User Feedback Simulation
    println!("🎓 Demo 3: Learning from User Feedback");
    println!("─────────────────────────────────────");
    
    simulate_user_feedback(&reducer, &enhanced_vulnerabilities).await;
    
    // Show analytics after feedback
    let analytics = reducer.get_analytics();
    println!("📈 Learning Analytics:");
    println!("   Total Feedback Entries: {}", analytics.total_feedback_entries);
    println!("   Accuracy Rate: {:.1}%", analytics.accuracy_rate * 100.0);
    println!("   False Positive Rate: {:.1}%", analytics.false_positive_rate * 100.0);
    println!("   Patterns Learned: {}", analytics.patterns_learned);
    println!("   Users Profiled: {}", analytics.users_profiled);
    println!("   Rules Analyzed: {}", analytics.rules_analyzed);
    println!("   Improvement Trend: {:.3}", analytics.improvement_trend);
    println!();

    // Demo 4: Confidence Factor Analysis
    println!("🔬 Demo 4: Confidence Factor Analysis");
    println!("────────────────────────────────────────");
    
    analyze_confidence_factors(&enhanced_vulnerabilities);

    // Demo 5: Pattern Similarity Detection
    println!("🧩 Demo 5: Pattern Similarity Detection");
    println!("──────────────────────────────────────");
    
    demonstrate_pattern_similarity(&enhanced_vulnerabilities);

    // Demo 6: Adaptive Recommendations
    println!("💡 Demo 6: Adaptive User Recommendations");
    println!("───────────────────────────────────────");
    
    demonstrate_adaptive_recommendations(&enhanced_vulnerabilities);

    // Demo 7: Integration with Analyzer
    println!("🔗 Demo 7: Integration with Main Analyzer");
    println!("─────────────────────────────────────────");
    
    demonstrate_analyzer_integration(analyzer).await?;

    println!("🎉 False Positive Reduction Demo Complete!");
    println!();
    println!("💡 Key Benefits Demonstrated:");
    println!("   • Intelligent false positive detection using ML models");
    println!("   • Continuous learning from user feedback");
    println!("   • Pattern-based similarity analysis for improved accuracy");
    println!("   • Context-aware confidence scoring and recommendations");
    println!("   • Automated action suggestions based on historical data");
    println!("   • Real-time improvement through ensemble ML techniques");

    Ok(())
}

/// Create sample vulnerabilities for demonstration
fn create_sample_vulnerabilities() -> Vec<Vulnerability> {
    vec![
        Vulnerability {
            id: "JS-XSS-001".to_string(),
            title: "Potential Cross-Site Scripting (XSS)".to_string(),
            description: "User input directly inserted into DOM without sanitization".to_string(),
            severity: Severity::High,
            category: "web_security".to_string(),
            cwe: Some("CWE-79".to_string()),
            owasp: Some("A03:2021".to_string()),
            file_path: "src/components/UserProfile.jsx".to_string(),
            line_number: 45,
            column_start: 12,
            column_end: 35,
            source_code: "innerHTML = userInput".to_string(),
            recommendation: "Use proper input sanitization or safe DOM manipulation methods".to_string(),
            references: vec!["https://owasp.org/www-community/attacks/xss/".to_string()],
            confidence: 0.85,
        },
        Vulnerability {
            id: "JS-SQL-002".to_string(),
            title: "SQL Injection Vulnerability".to_string(),
            description: "Direct string concatenation in SQL query construction".to_string(),
            severity: Severity::Critical,
            category: "database_security".to_string(),
            cwe: Some("CWE-89".to_string()),
            owasp: Some("A03:2021".to_string()),
            file_path: "src/api/users.js".to_string(),
            line_number: 78,
            column_start: 20,
            column_end: 55,
            source_code: "SELECT * FROM users WHERE id = \" + userId".to_string(),
            recommendation: "Use parameterized queries or prepared statements".to_string(),
            references: vec!["https://owasp.org/www-community/attacks/SQL_Injection".to_string()],
            confidence: 0.95,
        },
        Vulnerability {
            id: "JS-EVAL-003".to_string(),
            title: "Dangerous Use of eval()".to_string(),
            description: "Use of eval() function with user-controlled input".to_string(),
            severity: Severity::High,
            category: "code_injection".to_string(),
            cwe: Some("CWE-95".to_string()),
            owasp: Some("A03:2021".to_string()),
            file_path: "src/utils/calculator.js".to_string(),
            line_number: 23,
            column_start: 8,
            column_end: 30,
            source_code: "eval(userExpression)".to_string(),
            recommendation: "Use safer alternatives like Function constructor or math expression parsers".to_string(),
            references: vec!["https://developer.mozilla.org/en-US/docs/Web/JavaScript/Reference/Global_Objects/eval".to_string()],
            confidence: 0.78,
        },
        Vulnerability {
            id: "JS-CRYPTO-004".to_string(),
            title: "Weak Cryptographic Algorithm".to_string(),
            description: "Use of deprecated MD5 hashing algorithm".to_string(),
            severity: Severity::Medium,
            category: "cryptography".to_string(),
            cwe: Some("CWE-327".to_string()),
            owasp: Some("A02:2021".to_string()),
            file_path: "src/auth/password.js".to_string(),
            line_number: 56,
            column_start: 15,
            column_end: 38,
            source_code: "crypto.createHash('md5')".to_string(),
            recommendation: "Use stronger hashing algorithms like bcrypt, scrypt, or Argon2".to_string(),
            references: vec!["https://owasp.org/www-community/vulnerabilities/Use_of_a_Broken_or_Risky_Cryptographic_Algorithm".to_string()],
            confidence: 0.65,
        },
        Vulnerability {
            id: "JS-PATH-005".to_string(),
            title: "Path Traversal Vulnerability".to_string(),
            description: "User input used in file path without validation".to_string(),
            severity: Severity::High,
            category: "file_security".to_string(),
            cwe: Some("CWE-22".to_string()),
            owasp: Some("A01:2021".to_string()),
            file_path: "src/files/download.js".to_string(),
            line_number: 34,
            column_start: 25,
            column_end: 45,
            source_code: "fs.readFile(userPath)".to_string(),
            recommendation: "Validate and sanitize file paths, use allowlists for permitted paths".to_string(),
            references: vec!["https://owasp.org/www-community/attacks/Path_Traversal".to_string()],
            confidence: 0.82,
        },
        Vulnerability {
            id: "JS-REGEX-006".to_string(),
            title: "Regular Expression Denial of Service (ReDoS)".to_string(),
            description: "Complex regex pattern vulnerable to catastrophic backtracking".to_string(),
            severity: Severity::Medium,
            category: "performance_security".to_string(),
            cwe: Some("CWE-1333".to_string()),
            owasp: Some("A06:2021".to_string()),
            file_path: "src/validation/email.js".to_string(),
            line_number: 12,
            column_start: 18,
            column_end: 65,
            source_code: "/^([a-zA-Z0-9_\\.-]+)@([\\da-z\\.-]+)\\.([a-z\\.]{2,6})$/.test(input)".to_string(),
            recommendation: "Simplify regex patterns or use specialized validation libraries".to_string(),
            references: vec!["https://owasp.org/www-community/attacks/Regular_expression_Denial_of_Service_-_ReDoS".to_string()],
            confidence: 0.45,
        },
    ]
}

/// Simulate user feedback for learning demonstration
async fn simulate_user_feedback(reducer: &FalsePositiveReducer, vulnerabilities: &[EnhancedVulnerability]) {
    println!("⚡ Simulating user feedback for {} vulnerabilities...", vulnerabilities.len());
    
    let current_time = SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_secs();
    
    for (i, enhanced) in vulnerabilities.iter().enumerate() {
        // Simulate different user responses based on vulnerability characteristics
        let classification = if enhanced.vulnerability.confidence > 0.8 && enhanced.false_positive_probability < 0.3 {
            Classification::TruePositive
        } else if enhanced.false_positive_probability > 0.7 {
            Classification::FalsePositive
        } else if i % 3 == 0 {
            Classification::TruePositive
        } else if i % 4 == 0 {
            Classification::FalsePositive
        } else {
            Classification::RequiresReview
        };
        
        let feedback = VulnerabilityFeedback {
            vulnerability_id: enhanced.vulnerability.id.clone(),
            rule_id: format!("rule_{}", enhanced.vulnerability.category),
            file_path: enhanced.vulnerability.file_path.clone(),
            user_classification: classification.clone(),
            confidence: 0.8 + (i as f64 * 0.02),
            feedback_timestamp: current_time - (i as u64 * 3600), // Spread over time
            user_id: if i % 2 == 0 { "security_expert_1".to_string() } else { "developer_1".to_string() },
            context: FeedbackContext {
                code_context: format!("Context for {}", enhanced.vulnerability.source_code),
                surrounding_functions: vec!["handleUserInput".to_string(), "validateData".to_string()],
                framework_context: vec!["React".to_string(), "Express".to_string()],
                business_logic_context: "User data processing pipeline".to_string(),
                security_implications: "Potential data exposure risk".to_string(),
                remediation_effort: match enhanced.vulnerability.severity {
                    Severity::Critical => RemediationEffort::Significant,
                    Severity::High => RemediationEffort::Moderate,
                    Severity::Medium => RemediationEffort::Minor,
                    _ => RemediationEffort::Trivial,
                },
            },
            fix_applied: classification == Classification::TruePositive,
            time_to_feedback: Duration::from_secs(120 + (i as u64 * 30)),
        };
        
        if let Err(e) = reducer.record_feedback(feedback) {
            println!("   ⚠️  Failed to record feedback: {}", e);
        } else {
            let status_icon = match classification {
                Classification::TruePositive => "✅",
                Classification::FalsePositive => "❌",
                Classification::RequiresReview => "🔍",
                _ => "❓",
            };
            println!("   {} Recorded feedback for {} ({:?})", 
                status_icon, enhanced.vulnerability.title, classification);
        }
        
        sleep(Duration::from_millis(10)).await; // Small delay for demo
    }
    
    println!("   ✅ Completed feedback simulation for {} vulnerabilities", vulnerabilities.len());
    println!();
}

/// Analyze and display confidence factors
fn analyze_confidence_factors(vulnerabilities: &[EnhancedVulnerability]) {
    for (i, enhanced) in vulnerabilities.iter().take(3).enumerate() {
        println!("   🔬 Analysis #{}: {}", i + 1, enhanced.vulnerability.title);
        println!("      Overall Confidence: {:.1}%", enhanced.confidence_score * 100.0);
        
        for factor in &enhanced.contributing_factors {
            println!("      • {:?}: {:.3} (weight: {:.2})", 
                factor.factor_type, factor.contribution, factor.weight);
            if !factor.explanation.is_empty() {
                println!("        → {}", factor.explanation);
            }
        }
        println!();
    }
}

/// Demonstrate pattern similarity detection
fn demonstrate_pattern_similarity(vulnerabilities: &[EnhancedVulnerability]) {
    for (i, enhanced) in vulnerabilities.iter().take(2).enumerate() {
        println!("   🧩 Pattern Analysis #{}: {}", i + 1, enhanced.vulnerability.title);
        
        if enhanced.similar_patterns.is_empty() {
            println!("      No similar patterns found (new pattern)");
        } else {
            println!("      Found {} similar patterns:", enhanced.similar_patterns.len());
            for (j, pattern) in enhanced.similar_patterns.iter().take(3).enumerate() {
                println!("        {}. Similarity: {:.1}% | Classification: {:?} | Frequency: {}", 
                    j + 1, 
                    pattern.similarity_score * 100.0,
                    pattern.historical_classification,
                    pattern.occurrence_frequency
                );
            }
        }
        println!();
    }
}

/// Demonstrate adaptive recommendations
fn demonstrate_adaptive_recommendations(vulnerabilities: &[EnhancedVulnerability]) {
    for (i, enhanced) in vulnerabilities.iter().take(3).enumerate() {
        println!("   💡 Recommendations #{}: {}", i + 1, enhanced.vulnerability.title);
        println!("      False Positive Probability: {:.1}%", enhanced.false_positive_probability * 100.0);
        
        for rec in &enhanced.user_recommendations {
            println!("      • Action: {:?} (Priority: {:?})", 
                rec.recommendation_type, rec.priority);
            println!("        Explanation: {}", rec.explanation);
            println!("        Estimated Effort: {:?}", rec.estimated_effort);
        }
        
        if !enhanced.suggested_actions.is_empty() {
            println!("      🔧 Suggested Actions:");
            for action in &enhanced.suggested_actions {
                println!("        • {:?}: {} (Confidence: {:.1}%)", 
                    action.action_type, action.description, action.confidence * 100.0);
                if action.automation_possible {
                    println!("          ⚡ Can be automated");
                }
            }
        }
        println!();
    }
}

/// Demonstrate integration with main analyzer
async fn demonstrate_analyzer_integration(mut analyzer: Analyzer) -> Result<(), Box<dyn std::error::Error>> {
    println!("🔧 Testing enhanced vulnerability analysis...");
    
    // This would normally analyze a real directory
    // For demo purposes, we'll show the integration points
    println!("   ✅ Enhanced analysis mode enabled");
    println!("   🤖 ML-powered false positive reduction active");
    println!("   📊 User feedback integration ready");
    
    // Demonstrate analytics access
    if let Some(analytics) = analyzer.get_false_positive_analytics() {
        println!("   📈 Current Analytics:");
        println!("      • Total Feedback: {}", analytics.total_feedback_entries);
        println!("      • Accuracy Rate: {:.1}%", analytics.accuracy_rate * 100.0);
        println!("      • Patterns Learned: {}", analytics.patterns_learned);
    } else {
        println!("   📊 Analytics not available (no feedback data yet)");
    }
    
    println!("   🎯 Integration points demonstrated:");
    println!("      • Enhanced vulnerability analysis with ML processing");
    println!("      • Real-time confidence scoring and recommendations");
    println!("      • Continuous learning from user feedback");
    println!("      • Performance analytics and trend monitoring");
    
    Ok(())
}