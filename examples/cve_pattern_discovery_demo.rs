/// CVE Pattern Discovery Demonstration
/// 
/// This example demonstrates the complete automated pattern generation workflow:
/// 1. Discovering new vulnerability patterns from CVE databases
/// 2. Extracting high-quality patterns using AI/ML techniques
/// 3. Validating patterns for accuracy and performance
/// 4. Integrating validated patterns into the rule system
/// 
/// Usage: cargo run --example cve_pattern_discovery_demo

use devaic::{
    CVEPatternDiscovery, DiscoveryConfig, ExtractedPattern,
    PatternExtractionEngine, ExtractionConfig,
    PatternValidationSystem, ValidationConfig, ValidationResult,
    AutomatedRuleIntegration, IntegrationConfig, IntegrationStatus,
    Language, Severity,
};
use std::time::{Duration, SystemTime};
use tokio::time::sleep;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    // Initialize logging
    env_logger::Builder::from_env(env_logger::Env::default().default_filter_or("info")).init();
    
    println!("🔍 CVE Pattern Discovery Demonstration");
    println!("======================================");
    
    // Step 1: Configure CVE Pattern Discovery
    println!("\n📋 Step 1: Configuring CVE Pattern Discovery");
    let discovery_config = DiscoveryConfig {
        min_severity: 4.0,  // Medium severity and above
        max_age_days: 30,   // Last 30 days
        target_languages: vec![
            "java".to_string(),
            "python".to_string(),
            "javascript".to_string(),
            "c".to_string(),
            "cpp".to_string(),
        ],
        priority_categories: vec![
            "injection".to_string(),
            "xss".to_string(),
            "authentication".to_string(),
            "crypto".to_string(),
        ],
        rate_limit_requests_per_minute: 30,
        min_pattern_confidence: 0.7,
        max_patterns_per_run: 20,
    };
    
    println!("✓ CVE discovery configured:");
    println!("  - Minimum severity: {}", discovery_config.min_severity);
    println!("  - Target languages: {:?}", discovery_config.target_languages);
    println!("  - Max patterns per run: {}", discovery_config.max_patterns_per_run);
    
    // Step 2: Initialize CVE Pattern Discovery Engine
    println!("\n🤖 Step 2: Initializing CVE Pattern Discovery Engine");
    let mut discovery_engine = match CVEPatternDiscovery::new(discovery_config) {
        Ok(engine) => {
            println!("✓ CVE Pattern Discovery engine initialized successfully");
            engine
        }
        Err(e) => {
            println!("❌ Failed to initialize CVE Pattern Discovery: {}", e);
            println!("💡 Note: This demo requires internet access and optional API keys:");
            println!("   - NVD_API_KEY for NIST National Vulnerability Database");
            println!("   - GITHUB_TOKEN for GitHub Security Advisory Database");
            
            // Create a mock demonstration instead
            return demonstrate_with_mock_data().await;
        }
    };
    
    // Step 3: Discover New Patterns from CVE Data
    println!("\n🔎 Step 3: Discovering New Vulnerability Patterns");
    println!("Analyzing recent CVEs for new vulnerability patterns...");
    
    let discovered_patterns = match discovery_engine.discover_patterns().await {
        Ok(patterns) => {
            println!("✓ Discovered {} new vulnerability patterns", patterns.len());
            patterns
        }
        Err(e) => {
            println!("⚠️  Pattern discovery encountered issues: {}", e);
            println!("📝 Using simulated patterns for demonstration");
            create_simulated_patterns()
        }
    };
    
    // Display discovered patterns
    if !discovered_patterns.is_empty() {
        println!("\n📊 Discovered Patterns Summary:");
        for (i, pattern) in discovered_patterns.iter().enumerate() {
            println!("  {}. ID: {} | Languages: {:?} | Confidence: {:.2}", 
                i + 1, pattern.id, pattern.languages, 
                pattern.patterns.get(0).map(|p| p.confidence.unwrap_or(0.0)).unwrap_or(0.0));
        }
    }
    
    // Step 4: Configure Pattern Extraction Engine
    println!("\n⚙️  Step 4: Configuring Advanced Pattern Extraction");
    let extraction_config = ExtractionConfig {
        min_confidence: 0.6,
        max_patterns_per_cve: 5,
        enable_advanced_nlp: true,
        enable_code_analysis: true,
        enable_semantic_analysis: true,
        max_pattern_complexity: 100,
        target_languages: vec![
            "java".to_string(),
            "python".to_string(),
            "javascript".to_string(),
        ],
    };
    
    let pattern_extractor = PatternExtractionEngine::new(extraction_config)?;
    println!("✓ Pattern extraction engine configured with advanced NLP and code analysis");
    
    // Step 5: Configure Pattern Validation System
    println!("\n🛡️  Step 5: Setting Up Pattern Validation System");
    let validation_config = ValidationConfig {
        min_quality_score: 0.7,
        max_false_positive_rate: 0.1,
        max_performance_impact_ms: 10.0,
        min_coverage: 0.6,
        enable_comprehensive_testing: true,
        enable_ml_validation: true,
        test_corpus_size: 1000,
        validation_timeout_secs: 120,
        history_retention_days: 90,
    };
    
    let validation_system = PatternValidationSystem::new(validation_config)?;
    println!("✓ Validation system configured with comprehensive testing enabled");
    
    // Step 6: Validate Discovered Patterns
    println!("\n✅ Step 6: Validating Discovered Patterns");
    println!("Running comprehensive validation including:");
    println!("  - False positive rate estimation");
    println!("  - Performance impact assessment");
    println!("  - Coverage analysis");
    println!("  - Quality scoring");
    
    // Convert SecurityPatterns to ExtractedPatterns for validation
    let extracted_patterns = convert_security_patterns_to_extracted(&discovered_patterns);
    
    let validation_results = validation_system.validate_patterns(&extracted_patterns).await?;
    
    println!("✓ Validation completed for {} patterns", validation_results.len());
    
    // Display validation results
    let mut passed_validation = 0;
    let mut total_quality_score = 0.0;
    let mut total_fp_rate = 0.0;
    
    println!("\n📈 Validation Results Summary:");
    for result in &validation_results {
        if result.passed_validation {
            passed_validation += 1;
        }
        total_quality_score += result.overall_score;
        total_fp_rate += result.false_positive_analysis.estimated_fp_rate;
        
        let status = if result.passed_validation { "✅ PASS" } else { "❌ FAIL" };
        println!("  Pattern {}: {} | Quality: {:.3} | FP Rate: {:.1}% | Performance: {:.1}ms",
            result.pattern_id,
            status,
            result.overall_score,
            result.false_positive_analysis.estimated_fp_rate * 100.0,
            result.performance_metrics.average_execution_time_ms
        );
    }
    
    if !validation_results.is_empty() {
        let avg_quality = total_quality_score / validation_results.len() as f32;
        let avg_fp_rate = total_fp_rate / validation_results.len() as f32;
        
        println!("\n📊 Overall Validation Statistics:");
        println!("  - Patterns passed: {}/{}", passed_validation, validation_results.len());
        println!("  - Average quality score: {:.3}", avg_quality);
        println!("  - Average false positive rate: {:.1}%", avg_fp_rate * 100.0);
        println!("  - Validation success rate: {:.1}%", 
            (passed_validation as f32 / validation_results.len() as f32) * 100.0);
    }
    
    // Step 7: Configure Automated Rule Integration
    println!("\n🔧 Step 7: Configuring Automated Rule Integration");
    let integration_config = IntegrationConfig {
        auto_deploy_enabled: false, // Safety first - require manual approval
        min_validation_score: 0.8,
        enable_performance_monitoring: true,
        enable_adaptive_updates: false,
        require_manual_approval: true,
        max_patterns_per_batch: 5,
        monitoring_interval_secs: 60,
        performance_degradation_threshold: 0.2,
        fp_rate_threshold: 0.1,
        rule_retention_days: 90,
        enable_rule_versioning: true,
        rollback_timeout_minutes: 10,
    };
    
    let integration_system = AutomatedRuleIntegration::new(integration_config)?;
    println!("✓ Integration system configured with manual approval workflow");
    
    // Step 8: Integrate Validated Patterns
    println!("\n🚀 Step 8: Integrating High-Quality Patterns into Rule System");
    
    // Prepare patterns and validation results for integration
    let integration_data: Vec<_> = extracted_patterns.into_iter()
        .zip(validation_results.into_iter())
        .filter(|(_, validation)| validation.passed_validation)
        .collect();
    
    if integration_data.is_empty() {
        println!("⚠️  No patterns passed validation criteria for integration");
    } else {
        println!("Integrating {} validated patterns...", integration_data.len());
        
        let integration_summary = integration_system.integrate_patterns(integration_data).await?;
        
        println!("✓ Integration completed:");
        println!("  - Deployed automatically: {}", integration_summary.deployed_count);
        println!("  - Queued for approval: {}", integration_summary.queued_count);
        println!("  - Skipped: {}", integration_summary.skipped_count);
        println!("  - Failed: {}", integration_summary.failed_count);
        
        if integration_summary.failed_count > 0 {
            println!("\n❌ Integration Errors:");
            for error in &integration_summary.error_messages {
                println!("  - {}", error);
            }
        }
        
        // Step 9: Monitor Integration Status
        println!("\n📊 Step 9: Monitoring Integration Status");
        sleep(Duration::from_secs(2)).await; // Brief pause for demo
        
        let status = integration_system.get_integration_status().await?;
        
        println!("Current Integration Status:");
        println!("  - Total deployed rules: {}", status.total_deployed_rules);
        println!("  - Active rules: {}", status.active_rules);
        println!("  - Pending deployments: {}", status.pending_deployments);
        println!("  - System health: {:?}", status.health_metrics.health_status);
        println!("  - Average performance: {:.2}", status.performance_stats.average_rule_performance);
        
        if status.performance_stats.total_vulnerabilities_detected > 0 {
            println!("  - Vulnerabilities detected: {}", status.performance_stats.total_vulnerabilities_detected);
            println!("  - False positive rate: {:.1}%", status.performance_stats.false_positive_rate * 100.0);
        }
    }
    
    // Step 10: Demonstration Summary
    println!("\n🎉 CVE Pattern Discovery Demonstration Complete!");
    println!("=================================================");
    println!();
    println!("✅ Successfully demonstrated:");
    println!("  1. CVE data collection from multiple sources");
    println!("  2. AI-powered pattern extraction and analysis");
    println!("  3. Comprehensive pattern validation and scoring");
    println!("  4. Automated integration with safety controls");
    println!("  5. Real-time monitoring and performance tracking");
    println!();
    println!("🔮 Benefits of Automated Pattern Discovery:");
    println!("  • Faster response to new vulnerability disclosures");
    println!("  • Reduced manual effort in rule creation");
    println!("  • Improved detection accuracy through ML validation");
    println!("  • Continuous learning and adaptation");
    println!("  • Comprehensive quality assurance");
    println!();
    println!("🛡️  Security & Safety Features:");
    println!("  • Manual approval workflow for high-risk changes");
    println!("  • Comprehensive validation before deployment");
    println!("  • Real-time performance monitoring");
    println!("  • Automated rollback on performance degradation");
    println!("  • Audit trail for all pattern changes");
    
    Ok(())
}

/// Demonstrate functionality with mock data when CVE APIs are unavailable
async fn demonstrate_with_mock_data() -> Result<(), Box<dyn std::error::Error>> {
    println!("\n🎭 Running Mock Demonstration");
    println!("============================");
    
    // Create simulated discovery results
    let mock_patterns = create_simulated_patterns();
    println!("✓ Created {} simulated vulnerability patterns", mock_patterns.len());
    
    // Show pattern analysis
    println!("\n📊 Mock Pattern Analysis:");
    for (i, pattern) in mock_patterns.iter().enumerate() {
        println!("  {}. {} ({})", i + 1, pattern.name, pattern.category);
        println!("     Languages: {:?} | Severity: {:?}", pattern.languages, pattern.severity);
        if let Some(cwe) = &pattern.cwe {
            println!("     CWE: {} | Patterns: {}", cwe, pattern.patterns.len());
        }
    }
    
    // Simulate validation results
    println!("\n✅ Mock Validation Results:");
    println!("  - 3/4 patterns passed validation");
    println!("  - Average quality score: 0.847");
    println!("  - Average false positive rate: 4.2%");
    println!("  - Performance impact: < 5ms per pattern");
    
    // Simulate integration
    println!("\n🚀 Mock Integration Results:");
    println!("  - 2 patterns queued for manual approval");
    println!("  - 1 pattern auto-deployed to staging");
    println!("  - 0 integration failures");
    
    println!("\n💡 To run with real CVE data, configure API keys:");
    println!("   export NVD_API_KEY=your_nvd_api_key");
    println!("   export GITHUB_TOKEN=your_github_token");
    
    Ok(())
}

/// Create simulated security patterns for demonstration
fn create_simulated_patterns() -> Vec<devaic::pattern_loader::SecurityPattern> {
    use devaic::pattern_loader::{SecurityPattern, RegexPattern};
    use std::collections::HashMap;
    
    vec![
        SecurityPattern {
            id: "auto-sql-injection-001".to_string(),
            name: "SQL Injection via String Concatenation".to_string(),
            description: "Detects SQL injection vulnerabilities through string concatenation".to_string(),
            severity: Severity::High,
            category: "injection".to_string(),
            languages: vec!["java".to_string(), "python".to_string(), "javascript".to_string()],
            patterns: vec![
                RegexPattern {
                    regex: r"(?i)(select|insert|update|delete)\s+.*\+.*['\"][^'\"]*['\"]".to_string(),
                    flags: None,
                    description: Some("String concatenation in SQL queries".to_string()),
                    confidence: Some(0.85),
                }
            ],
            fix_suggestion: Some("Use parameterized queries or prepared statements".to_string()),
            cwe: Some("CWE-89".to_string()),
            owasp: Some("A03:2021 - Injection".to_string()),
            references: Some(vec!["CVE-2024-12345".to_string()]),
            metadata: Some({
                let mut meta = HashMap::new();
                meta.insert("source".to_string(), "automated-cve-analysis".to_string());
                meta.insert("confidence".to_string(), "0.85".to_string());
                meta
            }),
        },
        SecurityPattern {
            id: "auto-xss-dom-001".to_string(),
            name: "DOM-based XSS via innerHTML".to_string(),
            description: "Detects DOM-based XSS through innerHTML manipulation".to_string(),
            severity: Severity::High,
            category: "xss".to_string(),
            languages: vec!["javascript".to_string(), "typescript".to_string()],
            patterns: vec![
                RegexPattern {
                    regex: r"(?i)\.innerHTML\s*=\s*.*\+".to_string(),
                    flags: None,
                    description: Some("Direct innerHTML assignment with concatenation".to_string()),
                    confidence: Some(0.78),
                }
            ],
            fix_suggestion: Some("Use textContent or properly sanitize HTML content".to_string()),
            cwe: Some("CWE-79".to_string()),
            owasp: Some("A03:2021 - Injection".to_string()),
            references: Some(vec!["CVE-2024-12346".to_string()]),
            metadata: Some({
                let mut meta = HashMap::new();
                meta.insert("source".to_string(), "automated-cve-analysis".to_string());
                meta.insert("confidence".to_string(), "0.78".to_string());
                meta
            }),
        },
        SecurityPattern {
            id: "auto-auth-bypass-001".to_string(),
            name: "Authentication Bypass via Boolean Logic".to_string(),
            description: "Detects potential authentication bypass through boolean manipulation".to_string(),
            severity: Severity::Critical,
            category: "authentication".to_string(),
            languages: vec!["python".to_string(), "java".to_string(), "javascript".to_string()],
            patterns: vec![
                RegexPattern {
                    regex: r"(?i)(auth|login|verify).*==.*true".to_string(),
                    flags: None,
                    description: Some("Boolean authentication check".to_string()),
                    confidence: Some(0.72),
                }
            ],
            fix_suggestion: Some("Implement proper authentication validation logic".to_string()),
            cwe: Some("CWE-287".to_string()),
            owasp: Some("A07:2021 - Identification and Authentication Failures".to_string()),
            references: Some(vec!["CVE-2024-12347".to_string()]),
            metadata: Some({
                let mut meta = HashMap::new();
                meta.insert("source".to_string(), "automated-cve-analysis".to_string());
                meta.insert("confidence".to_string(), "0.72".to_string());
                meta
            }),
        },
        SecurityPattern {
            id: "auto-crypto-weak-001".to_string(),
            name: "Weak Cryptographic Algorithm Usage".to_string(),
            description: "Detects usage of weak cryptographic algorithms".to_string(),
            severity: Severity::Medium,
            category: "crypto".to_string(),
            languages: vec!["java".to_string(), "python".to_string(), "c".to_string()],
            patterns: vec![
                RegexPattern {
                    regex: r"(?i)(md5|sha1|des|rc4)".to_string(),
                    flags: None,
                    description: Some("Weak cryptographic algorithms".to_string()),
                    confidence: Some(0.65),
                }
            ],
            fix_suggestion: Some("Use stronger cryptographic algorithms like SHA-256, AES".to_string()),
            cwe: Some("CWE-327".to_string()),
            owasp: Some("A02:2021 - Cryptographic Failures".to_string()),
            references: Some(vec!["CVE-2024-12348".to_string()]),
            metadata: Some({
                let mut meta = HashMap::new();
                meta.insert("source".to_string(), "automated-cve-analysis".to_string());
                meta.insert("confidence".to_string(), "0.65".to_string());
                meta
            }),
        },
    ]
}

/// Convert SecurityPatterns to ExtractedPatterns for validation
fn convert_security_patterns_to_extracted(
    patterns: &[devaic::pattern_loader::SecurityPattern]
) -> Vec<ExtractedPattern> {
    use devaic::cve_pattern_discovery::{ExtractedPattern, VulnerabilityType};
    
    patterns.iter().map(|pattern| {
        let vulnerability_type = match pattern.category.as_str() {
            "injection" => VulnerabilityType::Injection,
            "xss" => VulnerabilityType::CrossSiteScripting,
            "authentication" => VulnerabilityType::BrokenAuthentication,
            "crypto" => VulnerabilityType::CryptographicFailure,
            _ => VulnerabilityType::Other(pattern.category.clone()),
        };
        
        ExtractedPattern {
            source_cve: pattern.metadata.as_ref()
                .and_then(|m| m.get("source"))
                .unwrap_or(&pattern.id)
                .clone(),
            pattern_type: vulnerability_type,
            extracted_regex: pattern.patterns.iter()
                .map(|p| p.regex.clone())
                .collect(),
            confidence_score: pattern.patterns.get(0)
                .and_then(|p| p.confidence)
                .unwrap_or(0.7),
            supporting_evidence: pattern.references.clone().unwrap_or_default(),
            affected_languages: pattern.languages.clone(),
            severity_estimate: pattern.severity.clone(),
            description: pattern.description.clone(),
            mitigation_advice: pattern.fix_suggestion.clone().unwrap_or_default(),
        }
    }).collect()
}