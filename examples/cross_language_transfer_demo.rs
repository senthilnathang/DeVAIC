/// Cross-Language Vulnerability Transfer Demonstration
/// 
/// This example demonstrates the complete cross-language vulnerability transfer workflow:
/// 1. Creating vulnerability patterns in one language
/// 2. Transferring patterns to multiple target languages
/// 3. Calculating confidence scores and similarity analysis
/// 4. Validating transferred patterns
/// 5. Analyzing transfer effectiveness
/// 
/// Usage: cargo run --example cross_language_transfer_demo

use devaic::{
    CrossLanguageTransfer, TransferConfig, TransferContext, TransferConfidenceScore,
    PatternSimilarityAnalysis, TransferViability,
    Language, Severity,
    pattern_loader::{SecurityPattern, RegexPattern},
};
use std::collections::HashMap;
use std::time::SystemTime;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    // Initialize logging
    env_logger::Builder::from_env(env_logger::Env::default().default_filter_or("info")).init();
    
    println!("🔄 Cross-Language Vulnerability Transfer Demonstration");
    println!("====================================================");
    
    // Step 1: Configure Cross-Language Transfer System
    println!("\n📋 Step 1: Configuring Cross-Language Transfer System");
    let transfer_config = TransferConfig {
        min_transfer_confidence: 0.6,
        enabled_languages: vec![
            Language::Java,
            Language::Python,
            Language::Javascript,
            Language::C,
            Language::Cpp,
            Language::Go,
            Language::Rust,
        ],
        max_transfers_per_type: 5,
        enable_semantic_analysis: true,
        enable_syntax_transfer: true,
        enable_behavioral_transfer: true,
        min_semantic_similarity: 0.5,
        enable_transfer_validation: true,
        transfer_learning_rate: 0.1,
        auto_transfer_threshold: 0.8,
    };
    
    println!("✓ Transfer system configured:");
    println!("  - Minimum confidence: {}", transfer_config.min_transfer_confidence);
    println!("  - Enabled languages: {} languages", transfer_config.enabled_languages.len());
    println!("  - Semantic analysis: {}", transfer_config.enable_semantic_analysis);
    println!("  - Transfer validation: {}", transfer_config.enable_transfer_validation);
    
    // Step 2: Initialize Cross-Language Transfer Engine
    println!("\n🔧 Step 2: Initializing Cross-Language Transfer Engine");
    let transfer_engine = CrossLanguageTransfer::new(transfer_config)?;
    println!("✓ Cross-language transfer engine initialized successfully");
    
    // Step 3: Create Source Vulnerability Patterns
    println!("\n🎯 Step 3: Creating Source Vulnerability Patterns");
    let source_patterns = create_demonstration_patterns();
    
    println!("✓ Created {} source vulnerability patterns:", source_patterns.len());
    for (i, pattern) in source_patterns.iter().enumerate() {
        println!("  {}. {} (Category: {}, Severity: {:?})", 
            i + 1, pattern.name, pattern.category, pattern.severity);
    }
    
    // Step 4: Perform Cross-Language Transfers
    println!("\n🚀 Step 4: Performing Cross-Language Pattern Transfers");
    let target_languages = vec![
        Language::Python,
        Language::Javascript, 
        Language::Java,
        Language::Go,
        Language::Rust,
    ];
    
    println!("Transferring patterns to {} target languages...", target_languages.len());
    let transfer_results = transfer_engine.transfer_patterns(&source_patterns, &target_languages).await?;
    
    println!("✓ Transfer completed: {} results generated", transfer_results.len());
    
    // Step 5: Analyze Transfer Results
    println!("\n📊 Step 5: Analyzing Transfer Results");
    for (i, result) in transfer_results.iter().enumerate() {
        println!("\n  Pattern {}: {}", i + 1, result.source_pattern.pattern_id);
        println!("    Source Language: {:?}", result.source_pattern.source_language);
        println!("    Target Patterns: {}", result.target_patterns.len());
        println!("    Success Rate: {:.1}%", 
            (result.transfer_stats.successful_transfers as f32 / result.transfer_stats.total_transfers_attempted as f32) * 100.0);
        println!("    Average Confidence: {:.3}", result.transfer_stats.average_confidence);
        
        // Show target pattern details
        for target in &result.target_patterns {
            println!("      → {:?}: {:.1}% confidence", 
                target.target_language, target.transfer_confidence * 100.0);
        }
    }
    
    // Step 6: Demonstrate Confidence Scoring
    println!("\n🎯 Step 6: Demonstrating Confidence Scoring");
    if let Some(first_pattern) = source_patterns.first() {
        let transfer_context = TransferContext {
            validation_result: None,
            transfer_parameters: HashMap::new(),
            metadata: HashMap::new(),
        };
        
        for target_lang in &[Language::Python, Language::Java, Language::Go] {
            println!("\n  Analyzing transfer confidence: {} → {:?}", first_pattern.id, target_lang);
            
            let confidence_score = transfer_engine.calculate_transfer_confidence(
                first_pattern,
                *target_lang,
                &transfer_context,
            ).await?;
            
            print_confidence_analysis(&confidence_score, first_pattern, *target_lang);
        }
    }
    
    // Step 7: Demonstrate Pattern Similarity Analysis
    println!("\n🔍 Step 7: Demonstrating Pattern Similarity Analysis");
    if source_patterns.len() >= 2 {
        println!("Comparing similarity between patterns...");
        
        let similarity_analysis = transfer_engine.analyze_pattern_similarity(
            &source_patterns[0],
            &source_patterns[1],
        ).await?;
        
        print_similarity_analysis(&similarity_analysis, &source_patterns[0], &source_patterns[1]);
    }
    
    // Step 8: Performance and Analytics
    println!("\n📈 Step 8: Transfer Performance Analytics");
    let analytics = transfer_engine.get_transfer_analytics().await?;
    
    println!("Transfer Analytics Summary:");
    println!("  - Total transfers: {}", analytics.total_transfers);
    println!("  - Successful transfers: {}", analytics.successful_transfers);
    println!("  - Overall success rate: {:.1}%", analytics.overall_success_rate * 100.0);
    
    if !analytics.success_rate_by_language.is_empty() {
        println!("  - Success by language:");
        for (lang, rate) in &analytics.success_rate_by_language {
            println!("    {:?}: {:.1}%", lang, rate * 100.0);
        }
    }
    
    if !analytics.recommendations.is_empty() {
        println!("  - Recommendations:");
        for rec in &analytics.recommendations {
            println!("    • {}", rec);
        }
    }
    
    // Step 9: Advanced Scenarios
    println!("\n🎓 Step 9: Advanced Transfer Scenarios");
    demonstrate_advanced_scenarios(&transfer_engine, &source_patterns).await?;
    
    // Step 10: Summary and Insights
    println!("\n🎉 Cross-Language Transfer Demonstration Complete!");
    println!("===============================================");
    println!();
    println!("✅ Successfully demonstrated:");
    println!("  1. Multi-language vulnerability pattern transfer");
    println!("  2. Confidence scoring with detailed analysis");
    println!("  3. Pattern similarity analysis across languages");
    println!("  4. Transfer validation and quality assessment");
    println!("  5. Performance analytics and insights");
    println!();
    println!("🔮 Key Benefits of Cross-Language Transfer:");
    println!("  • Leverage vulnerability knowledge across language boundaries");
    println!("  • Accelerate security rule development for new languages");
    println!("  • Maintain consistency in vulnerability detection");
    println!("  • Reduce manual effort in pattern adaptation");
    println!("  • Enable intelligent pattern optimization");
    println!();
    println!("🛡️  Quality Assurance Features:");
    println!("  • Comprehensive confidence scoring");
    println!("  • Semantic and syntactic compatibility analysis");
    println!("  • Historical success rate tracking");
    println!("  • Risk factor identification");
    println!("  • Transfer validation and quality metrics");
    
    Ok(())
}

/// Create demonstration vulnerability patterns
fn create_demonstration_patterns() -> Vec<SecurityPattern> {
    vec![
        SecurityPattern {
            id: "sql-injection-java-001".to_string(),
            name: "SQL Injection via String Concatenation".to_string(),
            description: "Detects SQL injection vulnerabilities through unsafe string concatenation in database queries".to_string(),
            severity: Severity::High,
            category: "injection".to_string(),
            languages: vec!["java".to_string()],
            patterns: vec![
                RegexPattern {
                    regex: r#"(?i)(Statement|PreparedStatement).*\.(execute|executeQuery|executeUpdate)\s*\(\s*["'].*\+.*["']\s*\)"#.to_string(),
                    flags: None,
                    description: Some("String concatenation in SQL execution".to_string()),
                    confidence: Some(0.85),
                }
            ],
            fix_suggestion: Some("Use parameterized queries or prepared statements with placeholders".to_string()),
            cwe: Some("CWE-89".to_string()),
            owasp: Some("A03:2021 - Injection".to_string()),
            references: Some(vec![
                "https://owasp.org/www-community/attacks/SQL_Injection".to_string(),
                "https://cheatsheetseries.owasp.org/cheatsheets/SQL_Injection_Prevention_Cheat_Sheet.html".to_string(),
            ]),
            metadata: Some({
                let mut meta = HashMap::new();
                meta.insert("source_language".to_string(), "java".to_string());
                meta.insert("confidence".to_string(), "0.85".to_string());
                meta.insert("complexity".to_string(), "medium".to_string());
                meta
            }),
        },
        SecurityPattern {
            id: "xss-javascript-001".to_string(),
            name: "DOM-based XSS via innerHTML".to_string(),
            description: "Detects DOM-based cross-site scripting through unsafe innerHTML manipulation".to_string(),
            severity: Severity::High,
            category: "xss".to_string(),
            languages: vec!["javascript".to_string()],
            patterns: vec![
                RegexPattern {
                    regex: r"(?i)\.(innerHTML|outerHTML)\s*=\s*.*\+".to_string(),
                    flags: None,
                    description: Some("Direct HTML injection via innerHTML".to_string()),
                    confidence: Some(0.78),
                }
            ],
            fix_suggestion: Some("Use textContent for text or properly sanitize HTML content with a trusted library".to_string()),
            cwe: Some("CWE-79".to_string()),
            owasp: Some("A03:2021 - Injection".to_string()),
            references: Some(vec![
                "https://owasp.org/www-community/attacks/xss/".to_string(),
                "https://cheatsheetseries.owasp.org/cheatsheets/Cross_Site_Scripting_Prevention_Cheat_Sheet.html".to_string(),
            ]),
            metadata: Some({
                let mut meta = HashMap::new();
                meta.insert("source_language".to_string(), "javascript".to_string());
                meta.insert("confidence".to_string(), "0.78".to_string());
                meta.insert("complexity".to_string(), "low".to_string());
                meta
            }),
        },
        SecurityPattern {
            id: "buffer-overflow-c-001".to_string(),
            name: "Buffer Overflow via Unsafe String Functions".to_string(),
            description: "Detects potential buffer overflow vulnerabilities from unsafe string manipulation functions".to_string(),
            severity: Severity::Critical,
            category: "buffer_overflow".to_string(),
            languages: vec!["c".to_string()],
            patterns: vec![
                RegexPattern {
                    regex: r"(?i)(strcpy|strcat|sprintf|gets)\s*\(".to_string(),
                    flags: None,
                    description: Some("Unsafe string functions prone to buffer overflow".to_string()),
                    confidence: Some(0.92),
                }
            ],
            fix_suggestion: Some("Use safe alternatives: strncpy, strncat, snprintf, fgets with proper bounds checking".to_string()),
            cwe: Some("CWE-120".to_string()),
            owasp: Some("A06:2021 - Vulnerable and Outdated Components".to_string()),
            references: Some(vec![
                "https://cwe.mitre.org/data/definitions/120.html".to_string(),
                "https://owasp.org/www-community/vulnerabilities/Buffer_Overflow".to_string(),
            ]),
            metadata: Some({
                let mut meta = HashMap::new();
                meta.insert("source_language".to_string(), "c".to_string());
                meta.insert("confidence".to_string(), "0.92".to_string());
                meta.insert("complexity".to_string(), "high".to_string());
                meta
            }),
        },
    ]
}

/// Print detailed confidence analysis
fn print_confidence_analysis(
    score: &TransferConfidenceScore,
    source_pattern: &SecurityPattern,
    target_language: Language,
) {
    println!("    Overall Confidence: {:.1}%", score.overall_confidence * 100.0);
    println!("    Component Scores:");
    println!("      • Semantic Similarity: {:.1}%", score.semantic_similarity * 100.0);
    println!("      • Syntactic Compatibility: {:.1}%", score.syntactic_compatibility * 100.0);
    println!("      • Pattern Complexity: {:.1}%", score.pattern_complexity_score * 100.0);
    println!("      • Language Support: {:.1}%", score.language_support_score * 100.0);
    println!("      • Historical Success: {:.1}%", score.historical_success_rate * 100.0);
    println!("      • Validation Score: {:.1}%", score.validation_score * 100.0);
    
    if !score.explanation.is_empty() {
        println!("    Explanations:");
        for explanation in &score.explanation {
            println!("      • {}", explanation);
        }
    }
    
    if !score.risk_factors.is_empty() {
        println!("    Risk Factors:");
        for risk in &score.risk_factors {
            println!("      ⚠️  {}", risk);
        }
    }
}

/// Print detailed similarity analysis
fn print_similarity_analysis(
    analysis: &PatternSimilarityAnalysis,
    pattern1: &SecurityPattern,
    pattern2: &SecurityPattern,
) {
    println!("  Comparing: '{}' vs '{}'", pattern1.name, pattern2.name);
    println!("  Overall Similarity: {:.1}%", analysis.overall_similarity * 100.0);
    println!("  Transfer Viability: {:?}", analysis.transfer_viability);
    println!("  Component Similarities:");
    println!("    • Semantic: {:.1}%", analysis.semantic_similarity * 100.0);
    println!("    • Structural: {:.1}%", analysis.structural_similarity * 100.0);
    println!("    • Behavioral: {:.1}%", analysis.behavioral_similarity * 100.0);
    println!("    • Effectiveness: {:.1}%", analysis.effectiveness_similarity * 100.0);
    
    if !analysis.similarity_factors.is_empty() {
        println!("  Similarity Factors:");
        for factor in &analysis.similarity_factors {
            println!("    ✓ {}", factor);
        }
    }
    
    if !analysis.differences.is_empty() {
        println!("  Key Differences:");
        for diff in &analysis.differences {
            println!("    • {}", diff);
        }
    }
}

/// Demonstrate advanced transfer scenarios
async fn demonstrate_advanced_scenarios(
    transfer_engine: &CrossLanguageTransfer,
    source_patterns: &[SecurityPattern],
) -> Result<(), Box<dyn std::error::Error>> {
    println!("Advanced Scenario 1: High-Confidence Transfers");
    
    // Find patterns with high transfer confidence
    let mut high_confidence_transfers = 0;
    let mut moderate_confidence_transfers = 0;
    let mut low_confidence_transfers = 0;
    
    for pattern in source_patterns {
        let transfer_context = TransferContext {
            validation_result: None,
            transfer_parameters: HashMap::new(),
            metadata: HashMap::new(),
        };
        
        for target_lang in &[Language::Python, Language::Javascript, Language::Java] {
            let confidence = transfer_engine.calculate_transfer_confidence(
                pattern,
                *target_lang,
                &transfer_context,
            ).await?;
            
            match confidence.overall_confidence {
                c if c >= 0.8 => high_confidence_transfers += 1,
                c if c >= 0.6 => moderate_confidence_transfers += 1,
                _ => low_confidence_transfers += 1,
            }
        }
    }
    
    println!("  Transfer Confidence Distribution:");
    println!("    High (≥80%): {} transfers", high_confidence_transfers);
    println!("    Moderate (60-79%): {} transfers", moderate_confidence_transfers);
    println!("    Low (<60%): {} transfers", low_confidence_transfers);
    
    println!("\nAdvanced Scenario 2: Cross-Category Pattern Analysis");
    
    // Analyze patterns across different vulnerability categories
    let categories: std::collections::HashSet<String> = source_patterns.iter()
        .map(|p| p.category.clone())
        .collect();
    
    println!("  Vulnerability Categories: {}", categories.len());
    for category in &categories {
        let category_patterns: Vec<_> = source_patterns.iter()
            .filter(|p| &p.category == category)
            .collect();
        println!("    {}: {} patterns", category, category_patterns.len());
    }
    
    println!("\nAdvanced Scenario 3: Language-Specific Adaptation Analysis");
    
    // Analyze which languages are best suited for different vulnerability types
    let target_languages = vec![Language::Python, Language::Javascript, Language::Java, Language::Go, Language::Rust];
    
    for lang in &target_languages {
        let mut total_confidence = 0.0;
        let mut pattern_count = 0;
        
        for pattern in source_patterns {
            let transfer_context = TransferContext {
                validation_result: None,
                transfer_parameters: HashMap::new(),
                metadata: HashMap::new(),
            };
            
            if let Ok(confidence) = transfer_engine.calculate_transfer_confidence(
                pattern,
                *lang,
                &transfer_context,
            ).await {
                total_confidence += confidence.overall_confidence;
                pattern_count += 1;
            }
        }
        
        let avg_confidence = if pattern_count > 0 {
            total_confidence / pattern_count as f32
        } else {
            0.0
        };
        
        println!("    {:?}: {:.1}% average confidence", lang, avg_confidence * 100.0);
    }
    
    Ok(())
}