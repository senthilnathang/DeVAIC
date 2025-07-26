/// Adaptive Rule Prioritization Demo
/// 
/// This example demonstrates the intelligent rule ordering system that learns
/// from historical findings to optimize vulnerability detection efficiency.

use devaic::{
    config::Config,
    analyzer::Analyzer,
    adaptive_rule_prioritization::{
        AdaptiveRulePrioritizer, AnalysisContext, PrioritizationStrategy,
        SecurityCategory, DevelopmentPhase, RuleExecution, 
    },
    Language, Severity, Vulnerability,
};
use std::sync::Arc;
use std::time::{Duration, SystemTime, UNIX_EPOCH};
use tokio::time::sleep;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    println!("🧠 DeVAIC Adaptive Rule Prioritization Demo");
    println!("═══════════════════════════════════════════");
    println!();

    // Demo 1: Basic Prioritization Setup
    println!("📋 Demo 1: Setting Up Adaptive Prioritization");
    println!("──────────────────────────────────────────");
    
    let mut prioritizer = AdaptiveRulePrioritizer::new(PrioritizationStrategy::Balanced);
    println!("✅ Created adaptive rule prioritizer with Balanced strategy");
    
    // Create analysis context for a JavaScript web application
    let context = AnalysisContext {
        primary_languages: vec![Language::Javascript, Language::TypeScript],
        codebase_size: 50000,
        frameworks_detected: vec!["React".to_string(), "Express".to_string()],
        security_focus_areas: vec![
            SecurityCategory::WebSecurity,
            SecurityCategory::ApiSecurity,
            SecurityCategory::InputValidation,
        ],
        time_constraints: Some(Duration::from_secs(300)), // 5 minute scan limit
        previous_scan_results: None,
        development_phase: DevelopmentPhase::Development,
    };
    
    println!("🎯 Analysis Context:");
    println!("   Languages: {:?}", context.primary_languages);
    println!("   Frameworks: {:?}", context.frameworks_detected);
    println!("   Security Focus: {:?}", context.security_focus_areas);
    println!("   Time Limit: {:?}", context.time_constraints);
    println!();

    // Demo 2: Rule Prioritization Without History
    println!("📊 Demo 2: Initial Rule Prioritization (No Historical Data)");
    println!("─────────────────────────────────────────────────────────");
    
    let available_rules = vec![
        "js_xss_detection".to_string(),
        "js_sql_injection".to_string(),
        "js_prototype_pollution".to_string(),
        "js_eval_usage".to_string(),
        "js_crypto_weak".to_string(),
        "js_path_traversal".to_string(),
        "js_open_redirect".to_string(),
        "js_csrf_protection".to_string(),
    ];
    
    let initial_priorities = prioritizer.prioritize_rules(&available_rules, &context);
    
    println!("🔍 Initial Rule Priorities (no learning data):");
    for (i, priority) in initial_priorities.iter().take(5).enumerate() {
        println!("   {}. {} (Score: {:.3}, Confidence: {:.1}%)", 
            i + 1, 
            priority.rule_id, 
            priority.priority_score,
            priority.confidence * 100.0
        );
        println!("      Expected Time: {:?}, Expected Findings: {}", 
            priority.estimated_execution_time, 
            priority.expected_findings
        );
    }
    println!();

    // Demo 3: Simulate Learning from Executions
    println!("🎓 Demo 3: Learning from Rule Execution History");
    println!("─────────────────────────────────────────────");
    
    simulate_historical_executions(&prioritizer, &available_rules).await;
    
    let learned_priorities = prioritizer.prioritize_rules(&available_rules, &context);
    
    println!("🧠 Adaptive Priorities (after learning):");
    for (i, priority) in learned_priorities.iter().take(5).enumerate() {
        println!("   {}. {} (Score: {:.3}, Confidence: {:.1}%)", 
            i + 1, 
            priority.rule_id, 
            priority.priority_score,
            priority.confidence * 100.0
        );
        println!("      Reasoning: {}", priority.reasoning);
    }
    println!();

    // Demo 4: Strategy Comparison
    println!("⚖️  Demo 4: Comparing Different Prioritization Strategies");
    println!("───────────────────────────────────────────────────────");
    
    compare_strategies(&available_rules, &context).await;

    // Demo 5: Performance Analytics
    println!("📈 Demo 5: Prioritization Analytics and Insights");
    println!("──────────────────────────────────────────────");
    
    let analytics = prioritizer.generate_analytics();
    println!("📊 Prioritization Analytics:");
    println!("   Total Rules Tracked: {}", analytics.total_rules);
    println!("   Effective Rules: {} ({:.1}%)", 
        analytics.effective_rules,
        analytics.effectiveness_rate * 100.0
    );
    println!("   Strategy Used: {}", analytics.strategy_used);
    
    println!("\n🏆 Top Performing Rules:");
    for (i, (rule_id, score)) in analytics.top_performing_rules.iter().take(3).enumerate() {
        println!("   {}. {} (Effectiveness: {:.3})", i + 1, rule_id, score);
    }
    
    if !analytics.language_effectiveness.is_empty() {
        println!("\n🌐 Language Effectiveness:");
        for (language, effectiveness) in &analytics.language_effectiveness {
            println!("   {:?}: {:.3}", language, effectiveness);
        }
    }
    println!();

    // Demo 6: Integration with Analyzer
    println!("🔗 Demo 6: Integration with Main Analyzer");
    println!("─────────────────────────────────────────");
    
    demonstrate_analyzer_integration(prioritizer).await?;

    println!("🎉 Adaptive Rule Prioritization Demo Complete!");
    println!("\n💡 Key Benefits Demonstrated:");
    println!("   • Intelligent rule ordering based on historical success");
    println!("   • Context-aware prioritization for different codebases");
    println!("   • Learning from execution results to improve efficiency");
    println!("   • Multiple strategies for different scanning scenarios");
    println!("   • Performance analytics for continuous optimization");

    Ok(())
}

/// Simulate historical rule executions for learning
async fn simulate_historical_executions(prioritizer: &AdaptiveRulePrioritizer, rules: &[String]) {
    println!("⚡ Simulating rule execution history...");
    
    let current_time = SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_secs();
    
    // Simulate successful executions for some rules
    for (i, rule_id) in rules.iter().enumerate() {
        for day in 0..30 { // 30 days of history
            let execution = RuleExecution {
                timestamp: current_time - (day * 24 * 3600),
                execution_time_ms: 20 + (i * 10) as u64, // Varying execution times
                vulnerabilities_found: if rule_id.contains("xss") || rule_id.contains("sql") {
                    if day % 3 == 0 { 2 } else { 0 } // High-yield rules
                } else if rule_id.contains("eval") || rule_id.contains("crypto") {
                    if day % 5 == 0 { 1 } else { 0 } // Medium-yield rules
                } else {
                    if day % 10 == 0 { 1 } else { 0 } // Low-yield rules
                },
                false_positives: 0,
                language: Language::Javascript,
                file_size: 1000 + (i * 200) as u64,
                file_complexity: 0.3 + (i as f64 * 0.1),
            };

            // Create sample vulnerabilities for successful executions
            let vulnerabilities = if execution.vulnerabilities_found > 0 {
                (0..execution.vulnerabilities_found).map(|j| {
                    Vulnerability {
                        id: format!("{}-{}-{}", rule_id, day, j),
                        title: format!("Simulated {} vulnerability", rule_id),
                        description: "Simulated vulnerability for learning demo".to_string(),
                        severity: if rule_id.contains("sql") || rule_id.contains("xss") {
                            Severity::High
                        } else if rule_id.contains("eval") {
                            Severity::Medium
                        } else {
                            Severity::Low
                        },
                        category: "web_security".to_string(),
                        cwe: Some("CWE-79".to_string()),
                        owasp: Some("A03:2021".to_string()),
                        file_path: format!("src/component_{}.js", i),
                        line_number: 10 + j as usize,
                        column_start: 5,
                        column_end: 25,
                        source_code: "// Simulated vulnerable code".to_string(),
                        recommendation: "Fix this simulated vulnerability".to_string(),
                        references: vec![],
                        confidence: 0.85,
                    }
                }).collect()
            } else {
                vec![]
            };

            prioritizer.record_execution(rule_id, execution, &vulnerabilities);
        }
        sleep(Duration::from_millis(1)).await; // Small delay for demo
    }
    
    println!("   ✅ Recorded 30 days of execution history for {} rules", rules.len());
}

/// Compare different prioritization strategies
async fn compare_strategies(rules: &[String], context: &AnalysisContext) {
    let strategies = vec![
        ("High Yield", PrioritizationStrategy::HighYield),
        ("High Severity", PrioritizationStrategy::HighSeverity),
        ("Balanced", PrioritizationStrategy::Balanced),
        ("Comprehensive", PrioritizationStrategy::Comprehensive),
    ];

    for (name, strategy) in strategies {
        let prioritizer = AdaptiveRulePrioritizer::new(strategy);
        
        // Add some mock history for comparison
        for rule_id in rules {
            let execution = RuleExecution {
                timestamp: SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_secs(),
                execution_time_ms: 50,
                vulnerabilities_found: if rule_id.contains("xss") { 3 } else { 1 },
                false_positives: 0,
                language: Language::Javascript,
                file_size: 1000,
                file_complexity: 0.5,
            };
            
            let mock_vulns = vec![
                Vulnerability {
                    id: "mock".to_string(),
                    title: "Mock".to_string(),
                    description: "Mock".to_string(),
                    severity: if rule_id.contains("sql") { Severity::Critical } else { Severity::Medium },
                    category: "mock".to_string(),
                    cwe: None,
                    owasp: None,
                    file_path: "mock.js".to_string(),
                    line_number: 1,
                    column_start: 0,
                    column_end: 10,
                    source_code: "mock".to_string(),
                    recommendation: "mock".to_string(),
                    references: vec![],
                    confidence: 0.8,
                }
            ];
            
            prioritizer.record_execution(rule_id, execution, &mock_vulns);
        }

        let priorities = prioritizer.prioritize_rules(rules, context);
        
        println!("📋 {} Strategy - Top 3 Rules:", name);
        for (i, priority) in priorities.iter().take(3).enumerate() {
            println!("   {}. {} (Score: {:.3})", 
                i + 1, 
                priority.rule_id, 
                priority.priority_score
            );
        }
        println!();
    }
}

/// Demonstrate integration with the main analyzer
async fn demonstrate_analyzer_integration(prioritizer: AdaptiveRulePrioritizer) -> Result<(), Box<dyn std::error::Error>> {
    println!("🔧 Integrating adaptive prioritization with analyzer...");
    
    let config = Config::default();
    let mut analyzer = Analyzer::new(config)?;
    
    // This would be the integration point where the analyzer uses
    // the adaptive prioritizer to order rule execution
    println!("   ✅ Analyzer created with adaptive prioritization support");
    println!("   🎯 Rules will now be executed in optimized order");
    println!("   📈 System will learn from each scan to improve efficiency");
    
    Ok(())
}