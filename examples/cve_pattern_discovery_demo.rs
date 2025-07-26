/// CVE Pattern Discovery Engine Demonstration
/// 
/// This example demonstrates the CVE pattern discovery engine's ability to
/// automatically identify and extract vulnerability patterns from code samples.

use devaic::{
    cve_pattern_discovery::{CVEPatternDiscovery, DiscoveryConfig},
    pattern_loader::SecurityPattern,
};

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    println!("🔍 CVE Pattern Discovery Engine Demo");
    println!("====================================\n");

    // Initialize pattern discovery engine
    let config = DiscoveryConfig {
        min_severity: 6.0,
        max_age_days: 30,
        target_languages: vec!["javascript".to_string(), "python".to_string()],
        priority_categories: vec!["injection".to_string(), "xss".to_string(), "authentication".to_string()],
        rate_limit_requests_per_minute: 60,
        min_pattern_confidence: 0.7,
        max_patterns_per_run: 10,
    };

    let mut discovery_engine = CVEPatternDiscovery::new(config)?;
    println!("✅ Initialized CVE Pattern Discovery Engine");

    // Demonstrate pattern discovery with sample vulnerable code
    println!("\n🔎 Discovering Patterns in Vulnerable Code Samples");
    println!("--------------------------------------------------");

    // Discover patterns from recent CVEs
    println!("\n1. Discovering Patterns from Recent CVEs:");
    let discovered_patterns = discovery_engine.discover_patterns().await?;
    println!("   → Discovered {} security patterns", discovered_patterns.len());
    
    for (i, pattern) in discovered_patterns.iter().take(5).enumerate() {
        println!("   {}. Pattern: {} (Languages: {:?})", 
            i + 1, 
            pattern.name, 
            pattern.languages
        );
    }

    // Test Case 2: Pattern Analysis Demonstration
    println!("\n2. Pattern Analysis Demonstration:");
    demo_pattern_analysis(&discovered_patterns).await?;

    // Test Case 3: Pattern Application Simulation
    println!("\n3. Pattern Application Simulation:");
    demo_pattern_application(&discovered_patterns).await?;

    println!("\n📊 Pattern Discovery Complete!");
    println!("\n🎉 CVE Pattern Discovery Demo Complete!");
    Ok(())
}

/// Demonstrate pattern analysis
async fn demo_pattern_analysis(patterns: &[SecurityPattern]) -> Result<(), Box<dyn std::error::Error>> {
    println!("   Analyzing discovered patterns...");
    
    // Group patterns by language
    let mut language_counts = std::collections::HashMap::new();
    for pattern in patterns {
        for language in &pattern.languages {
            *language_counts.entry(language.as_str()).or_insert(0) += 1;
        }
    }
    
    println!("   Pattern distribution by language:");
    for (language, count) in language_counts {
        println!("      • {}: {} patterns", language, count);
    }
    
    // Show pattern categories
    let mut category_counts = std::collections::HashMap::new();
    for pattern in patterns {
        *category_counts.entry(&pattern.category).or_insert(0) += 1;
    }
    
    println!("   Pattern distribution by category:");
    for (category, count) in category_counts {
        println!("      • {}: {} patterns", category, count);
    }
    
    Ok(())
}

/// Demonstrate pattern application simulation
async fn demo_pattern_application(patterns: &[SecurityPattern]) -> Result<(), Box<dyn std::error::Error>> {
    println!("   Simulating pattern application on test code...");
    
    let test_code_samples = vec![
        ("SQL Injection", "SELECT * FROM users WHERE id = ' + user_id + '"),
        ("XSS", "document.getElementById('output').innerHTML = userInput"),
        ("Command Injection", "system(\"rm -rf \" + user_path)"),
        ("Path Traversal", "file = open(\"/var/www/\" + user_file)"),
    ];
    
    for (vulnerability_type, code) in test_code_samples {
        println!("   Testing {} pattern on: {}", vulnerability_type, code);
        
        // Simulate pattern matching
        let matching_patterns: Vec<_> = patterns.iter()
            .filter(|p| p.category.to_lowercase().contains(&vulnerability_type.to_lowercase()) 
                     || p.name.to_lowercase().contains(&vulnerability_type.to_lowercase()))
            .collect();
            
        if !matching_patterns.is_empty() {
            println!("      ✓ {} matching patterns found", matching_patterns.len());
            for pattern in matching_patterns.iter().take(2) {
                println!("        • {}: {}", pattern.name, pattern.description);
            }
        } else {
            println!("      ○ No matching patterns found");
        }
    }
    
    Ok(())
}

