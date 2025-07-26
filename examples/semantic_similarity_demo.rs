/// Semantic Similarity Detection Engine Demonstration
/// 
/// This example demonstrates how the semantic similarity engine can find variations
/// of known vulnerabilities using AI-powered code analysis and semantic understanding.

use devaic::{
    semantic_similarity_engine::{SemanticSimilarityEngine, SimilarityConfig},
};

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    println!("🔍 Semantic Similarity Detection Engine Demo");
    println!("============================================\n");

    // Initialize the semantic similarity engine
    let config = SimilarityConfig {
        min_similarity_threshold: 0.85,
        enable_deep_analysis: true,
        enable_embedding_similarity: true,
        enable_syntactic_variations: true,
        enable_semantic_equivalents: true,
        max_analysis_depth: 10,
        analysis_timeout_ms: 5000,
        enable_ml_enhancement: true,
        ml_confidence_threshold: 0.7,
    };

    let engine = SemanticSimilarityEngine::new(config)?;
    println!("✅ Initialized Semantic Similarity Engine");
    
    println!("✅ Semantic Similarity Engine ready for analysis\n");

    // Demonstrate finding similar vulnerabilities in different code samples
    println!("🔎 Analyzing Code Samples for Similar Vulnerabilities");
    println!("----------------------------------------------------");

    // Test Case 1: SQL Injection Variants
    println!("\n1. SQL Injection Similarity Detection:");
    demo_sql_injection_variants(&engine).await?;

    // Test Case 2: Cross-Language Similarity
    println!("\n2. Cross-Language Vulnerability Detection:");
    demo_cross_language_similarity(&engine).await?;

    // Test Case 3: Obfuscated Pattern Detection
    println!("\n3. Obfuscated Pattern Detection:");
    demo_obfuscated_patterns(&engine).await?;

    // Test Case 4: Behavioral Equivalence
    println!("\n4. Behavioral Equivalence Detection:");
    demo_behavioral_equivalence(&engine).await?;

    // Display completion message
    println!("\n📊 Analysis Complete!");

    println!("\n🎉 Semantic Similarity Detection Demo Complete!");
    Ok(())
}

/// Demonstrate SQL injection variant detection
async fn demo_sql_injection_variants(engine: &SemanticSimilarityEngine) -> Result<(), Box<dyn std::error::Error>> {
    let test_cases = vec![
        "query = \"SELECT * FROM users WHERE id = \" + user_id",
        "sql = format!(\"SELECT * FROM customers WHERE email = '{}'\", email)",
        "result = db.query(\"DELETE FROM logs WHERE date < '\" + date + \"'\")",
    ];

    for (i, code) in test_cases.iter().enumerate() {
        println!("   Test {}: {}", i + 1, code);
        let patterns = engine.find_similar_vulnerabilities(code, "javascript").await?;
        println!("      → Found {} potential vulnerability patterns", patterns.len());
        
        if !patterns.is_empty() {
            for pattern in &patterns {
                println!("        • {} (confidence: {:.2})", 
                    pattern.pattern_info.title, 
                    pattern.detection_confidence
                );
            }
        }
    }
    Ok(())
}

/// Demonstrate cross-language similarity detection  
async fn demo_cross_language_similarity(engine: &SemanticSimilarityEngine) -> Result<(), Box<dyn std::error::Error>> {
    let cross_language_tests = vec![
        ("JavaScript", "document.getElementById('output').innerHTML = userInput;"),
        ("PHP", "echo $_GET['input'];"),
        ("Python", "print(f\"Hello {user_input}\")"),
        ("Java", "response.getWriter().write(userInput);"),
    ];

    for (language, code) in cross_language_tests {
        println!("   {}: {}", language, code);
        let lang_str = match language {
            "JavaScript" => "javascript",
            "PHP" => "php", 
            "Python" => "python",
            "Java" => "java",
            _ => "javascript",
        };
        
        let patterns = engine.find_similar_vulnerabilities(code, lang_str).await?;
        println!("      → Cross-language patterns found: {}", patterns.len());
    }
    Ok(())
}

/// Demonstrate obfuscated pattern detection
async fn demo_obfuscated_patterns(engine: &SemanticSimilarityEngine) -> Result<(), Box<dyn std::error::Error>> {
    let obfuscated_samples = vec![
        "eval(atob('c2VsZWN0ICogZnJvbSB1c2Vycw=='))", // Base64 encoded
        "var a='SELECT'; var b=' * FROM '; var c='users'; query=a+b+c;",
        "setTimeout(\"document.write('\" + params + \"')\", 100)",
    ];

    for code in obfuscated_samples {
        println!("   Analyzing: {}", code);
        let patterns = engine.find_similar_vulnerabilities(code, "javascript").await?;
        println!("      → Obfuscation-resistant detection: {} patterns", patterns.len());
    }
    Ok(())
}

/// Demonstrate behavioral equivalence detection
async fn demo_behavioral_equivalence(engine: &SemanticSimilarityEngine) -> Result<(), Box<dyn std::error::Error>> {
    let behavioral_tests = vec![
        "system(\"rm -rf \" + user_path)",
        "exec(\"del /f \" + filename)",
        "Runtime.getRuntime().exec(command)",
        "subprocess.call([\"rm\", user_file])",
    ];

    for code in behavioral_tests {
        println!("   Command execution pattern: {}", code);
        let patterns = engine.find_similar_vulnerabilities(code, "javascript").await?;
        println!("      → Behavioral equivalents found: {}", patterns.len());
        
        if !patterns.is_empty() {
            for pattern in &patterns {
                println!("        • Severity: {:?}, Type: {}", 
                    pattern.pattern_info.estimated_severity,
                    pattern.pattern_info.title
                );
            }
        }
    }
    Ok(())
}