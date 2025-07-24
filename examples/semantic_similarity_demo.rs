/// Semantic Similarity Detection Engine Demonstration
/// 
/// This example demonstrates how the semantic similarity engine can find variations
/// of known vulnerabilities using AI-powered code analysis and semantic understanding.

use devaic::{
    semantic_similarity_engine::{
        SemanticSimilarityEngine, SimilarityConfig, VulnerabilitySignature,
        CodeEmbedding, BehavioralSignature, VariationType,
    },
    Severity,
};
use std::collections::HashMap;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    println!("🔍 Semantic Similarity Detection Engine Demo");
    println!("============================================\n");

    // Initialize the semantic similarity engine
    let config = SimilarityConfig {
        similarity_threshold: 0.85,
        enable_cross_language: true,
        enable_normalization: true,
        max_context_lines: 20,
        enable_behavioral_analysis: true,
        cache_size: 1000,
        enable_obfuscation_resistance: true,
    };

    let engine = SemanticSimilarityEngine::new(config);
    println!("✅ Initialized Semantic Similarity Engine");

    // Create sample vulnerability signatures
    let sql_injection_signature = create_sql_injection_signature().await?;
    let buffer_overflow_signature = create_buffer_overflow_signature().await?;
    let xss_signature = create_xss_signature().await?;

    // Register known vulnerability signatures
    let signatures = vec![
        sql_injection_signature,
        buffer_overflow_signature,
        xss_signature,
    ];

    engine.initialize_with_signatures(signatures).await?;
    println!("✅ Registered {} vulnerability signatures\n", 3);

    // Demonstrate finding similar vulnerabilities in different code samples
    println!("🔎 Analyzing Code Samples for Similar Vulnerabilities");
    println!("----------------------------------------------------");

    // Test Case 1: SQL Injection Variants
    println!("\n1. SQL Injection Similarity Detection:");
    await_demo_sql_injection_variants(&engine).await?;

    // Test Case 2: Cross-Language Similarity
    println!("\n2. Cross-Language Vulnerability Detection:");
    await_demo_cross_language_similarity(&engine).await?;

    // Test Case 3: Obfuscated Pattern Detection
    println!("\n3. Obfuscated Pattern Detection:");
    await_demo_obfuscated_patterns(&engine).await?;

    // Test Case 4: Behavioral Equivalence
    println!("\n4. Behavioral Equivalence Detection:");
    await_demo_behavioral_equivalence(&engine).await?;

    // Display engine statistics
    println!("\n📊 Engine Statistics:");
    let stats = engine.get_statistics().await?;
    println!("   Total Signatures: {}", stats.total_signatures);
    println!("   Cache Size: {}", stats.cache_size);
    println!("   Average Confidence: {:.3}", stats.average_confidence);
    println!("   Languages: {:?}", stats.language_distribution.keys().collect::<Vec<_>>());

    println!("\n🎉 Semantic Similarity Detection Demo Complete!");
    Ok(())
}

/// Create SQL injection vulnerability signature
async fn create_sql_injection_signature() -> Result<VulnerabilitySignature, Box<dyn std::error::Error>> {
    let embedding = CodeEmbedding {
        vector: generate_mock_embedding("sql_injection", 512),
        language: "javascript".to_string(),
        normalized_code: "query = \"SELECT * FROM users WHERE id = \" + user_id".to_string(),
        structural_features: vec![0.8, 0.6, 0.9, 0.7, 0.5],
        control_flow_hash: 12345,
        data_flow_hash: 67890,
        confidence: 0.95,
    };

    Ok(VulnerabilitySignature {
        id: "sql-injection-001".to_string(),
        vulnerability_type: "sql_injection".to_string(),
        cwe_id: "CWE-89".to_string(),
        embedding,
        variations: vec![],
        severity: 9.0,
        applicable_languages: vec!["javascript".to_string(), "java".to_string(), "python".to_string()],
        behavioral_signature: BehavioralSignature {
            io_patterns: vec!["database_query".to_string(), "user_input".to_string()],
            memory_patterns: vec![],
            network_patterns: vec!["sql_connection".to_string()],
            filesystem_patterns: vec![],
            privilege_patterns: vec!["database_access".to_string()],
            data_flow_characteristics: vec!["untrusted_input_to_query".to_string()],
        },
    })
}

/// Create buffer overflow vulnerability signature
async fn create_buffer_overflow_signature() -> Result<VulnerabilitySignature, Box<dyn std::error::Error>> {
    let embedding = CodeEmbedding {
        vector: generate_mock_embedding("buffer_overflow", 512),
        language: "c".to_string(),
        normalized_code: "strcpy(buffer, user_input)".to_string(),
        structural_features: vec![0.9, 0.8, 0.7, 0.6, 0.8],
        control_flow_hash: 23456,
        data_flow_hash: 78901,
        confidence: 0.92,
    };

    Ok(VulnerabilitySignature {
        id: "buffer-overflow-001".to_string(),
        vulnerability_type: "buffer_overflow".to_string(),
        cwe_id: "CWE-120".to_string(),
        embedding,
        variations: vec![],
        severity: 8.5,
        applicable_languages: vec!["c".to_string(), "cpp".to_string()],
        behavioral_signature: BehavioralSignature {
            io_patterns: vec!["string_copy".to_string()],
            memory_patterns: vec!["unsafe_memory_operation".to_string()],
            network_patterns: vec![],
            filesystem_patterns: vec![],
            privilege_patterns: vec![],
            data_flow_characteristics: vec!["unchecked_buffer_copy".to_string()],
        },
    })
}

/// Create XSS vulnerability signature
async fn create_xss_signature() -> Result<VulnerabilitySignature, Box<dyn std::error::Error>> {
    let embedding = CodeEmbedding {
        vector: generate_mock_embedding("xss", 512),
        language: "javascript".to_string(),
        normalized_code: "document.innerHTML = user_input".to_string(),
        structural_features: vec![0.7, 0.9, 0.6, 0.8, 0.7],
        control_flow_hash: 34567,
        data_flow_hash: 89012,
        confidence: 0.88,
    };

    Ok(VulnerabilitySignature {
        id: "xss-001".to_string(),
        vulnerability_type: "cross_site_scripting".to_string(),
        cwe_id: "CWE-79".to_string(),
        embedding,
        variations: vec![],
        severity: 7.5,
        applicable_languages: vec!["javascript".to_string(), "html".to_string()],
        behavioral_signature: BehavioralSignature {
            io_patterns: vec!["dom_manipulation".to_string()],
            memory_patterns: vec![],
            network_patterns: vec!["http_response".to_string()],
            filesystem_patterns: vec![],
            privilege_patterns: vec!["script_execution".to_string()],
            data_flow_characteristics: vec!["untrusted_input_to_output".to_string()],
        },
    })
}

/// Demonstrate SQL injection variant detection
async fn await_demo_sql_injection_variants(engine: &SemanticSimilarityEngine) -> Result<(), Box<dyn std::error::Error>> {
    let test_cases = vec![
        // Original pattern
        ("Original", "var query = \"SELECT * FROM users WHERE id = \" + userId;", "javascript"),
        
        // String concatenation variant
        ("Concatenation Variant", "String sql = \"SELECT * FROM users WHERE id = \" + request.getParameter(\"id\");", "java"),
        
        // Template literal variant  
        ("Template Literal", "const query = `SELECT * FROM users WHERE id = ${userInput}`;", "javascript"),
        
        // Printf-style variant
        ("Printf Style", "sprintf(query, \"SELECT * FROM users WHERE id = %s\", user_id);", "c"),
        
        // Python f-string variant
        ("F-String Variant", "query = f\"SELECT * FROM users WHERE id = {user_id}\"", "python"),
    ];

    for (name, code, language) in test_cases {
        println!("   Testing: {}", name);
        let result = engine.find_similar_vulnerabilities(code, language).await?;
        
        if !result.matches.is_empty() {
            let best_match = &result.matches[0];
            println!("   ✅ Found similarity: {:.3} ({})", 
                best_match.similarity_score, 
                format_variation_type(&best_match.variation_type)
            );
            println!("      Explanation: {}", best_match.explanation);
        } else {
            println!("   ❌ No similarities detected");
        }
    }

    Ok(())
}

/// Demonstrate cross-language similarity detection
async fn await_demo_cross_language_similarity(engine: &SemanticSimilarityEngine) -> Result<(), Box<dyn std::error::Error>> {
    let test_cases = vec![
        // JavaScript XSS
        ("JavaScript XSS", "element.innerHTML = userInput;", "javascript"),
        
        // Java equivalent
        ("Java Equivalent", "response.getWriter().write(userInput);", "java"),
        
        // Python equivalent
        ("Python Flask", "return render_template_string(user_template)", "python"),
        
        // PHP equivalent
        ("PHP Echo", "echo $_GET['input'];", "php"),
    ];

    for (name, code, language) in test_cases {
        println!("   Testing: {} ({})", name, language);
        let result = engine.find_similar_vulnerabilities(code, language).await?;
        
        if !result.matches.is_empty() {
            let best_match = &result.matches[0];
            println!("   ✅ Cross-language match: {:.3}", best_match.similarity_score);
            println!("      Original: {} -> Current: {}", 
                best_match.vulnerability.embedding.language, language);
        } else {
            println!("   ❌ No cross-language similarities found");
        }
    }

    Ok(())
}

/// Demonstrate obfuscated pattern detection
async fn await_demo_obfuscated_patterns(engine: &SemanticSimilarityEngine) -> Result<(), Box<dyn std::error::Error>> {
    let test_cases = vec![
        // Normal SQL injection
        ("Normal", "query = \"SELECT * FROM users WHERE id = \" + id", "javascript"),
        
        // Variable renaming obfuscation
        ("Renamed Variables", "q = \"SELECT * FROM users WHERE id = \" + u", "javascript"),
        
        // String concatenation obfuscation
        ("Concatenation Obfuscation", "query = \"SELECT * FROM \" + \"users WHERE \" + \"id = \" + id", "javascript"),
        
        // Base64 obfuscation (conceptual)
        ("Encoding Obfuscation", "query = decode(\"U0VMRUNUICogRlJPTSB1c2Vyc\") + id", "javascript"),
        
        // Function call obfuscation
        ("Function Wrapper", "executeQuery(buildUserQuery(id))", "javascript"),
    ];

    for (name, code, language) in test_cases {
        println!("   Testing: {}", name);
        let result = engine.find_similar_vulnerabilities(code, language).await?;
        
        if !result.matches.is_empty() {
            let best_match = &result.matches[0];
            if matches!(best_match.variation_type, VariationType::Obfuscated) {
                println!("   🕵️ Obfuscation detected: {:.3}", best_match.similarity_score);
            } else {
                println!("   ✅ Pattern detected: {:.3} ({})", 
                    best_match.similarity_score,
                    format_variation_type(&best_match.variation_type)
                );
            }
        } else {
            println!("   ❌ Pattern not detected through obfuscation");
        }
    }

    Ok(())
}

/// Demonstrate behavioral equivalence detection
async fn await_demo_behavioral_equivalence(engine: &SemanticSimilarityEngine) -> Result<(), Box<dyn std::error::Error>> {
    let test_cases = vec![
        // Direct buffer copy
        ("Direct Copy", "strcpy(dest, src);", "c"),
        
        // Loop-based copy (behaviorally equivalent)
        ("Loop Copy", "for(int i=0; src[i]; i++) dest[i] = src[i];", "c"),
        
        // Memory copy function
        ("Memory Copy", "memcpy(dest, src, strlen(src));", "c"),
        
        // Unsafe string operation
        ("Unsafe Operation", "sprintf(dest, \"%s\", src);", "c"),
        
        // Different but equivalent unsafe operation
        ("Equivalent Unsafe", "strcat(dest, src);", "c"),
    ];

    for (name, code, language) in test_cases {
        println!("   Testing: {}", name);
        let result = engine.find_similar_vulnerabilities(code, language).await?;
        
        if !result.matches.is_empty() {
            let best_match = &result.matches[0];
            if matches!(best_match.variation_type, VariationType::Behavioral) {
                println!("   🧠 Behavioral equivalence: {:.3}", best_match.similarity_score);
                println!("      Matching features: {:?}", best_match.matching_features);
            } else {
                println!("   ✅ Pattern match: {:.3}", best_match.similarity_score);
            }
        } else {
            println!("   ❌ No behavioral equivalence detected");
        }
    }

    Ok(())
}

/// Generate mock embedding vector for demonstration
fn generate_mock_embedding(pattern_type: &str, size: usize) -> Vec<f64> {
    use std::collections::hash_map::DefaultHasher;
    use std::hash::{Hash, Hasher};
    
    let mut hasher = DefaultHasher::new();
    pattern_type.hash(&mut hasher);
    let seed = hasher.finish();
    
    let mut vector = Vec::with_capacity(size);
    for i in 0..size {
        let val = (seed.wrapping_add(i as u64) as f64).sin().abs();
        vector.push(val);
    }
    
    // Normalize to unit vector
    let magnitude: f64 = vector.iter().map(|x| x * x).sum::<f64>().sqrt();
    if magnitude > 0.0 {
        for val in &mut vector {
            *val /= magnitude;
        }
    }
    
    vector
}

/// Format variation type for display
fn format_variation_type(variation_type: &VariationType) -> String {
    match variation_type {
        VariationType::Syntactic => "Syntactic".to_string(),
        VariationType::Semantic => "Semantic".to_string(),
        VariationType::CrossLanguage => "Cross-Language".to_string(),
        VariationType::Obfuscated => "Obfuscated".to_string(),
        VariationType::ControlFlow => "Control Flow".to_string(),
        VariationType::DataFlow => "Data Flow".to_string(),
        VariationType::Behavioral => "Behavioral".to_string(),
    }
}