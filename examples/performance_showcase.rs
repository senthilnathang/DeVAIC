use devaic::{
    PerformanceOptimizer, WorkloadType, AsyncFileScanner, PerformanceMonitor,
    IntelligentCache, OptimizedRegexEngine, SIMDPatternMatcher, CharClass,
    get_global_memory_pools, benchmark_simd_operations, record_metric, time_it,
    Config, Analyzer, Result,
};
use std::path::PathBuf;
use std::time::Instant;
use tokio_stream::StreamExt;

#[tokio::main]
async fn main() -> Result<()> {
    println!("🚀 DeVAIC Performance Showcase");
    println!("==============================\n");

    // Initialize performance monitoring
    let monitor = PerformanceMonitor::new(Default::default());
    
    // 1. Performance Optimizer Demo
    demonstrate_performance_optimizer(&monitor).await?;
    
    // 2. Async Scanner Demo  
    demonstrate_async_scanner(&monitor).await?;
    
    // 3. Intelligent Caching Demo
    demonstrate_intelligent_cache(&monitor).await?;
    
    // 4. Optimized Regex Demo
    demonstrate_optimized_regex(&monitor).await?;
    
    // 5. SIMD Optimizations Demo
    demonstrate_simd_optimizations(&monitor).await?;
    
    // 6. Memory Pool Demo
    demonstrate_memory_pools(&monitor).await?;
    
    // 7. Integrated Performance Test
    demonstrate_integrated_performance(&monitor).await?;
    
    // Final performance report
    print_final_report(&monitor).await;
    
    Ok(())
}

async fn demonstrate_performance_optimizer(monitor: &PerformanceMonitor) -> Result<()> {
    println!("📊 1. Performance Optimizer");
    println!("---------------------------");
    
    // Create optimizer for different workload types
    let workloads = vec![
        (WorkloadType::LargeCodebase, "Large Codebase"),
        (WorkloadType::ManySmallFiles, "Many Small Files"),
        (WorkloadType::CpuIntensive, "CPU Intensive"),
        (WorkloadType::MemoryConstrained, "Memory Constrained"),
    ];
    
    for (workload_type, name) in workloads {
        let optimizer = PerformanceOptimizer::for_workload(workload_type);
        let config = optimizer.optimize_parallel_processing();
        
        println!("  {} Configuration:", name);
        println!("    Threads: {}", config.thread_count);
        println!("    Batch size: {}", config.batch_size);
        println!("    Work stealing: {}", config.work_stealing_enabled);
        
        record_metric!(monitor, "optimizer_threads", config.thread_count as f64, "count");
    }
    
    println!();
    Ok(())
}

async fn demonstrate_async_scanner(monitor: &PerformanceMonitor) -> Result<()> {
    println!("🔄 2. Async File Scanner");
    println!("------------------------");
    
    let config = Config::default();
    let scanner = AsyncFileScanner::new(config)
        .with_concurrency(8)
        .with_progress_callback(|processed, total| {
            if processed % 100 == 0 {
                println!("    Progress: {}/{} files", processed, total);
            }
        });
    
    // Create test directory with sample files
    let test_dir = create_test_files().await?;
    
    let (results, scan_time) = time_it!(monitor, "async_scan", {
        let mut stream = scanner.scan_directory_stream(&test_dir).await?;
        let mut all_vulnerabilities = Vec::new();
        
        while let Some(result) = stream.next().await {
            match result {
                Ok(vulnerabilities) => all_vulnerabilities.extend(vulnerabilities),
                Err(e) => eprintln!("    Scan error: {}", e),
            }
        }
        
        all_vulnerabilities
    });
    
    println!("  Async scan completed:");
    println!("    Files processed: {}", results.len());
    println!("    Scan time: {:?}", scan_time);
    
    // Cleanup
    tokio::fs::remove_dir_all(test_dir).await.ok();
    
    println!();
    Ok(())
}

async fn demonstrate_intelligent_cache(monitor: &PerformanceMonitor) -> Result<()> {
    println!("🧠 3. Intelligent Cache");
    println!("-----------------------");
    
    let cache = IntelligentCache::new(Default::default());
    
    // Simulate cache operations
    let test_data = vec![
        ("file1.py", "print('Hello World')"),
        ("file2.js", "console.log('Hello World');"),
        ("file3.java", "System.out.println(\"Hello World\");"),
        ("file1.py", "print('Hello World')"), // Duplicate for cache hit
    ];
    
    for (filename, content) in test_data {
        let cache_key = devaic::CacheKey::from_file_path(&PathBuf::from(filename));
        
        let (cache_result, lookup_time) = time_it!(monitor, "cache_lookup", {
            cache.get(&cache_key)
        });
        
        if cache_result.is_none() {
            // Cache miss - insert new entry
            let cache_entry = devaic::CacheEntry::new(
                devaic::intelligent_cache::CacheData::FileContent(content.to_string()),
                3600,
            );
            cache.insert(cache_key, cache_entry);
            println!("    Cache MISS for {}: {:?}", filename, lookup_time);
        } else {
            println!("    Cache HIT for {}: {:?}", filename, lookup_time);
        }
    }
    
    let stats = cache.get_stats();
    println!("  Cache Statistics:");
    println!("    Hit rate: {:.1}%", stats.hit_rate * 100.0);
    println!("    Total requests: {}", stats.total_requests);
    
    println!();
    Ok(())
}

async fn demonstrate_optimized_regex(monitor: &PerformanceMonitor) -> Result<()> {
    println!("🔍 4. Optimized Regex Engine");
    println!("----------------------------");
    
    let regex_engine = OptimizedRegexEngine::new();
    
    let test_patterns = vec![
        r"password\s*=\s*[\"']([^\"']+)[\"']",
        r"\b(exec|eval|system)\s*\(",
        r"api[_-]?key\s*[=:]\s*[\"']?([a-zA-Z0-9]{20,})",
        r"(SELECT|INSERT|UPDATE|DELETE).*FROM.*WHERE",
    ];
    
    let test_text = r#"
        password = "secret123"
        api_key = "abc123def456ghi789jkl012"
        exec(user_input)
        SELECT * FROM users WHERE id = 1
    "#;
    
    // Individual pattern compilation and matching
    for pattern in &test_patterns {
        let (regex, compile_time) = time_it!(monitor, "regex_compile", {
            regex_engine.compile_optimized(pattern)?
        });
        
        let (is_match, match_time) = time_it!(monitor, "regex_match", {
            regex.is_match(test_text)
        });
        
        println!("  Pattern: {:.50}...", pattern);
        println!("    Compile time: {:?}", compile_time);
        println!("    Match time: {:?}", match_time);
        println!("    Found match: {}", is_match);
    }
    
    // Batch matching demo
    let test_texts = vec![test_text, "clean code with no issues", test_text];
    let patterns: Vec<String> = test_patterns.iter().map(|p| p.to_string()).collect();
    
    let (batch_results, batch_time) = time_it!(monitor, "regex_batch", {
        regex_engine.batch_match(&patterns, &test_texts)?
    });
    
    println!("  Batch matching ({} patterns × {} texts): {:?}", 
             patterns.len(), test_texts.len(), batch_time);
    println!("    Total matches found: {}", 
             batch_results.iter().flatten().filter(|&&m| m).count());
    
    let stats = regex_engine.get_stats();
    println!("  Regex Engine Stats:");
    println!("    Total compilations: {}", stats.total_compilations);
    println!("    Cache hits: {}", stats.cache_hits);
    println!("    Average compile time: {:.2}ms", stats.average_compilation_time_ms);
    
    println!();
    Ok(())
}

async fn demonstrate_simd_optimizations(monitor: &PerformanceMonitor) -> Result<()> {
    println!("⚡ 5. SIMD Optimizations");
    println!("-----------------------");
    
    // SIMD capability detection
    let pattern_matcher = SIMDPatternMatcher::new();
    let simd_info = pattern_matcher.get_simd_info();
    
    println!("  SIMD Support:");
    println!("    Best instruction set: {}", simd_info.best_instruction_set());
    println!("    AVX2: {}", simd_info.avx2_available);
    println!("    SSE4.2: {}", simd_info.sse42_available);
    
    // SIMD benchmarking
    let (benchmark_results, benchmark_time) = time_it!(monitor, "simd_benchmark", {
        benchmark_simd_operations()
    });
    
    println!("  SIMD Benchmark Results ({}s):", benchmark_time.as_secs_f64());
    benchmark_results.print_results();
    
    // Pattern matching with SIMD
    let test_data = b"Hello world! This is a test of SIMD pattern matching with hello patterns.";
    let pattern = b"hello";
    
    let (matches, search_time) = time_it!(monitor, "simd_pattern_search", {
        devaic::simd_optimizations::simd_ops::find_pattern_simd(test_data, pattern)
    });
    
    println!("  Pattern Search:");
    println!("    Pattern: {:?}", std::str::from_utf8(pattern).unwrap());
    println!("    Matches found: {} positions", matches.len());
    println!("    Search time: {:?}", search_time);
    
    // Character class matching
    let hex_digits = CharClass::hex_digit();
    let digit_positions = devaic::simd_optimizations::simd_ops::match_char_class_simd(
        b"abc123def456", &hex_digits
    );
    println!("    Hex digits found at positions: {:?}", digit_positions);
    
    println!();
    Ok(())
}

async fn demonstrate_memory_pools(monitor: &PerformanceMonitor) -> Result<()> {
    println!("🏊 6. Memory Pools");
    println!("-----------------");
    
    let pools = get_global_memory_pools();
    
    // Demonstrate vulnerability pool
    let (vulnerability_vec, pool_get_time) = time_it!(monitor, "memory_pool_get", {
        pools.vulnerability_pool().get()
    });
    
    println!("  Memory Pool Operations:");
    println!("    Pool get time: {:?}", pool_get_time);
    
    // Use the pooled vector
    {
        let mut vulns = vulnerability_vec;
        for i in 0..100 {
            vulns.push(create_test_vulnerability(format!("vuln_{}", i)));
        }
        println!("    Added {} vulnerabilities to pooled vector", vulns.len());
        // Vector automatically returns to pool when dropped
    }
    
    // String pool demonstration
    let (pooled_string, _) = time_it!(monitor, "string_pool_get", {
        pools.string_pool().get_with_content("test content for pooled string")
    });
    println!("    String pool content: {:.30}...", pooled_string);
    
    // Memory statistics
    let memory_stats = pools.memory_stats();
    memory_stats.print_summary();
    
    println!();
    Ok(())
}

async fn demonstrate_integrated_performance(monitor: &PerformanceMonitor) -> Result<()> {
    println!("🎯 7. Integrated Performance Test");
    println!("--------------------------------");
    
    // Create a comprehensive test that combines all optimizations
    let config = Config::default();
    let analyzer = Analyzer::new(config)?;
    
    // Test with different file sizes and types
    let test_scenarios = vec![
        ("small_files", create_small_test_files().await?),
        ("medium_files", create_medium_test_files().await?),
    ];
    
    for (scenario_name, test_dir) in test_scenarios {
        println!("  Scenario: {}", scenario_name);
        
        // Warm up caches
        let _ = analyzer.analyze_directory(&test_dir)?;
        
        // Actual performance test
        let (vulnerabilities, analysis_time) = time_it!(monitor, 
            &format!("integrated_{}", scenario_name), {
            analyzer.analyze_directory(&test_dir)?
        });
        
        println!("    Analysis time: {:?}", analysis_time);
        println!("    Vulnerabilities found: {}", vulnerabilities.len());
        println!("    Throughput: {:.1} files/sec", 
                 10.0 / analysis_time.as_secs_f64()); // Assuming 10 files per scenario
        
        // Cache statistics
        let cache_stats = analyzer.get_cache_stats();
        println!("    Cache entries: {}", cache_stats.file_metadata_entries);
        
        // Cleanup
        tokio::fs::remove_dir_all(test_dir).await.ok();
    }
    
    println!();
    Ok(())
}

async fn print_final_report(monitor: &PerformanceMonitor) {
    println!("📈 Final Performance Report");
    println!("===========================");
    
    let report = monitor.generate_report();
    println!("  Uptime: {}s", report.uptime_seconds);
    println!("  Total metrics collected: {}", report.summary.total_metrics);
    println!("  Benchmarks run: {}", report.summary.total_benchmarks);
    
    // Print top metrics by value
    let mut metric_values: Vec<_> = report.metrics.iter()
        .map(|(name, series)| (name, series.statistics.mean))
        .collect();
    metric_values.sort_by(|a, b| b.1.partial_cmp(&a.1).unwrap());
    
    println!("\n  Top Metrics:");
    for (name, value) in metric_values.iter().take(5) {
        println!("    {}: {:.2}", name, value);
    }
    
    // System resource usage
    let system_metrics = report.system_metrics;
    println!("\n  System Resources:");
    println!("    Memory usage: {:.1} MB", system_metrics.memory_usage_mb);
    println!("    CPU utilization: {:.1}%", system_metrics.cpu_usage_percent);
    println!("    Thread count: {}", system_metrics.thread_count);
}

// Helper functions for creating test files and data

async fn create_test_files() -> Result<PathBuf> {
    let test_dir = std::env::temp_dir().join("devaic_perf_test");
    tokio::fs::create_dir_all(&test_dir).await?;
    
    let test_files = vec![
        ("test1.py", "import os\npassword = 'secret123'\nexec(user_input)"),
        ("test2.js", "const api_key = 'abc123def456';\nconsole.log(user_data);"),
        ("test3.java", "String password = \"hardcoded\";\nSystem.out.println(userInput);"),
    ];
    
    for (filename, content) in test_files {
        let file_path = test_dir.join(filename);
        tokio::fs::write(file_path, content).await?;
    }
    
    Ok(test_dir)
}

async fn create_small_test_files() -> Result<PathBuf> {
    let test_dir = std::env::temp_dir().join("devaic_small_test");
    tokio::fs::create_dir_all(&test_dir).await?;
    
    for i in 0..10 {
        let filename = format!("small_{}.py", i);
        let content = format!("# Small test file {}\nprint('Hello {}')", i, i);
        tokio::fs::write(test_dir.join(filename), content).await?;
    }
    
    Ok(test_dir)
}

async fn create_medium_test_files() -> Result<PathBuf> {
    let test_dir = std::env::temp_dir().join("devaic_medium_test");
    tokio::fs::create_dir_all(&test_dir).await?;
    
    for i in 0..10 {
        let filename = format!("medium_{}.py", i);
        let mut content = format!("# Medium test file {}\n", i);
        
        // Add more content to make it "medium" sized
        for j in 0..50 {
            content.push_str(&format!("def function_{}():\n    pass\n", j));
        }
        
        tokio::fs::write(test_dir.join(filename), content).await?;
    }
    
    Ok(test_dir)
}

fn create_test_vulnerability(id: String) -> devaic::Vulnerability {
    devaic::Vulnerability {
        id,
        vulnerability_type: "Test Vulnerability".to_string(),
        severity: devaic::Severity::Medium,
        category: "test".to_string(),
        description: "Test vulnerability for performance demo".to_string(),
        file_path: "test.py".to_string(),
        line_number: 1,
        column: 1,
        source_code: "test code".to_string(),
        recommendation: "Fix this test issue".to_string(),
        cwe: Some("CWE-000".to_string()),
    }
}