/// Incremental Analysis Demo for DeVAIC
/// 
/// This example demonstrates the incremental analysis capabilities that dramatically
/// improve performance for large codebases and CI/CD pipelines by only analyzing
/// changed files and their dependencies.

use devaic::{
    config::Config, 
    analyzer::Analyzer,
    incremental_analysis::{IncrementalAnalysisEngine, IncrementalConfig, AnalysisType},
    Severity,
};
use std::{
    fs,
    path::Path,
    time::{Duration, Instant},
};
use tempfile::TempDir;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    println!("🚀 DeVAIC Incremental Analysis Demo");
    println!("{}", "=".repeat(60));
    
    // Create a temporary project directory for demonstration
    let temp_dir = TempDir::new()?;
    let project_path = temp_dir.path();
    
    println!("\n📁 Setting up demo project at: {}", project_path.display());
    
    // Create sample project structure
    create_demo_project(project_path)?;
    
    // Initialize analyzer and incremental engine
    let config = Config::default();
    let analyzer = Analyzer::new(config)?;
    
    let incremental_config = IncrementalConfig {
        enabled: true,
        state_file_path: project_path.join(".devaic_incremental.json"),
        max_state_age_seconds: 3600, // 1 hour
        force_full_analysis_patterns: vec![
            "*.config".to_string(),
            "package.json".to_string(),
        ],
        excluded_directories: vec![
            ".git".to_string(),
            "node_modules".to_string(),
        ],
        include_dependency_analysis: true,
        compress_state: false, // For demo clarity
    };
    
    let mut incremental_engine = IncrementalAnalysisEngine::new(incremental_config, analyzer)?;
    
    // Demonstration 1: Initial Full Analysis
    println!("\n📊 Demonstration 1: Initial Full Analysis");
    println!("{}", "-".repeat(60));
    
    let start_time = Instant::now();
    let result1 = incremental_engine.analyze_directory_incremental(project_path).await?;
    let duration1 = start_time.elapsed();
    
    print_analysis_results(&result1, duration1, "Initial Analysis");
    
    // Demonstration 2: No Changes - Cached Results
    println!("\n📊 Demonstration 2: No Changes - Using Cached Results");
    println!("{}", "-".repeat(60));
    
    let start_time = Instant::now();
    let result2 = incremental_engine.analyze_directory_incremental(project_path).await?;
    let duration2 = start_time.elapsed();
    
    print_analysis_results(&result2, duration2, "Cached Analysis");
    
    // Demonstration 3: Modify a File
    println!("\n📊 Demonstration 3: File Modification - Incremental Analysis");
    println!("{}", "-".repeat(60));
    
    // Modify a Python file to introduce a vulnerability
    let python_file = project_path.join("src/auth.py");
    fs::write(&python_file, r#"
import sqlite3

def authenticate_user(username, password):
    # SQL Injection vulnerability added
    query = "SELECT * FROM users WHERE username = '" + username + "' AND password = '" + password + "'"
    conn = sqlite3.connect('users.db')
    cursor = conn.cursor()
    cursor.execute(query)
    result = cursor.fetchone()
    conn.close()
    return result is not None

def validate_input(data):
    # XSS vulnerability added
    return "<div>" + data + "</div>"
"#)?;
    
    println!("✏️  Modified src/auth.py to introduce vulnerabilities");
    
    let start_time = Instant::now();
    let result3 = incremental_engine.analyze_directory_incremental(project_path).await?;
    let duration3 = start_time.elapsed();
    
    print_analysis_results(&result3, duration3, "After File Modification");
    
    // Demonstration 4: Add New File
    println!("\n📊 Demonstration 4: New File Addition");
    println!("{}", "-".repeat(60));
    
    let new_file = project_path.join("src/crypto.py");
    fs::write(&new_file, r#"
import hashlib

def weak_hash(password):
    # Weak cryptographic algorithm
    return hashlib.md5(password.encode()).hexdigest()

def insecure_random():
    # Weak random number generation
    import random
    return random.randint(1000, 9999)
"#)?;
    
    println!("➕ Added new file src/crypto.py with crypto vulnerabilities");
    
    let start_time = Instant::now();
    let result4 = incremental_engine.analyze_directory_incremental(project_path).await?;
    let duration4 = start_time.elapsed();
    
    print_analysis_results(&result4, duration4, "After Adding New File");
    
    // Demonstration 5: Dependency Impact Analysis
    println!("\n📊 Demonstration 5: Dependency Impact Analysis");
    println!("{}", "-".repeat(60));
    
    // Modify a file that others depend on
    let config_file = project_path.join("src/config.py");
    fs::write(&config_file, r#"
# Configuration module with security issues
DEBUG = True  # Security risk in production
SECRET_KEY = "hardcoded_secret_123"  # Hardcoded secret
DATABASE_URL = "sqlite:///app.db?password=admin123"  # Exposed credentials

def get_config():
    return {
        'debug': DEBUG,
        'secret': SECRET_KEY,
        'db_url': DATABASE_URL
    }
"#)?;
    
    println!("🔧 Modified src/config.py (a dependency file)");
    
    let start_time = Instant::now();
    let result5 = incremental_engine.analyze_directory_incremental(project_path).await?;
    let duration5 = start_time.elapsed();
    
    print_analysis_results(&result5, duration5, "Dependency Impact Analysis");
    
    // Show Performance Comparison
    println!("\n⚡ Performance Comparison");
    println!("{}", "=".repeat(60));
    
    let speedup_vs_full = if duration1.as_millis() > 0 {
        duration1.as_millis() as f64 / duration3.as_millis() as f64
    } else {
        1.0
    };
    
    println!("Initial Full Analysis:     {:>8}ms", duration1.as_millis());
    println!("Cached Analysis:           {:>8}ms", duration2.as_millis());
    println!("Incremental Analysis:      {:>8}ms", duration3.as_millis());
    println!("New File Analysis:         {:>8}ms", duration4.as_millis());
    println!("Dependency Impact:         {:>8}ms", duration5.as_millis());
    println!("Speedup vs Full Analysis:  {:>8.1}x", speedup_vs_full);
    
    // Show Statistics
    if let Some(stats) = incremental_engine.get_statistics() {
        println!("\n📈 Incremental Analysis Statistics");
        println!("{}", "-".repeat(60));
        println!("Total Analyses:            {:>8}", stats.total_analyses);
        println!("Full Analyses:             {:>8}", stats.full_analyses);
        println!("Incremental Analyses:      {:>8}", stats.incremental_analyses);
        println!("Files Analyzed:            {:>8}", stats.files_analyzed);
        println!("Files Skipped:             {:>8}", stats.files_skipped);
        println!("Cache Hit Rate:            {:>7.1}%", stats.cache_hit_rate * 100.0);
        println!("Time Saved:                {:>8}ms", stats.time_saved_ms);
        println!("Avg Analysis Time:         {:>7.1}ms", stats.average_analysis_time_ms);
    }
    
    // Show Key Benefits
    println!("\n🎯 Key Benefits Demonstrated");
    println!("{}", "=".repeat(60));
    println!("✅ Dramatically faster analysis for large codebases");
    println!("✅ Intelligent change detection using file hashes");
    println!("✅ Dependency impact analysis for cascading changes");
    println!("✅ Persistent state management across analysis runs");
    println!("✅ Configurable cache invalidation strategies");
    println!("✅ Perfect for CI/CD pipelines and development workflows");
    
    // Show Use Cases
    println!("\n🔧 Ideal Use Cases");
    println!("{}", "-".repeat(60));
    println!("• Pre-commit hooks in Git workflows");
    println!("• Continuous Integration (CI) security scans");
    println!("• IDE integration for real-time analysis");
    println!("• Large monorepo security monitoring");
    println!("• Incremental security reviews");
    println!("• Developer productivity enhancement");
    
    println!("\n✅ Incremental Analysis Demo completed successfully!");
    println!("💡 This system enables DeVAIC to scale to massive codebases");
    println!("   while maintaining fast response times for developers.");
    
    Ok(())
}

fn create_demo_project(project_path: &Path) -> Result<(), Box<dyn std::error::Error>> {
    // Create directory structure
    let src_dir = project_path.join("src");
    let tests_dir = project_path.join("tests");
    fs::create_dir_all(&src_dir)?;
    fs::create_dir_all(&tests_dir)?;
    
    // Create Python files
    fs::write(src_dir.join("main.py"), r#"
import config
import auth

def main():
    print("Demo application starting...")
    user_authenticated = auth.authenticate_user("admin", "password")
    if user_authenticated:
        config_data = config.get_config()
        print(f"Config loaded: {config_data}")
    else:
        print("Authentication failed")

if __name__ == "__main__":
    main()
"#)?;
    
    fs::write(src_dir.join("auth.py"), r#"
def authenticate_user(username, password):
    # Simple authentication (will be modified later)
    return username == "admin" and password == "password"

def validate_input(data):
    # Basic input validation
    return data.strip()
"#)?;
    
    fs::write(src_dir.join("config.py"), r#"
# Configuration module
DEBUG = False
SECRET_KEY = "change_me_in_production"

def get_config():
    return {
        'debug': DEBUG,
        'secret': SECRET_KEY
    }
"#)?;
    
    // Create JavaScript files
    fs::write(src_dir.join("app.js"), r#"
const express = require('express');
const app = express();

app.get('/', (req, res) => {
    res.send('Hello World!');
});

app.listen(3000, () => {
    console.log('Server running on port 3000');
});
"#)?;
    
    // Create test files
    fs::write(tests_dir.join("test_auth.py"), r#"
import unittest
from src.auth import authenticate_user

class TestAuth(unittest.TestCase):
    def test_valid_user(self):
        self.assertTrue(authenticate_user("admin", "password"))
    
    def test_invalid_user(self):
        self.assertFalse(authenticate_user("user", "wrong"))

if __name__ == "__main__":
    unittest.main()
"#)?;
    
    // Create package.json
    fs::write(project_path.join("package.json"), r#"{
  "name": "demo-app",
  "version": "1.0.0",
  "description": "Demo application for incremental analysis",
  "main": "src/app.js",
  "scripts": {
    "start": "node src/app.js",
    "test": "python -m pytest tests/"
  },
  "dependencies": {
    "express": "^4.18.0"
  }
}
"#)?;
    
    // Create .gitignore
    fs::write(project_path.join(".gitignore"), r#"
node_modules/
*.pyc
__pycache__/
.pytest_cache/
*.log
"#)?;
    
    println!("✅ Created demo project with {} files", count_files(project_path));
    
    Ok(())
}

fn count_files(path: &Path) -> usize {
    walkdir::WalkDir::new(path)
        .into_iter()
        .filter_map(|e| e.ok())
        .filter(|e| e.file_type().is_file())
        .count()
}

fn print_analysis_results(
    result: &devaic::incremental_analysis::IncrementalAnalysisResult, 
    duration: Duration,
    title: &str
) {
    println!("📊 {}", title);
    println!("   Analysis Type: {:?}", result.analysis_type);
    println!("   Duration: {}ms", duration.as_millis());
    println!("   Vulnerabilities Found: {}", result.vulnerabilities.len());
    println!("   Changed Files: {}", result.changed_files.len());
    println!("   Skipped Files: {}", result.skipped_files.len());
    
    if !result.dependency_affected_files.is_empty() {
        println!("   Dependency Affected Files: {}", result.dependency_affected_files.len());
    }
    
    // Show vulnerability breakdown by severity
    let mut critical = 0;
    let mut high = 0;
    let mut medium = 0;
    let mut low = 0;
    let mut info = 0;
    
    for vuln in &result.vulnerabilities {
        match vuln.severity {
            Severity::Critical => critical += 1,
            Severity::High => high += 1,
            Severity::Medium => medium += 1,
            Severity::Low => low += 1,
            Severity::Info => info += 1,
        }
    }
    
    if result.vulnerabilities.len() > 0 {
        println!("   Severity Breakdown:");
        if critical > 0 { println!("     🔴 Critical: {}", critical); }
        if high > 0 { println!("     🟠 High: {}", high); }
        if medium > 0 { println!("     🟡 Medium: {}", medium); }
        if low > 0 { println!("     🟢 Low: {}", low); }
        if info > 0 { println!("     ℹ️  Info: {}", info); }
    }
    
    // Show cache efficiency for incremental analyses
    match result.analysis_type {
        AnalysisType::Incremental if result.skipped_files.len() > 0 => {
            let total_files = result.changed_files.len() + result.skipped_files.len();
            let cache_efficiency = (result.skipped_files.len() as f64 / total_files as f64) * 100.0;
            println!("   🚀 Cache Efficiency: {:.1}%", cache_efficiency);
        }
        _ => {}
    }
}