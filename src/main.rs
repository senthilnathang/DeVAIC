use clap::{Parser, ValueEnum};
use devaic::{Analyzer, Config, Report, Result};
use std::path::PathBuf;
use std::time::Instant;

#[derive(Parser)]
#[command(name = "devaic")]
#[command(about = "DeVAIC - Static code analyzer for vulnerability detection in embedded C, Python, and SCADA programming")]
#[command(version = "0.1.0")]
struct Cli {
    /// Target directory or file to analyze
    #[arg(value_name = "PATH")]
    target: PathBuf,

    /// Output format
    #[arg(short, long, default_value = "table")]
    format: OutputFormat,

    /// Output file (if not specified, prints to stdout)
    #[arg(short, long)]
    output: Option<PathBuf>,

    /// Configuration file path
    #[arg(short, long)]
    config: Option<PathBuf>,

    /// Severity threshold (only report vulnerabilities at or above this level)
    #[arg(short, long, default_value = "low")]
    severity: String,

    /// Enable verbose output
    #[arg(short, long)]
    verbose: bool,

    /// Disable colored output
    #[arg(long)]
    no_color: bool,

    /// Categories to analyze (comma-separated)
    #[arg(long)]
    categories: Option<String>,

    /// Maximum file size to analyze (in bytes)
    #[arg(long, default_value = "10485760")] // 10MB
    max_file_size: usize,

    /// Use Semgrep-style rules
    #[arg(long)]
    semgrep: bool,

    /// Directory containing Semgrep YAML rules
    #[arg(long)]
    rules_dir: Option<PathBuf>,
}

#[derive(Clone, ValueEnum)]
enum OutputFormat {
    Table,
    Json,
    Sarif,
    Excel,
    Pdf,
}

fn main() -> Result<()> {
    env_logger::init();
    
    let cli = Cli::parse();
    
    // Load configuration
    let mut config = if let Some(config_path) = &cli.config {
        Config::load_from_file(&config_path.to_string_lossy())?
    } else {
        Config::default()
    };

    // Override config with CLI arguments
    config.rules.severity_threshold = cli.severity.to_uppercase();
    config.output.verbose = cli.verbose;
    config.output.colors = !cli.no_color;
    config.analysis.max_file_size = cli.max_file_size;

    if let Some(categories) = &cli.categories {
        config.rules.enabled_categories = categories
            .split(',')
            .map(|s| s.trim().to_string())
            .collect();
    }

    // Initialize analyzer
    let analyzer = Analyzer::new(config.clone());
    
    if cli.verbose {
        println!("Starting analysis of: {}", cli.target.display());
    }

    let start_time = Instant::now();
    
    // Perform analysis
    let vulnerabilities = if cli.semgrep {
        // Use Semgrep-style analysis
        run_semgrep_analysis(&cli, &config)?
    } else {
        // Use traditional analysis
        if cli.target.is_file() {
            analyzer.analyze_file(&cli.target)?
        } else {
            analyzer.analyze_directory(&cli.target)?
        }
    };

    let analysis_duration = start_time.elapsed();
    
    // Count analyzed files
    let files_analyzed = if cli.target.is_file() {
        1
    } else {
        count_analyzed_files(&cli.target, &config)
    };

    // Generate report
    let mut report = Report::new(vulnerabilities, files_analyzed);
    report.set_duration(analysis_duration);

    // Output report
    let output_content = match cli.format {
        OutputFormat::Table => report.to_table(config.output.colors),
        OutputFormat::Json => report.to_json()?,
        OutputFormat::Sarif => report.to_sarif()?,
        OutputFormat::Excel => {
            if let Some(output_path) = &cli.output {
                report.to_excel(output_path)?;
                format!("Excel report written to: {}", output_path.display())
            } else {
                return Err(devaic::DevaicError::Config(
                    "Excel format requires --output parameter".to_string()
                ).into());
            }
        }
        OutputFormat::Pdf => {
            if let Some(output_path) = &cli.output {
                report.to_pdf(output_path)?;
                format!("PDF report written to: {}", output_path.display())
            } else {
                return Err(devaic::DevaicError::Config(
                    "PDF format requires --output parameter".to_string()
                ).into());
            }
        }
    };

    if let Some(output_path) = &cli.output {
        match cli.format {
            OutputFormat::Excel | OutputFormat::Pdf => {
                // Already handled above, just print the output content
                if cli.verbose {
                    println!("{}", output_content);
                }
            }
            _ => {
                std::fs::write(output_path, &output_content)?;
                if cli.verbose {
                    println!("Report written to: {}", output_path.display());
                }
            }
        }
    } else {
        println!("{}", output_content);
    }

    // Exit with non-zero code if critical or high vulnerabilities found
    let has_critical_issues = report.vulnerabilities.iter().any(|v| {
        matches!(v.severity, devaic::Severity::Critical | devaic::Severity::High)
    });

    if has_critical_issues {
        std::process::exit(1);
    }

    Ok(())
}

fn count_analyzed_files(path: &PathBuf, config: &Config) -> usize {
    use walkdir::WalkDir;
    
    WalkDir::new(path)
        .follow_links(config.analysis.follow_symlinks)
        .into_iter()
        .filter_map(|e| e.ok())
        .filter(|entry| entry.file_type().is_file())
        .filter(|entry| would_analyze_file(entry.path(), config))
        .count()
}

fn would_analyze_file(path: &std::path::Path, config: &Config) -> bool {
    // Use the exact same logic as analyze_file to determine if a file would be analyzed
    
    // First check if file has extension (same as analyze_file)
    let extension = match path.extension().and_then(|ext| ext.to_str()) {
        Some(ext) => ext,
        None => return false, // Skip files without extensions (same as analyze_file)
    };

    // Check if language is supported (same as analyze_file)
    if devaic::Language::from_extension(extension).is_none() {
        return false; // Skip files with unsupported extensions (same as analyze_file)
    }

    // Check file size (same as analyze_file)
    if let Ok(metadata) = std::fs::metadata(path) {
        if metadata.len() as usize > config.analysis.max_file_size {
            return false; // Skip files that exceed size limit (same as analyze_file)
        }
    }

    // Check exclude/include patterns
    let path_str = path.to_string_lossy();
    
    // Check exclude patterns
    for pattern in &config.analysis.exclude_patterns {
        if glob::Pattern::new(pattern)
            .map(|p| p.matches(&path_str))
            .unwrap_or(false)
        {
            return false;
        }
    }

    // Check include patterns
    if !config.analysis.include_patterns.is_empty() {
        for pattern in &config.analysis.include_patterns {
            if glob::Pattern::new(pattern)
                .map(|p| p.matches(&path_str))
                .unwrap_or(false)
            {
                return true;
            }
        }
        return false;
    }

    true
}

fn run_semgrep_analysis(cli: &Cli, config: &Config) -> Result<Vec<devaic::Vulnerability>> {
    use devaic::semgrep::SemgrepEngine;
    use walkdir::WalkDir;
    
    let mut engine = SemgrepEngine::new();
    
    // Load rules from directory
    let default_rules_dir = PathBuf::from("rules");
    let rules_dir = cli.rules_dir.as_ref()
        .unwrap_or(&default_rules_dir);
    
    if rules_dir.exists() {
        match engine.load_rules_from_directory(rules_dir) {
            Ok(count) => {
                if cli.verbose {
                    println!("Loaded {} Semgrep rules from {}", count, rules_dir.display());
                }
            }
            Err(e) => {
                eprintln!("Warning: Failed to load Semgrep rules: {}", e);
            }
        }
    } else if cli.verbose {
        println!("Rules directory {} not found, using built-in rules", rules_dir.display());
    }
    
    // Validate rules
    if let Err(errors) = engine.validate_rules() {
        eprintln!("Rule validation errors:");
        for error in errors {
            eprintln!("  {}", error);
        }
        return Err(devaic::DevaicError::Config(
            "Rule validation failed".to_string()
        ).into());
    }
    
    if cli.verbose {
        let stats = engine.get_rule_statistics();
        stats.print_summary();
    }
    
    // Pre-allocate vulnerabilities vector based on file count
    let mut all_vulnerabilities = if cli.target.is_file() {
        Vec::with_capacity(10) // Single file, assume ~10 vulnerabilities
    } else {
        // Count files to estimate capacity
        let file_count = WalkDir::new(&cli.target)
            .follow_links(config.analysis.follow_symlinks)
            .into_iter()
            .filter_map(|e| e.ok())
            .filter(|entry| entry.file_type().is_file())
            .filter(|entry| would_analyze_file(entry.path(), config))
            .count();
        Vec::with_capacity(file_count * 5) // Estimate 5 vulnerabilities per file
    };
    
    // Analyze files
    if cli.target.is_file() {
        if let Some(vuln) = analyze_file_with_semgrep(&cli.target, &engine, config)? {
            all_vulnerabilities.extend(vuln);
        }
    } else {
        // Analyze directory
        for entry in WalkDir::new(&cli.target)
            .follow_links(config.analysis.follow_symlinks)
            .into_iter()
            .filter_map(|e| e.ok())
            .filter(|entry| entry.file_type().is_file())
            .filter(|entry| would_analyze_file(entry.path(), config))
        {
            if let Some(vulns) = analyze_file_with_semgrep(entry.path(), &engine, config)? {
                all_vulnerabilities.extend(vulns);
            }
        }
    }
    
    Ok(all_vulnerabilities)
}

// Simple AST representation for Semgrep analysis
struct SimpleParsedAst {
    source: String,
}

impl devaic::semgrep::engine::AstLike for SimpleParsedAst {
    fn source(&self) -> &str {
        &self.source
    }
    
    fn root_node(&self) -> () {
        // Simplified for demo - real implementation would return tree-sitter Node
    }
}

fn analyze_file_with_semgrep(
    file_path: &std::path::Path, 
    engine: &devaic::semgrep::SemgrepEngine,
    config: &Config,
) -> Result<Option<Vec<devaic::Vulnerability>>> {
    use devaic::{Language, parsers::SourceFile};
    
    // Determine language from extension
    let extension = match file_path.extension().and_then(|ext| ext.to_str()) {
        Some(ext) => ext,
        None => return Ok(None),
    };
    
    let language = match Language::from_extension(extension) {
        Some(lang) => lang,
        None => return Ok(None),
    };
    
    // Read file
    let content = match std::fs::read_to_string(file_path) {
        Ok(content) => content,
        Err(e) => {
            eprintln!("Warning: Failed to read {}: {}", file_path.display(), e);
            return Ok(None);
        }
    };
    
    // Check file size limit
    if content.len() > config.analysis.max_file_size {
        eprintln!("Warning: File {} exceeds maximum size limit ({} bytes), skipping", 
                 file_path.display(), config.analysis.max_file_size);
        return Ok(None);
    }
    
    // Create source file
    let source_file = SourceFile::new(file_path.to_path_buf(), content, language);
    
    // For Semgrep analysis, we create a simple AST representation
    // In a full implementation, this would use proper tree-sitter parsing
    let ast = SimpleParsedAst {
        source: source_file.content.clone(),
    };
    
    // Analyze with Semgrep engine
    match engine.analyze_file(&source_file, &ast) {
        Ok(semgrep_vulns) => {
            let vulnerabilities: Vec<devaic::Vulnerability> = semgrep_vulns
                .into_iter()
                .map(|v| v.to_vulnerability())
                .collect();
            Ok(Some(vulnerabilities))
        }
        Err(e) => {
            eprintln!("Warning: Semgrep analysis failed for {}: {}", file_path.display(), e);
            Ok(None)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;
    use tempfile::TempDir;

    #[test]
    fn test_file_counting() {
        let temp_dir = TempDir::new().unwrap();
        let temp_path = temp_dir.path();

        // Create test files
        fs::write(temp_path.join("test.c"), "int main() { return 0; }").unwrap();
        fs::write(temp_path.join("test.py"), "print('hello')").unwrap();
        fs::write(temp_path.join("test.java"), "public class Test {}").unwrap();
        fs::write(temp_path.join("test.txt"), "not code").unwrap();
        fs::write(temp_path.join("noext"), "no extension").unwrap();

        let config = Config::default();
        let count = count_analyzed_files(&temp_path.to_path_buf(), &config);
        
        // Should count only .c, .py, and .java files (supported languages), not .txt or files without extensions
        assert_eq!(count, 3);
    }

    #[test]
    fn test_would_analyze_file() {
        let temp_dir = TempDir::new().unwrap();
        let temp_path = temp_dir.path();
        
        // Create test files
        fs::write(temp_path.join("test.c"), "int main() { return 0; }").unwrap();
        fs::write(temp_path.join("test.py"), "print('hello')").unwrap();
        fs::write(temp_path.join("test.java"), "public class Test {}").unwrap();
        fs::write(temp_path.join("test.txt"), "not code").unwrap();
        fs::write(temp_path.join("noext"), "no extension").unwrap();
        
        let config = Config::default();
        
        // Test supported extensions
        assert!(would_analyze_file(&temp_path.join("test.c"), &config));
        assert!(would_analyze_file(&temp_path.join("test.py"), &config));
        assert!(would_analyze_file(&temp_path.join("test.java"), &config));
        
        // Test unsupported extensions
        assert!(!would_analyze_file(&temp_path.join("test.txt"), &config));
        assert!(!would_analyze_file(&temp_path.join("noext"), &config));
    }
}