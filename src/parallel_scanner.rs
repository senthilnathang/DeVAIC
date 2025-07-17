use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::Instant;
use rayon::prelude::*;
use crate::cache::{get_global_cache, CachedFileWalker};
use crate::optimized_reader::OptimizedFileReader;
use crate::fast_walker::OptimizedDirectoryScanner;
use crate::{Language, Vulnerability, config::Config};

/// Parallel directory scanner with optimized performance
pub struct ParallelDirectoryScanner {
    config: Arc<Config>,
    thread_pool_size: usize,
    cache_enabled: bool,
    batch_size: usize,
    max_depth: usize,
    use_fast_walker: bool,
}

impl ParallelDirectoryScanner {
    pub fn new(config: Config, thread_pool_size: Option<usize>, cache_enabled: bool, max_depth: Option<usize>, use_fast_walker: Option<bool>) -> Self {
        let pool_size = thread_pool_size.unwrap_or_else(|| {
            std::thread::available_parallelism()
                .map(|n| n.get())
                .unwrap_or(4)
        });

        Self {
            config: Arc::new(config),
            thread_pool_size: pool_size,
            cache_enabled,
            batch_size: 100, // Process files in batches of 100
            max_depth: max_depth.unwrap_or(100),
            use_fast_walker: use_fast_walker.unwrap_or(true),
        }
    }

    /// Scan directory with parallel processing
    pub fn scan_directory(&self, path: &Path) -> crate::Result<ScanResults> {
        let start_time = Instant::now();
        
        // Step 1: Collect all files to analyze using optimized walker
        let files = if self.use_fast_walker {
            let scanner = OptimizedDirectoryScanner::new(
                self.config.analysis.follow_symlinks,
                self.config.analysis.max_file_size,
                self.max_depth,
                self.config.analysis.exclude_patterns.clone(),
                self.config.analysis.include_patterns.clone(),
                self.cache_enabled,
                self.batch_size,
            );
            scanner.scan_directory(path)
        } else {
            // Fallback to cached walker
            let walker = CachedFileWalker::new(
                self.config.analysis.follow_symlinks,
                self.config.analysis.max_file_size,
                self.config.analysis.exclude_patterns.clone(),
                self.config.analysis.include_patterns.clone(),
                self.max_depth,
            );
            walker.walk_directory(path)
        };
        
        log::info!("Found {} files to analyze", files.len());

        // Step 2: Process files in parallel batches
        let all_vulnerabilities = self.process_files_parallel(&files)?;
        
        let scan_time = start_time.elapsed();
        
        Ok(ScanResults {
            vulnerabilities: all_vulnerabilities,
            files_scanned: files.len(),
            scan_time_ms: scan_time.as_millis() as u64,
            cache_hits: 0, // TODO: Implement cache hit tracking
        })
    }

    /// Process files in parallel with batching
    fn process_files_parallel(&self, files: &[PathBuf]) -> crate::Result<Vec<Vulnerability>> {
        // Configure rayon thread pool
        let pool = rayon::ThreadPoolBuilder::new()
            .num_threads(self.thread_pool_size)
            .build()
            .map_err(|e| crate::DevaicError::Analysis(format!("Failed to create thread pool: {}", e)))?;

        pool.install(|| {
            // Process files in parallel batches
            let vulnerabilities: Vec<Vec<Vulnerability>> = files
                .par_chunks(self.batch_size)
                .map(|chunk| self.process_file_batch(chunk))
                .collect::<Result<Vec<_>, _>>()?;

            // Flatten results
            Ok(vulnerabilities.into_iter().flatten().collect())
        })
    }

    /// Process a batch of files
    fn process_file_batch(&self, files: &[PathBuf]) -> crate::Result<Vec<Vulnerability>> {
        let mut batch_vulnerabilities = Vec::new();
        let reader = OptimizedFileReader::new(self.cache_enabled);

        for file_path in files {
            match self.analyze_single_file(file_path, &reader) {
                Ok(mut vulnerabilities) => {
                    batch_vulnerabilities.append(&mut vulnerabilities);
                }
                Err(e) => {
                    log::debug!("Skipped file {}: {}", file_path.display(), e);
                }
            }
        }

        Ok(batch_vulnerabilities)
    }

    /// Analyze a single file
    fn analyze_single_file(&self, path: &Path, reader: &OptimizedFileReader) -> crate::Result<Vec<Vulnerability>> {
        // Get language from extension with caching
        let language = self.get_language_for_file(path)?;
        
        // Read file content with optimal strategy
        let content = reader.read_file(path)
            .map_err(|e| crate::DevaicError::Analysis(format!("Failed to read file {}: {}", path.display(), e)))?;

        // Check cache for content changes
        if self.cache_enabled {
            let cache = get_global_cache();
            if !cache.has_content_changed(path, &content) {
                // Content hasn't changed, could return cached results
                // For now, we'll continue with analysis
            }
        }

        // Create source file and analyze
        let source_file = crate::parsers::SourceFile::new(path.to_path_buf(), content, language);
        let mut parser = crate::parsers::ParserFactory::create_parser(&source_file.language)?;
        let ast = parser.parse(&source_file)?;

        // Use rule engine for analysis
        let rule_engine = crate::rules::RuleEngine::new(&self.config.rules);
        rule_engine.analyze(&source_file, &ast)
    }

    /// Get language for file with caching
    fn get_language_for_file(&self, path: &Path) -> crate::Result<Language> {
        let extension = path.extension()
            .and_then(|ext| ext.to_str())
            .ok_or_else(|| crate::DevaicError::Analysis("File has no extension".to_string()))?;

        // Check cache first
        if self.cache_enabled {
            let cache = get_global_cache();
            if let Some(cached_lang) = cache.get_language_for_extension(extension) {
                return cached_lang.ok_or_else(|| 
                    crate::DevaicError::Analysis(format!("Unsupported file extension: {}", extension))
                );
            }
        }

        // Cache miss - compute and cache
        let language = Language::from_extension(extension);
        
        if self.cache_enabled {
            let cache = get_global_cache();
            cache.cache_language_for_extension(extension.to_string(), language);
        }

        language.ok_or_else(|| 
            crate::DevaicError::Analysis(format!("Unsupported file extension: {}", extension))
        )
    }
}

/// Results from directory scanning
#[derive(Debug)]
pub struct ScanResults {
    pub vulnerabilities: Vec<Vulnerability>,
    pub files_scanned: usize,
    pub scan_time_ms: u64,
    pub cache_hits: usize,
}

impl ScanResults {
    /// Print scan summary
    pub fn print_summary(&self) {
        println!("Scan Summary:");
        println!("  Files scanned: {}", self.files_scanned);
        println!("  Vulnerabilities found: {}", self.vulnerabilities.len());
        println!("  Scan time: {}ms", self.scan_time_ms);
        println!("  Cache hits: {}", self.cache_hits);
        
        if self.files_scanned > 0 {
            println!("  Average time per file: {:.2}ms", 
                self.scan_time_ms as f64 / self.files_scanned as f64);
        }
    }

    /// Get vulnerabilities by severity
    pub fn get_vulnerabilities_by_severity(&self) -> std::collections::HashMap<String, usize> {
        let mut severity_counts = std::collections::HashMap::new();
        
        for vuln in &self.vulnerabilities {
            *severity_counts.entry(vuln.severity.to_string()).or_insert(0) += 1;
        }
        
        severity_counts
    }

    /// Get vulnerabilities by file
    pub fn get_vulnerabilities_by_file(&self) -> std::collections::HashMap<PathBuf, usize> {
        let mut file_counts = std::collections::HashMap::new();
        
        for vuln in &self.vulnerabilities {
            *file_counts.entry(PathBuf::from(&vuln.file_path)).or_insert(0) += 1;
        }
        
        file_counts
    }
}

/// Smart file filter with performance optimizations
pub struct SmartFileFilter {
    config: Arc<Config>,
    common_extensions: std::collections::HashSet<String>,
    binary_extensions: std::collections::HashSet<String>,
}

impl SmartFileFilter {
    pub fn new(config: Config) -> Self {
        // Common code file extensions
        let common_extensions = [
            "c", "cpp", "cc", "cxx", "h", "hpp", "hxx",
            "java", "js", "ts", "py", "rb", "go", "rs",
            "php", "cs", "kt", "swift", "scala", "pl",
            "sh", "bash", "zsh", "fish", "ps1", "bat",
            "html", "css", "scss", "less", "jsx", "tsx",
            "vue", "svelte", "yaml", "yml", "json", "xml",
            "sql", "r", "m", "mm", "dart", "lua", "vim",
        ].iter().map(|s| s.to_string()).collect();

        // Binary file extensions to skip
        let binary_extensions = [
            "exe", "dll", "so", "dylib", "a", "lib", "o", "obj",
            "bin", "img", "iso", "dmg", "pkg", "deb", "rpm",
            "zip", "tar", "gz", "bz2", "xz", "7z", "rar",
            "jpg", "jpeg", "png", "gif", "bmp", "svg", "ico",
            "mp3", "mp4", "avi", "mov", "wmv", "flv", "mkv",
            "pdf", "doc", "docx", "xls", "xlsx", "ppt", "pptx",
            "ttf", "otf", "woff", "woff2", "eot",
        ].iter().map(|s| s.to_string()).collect();

        Self {
            config: Arc::new(config),
            common_extensions,
            binary_extensions,
        }
    }

    /// Check if file should be analyzed (optimized)
    pub fn should_analyze(&self, path: &Path) -> bool {
        // Fast path: check extension
        if let Some(ext) = path.extension().and_then(|e| e.to_str()) {
            let ext_lower = ext.to_lowercase();
            
            // Skip binary files immediately
            if self.binary_extensions.contains(&ext_lower) {
                return false;
            }
            
            // Prioritize common code extensions
            if !self.common_extensions.contains(&ext_lower) {
                // Check if it's a supported language
                if Language::from_extension(&ext_lower).is_none() {
                    return false;
                }
            }
        } else {
            // No extension - might be a script with shebang
            if !self.might_be_script(path) {
                return false;
            }
        }

        // Check file size
        if let Ok(metadata) = std::fs::metadata(path) {
            if metadata.len() > self.config.analysis.max_file_size as u64 {
                return false;
            }
        }

        // Check patterns
        self.matches_patterns(path)
    }

    /// Check if file might be a script (no extension but executable)
    fn might_be_script(&self, path: &Path) -> bool {
        // Check if file is executable (Unix-like systems)
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            if let Ok(metadata) = std::fs::metadata(path) {
                let permissions = metadata.permissions();
                return permissions.mode() & 0o111 != 0; // Check execute permission
            }
        }

        // On Windows or if metadata fails, check common script names
        if let Some(filename) = path.file_name().and_then(|n| n.to_str()) {
            matches!(filename, "Makefile" | "Dockerfile" | "Jenkinsfile" | "Vagrantfile")
        } else {
            false
        }
    }

    /// Check if file matches include/exclude patterns
    fn matches_patterns(&self, path: &Path) -> bool {
        let path_str = path.to_string_lossy();
        
        // Check exclude patterns
        for pattern in &self.config.analysis.exclude_patterns {
            if glob::Pattern::new(pattern)
                .map(|p| p.matches(&path_str))
                .unwrap_or(false)
            {
                return false;
            }
        }

        // Check include patterns
        if !self.config.analysis.include_patterns.is_empty() {
            for pattern in &self.config.analysis.include_patterns {
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
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::TempDir;
    use std::fs::File;
    use std::io::Write;

    #[test]
    fn test_smart_file_filter() {
        let config = Config::default();
        let filter = SmartFileFilter::new(config);
        
        // Should analyze code files
        assert!(filter.should_analyze(Path::new("test.rs")));
        assert!(filter.should_analyze(Path::new("test.py")));
        assert!(filter.should_analyze(Path::new("test.java")));
        
        // Should skip binary files
        assert!(!filter.should_analyze(Path::new("test.exe")));
        assert!(!filter.should_analyze(Path::new("test.jpg")));
        assert!(!filter.should_analyze(Path::new("test.pdf")));
    }

    #[test]
    fn test_scan_results() {
        let results = ScanResults {
            vulnerabilities: vec![],
            files_scanned: 10,
            scan_time_ms: 1000,
            cache_hits: 5,
        };
        
        results.print_summary();
        assert_eq!(results.files_scanned, 10);
        assert_eq!(results.scan_time_ms, 1000);
    }
}