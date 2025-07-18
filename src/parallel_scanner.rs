use crate::{config::Config, Language, Vulnerability};
use crate::{
    cache::{get_global_cache, CachedFileWalker},
    fast_walker::OptimizedDirectoryScanner,
    optimized_reader::OptimizedFileReader,
};
use rayon::prelude::*;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::Instant;

/// Parallel directory scanner with optimized performance
pub struct ParallelDirectoryScanner {
    config: Arc<Config>,
    thread_pool_size: usize,
    cache_enabled: bool,
    batch_size: usize,
    max_depth: usize,
    use_fast_walker: bool,
    exclude_patterns: Vec<glob::Pattern>,
    include_patterns: Vec<glob::Pattern>,
}

impl ParallelDirectoryScanner {
    pub fn new(
        config: Config,
        thread_pool_size: Option<usize>,
        cache_enabled: bool,
        max_depth: Option<usize>,
        use_fast_walker: Option<bool>,
    ) -> Self {
        let pool_size = thread_pool_size.unwrap_or_else(|| {
            std::thread::available_parallelism()
                .map(|n| n.get())
                .unwrap_or(4)
        });

        let exclude_patterns = config
            .analysis
            .exclude_patterns
            .iter()
            .filter_map(|p| glob::Pattern::new(p).ok())
            .collect();

        let include_patterns = config
            .analysis
            .include_patterns
            .iter()
            .filter_map(|p| glob::Pattern::new(p).ok())
            .collect();

        Self {
            config: Arc::new(config),
            thread_pool_size: pool_size,
            cache_enabled,
            batch_size: 100, // Process files in batches of 100
            max_depth: max_depth.unwrap_or(100),
            use_fast_walker: use_fast_walker.unwrap_or(true),
            exclude_patterns,
            include_patterns,
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
                self.exclude_patterns.clone(),
                self.include_patterns.clone(),
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
        let (all_vulnerabilities, cache_hits) = self.process_files_parallel(&files)?;

        let scan_time = start_time.elapsed();

        Ok(ScanResults {
            vulnerabilities: all_vulnerabilities,
            files_scanned: files.len(),
            scan_time_ms: scan_time.as_millis() as u64,
            cache_hits,
        })
    }

    /// Process files in parallel with batching
    fn process_files_parallel(
        &self,
        files: &[PathBuf],
    ) -> crate::Result<(Vec<Vulnerability>, usize)> {
        // Configure rayon thread pool
        let pool = rayon::ThreadPoolBuilder::new()
            .num_threads(self.thread_pool_size)
            .build()
            .map_err(|e| {
                crate::DevaicError::Analysis(format!("Failed to create thread pool: {}", e))
            })?;

        pool.install(|| {
            // Process files in parallel batches
            let results: Vec<(Vec<Vulnerability>, usize)> = files
                .par_chunks(self.batch_size)
                .map(|chunk| self.process_file_batch(chunk))
                .collect::<Result<Vec<_>, _>>()?;

            // Flatten results
            let mut all_vulnerabilities = Vec::new();
            let mut total_cache_hits = 0;
            for (vulnerabilities, cache_hits) in results {
                all_vulnerabilities.extend(vulnerabilities);
                total_cache_hits += cache_hits;
            }

            Ok((all_vulnerabilities, total_cache_hits))
        })
    }

    /// Process a batch of files
    fn process_file_batch(
        &self,
        files: &[PathBuf],
    ) -> crate::Result<(Vec<Vulnerability>, usize)> {
        let mut batch_vulnerabilities = Vec::new();
        let mut cache_hits = 0;
        let reader = OptimizedFileReader::new(self.cache_enabled);

        for file_path in files {
            let (vulnerabilities, from_cache) =
                self.analyze_single_file_with_caching(file_path, &reader)?;
            if from_cache {
                cache_hits += 1;
            }
            batch_vulnerabilities.extend(vulnerabilities);
        }

        Ok((batch_vulnerabilities, cache_hits))
    }
    /// Analyze a single file with caching
    fn analyze_single_file_with_caching(
        &self,
        path: &Path,
        reader: &OptimizedFileReader,
    ) -> crate::Result<(Vec<Vulnerability>, bool)> {
        if self.cache_enabled {
            let cache = get_global_cache();
            let content = reader.read_file(path)?;
            if !cache.has_content_changed(path, &content) {
                if let Some(cached_vulnerabilities) = cache.get_analysis_result(path) {
                    return Ok((cached_vulnerabilities, true));
                }
            }
        }

        let vulnerabilities = self.analyze_single_file(path, reader)?;

        if self.cache_enabled {
            let cache = get_global_cache();
            cache.cache_analysis_result(path, vulnerabilities.clone());
        }

        Ok((vulnerabilities, false))
    }

    /// Analyze a single file
    fn analyze_single_file(
        &self,
        path: &Path,
        reader: &OptimizedFileReader,
    ) -> crate::Result<Vec<Vulnerability>> {
        // Get language from extension with caching
        let language = self.get_language_for_file(path)?;

        // Read file content with optimal strategy
        let content = reader.read_file(path).map_err(|e| {
            crate::DevaicError::Analysis(format!("Failed to read file {}: {}", path.display(), e))
        })?;

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
        let extension = path
            .extension()
            .and_then(|ext| ext.to_str())
            .ok_or_else(|| crate::DevaicError::Analysis("File has no extension".to_string()))?;

        // Check cache first
        if self.cache_enabled {
            let cache = get_global_cache();
            if let Some(cached_lang) = cache.get_language_for_extension(extension) {
                return cached_lang.ok_or_else(|| {
                    crate::DevaicError::Analysis(format!("Unsupported file extension: {}", extension))
                });
            }
        }

        // Cache miss - compute and cache
        let language = Language::from_extension(extension);

        if self.cache_enabled {
            let cache = get_global_cache();
            cache.cache_language_for_extension(extension.to_string(), language);
        }

        language.ok_or_else(|| {
            crate::DevaicError::Analysis(format!("Unsupported file extension: {}", extension))
        })
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
            println!(
                "  Average time per file: {:.2}ms",
                self.scan_time_ms as f64 / self.files_scanned as f64
            );
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
            *file_counts
                .entry(PathBuf::from(&vuln.file_path))
                .or_insert(0) += 1;
        }

        file_counts
    }
}

