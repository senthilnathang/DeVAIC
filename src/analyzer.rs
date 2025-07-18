use crate::{
    config::Config,
    error::{DevaicError, Result},
    parsers::{ParserFactory, SourceFile},
    rules::{RuleEngine, custom_pattern_rules::CustomPatternRules},
    pattern_loader::PatternLoader,
    cache::get_global_cache,
    optimized_reader::OptimizedFileReader,
    parallel_scanner::{ParallelDirectoryScanner},
    Language, Vulnerability,
};
use std::path::Path;
use walkdir::WalkDir;

pub struct Analyzer {
    config: Config,
    rule_engine: RuleEngine,
    optimized_reader: OptimizedFileReader,
    parallel_enabled: bool,
    max_depth: usize,
}

impl Analyzer {
    pub fn new(config: Config) -> Self {
        let rule_engine = RuleEngine::new(&config.rules);
        let optimized_reader = OptimizedFileReader::new(true); // Enable caching
        
        Self {
            config,
            rule_engine,
            optimized_reader,
            parallel_enabled: true,
            max_depth: 100,
        }
    }

    pub fn new_with_custom_patterns(config: Config, pattern_loader: PatternLoader) -> Self {
        let mut rule_engine = RuleEngine::new(&config.rules);
        let custom_rules = CustomPatternRules::new(pattern_loader);
        rule_engine.set_custom_pattern_rules(custom_rules);
        
        let optimized_reader = OptimizedFileReader::new(true); // Enable caching
        
        Self {
            config,
            rule_engine,
            optimized_reader,
            parallel_enabled: true,
            max_depth: 100,
        }
    }

    /// Enable or disable parallel processing
    pub fn set_parallel_enabled(&mut self, enabled: bool) {
        self.parallel_enabled = enabled;
    }

    /// Set maximum recursion depth for directory scanning
    pub fn set_max_depth(&mut self, max_depth: usize) {
        self.max_depth = max_depth;
    }

    /// Get cache statistics
    pub fn get_cache_stats(&self) -> crate::cache::CacheStats {
        get_global_cache().get_stats()
    }

    /// Clear all caches
    pub fn clear_caches(&self) {
        get_global_cache().clear_all();
    }

    pub fn analyze_directory(&self, path: &Path) -> Result<Vec<Vulnerability>> {
        if self.parallel_enabled {
            // Use parallel scanner for better performance
            let scanner = ParallelDirectoryScanner::new(
                self.config.clone(),
                None, // Use default thread count
                true, // Enable caching
                Some(self.max_depth), // Use configured max depth
                Some(true), // Use fast walker
            );
            
            match scanner.scan_directory(path) {
                Ok(results) => {
                    log::info!("Parallel scan completed: {} files, {} vulnerabilities, {}ms", 
                              results.files_scanned, results.vulnerabilities.len(), results.scan_time_ms);
                    Ok(results.vulnerabilities)
                }
                Err(e) => {
                    log::warn!("Parallel scan failed, falling back to sequential: {}", e);
                    self.analyze_directory_sequential(path)
                }
            }
        } else {
            self.analyze_directory_sequential(path)
        }
    }

    /// Sequential directory analysis (fallback)
    fn analyze_directory_sequential(&self, path: &Path) -> Result<Vec<Vulnerability>> {
        // Use smart file filter for better performance
        let mut vulnerabilities = Vec::new();
        
        for entry in WalkDir::new(path)
            .follow_links(self.config.analysis.follow_symlinks)
            .into_iter()
            .filter_map(|e| e.ok())
        {
            if entry.file_type().is_file() {
                let file_path = entry.path();
                
                log::debug!("Analyzing file: {}", file_path.display());
                match self.analyze_file(file_path) {
                    Ok(mut file_vulns) => vulnerabilities.append(&mut file_vulns),
                    Err(e) => {
                        log::debug!("Skipped file {}: {}", file_path.display(), e);
                    }
                }
            }
        }

        Ok(vulnerabilities)
    }

    pub fn analyze_file(&self, path: &Path) -> Result<Vec<Vulnerability>> {
        let extension = match path.extension().and_then(|ext| ext.to_str()) {
            Some(ext) => ext,
            None => {
                // Skip files without extensions
                return Ok(Vec::new());
            }
        };

        // Get language with caching
        let language = {
            let cache = get_global_cache();
            if let Some(cached_lang) = cache.get_language_for_extension(extension) {
                match cached_lang {
                    Some(lang) => lang,
                    None => {
                        log::debug!("Unsupported language extension: {} for file: {}", extension, path.display());
                        return Ok(Vec::new());
                    }
                }
            } else {
                let lang = Language::from_extension(extension);
                cache.cache_language_for_extension(extension.to_string(), lang);
                match lang {
                    Some(lang) => lang,
                    None => {
                        log::debug!("Unsupported language extension: {} for file: {}", extension, path.display());
                        return Ok(Vec::new());
                    }
                }
            }
        };

        // Use optimized reader for better performance
        let content = self.optimized_reader.read_file(path)
            .map_err(|e| DevaicError::Analysis(format!("Failed to read file {}: {}", path.display(), e)))?;

        // Check if content has changed using cache
        let cache = get_global_cache();
        if !cache.has_content_changed(path, &content) {
            // Content hasn't changed, could return cached analysis results
            // For now, we'll continue with analysis
            log::debug!("File content unchanged: {}", path.display());
        }

        let source_file = SourceFile::new(path.to_path_buf(), content, language);
        let mut parser = ParserFactory::create_parser(&source_file.language)?;
        let ast = parser.parse(&source_file)?;

        self.rule_engine.analyze(&source_file, &ast)
    }

}