use crate::Vulnerability;
use dashmap::DashMap;
use once_cell::sync::Lazy;
use siphasher::sip::SipHasher;
use std::fs::Metadata;
use std::hash::{Hash, Hasher};
use std::path::{Path, PathBuf};
use std::time::SystemTime;

/// Global cache for file system metadata and analysis results
static GLOBAL_CACHE: Lazy<FileSystemCache> = Lazy::new(|| FileSystemCache::new());

/// Cache entry for file metadata and analysis results
#[derive(Debug, Clone)]
pub struct CacheEntry {
    pub file_path: PathBuf,
    pub file_size: u64,
    pub modified_time: SystemTime,
    pub language: Option<crate::Language>,
    pub content_hash: u64,
    pub is_analyzed: bool,
    pub vulnerabilities_count: usize,
    pub analysis_time_ms: u64,
}

/// Fast hash function for file content
fn fast_hash(content: &str) -> u64 {
    let mut hasher = SipHasher::new();
    content.hash(&mut hasher);
    hasher.finish()
}

/// Cache for file system operations and analysis results
pub struct FileSystemCache {
    /// Cache for file metadata (path -> metadata)
    file_metadata: DashMap<PathBuf, CacheEntry>,
    /// Cache for directory listings (dir_path -> Vec<file_paths>)
    directory_cache: DashMap<PathBuf, Vec<PathBuf>>,
    /// Cache for file extension -> language mappings
    language_cache: DashMap<String, Option<crate::Language>>,
    /// Cache for glob pattern matching results
    pattern_cache: DashMap<String, Vec<PathBuf>>,
    /// Cache for file content hashes to detect changes
    content_cache: DashMap<PathBuf, u64>,
    /// Cache for analysis results
    analysis_results: DashMap<PathBuf, Vec<Vulnerability>>,
}

impl FileSystemCache {
    pub fn new() -> Self {
        Self {
            file_metadata: DashMap::new(),
            directory_cache: DashMap::new(),
            language_cache: DashMap::new(),
            pattern_cache: DashMap::new(),
            content_cache: DashMap::new(),
            analysis_results: DashMap::new(),
        }
    }

    /// Get cached file metadata or compute and cache it
    pub fn get_file_metadata(&self, path: &Path) -> Option<CacheEntry> {
        if let Some(entry) = self.file_metadata.get(path) {
            // Check if file has been modified since cached
            if let Ok(metadata) = std::fs::metadata(path) {
                if let Ok(modified) = metadata.modified() {
                    if modified == entry.modified_time {
                        return Some(entry.clone());
                    }
                }
            }
        }
        None
    }

    /// Cache file metadata
    pub fn cache_file_metadata(
        &self,
        path: PathBuf,
        metadata: Metadata,
        language: Option<crate::Language>,
    ) {
        if let Ok(modified_time) = metadata.modified() {
            let entry = CacheEntry {
                file_path: path.clone(),
                file_size: metadata.len(),
                modified_time,
                language,
                content_hash: 0,
                is_analyzed: false,
                vulnerabilities_count: 0,
                analysis_time_ms: 0,
            };
            self.file_metadata.insert(path, entry);
        }
    }

    /// Get cached directory listing
    pub fn get_directory_listing(&self, dir_path: &Path) -> Option<Vec<PathBuf>> {
        self.directory_cache
            .get(dir_path)
            .map(|entry| entry.clone())
    }

    /// Cache directory listing
    pub fn cache_directory_listing(&self, dir_path: PathBuf, files: Vec<PathBuf>) {
        self.directory_cache.insert(dir_path, files);
    }

    /// Get cached language for file extension
    pub fn get_language_for_extension(&self, extension: &str) -> Option<Option<crate::Language>> {
        self.language_cache.get(extension).map(|lang| *lang)
    }

    /// Cache language for file extension
    pub fn cache_language_for_extension(
        &self,
        extension: String,
        language: Option<crate::Language>,
    ) {
        self.language_cache.insert(extension, language);
    }

    /// Check if file content has changed using hash
    pub fn has_content_changed(&self, path: &Path, content: &str) -> bool {
        let new_hash = fast_hash(content);

        if let Some(cached_hash) = self.content_cache.get(path) {
            if *cached_hash == new_hash {
                return false;
            }
        }

        self.content_cache.insert(path.to_path_buf(), new_hash);
        true
    }

    /// Cache pattern matching results
    pub fn cache_pattern_match(&self, pattern: String, results: Vec<PathBuf>) {
        self.pattern_cache.insert(pattern, results);
    }

    /// Get cached pattern matching results
    pub fn get_pattern_match(&self, pattern: &str) -> Option<Vec<PathBuf>> {
        self.pattern_cache
            .get(pattern)
            .map(|results| results.clone())
    }
    /// Get cached analysis results
    pub fn get_analysis_result(&self, path: &Path) -> Option<Vec<Vulnerability>> {
        self.analysis_results
            .get(path)
            .map(|entry| entry.clone())
    }

    /// Cache analysis results
    pub fn cache_analysis_result(&self, path: &Path, vulnerabilities: Vec<Vulnerability>) {
        self.analysis_results
            .insert(path.to_path_buf(), vulnerabilities);
    }

    /// Update content hash for file
    pub fn update_content_hash(&self, path: &Path, content: &str) {
        let hash = fast_hash(content);
        self.content_cache.insert(path.to_path_buf(), hash);
    }

    /// Clear all caches
    pub fn clear_all(&self) {
        self.file_metadata.clear();
        self.directory_cache.clear();
        self.language_cache.clear();
        self.pattern_cache.clear();
        self.content_cache.clear();
        self.analysis_results.clear();
    }

    /// Get cache statistics
    pub fn get_stats(&self) -> CacheStats {
        CacheStats {
            file_metadata_entries: self.file_metadata.len(),
            directory_cache_entries: self.directory_cache.len(),
            language_cache_entries: self.language_cache.len(),
            pattern_cache_entries: self.pattern_cache.len(),
            content_cache_entries: self.content_cache.len(),
            analysis_results_entries: self.analysis_results.len(),
        }
    }
}

/// Statistics about cache usage
#[derive(Debug)]
pub struct CacheStats {
    pub file_metadata_entries: usize,
    pub directory_cache_entries: usize,
    pub language_cache_entries: usize,
    pub pattern_cache_entries: usize,
    pub content_cache_entries: usize,
    pub analysis_results_entries: usize,
}

impl CacheStats {
    pub fn print_summary(&self) {
        println!("Cache Statistics:");
        println!(
            "  File metadata entries: {}",
            self.file_metadata_entries
        );
        println!(
            "  Directory cache entries: {}",
            self.directory_cache_entries
        );
        println!(
            "  Language cache entries: {}",
            self.language_cache_entries
        );
        println!("  Pattern cache entries: {}", self.pattern_cache_entries);
        println!("  Content cache entries: {}", self.content_cache_entries);
        println!(
            "  Analysis results entries: {}",
            self.analysis_results_entries
        );
        println!(
            "  Total cache entries: {}",
            self.file_metadata_entries
                + self.directory_cache_entries
                + self.language_cache_entries
                + self.pattern_cache_entries
                + self.content_cache_entries
                + self.analysis_results_entries
        );
    }
}

/// Get global cache instance
pub fn get_global_cache() -> &'static FileSystemCache {
    &GLOBAL_CACHE
}

/// Cached file walker for optimized directory traversal
pub struct CachedFileWalker {
    cache: &'static FileSystemCache,
    follow_symlinks: bool,
    max_file_size: usize,
    exclude_patterns: Vec<String>,
    include_patterns: Vec<String>,
    max_depth: usize,
}

impl CachedFileWalker {
    pub fn new(
        follow_symlinks: bool,
        max_file_size: usize,
        exclude_patterns: Vec<String>,
        include_patterns: Vec<String>,
        max_depth: usize,
    ) -> Self {
        Self {
            cache: get_global_cache(),
            follow_symlinks,
            max_file_size,
            exclude_patterns,
            include_patterns,
            max_depth,
        }
    }

    /// Walk directory with caching optimization
    pub fn walk_directory(&self, path: &Path) -> Vec<PathBuf> {
        self.walk_directory_with_depth(path, 0)
    }

    /// Walk directory with depth limit to prevent infinite recursion
    fn walk_directory_with_depth(&self, path: &Path, depth: usize) -> Vec<PathBuf> {
        // Limit recursion depth to prevent infinite loops and improve performance
        if depth > self.max_depth {
            log::warn!(
                "Maximum recursion depth ({}) reached for directory: {}",
                self.max_depth,
                path.display()
            );
            return Vec::new();
        }

        // Check cache first
        if let Some(cached_files) = self.cache.get_directory_listing(path) {
            return cached_files;
        }

        // Collect files from directory
        let mut files = Vec::new();

        if let Ok(entries) = std::fs::read_dir(path) {
            for entry in entries.flatten() {
                let file_path = entry.path();

                if file_path.is_file() {
                    if self.should_analyze_file(&file_path) {
                        files.push(file_path);
                    }
                } else if file_path.is_dir() {
                    // Recursively walk subdirectories
                    // Only follow symlinks if configured to do so
                    let is_symlink = file_path
                        .symlink_metadata()
                        .map(|m| m.file_type().is_symlink())
                        .unwrap_or(false);

                    if !is_symlink || self.follow_symlinks {
                        let subdir_files = self.walk_directory_with_depth(&file_path, depth + 1);
                        files.extend(subdir_files);
                    }
                }
            }
        }

        // Cache results
        self.cache
            .cache_directory_listing(path.to_path_buf(), files.clone());
        files
    }

    /// Check if file should be analyzed (with caching)
    fn should_analyze_file(&self, path: &Path) -> bool {
        // Check cached metadata first
        if let Some(cached_entry) = self.cache.get_file_metadata(path) {
            if cached_entry.file_size > self.max_file_size as u64 {
                return false;
            }
            if cached_entry.language.is_none() {
                return false;
            }
        } else {
            // Cache miss - compute and cache metadata
            if let Ok(metadata) = std::fs::metadata(path) {
                if metadata.len() > self.max_file_size as u64 {
                    return false;
                }

                // Get language from extension with caching
                let language = if let Some(ext) = path.extension().and_then(|e| e.to_str()) {
                    if let Some(cached_lang) = self.cache.get_language_for_extension(ext) {
                        cached_lang
                    } else {
                        let lang = crate::Language::from_extension(ext);
                        self.cache
                            .cache_language_for_extension(ext.to_string(), lang);
                        lang
                    }
                } else {
                    None
                };

                if language.is_none() {
                    return false;
                }

                self.cache
                    .cache_file_metadata(path.to_path_buf(), metadata, language);
            } else {
                return false;
            }
        }

        // Check exclude/include patterns
        self.matches_patterns(path)
    }

    /// Check if file matches include/exclude patterns
    fn matches_patterns(&self, path: &Path) -> bool {
        let path_str = path.to_string_lossy();

        // Check exclude patterns
        for pattern in &self.exclude_patterns {
            if glob::Pattern::new(pattern)
                .map(|p| p.matches(&path_str))
                .unwrap_or(false)
            {
                return false;
            }
        }

        // Check include patterns
        if !self.include_patterns.is_empty() {
            for pattern in &self.include_patterns {
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