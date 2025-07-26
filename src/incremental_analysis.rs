/// Incremental Analysis System for DeVAIC
/// 
/// This module provides intelligent incremental analysis capabilities that can detect
/// which files have changed since the last analysis and only re-analyze those files.
/// This dramatically improves performance for large codebases and CI/CD pipelines.

use crate::{
    analyzer::Analyzer,
    error::{DevaicError, Result},
    Language, Vulnerability, Severity,
    false_positive_reduction::EnhancedVulnerability,
    impact_assessment::AssessedVulnerability,
};
use std::{
    collections::{HashMap, HashSet},
    fs,
    path::{Path, PathBuf},
    time::{SystemTime, UNIX_EPOCH},
};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use walkdir::WalkDir;

/// Configuration for incremental analysis
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct IncrementalConfig {
    /// Enable incremental analysis
    pub enabled: bool,
    /// Path to store incremental state
    pub state_file_path: PathBuf,
    /// Maximum age of state file before full re-analysis (in seconds)
    pub max_state_age_seconds: u64,
    /// Force full analysis on these file patterns
    pub force_full_analysis_patterns: Vec<String>,
    /// Skip incremental analysis for these directories
    pub excluded_directories: Vec<String>,
    /// Include dependency analysis for changed files
    pub include_dependency_analysis: bool,
    /// Store results in compressed format
    pub compress_state: bool,
}

impl Default for IncrementalConfig {
    fn default() -> Self {
        Self {
            enabled: true,
            state_file_path: PathBuf::from(".devaic_incremental_state.json"),
            max_state_age_seconds: 7 * 24 * 3600, // 1 week
            force_full_analysis_patterns: vec![
                "*.config".to_string(),
                "*.yml".to_string(),
                "*.yaml".to_string(),
                "Dockerfile*".to_string(),
                "requirements*.txt".to_string(),
                "package*.json".to_string(),
                "Cargo.toml".to_string(),
                "pom.xml".to_string(),
            ],
            excluded_directories: vec![
                ".git".to_string(),
                "node_modules".to_string(),
                "target".to_string(),
                "build".to_string(),
                "dist".to_string(),
                ".devaic".to_string(),
            ],
            include_dependency_analysis: true,
            compress_state: true,
        }
    }
}

/// File metadata for change detection
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FileMetadata {
    pub path: PathBuf,
    pub size: u64,
    pub modified_time: u64,
    pub content_hash: String,
    pub language: Option<Language>,
    pub last_analyzed: u64,
}

/// Dependency relationship between files
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FileDependency {
    pub dependent_file: PathBuf,
    pub dependency_file: PathBuf,
    pub dependency_type: DependencyType,
    pub confidence: f64,
}

/// Types of dependencies between files
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum DependencyType {
    Import,
    Include,
    Reference,
    Configuration,
    Build,
    Test,
}

/// Analysis results for a specific file
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FileAnalysisResult {
    pub file_path: PathBuf,
    pub vulnerabilities: Vec<Vulnerability>,
    pub analysis_timestamp: u64,
    pub analyzer_version: String,
    pub analysis_duration_ms: u64,
    pub file_metadata: FileMetadata,
}

/// Incremental analysis state
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct IncrementalState {
    pub version: String,
    pub last_full_analysis: u64,
    pub file_metadata: HashMap<PathBuf, FileMetadata>,
    pub file_dependencies: Vec<FileDependency>,
    pub cached_results: HashMap<PathBuf, FileAnalysisResult>,
    pub analysis_statistics: IncrementalStatistics,
    pub project_root: PathBuf,
}

/// Statistics for incremental analysis performance
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct IncrementalStatistics {
    pub total_analyses: u64,
    pub incremental_analyses: u64,
    pub full_analyses: u64,
    pub files_analyzed: u64,
    pub files_skipped: u64,
    pub time_saved_ms: u64,
    pub cache_hit_rate: f64,
    pub average_analysis_time_ms: f64,
    pub last_updated: u64,
}

impl Default for IncrementalStatistics {
    fn default() -> Self {
        Self {
            total_analyses: 0,
            incremental_analyses: 0,
            full_analyses: 0,
            files_analyzed: 0,
            files_skipped: 0,
            time_saved_ms: 0,
            cache_hit_rate: 0.0,
            average_analysis_time_ms: 0.0,
            last_updated: current_timestamp(),
        }
    }
}

/// Result of incremental analysis
#[derive(Debug)]
pub struct IncrementalAnalysisResult {
    pub vulnerabilities: Vec<Vulnerability>,
    pub changed_files: Vec<PathBuf>,
    pub skipped_files: Vec<PathBuf>,
    pub dependency_affected_files: Vec<PathBuf>,
    pub analysis_type: AnalysisType,
    pub statistics: IncrementalStatistics,
    pub total_duration_ms: u64,
}

/// Type of analysis performed
#[derive(Debug, Clone)]
pub enum AnalysisType {
    Full,
    Incremental,
    Dependency,
    Forced,
}

/// Main incremental analysis engine
pub struct IncrementalAnalysisEngine {
    config: IncrementalConfig,
    state: Option<IncrementalState>,
    analyzer: Analyzer,
    dependency_detector: DependencyDetector,
}

impl IncrementalAnalysisEngine {
    /// Create a new incremental analysis engine
    pub fn new(config: IncrementalConfig, analyzer: Analyzer) -> Result<Self> {
        let dependency_detector = DependencyDetector::new();
        
        Ok(Self {
            config,
            state: None,
            analyzer,
            dependency_detector,
        })
    }

    /// Load existing state or create new state
    pub fn load_state(&mut self, project_root: &Path) -> Result<()> {
        let state_path = project_root.join(&self.config.state_file_path);
        
        if state_path.exists() {
            match self.load_state_from_file(&state_path) {
                Ok(state) => {
                    // Check if state is too old
                    let state_age = current_timestamp() - state.last_full_analysis;
                    if state_age > self.config.max_state_age_seconds {
                        log::info!("Incremental state is too old ({} seconds), starting fresh", state_age);
                        self.create_new_state(project_root);
                    } else {
                        self.state = Some(state);
                        log::info!("Loaded incremental state with {} cached files", 
                                  self.state.as_ref().unwrap().file_metadata.len());
                    }
                }
                Err(e) => {
                    log::warn!("Failed to load incremental state: {}, starting fresh", e);
                    self.create_new_state(project_root);
                }
            }
        } else {
            log::info!("No incremental state found, starting fresh analysis");
            self.create_new_state(project_root);
        }
        
        Ok(())
    }

    /// Perform incremental analysis on a directory
    pub async fn analyze_directory_incremental(&mut self, path: &Path) -> Result<IncrementalAnalysisResult> {
        let start_time = std::time::Instant::now();
        
        if !self.config.enabled {
            log::info!("Incremental analysis disabled, performing full analysis");
            return self.perform_full_analysis(path).await;
        }

        // Ensure state is loaded
        if self.state.is_none() {
            self.load_state(path)?;
        }

        // Detect changed files - do this before getting mutable state borrow
        let changed_files = self.detect_changed_files(path)?;
        let dependency_affected_files = if self.config.include_dependency_analysis {
            self.analyze_dependency_impact(&changed_files)?
        } else {
            Vec::new()
        };

        // Determine analysis type
        let analysis_type = self.determine_analysis_type(&changed_files, &dependency_affected_files);
        
        let result = match analysis_type {
            AnalysisType::Full => self.perform_full_analysis(path).await?,
            AnalysisType::Incremental => self.perform_incremental_analysis(path, changed_files, dependency_affected_files).await?,
            AnalysisType::Dependency => self.perform_dependency_analysis(path, dependency_affected_files).await?,
            AnalysisType::Forced => self.perform_full_analysis(path).await?,
        };

        // Update statistics
        let duration_ms = start_time.elapsed().as_millis() as u64;
        self.update_statistics(&result, duration_ms);
        
        // Save state
        self.save_state(path)?;
        
        // Get statistics after all state modifications are done
        let statistics = {
            let state = self.state.as_ref().unwrap();
            state.analysis_statistics.clone()
        };
        
        let final_result = IncrementalAnalysisResult {
            vulnerabilities: result.vulnerabilities,
            changed_files: result.changed_files,
            skipped_files: result.skipped_files,
            dependency_affected_files: result.dependency_affected_files,
            analysis_type: result.analysis_type,
            statistics,
            total_duration_ms: duration_ms,
        };

        log::info!("Incremental analysis completed: {:?} in {}ms", 
                  final_result.analysis_type, duration_ms);
        
        Ok(final_result)
    }

    /// Detect files that have changed since last analysis
    fn detect_changed_files(&self, root_path: &Path) -> Result<Vec<PathBuf>> {
        let mut changed_files = Vec::new();
        let state = self.state.as_ref().unwrap();
        
        for entry in WalkDir::new(root_path)
            .follow_links(false)
            .into_iter()
            .filter_map(|e| e.ok())
            .filter(|e| e.file_type().is_file())
        {
            let file_path = entry.path();
            
            // Skip excluded directories
            if self.is_path_excluded(file_path) {
                continue;
            }

            // Get current metadata
            let current_metadata = self.get_file_metadata(file_path)?;
            
            // Check if file has changed
            if let Some(cached_metadata) = state.file_metadata.get(&file_path.to_path_buf()) {
                if self.has_file_changed(&current_metadata, cached_metadata) {
                    changed_files.push(file_path.to_path_buf());
                }
            } else {
                // New file
                changed_files.push(file_path.to_path_buf());
            }
        }
        
        // Check for deleted files
        for cached_path in state.file_metadata.keys() {
            if !cached_path.exists() {
                log::info!("File deleted: {}", cached_path.display());
                // Note: We don't add deleted files to changed_files as they don't need analysis
            }
        }
        
        Ok(changed_files)
    }

    /// Analyze which files are affected by dependencies
    fn analyze_dependency_impact(&self, changed_files: &[PathBuf]) -> Result<Vec<PathBuf>> {
        let mut affected_files = HashSet::new();
        let state = self.state.as_ref().unwrap();
        
        for changed_file in changed_files {
            // Find files that depend on the changed file
            for dependency in &state.file_dependencies {
                if dependency.dependency_file == *changed_file {
                    affected_files.insert(dependency.dependent_file.clone());
                }
            }
        }
        
        Ok(affected_files.into_iter().collect())
    }

    /// Perform full analysis on all files
    async fn perform_full_analysis(&mut self, path: &Path) -> Result<IncrementalAnalysisResult> {
        log::info!("Performing full analysis");
        
        let vulnerabilities = self.analyzer.analyze_directory(path).await?;
        let all_files = self.collect_all_files(path)?;
        
        // Collect metadata first to avoid borrow checker issues
        let mut metadata_updates = Vec::new();
        for file_path in &all_files {
            let metadata = self.get_file_metadata(file_path)?;
            metadata_updates.push((file_path.clone(), metadata));
        }
        
        // Update state with all files
        let state = self.state.as_mut().unwrap();
        state.file_metadata.clear();
        state.cached_results.clear();
        
        for (file_path, metadata) in metadata_updates {
            state.file_metadata.insert(file_path, metadata);
        }
        
        // Update dependencies
        if self.config.include_dependency_analysis {
            state.file_dependencies = self.dependency_detector.analyze_dependencies(path)?;
        }
        
        state.last_full_analysis = current_timestamp();
        state.analysis_statistics.full_analyses += 1;
        
        Ok(IncrementalAnalysisResult {
            vulnerabilities,
            changed_files: all_files.clone(),
            skipped_files: Vec::new(),
            dependency_affected_files: Vec::new(),
            analysis_type: AnalysisType::Full,
            statistics: state.analysis_statistics.clone(),
            total_duration_ms: 0, // Will be set by caller
        })
    }

    /// Perform incremental analysis on changed files only
    async fn perform_incremental_analysis(
        &mut self, 
        _path: &Path, 
        changed_files: Vec<PathBuf>, 
        dependency_affected_files: Vec<PathBuf>
    ) -> Result<IncrementalAnalysisResult> {
        log::info!("Performing incremental analysis on {} changed files and {} dependency-affected files", 
                  changed_files.len(), dependency_affected_files.len());
        
        let mut all_files_to_analyze: HashSet<PathBuf> = changed_files.iter().cloned().collect();
        all_files_to_analyze.extend(dependency_affected_files.iter().cloned());
        
        let mut vulnerabilities = Vec::new();
        let mut skipped_files = Vec::new();
        let mut metadata_updates = Vec::new();
        let mut cache_updates = Vec::new();
        
        // Analyze changed and affected files
        for file_path in &all_files_to_analyze {
            match self.analyzer.analyze_file(file_path).await {
                Ok(file_vulns) => {
                    vulnerabilities.extend(file_vulns.clone());
                    
                    // Collect metadata and cache updates
                    let metadata = self.get_file_metadata(file_path)?;
                    metadata_updates.push((file_path.clone(), metadata.clone()));
                    
                    let result = FileAnalysisResult {
                        file_path: file_path.clone(),
                        vulnerabilities: file_vulns,
                        analysis_timestamp: current_timestamp(),
                        analyzer_version: "DeVAIC-1.0".to_string(),
                        analysis_duration_ms: 0,
                        file_metadata: metadata,
                    };
                    cache_updates.push((file_path.clone(), result));
                }
                Err(e) => {
                    log::warn!("Failed to analyze file {}: {}", file_path.display(), e);
                }
            }
        }
        
        // Apply collected updates to state
        let state = self.state.as_mut().unwrap();
        for (file_path, metadata) in metadata_updates {
            state.file_metadata.insert(file_path, metadata);
        }
        for (file_path, result) in cache_updates {
            state.cached_results.insert(file_path, result);
        }
        
        // Collect cached results for unchanged files
        for (cached_path, cached_result) in &state.cached_results {
            if !all_files_to_analyze.contains(cached_path) && cached_path.exists() {
                vulnerabilities.extend(cached_result.vulnerabilities.clone());
                skipped_files.push(cached_path.clone());
            }
        }
        
        state.analysis_statistics.incremental_analyses += 1;
        state.analysis_statistics.files_analyzed += all_files_to_analyze.len() as u64;
        state.analysis_statistics.files_skipped += skipped_files.len() as u64;
        
        Ok(IncrementalAnalysisResult {
            vulnerabilities,
            changed_files,
            skipped_files,
            dependency_affected_files,
            analysis_type: AnalysisType::Incremental,
            statistics: state.analysis_statistics.clone(),
            total_duration_ms: 0, // Will be set by caller
        })
    }

    /// Perform dependency-only analysis
    async fn perform_dependency_analysis(
        &mut self, 
        _path: &Path, 
        dependency_affected_files: Vec<PathBuf>
    ) -> Result<IncrementalAnalysisResult> {
        log::info!("Performing dependency analysis on {} files", dependency_affected_files.len());
        
        let mut vulnerabilities = Vec::new();
        let mut metadata_updates = Vec::new();
        
        for file_path in &dependency_affected_files {
            match self.analyzer.analyze_file(file_path).await {
                Ok(file_vulns) => {
                    vulnerabilities.extend(file_vulns);
                    
                    // Collect metadata updates
                    let metadata = self.get_file_metadata(file_path)?;
                    metadata_updates.push((file_path.clone(), metadata));
                }
                Err(e) => {
                    log::warn!("Failed to analyze dependency-affected file {}: {}", file_path.display(), e);
                }
            }
        }
        
        // Apply collected metadata updates to state
        let state = self.state.as_mut().unwrap();
        for (file_path, metadata) in metadata_updates {
            state.file_metadata.insert(file_path, metadata);
        }
        
        Ok(IncrementalAnalysisResult {
            vulnerabilities,
            changed_files: Vec::new(),
            skipped_files: Vec::new(),
            dependency_affected_files,
            analysis_type: AnalysisType::Dependency,
            statistics: state.analysis_statistics.clone(),
            total_duration_ms: 0, // Will be set by caller
        })
    }

    /// Determine what type of analysis to perform
    fn determine_analysis_type(
        &self, 
        changed_files: &[PathBuf], 
        dependency_affected_files: &[PathBuf]
    ) -> AnalysisType {
        // Check for force full analysis patterns
        for file_path in changed_files {
            if self.should_force_full_analysis(file_path) {
                return AnalysisType::Forced;
            }
        }
        
        // If too many files changed, do full analysis
        let total_changed = changed_files.len() + dependency_affected_files.len();
        if total_changed > 100 { // Configurable threshold
            return AnalysisType::Full;
        }
        
        if !changed_files.is_empty() {
            AnalysisType::Incremental
        } else if !dependency_affected_files.is_empty() {
            AnalysisType::Dependency
        } else {
            AnalysisType::Incremental // No changes, return cached results
        }
    }

    /// Check if a file should force full analysis
    fn should_force_full_analysis(&self, file_path: &Path) -> bool {
        let file_name = file_path.file_name()
            .and_then(|n| n.to_str())
            .unwrap_or("");
        
        for pattern in &self.config.force_full_analysis_patterns {
            if pattern.contains('*') {
                // Simple glob matching
                let pattern_parts: Vec<&str> = pattern.split('*').collect();
                if pattern_parts.len() == 2 {
                    let prefix = pattern_parts[0];
                    let suffix = pattern_parts[1];
                    if file_name.starts_with(prefix) && file_name.ends_with(suffix) {
                        return true;
                    }
                }
            } else if file_name == pattern {
                return true;
            }
        }
        
        false
    }

    /// Check if a path should be excluded from analysis
    fn is_path_excluded(&self, path: &Path) -> bool {
        for excluded_dir in &self.config.excluded_directories {
            if path.components().any(|c| c.as_os_str() == excluded_dir.as_str()) {
                return true;
            }
        }
        false
    }

    /// Get metadata for a file
    fn get_file_metadata(&self, path: &Path) -> Result<FileMetadata> {
        let metadata = fs::metadata(path)
            .map_err(|e| DevaicError::Analysis(format!("Failed to get metadata for {}: {}", path.display(), e)))?;
        
        let modified_time = metadata.modified()
            .map_err(|e| DevaicError::Analysis(format!("Failed to get modified time for {}: {}", path.display(), e)))?
            .duration_since(UNIX_EPOCH)
            .map_err(|e| DevaicError::Analysis(format!("Invalid modified time for {}: {}", path.display(), e)))?
            .as_secs();
        
        let content = fs::read(path)
            .map_err(|e| DevaicError::Analysis(format!("Failed to read file {}: {}", path.display(), e)))?;
        
        let content_hash = format!("{:x}", Sha256::digest(&content));
        
        let language = path.extension()
            .and_then(|ext| ext.to_str())
            .and_then(Language::from_extension);
        
        Ok(FileMetadata {
            path: path.to_path_buf(),
            size: metadata.len(),
            modified_time,
            content_hash,
            language,
            last_analyzed: current_timestamp(),
        })
    }

    /// Check if a file has changed
    fn has_file_changed(&self, current: &FileMetadata, cached: &FileMetadata) -> bool {
        current.size != cached.size 
            || current.modified_time != cached.modified_time 
            || current.content_hash != cached.content_hash
    }

    /// Collect all analyzable files in directory
    fn collect_all_files(&self, path: &Path) -> Result<Vec<PathBuf>> {
        let mut files = Vec::new();
        
        for entry in WalkDir::new(path)
            .follow_links(false)
            .into_iter()
            .filter_map(|e| e.ok())
            .filter(|e| e.file_type().is_file())
        {
            let file_path = entry.path();
            
            if !self.is_path_excluded(file_path) {
                // Check if it's an analyzable file
                if let Some(ext) = file_path.extension().and_then(|e| e.to_str()) {
                    if Language::from_extension(ext).is_some() {
                        files.push(file_path.to_path_buf());
                    }
                }
            }
        }
        
        Ok(files)
    }

    /// Load state from file
    fn load_state_from_file(&self, path: &Path) -> Result<IncrementalState> {
        let content = fs::read_to_string(path)
            .map_err(|e| DevaicError::Analysis(format!("Failed to read state file: {}", e)))?;
        
        serde_json::from_str(&content)
            .map_err(|e| DevaicError::Analysis(format!("Failed to parse state file: {}", e)))
    }

    /// Save state to file
    fn save_state(&self, project_root: &Path) -> Result<()> {
        if let Some(ref state) = self.state {
            let state_path = project_root.join(&self.config.state_file_path);
            
            // Ensure directory exists
            if let Some(parent) = state_path.parent() {
                fs::create_dir_all(parent)
                    .map_err(|e| DevaicError::Analysis(format!("Failed to create state directory: {}", e)))?;
            }
            
            let content = serde_json::to_string_pretty(state)
                .map_err(|e| DevaicError::Analysis(format!("Failed to serialize state: {}", e)))?;
            
            fs::write(&state_path, content)
                .map_err(|e| DevaicError::Analysis(format!("Failed to write state file: {}", e)))?;
            
            log::debug!("Saved incremental state to {}", state_path.display());
        }
        
        Ok(())
    }

    /// Create new empty state
    fn create_new_state(&mut self, project_root: &Path) {
        self.state = Some(IncrementalState {
            version: "1.0".to_string(),
            last_full_analysis: current_timestamp(),
            file_metadata: HashMap::new(),
            file_dependencies: Vec::new(),
            cached_results: HashMap::new(),
            analysis_statistics: IncrementalStatistics::default(),
            project_root: project_root.to_path_buf(),
        });
    }

    /// Update analysis statistics
    fn update_statistics(&mut self, result: &IncrementalAnalysisResult, duration_ms: u64) {
        if let Some(ref mut state) = self.state {
            let stats = &mut state.analysis_statistics;
            stats.total_analyses += 1;
            stats.last_updated = current_timestamp();
            
            match result.analysis_type {
                AnalysisType::Full => {
                    stats.full_analyses += 1;
                }
                AnalysisType::Incremental => {
                    stats.incremental_analyses += 1;
                    stats.time_saved_ms += duration_ms * result.skipped_files.len() as u64 / 10; // Estimate
                }
                _ => {}
            }
            
            // Update cache hit rate
            let total_files = result.changed_files.len() + result.skipped_files.len();
            if total_files > 0 {
                stats.cache_hit_rate = result.skipped_files.len() as f64 / total_files as f64;
            }
            
            // Update average analysis time
            stats.average_analysis_time_ms = 
                (stats.average_analysis_time_ms * (stats.total_analyses - 1) as f64 + duration_ms as f64) 
                / stats.total_analyses as f64;
        }
    }

    /// Get current analysis statistics
    pub fn get_statistics(&self) -> Option<&IncrementalStatistics> {
        self.state.as_ref().map(|s| &s.analysis_statistics)
    }

    /// Clear all cached state
    pub fn clear_cache(&mut self) -> Result<()> {
        if let Some(ref mut state) = self.state {
            state.file_metadata.clear();
            state.cached_results.clear();
            state.last_full_analysis = 0;
            log::info!("Cleared incremental analysis cache");
        }
        Ok(())
    }

    /// Force full analysis on next run
    pub fn force_full_analysis_on_next_run(&mut self) -> Result<()> {
        if let Some(ref mut state) = self.state {
            state.last_full_analysis = 0;
            log::info!("Marked for full analysis on next run");
        }
        Ok(())
    }
}

/// Dependency detector for analyzing file relationships
pub struct DependencyDetector {
    import_patterns: HashMap<Language, Vec<regex::Regex>>,
}

impl Default for DependencyDetector {
    fn default() -> Self {
        Self::new()
    }
}

impl DependencyDetector {
    pub fn new() -> Self {
        let mut import_patterns = HashMap::new();
        
        // Define import patterns for different languages
        import_patterns.insert(Language::Python, vec![
            regex::Regex::new(r"^import\s+(\S+)").unwrap(),
            regex::Regex::new(r"^from\s+(\S+)\s+import").unwrap(),
        ]);
        
        import_patterns.insert(Language::Javascript, vec![
            regex::Regex::new(r#"import\s+.*\s+from\s+['"]([^'"]+)['"]"#).unwrap(),
            regex::Regex::new(r#"require\(['"]([^'"]+)['"]\)"#).unwrap(),
        ]);
        
        import_patterns.insert(Language::TypeScript, vec![
            regex::Regex::new(r#"import\s+.*\s+from\s+['"]([^'"]+)['"]"#).unwrap(),
            regex::Regex::new(r#"require\(['"]([^'"]+)['"]\)"#).unwrap(),
        ]);
        
        import_patterns.insert(Language::Java, vec![
            regex::Regex::new(r"^import\s+([^;]+);").unwrap(),
        ]);
        
        import_patterns.insert(Language::Go, vec![
            regex::Regex::new(r#"import\s+"([^"]+)""#).unwrap(),
        ]);
        
        import_patterns.insert(Language::Rust, vec![
            regex::Regex::new(r"use\s+([^;]+);").unwrap(),
            regex::Regex::new(r"mod\s+(\w+);").unwrap(),
        ]);
        
        Self { import_patterns }
    }

    /// Analyze dependencies across the project
    pub fn analyze_dependencies(&self, root_path: &Path) -> Result<Vec<FileDependency>> {
        let mut dependencies = Vec::new();
        
        for entry in WalkDir::new(root_path)
            .follow_links(false)
            .into_iter()
            .filter_map(|e| e.ok())
            .filter(|e| e.file_type().is_file())
        {
            let file_path = entry.path();
            
            if let Some(ext) = file_path.extension().and_then(|e| e.to_str()) {
                if let Some(language) = Language::from_extension(ext) {
                    if let Ok(file_deps) = self.analyze_file_dependencies(file_path, &language, root_path) {
                        dependencies.extend(file_deps);
                    }
                }
            }
        }
        
        Ok(dependencies)
    }

    /// Analyze dependencies for a single file
    fn analyze_file_dependencies(
        &self, 
        file_path: &Path, 
        language: &Language, 
        root_path: &Path
    ) -> Result<Vec<FileDependency>> {
        let mut dependencies = Vec::new();
        
        if let Some(patterns) = self.import_patterns.get(language) {
            let content = fs::read_to_string(file_path)
                .map_err(|e| DevaicError::Analysis(format!("Failed to read file: {}", e)))?;
            
            for line in content.lines() {
                for pattern in patterns {
                    if let Some(captures) = pattern.captures(line) {
                        if let Some(import_path) = captures.get(1) {
                            let dependency_path = self.resolve_import_path(
                                import_path.as_str(), 
                                file_path, 
                                language, 
                                root_path
                            );
                            
                            if let Some(resolved_path) = dependency_path {
                                dependencies.push(FileDependency {
                                    dependent_file: file_path.to_path_buf(),
                                    dependency_file: resolved_path,
                                    dependency_type: DependencyType::Import,
                                    confidence: 0.9,
                                });
                            }
                        }
                    }
                }
            }
        }
        
        Ok(dependencies)
    }

    /// Resolve import path to actual file path
    fn resolve_import_path(
        &self, 
        import_path: &str, 
        current_file: &Path, 
        language: &Language, 
        root_path: &Path
    ) -> Option<PathBuf> {
        match language {
            Language::Python => {
                // Convert module path to file path
                let module_path = import_path.replace('.', "/");
                let py_file = format!("{}.py", module_path);
                let init_file = format!("{}/__init__.py", module_path);
                
                // Try relative to current file
                if let Some(parent) = current_file.parent() {
                    let relative_py = parent.join(&py_file);
                    if relative_py.exists() {
                        return Some(relative_py);
                    }
                    let relative_init = parent.join(&init_file);
                    if relative_init.exists() {
                        return Some(relative_init);
                    }
                }
                
                // Try relative to project root
                let root_py = root_path.join(&py_file);
                if root_py.exists() {
                    return Some(root_py);
                }
                let root_init = root_path.join(&init_file);
                if root_init.exists() {
                    return Some(root_init);
                }
            }
            Language::Javascript | Language::TypeScript => {
                // Handle relative imports
                if import_path.starts_with('.') {
                    if let Some(parent) = current_file.parent() {
                        let resolved = parent.join(import_path);
                        
                        // Try different extensions
                        for ext in &["js", "ts", "jsx", "tsx"] {
                            let with_ext = resolved.with_extension(ext);
                            if with_ext.exists() {
                                return Some(with_ext);
                            }
                        }
                        
                        // Try index files
                        for ext in &["js", "ts", "jsx", "tsx"] {
                            let index_file = resolved.join(format!("index.{}", ext));
                            if index_file.exists() {
                                return Some(index_file);
                            }
                        }
                    }
                }
            }
            _ => {
                // Basic resolution for other languages
                if let Some(parent) = current_file.parent() {
                    let resolved = parent.join(import_path);
                    if resolved.exists() {
                        return Some(resolved);
                    }
                }
            }
        }
        
        None
    }
}

/// Get current timestamp in seconds
fn current_timestamp() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs()
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::TempDir;
    use std::fs;

    #[tokio::test]
    async fn test_incremental_analysis_basic() {
        let temp_dir = TempDir::new().unwrap();
        let project_path = temp_dir.path();
        
        // Create test files
        let test_file = project_path.join("test.py");
        fs::write(&test_file, "print('hello')").unwrap();
        
        let config = IncrementalConfig::default();
        let analyzer = Analyzer::new(crate::config::Config::default()).unwrap();
        let mut engine = IncrementalAnalysisEngine::new(config, analyzer).unwrap();
        
        // First analysis should be full
        let result = engine.analyze_directory_incremental(project_path).await.unwrap();
        assert!(matches!(result.analysis_type, AnalysisType::Full));
        
        // Second analysis should be incremental with no changes
        let result = engine.analyze_directory_incremental(project_path).await.unwrap();
        assert!(matches!(result.analysis_type, AnalysisType::Incremental));
        assert_eq!(result.changed_files.len(), 0);
    }

    #[test]
    fn test_dependency_detection() {
        let detector = DependencyDetector::new();
        
        // Test Python import detection
        let patterns = &detector.import_patterns[&Language::Python];
        let test_lines = vec![
            "import os",
            "from sys import path",
            "import numpy as np",
        ];
        
        for line in test_lines {
            let found = patterns.iter().any(|p| p.is_match(line));
            assert!(found, "Failed to match: {}", line);
        }
    }

    #[test]
    fn test_file_change_detection() {
        let metadata1 = FileMetadata {
            path: PathBuf::from("test.py"),
            size: 100,
            modified_time: 1000,
            content_hash: "abc123".to_string(),
            language: Some(Language::Python),
            last_analyzed: 1000,
        };
        
        let metadata2 = FileMetadata {
            path: PathBuf::from("test.py"),
            size: 100,
            modified_time: 1001, // Different time
            content_hash: "abc123".to_string(),
            language: Some(Language::Python),
            last_analyzed: 1001,
        };
        
        let config = IncrementalConfig::default();
        let analyzer = Analyzer::new(crate::config::Config::default()).unwrap();
        let engine = IncrementalAnalysisEngine::new(config, analyzer).unwrap();
        
        assert!(engine.has_file_changed(&metadata2, &metadata1));
    }
}