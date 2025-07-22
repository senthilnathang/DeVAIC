use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::Instant;
use tokio::fs;
use tokio::io::{AsyncReadExt, BufReader};
use tokio::sync::{mpsc, Semaphore};
use tokio_stream::{wrappers::ReceiverStream, StreamExt};
use futures::future::join_all;
use crate::{Config, Language, Result, Vulnerability};
use crate::cache::get_global_cache;

/// Async file scanner with streaming processing and backpressure control
pub struct AsyncFileScanner {
    config: Arc<Config>,
    concurrent_limit: usize,
    buffer_size: usize,
    chunk_size: usize,
    progress_callback: Option<Box<dyn Fn(usize, usize) + Send + Sync>>,
}

impl AsyncFileScanner {
    pub fn new(config: Config) -> Self {
        let concurrent_limit = std::thread::available_parallelism()
            .map(|n| n.get() * 2)
            .unwrap_or(8);

        Self {
            config: Arc::new(config),
            concurrent_limit,
            buffer_size: 64 * 1024,
            chunk_size: 100,
            progress_callback: None,
        }
    }

    /// Set progress callback for monitoring
    pub fn with_progress_callback<F>(mut self, callback: F) -> Self
    where
        F: Fn(usize, usize) + Send + Sync + 'static,
    {
        self.progress_callback = Some(Box::new(callback));
        self
    }

    /// Configure concurrency limits
    pub fn with_concurrency(mut self, concurrent_limit: usize) -> Self {
        self.concurrent_limit = concurrent_limit;
        self
    }

    /// Scan directory asynchronously with streaming
    pub async fn scan_directory_stream(
        &self,
        path: &Path,
    ) -> Result<impl futures::Stream<Item = Result<Vec<Vulnerability>>>> {
        let files = self.collect_files_async(path).await?;
        let total_files = files.len();
        
        log::info!("Starting async scan of {} files", total_files);

        let (tx, rx) = mpsc::channel(self.chunk_size);
        let semaphore = Arc::new(Semaphore::new(self.concurrent_limit));
        
        // Spawn task to process files and send results
        let config = Arc::clone(&self.config);
        let buffer_size = self.buffer_size;
        let progress_callback = self.progress_callback.as_ref().map(|cb| Arc::clone(cb) as Arc<dyn Fn(usize, usize) + Send + Sync>);
        
        tokio::spawn(async move {
            let mut processed = 0;
            
            for chunk in files.chunks(100) { // Process in chunks of 100 files
                let chunk_tasks: Vec<_> = chunk
                    .iter()
                    .map(|file_path| {
                        let semaphore = Arc::clone(&semaphore);
                        let config = Arc::clone(&config);
                        let file_path = file_path.clone();
                        let buffer_size = buffer_size;
                        
                        async move {
                            let _permit = semaphore.acquire().await.unwrap();
                            Self::analyze_file_async(&file_path, &config, buffer_size).await
                        }
                    })
                    .collect();

                let chunk_results = join_all(chunk_tasks).await;
                let mut chunk_vulnerabilities = Vec::new();
                
                for result in chunk_results {
                    match result {
                        Ok(vulns) => chunk_vulnerabilities.extend(vulns),
                        Err(e) => log::warn!("File analysis error: {}", e),
                    }
                    processed += 1;
                }

                // Report progress
                if let Some(ref callback) = progress_callback {
                    callback(processed, total_files);
                }

                if let Err(e) = tx.send(Ok(chunk_vulnerabilities)).await {
                    log::error!("Failed to send chunk results: {}", e);
                    break;
                }
            }
        });

        Ok(ReceiverStream::new(rx))
    }

    /// Collect all files to analyze asynchronously
    async fn collect_files_async(&self, root_path: &Path) -> Result<Vec<PathBuf>> {
        let mut files = Vec::new();
        let mut stack = vec![root_path.to_path_buf()];

        while let Some(current_path) = stack.pop() {
            let metadata = match fs::metadata(&current_path).await {
                Ok(metadata) => metadata,
                Err(_) => continue,
            };

            if metadata.is_file() {
                if self.should_analyze_file(&current_path) {
                    files.push(current_path);
                }
            } else if metadata.is_dir() {
                let mut entries = match fs::read_dir(&current_path).await {
                    Ok(entries) => entries,
                    Err(_) => continue,
                };

                while let Some(entry) = entries.next_entry().await? {
                    let path = entry.path();
                    if self.should_traverse_directory(&path) {
                        stack.push(path);
                    }
                }
            }
        }

        Ok(files)
    }

    /// Check if file should be analyzed based on configuration
    fn should_analyze_file(&self, path: &Path) -> bool {
        // Check file extension
        if let Some(extension) = path.extension().and_then(|ext| ext.to_str()) {
            if Language::from_extension(extension).is_none() {
                return false;
            }
        } else {
            return false;
        }

        // Check include/exclude patterns
        let path_str = path.to_string_lossy();
        
        // Check exclude patterns
        for pattern in &self.config.analysis.exclude_patterns {
            if glob::Pattern::new(pattern)
                .ok()
                .map_or(false, |p| p.matches(&path_str))
            {
                return false;
            }
        }

        // Check include patterns (if specified)
        if !self.config.analysis.include_patterns.is_empty() {
            let mut matches_include = false;
            for pattern in &self.config.analysis.include_patterns {
                if glob::Pattern::new(pattern)
                    .ok()
                    .map_or(false, |p| p.matches(&path_str))
                {
                    matches_include = true;
                    break;
                }
            }
            if !matches_include {
                return false;
            }
        }

        true
    }

    /// Check if directory should be traversed
    fn should_traverse_directory(&self, path: &Path) -> bool {
        let path_str = path.to_string_lossy();
        
        // Check common directory patterns to skip
        let skip_dirs = [
            ".git", ".svn", ".hg", "node_modules", "target", 
            "build", "dist", "__pycache__", ".pytest_cache",
        ];
        
        if let Some(dir_name) = path.file_name().and_then(|name| name.to_str()) {
            if skip_dirs.contains(&dir_name) {
                return false;
            }
        }

        // Check exclude patterns
        for pattern in &self.config.analysis.exclude_patterns {
            if glob::Pattern::new(pattern)
                .ok()
                .map_or(false, |p| p.matches(&path_str))
            {
                return false;
            }
        }

        true
    }

    /// Analyze single file asynchronously with streaming
    async fn analyze_file_async(
        file_path: &Path,
        config: &Config,
        buffer_size: usize,
    ) -> Result<Vec<Vulnerability>> {
        let start_time = Instant::now();
        
        // Get language from extension
        let language = match file_path.extension().and_then(|ext| ext.to_str()) {
            Some(ext) => match Language::from_extension(ext) {
                Some(lang) => lang,
                None => return Ok(Vec::new()),
            },
            None => return Ok(Vec::new()),
        };

        // Check cache first
        if let Some(cached_vulns) = Self::check_cache(file_path).await {
            log::debug!("Cache hit for file: {}", file_path.display());
            return Ok(cached_vulns);
        }

        // Read file content with streaming
        let content = Self::read_file_streaming(file_path, buffer_size).await?;
        
        // Cache file content hash for future comparisons
        Self::update_cache(file_path, &content).await;

        // Create source file and analyze
        let source_file = crate::parsers::SourceFile::new(
            file_path.to_path_buf(),
            content,
            language,
        );

        // Parse and analyze (CPU-bound work)
        let vulnerabilities = tokio::task::spawn_blocking(move || -> Result<Vec<Vulnerability>> {
            let mut parser = crate::parsers::ParserFactory::create_parser(&source_file.language)?;
            let ast = parser.parse(&source_file)?;
            let rule_engine = crate::rules::RuleEngine::new(&config.rules);
            rule_engine.analyze(&source_file, &ast)
        }).await.map_err(|e| crate::DevaicError::Analysis(format!("Task join error: {}", e)))??;

        let analysis_time = start_time.elapsed();
        log::debug!("Analyzed {} in {:?}", file_path.display(), analysis_time);

        Ok(vulnerabilities)
    }

    /// Read file with async streaming
    async fn read_file_streaming(path: &Path, buffer_size: usize) -> Result<String> {
        let file = fs::File::open(path).await
            .map_err(|e| crate::DevaicError::Analysis(format!("Failed to open file {}: {}", path.display(), e)))?;
        
        let metadata = file.metadata().await
            .map_err(|e| crate::DevaicError::Analysis(format!("Failed to get metadata for {}: {}", path.display(), e)))?;
        
        let file_size = metadata.len() as usize;
        
        if file_size == 0 {
            return Ok(String::new());
        }

        // Pre-allocate string with file size capacity
        let mut content = String::with_capacity(file_size);
        let mut reader = BufReader::with_capacity(buffer_size, file);
        
        reader.read_to_string(&mut content).await
            .map_err(|e| crate::DevaicError::Analysis(format!("Failed to read file {}: {}", path.display(), e)))?;
        
        Ok(content)
    }

    /// Check cache for existing analysis
    async fn check_cache(path: &Path) -> Option<Vec<Vulnerability>> {
        let cache = get_global_cache();
        
        // Check if file content has changed
        if let Ok(content) = fs::read_to_string(path).await {
            if !cache.has_content_changed(path, &content) {
                return cache.get_analysis_result(path);
            }
        }
        
        None
    }

    /// Update cache with file information
    async fn update_cache(path: &Path, content: &str) {
        let cache = get_global_cache();
        
        // Update content hash for change detection
        cache.update_content_hash(path, content);
    }
}

/// Async batch processor for handling large numbers of files efficiently
pub struct AsyncBatchProcessor {
    batch_size: usize,
    concurrent_batches: usize,
    retry_attempts: usize,
    timeout_seconds: u64,
}

impl AsyncBatchProcessor {
    pub fn new(batch_size: usize, concurrent_batches: usize) -> Self {
        Self {
            batch_size,
            concurrent_batches,
            retry_attempts: 3,
            timeout_seconds: 30,
        }
    }

    /// Process files in batches with error handling and retries
    pub async fn process_files_batched<F, R>(
        &self,
        files: Vec<PathBuf>,
        processor: F,
    ) -> Vec<Result<R>>
    where
        F: Fn(PathBuf) -> std::pin::Pin<Box<dyn futures::Future<Output = Result<R>> + Send>> + Send + Sync + Clone + 'static,
        R: Send + 'static,
    {
        let batches: Vec<_> = files.chunks(self.batch_size)
            .map(|chunk| chunk.to_vec())
            .collect();

        let semaphore = Arc::new(Semaphore::new(self.concurrent_batches));
        let mut tasks = Vec::new();

        for batch in batches {
            let semaphore = Arc::clone(&semaphore);
            let processor = processor.clone();
            let timeout = self.timeout_seconds;
            let retry_attempts = self.retry_attempts;

            let task = tokio::spawn(async move {
                let _permit = semaphore.acquire().await.unwrap();
                
                let batch_tasks: Vec<_> = batch.into_iter()
                    .map(|file| {
                        let processor = processor.clone();
                        async move {
                            Self::process_with_retry(file, processor, retry_attempts, timeout).await
                        }
                    })
                    .collect();

                join_all(batch_tasks).await
            });

            tasks.push(task);
        }

        // Wait for all batches to complete
        let batch_results = join_all(tasks).await;
        
        // Flatten results
        let mut all_results = Vec::new();
        for batch_result in batch_results {
            match batch_result {
                Ok(results) => all_results.extend(results),
                Err(e) => {
                    log::error!("Batch processing error: {}", e);
                    // Add error results for failed batch
                    for _ in 0..self.batch_size {
                        all_results.push(Err(crate::DevaicError::Analysis(
                            format!("Batch processing failed: {}", e)
                        )));
                    }
                }
            }
        }

        all_results
    }

    /// Process single file with retry logic
    async fn process_with_retry<F, R>(
        file: PathBuf,
        processor: F,
        retry_attempts: usize,
        timeout_seconds: u64,
    ) -> Result<R>
    where
        F: Fn(PathBuf) -> std::pin::Pin<Box<dyn futures::Future<Output = Result<R>> + Send>>,
    {
        let mut last_error = None;
        
        for attempt in 0..retry_attempts {
            let result = tokio::time::timeout(
                std::time::Duration::from_secs(timeout_seconds),
                processor(file.clone())
            ).await;

            match result {
                Ok(Ok(value)) => return Ok(value),
                Ok(Err(e)) => {
                    last_error = Some(e);
                    if attempt < retry_attempts - 1 {
                        tokio::time::sleep(std::time::Duration::from_millis(100 * (1 << attempt))).await;
                    }
                }
                Err(_) => {
                    last_error = Some(crate::DevaicError::Analysis("Timeout".to_string()));
                    if attempt < retry_attempts - 1 {
                        tokio::time::sleep(std::time::Duration::from_millis(100 * (1 << attempt))).await;
                    }
                }
            }
        }

        Err(last_error.unwrap_or_else(|| 
            crate::DevaicError::Analysis("All retry attempts failed".to_string())
        ))
    }
}

/// Streaming vulnerability collector for memory-efficient processing
pub struct StreamingVulnerabilityCollector {
    buffer: Vec<Vulnerability>,
    buffer_limit: usize,
    total_collected: usize,
    deduplication_enabled: bool,
    seen_hashes: std::collections::HashSet<u64>,
}

impl StreamingVulnerabilityCollector {
    pub fn new(buffer_limit: usize, deduplication_enabled: bool) -> Self {
        Self {
            buffer: Vec::with_capacity(buffer_limit),
            buffer_limit,
            total_collected: 0,
            deduplication_enabled,
            seen_hashes: std::collections::HashSet::new(),
        }
    }

    /// Add vulnerabilities to the collector
    pub fn add_batch(&mut self, vulnerabilities: Vec<Vulnerability>) {
        for vuln in vulnerabilities {
            if self.deduplication_enabled {
                let hash = self.calculate_hash(&vuln);
                if self.seen_hashes.insert(hash) {
                    self.buffer.push(vuln);
                    self.total_collected += 1;
                }
            } else {
                self.buffer.push(vuln);
                self.total_collected += 1;
            }
        }
    }

    /// Get buffered vulnerabilities and clear buffer
    pub fn drain_buffer(&mut self) -> Vec<Vulnerability> {
        std::mem::take(&mut self.buffer)
    }

    /// Get statistics
    pub fn stats(&self) -> (usize, usize, usize) {
        (self.buffer.len(), self.total_collected, self.seen_hashes.len())
    }

    /// Calculate hash for deduplication
    fn calculate_hash(&self, vuln: &Vulnerability) -> u64 {
        use std::hash::{Hash, Hasher};
        let mut hasher = siphasher::sip::SipHasher::new();
        
        vuln.vulnerability_type.hash(&mut hasher);
        vuln.file_path.hash(&mut hasher);
        vuln.line_number.hash(&mut hasher);
        
        hasher.finish()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::TempDir;
    use tokio::fs::File;
    use tokio::io::AsyncWriteExt;

    #[tokio::test]
    async fn test_async_file_scanner() {
        let temp_dir = TempDir::new().unwrap();
        let file_path = temp_dir.path().join("test.py");
        
        let mut file = File::create(&file_path).await.unwrap();
        file.write_all(b"print('Hello, world!')").await.unwrap();
        file.flush().await.unwrap();
        
        let config = Config::default();
        let scanner = AsyncFileScanner::new(config);
        
        let files = scanner.collect_files_async(temp_dir.path()).await.unwrap();
        assert_eq!(files.len(), 1);
        assert_eq!(files[0], file_path);
    }

    #[tokio::test]
    async fn test_streaming_collector() {
        let mut collector = StreamingVulnerabilityCollector::new(100, true);
        
        let vuln = Vulnerability {
            id: "test".to_string(),
            vulnerability_type: "SQL Injection".to_string(),
            severity: crate::Severity::High,
            category: "security".to_string(),
            description: "Test vulnerability".to_string(),
            file_path: "test.py".to_string(),
            line_number: 10,
            column: 5,
            source_code: "test code".to_string(),
            recommendation: "Fix this".to_string(),
            cwe: None,
        };
        
        collector.add_batch(vec![vuln.clone(), vuln]); // Duplicate should be deduplicated
        
        let (buffer_len, total, unique) = collector.stats();
        assert_eq!(buffer_len, 1);
        assert_eq!(total, 1);
        assert_eq!(unique, 1);
    }
}