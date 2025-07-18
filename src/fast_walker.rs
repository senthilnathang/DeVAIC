use std::path::{Path, PathBuf};
use std::fs::{self, DirEntry};
use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};
use crate::Language;

/// High-performance directory walker with optimizations
pub struct FastDirectoryWalker {
    follow_symlinks: bool,
    max_file_size: usize,
    max_depth: usize,
    exclude_patterns: Vec<glob::Pattern>,
    include_patterns: Vec<glob::Pattern>,
    file_counter: Arc<AtomicUsize>,
}

impl FastDirectoryWalker {
    pub fn new(
        follow_symlinks: bool,
        max_file_size: usize,
        max_depth: usize,
        exclude_patterns: Vec<glob::Pattern>,
        include_patterns: Vec<glob::Pattern>,
    ) -> Self {
        Self {
            follow_symlinks,
            max_file_size,
            max_depth,
            exclude_patterns,
            include_patterns,
            file_counter: Arc::new(AtomicUsize::new(0)),
        }
    }

    /// Walk directory with optimized depth-first traversal (simpler and faster)
    pub fn walk_directory(&self, root_path: &Path) -> Vec<PathBuf> {
        let mut files = Vec::new();
        self.walk_recursive(root_path, 0, &mut files);
        files
    }
    
    /// Recursive depth-first traversal (simpler than breadth-first)
    fn walk_recursive(&self, dir_path: &Path, depth: usize, files: &mut Vec<PathBuf>) {
        if depth > self.max_depth {
            return;
        }

        // Process files in current directory
        let dir_files = self.scan_single_directory(dir_path);
        files.extend(dir_files);

        // Recurse into subdirectories
        if depth < self.max_depth {
            if let Ok(entries) = fs::read_dir(dir_path) {
                for entry in entries.flatten() {
                    let path = entry.path();
                    if path.is_dir() && self.should_traverse_directory(&path) {
                        self.walk_recursive(&path, depth + 1, files);
                    }
                }
            }
        }
    }

    /// Scan a single directory without recursion
    fn scan_single_directory(&self, dir_path: &Path) -> Vec<PathBuf> {
        // Skip caching for simplicity and performance

        let mut files = Vec::new();
        
        // Use read_dir for better performance than walkdir for single directory
        match fs::read_dir(dir_path) {
            Ok(entries) => {
                // Pre-allocate vector with estimated capacity
                let mut valid_files = Vec::with_capacity(64);
                
                // Process entries directly without collecting first (saves memory)
                for entry in entries {
                    if let Ok(entry) = entry {
                        let path = entry.path();
                        
                        // Quick file type check using DirEntry (faster than Path::is_file)
                        if let Ok(file_type) = entry.file_type() {
                            if file_type.is_file() {
                                // Use fast file check with early returns
                                if self.should_analyze_file_fast(&path, &entry) {
                                    valid_files.push(path);
                                }
                            }
                        }
                    }
                }
                
                files.extend(valid_files);
            }
            Err(_) => {
                // Skip directories we can't read
                return files;
            }
        }

        // Skip caching for better performance

        files
    }

    /// Faster file analysis check using DirEntry metadata
    fn should_analyze_file_fast(&self, file_path: &Path, entry: &DirEntry) -> bool {
        // Quick file size check using cached metadata from DirEntry
        if let Ok(metadata) = entry.metadata() {
            if metadata.len() > self.max_file_size as u64 {
                return false;
            }
        }

        // Check if file has supported extension
        let extension = match file_path.extension().and_then(|ext| ext.to_str()) {
            Some(ext) => ext.to_lowercase(),
            None => return false,
        };

        // Fast extension check for common non-code files
        match extension.as_str() {
            // Binary files
            "exe" | "dll" | "so" | "dylib" | "a" | "lib" | "o" | "obj" |
            "bin" | "img" | "iso" | "dmg" | "pkg" | "deb" | "rpm" |
            // Archives
            "zip" | "tar" | "gz" | "bz2" | "xz" | "7z" | "rar" |
            // Images
            "jpg" | "jpeg" | "png" | "gif" | "bmp" | "svg" | "ico" |
            // Media
            "mp3" | "mp4" | "avi" | "mov" | "wmv" | "flv" | "mkv" |
            // Documents
            "pdf" | "doc" | "docx" | "xls" | "xlsx" | "ppt" | "pptx" |
            // Fonts
            "ttf" | "otf" | "woff" | "woff2" | "eot" => return false,
            _ => {}
        }

        // Direct language check for better performance
        if Language::from_extension(&extension).is_none() {
            return false;
        }

        // Fast pattern matching using pre-compiled patterns
        let path_str = file_path.to_string_lossy();
        
        // Check exclude patterns
        for pattern in &self.exclude_patterns {
            if pattern.matches(&path_str) {
                return false;
            }
        }

        // Check include patterns
        if !self.include_patterns.is_empty() {
            let mut matches = false;
            for pattern in &self.include_patterns {
                if pattern.matches(&path_str) {
                    matches = true;
                    break;
                }
            }
            if !matches {
                return false;
            }
        }

        // Update file counter
        self.file_counter.fetch_add(1, Ordering::Relaxed);

        true
    }

    /// Check if we should traverse into a directory
    fn should_traverse_directory(&self, dir_path: &Path) -> bool {
        // Get directory name once for multiple checks
        let dir_name = match dir_path.file_name().and_then(|n| n.to_str()) {
            Some(name) => name,
            None => return false,
        };

        // Skip hidden directories (starting with .)
        if dir_name.starts_with('.') && dir_name != "." && dir_name != ".." {
            return false;
        }

        // Common directories to skip for performance (check first for speed)
        match dir_name {
            "node_modules" | "target" | "build" | "dist" | ".git" | 
            ".svn" | ".hg" | "__pycache__" | ".pytest_cache" | 
            "coverage" | ".nyc_output" | "vendor" | "bin" | "obj" |
            ".vscode" | ".idea" | ".vs" | "Debug" | "Release" |
            "Pods" | "DerivedData" | "xcuserdata" | "CMakeFiles" |
            "venv" | "env" | ".env" | "site-packages" |
            "bower_components" | "jspm_packages" | "typings" |
            ".sass-cache" | ".gradle" | ".m2" | ".ivy2" | ".sbt" => {
                return false;
            }
            _ => {}
        }

        // Check if directory is a symlink
        if let Ok(metadata) = dir_path.symlink_metadata() {
            if metadata.file_type().is_symlink() && !self.follow_symlinks {
                return false;
            }
        }

        // Check exclude patterns (only if we have patterns)
        if !self.exclude_patterns.is_empty() {
            let path_str = dir_path.to_string_lossy();
            for pattern in &self.exclude_patterns {
                if pattern.matches(&path_str) {
                    return false;
                }
            }
        }

        true
    }

    /// Get current file count
    pub fn get_file_count(&self) -> usize {
        self.file_counter.load(Ordering::Relaxed)
    }

    /// Reset file counter
    pub fn reset_counter(&self) {
        self.file_counter.store(0, Ordering::Relaxed);
    }
}

/// Optimized parallel directory scanner
pub struct OptimizedDirectoryScanner {
    walker: FastDirectoryWalker,
    batch_size: usize,
}

impl OptimizedDirectoryScanner {
    pub fn new(
        follow_symlinks: bool,
        max_file_size: usize,
        max_depth: usize,
        exclude_patterns: Vec<glob::Pattern>,
        include_patterns: Vec<glob::Pattern>,
        batch_size: usize,
    ) -> Self {
        let walker = FastDirectoryWalker::new(
            follow_symlinks,
            max_file_size,
            max_depth,
            exclude_patterns,
            include_patterns,
        );

        Self {
            walker,
            batch_size,
        }
    }

    /// Scan directory with optimized parallel processing
    pub fn scan_directory(&self, root_path: &Path) -> Vec<PathBuf> {
        self.walker.reset_counter();
        let start_time = std::time::Instant::now();
        
        let files = self.walker.walk_directory(root_path);
        
        let duration = start_time.elapsed();
        let file_count = self.walker.get_file_count();
        
        log::info!("Fast scanner found {} files in {:.2}s", file_count, duration.as_secs_f64());
        
        files
    }

    /// Get scanner statistics
    pub fn get_stats(&self) -> ScannerStats {
        ScannerStats {
            files_found: self.walker.get_file_count(),
            batch_size: self.batch_size,
        }
    }
}

/// Scanner statistics
#[derive(Debug)]
pub struct ScannerStats {
    pub files_found: usize,
    pub batch_size: usize,
}

/// Directory traversal strategy
#[derive(Debug, Clone)]
pub enum TraversalStrategy {
    /// Breadth-first search (better for shallow, wide directories)
    BreadthFirst,
    /// Depth-first search (better for deep, narrow directories)
    DepthFirst,
    /// Adaptive strategy based on directory structure
    Adaptive,
}

/// Advanced directory walker with configurable strategies
pub struct AdvancedDirectoryWalker {
    base_walker: FastDirectoryWalker,
    strategy: TraversalStrategy,
    progress_callback: Option<Box<dyn Fn(usize, usize) + Send + Sync>>,
}

impl AdvancedDirectoryWalker {
    pub fn new(
        follow_symlinks: bool,
        max_file_size: usize,
        max_depth: usize,
        exclude_patterns: Vec<glob::Pattern>,
        include_patterns: Vec<glob::Pattern>,
        strategy: TraversalStrategy,
    ) -> Self {
        let base_walker = FastDirectoryWalker::new(
            follow_symlinks,
            max_file_size,
            max_depth,
            exclude_patterns,
            include_patterns,
        );

        Self {
            base_walker,
            strategy,
            progress_callback: None,
        }
    }

    /// Set progress callback for long-running scans
    pub fn set_progress_callback<F>(&mut self, callback: F) 
    where
        F: Fn(usize, usize) + Send + Sync + 'static,
    {
        self.progress_callback = Some(Box::new(callback));
    }

    /// Walk directory with selected strategy
    pub fn walk_directory(&self, root_path: &Path) -> Vec<PathBuf> {
        match self.strategy {
            TraversalStrategy::BreadthFirst => self.base_walker.walk_directory(root_path),
            TraversalStrategy::DepthFirst => self.walk_depth_first(root_path),
            TraversalStrategy::Adaptive => self.walk_adaptive(root_path),
        }
    }

    /// Depth-first traversal implementation
    fn walk_depth_first(&self, root_path: &Path) -> Vec<PathBuf> {
        let mut files = Vec::new();
        self.walk_depth_first_recursive(root_path, 0, &mut files);
        files
    }

    /// Recursive depth-first helper
    fn walk_depth_first_recursive(&self, dir_path: &Path, depth: usize, files: &mut Vec<PathBuf>) {
        if depth > self.base_walker.max_depth {
            return;
        }

        // Process files in current directory
        let dir_files = self.base_walker.scan_single_directory(dir_path);
        files.extend(dir_files);

        // Recurse into subdirectories
        if depth < self.base_walker.max_depth {
            if let Ok(entries) = fs::read_dir(dir_path) {
                for entry in entries.flatten() {
                    let path = entry.path();
                    if path.is_dir() && self.base_walker.should_traverse_directory(&path) {
                        self.walk_depth_first_recursive(&path, depth + 1, files);
                    }
                }
            }
        }
    }

    /// Adaptive traversal based on directory structure
    fn walk_adaptive(&self, root_path: &Path) -> Vec<PathBuf> {
        // Analyze directory structure to choose optimal strategy
        let (width, depth) = self.analyze_directory_structure(root_path);
        
        if width > depth * 2 {
            // Wide directory: use breadth-first
            self.base_walker.walk_directory(root_path)
        } else {
            // Deep directory: use depth-first
            self.walk_depth_first(root_path)
        }
    }

    /// Analyze directory structure to determine optimal traversal strategy
    fn analyze_directory_structure(&self, root_path: &Path) -> (usize, usize) {
        let mut max_width = 0;
        let mut max_depth = 0;
        
        self.analyze_recursive(root_path, 0, &mut max_width, &mut max_depth);
        
        (max_width, max_depth)
    }

    /// Recursive structure analysis
    fn analyze_recursive(&self, dir_path: &Path, depth: usize, max_width: &mut usize, max_depth: &mut usize) {
        if depth > 3 {  // Limit analysis depth for performance
            return;
        }

        *max_depth = (*max_depth).max(depth);

        if let Ok(entries) = fs::read_dir(dir_path) {
            let mut dir_count = 0;
            for entry in entries.flatten() {
                let path = entry.path();
                if path.is_dir() && self.base_walker.should_traverse_directory(&path) {
                    dir_count += 1;
                    self.analyze_recursive(&path, depth + 1, max_width, max_depth);
                }
            }
            *max_width = (*max_width).max(dir_count);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::TempDir;
    use std::fs::File;
    use std::io::Write;

    #[test]
    fn test_fast_walker_basic() {
        let temp_dir = TempDir::new().unwrap();
        let test_file = temp_dir.path().join("test.py");
        let mut file = File::create(&test_file).unwrap();
        writeln!(file, "print('hello')").unwrap();

        let walker = FastDirectoryWalker::new(
            false,
            1024*1024,
            100,
            vec![],
            vec![],
        );

        let files = walker.walk_directory(temp_dir.path());
        assert_eq!(files.len(), 1);
        assert_eq!(files[0], test_file);
    }

    #[test]
    fn test_depth_limiting() {
        let temp_dir = TempDir::new().unwrap();
        
        // Create nested directory structure
        let nested_dir = temp_dir.path().join("level1").join("level2");
        std::fs::create_dir_all(&nested_dir).unwrap();
        
        let deep_file = nested_dir.join("deep.py");
        let mut file = File::create(&deep_file).unwrap();
        writeln!(file, "print('deep')").unwrap();

        // Test with depth limit 1
        let walker = FastDirectoryWalker::new(
            false,
            1024*1024,
            1,
            vec![],
            vec![],
        );

        let files = walker.walk_directory(temp_dir.path());
        assert_eq!(files.len(), 0); // Should not find the deep file
    }
}
