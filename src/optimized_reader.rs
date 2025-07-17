use std::fs::File;
use std::io::{BufReader, BufRead, Read};
use std::path::Path;
use memmap2::Mmap;
use crate::cache::get_global_cache;

/// Threshold for using memory-mapped files (1MB)
const MMAP_THRESHOLD: usize = 1024 * 1024;

/// Threshold for using buffered reading (10KB)
const BUFFER_THRESHOLD: usize = 10 * 1024;

/// Optimized file reader with memory mapping and caching
pub struct OptimizedFileReader {
    cache_enabled: bool,
}

impl OptimizedFileReader {
    pub fn new(cache_enabled: bool) -> Self {
        Self { cache_enabled }
    }

    /// Read file content with optimal strategy based on file size
    pub fn read_file(&self, path: &Path) -> std::io::Result<String> {
        let metadata = std::fs::metadata(path)?;
        let file_size = metadata.len() as usize;

        // Check cache first if enabled
        if self.cache_enabled {
            let cache = get_global_cache();
            if let Some(cached_entry) = cache.get_file_metadata(path) {
                if cached_entry.file_size == metadata.len() {
                    if let Ok(modified) = metadata.modified() {
                        if modified == cached_entry.modified_time {
                            // File hasn't changed, but we still need to read content
                            // Cache stores metadata, not content for memory efficiency
                        }
                    }
                }
            }
        }

        match file_size {
            // Large files: use memory mapping
            size if size > MMAP_THRESHOLD => self.read_with_mmap(path),
            // Medium files: use buffered reading
            size if size > BUFFER_THRESHOLD => self.read_with_buffer(path),
            // Small files: direct reading
            _ => self.read_direct(path),
        }
    }

    /// Read file using memory mapping for large files
    fn read_with_mmap(&self, path: &Path) -> std::io::Result<String> {
        let file = File::open(path)?;
        let mmap = unsafe { Mmap::map(&file)? };
        
        // Convert bytes to string
        match std::str::from_utf8(&mmap) {
            Ok(content) => Ok(content.to_string()),
            Err(_) => {
                // If not valid UTF-8, try to handle as bytes
                String::from_utf8(mmap.to_vec())
                    .map_err(|_| std::io::Error::new(
                        std::io::ErrorKind::InvalidData,
                        "File contains invalid UTF-8"
                    ))
            }
        }
    }

    /// Read file using buffered reading for medium files
    fn read_with_buffer(&self, path: &Path) -> std::io::Result<String> {
        let file = File::open(path)?;
        let mut reader = BufReader::with_capacity(64 * 1024, file); // 64KB buffer
        let mut content = String::new();
        reader.read_to_string(&mut content)?;
        Ok(content)
    }

    /// Read file directly for small files
    fn read_direct(&self, path: &Path) -> std::io::Result<String> {
        std::fs::read_to_string(path)
    }

    /// Read file lines efficiently (useful for line-by-line processing)
    pub fn read_lines(&self, path: &Path) -> std::io::Result<Vec<String>> {
        let file = File::open(path)?;
        let reader = BufReader::new(file);
        let lines: Result<Vec<String>, std::io::Error> = reader.lines().collect();
        lines
    }

    /// Stream file lines (memory efficient for large files)
    pub fn stream_lines(&self, path: &Path) -> std::io::Result<impl Iterator<Item = std::io::Result<String>>> {
        let file = File::open(path)?;
        let reader = BufReader::new(file);
        Ok(reader.lines())
    }
}

/// Parallel file reader using rayon for concurrent file processing
pub struct ParallelFileReader {
    reader: OptimizedFileReader,
    thread_pool_size: usize,
}

impl ParallelFileReader {
    pub fn new(cache_enabled: bool, thread_pool_size: Option<usize>) -> Self {
        let pool_size = thread_pool_size.unwrap_or_else(|| {
            std::thread::available_parallelism()
                .map(|n| n.get())
                .unwrap_or(4)
        });

        Self {
            reader: OptimizedFileReader::new(cache_enabled),
            thread_pool_size: pool_size,
        }
    }

    /// Read multiple files in parallel
    pub fn read_files_parallel(&self, paths: &[&Path]) -> Vec<(String, Result<String, std::io::Error>)> {
        use rayon::prelude::*;

        // Configure rayon thread pool
        let pool = rayon::ThreadPoolBuilder::new()
            .num_threads(self.thread_pool_size)
            .build()
            .unwrap();

        pool.install(|| {
            paths.par_iter().map(|path| {
                let path_str = path.to_string_lossy().to_string();
                let result = self.reader.read_file(path);
                (path_str, result)
            }).collect()
        })
    }

    /// Process files in parallel with a custom function
    pub fn process_files_parallel<F, R>(&self, paths: &[&Path], processor: F) -> Vec<R>
    where
        F: Fn(&Path, &str) -> R + Send + Sync,
        R: Send,
    {
        use rayon::prelude::*;

        let pool = rayon::ThreadPoolBuilder::new()
            .num_threads(self.thread_pool_size)
            .build()
            .unwrap();

        pool.install(|| {
            paths.par_iter().filter_map(|path| {
                match self.reader.read_file(path) {
                    Ok(content) => Some(processor(path, &content)),
                    Err(_) => None,
                }
            }).collect()
        })
    }
}

/// File content analyzer with caching and pattern matching optimization
pub struct FileContentAnalyzer {
    reader: OptimizedFileReader,
    cache_enabled: bool,
}

impl FileContentAnalyzer {
    pub fn new(cache_enabled: bool) -> Self {
        Self {
            reader: OptimizedFileReader::new(cache_enabled),
            cache_enabled,
        }
    }

    /// Analyze file content with caching
    pub fn analyze_file_content(&self, path: &Path) -> std::io::Result<FileContentInfo> {
        let content = self.reader.read_file(path)?;
        
        // Check if content has changed (using hash)
        if self.cache_enabled {
            let cache = get_global_cache();
            if !cache.has_content_changed(path, &content) {
                // Content hasn't changed, could return cached analysis results
                // For now, we'll continue with analysis
            }
        }

        let info = FileContentInfo {
            line_count: content.lines().count(),
            char_count: content.chars().count(),
            byte_count: content.len(),
            is_binary: self.is_binary_content(&content),
            language_hints: self.detect_language_hints(&content),
        };

        Ok(info)
    }

    /// Check if content appears to be binary
    fn is_binary_content(&self, content: &str) -> bool {
        // Simple heuristic: if more than 1% of characters are non-printable, consider binary
        let total_chars = content.chars().count();
        if total_chars == 0 {
            return false;
        }

        let non_printable_count = content.chars()
            .filter(|c| c.is_control() && !c.is_whitespace())
            .count();

        (non_printable_count as f64 / total_chars as f64) > 0.01
    }

    /// Detect language hints from content
    fn detect_language_hints(&self, content: &str) -> Vec<String> {
        let mut hints = Vec::new();

        // Check for shebangs
        if content.starts_with("#!") {
            if let Some(first_line) = content.lines().next() {
                if first_line.contains("python") {
                    hints.push("python".to_string());
                } else if first_line.contains("bash") || first_line.contains("sh") {
                    hints.push("bash".to_string());
                } else if first_line.contains("node") {
                    hints.push("javascript".to_string());
                }
            }
        }

        // Check for common language patterns
        if content.contains("package main") || content.contains("func main()") {
            hints.push("go".to_string());
        }
        if content.contains("public class") || content.contains("public static void main") {
            hints.push("java".to_string());
        }
        if content.contains("fn main()") || content.contains("use std::") {
            hints.push("rust".to_string());
        }
        if content.contains("def ") && content.contains("import ") {
            hints.push("python".to_string());
        }
        if content.contains("function ") || content.contains("const ") || content.contains("let ") {
            hints.push("javascript".to_string());
        }

        hints
    }
}

/// Information about file content
#[derive(Debug, Clone)]
pub struct FileContentInfo {
    pub line_count: usize,
    pub char_count: usize,
    pub byte_count: usize,
    pub is_binary: bool,
    pub language_hints: Vec<String>,
}

impl FileContentInfo {
    /// Calculate content complexity score
    pub fn complexity_score(&self) -> f64 {
        let line_factor = (self.line_count as f64).log10().max(1.0);
        let char_factor = (self.char_count as f64).log10().max(1.0);
        let binary_penalty = if self.is_binary { 0.1 } else { 1.0 };
        
        line_factor * char_factor * binary_penalty
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs::File;
    use std::io::Write;
    use tempfile::TempDir;

    #[test]
    fn test_optimized_reader_small_file() {
        let temp_dir = TempDir::new().unwrap();
        let file_path = temp_dir.path().join("small.txt");
        let mut file = File::create(&file_path).unwrap();
        writeln!(file, "Hello, world!").unwrap();

        let reader = OptimizedFileReader::new(true);
        let content = reader.read_file(&file_path).unwrap();
        assert_eq!(content.trim(), "Hello, world!");
    }

    #[test]
    fn test_file_content_analyzer() {
        let temp_dir = TempDir::new().unwrap();
        let file_path = temp_dir.path().join("test.py");
        let mut file = File::create(&file_path).unwrap();
        writeln!(file, "#!/usr/bin/env python3").unwrap();
        writeln!(file, "def main():").unwrap();
        writeln!(file, "    print('Hello')").unwrap();

        let analyzer = FileContentAnalyzer::new(true);
        let info = analyzer.analyze_file_content(&file_path).unwrap();
        
        assert_eq!(info.line_count, 3);
        assert!(!info.is_binary);
        assert!(info.language_hints.contains(&"python".to_string()));
    }
}