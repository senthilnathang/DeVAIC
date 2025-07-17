use std::time::{Duration, Instant};
use std::path::Path;
use crate::{Analyzer, Config, cache::get_global_cache};

/// Performance benchmark for different scanning strategies
pub struct PerformanceBenchmark {
    config: Config,
}

impl PerformanceBenchmark {
    pub fn new(config: Config) -> Self {
        Self { config }
    }

    /// Run comprehensive benchmark comparing different scanning strategies
    pub fn run_benchmark(&self, target_path: &Path) -> BenchmarkResults {
        println!("Running performance benchmark on: {}", target_path.display());
        
        // Clear cache before benchmarking
        get_global_cache().clear_all();
        
        // Benchmark 1: Sequential scanning without cache
        println!("1. Sequential scanning without cache...");
        let seq_no_cache = self.benchmark_sequential(target_path, false);
        
        // Clear cache
        get_global_cache().clear_all();
        
        // Benchmark 2: Sequential scanning with cache
        println!("2. Sequential scanning with cache...");
        let seq_with_cache = self.benchmark_sequential(target_path, true);
        
        // Clear cache
        get_global_cache().clear_all();
        
        // Benchmark 3: Parallel scanning without cache
        println!("3. Parallel scanning without cache...");
        let par_no_cache = self.benchmark_parallel(target_path, false);
        
        // Clear cache
        get_global_cache().clear_all();
        
        // Benchmark 4: Parallel scanning with cache
        println!("4. Parallel scanning with cache...");
        let par_with_cache = self.benchmark_parallel(target_path, true);
        
        // Run cache-enabled parallel scan again to test cache hits
        println!("5. Parallel scanning with cache (second run)...");
        let par_cache_hit = self.benchmark_parallel(target_path, true);

        BenchmarkResults {
            sequential_no_cache: seq_no_cache,
            sequential_with_cache: seq_with_cache,
            parallel_no_cache: par_no_cache,
            parallel_with_cache: par_with_cache,
            parallel_cache_hit: par_cache_hit,
        }
    }

    /// Benchmark sequential scanning
    fn benchmark_sequential(&self, target_path: &Path, enable_cache: bool) -> BenchmarkResult {
        let start = Instant::now();
        
        // Create analyzer with sequential mode
        let mut analyzer = if enable_cache {
            Analyzer::new(self.config.clone())
        } else {
            let mut analyzer = Analyzer::new(self.config.clone());
            analyzer.set_parallel_enabled(false);
            analyzer
        };
        
        analyzer.set_parallel_enabled(false);
        
        let vulnerabilities = analyzer.analyze_directory(target_path)
            .unwrap_or_else(|_| Vec::new());
        
        let duration = start.elapsed();
        let cache_stats = analyzer.get_cache_stats();
        
        BenchmarkResult {
            duration,
            vulnerabilities_found: vulnerabilities.len(),
            cache_enabled: enable_cache,
            cache_entries: cache_stats.file_metadata_entries + cache_stats.directory_cache_entries,
        }
    }

    /// Benchmark parallel scanning
    fn benchmark_parallel(&self, target_path: &Path, enable_cache: bool) -> BenchmarkResult {
        let start = Instant::now();
        
        // Create analyzer with parallel mode
        let mut analyzer = if enable_cache {
            Analyzer::new(self.config.clone())
        } else {
            let mut analyzer = Analyzer::new(self.config.clone());
            analyzer.set_parallel_enabled(true);
            analyzer
        };
        
        analyzer.set_parallel_enabled(true);
        
        let vulnerabilities = analyzer.analyze_directory(target_path)
            .unwrap_or_else(|_| Vec::new());
        
        let duration = start.elapsed();
        let cache_stats = analyzer.get_cache_stats();
        
        BenchmarkResult {
            duration,
            vulnerabilities_found: vulnerabilities.len(),
            cache_enabled: enable_cache,
            cache_entries: cache_stats.file_metadata_entries + cache_stats.directory_cache_entries,
        }
    }

    /// Benchmark fast walker performance
    fn benchmark_fast_walker(&self, target_path: &Path, enable_cache: bool) -> BenchmarkResult {
        let start = Instant::now();
        
        // Create analyzer with fast walker enabled
        let mut analyzer = Analyzer::new(self.config.clone());
        analyzer.set_parallel_enabled(true);
        
        let vulnerabilities = analyzer.analyze_directory(target_path)
            .unwrap_or_else(|_| Vec::new());
        
        let duration = start.elapsed();
        let cache_stats = analyzer.get_cache_stats();
        
        BenchmarkResult {
            duration,
            vulnerabilities_found: vulnerabilities.len(),
            cache_enabled: enable_cache,
            cache_entries: cache_stats.file_metadata_entries + cache_stats.directory_cache_entries,
        }
    }
}

/// Single benchmark result
#[derive(Debug, Clone)]
pub struct BenchmarkResult {
    pub duration: Duration,
    pub vulnerabilities_found: usize,
    pub cache_enabled: bool,
    pub cache_entries: usize,
}

impl BenchmarkResult {
    pub fn print_summary(&self, name: &str) {
        println!("  {}: {:.2}s, {} vulnerabilities, cache: {}, entries: {}", 
                name, 
                self.duration.as_secs_f64(),
                self.vulnerabilities_found,
                if self.cache_enabled { "enabled" } else { "disabled" },
                self.cache_entries);
    }
}

/// Complete benchmark results
#[derive(Debug)]
pub struct BenchmarkResults {
    pub sequential_no_cache: BenchmarkResult,
    pub sequential_with_cache: BenchmarkResult,
    pub parallel_no_cache: BenchmarkResult,
    pub parallel_with_cache: BenchmarkResult,
    pub parallel_cache_hit: BenchmarkResult,
}

impl BenchmarkResults {
    /// Print complete benchmark summary
    pub fn print_summary(&self) {
        println!("\n=== Performance Benchmark Results ===");
        self.sequential_no_cache.print_summary("Sequential (no cache)");
        self.sequential_with_cache.print_summary("Sequential (with cache)");
        self.parallel_no_cache.print_summary("Parallel (no cache)");
        self.parallel_with_cache.print_summary("Parallel (with cache)");
        self.parallel_cache_hit.print_summary("Parallel (cache hit)");
        
        println!("\n=== Performance Analysis ===");
        
        // Calculate speedup from parallelization
        let seq_time = self.sequential_no_cache.duration.as_secs_f64();
        let par_time = self.parallel_no_cache.duration.as_secs_f64();
        let parallel_speedup = seq_time / par_time;
        
        println!("Parallel speedup: {:.2}x", parallel_speedup);
        
        // Calculate cache benefits
        let seq_cache_benefit = self.sequential_no_cache.duration.as_secs_f64() / 
                               self.sequential_with_cache.duration.as_secs_f64();
        let par_cache_benefit = self.parallel_no_cache.duration.as_secs_f64() / 
                               self.parallel_with_cache.duration.as_secs_f64();
        
        println!("Sequential cache benefit: {:.2}x", seq_cache_benefit);
        println!("Parallel cache benefit: {:.2}x", par_cache_benefit);
        
        // Calculate cache hit performance
        let cache_hit_speedup = self.parallel_with_cache.duration.as_secs_f64() / 
                               self.parallel_cache_hit.duration.as_secs_f64();
        
        println!("Cache hit speedup: {:.2}x", cache_hit_speedup);
        
        // Best configuration
        let durations = [
            self.sequential_no_cache.duration,
            self.sequential_with_cache.duration,
            self.parallel_no_cache.duration,
            self.parallel_with_cache.duration,
            self.parallel_cache_hit.duration,
        ];
        let best_time = durations.iter().min().unwrap();
        
        let best_config = if *best_time == self.sequential_no_cache.duration {
            "Sequential (no cache)"
        } else if *best_time == self.sequential_with_cache.duration {
            "Sequential (with cache)"
        } else if *best_time == self.parallel_no_cache.duration {
            "Parallel (no cache)"
        } else if *best_time == self.parallel_with_cache.duration {
            "Parallel (with cache)"
        } else {
            "Parallel (cache hit)"
        };
        
        println!("Best configuration: {} ({:.2}s)", best_config, best_time.as_secs_f64());
    }
}

/// File size analysis for performance tuning
pub struct FileSizeAnalyzer;

impl FileSizeAnalyzer {
    /// Analyze file size distribution in a directory
    pub fn analyze_directory(path: &Path) -> FileSizeStats {
        let mut stats = FileSizeStats::new();
        
        if let Ok(entries) = std::fs::read_dir(path) {
            for entry in entries.flatten() {
                let file_path = entry.path();
                
                if file_path.is_file() {
                    if let Ok(metadata) = std::fs::metadata(&file_path) {
                        stats.add_file(metadata.len());
                    }
                } else if file_path.is_dir() {
                    let subdir_stats = Self::analyze_directory(&file_path);
                    stats.merge(subdir_stats);
                }
            }
        }
        
        stats
    }
}

/// File size statistics
#[derive(Debug, Clone)]
pub struct FileSizeStats {
    pub total_files: usize,
    pub total_size: u64,
    pub min_size: u64,
    pub max_size: u64,
    pub sizes: Vec<u64>,
}

impl FileSizeStats {
    fn new() -> Self {
        Self {
            total_files: 0,
            total_size: 0,
            min_size: u64::MAX,
            max_size: 0,
            sizes: Vec::new(),
        }
    }
    
    fn add_file(&mut self, size: u64) {
        self.total_files += 1;
        self.total_size += size;
        self.min_size = self.min_size.min(size);
        self.max_size = self.max_size.max(size);
        self.sizes.push(size);
    }
    
    fn merge(&mut self, other: FileSizeStats) {
        self.total_files += other.total_files;
        self.total_size += other.total_size;
        self.min_size = self.min_size.min(other.min_size);
        self.max_size = self.max_size.max(other.max_size);
        self.sizes.extend(other.sizes);
    }
    
    pub fn average_size(&self) -> f64 {
        if self.total_files == 0 {
            0.0
        } else {
            self.total_size as f64 / self.total_files as f64
        }
    }
    
    pub fn median_size(&self) -> u64 {
        if self.sizes.is_empty() {
            return 0;
        }
        
        let mut sorted_sizes = self.sizes.clone();
        sorted_sizes.sort();
        
        let mid = sorted_sizes.len() / 2;
        if sorted_sizes.len() % 2 == 0 {
            (sorted_sizes[mid - 1] + sorted_sizes[mid]) / 2
        } else {
            sorted_sizes[mid]
        }
    }
    
    pub fn print_summary(&self) {
        println!("File Size Statistics:");
        println!("  Total files: {}", self.total_files);
        println!("  Total size: {} bytes ({:.2} MB)", self.total_size, self.total_size as f64 / 1024.0 / 1024.0);
        println!("  Average size: {:.2} bytes", self.average_size());
        println!("  Median size: {} bytes", self.median_size());
        println!("  Min size: {} bytes", self.min_size);
        println!("  Max size: {} bytes", self.max_size);
        
        // Size distribution
        let small_files = self.sizes.iter().filter(|&&size| size < 1024).count();
        let medium_files = self.sizes.iter().filter(|&&size| size >= 1024 && size < 1024 * 1024).count();
        let large_files = self.sizes.iter().filter(|&&size| size >= 1024 * 1024).count();
        
        println!("  Small files (<1KB): {} ({:.1}%)", small_files, small_files as f64 / self.total_files as f64 * 100.0);
        println!("  Medium files (1KB-1MB): {} ({:.1}%)", medium_files, medium_files as f64 / self.total_files as f64 * 100.0);
        println!("  Large files (>1MB): {} ({:.1}%)", large_files, large_files as f64 / self.total_files as f64 * 100.0);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::TempDir;
    use std::fs::File;
    use std::io::Write;

    #[test]
    fn test_file_size_analyzer() {
        let temp_dir = TempDir::new().unwrap();
        
        // Create test files
        let small_file = temp_dir.path().join("small.txt");
        let mut file = File::create(&small_file).unwrap();
        writeln!(file, "small").unwrap();
        
        let medium_file = temp_dir.path().join("medium.txt");
        let mut file = File::create(&medium_file).unwrap();
        for _ in 0..100 {
            writeln!(file, "This is a medium sized file with some content").unwrap();
        }
        
        let stats = FileSizeAnalyzer::analyze_directory(temp_dir.path());
        assert_eq!(stats.total_files, 2);
        assert!(stats.total_size > 0);
        assert!(stats.average_size() > 0.0);
    }
}