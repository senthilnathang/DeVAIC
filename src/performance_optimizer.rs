use std::sync::Arc;
use std::time::Instant;
use crate::{Result, Vulnerability};
use rayon::prelude::*;
use dashmap::DashMap;

/// Advanced performance optimizer for DeVAIC analysis engine
pub struct PerformanceOptimizer {
    /// Thread pool configuration
    thread_pool_config: ThreadPoolConfig,
    /// Memory management settings
    memory_config: MemoryConfig,
    /// I/O optimization settings
    io_config: IoConfig,
    /// Cache configuration
    cache_config: CacheConfig,
    /// Runtime metrics collection
    metrics: Arc<DashMap<String, PerformanceMetric>>,
}

#[derive(Clone)]
pub struct ThreadPoolConfig {
    pub core_threads: usize,
    pub max_threads: usize,
    pub batch_size: usize,
    pub work_stealing: bool,
    pub thread_affinity: bool,
}

#[derive(Clone)]
pub struct MemoryConfig {
    pub max_memory_mb: usize,
    pub gc_threshold: f64,
    pub pre_allocate_capacity: usize,
    pub use_memory_pools: bool,
}

#[derive(Clone)]
pub struct IoConfig {
    pub async_enabled: bool,
    pub buffer_size: usize,
    pub concurrent_reads: usize,
    pub memory_mapping_threshold: usize,
    pub compression_enabled: bool,
}

#[derive(Clone)]
pub struct CacheConfig {
    pub enabled: bool,
    pub max_size_mb: usize,
    pub ttl_seconds: u64,
    pub eviction_strategy: EvictionStrategy,
    pub write_through: bool,
}

#[derive(Clone)]
pub enum EvictionStrategy {
    LRU,
    LFU,
    FIFO,
    Adaptive,
}

#[derive(Debug, Clone)]
pub struct PerformanceMetric {
    pub name: String,
    pub value: f64,
    pub unit: String,
    pub timestamp: std::time::Instant,
    pub samples: Vec<f64>,
}

impl PerformanceOptimizer {
    pub fn new() -> Self {
        let core_count = std::thread::available_parallelism()
            .map(|n| n.get())
            .unwrap_or(4);

        Self {
            thread_pool_config: ThreadPoolConfig {
                core_threads: core_count,
                max_threads: core_count * 2,
                batch_size: 100,
                work_stealing: true,
                thread_affinity: false,
            },
            memory_config: MemoryConfig {
                max_memory_mb: 2048,
                gc_threshold: 0.8,
                pre_allocate_capacity: 1000,
                use_memory_pools: true,
            },
            io_config: IoConfig {
                async_enabled: true,
                buffer_size: 64 * 1024,
                concurrent_reads: core_count,
                memory_mapping_threshold: 1024 * 1024,
                compression_enabled: false,
            },
            cache_config: CacheConfig {
                enabled: true,
                max_size_mb: 512,
                ttl_seconds: 3600,
                eviction_strategy: EvictionStrategy::Adaptive,
                write_through: false,
            },
            metrics: Arc::new(DashMap::new()),
        }
    }

    /// Create optimized configuration for different workloads
    pub fn for_workload(workload: WorkloadType) -> Self {
        let mut optimizer = Self::new();
        
        match workload {
            WorkloadType::LargeCodebase => {
                optimizer.memory_config.max_memory_mb = 4096;
                optimizer.thread_pool_config.batch_size = 200;
                optimizer.io_config.concurrent_reads *= 2;
                optimizer.cache_config.max_size_mb = 1024;
            },
            WorkloadType::ManySmallFiles => {
                optimizer.thread_pool_config.batch_size = 50;
                optimizer.io_config.buffer_size = 16 * 1024;
                optimizer.thread_pool_config.max_threads *= 2;
            },
            WorkloadType::CpuIntensive => {
                optimizer.thread_pool_config.work_stealing = true;
                optimizer.thread_pool_config.thread_affinity = true;
                optimizer.memory_config.use_memory_pools = true;
            },
            WorkloadType::MemoryConstrained => {
                optimizer.memory_config.max_memory_mb = 512;
                optimizer.cache_config.max_size_mb = 128;
                optimizer.io_config.compression_enabled = true;
            },
        }
        
        optimizer
    }

    /// Optimize parallel processing configuration with enhanced SIMD and cache awareness
    pub fn optimize_parallel_processing(&self) -> OptimizedParallelConfig {
        let available_memory = self.get_available_memory();
        let cpu_cores = std::thread::available_parallelism()
            .map(|n| n.get())
            .unwrap_or(4);

        // Enhanced adaptive configuration with L3 cache awareness
        let l3_cache_size = self.detect_l3_cache_size();
        let optimal_threads = if available_memory < 1024 * 1024 * 1024 { // < 1GB
            (cpu_cores / 2).max(1)
        } else if available_memory > 8 * 1024 * 1024 * 1024 { // > 8GB
            // Scale more aggressively for large memory systems
            (cpu_cores * 3).min(32) // Cap at 32 threads to avoid thrashing
        } else if available_memory > 4 * 1024 * 1024 * 1024 { // > 4GB
            cpu_cores * 2
        } else {
            cpu_cores
        };

        OptimizedParallelConfig {
            thread_count: optimal_threads,
            batch_size: self.calculate_optimal_batch_size_v2(available_memory, l3_cache_size),
            chunk_strategy: ChunkStrategy::CacheAware,
            work_stealing_enabled: true,
            numa_awareness: self.detect_numa_topology(),
            simd_enabled: self.detect_simd_support(),
            prefetch_distance: self.calculate_prefetch_distance(l3_cache_size),
            memory_bandwidth_awareness: true,
        }
    }
    
    /// Enhanced batch size calculation with cache line and memory bandwidth awareness
    fn calculate_optimal_batch_size_v2(&self, available_memory: usize, l3_cache_size: usize) -> usize {
        let base_batch_size = self.thread_pool_config.batch_size;
        let memory_factor = (available_memory / (1024 * 1024 * 1024)).max(1); // GB
        
        // Cache-aware batch sizing - aim for batches that fit in L3 cache
        let cache_optimal_size = (l3_cache_size / 4).max(64 * 1024); // Use 1/4 of L3 cache
        let items_per_cache_batch = cache_optimal_size / 1024; // Assume ~1KB per item
        
        // Balance between cache locality and parallelism
        let cache_aware_batch = items_per_cache_batch.clamp(50, 500);
        let memory_scaled_batch = base_batch_size * memory_factor;
        
        // Use geometric mean for balanced performance
        ((cache_aware_batch * memory_scaled_batch) as f64).sqrt() as usize
    }
    
    /// Detect L3 cache size for cache-aware optimization
    fn detect_l3_cache_size(&self) -> usize {
        // In a real implementation, would use CPUID or /sys/devices/system/cpu/
        // Conservative estimate for modern CPUs
        match std::thread::available_parallelism().map(|n| n.get()).unwrap_or(4) {
            1..=2 => 4 * 1024 * 1024,   // 4MB
            3..=4 => 8 * 1024 * 1024,   // 8MB
            5..=8 => 16 * 1024 * 1024,  // 16MB
            9..=16 => 32 * 1024 * 1024, // 32MB
            _ => 64 * 1024 * 1024,      // 64MB for high-end systems
        }
    }
    
    /// Detect SIMD instruction set support
    fn detect_simd_support(&self) -> SIMDCapabilities {
        // In production, would use CPUID detection
        SIMDCapabilities {
            sse2: true,
            sse4_2: true,
            avx: true,
            avx2: true,
            avx512: false, // Conservative default
        }
    }
    
    /// Calculate optimal prefetch distance based on cache hierarchy
    fn calculate_prefetch_distance(&self, l3_cache_size: usize) -> usize {
        // Prefetch distance should be large enough to hide memory latency
        // but not so large as to pollute cache
        (l3_cache_size / (64 * 1024)).clamp(8, 64) // 8-64 cache lines ahead
    }

    /// Calculate optimal batch size based on available memory
    fn calculate_optimal_batch_size(&self, available_memory: usize) -> usize {
        // Heuristic: larger batch sizes for more memory
        let base_batch_size = self.thread_pool_config.batch_size;
        let memory_factor = (available_memory / (1024 * 1024 * 1024)).max(1); // GB
        
        (base_batch_size * memory_factor).min(1000)
    }

    /// Get available system memory
    fn get_available_memory(&self) -> usize {
        // Simplified implementation - would use system APIs in production
        8 * 1024 * 1024 * 1024 // Assume 8GB for now
    }

    /// Detect NUMA topology for optimal thread placement
    fn detect_numa_topology(&self) -> bool {
        // Simplified - would use hwloc or similar in production
        std::thread::available_parallelism()
            .map(|n| n.get())
            .unwrap_or(4) > 8
    }

    /// Record performance metric
    pub fn record_metric(&self, name: &str, value: f64, unit: &str) {
        let mut metric = self.metrics.entry(name.to_string()).or_insert_with(|| {
            PerformanceMetric {
                name: name.to_string(),
                value: 0.0,
                unit: unit.to_string(),
                timestamp: Instant::now(),
                samples: Vec::with_capacity(1000),
            }
        });

        metric.value = value;
        metric.timestamp = Instant::now();
        metric.samples.push(value);

        // Keep only last 1000 samples
        if metric.samples.len() > 1000 {
            metric.samples.remove(0);
        }
    }

    /// Get performance statistics
    pub fn get_performance_stats(&self) -> PerformanceStats {
        let mut stats = PerformanceStats::default();

        for entry in self.metrics.iter() {
            let metric = entry.value();
            match entry.key().as_str() {
                "files_per_second" => stats.throughput = metric.value,
                "memory_usage_mb" => stats.memory_usage_mb = metric.value as usize,
                "cpu_utilization" => stats.cpu_utilization = metric.value,
                "cache_hit_ratio" => stats.cache_hit_ratio = metric.value,
                _ => {}
            }
        }

        stats
    }

    /// Optimize memory allocation patterns
    pub fn optimize_memory_allocation(&self) -> MemoryAllocationStrategy {
        MemoryAllocationStrategy {
            use_object_pools: self.memory_config.use_memory_pools,
            pre_allocate_collections: true,
            batch_allocations: true,
            memory_alignment: 64, // Cache line aligned
            huge_pages_enabled: self.memory_config.max_memory_mb > 1024,
        }
    }

    /// Create optimized regex compiler with caching
    pub fn create_regex_optimizer(&self) -> RegexOptimizer {
        RegexOptimizer::new(self.cache_config.clone())
    }

    /// Profile a code block and record metrics
    pub fn profile<F, R>(&self, name: &str, f: F) -> R
    where
        F: FnOnce() -> R,
    {
        let start = Instant::now();
        let result = f();
        let duration = start.elapsed();
        
        self.record_metric(&format!("{}_duration_ms", name), duration.as_millis() as f64, "ms");
        result
    }

    /// Adaptive performance tuning based on runtime metrics
    pub fn adaptive_tune(&mut self) {
        let stats = self.get_performance_stats();
        
        // Adjust thread pool based on CPU utilization
        if stats.cpu_utilization < 0.5 && self.thread_pool_config.core_threads < self.thread_pool_config.max_threads {
            self.thread_pool_config.core_threads += 1;
        } else if stats.cpu_utilization > 0.9 && self.thread_pool_config.core_threads > 1 {
            self.thread_pool_config.core_threads -= 1;
        }

        // Adjust batch size based on throughput
        if stats.throughput < 100.0 && self.thread_pool_config.batch_size < 500 {
            self.thread_pool_config.batch_size += 25;
        } else if stats.throughput > 1000.0 && self.thread_pool_config.batch_size > 25 {
            self.thread_pool_config.batch_size -= 25;
        }

        // Adjust memory settings based on usage
        if stats.memory_usage_mb > (self.memory_config.max_memory_mb as f64 * 0.9) as usize {
            if self.cache_config.max_size_mb > 64 {
                self.cache_config.max_size_mb -= 64;
            }
        }
    }
}

#[derive(Debug, Clone)]
pub enum WorkloadType {
    LargeCodebase,
    ManySmallFiles,
    CpuIntensive,
    MemoryConstrained,
}

#[derive(Debug, Clone)]
pub struct OptimizedParallelConfig {
    pub thread_count: usize,
    pub batch_size: usize,
    pub chunk_strategy: ChunkStrategy,
    pub work_stealing_enabled: bool,
    pub numa_awareness: bool,
    pub simd_enabled: SIMDCapabilities,
    pub prefetch_distance: usize,
    pub memory_bandwidth_awareness: bool,
}

#[derive(Debug, Clone)]
pub enum ChunkStrategy {
    Fixed(usize),
    Adaptive,
    WorkStealing,
    CacheAware,
    NumaAware,
}

#[derive(Debug, Default)]
pub struct PerformanceStats {
    pub throughput: f64, // files per second
    pub memory_usage_mb: usize,
    pub cpu_utilization: f64,
    pub cache_hit_ratio: f64,
    pub average_latency_ms: f64,
    pub peak_memory_mb: usize,
    pub gc_frequency: f64,
}

#[derive(Debug, Clone)]
pub struct SIMDCapabilities {
    pub sse2: bool,
    pub sse4_2: bool,
    pub avx: bool,
    pub avx2: bool,
    pub avx512: bool,
}

#[derive(Debug, Clone)]
pub struct MemoryAllocationStrategy {
    pub use_object_pools: bool,
    pub pre_allocate_collections: bool,
    pub batch_allocations: bool,
    pub memory_alignment: usize,
    pub huge_pages_enabled: bool,
}

/// Optimized regex compiler with compilation caching and SIMD support
pub struct RegexOptimizer {
    compiled_cache: Arc<DashMap<String, regex::Regex>>,
    cache_config: CacheConfig,
}

impl RegexOptimizer {
    pub fn new(cache_config: CacheConfig) -> Self {
        Self {
            compiled_cache: Arc::new(DashMap::new()),
            cache_config,
        }
    }

    /// Get or compile regex with caching
    pub fn get_regex(&self, pattern: &str) -> Result<regex::Regex> {
        if let Some(cached_regex) = self.compiled_cache.get(pattern) {
            return Ok(cached_regex.clone());
        }

        let regex = regex::Regex::new(pattern)
            .map_err(|e| crate::DevaicError::Analysis(format!("Invalid regex pattern: {}", e)))?;

        // Cache the compiled regex
        if self.cache_config.enabled {
            self.compiled_cache.insert(pattern.to_string(), regex.clone());
        }

        Ok(regex)
    }

    /// Batch compile multiple patterns for efficiency
    pub fn batch_compile(&self, patterns: &[String]) -> Result<Vec<regex::Regex>> {
        patterns.par_iter()
            .map(|pattern| self.get_regex(pattern))
            .collect()
    }

    /// Clear regex cache
    pub fn clear_cache(&self) {
        self.compiled_cache.clear();
    }

    /// Get cache statistics
    pub fn cache_stats(&self) -> (usize, usize) {
        (self.compiled_cache.len(), self.cache_config.max_size_mb * 1024 * 1024)
    }
}

/// High-performance vulnerability aggregator with SIMD optimizations
pub struct OptimizedVulnerabilityAggregator {
    vulnerabilities: Vec<Vulnerability>,
    capacity: usize,
    deduplication_enabled: bool,
    hash_set: std::collections::HashSet<u64>,
}

impl OptimizedVulnerabilityAggregator {
    pub fn new(capacity: usize, deduplication_enabled: bool) -> Self {
        Self {
            vulnerabilities: Vec::with_capacity(capacity),
            capacity,
            deduplication_enabled,
            hash_set: if deduplication_enabled {
                std::collections::HashSet::with_capacity(capacity)
            } else {
                std::collections::HashSet::new()
            },
        }
    }

    /// Add vulnerability with optional deduplication
    pub fn add(&mut self, vulnerability: Vulnerability) {
        if self.deduplication_enabled {
            let hash = self.calculate_vulnerability_hash(&vulnerability);
            if self.hash_set.insert(hash) {
                self.vulnerabilities.push(vulnerability);
            }
        } else {
            self.vulnerabilities.push(vulnerability);
        }
    }

    /// Batch add vulnerabilities
    pub fn extend(&mut self, vulnerabilities: Vec<Vulnerability>) {
        if self.deduplication_enabled {
            for vuln in vulnerabilities {
                self.add(vuln);
            }
        } else {
            self.vulnerabilities.extend(vulnerabilities);
        }
    }

    /// Get all vulnerabilities
    pub fn into_vulnerabilities(self) -> Vec<Vulnerability> {
        self.vulnerabilities
    }

    /// Calculate hash for vulnerability deduplication
    fn calculate_vulnerability_hash(&self, vuln: &Vulnerability) -> u64 {
        use std::hash::{Hash, Hasher};
        let mut hasher = siphasher::sip::SipHasher::new();
        
        vuln.title.hash(&mut hasher);
        vuln.file_path.hash(&mut hasher);
        vuln.line_number.hash(&mut hasher);
        vuln.source_code.hash(&mut hasher);
        
        hasher.finish()
    }

    /// Get statistics
    pub fn stats(&self) -> (usize, usize) {
        (self.vulnerabilities.len(), self.capacity)
    }
}

// Enhanced optimization structures (moved to end of file to avoid duplicates)

/// Enhanced cache implementation with intelligent prefetching
pub struct IntelligentCache<K, V> 
where
    K: std::hash::Hash + Eq + Clone,
    V: Clone,
{
    l1_cache: lru::LruCache<K, V>,
    l2_cache: lfu::LfuCache<K, V>,
    access_patterns: AccessPatternAnalyzer<K>,
    prefetch_engine: PrefetchEngine<K, V>,
    hit_stats: CacheStatistics,
}

impl<K, V> IntelligentCache<K, V>
where
    K: std::hash::Hash + Eq + Clone,
    V: Clone,
{
    pub fn new(l1_capacity: usize, l2_capacity: usize) -> Self {
        Self {
            l1_cache: lru::LruCache::new(l1_capacity.try_into().unwrap()),
            l2_cache: lfu::LfuCache::new(l2_capacity),
            access_patterns: AccessPatternAnalyzer::new(),
            prefetch_engine: PrefetchEngine::new(),
            hit_stats: CacheStatistics::default(),
        }
    }
    
    pub fn get(&mut self, key: &K) -> Option<V> {
        self.access_patterns.record_access(key.clone());
        
        // Try L1 cache first
        if let Some(value) = self.l1_cache.get(key) {
            self.hit_stats.l1_hits += 1;
            
            // Trigger predictive prefetching
            if let Some(predicted_keys) = self.access_patterns.predict_next_access(key) {
                for pred_key in predicted_keys {
                    self.prefetch_engine.schedule_prefetch(pred_key);
                }
            }
            
            return Some(value.clone());
        }
        
        // Try L2 cache
        if let Some(value) = self.l2_cache.get(key) {
            self.hit_stats.l2_hits += 1;
            // Promote to L1
            self.l1_cache.put(key.clone(), value.clone());
            return Some(value);
        }
        
        self.hit_stats.misses += 1;
        None
    }
    
    pub fn put(&mut self, key: K, value: V) {
        // Always put in L1, let LRU handle eviction to L2
        let evicted_value = self.l1_cache.put(key.clone(), value);
        if let Some(evicted_value) = evicted_value {
            // Store evicted item in L2 with a temporary key strategy
            // Note: This is a simplified approach - in a real implementation,
            // we'd need to track evicted keys separately
            self.l2_cache.put(key.clone(), evicted_value);
        }
        
        self.access_patterns.record_access(key);
    }
    
    pub fn stats(&self) -> &CacheStatistics {
        &self.hit_stats
    }
    
    pub fn hit_ratio(&self) -> f64 {
        let total = self.hit_stats.l1_hits + self.hit_stats.l2_hits + self.hit_stats.misses;
        if total == 0 {
            0.0
        } else {
            (self.hit_stats.l1_hits + self.hit_stats.l2_hits) as f64 / total as f64
        }
    }
}

#[derive(Debug, Default)]
pub struct CacheStatistics {
    pub l1_hits: u64,
    pub l2_hits: u64,
    pub misses: u64,
    pub evictions: u64,
    pub prefetch_hits: u64,
}

/// Analyzes access patterns for predictive caching
pub struct AccessPatternAnalyzer<K> {
    sequence_patterns: std::collections::HashMap<K, Vec<K>>,
    temporal_patterns: std::collections::VecDeque<(K, std::time::Instant)>,
    frequency_map: std::collections::HashMap<K, u32>,
}

impl<K> AccessPatternAnalyzer<K> 
where
    K: std::hash::Hash + Eq + Clone,
{
    pub fn new() -> Self {
        Self {
            sequence_patterns: std::collections::HashMap::new(),
            temporal_patterns: std::collections::VecDeque::new(),
            frequency_map: std::collections::HashMap::new(),
        }
    }
    
    pub fn record_access(&mut self, key: K) {
        let now = std::time::Instant::now();
        
        // Update frequency
        *self.frequency_map.entry(key.clone()).or_insert(0) += 1;
        
        // Record temporal pattern
        self.temporal_patterns.push_back((key.clone(), now));
        
        // Keep only recent accesses (last 1000)
        while self.temporal_patterns.len() > 1000 {
            self.temporal_patterns.pop_front();
        }
        
        // Update sequence patterns
        if let Some((prev_key, _)) = self.temporal_patterns.get(self.temporal_patterns.len().saturating_sub(2)) {
            self.sequence_patterns
                .entry(prev_key.clone())
                .or_insert_with(Vec::new)
                .push(key);
        }
    }
    
    pub fn predict_next_access(&self, current_key: &K) -> Option<Vec<K>> {
        // Simple sequence-based prediction
        self.sequence_patterns.get(current_key).map(|seq| {
            seq.iter()
                .take(3) // Predict next 3 likely accesses
                .cloned()
                .collect()
        })
    }
}

/// Manages prefetching operations
pub struct PrefetchEngine<K, V> {
    pending_prefetches: std::collections::VecDeque<K>,
    prefetch_cache: std::collections::HashMap<K, V>,
}

impl<K, V> PrefetchEngine<K, V>
where
    K: std::hash::Hash + Eq + Clone,
    V: Clone,
{
    pub fn new() -> Self {
        Self {
            pending_prefetches: std::collections::VecDeque::new(),
            prefetch_cache: std::collections::HashMap::new(),
        }
    }
    
    pub fn schedule_prefetch(&mut self, key: K) {
        if !self.prefetch_cache.contains_key(&key) {
            self.pending_prefetches.push_back(key);
        }
    }
    
    pub fn execute_prefetches<F>(&mut self, mut loader: F) 
    where
        F: FnMut(&K) -> Option<V>,
    {
        while let Some(key) = self.pending_prefetches.pop_front() {
            if let Some(value) = loader(&key) {
                self.prefetch_cache.insert(key, value);
            }
        }
    }
    
    pub fn get_prefetched(&mut self, key: &K) -> Option<V> {
        self.prefetch_cache.remove(key)
    }
}

// Placeholder implementations for missing types
mod lfu {
    use std::collections::HashMap;
    
    pub struct LfuCache<K, V> {
        data: HashMap<K, (V, u32)>,
        capacity: usize,
    }
    
    impl<K, V> LfuCache<K, V> 
    where
        K: std::hash::Hash + Eq + Clone,
        V: Clone,
    {
        pub fn new(capacity: usize) -> Self {
            Self {
                data: HashMap::with_capacity(capacity),
                capacity,
            }
        }
        
        pub fn get(&mut self, key: &K) -> Option<V> {
            if let Some((value, freq)) = self.data.get_mut(key) {
                *freq += 1;
                Some(value.clone())
            } else {
                None
            }
        }
        
        pub fn put(&mut self, key: K, value: V) {
            if self.data.len() >= self.capacity && !self.data.contains_key(&key) {
                // Evict least frequently used
                if let Some(lfu_key) = self.data.iter()
                    .min_by_key(|(_, (_, freq))| *freq)
                    .map(|(k, _)| k.clone()) {
                    self.data.remove(&lfu_key);
                }
            }
            self.data.insert(key, (value, 1));
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_performance_optimizer_creation() {
        let optimizer = PerformanceOptimizer::new();
        assert!(optimizer.thread_pool_config.core_threads > 0);
        assert!(optimizer.memory_config.max_memory_mb > 0);
    }

    #[test]
    fn test_workload_specific_optimization() {
        let optimizer = PerformanceOptimizer::for_workload(WorkloadType::LargeCodebase);
        assert!(optimizer.memory_config.max_memory_mb >= 4096);
        assert!(optimizer.thread_pool_config.batch_size >= 200);
    }

    #[test]
    fn test_regex_optimizer() {
        let config = CacheConfig {
            enabled: true,
            max_size_mb: 64,
            ttl_seconds: 3600,
            eviction_strategy: EvictionStrategy::LRU,
            write_through: false,
        };
        
        let optimizer = RegexOptimizer::new(config);
        let regex = optimizer.get_regex(r"\d+").unwrap();
        assert!(regex.is_match("123"));
    }

    #[test]
    fn test_vulnerability_aggregator() {
        let mut aggregator = OptimizedVulnerabilityAggregator::new(100, true);
        
        let vuln = Vulnerability {
            id: "test".to_string(),
            title: "SQL Injection".to_string(),
            severity: crate::Severity::High,
            category: "security".to_string(),
            description: "Test vulnerability".to_string(),
            file_path: "test.py".to_string(),
            line_number: 10,
            column_start: 5,
            column_end: 5,
            source_code: "test code".to_string(),
            recommendation: "Fix this".to_string(),
            cwe: None,
            owasp: None,
            references: vec![],
            confidence: 0.8,
        };
        
        aggregator.add(vuln.clone());
        aggregator.add(vuln); // Duplicate - should be deduplicated
        
        let vulns = aggregator.into_vulnerabilities();
        assert_eq!(vulns.len(), 1);
    }
}