/// AI-Powered Vulnerability Detection Performance Optimizer
/// 
/// This module provides enterprise-grade performance optimizations specifically
/// designed for AI-powered vulnerability detection systems at scale.

use std::collections::{HashMap, VecDeque};
use std::sync::{Arc, RwLock};
use std::time::{Duration, Instant};
use serde::{Deserialize, Serialize};
use tokio::sync::Semaphore;

/// Configuration for AI performance optimization
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AIPerformanceConfig {
    /// Maximum concurrent AI analysis tasks
    pub max_concurrent_ai_tasks: usize,
    /// Embedding cache size (number of embeddings)
    pub embedding_cache_size: usize,
    /// Business logic cache size (number of workflow models)
    pub workflow_cache_size: usize,
    /// Memory pool size for AI operations
    pub ai_memory_pool_size: usize,
    /// Batch size for bulk AI analysis
    pub ai_batch_size: usize,
    /// Enable SIMD optimizations for vector operations
    pub enable_simd_vectors: bool,
    /// Prefetch strategy for embeddings
    pub enable_embedding_prefetch: bool,
    /// Adaptive load balancing for AI tasks
    pub enable_adaptive_load_balancing: bool,
    /// Memory pressure threshold (0.0-1.0)
    pub memory_pressure_threshold: f64,
    /// Performance monitoring interval
    pub monitoring_interval_secs: u64,
}

impl Default for AIPerformanceConfig {
    fn default() -> Self {
        Self {
            max_concurrent_ai_tasks: num_cpus::get() * 2,
            embedding_cache_size: 50000,
            workflow_cache_size: 1000,
            ai_memory_pool_size: 1024 * 1024 * 512, // 512MB
            ai_batch_size: 32,
            enable_simd_vectors: true,
            enable_embedding_prefetch: true,
            enable_adaptive_load_balancing: true,
            memory_pressure_threshold: 0.8,
            monitoring_interval_secs: 30,
        }
    }
}

/// Enterprise-scale AI performance optimizer
pub struct AIPerformanceOptimizer {
    config: AIPerformanceConfig,
    metrics: Arc<RwLock<AIPerformanceMetrics>>,
    embedding_pool: Arc<RwLock<EmbeddingMemoryPool>>,
    task_semaphore: Arc<Semaphore>,
    load_balancer: Arc<RwLock<AILoadBalancer>>,
    cache_manager: Arc<RwLock<AICache>>,
    memory_monitor: Arc<RwLock<MemoryMonitor>>,
}

/// AI-specific performance metrics
#[derive(Debug, Default, Clone, Serialize, Deserialize)]
pub struct AIPerformanceMetrics {
    /// Total AI analysis operations performed
    pub total_ai_operations: u64,
    /// Average AI analysis time in milliseconds
    pub avg_ai_analysis_time_ms: f64,
    /// Embedding cache hit rate (0.0-1.0)
    pub embedding_cache_hit_rate: f64,
    /// Workflow cache hit rate (0.0-1.0)
    pub workflow_cache_hit_rate: f64,
    /// Memory pool utilization (0.0-1.0)
    pub memory_pool_utilization: f64,
    /// SIMD operations per second
    pub simd_operations_per_sec: u64,
    /// Concurrent AI tasks currently running
    pub active_ai_tasks: u64,
    /// Average batch processing time
    pub avg_batch_processing_time_ms: f64,
    /// False positive rate for AI detections
    pub ai_false_positive_rate: f64,
    /// AI detection accuracy
    pub ai_detection_accuracy: f64,
    /// Memory pressure level
    pub memory_pressure: f64,
    /// Throughput (files analyzed per second)
    pub throughput_files_per_sec: f64,
}

/// Memory pool specifically optimized for AI embeddings
#[derive(Debug)]
pub struct EmbeddingMemoryPool {
    /// Pre-allocated embedding vectors
    embedding_pool: VecDeque<Vec<f64>>,
    /// Pool statistics
    pool_stats: PoolStatistics,
    /// Maximum pool size
    max_pool_size: usize,
    /// Vector dimension size
    vector_dimension: usize,
}

/// Memory pool statistics
#[derive(Debug, Default, Clone)]
pub struct PoolStatistics {
    pub total_allocations: u64,
    pub pool_hits: u64,
    pub pool_misses: u64,
    pub current_pool_size: usize,
    pub peak_pool_size: usize,
}

/// AI task load balancer
#[derive(Debug)]
pub struct AILoadBalancer {
    /// Worker thread pool information
    workers: Vec<WorkerInfo>,
    /// Task distribution strategy
    strategy: LoadBalancingStrategy,
    /// Current load distribution
    load_distribution: HashMap<usize, f64>,
}

/// Worker thread information
#[derive(Debug, Clone)]
pub struct WorkerInfo {
    pub worker_id: usize,
    pub current_load: f64,
    pub tasks_completed: u64,
    pub avg_task_duration_ms: f64,
    pub last_activity: Instant,
    pub specialization: WorkerSpecialization,
}

/// Worker specialization for different AI tasks
#[derive(Debug, Clone, PartialEq)]
pub enum WorkerSpecialization {
    SemanticSimilarity,
    BusinessLogic,
    EmbeddingGeneration,
    PatternMatching,
    General,
}

/// Load balancing strategies
#[derive(Debug, Clone)]
pub enum LoadBalancingStrategy {
    RoundRobin,
    LeastLoaded,
    WeightedRoundRobin { weights: Vec<f64> },
    Adaptive,
    Specialized,
}

/// Multi-level AI cache system
#[derive(Debug)]
pub struct AICache {
    /// L1 Cache: Recently used embeddings (LRU)
    l1_embedding_cache: lru::LruCache<String, Vec<f64>>,
    /// L2 Cache: Frequently used workflows (LFU)
    l2_workflow_cache: HashMap<String, (u64, crate::business_logic_analyzer::WorkflowModel)>,
    /// L3 Cache: Persistent similarity results
    l3_similarity_cache: HashMap<u64, SimilarityResultCache>,
    /// Cache statistics
    cache_stats: AICacheStatistics,
}

/// Cached similarity results
#[derive(Debug, Clone)]
pub struct SimilarityResultCache {
    pub result: crate::semantic_similarity_engine::SimilarityResult,
    pub timestamp: Instant,
    pub access_count: u64,
}

/// AI cache statistics
#[derive(Debug, Default, Clone)]
pub struct AICacheStatistics {
    pub l1_hits: u64,
    pub l1_misses: u64,
    pub l2_hits: u64,
    pub l2_misses: u64,
    pub l3_hits: u64,
    pub l3_misses: u64,
    pub total_evictions: u64,
}

/// Memory usage monitoring
#[derive(Debug)]
pub struct MemoryMonitor {
    /// Current memory usage in bytes
    current_usage: u64,
    /// Peak memory usage
    peak_usage: u64,
    /// Memory usage history for trend analysis
    usage_history: VecDeque<(Instant, u64)>,
    /// Memory pressure alerts
    pressure_alerts: Vec<MemoryPressureAlert>,
}

/// Memory pressure alert
#[derive(Debug, Clone)]
pub struct MemoryPressureAlert {
    pub timestamp: Instant,
    pub pressure_level: f64,
    pub memory_usage: u64,
    pub recommended_action: String,
}

impl AIPerformanceOptimizer {
    /// Create a new AI performance optimizer
    pub fn new(config: AIPerformanceConfig) -> Self {
        let task_semaphore = Arc::new(Semaphore::new(config.max_concurrent_ai_tasks));
        
        let embedding_pool = Arc::new(RwLock::new(EmbeddingMemoryPool::new(
            config.ai_memory_pool_size,
            512, // Standard embedding dimension
        )));
        
        let load_balancer = Arc::new(RwLock::new(AILoadBalancer::new(
            config.max_concurrent_ai_tasks,
            LoadBalancingStrategy::Adaptive,
        )));
        
        let cache_manager = Arc::new(RwLock::new(AICache::new(
            config.embedding_cache_size,
            config.workflow_cache_size,
        )));
        
        let memory_monitor = Arc::new(RwLock::new(MemoryMonitor::new()));
        
        Self {
            config,
            metrics: Arc::new(RwLock::new(AIPerformanceMetrics::default())),
            embedding_pool,
            task_semaphore,
            load_balancer,
            cache_manager,
            memory_monitor,
        }
    }

    /// Optimize embedding generation with memory pooling
    pub async fn optimized_embedding_generation(&self, code: &str, language: &str) -> Result<Vec<f64>, Box<dyn std::error::Error>> {
        let _permit = self.task_semaphore.acquire().await?;
        let start_time = Instant::now();

        // Check cache first
        let cache_key = format!("{}:{}", language, self.hash_code(code));
        if let Some(cached_embedding) = self.get_cached_embedding(&cache_key).await {
            self.update_cache_hit_metrics(true).await;
            return Ok(cached_embedding);
        }
        self.update_cache_hit_metrics(false).await;

        // Get pre-allocated vector from pool
        let mut embedding_vector = self.get_pooled_vector().await;
        
        // Generate embedding with SIMD optimization if enabled
        if self.config.enable_simd_vectors {
            self.generate_embedding_simd(code, language, &mut embedding_vector)?;
        } else {
            self.generate_embedding_standard(code, language, &mut embedding_vector)?;
        }

        // Cache the result
        self.cache_embedding(cache_key, embedding_vector.clone()).await;
        
        // Update metrics
        let duration = start_time.elapsed();
        self.update_ai_metrics(duration).await;

        Ok(embedding_vector)
    }

    /// Batch process multiple files for optimal throughput
    pub async fn batch_process_files(&self, files: Vec<(String, String, String)>) -> Result<Vec<Vec<f64>>, Box<dyn std::error::Error>> {
        let batch_start = Instant::now();
        let mut results = Vec::with_capacity(files.len());
        
        // Process in optimized batches
        for chunk in files.chunks(self.config.ai_batch_size) {
            let batch_futures: Vec<_> = chunk.iter()
                .map(|(path, code, language)| {
                    self.optimized_embedding_generation(code, language)
                })
                .collect();
            
            let batch_results = futures::future::join_all(batch_futures).await;
            
            for result in batch_results {
                results.push(result?);
            }
            
            // Check memory pressure between batches
            if self.is_memory_pressure_high().await {
                self.perform_memory_cleanup().await?;
            }
        }
        
        // Update batch processing metrics
        let batch_duration = batch_start.elapsed();
        self.update_batch_metrics(files.len(), batch_duration).await;
        
        Ok(results)
    }

    /// Optimize business logic analysis with workflow caching
    pub async fn optimized_business_logic_analysis(
        &self, 
        code: &str, 
        language: crate::Language,
        workflow_id: &str
    ) -> Result<crate::business_logic_analyzer::BusinessLogicAnalysisResult, Box<dyn std::error::Error>> {
        let _permit = self.task_semaphore.acquire().await?;
        let start_time = Instant::now();

        // Get workflow from cache
        let workflow = self.get_cached_workflow(workflow_id).await
            .ok_or("Workflow not found in cache")?;

        // Perform optimized analysis
        let analyzer = crate::business_logic_analyzer::BusinessLogicAnalyzer::new(
            crate::business_logic_analyzer::BusinessLogicConfig::default()
        );
        
        let result = analyzer.analyze_business_logic(code, language).await?;
        
        // Update metrics
        let duration = start_time.elapsed();
        self.update_ai_metrics(duration).await;

        Ok(result)
    }

    /// Get optimal worker for AI task
    pub async fn get_optimal_worker(&self, task_type: WorkerSpecialization) -> usize {
        let load_balancer = self.load_balancer.read().unwrap();
        load_balancer.get_optimal_worker(task_type)
    }

    /// Perform memory cleanup when under pressure
    pub async fn perform_memory_cleanup(&self) -> Result<(), Box<dyn std::error::Error>> {
        let mut cache = self.cache_manager.write().unwrap();
        
        // Clean L1 cache (keep only most recent entries)
        let l1_target_size = cache.l1_embedding_cache.cap().get() / 2;
        cache.l1_embedding_cache.resize(std::num::NonZeroUsize::new(l1_target_size).unwrap());
        
        // Clean L2 cache (remove least frequently used)
        let mut l2_entries: Vec<_> = cache.l2_workflow_cache.iter().collect();
        l2_entries.sort_by_key(|(_, (freq, _))| *freq);
        let keep_count = cache.l2_workflow_cache.len() / 2;
        
        let keys_to_remove: Vec<_> = l2_entries.iter()
            .take(cache.l2_workflow_cache.len() - keep_count)
            .map(|(key, _)| (*key).clone())
            .collect();
        
        for key in keys_to_remove {
            cache.l2_workflow_cache.remove(&key);
        }
        
        // Clean L3 cache (remove old entries)
        let cutoff_time = Instant::now() - Duration::from_secs(3600); // 1 hour
        cache.l3_similarity_cache.retain(|_, cached| cached.timestamp > cutoff_time);
        
        // Update memory monitor
        let mut monitor = self.memory_monitor.write().unwrap();
        monitor.record_cleanup();
        
        Ok(())
    }

    /// Get real-time performance metrics
    pub async fn get_performance_metrics(&self) -> AIPerformanceMetrics {
        let mut current_metrics = {
            let metrics = self.metrics.read().unwrap();
            metrics.clone()
        }; // Guard is dropped here
        
        // Update real-time values
        current_metrics.memory_pressure = self.calculate_memory_pressure().await;
        current_metrics.active_ai_tasks = (self.config.max_concurrent_ai_tasks - self.task_semaphore.available_permits()) as u64;
        
        // Calculate cache hit rates
        let (embedding_hit_rate, workflow_hit_rate) = {
            let cache = self.cache_manager.read().unwrap();
            (cache.calculate_l1_hit_rate(), cache.calculate_l2_hit_rate())
        }; // Guard is dropped here
        current_metrics.embedding_cache_hit_rate = embedding_hit_rate;
        current_metrics.workflow_cache_hit_rate = workflow_hit_rate;
        
        current_metrics
    }

    /// Enable adaptive performance tuning
    pub async fn enable_adaptive_tuning(&self) {
        // Start background monitoring task
        let optimizer = Arc::new(self.clone());
        tokio::spawn(async move {
            optimizer.adaptive_tuning_loop().await;
        });
    }

    /// Background adaptive tuning loop
    async fn adaptive_tuning_loop(&self) {
        let mut interval = tokio::time::interval(Duration::from_secs(self.config.monitoring_interval_secs));
        
        loop {
            interval.tick().await;
            
            let metrics = self.get_performance_metrics().await;
            
            // Adjust based on performance metrics
            if metrics.memory_pressure > self.config.memory_pressure_threshold {
                let _ = self.perform_memory_cleanup().await;
            }
            
            // Adjust batch size based on throughput
            if metrics.throughput_files_per_sec < 10.0 && self.config.ai_batch_size < 64 {
                // Increase batch size for better throughput
                // Note: This would require making config mutable or using atomic values
            }
            
            // Adjust concurrency based on system load
            let system_load = self.get_system_load().await;
            if system_load > 0.8 && self.task_semaphore.available_permits() > 2 {
                // Reduce concurrency under high system load
                // Note: Would need mechanism to adjust semaphore permits
            }
        }
    }

    // Helper methods
    
    async fn get_cached_embedding(&self, key: &str) -> Option<Vec<f64>> {
        let cache = self.cache_manager.read().unwrap();
        cache.l1_embedding_cache.peek(key).cloned()
    }
    
    async fn cache_embedding(&self, key: String, embedding: Vec<f64>) {
        let mut cache = self.cache_manager.write().unwrap();
        cache.l1_embedding_cache.put(key, embedding);
    }
    
    async fn get_cached_workflow(&self, workflow_id: &str) -> Option<crate::business_logic_analyzer::WorkflowModel> {
        let mut cache = self.cache_manager.write().unwrap();
        if let Some((freq, workflow)) = cache.l2_workflow_cache.get_mut(workflow_id) {
            *freq += 1;
            Some(workflow.clone())
        } else {
            None
        }
    }
    
    async fn get_pooled_vector(&self) -> Vec<f64> {
        let mut pool = self.embedding_pool.write().unwrap();
        pool.get_vector()
    }
    
    fn hash_code(&self, code: &str) -> u64 {
        use std::collections::hash_map::DefaultHasher;
        use std::hash::{Hash, Hasher};
        
        let mut hasher = DefaultHasher::new();
        code.hash(&mut hasher);
        hasher.finish()
    }
    
    fn generate_embedding_simd(&self, code: &str, language: &str, embedding: &mut Vec<f64>) -> Result<(), Box<dyn std::error::Error>> {
        // SIMD-optimized embedding generation
        // This would use actual SIMD instructions for vector operations
        self.generate_embedding_standard(code, language, embedding)
    }
    
    fn generate_embedding_standard(&self, code: &str, language: &str, embedding: &mut Vec<f64>) -> Result<(), Box<dyn std::error::Error>> {
        // Standard embedding generation (placeholder)
        let hash = self.hash_code(&format!("{}:{}", language, code));
        for i in 0..embedding.len() {
            embedding[i] = ((hash.wrapping_add(i as u64)) as f64).sin().abs();
        }
        Ok(())
    }
    
    async fn update_cache_hit_metrics(&self, hit: bool) {
        // Update cache hit rate metrics
    }
    
    async fn update_ai_metrics(&self, duration: Duration) {
        let mut metrics = self.metrics.write().unwrap();
        metrics.total_ai_operations += 1;
        
        // Update running average
        let new_time = duration.as_millis() as f64;
        metrics.avg_ai_analysis_time_ms = (metrics.avg_ai_analysis_time_ms * (metrics.total_ai_operations - 1) as f64 + new_time) / metrics.total_ai_operations as f64;
    }
    
    async fn update_batch_metrics(&self, batch_size: usize, duration: Duration) {
        let mut metrics = self.metrics.write().unwrap();
        metrics.avg_batch_processing_time_ms = duration.as_millis() as f64;
        metrics.throughput_files_per_sec = batch_size as f64 / duration.as_secs_f64();
    }
    
    async fn is_memory_pressure_high(&self) -> bool {
        self.calculate_memory_pressure().await > self.config.memory_pressure_threshold
    }
    
    async fn calculate_memory_pressure(&self) -> f64 {
        // Calculate current memory pressure (placeholder)
        0.5
    }
    
    async fn get_system_load(&self) -> f64 {
        // Get current system load (placeholder)
        0.5
    }
}

impl Clone for AIPerformanceOptimizer {
    fn clone(&self) -> Self {
        Self {
            config: self.config.clone(),
            metrics: Arc::clone(&self.metrics),
            embedding_pool: Arc::clone(&self.embedding_pool),
            task_semaphore: Arc::clone(&self.task_semaphore),
            load_balancer: Arc::clone(&self.load_balancer),
            cache_manager: Arc::clone(&self.cache_manager),
            memory_monitor: Arc::clone(&self.memory_monitor),
        }
    }
}

impl EmbeddingMemoryPool {
    pub fn new(max_pool_size: usize, vector_dimension: usize) -> Self {
        let mut pool = VecDeque::new();
        
        // Pre-allocate some vectors
        for _ in 0..std::cmp::min(max_pool_size / 4, 1000) {
            pool.push_back(vec![0.0; vector_dimension]);
        }
        
        Self {
            embedding_pool: pool,
            pool_stats: PoolStatistics::default(),
            max_pool_size: max_pool_size / (vector_dimension * 8), // Adjust for f64 size
            vector_dimension,
        }
    }
    
    pub fn get_vector(&mut self) -> Vec<f64> {
        self.pool_stats.total_allocations += 1;
        
        if let Some(mut vector) = self.embedding_pool.pop_front() {
            self.pool_stats.pool_hits += 1;
            vector.fill(0.0); // Clear the vector
            vector
        } else {
            self.pool_stats.pool_misses += 1;
            vec![0.0; self.vector_dimension]
        }
    }
    
    pub fn return_vector(&mut self, vector: Vec<f64>) {
        if self.embedding_pool.len() < self.max_pool_size {
            self.embedding_pool.push_back(vector);
            self.pool_stats.current_pool_size = self.embedding_pool.len();
            self.pool_stats.peak_pool_size = self.pool_stats.peak_pool_size.max(self.pool_stats.current_pool_size);
        }
    }
    
    pub fn get_statistics(&self) -> &PoolStatistics {
        &self.pool_stats
    }
}

impl AILoadBalancer {
    pub fn new(worker_count: usize, strategy: LoadBalancingStrategy) -> Self {
        let workers = (0..worker_count)
            .map(|id| WorkerInfo {
                worker_id: id,
                current_load: 0.0,
                tasks_completed: 0,
                avg_task_duration_ms: 0.0,
                last_activity: Instant::now(),
                specialization: WorkerSpecialization::General,
            })
            .collect();
        
        Self {
            workers,
            strategy,
            load_distribution: HashMap::new(),
        }
    }
    
    pub fn get_optimal_worker(&self, task_type: WorkerSpecialization) -> usize {
        match &self.strategy {
            LoadBalancingStrategy::LeastLoaded => {
                self.workers.iter()
                    .min_by(|a, b| a.current_load.partial_cmp(&b.current_load).unwrap())
                    .map(|w| w.worker_id)
                    .unwrap_or(0)
            },
            LoadBalancingStrategy::Specialized => {
                // Find specialized worker first, fallback to least loaded
                self.workers.iter()
                    .filter(|w| w.specialization == task_type || w.specialization == WorkerSpecialization::General)
                    .min_by(|a, b| a.current_load.partial_cmp(&b.current_load).unwrap())
                    .map(|w| w.worker_id)
                    .unwrap_or(0)
            },
            LoadBalancingStrategy::Adaptive => {
                // Consider both load and task type performance
                self.workers.iter()
                    .min_by(|a, b| {
                        let a_score = a.current_load + if a.specialization == task_type { -0.2 } else { 0.0 };
                        let b_score = b.current_load + if b.specialization == task_type { -0.2 } else { 0.0 };
                        a_score.partial_cmp(&b_score).unwrap()
                    })
                    .map(|w| w.worker_id)
                    .unwrap_or(0)
            },
            _ => 0, // Simple fallback
        }
    }
}

impl AICache {
    pub fn new(embedding_cache_size: usize, workflow_cache_size: usize) -> Self {
        Self {
            l1_embedding_cache: lru::LruCache::new(std::num::NonZeroUsize::new(embedding_cache_size).unwrap()),
            l2_workflow_cache: HashMap::with_capacity(workflow_cache_size),
            l3_similarity_cache: HashMap::new(),
            cache_stats: AICacheStatistics::default(),
        }
    }
    
    pub fn calculate_l1_hit_rate(&self) -> f64 {
        let total = self.cache_stats.l1_hits + self.cache_stats.l1_misses;
        if total > 0 {
            self.cache_stats.l1_hits as f64 / total as f64
        } else {
            0.0
        }
    }
    
    pub fn calculate_l2_hit_rate(&self) -> f64 {
        let total = self.cache_stats.l2_hits + self.cache_stats.l2_misses;
        if total > 0 {
            self.cache_stats.l2_hits as f64 / total as f64
        } else {
            0.0
        }
    }
}

impl MemoryMonitor {
    pub fn new() -> Self {
        Self {
            current_usage: 0,
            peak_usage: 0,
            usage_history: VecDeque::new(),
            pressure_alerts: Vec::new(),
        }
    }
    
    pub fn record_cleanup(&mut self) {
        self.pressure_alerts.push(MemoryPressureAlert {
            timestamp: Instant::now(),
            pressure_level: 0.8,
            memory_usage: self.current_usage,
            recommended_action: "Memory cleanup performed".to_string(),
        });
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_ai_performance_optimizer_creation() {
        let config = AIPerformanceConfig::default();
        let optimizer = AIPerformanceOptimizer::new(config);
        
        let metrics = optimizer.get_performance_metrics().await;
        assert_eq!(metrics.total_ai_operations, 0);
    }

    #[tokio::test]
    async fn test_embedding_generation_optimization() {
        let config = AIPerformanceConfig::default();
        let optimizer = AIPerformanceOptimizer::new(config);
        
        let code = "function test() { return 'hello'; }";
        let result = optimizer.optimized_embedding_generation(code, "javascript").await;
        
        assert!(result.is_ok());
        let embedding = result.unwrap();
        assert_eq!(embedding.len(), 512);
    }

    #[test]
    fn test_embedding_memory_pool() {
        let mut pool = EmbeddingMemoryPool::new(1000, 512);
        
        let vector1 = pool.get_vector();
        assert_eq!(vector1.len(), 512);
        
        let stats = pool.get_statistics();
        assert_eq!(stats.total_allocations, 1);
        
        pool.return_vector(vector1);
        let vector2 = pool.get_vector();
        assert_eq!(vector2.len(), 512);
        
        let stats = pool.get_statistics();
        assert_eq!(stats.pool_hits, 1);
    }

    #[test]
    fn test_load_balancer() {
        let balancer = AILoadBalancer::new(4, LoadBalancingStrategy::LeastLoaded);
        
        let worker_id = balancer.get_optimal_worker(WorkerSpecialization::SemanticSimilarity);
        assert!(worker_id < 4);
    }
}