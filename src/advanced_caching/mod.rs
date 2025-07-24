/// Advanced Caching Strategies for Enterprise-Scale Vulnerability Analysis
/// 
/// This module provides comprehensive caching solutions designed for large-scale
/// deployments with distributed systems, intelligent cache warming, and advanced
/// coherency management.

pub mod distributed_cache;
pub mod smart_cache_warming;
pub mod cache_coherency;
pub mod cache_analytics;
pub mod predictive_cache;
pub mod memory_aware_cache;

pub use distributed_cache::{
    DistributedCache, DistributedCacheConfig, CacheBackend, RedisCache, MemcachedCache,
    CacheCluster, CacheNode, CacheReplicationStrategy,
};

pub use smart_cache_warming::{
    SmartCacheWarmer, CacheWarmingConfig, WarmingStrategy, PredictiveWarming,
    CachePreloader, WarmingScheduler,
};

pub use cache_coherency::{
    CacheCoherencyManager, CoherencyConfig, CoherencyProtocol, InvalidationStrategy,
    CacheSync, ConsistencyLevel,
};

pub use cache_analytics::{
    CacheAnalytics, CacheMetrics, CacheOptimizer, CacheInsights,
    HitRateAnalyzer, EvictionAnalyzer, PerformanceProfiler,
};

pub use predictive_cache::{
    PredictiveCache, PredictionModel, AccessPatternAnalyzer, CachePrefetcher,
    TrendAnalyzer, UsagePredictor,
};

pub use memory_aware_cache::{
    MemoryAwareCache, MemoryPressureMonitor, AdaptiveCacheManager,
    MemoryOptimizedEviction, CacheCompressionEngine,
};

use std::collections::HashMap;
use std::sync::{Arc, RwLock};
use std::time::{Duration, Instant};
use serde::{Deserialize, Serialize};

/// Advanced caching system configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AdvancedCachingConfig {
    /// Enable distributed caching across multiple nodes
    pub enable_distributed_caching: bool,
    /// Distributed cache configuration
    pub distributed_cache: DistributedCacheConfig,
    /// Enable smart cache warming and preloading
    pub enable_smart_warming: bool,
    /// Cache warming configuration
    pub warming_config: CacheWarmingConfig,
    /// Enable cache coherency management
    pub enable_coherency_management: bool,
    /// Cache coherency configuration
    pub coherency_config: CoherencyConfig,
    /// Enable predictive caching based on access patterns
    pub enable_predictive_caching: bool,
    /// Enable memory-aware cache management
    pub enable_memory_aware_caching: bool,
    /// Cache analytics and optimization
    pub enable_cache_analytics: bool,
    /// Global cache size limits
    pub global_cache_size_mb: usize,
    /// Cache eviction strategy
    pub eviction_strategy: EvictionStrategy,
    /// Cache compression settings
    pub compression_config: CompressionConfig,
}

/// Cache eviction strategies
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum EvictionStrategy {
    LRU,
    LFU,
    TimeToLive { ttl_seconds: u64 },
    Adaptive,
    MemoryPressureAware,
    AccessPatternBased,
}

/// Cache compression configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CompressionConfig {
    pub enable_compression: bool,
    pub compression_algorithm: CompressionAlgorithm,
    pub compression_threshold_bytes: usize,
    pub compression_level: u8,
}

/// Compression algorithms
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum CompressionAlgorithm {
    None,
    Gzip,
    Lz4,
    Zstd,
    Snappy,
}

impl Default for AdvancedCachingConfig {
    fn default() -> Self {
        Self {
            enable_distributed_caching: false,
            distributed_cache: DistributedCacheConfig::default(),
            enable_smart_warming: true,
            warming_config: CacheWarmingConfig::default(),
            enable_coherency_management: true,
            coherency_config: CoherencyConfig::default(),
            enable_predictive_caching: true,
            enable_memory_aware_caching: true,
            enable_cache_analytics: true,
            global_cache_size_mb: 2048, // 2GB default
            eviction_strategy: EvictionStrategy::Adaptive,
            compression_config: CompressionConfig {
                enable_compression: true,
                compression_algorithm: CompressionAlgorithm::Lz4,
                compression_threshold_bytes: 1024, // 1KB
                compression_level: 3,
            },
        }
    }
}

/// Advanced caching system manager
pub struct AdvancedCachingSystem {
    config: AdvancedCachingConfig,
    distributed_cache: Option<Arc<DistributedCache>>,
    smart_warmer: Option<Arc<SmartCacheWarmer>>,
    coherency_manager: Option<Arc<CacheCoherencyManager>>,
    predictive_cache: Option<Arc<PredictiveCache>>,
    memory_aware_cache: Option<Arc<MemoryAwareCache>>,
    analytics: Option<Arc<CacheAnalytics>>,
    local_caches: Arc<RwLock<HashMap<String, Arc<LocalCache>>>>,
    performance_monitor: Arc<RwLock<CachePerformanceMonitor>>,
}

/// Local cache implementation
pub struct LocalCache {
    cache_id: String,
    cache_type: CacheType,
    storage: Arc<RwLock<HashMap<String, CacheEntry>>>,
    access_stats: Arc<RwLock<AccessStatistics>>,
    last_cleanup: Arc<RwLock<Instant>>,
}

/// Cache types for different use cases
#[derive(Debug, Clone)]
pub enum CacheType {
    AST,              // AST parsing results
    Embeddings,       // AI embeddings
    RuleMatches,      // Rule matching results
    FileMetadata,     // File information
    BusinessLogic,    // Business logic models
    Similarity,       // Semantic similarity results
    Configuration,    // Configuration data
    Temporary,        // Short-lived temporary data
}

/// Cache entry with metadata
#[derive(Debug, Clone)]
pub struct CacheEntry {
    pub key: String,
    pub value: Vec<u8>, // Serialized data
    pub created_at: Instant,
    pub last_accessed: Instant,
    pub access_count: u64,
    pub size_bytes: usize,
    pub cache_type: CacheType,
    pub ttl: Option<Duration>,
    pub compression_info: Option<CompressionInfo>,
    pub metadata: HashMap<String, String>,
}

/// Compression information
#[derive(Debug, Clone)]
pub struct CompressionInfo {
    pub algorithm: CompressionAlgorithm,
    pub original_size: usize,
    pub compressed_size: usize,
    pub compression_ratio: f64,
}

/// Access statistics for cache optimization
#[derive(Debug, Default, Clone)]
pub struct AccessStatistics {
    pub total_hits: u64,
    pub total_misses: u64,
    pub total_evictions: u64,
    pub avg_access_time_ns: f64,
    pub cache_size_bytes: usize,
    pub entry_count: usize,
    pub hit_rate: f64,
    pub access_patterns: HashMap<String, AccessPattern>,
}

/// Access pattern analysis
#[derive(Debug, Clone)]
pub struct AccessPattern {
    pub key: String,
    pub frequency: u64,
    pub last_access: Instant,
    pub access_interval_ms: Vec<u64>,
    pub predictability_score: f64,
    pub importance_score: f64,
}

/// Cache performance monitoring
#[derive(Debug, Default)]
pub struct CachePerformanceMonitor {
    pub global_stats: AccessStatistics,
    pub cache_specific_stats: HashMap<String, AccessStatistics>,
    pub performance_trends: Vec<PerformanceTrend>,
    pub alerts: Vec<CacheAlert>,
    pub optimization_suggestions: Vec<OptimizationSuggestion>,
}

/// Performance trend tracking
#[derive(Debug, Clone)]
pub struct PerformanceTrend {
    pub timestamp: Instant,
    pub metric_name: String,
    pub value: f64,
    pub trend_direction: TrendDirection,
    pub confidence: f64,
}

/// Trend directions
#[derive(Debug, Clone)]
pub enum TrendDirection {
    Improving,
    Declining,
    Stable,
    Volatile,
}

/// Cache performance alerts
#[derive(Debug, Clone)]
pub struct CacheAlert {
    pub alert_id: String,
    pub alert_type: CacheAlertType,
    pub severity: AlertSeverity,
    pub message: String,
    pub cache_id: Option<String>,
    pub timestamp: Instant,
    pub threshold_value: f64,
    pub current_value: f64,
    pub suggested_actions: Vec<String>,
}

/// Cache alert types
#[derive(Debug, Clone)]
pub enum CacheAlertType {
    LowHitRate,
    HighEvictionRate,
    MemoryPressure,
    SlowAccess,
    CoherencyViolation,
    NetworkPartition,
    StorageFailure,
}

/// Alert severity levels
#[derive(Debug, Clone)]
pub enum AlertSeverity {
    Info,
    Warning,
    Critical,
    Emergency,
}

/// Cache optimization suggestions
#[derive(Debug, Clone)]
pub struct OptimizationSuggestion {
    pub suggestion_id: String,
    pub category: OptimizationCategory,
    pub title: String,
    pub description: String,
    pub expected_improvement: f64,
    pub implementation_effort: EffortLevel,
    pub priority: Priority,
    pub applicable_caches: Vec<String>,
}

/// Optimization categories
#[derive(Debug, Clone)]
pub enum OptimizationCategory {
    SizeOptimization,
    EvictionStrategy,
    WarmingStrategy,
    CompressionSettings,
    NetworkOptimization,
    MemoryAllocation,
    AccessPatternOptimization,
}

/// Implementation effort levels
#[derive(Debug, Clone)]
pub enum EffortLevel {
    Low,
    Medium,
    High,
    VeryHigh,
}

/// Priority levels
#[derive(Debug, Clone)]
pub enum Priority {
    Low,
    Medium,
    High,
    Critical,
}

impl AdvancedCachingSystem {
    /// Create a new advanced caching system
    pub fn new(config: AdvancedCachingConfig) -> Self {
        Self {
            config: config.clone(),
            distributed_cache: None,
            smart_warmer: None,
            coherency_manager: None,
            predictive_cache: None,
            memory_aware_cache: None,
            analytics: None,
            local_caches: Arc::new(RwLock::new(HashMap::new())),
            performance_monitor: Arc::new(RwLock::new(CachePerformanceMonitor::default())),
        }
    }

    /// Initialize the advanced caching system
    pub async fn initialize(&mut self) -> Result<(), Box<dyn std::error::Error>> {
        // Initialize distributed caching if enabled
        if self.config.enable_distributed_caching {
            let distributed_cache = DistributedCache::new(self.config.distributed_cache.clone()).await?;
            self.distributed_cache = Some(Arc::new(distributed_cache));
        }

        // Initialize smart cache warming
        if self.config.enable_smart_warming {
            let smart_warmer = SmartCacheWarmer::new(
                self.config.warming_config.clone(),
                self.distributed_cache.clone(),
            ).await?;
            self.smart_warmer = Some(Arc::new(smart_warmer));
        }

        // Initialize cache coherency management
        if self.config.enable_coherency_management {
            let coherency_manager = CacheCoherencyManager::new(
                self.config.coherency_config.clone(),
                self.distributed_cache.clone(),
            ).await?;
            self.coherency_manager = Some(Arc::new(coherency_manager));
        }

        // Initialize predictive caching
        if self.config.enable_predictive_caching {
            let predictive_cache = PredictiveCache::new().await?;
            self.predictive_cache = Some(Arc::new(predictive_cache));
        }

        // Initialize memory-aware caching
        if self.config.enable_memory_aware_caching {
            let memory_aware_cache = MemoryAwareCache::new(
                self.config.global_cache_size_mb
            ).await?;
            self.memory_aware_cache = Some(Arc::new(memory_aware_cache));
        }

        // Initialize cache analytics
        if self.config.enable_cache_analytics {
            let analytics = CacheAnalytics::new().await?;
            self.analytics = Some(Arc::new(analytics));
        }

        // Start background monitoring and optimization
        self.start_background_tasks().await?;

        Ok(())
    }

    /// Get or create a local cache
    pub async fn get_cache(&self, cache_id: &str, cache_type: CacheType) -> Arc<LocalCache> {
        let mut caches = self.local_caches.write().unwrap();
        
        if let Some(cache) = caches.get(cache_id) {
            Arc::clone(cache)
        } else {
            let cache = Arc::new(LocalCache::new(cache_id.to_string(), cache_type));
            caches.insert(cache_id.to_string(), Arc::clone(&cache));
            cache
        }
    }

    /// Store data in cache with intelligent placement
    pub async fn store<T: Serialize>(
        &self,
        cache_id: &str,
        key: &str,
        value: &T,
        cache_type: CacheType,
        ttl: Option<Duration>,
    ) -> Result<(), Box<dyn std::error::Error>> {
        // Serialize the value
        let serialized = bincode::serialize(value)?;
        
        // Apply compression if configured
        let (final_data, compression_info) = self.apply_compression(&serialized)?;
        
        // Create cache entry
        let entry = CacheEntry {
            key: key.to_string(),
            value: final_data,
            created_at: Instant::now(),
            last_accessed: Instant::now(),
            access_count: 0,
            size_bytes: serialized.len(),
            cache_type: cache_type.clone(),
            ttl,
            compression_info,
            metadata: HashMap::new(),
        };

        // Store in local cache
        let local_cache = self.get_cache(cache_id, cache_type).await;
        local_cache.store(key, entry.clone()).await?;

        // Store in distributed cache if available
        if let Some(ref distributed_cache) = self.distributed_cache {
            distributed_cache.store(cache_id, key, &entry).await?;
        }

        // Update predictive cache if enabled
        if let Some(ref predictive_cache) = self.predictive_cache {
            predictive_cache.record_access(cache_id, key).await;
        }

        // Notify coherency manager
        if let Some(ref coherency_manager) = self.coherency_manager {
            coherency_manager.notify_update(cache_id, key).await?;
        }

        Ok(())
    }

    /// Retrieve data from cache with intelligent fallback
    pub async fn retrieve<T: for<'de> Deserialize<'de>>(
        &self,
        cache_id: &str,
        key: &str,
        cache_type: CacheType,
    ) -> Result<Option<T>, Box<dyn std::error::Error>> {
        // Try local cache first
        let local_cache = self.get_cache(cache_id, cache_type.clone()).await;
        if let Some(entry) = local_cache.retrieve(key).await? {
            // Decompress if needed
            let decompressed_data = self.decompress_data(&entry.value, &entry.compression_info)?;
            
            // Deserialize and return
            let value: T = bincode::deserialize(&decompressed_data)?;
            return Ok(Some(value));
        }

        // Try distributed cache if available
        if let Some(ref distributed_cache) = self.distributed_cache {
            if let Some(entry) = distributed_cache.retrieve(cache_id, key).await? {
                // Store in local cache for future access
                local_cache.store(key, entry.clone()).await?;
                
                // Decompress and deserialize
                let decompressed_data = self.decompress_data(&entry.value, &entry.compression_info)?;
                let value: T = bincode::deserialize(&decompressed_data)?;
                return Ok(Some(value));
            }
        }

        // Update access patterns for predictive caching
        if let Some(ref predictive_cache) = self.predictive_cache {
            predictive_cache.record_miss(cache_id, key).await;
        }

        Ok(None)
    }

    /// Invalidate cache entries across all levels
    pub async fn invalidate(
        &self,
        cache_id: &str,
        key: &str,
    ) -> Result<(), Box<dyn std::error::Error>> {
        // Invalidate local cache
        let local_cache = self.get_cache(cache_id, CacheType::Temporary).await;
        local_cache.invalidate(key).await?;

        // Invalidate distributed cache
        if let Some(ref distributed_cache) = self.distributed_cache {
            distributed_cache.invalidate(cache_id, key).await?;
        }

        // Notify coherency manager
        if let Some(ref coherency_manager) = self.coherency_manager {
            coherency_manager.notify_invalidation(cache_id, key).await?;
        }

        Ok(())
    }

    /// Get comprehensive cache statistics
    pub async fn get_cache_statistics(&self) -> CacheStatisticsReport {
        let monitor = self.performance_monitor.read().unwrap();
        
        CacheStatisticsReport {
            global_stats: monitor.global_stats.clone(),
            cache_specific_stats: monitor.cache_specific_stats.clone(),
            performance_trends: monitor.performance_trends.clone(),
            active_alerts: monitor.alerts.clone(),
            optimization_suggestions: monitor.optimization_suggestions.clone(),
            distributed_cache_stats: self.get_distributed_cache_stats().await,
            predictive_cache_stats: self.get_predictive_cache_stats().await,
        }
    }

    /// Start background optimization and monitoring tasks
    async fn start_background_tasks(&self) -> Result<(), Box<dyn std::error::Error>> {
        // Start cache warming if enabled
        if let Some(ref smart_warmer) = self.smart_warmer {
            smart_warmer.start_warming_scheduler().await;
        }

        // Start coherency monitoring
        if let Some(ref coherency_manager) = self.coherency_manager {
            coherency_manager.start_coherency_monitoring().await;
        }

        // Start predictive analysis
        if let Some(ref predictive_cache) = self.predictive_cache {
            predictive_cache.start_pattern_analysis().await;
        }

        // Start memory pressure monitoring
        if let Some(ref memory_aware_cache) = self.memory_aware_cache {
            memory_aware_cache.start_memory_monitoring().await;
        }

        // Start analytics collection
        if let Some(ref analytics) = self.analytics {
            analytics.start_analytics_collection().await;
        }

        Ok(())
    }

    /// Apply compression based on configuration
    fn apply_compression(
        &self,
        data: &[u8],
    ) -> Result<(Vec<u8>, Option<CompressionInfo>), Box<dyn std::error::Error>> {
        if !self.config.compression_config.enable_compression 
            || data.len() < self.config.compression_config.compression_threshold_bytes {
            return Ok((data.to_vec(), None));
        }

        let original_size = data.len();
        let compressed_data = match self.config.compression_config.compression_algorithm {
            CompressionAlgorithm::None => data.to_vec(),
            CompressionAlgorithm::Gzip => {
                // Implementation would use flate2 crate
                data.to_vec() // Placeholder
            },
            CompressionAlgorithm::Lz4 => {
                // Implementation would use lz4 crate
                data.to_vec() // Placeholder
            },
            CompressionAlgorithm::Zstd => {
                // Implementation would use zstd crate
                data.to_vec() // Placeholder
            },
            CompressionAlgorithm::Snappy => {
                // Implementation would use snap crate
                data.to_vec() // Placeholder
            },
        };

        let compressed_size = compressed_data.len();
        let compression_ratio = compressed_size as f64 / original_size as f64;

        let compression_info = CompressionInfo {
            algorithm: self.config.compression_config.compression_algorithm.clone(),
            original_size,
            compressed_size,
            compression_ratio,
        };

        Ok((compressed_data, Some(compression_info)))
    }

    /// Decompress data based on compression info
    fn decompress_data(
        &self,
        data: &[u8],
        compression_info: &Option<CompressionInfo>,
    ) -> Result<Vec<u8>, Box<dyn std::error::Error>> {
        match compression_info {
            Some(info) => {
                match info.algorithm {
                    CompressionAlgorithm::None => Ok(data.to_vec()),
                    CompressionAlgorithm::Gzip => {
                        // Implementation would use flate2 crate
                        Ok(data.to_vec()) // Placeholder
                    },
                    CompressionAlgorithm::Lz4 => {
                        // Implementation would use lz4 crate
                        Ok(data.to_vec()) // Placeholder
                    },
                    CompressionAlgorithm::Zstd => {
                        // Implementation would use zstd crate
                        Ok(data.to_vec()) // Placeholder
                    },
                    CompressionAlgorithm::Snappy => {
                        // Implementation would use snap crate
                        Ok(data.to_vec()) // Placeholder
                    },
                }
            },
            None => Ok(data.to_vec()),
        }
    }

    async fn get_distributed_cache_stats(&self) -> Option<DistributedCacheStats> {
        if let Some(ref distributed_cache) = self.distributed_cache {
            Some(distributed_cache.get_statistics().await)
        } else {
            None
        }
    }

    async fn get_predictive_cache_stats(&self) -> Option<PredictiveCacheStats> {
        if let Some(ref predictive_cache) = self.predictive_cache {
            Some(predictive_cache.get_statistics().await)
        } else {
            None
        }
    }
}

impl LocalCache {
    pub fn new(cache_id: String, cache_type: CacheType) -> Self {
        Self {
            cache_id,
            cache_type,
            storage: Arc::new(RwLock::new(HashMap::new())),
            access_stats: Arc::new(RwLock::new(AccessStatistics::default())),
            last_cleanup: Arc::new(RwLock::new(Instant::now())),
        }
    }

    pub async fn store(&self, key: &str, entry: CacheEntry) -> Result<(), Box<dyn std::error::Error>> {
        let mut storage = self.storage.write().unwrap();
        storage.insert(key.to_string(), entry);
        
        // Update statistics
        let mut stats = self.access_stats.write().unwrap();
        stats.entry_count = storage.len();
        stats.cache_size_bytes = storage.values().map(|e| e.size_bytes).sum();
        
        Ok(())
    }

    pub async fn retrieve(&self, key: &str) -> Result<Option<CacheEntry>, Box<dyn std::error::Error>> {
        let mut storage = self.storage.write().unwrap();
        
        if let Some(mut entry) = storage.get_mut(key) {
            entry.last_accessed = Instant::now();
            entry.access_count += 1;
            
            // Update statistics
            let mut stats = self.access_stats.write().unwrap();
            stats.total_hits += 1;
            stats.hit_rate = stats.total_hits as f64 / (stats.total_hits + stats.total_misses) as f64;
            
            Ok(Some(entry.clone()))
        } else {
            // Update miss statistics
            let mut stats = self.access_stats.write().unwrap();
            stats.total_misses += 1;
            stats.hit_rate = stats.total_hits as f64 / (stats.total_hits + stats.total_misses) as f64;
            
            Ok(None)
        }
    }

    pub async fn invalidate(&self, key: &str) -> Result<(), Box<dyn std::error::Error>> {
        let mut storage = self.storage.write().unwrap();
        storage.remove(key);
        
        // Update statistics
        let mut stats = self.access_stats.write().unwrap();
        stats.entry_count = storage.len();
        stats.cache_size_bytes = storage.values().map(|e| e.size_bytes).sum();
        
        Ok(())
    }
}

/// Comprehensive cache statistics report
#[derive(Debug, Clone)]
pub struct CacheStatisticsReport {
    pub global_stats: AccessStatistics,
    pub cache_specific_stats: HashMap<String, AccessStatistics>,
    pub performance_trends: Vec<PerformanceTrend>,
    pub active_alerts: Vec<CacheAlert>,
    pub optimization_suggestions: Vec<OptimizationSuggestion>,
    pub distributed_cache_stats: Option<DistributedCacheStats>,
    pub predictive_cache_stats: Option<PredictiveCacheStats>,
}

/// Placeholder for distributed cache stats (to be implemented in distributed_cache.rs)
#[derive(Debug, Clone)]
pub struct DistributedCacheStats {
    pub cluster_health: f64,
    pub node_count: usize,
    pub replication_factor: usize,
    pub network_latency_ms: f64,
}

/// Placeholder for predictive cache stats (to be implemented in predictive_cache.rs)
#[derive(Debug, Clone)]
pub struct PredictiveCacheStats {
    pub prediction_accuracy: f64,
    pub prefetch_hit_rate: f64,
    pub patterns_learned: usize,
    pub predictions_made: u64,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_advanced_caching_system_creation() {
        let config = AdvancedCachingConfig::default();
        let mut caching_system = AdvancedCachingSystem::new(config);
        
        // Should create without distributed caching for testing
        let mut test_config = AdvancedCachingConfig::default();
        test_config.enable_distributed_caching = false;
        caching_system.config = test_config;
        
        let result = caching_system.initialize().await;
        assert!(result.is_ok());
    }

    #[tokio::test]
    async fn test_local_cache_operations() {
        let cache = LocalCache::new("test_cache".to_string(), CacheType::AST);
        
        let entry = CacheEntry {
            key: "test_key".to_string(),
            value: b"test_value".to_vec(),
            created_at: Instant::now(),
            last_accessed: Instant::now(),
            access_count: 0,
            size_bytes: 10,
            cache_type: CacheType::AST,
            ttl: None,
            compression_info: None,
            metadata: HashMap::new(),
        };
        
        // Test store
        cache.store("test_key", entry).await.unwrap();
        
        // Test retrieve
        let retrieved = cache.retrieve("test_key").await.unwrap();
        assert!(retrieved.is_some());
        
        // Test invalidate
        cache.invalidate("test_key").await.unwrap();
        let after_invalidate = cache.retrieve("test_key").await.unwrap();
        assert!(after_invalidate.is_none());
    }

    #[test]
    fn test_compression_config_default() {
        let config = AdvancedCachingConfig::default();
        assert!(config.compression_config.enable_compression);
        assert_eq!(config.compression_config.compression_threshold_bytes, 1024);
    }
}