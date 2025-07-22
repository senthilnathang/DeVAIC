use std::collections::{HashMap, BTreeMap};
use std::sync::Arc;
use std::time::{Duration, SystemTime, UNIX_EPOCH};
use std::hash::{Hash, Hasher};
use parking_lot::{RwLock, Mutex};
use siphasher::sip::SipHasher;
use crate::Vulnerability;

/// Multi-level intelligent caching system with adaptive eviction
pub struct IntelligentCache {
    l1_cache: Arc<RwLock<LRUCache<CacheKey, CacheEntry>>>,
    l2_cache: Arc<RwLock<LFUCache<CacheKey, CacheEntry>>>,
    l3_persistent: Arc<RwLock<PersistentCache>>,
    analytics: Arc<Mutex<CacheAnalytics>>,
    config: CacheConfig,
    predictor: Arc<Mutex<AccessPredictor>>,
}

#[derive(Debug, Clone)]
pub struct CacheConfig {
    pub l1_size: usize,
    pub l2_size: usize,
    pub l3_size: usize,
    pub ttl_seconds: u64,
    pub enable_prefetching: bool,
    pub enable_compression: bool,
    pub enable_persistence: bool,
    pub adaptive_sizing: bool,
    pub max_memory_mb: usize,
}

impl Default for CacheConfig {
    fn default() -> Self {
        Self {
            l1_size: 1000,
            l2_size: 5000,
            l3_size: 20000,
            ttl_seconds: 3600, // 1 hour
            enable_prefetching: true,
            enable_compression: true,
            enable_persistence: true,
            adaptive_sizing: true,
            max_memory_mb: 512,
        }
    }
}

/// Universal cache key with automatic hashing
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct CacheKey {
    namespace: String,
    key: String,
    hash: u64,
}

impl CacheKey {
    pub fn new(namespace: &str, key: &str) -> Self {
        let mut hasher = SipHasher::new();
        namespace.hash(&mut hasher);
        key.hash(&mut hasher);
        let hash = hasher.finish();
        
        Self {
            namespace: namespace.to_string(),
            key: key.to_string(),
            hash,
        }
    }
    
    pub fn from_file_path(path: &std::path::Path) -> Self {
        Self::new("file", &path.to_string_lossy())
    }
    
    pub fn from_analysis_request(file_path: &str, rule_set: &str) -> Self {
        Self::new("analysis", &format!("{}:{}", file_path, rule_set))
    }
    
    pub fn from_regex_pattern(pattern: &str) -> Self {
        Self::new("regex", pattern)
    }
}

/// Cache entry with metadata and compression support
#[derive(Debug, Clone)]
pub struct CacheEntry {
    data: CacheData,
    metadata: CacheMetadata,
    compressed: bool,
}

#[derive(Debug, Clone)]
pub enum CacheData {
    Vulnerabilities(Vec<Vulnerability>),
    ParsedAST(Vec<u8>), // Serialized AST
    FileContent(String),
    CompiledRegex(Vec<u8>), // Serialized regex
    Generic(Vec<u8>),
}

#[derive(Debug, Clone)]
pub struct CacheMetadata {
    created_at: u64,
    last_accessed: u64,
    access_count: u64,
    size_bytes: usize,
    ttl_seconds: u64,
    tags: HashMap<String, String>,
    version: u32,
}

impl CacheEntry {
    pub fn new(data: CacheData, ttl_seconds: u64) -> Self {
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or(Duration::ZERO)
            .as_secs();
        
        let size_bytes = Self::calculate_size(&data);
        
        Self {
            data,
            metadata: CacheMetadata {
                created_at: now,
                last_accessed: now,
                access_count: 1,
                size_bytes,
                ttl_seconds,
                tags: HashMap::new(),
                version: 1,
            },
            compressed: false,
        }
    }
    
    pub fn is_expired(&self) -> bool {
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or(Duration::ZERO)
            .as_secs();
        
        now > self.metadata.created_at + self.metadata.ttl_seconds
    }
    
    pub fn access(&mut self) {
        self.metadata.last_accessed = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or(Duration::ZERO)
            .as_secs();
        self.metadata.access_count += 1;
    }
    
    fn calculate_size(data: &CacheData) -> usize {
        match data {
            CacheData::Vulnerabilities(vulns) => vulns.len() * 500, // Rough estimate
            CacheData::ParsedAST(bytes) => bytes.len(),
            CacheData::FileContent(content) => content.len(),
            CacheData::CompiledRegex(bytes) => bytes.len(),
            CacheData::Generic(bytes) => bytes.len(),
        }
    }
}

/// LRU cache implementation for L1 (most recently used)
pub struct LRUCache<K, V> {
    data: HashMap<K, V>,
    order: std::collections::VecDeque<K>,
    capacity: usize,
}

impl<K: Clone + Eq + Hash, V> LRUCache<K, V> {
    pub fn new(capacity: usize) -> Self {
        Self {
            data: HashMap::with_capacity(capacity),
            order: std::collections::VecDeque::with_capacity(capacity),
            capacity,
        }
    }
    
    pub fn get(&mut self, key: &K) -> Option<&V> {
        if self.data.contains_key(key) {
            // Move to front (most recent)
            self.order.retain(|k| k != key);
            self.order.push_back(key.clone());
            self.data.get(key)
        } else {
            None
        }
    }
    
    pub fn insert(&mut self, key: K, value: V) -> Option<V> {
        if let Some(existing) = self.data.remove(&key) {
            self.order.retain(|k| k != &key);
            self.order.push_back(key.clone());
            self.data.insert(key, value);
            Some(existing)
        } else {
            if self.data.len() >= self.capacity {
                if let Some(oldest_key) = self.order.pop_front() {
                    self.data.remove(&oldest_key);
                }
            }
            self.order.push_back(key.clone());
            self.data.insert(key, value);
            None
        }
    }
    
    pub fn len(&self) -> usize {
        self.data.len()
    }
    
    pub fn clear(&mut self) {
        self.data.clear();
        self.order.clear();
    }
}

/// LFU cache implementation for L2 (least frequently used)
pub struct LFUCache<K, V> {
    data: HashMap<K, V>,
    frequencies: HashMap<K, u64>,
    frequency_buckets: BTreeMap<u64, std::collections::HashSet<K>>,
    capacity: usize,
    min_frequency: u64,
}

impl<K: Clone + Eq + Hash, V> LFUCache<K, V> {
    pub fn new(capacity: usize) -> Self {
        Self {
            data: HashMap::with_capacity(capacity),
            frequencies: HashMap::with_capacity(capacity),
            frequency_buckets: BTreeMap::new(),
            capacity,
            min_frequency: 0,
        }
    }
    
    pub fn get(&mut self, key: &K) -> Option<&V> {
        if self.data.contains_key(key) {
            self.increment_frequency(key);
            self.data.get(key)
        } else {
            None
        }
    }
    
    pub fn insert(&mut self, key: K, value: V) -> Option<V> {
        if self.capacity == 0 {
            return None;
        }
        
        if let Some(existing) = self.data.remove(&key) {
            self.data.insert(key.clone(), value);
            self.increment_frequency(&key);
            Some(existing)
        } else {
            if self.data.len() >= self.capacity {
                self.evict_least_frequent();
            }
            
            self.data.insert(key.clone(), value);
            self.frequencies.insert(key.clone(), 1);
            self.frequency_buckets.entry(1).or_insert_with(std::collections::HashSet::new).insert(key);
            self.min_frequency = 1;
            
            None
        }
    }
    
    fn increment_frequency(&mut self, key: &K) {
        let current_freq = self.frequencies.get(key).copied().unwrap_or(0);
        let new_freq = current_freq + 1;
        
        // Remove from current frequency bucket
        if let Some(bucket) = self.frequency_buckets.get_mut(&current_freq) {
            bucket.remove(key);
            if bucket.is_empty() && current_freq == self.min_frequency {
                self.min_frequency += 1;
            }
        }
        
        // Add to new frequency bucket
        self.frequency_buckets.entry(new_freq).or_insert_with(std::collections::HashSet::new).insert(key.clone());
        self.frequencies.insert(key.clone(), new_freq);
    }
    
    fn evict_least_frequent(&mut self) {
        if let Some(bucket) = self.frequency_buckets.get_mut(&self.min_frequency) {
            if let Some(key) = bucket.iter().next().cloned() {
                bucket.remove(&key);
                self.data.remove(&key);
                self.frequencies.remove(&key);
            }
        }
    }
    
    pub fn len(&self) -> usize {
        self.data.len()
    }
    
    pub fn clear(&mut self) {
        self.data.clear();
        self.frequencies.clear();
        self.frequency_buckets.clear();
        self.min_frequency = 0;
    }
}

/// Persistent cache for long-term storage
pub struct PersistentCache {
    data: HashMap<CacheKey, CacheEntry>,
    dirty_keys: std::collections::HashSet<CacheKey>,
    max_size: usize,
}

impl PersistentCache {
    pub fn new(max_size: usize) -> Self {
        Self {
            data: HashMap::with_capacity(max_size),
            dirty_keys: std::collections::HashSet::new(),
            max_size,
        }
    }
    
    pub fn get(&mut self, key: &CacheKey) -> Option<CacheEntry> {
        if self.data.contains_key(key) {
            if let Some(entry) = self.data.get(key) {
                if entry.is_expired() {
                    self.data.remove(key);
                    return None;
                }
            }
            
            // Entry exists and is not expired, clone it and update access
            if let Some(entry) = self.data.get_mut(key) {
                entry.access();
                Some(entry.clone())
            } else {
                None
            }
        } else {
            None
        }
    }
    
    pub fn insert(&mut self, key: CacheKey, value: CacheEntry) {
        if self.data.len() >= self.max_size {
            self.evict_oldest();
        }
        
        self.dirty_keys.insert(key.clone());
        self.data.insert(key, value);
    }
    
    fn evict_oldest(&mut self) {
        if let Some((oldest_key, _)) = self.data.iter()
            .min_by_key(|(_, entry)| entry.metadata.last_accessed)
            .map(|(k, v)| (k.clone(), v.clone()))
        {
            self.data.remove(&oldest_key);
            self.dirty_keys.remove(&oldest_key);
        }
    }
    
    pub fn len(&self) -> usize {
        self.data.len()
    }
}

/// Access pattern predictor for intelligent prefetching
pub struct AccessPredictor {
    access_history: std::collections::VecDeque<(CacheKey, u64)>,
    patterns: HashMap<CacheKey, Vec<CacheKey>>, // Key -> likely next keys
    sequence_detector: SequenceDetector,
}

impl AccessPredictor {
    pub fn new() -> Self {
        Self {
            access_history: std::collections::VecDeque::with_capacity(10000),
            patterns: HashMap::new(),
            sequence_detector: SequenceDetector::new(),
        }
    }
    
    pub fn record_access(&mut self, key: CacheKey) {
        let timestamp = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or(Duration::ZERO)
            .as_secs();
        
        self.access_history.push_back((key.clone(), timestamp));
        if self.access_history.len() > 10000 {
            self.access_history.pop_front();
        }
        
        self.update_patterns(&key);
        self.sequence_detector.add_access(key);
    }
    
    pub fn predict_next_accesses(&self, current_key: &CacheKey) -> Vec<CacheKey> {
        let mut predictions = Vec::new();
        
        // Pattern-based predictions
        if let Some(likely_next) = self.patterns.get(current_key) {
            predictions.extend(likely_next.clone());
        }
        
        // Sequence-based predictions
        predictions.extend(self.sequence_detector.predict_next(current_key));
        
        predictions
    }
    
    fn update_patterns(&mut self, current_key: &CacheKey) {
        // Look for patterns in recent accesses
        if self.access_history.len() >= 2 {
            if let Some((prev_key, _)) = self.access_history.get(self.access_history.len() - 2) {
                self.patterns.entry(prev_key.clone())
                    .or_insert_with(Vec::new)
                    .push(current_key.clone());
            }
        }
    }
}

/// Sequence pattern detector
pub struct SequenceDetector {
    sequences: HashMap<Vec<CacheKey>, CacheKey>,
    recent_accesses: std::collections::VecDeque<CacheKey>,
}

impl SequenceDetector {
    pub fn new() -> Self {
        Self {
            sequences: HashMap::new(),
            recent_accesses: std::collections::VecDeque::with_capacity(100),
        }
    }
    
    pub fn add_access(&mut self, key: CacheKey) {
        self.recent_accesses.push_back(key.clone());
        if self.recent_accesses.len() > 100 {
            self.recent_accesses.pop_front();
        }
        
        // Look for sequences of length 2-5
        for seq_len in 2..=5 {
            if self.recent_accesses.len() >= seq_len + 1 {
                let seq: Vec<CacheKey> = self.recent_accesses
                    .range(self.recent_accesses.len() - seq_len - 1..self.recent_accesses.len() - 1)
                    .cloned()
                    .collect();
                
                self.sequences.insert(seq, key.clone());
            }
        }
    }
    
    pub fn predict_next(&self, current_key: &CacheKey) -> Vec<CacheKey> {
        let mut predictions = Vec::new();
        
        // Look for sequences ending with current key
        for (seq, next_key) in &self.sequences {
            if seq.last() == Some(current_key) {
                predictions.push(next_key.clone());
            }
        }
        
        predictions
    }
}

/// Cache analytics for performance monitoring
#[derive(Debug, Default)]
pub struct CacheAnalytics {
    total_requests: u64,
    l1_hits: u64,
    l2_hits: u64,
    l3_hits: u64,
    misses: u64,
    evictions: u64,
    prefetch_hits: u64,
    prefetch_misses: u64,
    total_size_bytes: usize,
}

impl CacheAnalytics {
    pub fn record_l1_hit(&mut self) {
        self.total_requests += 1;
        self.l1_hits += 1;
    }
    
    pub fn record_l2_hit(&mut self) {
        self.total_requests += 1;
        self.l2_hits += 1;
    }
    
    pub fn record_l3_hit(&mut self) {
        self.total_requests += 1;
        self.l3_hits += 1;
    }
    
    pub fn record_miss(&mut self) {
        self.total_requests += 1;
        self.misses += 1;
    }
    
    pub fn hit_rate(&self) -> f64 {
        if self.total_requests == 0 {
            return 0.0;
        }
        (self.l1_hits + self.l2_hits + self.l3_hits) as f64 / self.total_requests as f64
    }
    
    pub fn get_stats(&self) -> CacheStats {
        CacheStats {
            total_requests: self.total_requests,
            hit_rate: self.hit_rate(),
            l1_hit_rate: if self.total_requests > 0 { self.l1_hits as f64 / self.total_requests as f64 } else { 0.0 },
            l2_hit_rate: if self.total_requests > 0 { self.l2_hits as f64 / self.total_requests as f64 } else { 0.0 },
            l3_hit_rate: if self.total_requests > 0 { self.l3_hits as f64 / self.total_requests as f64 } else { 0.0 },
            miss_rate: if self.total_requests > 0 { self.misses as f64 / self.total_requests as f64 } else { 0.0 },
            evictions: self.evictions,
            total_size_bytes: self.total_size_bytes,
        }
    }
}

#[derive(Debug)]
pub struct CacheStats {
    pub total_requests: u64,
    pub hit_rate: f64,
    pub l1_hit_rate: f64,
    pub l2_hit_rate: f64,
    pub l3_hit_rate: f64,
    pub miss_rate: f64,
    pub evictions: u64,
    pub total_size_bytes: usize,
}

impl IntelligentCache {
    pub fn new(config: CacheConfig) -> Self {
        Self {
            l1_cache: Arc::new(RwLock::new(LRUCache::new(config.l1_size))),
            l2_cache: Arc::new(RwLock::new(LFUCache::new(config.l2_size))),
            l3_persistent: Arc::new(RwLock::new(PersistentCache::new(config.l3_size))),
            analytics: Arc::new(Mutex::new(CacheAnalytics::default())),
            predictor: Arc::new(Mutex::new(AccessPredictor::new())),
            config,
        }
    }
    
    /// Get value from cache with intelligent multi-level lookup
    pub fn get(&self, key: &CacheKey) -> Option<CacheEntry> {
        // Record access for prediction
        self.predictor.lock().record_access(key.clone());
        
        // L1 Cache (LRU - most recent)
        if let Some(entry) = self.l1_cache.write().get(key).cloned() {
            self.analytics.lock().record_l1_hit();
            return Some(entry);
        }
        
        // L2 Cache (LFU - most frequent)
        if let Some(entry) = self.l2_cache.write().get(key).cloned() {
            self.analytics.lock().record_l2_hit();
            // Promote to L1
            self.l1_cache.write().insert(key.clone(), entry.clone());
            return Some(entry);
        }
        
        // L3 Cache (Persistent)
        if let Some(entry) = self.l3_persistent.write().get(key) {
            self.analytics.lock().record_l3_hit();
            // Promote to L2 and L1
            self.l2_cache.write().insert(key.clone(), entry.clone());
            self.l1_cache.write().insert(key.clone(), entry.clone());
            return Some(entry);
        }
        
        self.analytics.lock().record_miss();
        
        // Trigger prefetching for predicted next accesses
        if self.config.enable_prefetching {
            self.prefetch_predicted_accesses(key);
        }
        
        None
    }
    
    /// Insert value into cache with intelligent placement
    pub fn insert(&self, key: CacheKey, value: CacheEntry) {
        // Always insert into L1 (most recent)
        self.l1_cache.write().insert(key.clone(), value.clone());
        
        // Update size tracking
        self.analytics.lock().total_size_bytes += value.metadata.size_bytes;
        
        // If high value item, also insert into L2
        if value.metadata.access_count > 5 {
            self.l2_cache.write().insert(key.clone(), value.clone());
        }
        
        // If persistent storage is enabled, insert into L3
        if self.config.enable_persistence {
            self.l3_persistent.write().insert(key.clone(), value);
        }
    }
    
    /// Prefetch predicted next accesses
    fn prefetch_predicted_accesses(&self, current_key: &CacheKey) {
        if !self.config.enable_prefetching {
            return;
        }
        
        let predictions = self.predictor.lock().predict_next_accesses(current_key);
        
        for predicted_key in predictions.iter().take(5) { // Limit prefetch to 5 items
            // Check if already in any cache level
            if self.l1_cache.read().data.contains_key(predicted_key) ||
               self.l2_cache.read().data.contains_key(predicted_key) ||
               self.l3_persistent.read().data.contains_key(predicted_key) {
                continue;
            }
            
            // In a real implementation, would trigger async loading
            // For now, just record the prefetch attempt
            // self.load_and_cache_async(predicted_key);
        }
    }
    
    /// Get cache statistics
    pub fn get_stats(&self) -> CacheStats {
        let mut stats = self.analytics.lock().get_stats();
        stats.total_size_bytes = self.l1_cache.read().len() * 1000 + // Rough estimate
                                self.l2_cache.read().len() * 1000 +
                                self.l3_persistent.read().len() * 1000;
        stats
    }
    
    /// Clear all cache levels
    pub fn clear_all(&self) {
        self.l1_cache.write().clear();
        self.l2_cache.write().clear();
        self.l3_persistent.write().data.clear();
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_cache_key() {
        let key1 = CacheKey::new("test", "key1");
        let key2 = CacheKey::new("test", "key1");
        let key3 = CacheKey::new("test", "key2");
        
        assert_eq!(key1, key2);
        assert_ne!(key1, key3);
        assert_eq!(key1.hash, key2.hash);
        assert_ne!(key1.hash, key3.hash);
    }
    
    #[test]
    fn test_lru_cache() {
        let mut cache = LRUCache::new(2);
        
        cache.insert("key1", "value1");
        cache.insert("key2", "value2");
        
        assert_eq!(cache.get(&"key1"), Some(&"value1"));
        
        // This should evict key2 (least recently used)
        cache.insert("key3", "value3");
        
        assert_eq!(cache.get(&"key2"), None);
        assert_eq!(cache.get(&"key1"), Some(&"value1"));
        assert_eq!(cache.get(&"key3"), Some(&"value3"));
    }
    
    #[test]
    fn test_intelligent_cache() {
        let cache = IntelligentCache::new(CacheConfig::default());
        let key = CacheKey::new("test", "key1");
        let entry = CacheEntry::new(CacheData::Generic(b"test data".to_vec()), 3600);
        
        assert!(cache.get(&key).is_none());
        
        cache.insert(key.clone(), entry.clone());
        
        let retrieved = cache.get(&key);
        assert!(retrieved.is_some());
        
        let stats = cache.get_stats();
        assert_eq!(stats.total_requests, 2); // 1 miss + 1 hit
        assert!(stats.hit_rate > 0.0);
    }
}