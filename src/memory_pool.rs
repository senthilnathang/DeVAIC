use std::collections::VecDeque;
use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};
use parking_lot::{RwLock, Mutex as PLMutex};
use crate::Vulnerability;
use std::alloc::{GlobalAlloc, Layout, System};
use std::ptr::NonNull;

/// Memory pool for reusing allocated objects to reduce garbage collection pressure
pub struct MemoryPool<T> {
    pool: Arc<PLMutex<VecDeque<Box<T>>>>,
    factory: Box<dyn Fn() -> T + Send + Sync>,
    max_size: usize,
    reset_fn: Option<Box<dyn Fn(&mut T) + Send + Sync>>,
    // Performance metrics
    total_allocations: AtomicUsize,
    cache_hits: AtomicUsize,
    cache_misses: AtomicUsize,
}

impl<T> MemoryPool<T>
where
    T: Send + 'static,
{
    pub fn new<F>(factory: F, max_size: usize) -> Self
    where
        F: Fn() -> T + Send + Sync + 'static,
    {
        Self {
            pool: Arc::new(PLMutex::new(VecDeque::with_capacity(max_size))),
            factory: Box::new(factory),
            max_size,
            reset_fn: None,
            total_allocations: AtomicUsize::new(0),
            cache_hits: AtomicUsize::new(0),
            cache_misses: AtomicUsize::new(0),
        }
    }

    pub fn with_reset<R>(mut self, reset_fn: R) -> Self
    where
        R: Fn(&mut T) + Send + Sync + 'static,
    {
        self.reset_fn = Some(Box::new(reset_fn));
        self
    }

    /// Get an object from the pool or create a new one
    pub fn get(&self) -> PooledObject<T> {
        self.total_allocations.fetch_add(1, Ordering::Relaxed);
        
        let mut pool = self.pool.lock();
        let object = match pool.pop_front() {
            Some(mut obj) => {
                self.cache_hits.fetch_add(1, Ordering::Relaxed);
                // Reset the object if reset function is provided
                if let Some(ref reset_fn) = self.reset_fn {
                    reset_fn(&mut obj);
                }
                obj
            }
            None => {
                self.cache_misses.fetch_add(1, Ordering::Relaxed);
                Box::new((self.factory)())
            }
        };

        PooledObject {
            object: Some(object),
            pool: Arc::clone(&self.pool),
            max_size: self.max_size,
        }
    }

    /// Get current pool size
    pub fn size(&self) -> usize {
        self.pool.lock().len()
    }

    /// Clear all pooled objects
    pub fn clear(&self) {
        self.pool.lock().clear();
    }

    /// Pre-populate the pool with objects
    pub fn pre_populate(&self, count: usize) {
        let mut pool = self.pool.lock();
        let actual_count = count.min(self.max_size);
        
        for _ in 0..actual_count {
            pool.push_back(Box::new((self.factory)()));
        }
    }
    
    /// Get pool performance statistics
    pub fn stats(&self) -> PoolStats {
        let total = self.total_allocations.load(Ordering::Relaxed);
        let hits = self.cache_hits.load(Ordering::Relaxed);
        let misses = self.cache_misses.load(Ordering::Relaxed);
        
        PoolStats {
            total_allocations: total,
            cache_hits: hits,
            cache_misses: misses,
            hit_ratio: if total > 0 { hits as f64 / total as f64 } else { 0.0 },
            current_size: self.size(),
            max_size: self.max_size,
        }
    }
    
    /// Warm up the pool by pre-allocating and immediately releasing objects
    pub fn warm_up(&self, iterations: usize) {
        for _ in 0..iterations {
            let _obj = self.get();
            // Object is automatically returned to pool when dropped
        }
    }
}

/// RAII wrapper that automatically returns objects to the pool when dropped
pub struct PooledObject<T> {
    object: Option<Box<T>>,
    pool: Arc<PLMutex<VecDeque<Box<T>>>>,
    max_size: usize,
}

impl<T> PooledObject<T> {
    /// Get a reference to the pooled object
    pub fn as_ref(&self) -> &T {
        self.object.as_ref().unwrap().as_ref()
    }

    /// Get a mutable reference to the pooled object
    pub fn as_mut(&mut self) -> &mut T {
        self.object.as_mut().unwrap().as_mut()
    }

    /// Take ownership of the object (won't be returned to pool)
    pub fn into_inner(mut self) -> Box<T> {
        self.object.take().unwrap()
    }
}

impl<T> Drop for PooledObject<T> {
    fn drop(&mut self) {
        if let Some(object) = self.object.take() {
            let mut pool = self.pool.lock();
            if pool.len() < self.max_size {
                pool.push_back(object);
            }
            // If pool is full, object is simply dropped
        }
    }
}

impl<T> std::ops::Deref for PooledObject<T> {
    type Target = T;

    fn deref(&self) -> &Self::Target {
        self.as_ref()
    }
}

impl<T> std::ops::DerefMut for PooledObject<T> {
    fn deref_mut(&mut self) -> &mut Self::Target {
        self.as_mut()
    }
}

/// Specialized memory pool for vulnerabilities
pub struct VulnerabilityPool {
    pool: MemoryPool<Vec<Vulnerability>>,
}

impl VulnerabilityPool {
    pub fn new(max_size: usize) -> Self {
        let pool = MemoryPool::new(
            || Vec::with_capacity(100), // Pre-allocate capacity for 100 vulnerabilities
            max_size,
        ).with_reset(|vec: &mut Vec<Vulnerability>| {
            vec.clear(); // Reset by clearing the vector
        });

        Self { pool }
    }

    pub fn get(&self) -> PooledObject<Vec<Vulnerability>> {
        self.pool.get()
    }

    pub fn size(&self) -> usize {
        self.pool.size()
    }

    pub fn pre_populate(&self, count: usize) {
        self.pool.pre_populate(count);
    }
}

/// String pool for reusing string allocations
pub struct StringPool {
    pool: MemoryPool<String>,
}

impl StringPool {
    pub fn new(max_size: usize) -> Self {
        let pool = MemoryPool::new(
            || String::with_capacity(1024), // Pre-allocate 1KB capacity
            max_size,
        ).with_reset(|string: &mut String| {
            string.clear(); // Reset by clearing the string
        });

        Self { pool }
    }

    pub fn get(&self) -> PooledObject<String> {
        self.pool.get()
    }

    pub fn get_with_content(&self, content: &str) -> PooledObject<String> {
        let mut pooled = self.get();
        pooled.push_str(content);
        pooled
    }
}

/// Memory arena for bulk allocations with automatic cleanup
pub struct MemoryArena {
    chunks: RwLock<Vec<Vec<u8>>>,
    current_chunk: RwLock<usize>,
    chunk_size: usize,
    total_allocated: RwLock<usize>,
    max_memory: usize,
}

impl MemoryArena {
    pub fn new(chunk_size: usize, max_memory: usize) -> Self {
        Self {
            chunks: RwLock::new(Vec::new()),
            current_chunk: RwLock::new(0),
            chunk_size,
            total_allocated: RwLock::new(0),
            max_memory,
        }
    }

    /// Allocate memory from the arena
    pub fn allocate(&self, size: usize) -> Option<*mut u8> {
        if size > self.chunk_size {
            return None; // Can't allocate objects larger than chunk size
        }

        let mut chunks = self.chunks.write();
        let mut current_chunk = self.current_chunk.write();
        let mut total_allocated = self.total_allocated.write();

        // Check if we would exceed memory limit
        if *total_allocated + size > self.max_memory {
            return None;
        }

        // Ensure we have at least one chunk
        if chunks.is_empty() {
            chunks.push(vec![0u8; self.chunk_size]);
            *current_chunk = 0;
        }

        // Check if current chunk has enough space
        if chunks[*current_chunk].capacity() - chunks[*current_chunk].len() < size {
            // Create new chunk
            chunks.push(vec![0u8; self.chunk_size]);
            *current_chunk = chunks.len() - 1;
        }

        // Allocate from current chunk
        let chunk = &mut chunks[*current_chunk];
        let ptr = chunk.as_mut_ptr().wrapping_add(chunk.len());
        chunk.extend(std::iter::repeat(0).take(size));
        *total_allocated += size;

        Some(ptr)
    }

    /// Get current memory usage
    pub fn memory_usage(&self) -> usize {
        *self.total_allocated.read()
    }

    /// Clear all allocated memory
    pub fn clear(&self) {
        let mut chunks = self.chunks.write();
        let mut total_allocated = self.total_allocated.write();
        
        chunks.clear();
        *total_allocated = 0;
        *self.current_chunk.write() = 0;
    }

    /// Get statistics
    pub fn stats(&self) -> ArenaStats {
        let chunks = self.chunks.read();
        ArenaStats {
            total_chunks: chunks.len(),
            chunk_size: self.chunk_size,
            total_allocated: *self.total_allocated.read(),
            max_memory: self.max_memory,
        }
    }
}

#[derive(Debug)]
pub struct ArenaStats {
    pub total_chunks: usize,
    pub chunk_size: usize,
    pub total_allocated: usize,
    pub max_memory: usize,
}

#[derive(Debug)]
pub struct PoolStats {
    pub total_allocations: usize,
    pub cache_hits: usize,
    pub cache_misses: usize,
    pub hit_ratio: f64,
    pub current_size: usize,
    pub max_size: usize,
}

impl PoolStats {
    pub fn print_summary(&self) {
        println!("Pool Statistics:");
        println!("  Total allocations: {}", self.total_allocations);
        println!("  Cache hits: {} ({:.1}%)", self.cache_hits, self.hit_ratio * 100.0);
        println!("  Cache misses: {}", self.cache_misses);
        println!("  Current size: {}/{}", self.current_size, self.max_size);
    }
}

/// Global memory pools for common object types
pub struct GlobalMemoryPools {
    vulnerability_pool: VulnerabilityPool,
    string_pool: StringPool,
    arena: MemoryArena,
}

impl GlobalMemoryPools {
    pub fn new() -> Self {
        Self {
            vulnerability_pool: VulnerabilityPool::new(100),
            string_pool: StringPool::new(200),
            arena: MemoryArena::new(1024 * 1024, 64 * 1024 * 1024), // 1MB chunks, 64MB max
        }
    }

    pub fn vulnerability_pool(&self) -> &VulnerabilityPool {
        &self.vulnerability_pool
    }

    pub fn string_pool(&self) -> &StringPool {
        &self.string_pool
    }

    pub fn arena(&self) -> &MemoryArena {
        &self.arena
    }

    /// Initialize pools with pre-allocated objects
    pub fn initialize(&self) {
        self.vulnerability_pool.pre_populate(20);
        self.string_pool.pool.pre_populate(50);
    }

    /// Get memory usage statistics
    pub fn memory_stats(&self) -> MemoryStats {
        MemoryStats {
            vulnerability_pool_size: self.vulnerability_pool.size(),
            string_pool_size: self.string_pool.pool.size(),
            arena_stats: self.arena.stats(),
            vulnerability_pool_stats: self.vulnerability_pool.pool.stats(),
            string_pool_stats: self.string_pool.pool.stats(),
        }
    }
    
    /// Warm up all pools for better initial performance
    pub fn warm_up(&self) {
        // Warm up pools by allocating and releasing objects
        self.vulnerability_pool.pool.warm_up(10);
        self.string_pool.pool.warm_up(20);
    }

    /// Clear all pools
    pub fn clear_all(&self) {
        self.vulnerability_pool.pool.clear();
        self.string_pool.pool.clear();
        self.arena.clear();
    }
}

#[derive(Debug)]
pub struct MemoryStats {
    pub vulnerability_pool_size: usize,
    pub string_pool_size: usize,
    pub arena_stats: ArenaStats,
    pub vulnerability_pool_stats: PoolStats,
    pub string_pool_stats: PoolStats,
}

impl MemoryStats {
    pub fn print_summary(&self) {
        println!("Memory Pool Statistics:");
        println!("\nVulnerability Pool:");
        self.vulnerability_pool_stats.print_summary();
        println!("\nString Pool:");
        self.string_pool_stats.print_summary();
        println!("\nMemory Arena:");
        println!("  Total chunks: {}", self.arena_stats.total_chunks);
        println!("  Allocated memory: {} KB", self.arena_stats.total_allocated / 1024);
        println!("  Maximum memory: {} MB", self.arena_stats.max_memory / 1024 / 1024);
        println!("  Memory utilization: {:.1}%", 
            (self.arena_stats.total_allocated as f64 / self.arena_stats.max_memory as f64) * 100.0);
    }
}

/// Lock-free memory allocator for high-performance scenarios
pub struct LockFreeAllocator {
    system_allocator: System,
    allocation_count: AtomicUsize,
    deallocation_count: AtomicUsize,
    total_allocated: AtomicUsize,
}

impl LockFreeAllocator {
    pub fn new() -> Self {
        Self {
            system_allocator: System,
            allocation_count: AtomicUsize::new(0),
            deallocation_count: AtomicUsize::new(0),
            total_allocated: AtomicUsize::new(0),
        }
    }
    
    pub fn allocate_aligned(&self, size: usize, align: usize) -> Option<NonNull<u8>> {
        let layout = Layout::from_size_align(size, align).ok()?;
        
        // Use system allocator but track metrics
        unsafe {
            let ptr = self.system_allocator.alloc(layout);
            if !ptr.is_null() {
                self.allocation_count.fetch_add(1, Ordering::Relaxed);
                self.total_allocated.fetch_add(size, Ordering::Relaxed);
                NonNull::new(ptr)
            } else {
                None
            }
        }
    }
    
    pub unsafe fn deallocate_aligned(&self, ptr: NonNull<u8>, size: usize, align: usize) {
        let layout = Layout::from_size_align_unchecked(size, align);
        self.system_allocator.dealloc(ptr.as_ptr(), layout);
        self.deallocation_count.fetch_add(1, Ordering::Relaxed);
        self.total_allocated.fetch_sub(size, Ordering::Relaxed);
    }
    
    pub fn stats(&self) -> AllocatorStats {
        AllocatorStats {
            allocations: self.allocation_count.load(Ordering::Relaxed),
            deallocations: self.deallocation_count.load(Ordering::Relaxed),
            active_allocations: self.allocation_count.load(Ordering::Relaxed) 
                - self.deallocation_count.load(Ordering::Relaxed),
            total_allocated_bytes: self.total_allocated.load(Ordering::Relaxed),
        }
    }
}

#[derive(Debug)]
pub struct AllocatorStats {
    pub allocations: usize,
    pub deallocations: usize,
    pub active_allocations: usize,
    pub total_allocated_bytes: usize,
}

impl AllocatorStats {
    pub fn print_summary(&self) {
        println!("Lock-Free Allocator Statistics:");
        println!("  Total allocations: {}", self.allocations);
        println!("  Total deallocations: {}", self.deallocations);
        println!("  Active allocations: {}", self.active_allocations);
        println!("  Total allocated: {} KB", self.total_allocated_bytes / 1024);
    }
}

/// Thread-local memory pools for zero-contention allocation
thread_local! {
    static LOCAL_VULNERABILITY_POOL: MemoryPool<Vec<Vulnerability>> = 
        MemoryPool::new(|| Vec::with_capacity(50), 20)
            .with_reset(|v| v.clear());
    
    static LOCAL_STRING_POOL: MemoryPool<String> = 
        MemoryPool::new(|| String::with_capacity(512), 30)
            .with_reset(|s| s.clear());
}

/// Get thread-local vulnerability pool for zero-contention access
pub fn get_local_vulnerability_pool() -> impl Fn() -> PooledObject<Vec<Vulnerability>> {
    || LOCAL_VULNERABILITY_POOL.with(|pool| pool.get())
}

/// Get thread-local string pool for zero-contention access
pub fn get_local_string_pool() -> impl Fn() -> PooledObject<String> {
    || LOCAL_STRING_POOL.with(|pool| pool.get())
}

/// Global instance of memory pools
static GLOBAL_POOLS: once_cell::sync::Lazy<GlobalMemoryPools> = 
    once_cell::sync::Lazy::new(|| {
        let pools = GlobalMemoryPools::new();
        pools.initialize();
        pools.warm_up();  // Warm up pools for better performance
        pools
    });

/// Get global memory pools instance
pub fn get_global_memory_pools() -> &'static GlobalMemoryPools {
    &GLOBAL_POOLS
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_memory_pool() {
        let pool = MemoryPool::new(|| vec![1, 2, 3], 5);
        
        let mut obj1 = pool.get();
        obj1.push(4);
        assert_eq!(*obj1, vec![1, 2, 3, 4]);
        
        drop(obj1); // Return to pool
        assert_eq!(pool.size(), 1);
        
        let obj2 = pool.get();
        assert_eq!(*obj2, vec![1, 2, 3, 4]); // Reused object
    }

    #[test]
    fn test_vulnerability_pool() {
        let pool = VulnerabilityPool::new(10);
        
        let mut vulns = pool.get();
        vulns.push(Vulnerability {
            id: "test".to_string(),
            title: "Test".to_string(),
            severity: crate::Severity::High,
            category: "test".to_string(),
            description: "Test".to_string(),
            file_path: "test.rs".to_string(),
            line_number: 1,
            column_start: 1,
            column_end: 1,
            source_code: "test".to_string(),
            recommendation: "test".to_string(),
            cwe: None,
            owasp: None,
            references: vec![],
            confidence: 0.8,
        });
        
        assert_eq!(vulns.len(), 1);
        drop(vulns);
        
        // Next allocation should get cleared vector
        let vulns2 = pool.get();
        assert_eq!(vulns2.len(), 0);
    }

    #[test]
    fn test_memory_arena() {
        let arena = MemoryArena::new(1024, 4096);
        
        let ptr1 = arena.allocate(100);
        assert!(ptr1.is_some());
        
        let ptr2 = arena.allocate(200);
        assert!(ptr2.is_some());
        
        assert_eq!(arena.memory_usage(), 300);
        
        // Allocate something too big
        let ptr3 = arena.allocate(2000);
        assert!(ptr3.is_none());
    }

    #[test]
    fn test_string_pool() {
        let pool = StringPool::new(5);
        
        let mut s1 = pool.get_with_content("hello");
        assert_eq!(*s1, "hello");
        
        s1.push_str(" world");
        assert_eq!(*s1, "hello world");
        
        drop(s1);
        
        // Should get cleared string
        let s2 = pool.get();
        assert_eq!(s2.len(), 0);
    }
}