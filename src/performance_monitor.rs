use std::collections::{HashMap, VecDeque};
use std::sync::Arc;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};
use parking_lot::RwLock;
use serde::{Serialize, Deserialize};

/// Comprehensive performance monitoring system
#[derive(Debug)]
pub struct PerformanceMonitor {
    metrics: Arc<RwLock<HashMap<String, MetricSeries>>>,
    benchmarks: Arc<RwLock<HashMap<String, BenchmarkResult>>>,
    system_metrics: Arc<RwLock<SystemMetrics>>,
    config: MonitorConfig,
    start_time: Instant,
}

#[derive(Debug, Clone)]
pub struct MonitorConfig {
    pub max_samples_per_metric: usize,
    pub enable_system_monitoring: bool,
    pub enable_memory_tracking: bool,
    pub enable_cpu_tracking: bool,
    pub sampling_interval_ms: u64,
    pub export_interval_seconds: u64,
}

impl Default for MonitorConfig {
    fn default() -> Self {
        Self {
            max_samples_per_metric: 1000,
            enable_system_monitoring: true,
            enable_memory_tracking: true,
            enable_cpu_tracking: true,
            sampling_interval_ms: 100,
            export_interval_seconds: 60,
        }
    }
}

/// Time-series metric data
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MetricSeries {
    pub name: String,
    pub unit: String,
    pub samples: VecDeque<MetricSample>,
    pub statistics: MetricStatistics,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MetricSample {
    pub timestamp: u64,
    pub value: f64,
    pub tags: HashMap<String, String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MetricStatistics {
    pub count: usize,
    pub sum: f64,
    pub min: f64,
    pub max: f64,
    pub mean: f64,
    pub std_dev: f64,
    pub percentiles: HashMap<String, f64>, // P50, P90, P95, P99
}

/// System-level metrics
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct SystemMetrics {
    pub memory_usage_mb: f64,
    pub cpu_usage_percent: f64,
    pub disk_io_read_mb: f64,
    pub disk_io_write_mb: f64,
    pub network_rx_mb: f64,
    pub network_tx_mb: f64,
    pub thread_count: usize,
    pub open_file_descriptors: usize,
    pub last_updated: u64,
}

/// Benchmark result with detailed timing information
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BenchmarkResult {
    pub name: String,
    pub iterations: usize,
    pub total_duration_ms: f64,
    pub avg_duration_ms: f64,
    pub min_duration_ms: f64,
    pub max_duration_ms: f64,
    pub std_deviation_ms: f64,
    pub throughput_ops_per_sec: f64,
    pub memory_used_mb: f64,
    pub timestamp: u64,
    pub tags: HashMap<String, String>,
}

impl PerformanceMonitor {
    pub fn new(config: MonitorConfig) -> Self {
        let monitor = Self {
            metrics: Arc::new(RwLock::new(HashMap::new())),
            benchmarks: Arc::new(RwLock::new(HashMap::new())),
            system_metrics: Arc::new(RwLock::new(SystemMetrics::default())),
            config,
            start_time: Instant::now(),
        };

        // Start background system monitoring if enabled
        if monitor.config.enable_system_monitoring {
            monitor.start_system_monitoring();
        }

        monitor
    }

    /// Record a metric value with optional tags
    pub fn record_metric(&self, name: &str, value: f64, unit: &str, tags: Option<HashMap<String, String>>) {
        let timestamp = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or(Duration::ZERO)
            .as_millis() as u64;

        let sample = MetricSample {
            timestamp,
            value,
            tags: tags.unwrap_or_default(),
        };

        let mut metrics = self.metrics.write();
        let metric_series = metrics.entry(name.to_string()).or_insert_with(|| {
            MetricSeries {
                name: name.to_string(),
                unit: unit.to_string(),
                samples: VecDeque::new(),
                statistics: MetricStatistics {
                    count: 0,
                    sum: 0.0,
                    min: f64::INFINITY,
                    max: f64::NEG_INFINITY,
                    mean: 0.0,
                    std_dev: 0.0,
                    percentiles: HashMap::new(),
                },
            }
        });

        // Add sample and maintain size limit
        metric_series.samples.push_back(sample);
        if metric_series.samples.len() > self.config.max_samples_per_metric {
            metric_series.samples.pop_front();
        }

        // Update statistics
        self.update_statistics(metric_series);
    }

    /// Record timing metric with automatic duration calculation
    pub fn time_operation<F, R>(&self, operation_name: &str, operation: F) -> (R, Duration)
    where
        F: FnOnce() -> R,
    {
        let start = Instant::now();
        let result = operation();
        let duration = start.elapsed();

        let mut tags = std::collections::HashMap::new();
        tags.insert("operation".to_string(), operation_name.to_string());
        
        self.record_metric(
            &format!("{}_duration_ms", operation_name),
            duration.as_millis() as f64,
            "milliseconds",
            Some(tags),
        );

        (result, duration)
    }

    /// Benchmark an operation with multiple iterations
    pub fn benchmark<F>(&self, name: &str, iterations: usize, operation: F) -> BenchmarkResult
    where
        F: Fn() -> (),
    {
        let mut durations = Vec::with_capacity(iterations);
        let start_memory = self.get_current_memory_usage();
        let total_start = Instant::now();

        // Run benchmark iterations
        for _ in 0..iterations {
            let iter_start = Instant::now();
            operation();
            let iter_duration = iter_start.elapsed();
            durations.push(iter_duration.as_millis() as f64);
        }

        let total_duration = total_start.elapsed();
        let end_memory = self.get_current_memory_usage();

        // Calculate statistics
        let total_duration_ms = total_duration.as_millis() as f64;
        let avg_duration_ms = durations.iter().sum::<f64>() / iterations as f64;
        let min_duration_ms = durations.iter().fold(f64::INFINITY, |a, &b| a.min(b));
        let max_duration_ms = durations.iter().fold(f64::NEG_INFINITY, |a, &b| a.max(b));
        
        let variance = durations.iter()
            .map(|&x| (x - avg_duration_ms).powi(2))
            .sum::<f64>() / iterations as f64;
        let std_deviation_ms = variance.sqrt();

        let throughput_ops_per_sec = if total_duration_ms > 0.0 {
            (iterations as f64 * 1000.0) / total_duration_ms
        } else {
            0.0
        };

        let result = BenchmarkResult {
            name: name.to_string(),
            iterations,
            total_duration_ms,
            avg_duration_ms,
            min_duration_ms,
            max_duration_ms,
            std_deviation_ms,
            throughput_ops_per_sec,
            memory_used_mb: end_memory - start_memory,
            timestamp: SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap_or(Duration::ZERO)
                .as_secs(),
            tags: HashMap::new(),
        };

        // Store benchmark result
        self.benchmarks.write().insert(name.to_string(), result.clone());

        result
    }

    /// Get metric statistics
    pub fn get_metric(&self, name: &str) -> Option<MetricSeries> {
        self.metrics.read().get(name).cloned()
    }

    /// Get all metrics
    pub fn get_all_metrics(&self) -> HashMap<String, MetricSeries> {
        self.metrics.read().clone()
    }

    /// Get benchmark result
    pub fn get_benchmark(&self, name: &str) -> Option<BenchmarkResult> {
        self.benchmarks.read().get(name).cloned()
    }

    /// Get all benchmark results
    pub fn get_all_benchmarks(&self) -> HashMap<String, BenchmarkResult> {
        self.benchmarks.read().clone()
    }

    /// Get system metrics
    pub fn get_system_metrics(&self) -> SystemMetrics {
        self.system_metrics.read().clone()
    }

    /// Generate performance report
    pub fn generate_report(&self) -> PerformanceReport {
        let metrics = self.get_all_metrics();
        let benchmarks = self.get_all_benchmarks();
        let system_metrics = self.get_system_metrics();
        let uptime_seconds = self.start_time.elapsed().as_secs();

        PerformanceReport {
            timestamp: SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap_or(Duration::ZERO)
                .as_secs(),
            uptime_seconds,
            metrics,
            benchmarks,
            system_metrics,
            summary: self.generate_summary(),
        }
    }

    /// Export metrics to JSON format
    pub fn export_metrics_json(&self) -> String {
        let report = self.generate_report();
        serde_json::to_string_pretty(&report).unwrap_or_else(|_| "{}".to_string())
    }

    /// Clear all metrics and benchmarks
    pub fn clear_all(&self) {
        self.metrics.write().clear();
        self.benchmarks.write().clear();
    }

    /// Update metric statistics
    fn update_statistics(&self, metric_series: &mut MetricSeries) {
        let values: Vec<f64> = metric_series.samples.iter().map(|s| s.value).collect();
        
        if values.is_empty() {
            return;
        }

        metric_series.statistics.count = values.len();
        metric_series.statistics.sum = values.iter().sum();
        metric_series.statistics.min = values.iter().fold(f64::INFINITY, |a, &b| a.min(b));
        metric_series.statistics.max = values.iter().fold(f64::NEG_INFINITY, |a, &b| a.max(b));
        metric_series.statistics.mean = metric_series.statistics.sum / values.len() as f64;

        // Calculate standard deviation
        let variance = values.iter()
            .map(|&x| (x - metric_series.statistics.mean).powi(2))
            .sum::<f64>() / values.len() as f64;
        metric_series.statistics.std_dev = variance.sqrt();

        // Calculate percentiles
        let mut sorted_values = values.clone();
        sorted_values.sort_by(|a, b| a.partial_cmp(b).unwrap_or(std::cmp::Ordering::Equal));
        
        let _len = sorted_values.len();
        metric_series.statistics.percentiles.insert("P50".to_string(), 
            self.percentile(&sorted_values, 0.5));
        metric_series.statistics.percentiles.insert("P90".to_string(), 
            self.percentile(&sorted_values, 0.9));
        metric_series.statistics.percentiles.insert("P95".to_string(), 
            self.percentile(&sorted_values, 0.95));
        metric_series.statistics.percentiles.insert("P99".to_string(), 
            self.percentile(&sorted_values, 0.99));
    }

    /// Calculate percentile value
    fn percentile(&self, sorted_values: &[f64], p: f64) -> f64 {
        if sorted_values.is_empty() {
            return 0.0;
        }
        
        let index = (p * (sorted_values.len() - 1) as f64).round() as usize;
        sorted_values[index.min(sorted_values.len() - 1)]
    }

    /// Get current memory usage (simplified implementation)
    fn get_current_memory_usage(&self) -> f64 {
        // In a real implementation, this would use system APIs
        // For now, return a placeholder value
        0.0
    }

    /// Start background system monitoring
    fn start_system_monitoring(&self) {
        if !self.config.enable_system_monitoring {
            return;
        }

        let system_metrics = Arc::clone(&self.system_metrics);
        let interval = Duration::from_millis(self.config.sampling_interval_ms);

        std::thread::spawn(move || {
            loop {
                std::thread::sleep(interval);
                
                // Update system metrics (simplified implementation)
                let mut metrics = system_metrics.write();
                metrics.last_updated = SystemTime::now()
                    .duration_since(UNIX_EPOCH)
                    .unwrap_or(Duration::ZERO)
                    .as_secs();
                
                // In a real implementation, these would use system APIs
                metrics.memory_usage_mb = 100.0; // Placeholder
                metrics.cpu_usage_percent = 25.0; // Placeholder
                metrics.thread_count = std::thread::available_parallelism()
                    .map(|n| n.get())
                    .unwrap_or(4);
            }
        });
    }

    /// Generate summary statistics
    fn generate_summary(&self) -> PerformanceSummary {
        let metrics = self.metrics.read();
        let benchmarks = self.benchmarks.read();
        
        let total_metrics = metrics.len();
        let total_benchmarks = benchmarks.len();
        
        let avg_throughput = benchmarks.values()
            .map(|b| b.throughput_ops_per_sec)
            .sum::<f64>() / benchmarks.len().max(1) as f64;

        PerformanceSummary {
            total_metrics,
            total_benchmarks,
            avg_throughput_ops_per_sec: avg_throughput,
            uptime_seconds: self.start_time.elapsed().as_secs(),
        }
    }
}

/// Performance report containing all metrics and benchmarks
#[derive(Debug, Serialize, Deserialize)]
pub struct PerformanceReport {
    pub timestamp: u64,
    pub uptime_seconds: u64,
    pub metrics: HashMap<String, MetricSeries>,
    pub benchmarks: HashMap<String, BenchmarkResult>,
    pub system_metrics: SystemMetrics,
    pub summary: PerformanceSummary,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct PerformanceSummary {
    pub total_metrics: usize,
    pub total_benchmarks: usize,
    pub avg_throughput_ops_per_sec: f64,
    pub uptime_seconds: u64,
}

/// Macro for easy metric recording
#[macro_export]
macro_rules! record_metric {
    ($monitor:expr, $name:expr, $value:expr, $unit:expr) => {
        $monitor.record_metric($name, $value, $unit, None)
    };
    ($monitor:expr, $name:expr, $value:expr, $unit:expr, $tags:expr) => {
        $monitor.record_metric($name, $value, $unit, Some($tags))
    };
}

/// Macro for timing operations
#[macro_export]
macro_rules! time_it {
    ($monitor:expr, $name:expr, $operation:expr) => {
        $monitor.time_operation($name, || $operation)
    };
}

// Helper macro for creating HashMap
#[macro_export]
macro_rules! hashmap {
    ($( $key: expr => $val: expr ),*) => {{
         let mut map = std::collections::HashMap::new();
         $( map.insert($key, $val); )*
         map
    }}
}

// Make these available for use in the crate
pub use record_metric;
pub use time_it;
pub use hashmap;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_performance_monitor() {
        let monitor = PerformanceMonitor::new(MonitorConfig::default());
        
        // Record some metrics
        monitor.record_metric("test_metric", 42.0, "units", None);
        monitor.record_metric("test_metric", 43.0, "units", None);
        monitor.record_metric("test_metric", 41.0, "units", None);
        
        let metric = monitor.get_metric("test_metric").unwrap();
        assert_eq!(metric.samples.len(), 3);
        assert_eq!(metric.statistics.count, 3);
        assert_eq!(metric.statistics.mean, 42.0);
    }

    #[test]
    fn test_benchmark() {
        let monitor = PerformanceMonitor::new(MonitorConfig::default());
        
        let result = monitor.benchmark("test_operation", 10, || {
            // Simulate some work
            std::thread::sleep(Duration::from_millis(1));
        });
        
        assert_eq!(result.iterations, 10);
        assert!(result.avg_duration_ms > 0.0);
        assert!(result.throughput_ops_per_sec > 0.0);
    }

    #[test]
    fn test_timing_macro() {
        let monitor = PerformanceMonitor::new(MonitorConfig::default());
        
        let (result, duration) = time_it!(monitor, "test_op", {
            // Add a small delay to ensure measurable time
            std::thread::sleep(std::time::Duration::from_nanos(1));
            42
        });
        
        assert_eq!(result, 42);
        assert!(duration.as_nanos() > 0);
        
        // Check that metric was recorded
        let metric = monitor.get_metric("test_op_duration_ms").unwrap();
        assert_eq!(metric.samples.len(), 1);
    }
}