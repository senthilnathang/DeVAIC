/// Real-time Progress Reporting System
/// 
/// Provides real-time feedback during vulnerability analysis similar to Semgrep,
/// showing computation progress, statistics, and results as they're calculated.

use std::collections::HashMap;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};
use tokio::sync::broadcast;
use serde::{Deserialize, Serialize};
use crate::{Vulnerability, Severity};

/// Helper function for serde default
fn duration_max() -> Duration {
    Duration::MAX
}

/// Progress event types
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum ProgressEvent {
    /// Analysis started
    AnalysisStarted {
        total_files: usize,
        total_rules: usize,
        #[serde(skip, default = "std::time::Instant::now")]
        start_time: Instant,
    },
    /// File analysis started
    FileStarted {
        file_path: String,
        file_size: u64,
        file_index: usize,
    },
    /// File analysis completed
    FileCompleted {
        file_path: String,
        vulnerabilities_found: usize,
        #[serde(skip, default)]
        processing_time: Duration,
        file_index: usize,
    },
    /// Rule execution progress
    RuleProgress {
        rule_name: String,
        files_processed: usize,
        matches_found: usize,
    },
    /// Vulnerability found
    VulnerabilityFound {
        vulnerability: Vulnerability,
        file_path: String,
        #[serde(skip, default)]
        computation_time: Duration,
    },
    /// Statistics update
    StatsUpdate {
        stats: AnalysisStatistics,
    },
    /// Performance metrics
    PerformanceMetrics {
        metrics: PerformanceMetrics,
    },
    /// Analysis completed
    AnalysisCompleted {
        total_vulnerabilities: usize,
        #[serde(skip, default)]
        total_time: Duration,
        final_stats: AnalysisStatistics,
    },
    /// Error occurred
    Error {
        message: String,
        file_path: Option<String>,
    },
}

/// Real-time analysis statistics
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AnalysisStatistics {
    pub files_processed: usize,
    pub files_remaining: usize,
    pub total_files: usize,
    pub vulnerabilities_by_severity: HashMap<Severity, usize>,
    pub vulnerabilities_by_category: HashMap<String, usize>,
    pub rules_executed: usize,
    pub processing_rate_fps: f64, // Files per second
    #[serde(skip, default)]
    pub estimated_time_remaining: Duration,
    pub memory_usage_mb: f64,
    pub cpu_usage_percent: f64,
}

/// Performance metrics
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PerformanceMetrics {
    #[serde(skip, default)]
    pub avg_file_processing_time: Duration,
    #[serde(skip, default = "duration_max")]
    pub fastest_file_time: Duration,
    #[serde(skip, default)]
    pub slowest_file_time: Duration,
    pub throughput_mb_per_sec: f64,
    pub cache_hit_rate: f64,
    pub pattern_matching_efficiency: f64,
    pub memory_peak_mb: f64,
    pub cpu_cores_utilized: usize,
}

/// Progress reporter for real-time analysis feedback
pub struct ProgressReporter {
    sender: broadcast::Sender<ProgressEvent>,
    stats: Arc<Mutex<AnalysisStatistics>>,
    metrics: Arc<Mutex<PerformanceMetrics>>,
    start_time: Arc<Mutex<Option<Instant>>>,
    file_times: Arc<Mutex<Vec<Duration>>>,
    show_progress_bar: bool,
    show_detailed_stats: bool,
    verbose_mode: bool,
}

impl ProgressReporter {
    /// Create a new progress reporter
    pub fn new(show_progress_bar: bool, show_detailed_stats: bool, verbose_mode: bool) -> Self {
        let (sender, _) = broadcast::channel(1000);
        
        let stats = AnalysisStatistics {
            files_processed: 0,
            files_remaining: 0,
            total_files: 0,
            vulnerabilities_by_severity: HashMap::new(),
            vulnerabilities_by_category: HashMap::new(),
            rules_executed: 0,
            processing_rate_fps: 0.0,
            estimated_time_remaining: Duration::ZERO,
            memory_usage_mb: 0.0,
            cpu_usage_percent: 0.0,
        };

        let metrics = PerformanceMetrics {
            avg_file_processing_time: Duration::ZERO,
            fastest_file_time: Duration::MAX,
            slowest_file_time: Duration::ZERO,
            throughput_mb_per_sec: 0.0,
            cache_hit_rate: 0.0,
            pattern_matching_efficiency: 0.0,
            memory_peak_mb: 0.0,
            cpu_cores_utilized: 0,
        };

        Self {
            sender,
            stats: Arc::new(Mutex::new(stats)),
            metrics: Arc::new(Mutex::new(metrics)),
            start_time: Arc::new(Mutex::new(None)),
            file_times: Arc::new(Mutex::new(Vec::new())),
            show_progress_bar,
            show_detailed_stats,
            verbose_mode,
        }
    }

    /// Subscribe to progress events
    pub fn subscribe(&self) -> broadcast::Receiver<ProgressEvent> {
        self.sender.subscribe()
    }

    /// Start analysis reporting
    pub fn start_analysis(&self, total_files: usize, total_rules: usize) {
        let now = Instant::now();
        {
            let mut start_time = self.start_time.lock().unwrap();
            *start_time = Some(now);
        }
        
        {
            let mut stats = self.stats.lock().unwrap();
            stats.total_files = total_files;
            stats.files_remaining = total_files;
        }

        let event = ProgressEvent::AnalysisStarted {
            total_files,
            total_rules,
            start_time: now,
        };

        let _ = self.sender.send(event.clone());
        self.print_analysis_start(&event);
    }

    /// Report file analysis start
    pub fn file_started(&self, file_path: String, file_size: u64, file_index: usize) {
        let event = ProgressEvent::FileStarted {
            file_path: file_path.clone(),
            file_size,
            file_index,
        };

        let _ = self.sender.send(event.clone());
        
        if self.verbose_mode {
            self.print_file_start(&event);
        }
    }

    /// Report file analysis completion
    pub fn file_completed(&self, file_path: String, vulnerabilities_found: usize, processing_time: Duration, file_index: usize) {
        // Update file processing times
        {
            let mut times = self.file_times.lock().unwrap();
            times.push(processing_time);
        }

        // Update statistics
        {
            let mut stats = self.stats.lock().unwrap();
            stats.files_processed += 1;
            stats.files_remaining = stats.total_files.saturating_sub(stats.files_processed);
            
            // Calculate processing rate
            let start_time = self.start_time.lock().unwrap();
            if let Some(start_time) = *start_time {
                let elapsed = start_time.elapsed();
                stats.processing_rate_fps = stats.files_processed as f64 / elapsed.as_secs_f64();
                
                // Estimate remaining time
                if stats.processing_rate_fps > 0.0 {
                    let remaining_seconds = stats.files_remaining as f64 / stats.processing_rate_fps;
                    stats.estimated_time_remaining = Duration::from_secs_f64(remaining_seconds);
                }
            }
        }

        // Update performance metrics
        {
            let mut metrics = self.metrics.lock().unwrap();
            let times = self.file_times.lock().unwrap();
            
            if !times.is_empty() {
                let total: Duration = times.iter().sum();
                metrics.avg_file_processing_time = total / times.len() as u32;
                metrics.fastest_file_time = *times.iter().min().unwrap_or(&Duration::ZERO);
                metrics.slowest_file_time = *times.iter().max().unwrap_or(&Duration::ZERO);
            }
        }

        let event = ProgressEvent::FileCompleted {
            file_path: file_path.clone(),
            vulnerabilities_found,
            processing_time,
            file_index,
        };

        let _ = self.sender.send(event.clone());
        self.print_file_completion(&event);
        
        // Send stats update
        self.send_stats_update();
    }

    /// Report vulnerability found
    pub fn vulnerability_found(&self, vulnerability: Vulnerability, file_path: String, computation_time: Duration) {
        // Update vulnerability statistics
        {
            let mut stats = self.stats.lock().unwrap();
            *stats.vulnerabilities_by_severity.entry(vulnerability.severity.clone()).or_insert(0) += 1;
            *stats.vulnerabilities_by_category.entry(vulnerability.category.clone()).or_insert(0) += 1;
        }

        let event = ProgressEvent::VulnerabilityFound {
            vulnerability: vulnerability.clone(),
            file_path: file_path.clone(),
            computation_time,
        };

        let _ = self.sender.send(event.clone());
        self.print_vulnerability_found(&event);
    }

    /// Report rule execution progress
    pub fn rule_progress(&self, rule_name: String, files_processed: usize, matches_found: usize) {
        {
            let mut stats = self.stats.lock().unwrap();
            stats.rules_executed += 1;
        }

        let event = ProgressEvent::RuleProgress {
            rule_name: rule_name.clone(),
            files_processed,
            matches_found,
        };

        let _ = self.sender.send(event.clone());
        
        if self.verbose_mode {
            self.print_rule_progress(&event);
        }
    }

    /// Complete analysis reporting
    pub fn complete_analysis(&self, total_vulnerabilities: usize) {
        let start_time = *self.start_time.lock().unwrap();
        let total_time = start_time.map(|t| t.elapsed()).unwrap_or(Duration::ZERO);
        let final_stats = self.stats.lock().unwrap().clone();

        let event = ProgressEvent::AnalysisCompleted {
            total_vulnerabilities,
            total_time,
            final_stats: final_stats.clone(),
        };

        let _ = self.sender.send(event.clone());
        self.print_analysis_completion(&event);
    }

    /// Send statistics update
    fn send_stats_update(&self) {
        let stats = self.stats.lock().unwrap().clone();
        let event = ProgressEvent::StatsUpdate { stats: stats.clone() };
        let _ = self.sender.send(event);
        
        if self.show_detailed_stats {
            self.print_stats_update(&stats);
        }
    }

    /// Print analysis start
    fn print_analysis_start(&self, event: &ProgressEvent) {
        if let ProgressEvent::AnalysisStarted { total_files, total_rules, .. } = event {
            println!("🔍 Starting DeVAIC Analysis");
            println!("════════════════════════════");
            println!("📁 Files to analyze: {}", total_files);
            println!("📋 Rules to execute: {}", total_rules);
            println!("⏰ Started at: {}", std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap().as_secs());
            println!();
        }
    }

    /// Print file start
    fn print_file_start(&self, event: &ProgressEvent) {
        if let ProgressEvent::FileStarted { file_path, file_size, file_index } = event {
            println!("🔎 [{:>4}] Analyzing: {} ({} bytes)", file_index + 1, file_path, file_size);
        }
    }

    /// Print file completion
    fn print_file_completion(&self, event: &ProgressEvent) {
        if let ProgressEvent::FileCompleted { file_path, vulnerabilities_found, processing_time, file_index } = event {
            let status_icon = if *vulnerabilities_found > 0 { "⚠️" } else { "✅" };
            let filename = std::path::Path::new(file_path).file_name()
                .and_then(|n| n.to_str())
                .unwrap_or(file_path);
            
            if self.show_progress_bar {
                let stats = self.stats.lock().unwrap();
                let progress = (stats.files_processed as f64 / stats.total_files as f64 * 100.0) as usize;
                let bar_width = 30;
                let filled = (progress * bar_width / 100).min(bar_width);
                let bar = "█".repeat(filled) + &"░".repeat(bar_width - filled);
                
                print!("\r{} [{:>3}%] [{}] {:>4}/{} | {} ({} vulns) [{:.2}ms]", 
                    status_icon, progress, bar, stats.files_processed, stats.total_files, 
                    filename, vulnerabilities_found, processing_time.as_millis());
                
                if stats.files_processed == stats.total_files {
                    println!(); // New line after completion
                }
            } else {
                println!("{} [{:>4}] {} ({} vulnerabilities) - {:.2}ms", 
                    status_icon, file_index + 1, filename, vulnerabilities_found, processing_time.as_millis());
            }
            
            std::io::Write::flush(&mut std::io::stdout()).unwrap();
        }
    }

    /// Print vulnerability found
    fn print_vulnerability_found(&self, event: &ProgressEvent) {
        if let ProgressEvent::VulnerabilityFound { vulnerability, file_path, computation_time } = event {
            let severity_icon = match vulnerability.severity {
                Severity::Critical => "🔴",
                Severity::High => "🟠", 
                Severity::Medium => "🟡",
                Severity::Low => "🔵",
                Severity::Info => "⚪",
            };
            
            if self.verbose_mode {
                println!("  {} {} [{}:{}] {} ({:.2}ms)", 
                    severity_icon, 
                    vulnerability.severity,
                    std::path::Path::new(file_path).file_name().unwrap_or_default().to_str().unwrap_or(""),
                    vulnerability.line_number,
                    vulnerability.title,
                    computation_time.as_millis()
                );
            }
        }
    }

    /// Print rule progress
    fn print_rule_progress(&self, event: &ProgressEvent) {
        if let ProgressEvent::RuleProgress { rule_name, files_processed, matches_found } = event {
            println!("📏 Rule: {} | Files: {} | Matches: {}", rule_name, files_processed, matches_found);
        }
    }

    /// Print statistics update
    fn print_stats_update(&self, stats: &AnalysisStatistics) {
        println!("\n📊 Real-time Statistics:");
        println!("   Progress: {}/{} files ({:.1}%)", 
            stats.files_processed, 
            stats.total_files,
            (stats.files_processed as f64 / stats.total_files as f64 * 100.0)
        );
        println!("   Processing rate: {:.1} files/sec", stats.processing_rate_fps);
        println!("   ETA: {:.1}s", stats.estimated_time_remaining.as_secs_f64());
        
        if !stats.vulnerabilities_by_severity.is_empty() {
            println!("   Vulnerabilities by severity:");
            for (severity, count) in &stats.vulnerabilities_by_severity {
                let icon = match severity {
                    Severity::Critical => "🔴",
                    Severity::High => "🟠", 
                    Severity::Medium => "🟡",
                    Severity::Low => "🔵",
                    Severity::Info => "⚪",
                };
                println!("     {} {}: {}", icon, severity, count);
            }
        }
        println!();
    }

    /// Print analysis completion
    fn print_analysis_completion(&self, event: &ProgressEvent) {
        if let ProgressEvent::AnalysisCompleted { total_vulnerabilities, total_time, final_stats } = event {
            println!("\n🎉 Analysis Complete!");
            println!("═══════════════════════");
            println!("⏱️  Total time: {:.2}s", total_time.as_secs_f64());
            println!("📁 Files analyzed: {}", final_stats.total_files);
            println!("🐛 Vulnerabilities found: {}", total_vulnerabilities);
            println!("📈 Average rate: {:.1} files/sec", final_stats.processing_rate_fps);
            
            if !final_stats.vulnerabilities_by_severity.is_empty() {
                println!("\n📊 Final Results:");
                for (severity, count) in &final_stats.vulnerabilities_by_severity {
                    let icon = match severity {
                        Severity::Critical => "🔴",
                        Severity::High => "🟠", 
                        Severity::Medium => "🟡",
                        Severity::Low => "🔵",
                        Severity::Info => "⚪",
                    };
                    println!("   {} {}: {} vulnerabilities", icon, severity, count);
                }
            }

            // Performance summary
            let metrics = self.metrics.lock().unwrap();
            println!("\n⚡ Performance Summary:");
            println!("   Avg file time: {:.2}ms", metrics.avg_file_processing_time.as_millis());
            println!("   Fastest file: {:.2}ms", metrics.fastest_file_time.as_millis());
            println!("   Slowest file: {:.2}ms", metrics.slowest_file_time.as_millis());
            if metrics.cache_hit_rate > 0.0 {
                println!("   Cache hit rate: {:.1}%", metrics.cache_hit_rate * 100.0);
            }
        }
    }
}

impl Default for AnalysisStatistics {
    fn default() -> Self {
        Self {
            files_processed: 0,
            files_remaining: 0,
            total_files: 0,
            vulnerabilities_by_severity: HashMap::new(),
            vulnerabilities_by_category: HashMap::new(),
            rules_executed: 0,
            processing_rate_fps: 0.0,
            estimated_time_remaining: Duration::ZERO,
            memory_usage_mb: 0.0,
            cpu_usage_percent: 0.0,
        }
    }
}

impl Default for PerformanceMetrics {
    fn default() -> Self {
        Self {
            avg_file_processing_time: Duration::ZERO,
            fastest_file_time: Duration::MAX,
            slowest_file_time: Duration::ZERO,
            throughput_mb_per_sec: 0.0,
            cache_hit_rate: 0.0,
            pattern_matching_efficiency: 0.0,
            memory_peak_mb: 0.0,
            cpu_cores_utilized: 0,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_progress_reporter_creation() {
        let reporter = ProgressReporter::new(true, true, false);
        let mut receiver = reporter.subscribe();
        
        // Should be able to subscribe to events
        assert!(receiver.try_recv().is_err()); // No events yet
    }

    #[tokio::test]
    async fn test_analysis_progress_flow() {
        let mut reporter = ProgressReporter::new(false, false, false);
        let mut receiver = reporter.subscribe();
        
        // Start analysis
        reporter.start_analysis(5, 10);
        
        let event = receiver.recv().await.unwrap();
        match event {
            ProgressEvent::AnalysisStarted { total_files, total_rules, .. } => {
                assert_eq!(total_files, 5);
                assert_eq!(total_rules, 10);
            }
            _ => panic!("Expected AnalysisStarted event"),
        }
        
        // Complete a file
        reporter.file_completed("test.rs".to_string(), 2, Duration::from_millis(100), 0);
        
        let event = receiver.recv().await.unwrap();
        match event {
            ProgressEvent::FileCompleted { vulnerabilities_found, .. } => {
                assert_eq!(vulnerabilities_found, 2);
            }
            _ => panic!("Expected FileCompleted event"),
        }
    }

    #[test]
    fn test_statistics_calculation() {
        let mut stats = AnalysisStatistics::default();
        stats.total_files = 100;
        stats.files_processed = 25;
        stats.files_remaining = 75;
        
        assert_eq!(stats.files_processed as f64 / stats.total_files as f64, 0.25);
    }
}