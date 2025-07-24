/// Performance optimization modules for enterprise-scale deployments
/// 
/// This module provides comprehensive performance optimizations specifically
/// designed for AI-powered vulnerability detection at enterprise scale.

pub mod ai_performance_optimizer;
pub mod enterprise_benchmarks;
pub mod memory_profiler;
pub mod scalability_analyzer;

pub use ai_performance_optimizer::{
    AIPerformanceOptimizer, AIPerformanceConfig, AIPerformanceMetrics,
    EmbeddingMemoryPool, AILoadBalancer, WorkerSpecialization,
};

// Re-export commonly used performance types
pub use enterprise_benchmarks::{
    EnterpriseBenchmarkSuite, EnterpriseBenchmarkConfig, BenchmarkResult, 
    PerformanceReport, TestDataGenerator, AIAnalysisType,
};

pub use memory_profiler::{
    MemoryProfiler, MemoryProfilerConfig, MemoryUsageReport, 
    MemoryOptimizationRecommendation, MemoryAlert, MemoryAlertType,
};

pub use scalability_analyzer::{
    ScalabilityAnalyzer, ScalabilityConfig, ScalabilityReport, 
    LoadTestResult, ScalabilityScenario, PerformanceThresholds,
};