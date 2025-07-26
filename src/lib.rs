pub mod analyzer;
pub mod build_break;
pub mod parsers;
pub mod rules;
pub mod report;
pub mod config;
pub mod error;
pub mod semgrep;
pub mod security_utils;
pub mod pattern_loader;
pub mod cache;
pub mod optimized_reader;
pub mod parallel_scanner;
pub mod benchmark;
pub mod fast_walker;
pub mod ast_analyzer;
pub mod ml_engine;
pub mod ide_integration;
pub mod lsp_server;
pub mod custom_rules;
pub mod compliance;
pub mod visualization;
pub mod performance_optimizer;
#[cfg(feature = "async")]
pub mod async_scanner;
pub mod memory_pool;
pub mod optimized_ast_parser;
pub mod performance_monitor;
pub mod intelligent_cache;
pub mod optimized_regex;
pub mod simd_optimizations;
pub mod cve_pattern_discovery;
pub mod pattern_extraction_engine;
pub mod pattern_validation_system;
pub mod automated_rule_integration;
pub mod cross_language_transfer;
pub mod semantic_similarity_engine;
pub mod transfer_validation_engine;
pub mod business_logic_analyzer;
pub mod performance;
pub mod advanced_caching;
pub mod progress_reporter;
pub mod adaptive_rule_prioritization;
pub mod false_positive_reduction;
pub mod impact_assessment;
pub mod incremental_analysis;

pub use analyzer::Analyzer;
pub use build_break::{BuildBreakAnalyzer, BuildBreakResult};
pub use error::{DevaicError, Result};
pub use report::Report;
pub use config::Config;
pub use ml_engine::{MLEngine, MLModel, MLPrediction};
pub use ide_integration::{IDEIntegration, DevaicLanguageServer};
pub use custom_rules::{CustomRuleEngine, CustomRule};
pub use compliance::{ComplianceEngine, ComplianceReport};
pub use visualization::{VisualizationEngine, SecurityDashboard};
pub use performance_optimizer::{PerformanceOptimizer, WorkloadType};
#[cfg(feature = "async")]
pub use async_scanner::{AsyncFileScanner, StreamingVulnerabilityCollector};
pub use memory_pool::{MemoryPool, get_global_memory_pools};
pub use performance_monitor::PerformanceMonitor;
pub use intelligent_cache::{IntelligentCache, CacheKey, CacheEntry};
pub use optimized_regex::{OptimizedRegexEngine, simd_ops};
pub use simd_optimizations::{SIMDPatternMatcher, CharClass, benchmark_simd_operations};
pub use cve_pattern_discovery::{CVEPatternDiscovery, DiscoveryConfig, CVERecord, ExtractedPattern};
pub use pattern_extraction_engine::{PatternExtractionEngine, ExtractionConfig, CodeAnalysisResult};
pub use pattern_validation_system::{PatternValidationSystem, ValidationConfig, ValidationResult};
pub use automated_rule_integration::{AutomatedRuleIntegration, IntegrationConfig, IntegrationStatus};
pub use cross_language_transfer::{
    CrossLanguageTransfer, TransferConfig, TransferResult, TransferAnalytics,
    TransferConfidenceScore, TransferContext, PatternSimilarityAnalysis, TransferViability
};
pub use semantic_similarity_engine::{
    SemanticSimilarityEngine, SimilarityConfig, SimilarityAnalysisResult, SimilarPattern,
    SimilarityType, VariationDetection, VariationType
};
pub use performance::{
    AIPerformanceOptimizer, AIPerformanceConfig, MemoryProfiler, MemoryProfilerConfig,
    ScalabilityAnalyzer, ScalabilityConfig, EnterpriseBenchmarkSuite, EnterpriseBenchmarkConfig,
};
pub use business_logic_analyzer::{BusinessLogicAnalyzer, BusinessLogicConfig};
pub use advanced_caching::{
    AdvancedCachingSystem, AdvancedCachingConfig, DistributedCache, SmartCacheWarmer,
    CacheCoherencyManager, CacheType, CacheEntry as AdvancedCacheEntry, LocalCache, CacheStatisticsReport
};
pub use false_positive_reduction::{
    FalsePositiveReducer, EnhancedVulnerability, VulnerabilityFeedback, Classification,
    FeedbackContext, RemediationEffort, FPReductionAnalytics
};
pub use impact_assessment::{
    ImpactAssessmentEngine, AssessedVulnerability, CvssAssessment, BusinessImpactAnalysis,
    EnvironmentalImpact, ExploitabilityAssessment, ComplianceImpactAnalysis, OverallRiskAssessment,
    RemediationGuidance, RiskClassification, RemediationPriority, ImpactAssessmentConfig
};
pub use incremental_analysis::{
    IncrementalAnalysisEngine, IncrementalConfig, IncrementalAnalysisResult, IncrementalStatistics,
    FileMetadata, FileDependency, DependencyType, AnalysisType
};

#[derive(Debug, Clone, PartialEq, Eq, Hash, serde::Serialize, serde::Deserialize, Copy)]
pub enum Language {
    C,
    Cpp,
    Python,
    Java,
    Javascript,
    TypeScript,
    Go,
    Php,
    Ruby,
    Kotlin,
    CSharp,
    Bash,
    Scada,
    Cobol,
    Pascal,
    Dart,
    Swift,
    Rust,
    Delphi,
    Wasm,
    Zig,
    V,
    Carbon,
    Nim,
}

impl Language {
    pub fn from_extension(ext: &str) -> Option<Self> {
        match ext.to_lowercase().as_str() {
            "c" | "h" => Some(Language::C),
            "cpp" | "cc" | "cxx" | "c++" | "hpp" | "hxx" | "h++" => Some(Language::Cpp),
            "py" => Some(Language::Python),
            "java" => Some(Language::Java),
            "js" | "jsx" | "mjs" | "cjs" | "svelte" | "astro" => Some(Language::Javascript),
            "ts" | "tsx" => Some(Language::TypeScript),
            "go" => Some(Language::Go),
            "php" | "php3" | "php4" | "php5" | "phtml" => Some(Language::Php),
            "rb" | "ruby" | "rake" | "gemspec" => Some(Language::Ruby),
            "kt" | "kts" => Some(Language::Kotlin),
            "cs" => Some(Language::CSharp),
            "sh" | "bash" | "zsh" | "fish" => Some(Language::Bash),
            "st" | "sl" | "scl" | "fbd" | "ld" | "il" => Some(Language::Scada),
            "cob" | "cbl" | "cpy" | "cobol" => Some(Language::Cobol),
            "pp" | "pascal" | "inc" => Some(Language::Pascal),
            "dart" => Some(Language::Dart),
            "swift" => Some(Language::Swift),
            "rs" => Some(Language::Rust),
            "pas" | "dpr" | "dpk" | "dfm" | "fmx" | "dcu" => Some(Language::Delphi),
            "wasm" | "wat" | "wast" => Some(Language::Wasm),
            "zig" => Some(Language::Zig),
            "v" => Some(Language::V),
            "carbon" => Some(Language::Carbon),
            "nim" | "nims" | "nimble" => Some(Language::Nim),
            _ => None,
        }
    }

    pub fn all() -> Vec<Language> {
        vec![
            Language::C,
            Language::Cpp,
            Language::Python,
            Language::Java,
            Language::Javascript,
            Language::TypeScript,
            Language::Go,
            Language::Php,
            Language::Ruby,
            Language::Kotlin,
            Language::CSharp,
            Language::Bash,
            Language::Scada,
            Language::Cobol,
            Language::Pascal,
            Language::Dart,
            Language::Swift,
            Language::Rust,
            Language::Delphi,
            Language::Wasm,
            Language::Zig,
            Language::V,
            Language::Carbon,
            Language::Nim,
        ]
    }
}

impl std::fmt::Display for Language {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Language::C => write!(f, "c"),
            Language::Cpp => write!(f, "cpp"),
            Language::Python => write!(f, "python"),
            Language::Java => write!(f, "java"),
            Language::Javascript => write!(f, "javascript"),
            Language::TypeScript => write!(f, "typescript"),
            Language::Go => write!(f, "go"),
            Language::Php => write!(f, "php"),
            Language::Ruby => write!(f, "ruby"),
            Language::Kotlin => write!(f, "kotlin"),
            Language::CSharp => write!(f, "csharp"),
            Language::Bash => write!(f, "bash"),
            Language::Scada => write!(f, "scada"),
            Language::Cobol => write!(f, "cobol"),
            Language::Pascal => write!(f, "pascal"),
            Language::Dart => write!(f, "dart"),
            Language::Swift => write!(f, "swift"),
            Language::Rust => write!(f, "rust"),
            Language::Delphi => write!(f, "delphi"),
            Language::Wasm => write!(f, "wasm"),
            Language::Zig => write!(f, "zig"),
            Language::V => write!(f, "v"),
            Language::Carbon => write!(f, "carbon"),
            Language::Nim => write!(f, "nim"),
        }
    }
}

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct Location {
    pub line: usize,
    pub column_start: usize,
    pub file_path: String,
}

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct Vulnerability {
    pub id: String,
    pub title: String,
    pub description: String,
    pub severity: Severity,
    pub category: String,
    pub cwe: Option<String>,
    pub owasp: Option<String>,
    pub file_path: String,
    pub line_number: usize,
    pub column_start: usize,
    pub column_end: usize,
    pub source_code: String,
    pub recommendation: String,
    pub references: Vec<String>,
    pub confidence: f64,
}

#[derive(Debug, Clone, PartialEq, Eq, Hash, serde::Serialize, serde::Deserialize)]
pub enum Severity {
    Critical,
    High,
    Medium,
    Low,
    Info,
}

impl std::fmt::Display for Severity {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Severity::Critical => write!(f, "CRITICAL"),
            Severity::High => write!(f, "HIGH"),
            Severity::Medium => write!(f, "MEDIUM"),
            Severity::Low => write!(f, "LOW"),
            Severity::Info => write!(f, "INFO"),
        }
    }
}