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
        }
    }
}

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct Vulnerability {
    pub id: String,
    pub cwe: Option<String>,
    pub vulnerability_type: String,
    pub severity: Severity,
    pub category: String,
    pub description: String,
    pub file_path: String,
    pub line_number: usize,
    pub column: usize,
    pub source_code: String,
    pub recommendation: String,
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