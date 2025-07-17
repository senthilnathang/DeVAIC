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

pub use analyzer::Analyzer;
pub use build_break::{BuildBreakAnalyzer, BuildBreakResult};
pub use error::{DevaicError, Result};
pub use report::Report;
pub use config::Config;

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
}

impl Language {
    pub fn from_extension(ext: &str) -> Option<Self> {
        match ext.to_lowercase().as_str() {
            "c" | "h" => Some(Language::C),
            "cpp" | "cc" | "cxx" | "c++" | "hpp" | "hxx" | "h++" => Some(Language::Cpp),
            "py" => Some(Language::Python),
            "java" => Some(Language::Java),
            "js" | "jsx" | "mjs" | "cjs" => Some(Language::Javascript),
            "ts" | "tsx" => Some(Language::TypeScript),
            "go" => Some(Language::Go),
            "php" | "php3" | "php4" | "php5" | "phtml" => Some(Language::Php),
            "rb" | "ruby" | "rake" | "gemspec" => Some(Language::Ruby),
            "kt" | "kts" => Some(Language::Kotlin),
            "cs" => Some(Language::CSharp),
            "sh" | "bash" | "zsh" | "fish" => Some(Language::Bash),
            "st" | "sl" | "scl" | "fbd" | "ld" | "il" => Some(Language::Scada),
            "cob" | "cbl" | "cpy" | "cobol" => Some(Language::Cobol),
            "pas" | "pp" | "pascal" | "inc" => Some(Language::Pascal),
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