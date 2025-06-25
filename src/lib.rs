pub mod analyzer;
pub mod parsers;
pub mod rules;
pub mod report;
pub mod config;
pub mod error;
pub mod semgrep;

pub use analyzer::Analyzer;
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
    Scada,
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
            "st" | "sl" | "scl" | "fbd" | "ld" | "il" => Some(Language::Scada),
            _ => None,
        }
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
            Language::Scada => write!(f, "scada"),
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

#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
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