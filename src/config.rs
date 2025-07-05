use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use crate::error::{DevaicError, Result};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Config {
    pub rules: RulesConfig,
    pub output: OutputConfig,
    pub analysis: AnalysisConfig,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RulesConfig {
    pub enabled_categories: Vec<String>,
    pub severity_threshold: String,
    pub custom_rules: HashMap<String, bool>,
    pub build_break_rules: BuildBreakRules,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BuildBreakRules {
    pub max_critical: u32,
    pub max_high: u32,
    pub max_medium: u32,
    pub max_low: u32,
    pub fail_on_timeout: bool,
    pub require_all_tests_pass: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct OutputConfig {
    pub format: String,
    pub file: Option<String>,
    pub verbose: bool,
    pub colors: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AnalysisConfig {
    pub max_file_size: usize,
    pub exclude_patterns: Vec<String>,
    pub include_patterns: Vec<String>,
    pub follow_symlinks: bool,
}

impl Default for Config {
    fn default() -> Self {
        Self {
            rules: RulesConfig {
                enabled_categories: vec![
                    "injection".to_string(),
                    "authentication".to_string(),
                    "authorization".to_string(),
                    "cryptographic".to_string(),
                    "deserialization".to_string(),
                    "logging".to_string(),
                    "validation".to_string(),
                    "privacy".to_string(),
                    "security".to_string(),
                    "vulnerability".to_string(),
                    "sanitizer".to_string(),
                    "dependency".to_string(),
                ],
                severity_threshold: "LOW".to_string(),
                custom_rules: HashMap::new(),
                build_break_rules: BuildBreakRules {
                    max_critical: 0,
                    max_high: 2,
                    max_medium: 5,
                    max_low: 10,
                    fail_on_timeout: true,
                    require_all_tests_pass: false,
                },
            },
            output: OutputConfig {
                format: "table".to_string(),
                file: None,
                verbose: false,
                colors: true,
            },
            analysis: AnalysisConfig {
                max_file_size: 10 * 1024 * 1024, // 10MB
                exclude_patterns: vec![
                    "*.git/*".to_string(),
                    "target/*".to_string(),
                    "node_modules/*".to_string(),
                ],
                include_patterns: vec![
                    "*.c".to_string(),
                    "*.h".to_string(),
                    "*.cpp".to_string(),
                    "*.cc".to_string(),
                    "*.cxx".to_string(),
                    "*.c++".to_string(),
                    "*.hpp".to_string(),
                    "*.hxx".to_string(),
                    "*.h++".to_string(),
                    "*.py".to_string(),
                    "*.java".to_string(),
                    "*.js".to_string(),
                    "*.jsx".to_string(),
                    "*.mjs".to_string(),
                    "*.cjs".to_string(),
                    "*.ts".to_string(),
                    "*.tsx".to_string(),
                    "*.go".to_string(),
                    "*.php".to_string(),
                    "*.rb".to_string(),
                    "*.rs".to_string(),
                    "*.kt".to_string(),
                    "*.scala".to_string(),
                    "*.cs".to_string(),
                    "*.yaml".to_string(),
                    "*.yml".to_string(),
                    "*.json".to_string(),
                    "*.tf".to_string(),
                    "*.dockerfile".to_string(),
                    "Dockerfile".to_string(),
                    "*.st".to_string(),
                    "*.sl".to_string(),
                    "*.scl".to_string(),
                    "*.fbd".to_string(),
                    "*.ld".to_string(),
                    "*.il".to_string(),
                ],
                follow_symlinks: false,
            },
        }
    }
}

impl Config {
    pub fn load_from_file(path: &str) -> Result<Self> {
        let content = std::fs::read_to_string(path)?;
        let config: Config = toml::from_str(&content)
            .map_err(|e| DevaicError::Config(format!("Failed to parse config: {}", e)))?;
        Ok(config)
    }

    pub fn save_to_file(&self, path: &str) -> Result<()> {
        let content = toml::to_string_pretty(self)
            .map_err(|e| DevaicError::Config(format!("Failed to serialize config: {}", e)))?;
        std::fs::write(path, content)?;
        Ok(())
    }
}