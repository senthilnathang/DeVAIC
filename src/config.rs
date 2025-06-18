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
                ],
                severity_threshold: "LOW".to_string(),
                custom_rules: HashMap::new(),
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
                    "*.py".to_string(),
                    "*.st".to_string(),
                    "*.scl".to_string(),
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