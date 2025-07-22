// Stub implementation for IDE integration when feature is disabled

use crate::{Vulnerability, Result};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct Url(pub String);

#[derive(Debug, Clone)]
pub struct Client;

#[derive(Debug)]
pub struct Diagnostic;

pub struct DevaicLanguageServer {
    pub client: Client,
    pub document_cache: HashMap<Url, String>,
    pub vulnerability_cache: HashMap<Url, Vec<Vulnerability>>,
}

impl DevaicLanguageServer {
    pub fn new(client: Client) -> Self {
        Self {
            client,
            document_cache: HashMap::new(),
            vulnerability_cache: HashMap::new(),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct IDEPlugin {
    pub name: String,
    pub version: String,
    pub supported_ides: Vec<String>,
    pub language_support: Vec<crate::Language>,
    pub real_time_analysis: bool,
    pub auto_fix_suggestions: bool,
}

pub struct IDEIntegration;

impl IDEIntegration {
    pub fn create_vscode_extension() -> VSCodeExtension {
        VSCodeExtension {
            name: "devaic-security".to_string(),
            display_name: "DeVAIC Security Analyzer".to_string(),
            description: "Real-time security vulnerability detection".to_string(),
            version: "1.0.0".to_string(),
            publisher: "devaic".to_string(),
            engines: vec!["vscode".to_string()],
            categories: vec!["Linters".to_string()],
            activation_events: vec!["onLanguage:rust".to_string()],
            main: "./out/extension.js".to_string(),
            contributes: VSCodeContributes {
                commands: vec![],
                configuration: VSCodeConfiguration {
                    title: "DeVAIC".to_string(),
                    properties: vec![],
                },
            },
        }
    }

    pub async fn start_language_server() -> Result<()> {
        Err(crate::error::DevaicError::Analysis(
            "IDE integration feature not enabled. Compile with --features ide".to_string()
        ))
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VSCodeExtension {
    pub name: String,
    pub display_name: String,
    pub description: String,
    pub version: String,
    pub publisher: String,
    pub engines: Vec<String>,
    pub categories: Vec<String>,
    pub activation_events: Vec<String>,
    pub main: String,
    pub contributes: VSCodeContributes,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VSCodeContributes {
    pub commands: Vec<VSCodeCommand>,
    pub configuration: VSCodeConfiguration,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VSCodeCommand {
    pub command: String,
    pub title: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VSCodeConfiguration {
    pub title: String,
    pub properties: Vec<(String, String)>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct IntelliJPlugin {
    pub name: String,
    pub id: String,
    pub version: String,
    pub vendor: String,
    pub description: String,
    pub since_build: String,
    pub until_build: String,
    pub supported_languages: Vec<String>,
    pub features: Vec<String>,
}