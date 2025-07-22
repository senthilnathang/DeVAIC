use crate::{
    analyzer::Analyzer,
    config::Config,
    error::Result,
    Language, Vulnerability,
};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
#[cfg(feature = "ide")]
use tower_lsp::jsonrpc::Result as LspResult;
#[cfg(feature = "ide")]
use tower_lsp::lsp_types::*;
#[cfg(feature = "ide")]
use tower_lsp::{Client, LanguageServer, LspService, Server};

// Placeholder types when IDE feature is disabled
#[cfg(not(feature = "ide"))]
pub type LspResult<T> = std::result::Result<T, String>;
#[cfg(not(feature = "ide"))]
#[derive(Debug, Clone)]
pub struct Client;
#[cfg(not(feature = "ide"))]
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct Url(String);
#[cfg(not(feature = "ide"))]
pub struct Diagnostic;
#[cfg(not(feature = "ide"))]
pub struct InitializeParams;
#[cfg(not(feature = "ide"))]
pub struct InitializeResult;
#[cfg(not(feature = "ide"))]
pub struct InitializedParams;
#[cfg(not(feature = "ide"))]
pub struct DidOpenTextDocumentParams;
#[cfg(not(feature = "ide"))]
pub struct DidChangeTextDocumentParams;
#[cfg(not(feature = "ide"))]
pub struct HoverParams;
#[cfg(not(feature = "ide"))]
pub struct Hover;
#[cfg(not(feature = "ide"))]
pub struct CodeActionParams;
#[cfg(not(feature = "ide"))]
pub struct CodeActionResponse;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct IDEPlugin {
    pub name: String,
    pub version: String,
    pub supported_ides: Vec<String>,
    pub language_support: Vec<Language>,
    pub real_time_analysis: bool,
    pub auto_fix_suggestions: bool,
}

pub struct DevaicLanguageServer {
    client: Client,
    #[allow(dead_code)]
    analyzer: Analyzer,
    config: Config,
    document_cache: HashMap<Url, String>,
    vulnerability_cache: HashMap<Url, Vec<Vulnerability>>,
}

impl DevaicLanguageServer {
    pub fn new(client: Client) -> Self {
        let config = Config::default();
        let analyzer = Analyzer::new(config.clone()).unwrap_or_else(|_| {
            // Create a default analyzer if creation fails - this is a placeholder
            // In real implementation, we'd handle this error properly
            panic!("Failed to create analyzer")
        });
        
        Self {
            client,
            analyzer,
            config,
            document_cache: HashMap::new(),
            vulnerability_cache: HashMap::new(),
        }
    }
    
    #[cfg(feature = "ide")]
    async fn analyze_document(&mut self, uri: &Url, content: &str) -> Result<Vec<Vulnerability>> {
        // For IDE integration, we'll need to implement proper URI to path conversion
        let path_str = uri.path();
        let path = std::path::PathBuf::from(path_str);
        
        // Determine language from file extension
        let language = if let Some(ext) = path.extension() {
            if let Some(ext_str) = ext.to_str() {
                Language::from_extension(ext_str)
            } else {
                None
            }
        } else {
            None
        };
        
        if let Some(_lang) = language {
            // For now, return empty vulnerabilities - this would be implemented with proper content analysis
            let vulnerabilities = Vec::new();
            self.vulnerability_cache.insert(uri.clone(), vulnerabilities.clone());
            Ok(vulnerabilities)
        } else {
            Ok(Vec::new())
        }
    }
    
    #[cfg(feature = "ide")]
    fn vulnerabilities_to_diagnostics(&self, vulnerabilities: &[Vulnerability]) -> Vec<Diagnostic> {
        vulnerabilities.iter().map(|vuln| {
            let severity = match vuln.severity {
                crate::Severity::Critical | crate::Severity::High => DiagnosticSeverity::ERROR,
                crate::Severity::Medium => DiagnosticSeverity::WARNING,
                crate::Severity::Low => DiagnosticSeverity::INFORMATION,
                crate::Severity::Info => DiagnosticSeverity::HINT,
            };
            
            let range = Range {
                start: Position {
                    line: (vuln.line_number.saturating_sub(1)) as u32,
                    character: vuln.column as u32,
                },
                end: Position {
                    line: (vuln.line_number.saturating_sub(1)) as u32,
                    character: (vuln.column + vuln.source_code.len()) as u32,
                },
            };
            
            Diagnostic {
                range,
                severity: Some(severity),
                code: Some(NumberOrString::String(vuln.id.clone())),
                code_description: vuln.cwe.as_ref().map(|cwe| CodeDescription {
                    href: Url::parse(&format!("https://cwe.mitre.org/data/definitions/{}.html", 
                                             cwe.replace("CWE-", ""))).unwrap(),
                }),
                source: Some("DeVAIC".to_string()),
                message: format!("{}\n\nRecommendation: {}", vuln.description, vuln.recommendation),
                related_information: None,
                tags: Some(vec![DiagnosticTag::UNNECESSARY]),
                data: None,
            }
        }).collect()
    }
    
    #[cfg(feature = "ide")]
    async fn publish_diagnostics(&self, uri: Url, diagnostics: Vec<Diagnostic>) {
        self.client.publish_diagnostics(uri, diagnostics, None).await;
    }
    
    #[cfg(not(feature = "ide"))]
    #[allow(dead_code)]
    async fn publish_diagnostics(&self, _uri: Url, _diagnostics: Vec<Diagnostic>) {
        // Stub implementation
    }
}

#[cfg(feature = "ide")]
#[tower_lsp::async_trait]
impl LanguageServer for DevaicLanguageServer {
    async fn initialize(&self, _: InitializeParams) -> LspResult<InitializeResult> {
        Ok(InitializeResult {
            capabilities: ServerCapabilities {
                text_document_sync: Some(TextDocumentSyncCapability::Kind(
                    TextDocumentSyncKind::FULL,
                )),
                diagnostic_provider: Some(DiagnosticServerCapabilities::Options(
                    DiagnosticOptions {
                        identifier: Some("devaic".to_string()),
                        inter_file_dependencies: true,
                        workspace_diagnostics: true,
                        work_done_progress_options: WorkDoneProgressOptions::default(),
                    },
                )),
                code_action_provider: Some(CodeActionProviderCapability::Simple(true)),
                hover_provider: Some(HoverProviderCapability::Simple(true)),
                completion_provider: Some(CompletionOptions {
                    resolve_provider: Some(false),
                    trigger_characters: Some(vec![".".to_string(), ":".to_string()]),
                    work_done_progress_options: WorkDoneProgressOptions::default(),
                    all_commit_characters: None,
                    completion_item: None,
                }),
                ..ServerCapabilities::default()
            },
            server_info: Some(ServerInfo {
                name: "DeVAIC Language Server".to_string(),
                version: Some(env!("CARGO_PKG_VERSION").to_string()),
            }),
        })
    }
    
    async fn initialized(&self, _: InitializedParams) {
        self.client
            .log_message(MessageType::INFO, "DeVAIC Language Server initialized!")
            .await;
    }
    
    async fn shutdown(&self) -> LspResult<()> {
        Ok(())
    }
    
    async fn did_open(&self, params: DidOpenTextDocumentParams) {
        let uri = params.text_document.uri;
        let content = params.text_document.text;
        
        // Cache the document content
        let mut server = self.clone();
        server.document_cache.insert(uri.clone(), content.clone());
        
        // Analyze the document
        if let Ok(vulnerabilities) = server.analyze_document(&uri, &content).await {
            let diagnostics = server.vulnerabilities_to_diagnostics(&vulnerabilities);
            server.publish_diagnostics(uri, diagnostics).await;
        }
    }
    
    async fn did_change(&self, params: DidChangeTextDocumentParams) {
        let uri = params.text_document.uri;
        
        if let Some(change) = params.content_changes.into_iter().next() {
            let content = change.text;
            
            // Update cache and re-analyze
            let mut server = self.clone();
            server.document_cache.insert(uri.clone(), content.clone());
            
            if let Ok(vulnerabilities) = server.analyze_document(&uri, &content).await {
                let diagnostics = server.vulnerabilities_to_diagnostics(&vulnerabilities);
                server.publish_diagnostics(uri, diagnostics).await;
            }
        }
    }
    
    async fn hover(&self, params: HoverParams) -> LspResult<Option<Hover>> {
        let uri = &params.text_document_position_params.text_document.uri;
        let position = params.text_document_position_params.position;
        
        if let Some(vulnerabilities) = self.vulnerability_cache.get(uri) {
            for vuln in vulnerabilities {
                let vuln_line = (vuln.line_number.saturating_sub(1)) as u32;
                if vuln_line == position.line {
                    let hover_content = format!(
                        "**Security Issue: {}**\n\n{}\n\n**Severity:** {}\n\n**Recommendation:** {}",
                        vuln.vulnerability_type,
                        vuln.description,
                        vuln.severity,
                        vuln.recommendation
                    );
                    
                    return Ok(Some(Hover {
                        contents: HoverContents::Markup(MarkupContent {
                            kind: MarkupKind::Markdown,
                            value: hover_content,
                        }),
                        range: None,
                    }));
                }
            }
        }
        
        Ok(None)
    }
    
    async fn code_action(&self, params: CodeActionParams) -> LspResult<Option<CodeActionResponse>> {
        let uri = &params.text_document.uri;
        let range = params.range;
        
        let mut actions = Vec::new();
        
        if let Some(vulnerabilities) = self.vulnerability_cache.get(uri) {
            for vuln in vulnerabilities {
                let vuln_line = (vuln.line_number.saturating_sub(1)) as u32;
                if vuln_line >= range.start.line && vuln_line <= range.end.line {
                    // Create quick fix action
                    let action = CodeAction {
                        title: format!("Fix: {}", vuln.vulnerability_type),
                        kind: Some(CodeActionKind::QUICKFIX),
                        diagnostics: Some(vec![]),
                        edit: Some(WorkspaceEdit {
                            changes: Some({
                                let mut changes = HashMap::new();
                                changes.insert(uri.clone(), vec![TextEdit {
                                    range: Range {
                                        start: Position { line: vuln_line, character: 0 },
                                        end: Position { line: vuln_line + 1, character: 0 },
                                    },
                                    new_text: format!("// TODO: {}\n", vuln.recommendation),
                                }]);
                                changes
                            }),
                            document_changes: None,
                            change_annotations: None,
                        }),
                        command: None,
                        data: None,
                        is_preferred: Some(true),
                        disabled: None,
                    };
                    
                    actions.push(CodeActionOrCommand::CodeAction(action));
                }
            }
        }
        
        Ok(Some(actions))
    }
}

impl Clone for DevaicLanguageServer {
    fn clone(&self) -> Self {
        Self {
            client: self.client.clone(),
            analyzer: Analyzer::new(self.config.clone()).unwrap_or_else(|_| {
                panic!("Failed to create analyzer")
            }),
            config: self.config.clone(),
            document_cache: self.document_cache.clone(),
            vulnerability_cache: self.vulnerability_cache.clone(),
        }
    }
}

pub struct IDEIntegration;

impl IDEIntegration {
    pub fn create_vscode_extension() -> VSCodeExtension {
        VSCodeExtension {
            name: "devaic-security".to_string(),
            display_name: "DeVAIC Security Analyzer".to_string(),
            description: "Real-time security vulnerability detection for multiple programming languages".to_string(),
            version: "1.0.0".to_string(),
            publisher: "devaic".to_string(),
            engines: vec!["vscode".to_string()],
            categories: vec!["Linters".to_string(), "Other".to_string()],
            activation_events: vec![
                "onLanguage:rust".to_string(),
                "onLanguage:go".to_string(),
                "onLanguage:javascript".to_string(),
                "onLanguage:typescript".to_string(),
                "onLanguage:python".to_string(),
                "onLanguage:java".to_string(),
                "onLanguage:kotlin".to_string(),
                "onLanguage:swift".to_string(),
                "onLanguage:c".to_string(),
                "onLanguage:cpp".to_string(),
            ],
            main: "./out/extension.js".to_string(),
            contributes: VSCodeContributes {
                commands: vec![
                    VSCodeCommand {
                        command: "devaic.analyzeFile".to_string(),
                        title: "Analyze File with DeVAIC".to_string(),
                    },
                    VSCodeCommand {
                        command: "devaic.analyzeWorkspace".to_string(),
                        title: "Analyze Workspace with DeVAIC".to_string(),
                    },
                ],
                configuration: VSCodeConfiguration {
                    title: "DeVAIC".to_string(),
                    properties: vec![
                        ("devaic.enableRealTimeAnalysis".to_string(), "Enable real-time analysis".to_string()),
                        ("devaic.severityThreshold".to_string(), "Minimum severity level to report".to_string()),
                        ("devaic.enableMLAnalysis".to_string(), "Enable machine learning analysis".to_string()),
                    ],
                },
            },
        }
    }
    
    pub fn create_intellij_plugin() -> IntelliJPlugin {
        IntelliJPlugin {
            name: "DeVAIC Security Analyzer".to_string(),
            id: "com.devaic.security".to_string(),
            version: "1.0.0".to_string(),
            vendor: "DeVAIC Team".to_string(),
            description: "Advanced security vulnerability detection for IntelliJ IDEA".to_string(),
            since_build: "203".to_string(),
            until_build: "232.*".to_string(),
            supported_languages: vec![
                "JAVA".to_string(),
                "Kotlin".to_string(),
                "JavaScript".to_string(),
                "TypeScript".to_string(),
                "Python".to_string(),
                "Go".to_string(),
                "Rust".to_string(),
            ],
            features: vec![
                "Real-time vulnerability detection".to_string(),
                "Quick fix suggestions".to_string(),
                "Security metrics dashboard".to_string(),
                "Compliance reporting".to_string(),
            ],
        }
    }
    
    #[cfg(feature = "ide")]
    pub async fn start_language_server() -> Result<()> {
        let stdin = tokio::io::stdin();
        let stdout = tokio::io::stdout();
        
        let (service, socket) = LspService::new(|client| DevaicLanguageServer::new(client));
        Server::new(stdin, stdout, socket).serve(service).await;
        
        Ok(())
    }
    
    #[cfg(not(feature = "ide"))]
    pub async fn start_language_server() -> Result<()> {
        Err(crate::error::DevaicError::Analysis("IDE integration feature not enabled. Compile with --features ide".to_string()))
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