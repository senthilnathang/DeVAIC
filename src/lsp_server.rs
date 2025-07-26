/// Language Server Protocol Implementation for DeVAIC
/// 
/// This module provides LSP server functionality for IDE integration,
/// enabling real-time security analysis as users type.

use crate::{
    analyzer::Analyzer,
    config::Config,
    error::{DevaicError, Result},
    parsers::SourceFile,
    Language, Severity, Vulnerability,
};
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use std::collections::HashMap;
use std::io::{BufRead, BufReader, Write};
use std::path::PathBuf;
use std::sync::{Arc, Mutex};
use std::thread;
use std::time::Instant;

pub struct LSPServer {
    analyzer: Arc<Analyzer>,
    config: Arc<Mutex<Config>>,
    capabilities: ServerCapabilities,
    documents: Arc<Mutex<HashMap<String, DocumentInfo>>>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ServerCapabilities {
    pub text_document_sync: TextDocumentSyncKind,
    pub diagnostic_provider: bool,
    pub hover_provider: bool,
    pub code_action_provider: bool,
    pub completion_provider: Option<CompletionOptions>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum TextDocumentSyncKind {
    None = 0,
    Full = 1,
    Incremental = 2,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CompletionOptions {
    pub trigger_characters: Vec<String>,
}

#[derive(Debug, Clone)]
pub struct DocumentInfo {
    pub uri: String,
    pub version: i32,
    pub content: String,
    pub language_id: String,
    pub last_analysis: Option<Instant>,
    pub diagnostics: Vec<LSPDiagnostic>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LSPDiagnostic {
    pub range: LSPRange,
    pub severity: LSPSeverity,
    pub code: Option<String>,
    pub source: String,
    pub message: String,
    pub related_information: Option<Vec<DiagnosticRelatedInformation>>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LSPRange {
    pub start: LSPPosition,
    pub end: LSPPosition,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LSPPosition {
    pub line: u32,
    pub character: u32,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum LSPSeverity {
    Error = 1,
    Warning = 2,
    Information = 3,
    Hint = 4,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DiagnosticRelatedInformation {
    pub location: LSPLocation,
    pub message: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LSPLocation {
    pub uri: String,
    pub range: LSPRange,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct InitializeParams {
    pub process_id: Option<u32>,
    pub root_uri: Option<String>,
    pub capabilities: ClientCapabilities,
    pub initialization_options: Option<Value>,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct ClientCapabilities {
    pub text_document: Option<TextDocumentClientCapabilities>,
    pub workspace: Option<WorkspaceClientCapabilities>,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct TextDocumentClientCapabilities {
    pub diagnostic: Option<DiagnosticClientCapabilities>,
    pub hover: Option<HoverClientCapabilities>,
    pub code_action: Option<CodeActionClientCapabilities>,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct WorkspaceClientCapabilities {
    pub configuration: Option<bool>,
    pub did_change_configuration: Option<DidChangeConfigurationClientCapabilities>,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct DiagnosticClientCapabilities {
    pub dynamic_registration: Option<bool>,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct HoverClientCapabilities {
    pub dynamic_registration: Option<bool>,
    pub content_format: Option<Vec<String>>,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct CodeActionClientCapabilities {
    pub dynamic_registration: Option<bool>,
    pub code_action_literal_support: Option<CodeActionLiteralSupport>,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct CodeActionLiteralSupport {
    pub code_action_kind: CodeActionKindSupport,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct CodeActionKindSupport {
    pub value_set: Vec<String>,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct DidChangeConfigurationClientCapabilities {
    pub dynamic_registration: Option<bool>,
}

impl LSPServer {
    pub fn new() -> Result<Self> {
        let config = Config::load_from_file("devaic.toml").unwrap_or_default();
        let analyzer = Analyzer::new(config.clone())?;

        Ok(Self {
            analyzer: Arc::new(analyzer),
            config: Arc::new(Mutex::new(config)),
            capabilities: ServerCapabilities {
                text_document_sync: TextDocumentSyncKind::Full,
                diagnostic_provider: true,
                hover_provider: true,
                code_action_provider: true,
                completion_provider: Some(CompletionOptions {
                    trigger_characters: vec![".".to_string(), "::".to_string()],
                }),
            },
            documents: Arc::new(Mutex::new(HashMap::new())),
        })
    }

    pub async fn run(&self) -> Result<()> {
        eprintln!("DeVAIC Language Server starting...");
        
        let stdin = std::io::stdin();
        let mut reader = BufReader::new(stdin);
        
        loop {
            match self.read_message(&mut reader) {
                Ok(Some(message)) => {
                    if let Err(e) = self.handle_message(message).await {
                        eprintln!("Error handling message: {}", e);
                    }
                }
                Ok(None) => {
                    // Connection closed
                    break;
                }
                Err(e) => {
                    eprintln!("Error reading message: {}", e);
                    break;
                }
            }
        }

        eprintln!("DeVAIC Language Server shutting down...");
        Ok(())
    }

    fn read_message(&self, reader: &mut BufReader<std::io::Stdin>) -> Result<Option<Value>> {
        let mut headers = HashMap::new();
        let mut line = String::new();

        // Read headers
        loop {
            line.clear();
            if reader.read_line(&mut line)? == 0 {
                return Ok(None); // EOF
            }

            let line = line.trim();
            if line.is_empty() {
                break; // End of headers
            }

            if let Some(colon_pos) = line.find(':') {
                let key = line[..colon_pos].trim().to_lowercase();
                let value = line[colon_pos + 1..].trim();
                headers.insert(key, value.to_string());
            }
        }

        // Get content length
        let content_length = headers
            .get("content-length")
            .and_then(|s| s.parse::<usize>().ok())
            .ok_or_else(|| DevaicError::Parse("Missing or invalid Content-Length header".to_string()))?;

        // Read content
        let mut content = vec![0u8; content_length];
        std::io::Read::read_exact(reader, &mut content)?;
        
        let content_str = String::from_utf8(content)
            .map_err(|e| DevaicError::Parse(format!("Invalid UTF-8 in message content: {}", e)))?;

        // Parse JSON
        let message: Value = serde_json::from_str(&content_str)
            .map_err(|e| DevaicError::Parse(format!("Invalid JSON: {}", e)))?;

        Ok(Some(message))
    }

    async fn handle_message(&self, message: Value) -> Result<()> {
        if let Some(method) = message.get("method").and_then(|m| m.as_str()) {
            match method {
                "initialize" => self.handle_initialize(message)?,
                "initialized" => self.handle_initialized()?,
                "textDocument/didOpen" => self.handle_did_open(message).await?,
                "textDocument/didChange" => self.handle_did_change(message).await?,
                "textDocument/didSave" => self.handle_did_save(message).await?,
                "textDocument/didClose" => self.handle_did_close(message)?,
                "textDocument/hover" => self.handle_hover(message)?,
                "textDocument/codeAction" => self.handle_code_action(message)?,
                "textDocument/analyze" => self.handle_analyze(message).await?,
                "workspace/didChangeConfiguration" => self.handle_configuration_change(message)?,
                "shutdown" => self.handle_shutdown()?,
                "exit" => std::process::exit(0),
                _ => {
                    eprintln!("Unhandled method: {}", method);
                }
            }
        }
        Ok(())
    }

    fn handle_initialize(&self, message: Value) -> Result<()> {
        let id = message.get("id").cloned().unwrap_or(json!(null));
        
        let response = json!({
            "jsonrpc": "2.0",
            "id": id,
            "result": {
                "capabilities": self.capabilities,
                "serverInfo": {
                    "name": "DeVAIC Language Server",
                    "version": env!("CARGO_PKG_VERSION")
                }
            }
        });

        self.send_response(response)?;
        Ok(())
    }

    fn handle_initialized(&self) -> Result<()> {
        eprintln!("Language server initialized successfully");
        Ok(())
    }

    async fn handle_did_open(&self, message: Value) -> Result<()> {
        if let Some(params) = message.get("params") {
            if let Some(text_document) = params.get("textDocument") {
                let uri = text_document.get("uri").and_then(|u| u.as_str()).unwrap_or("");
                let version = text_document.get("version").and_then(|v| v.as_i64()).unwrap_or(0) as i32;
                let content = text_document.get("text").and_then(|t| t.as_str()).unwrap_or("");
                let language_id = text_document.get("languageId").and_then(|l| l.as_str()).unwrap_or("");

                let doc_info = DocumentInfo {
                    uri: uri.to_string(),
                    version,
                    content: content.to_string(),
                    language_id: language_id.to_string(),
                    last_analysis: None,
                    diagnostics: Vec::new(),
                };

                {
                    let mut documents = self.documents.lock().unwrap();
                    documents.insert(uri.to_string(), doc_info);
                }

                // Analyze document
                self.analyze_document(uri).await?;
            }
        }
        Ok(())
    }

    async fn handle_did_change(&self, message: Value) -> Result<()> {
        if let Some(params) = message.get("params") {
            if let Some(text_document) = params.get("textDocument") {
                let uri = text_document.get("uri").and_then(|u| u.as_str()).unwrap_or("");
                let version = text_document.get("version").and_then(|v| v.as_i64()).unwrap_or(0) as i32;

                if let Some(content_changes) = params.get("contentChanges").and_then(|c| c.as_array()) {
                    if let Some(change) = content_changes.first() {
                        if let Some(text) = change.get("text").and_then(|t| t.as_str()) {
                            // Update document
                            {
                                let mut documents = self.documents.lock().unwrap();
                                if let Some(doc) = documents.get_mut(uri) {
                                    doc.content = text.to_string();
                                    doc.version = version;
                                }
                            }

                            // Analyze document with debouncing
                            self.analyze_document_debounced(uri).await?;
                        }
                    }
                }
            }
        }
        Ok(())
    }

    async fn handle_did_save(&self, message: Value) -> Result<()> {
        if let Some(params) = message.get("params") {
            if let Some(text_document) = params.get("textDocument") {
                let uri = text_document.get("uri").and_then(|u| u.as_str()).unwrap_or("");
                self.analyze_document(uri).await?;
            }
        }
        Ok(())
    }

    fn handle_did_close(&self, message: Value) -> Result<()> {
        if let Some(params) = message.get("params") {
            if let Some(text_document) = params.get("textDocument") {
                let uri = text_document.get("uri").and_then(|u| u.as_str()).unwrap_or("");
                
                {
                    let mut documents = self.documents.lock().unwrap();
                    documents.remove(uri);
                }

                // Clear diagnostics
                self.publish_diagnostics(uri, Vec::new())?;
            }
        }
        Ok(())
    }

    fn handle_hover(&self, _message: Value) -> Result<()> {
        // TODO: Implement hover functionality
        Ok(())
    }

    fn handle_code_action(&self, _message: Value) -> Result<()> {
        // TODO: Implement code actions
        Ok(())
    }

    async fn handle_analyze(&self, message: Value) -> Result<()> {
        if let Some(params) = message.get("params") {
            if let Some(text_document) = params.get("textDocument") {
                let uri = text_document.get("uri").and_then(|u| u.as_str()).unwrap_or("");
                let diagnostics = self.analyze_document(uri).await?;
                
                let id = message.get("id").cloned().unwrap_or(json!(null));
                let response = json!({
                    "jsonrpc": "2.0",
                    "id": id,
                    "result": diagnostics
                });
                
                self.send_response(response)?;
            }
        }
        Ok(())
    }

    fn handle_configuration_change(&self, _message: Value) -> Result<()> {
        // TODO: Handle configuration changes
        Ok(())
    }

    fn handle_shutdown(&self) -> Result<()> {
        let response = json!({
            "jsonrpc": "2.0",
            "id": null,
            "result": null
        });
        self.send_response(response)?;
        Ok(())
    }

    async fn analyze_document(&self, uri: &str) -> Result<Vec<LSPDiagnostic>> {
        let (content, language_id) = {
            let documents = self.documents.lock().unwrap();
            if let Some(doc) = documents.get(uri) {
                (doc.content.clone(), doc.language_id.clone())
            } else {
                return Ok(Vec::new());
            }
        };

        // Parse URI to get file path
        let file_path = if uri.starts_with("file://") {
            PathBuf::from(&uri[7..])
        } else {
            PathBuf::from(uri)
        };

        // Create source file
        let language = self.language_from_id(&language_id);
        let source_file = SourceFile {
            path: file_path,
            content,
            language,
        };

        // Analyze with DeVAIC
        let _config = self.config.lock().unwrap();
        let vulnerabilities = self.analyzer.analyze_file(&source_file.path).await?;

        // Convert to LSP diagnostics
        let diagnostics: Vec<LSPDiagnostic> = vulnerabilities
            .into_iter()
            .map(|vuln| self.vulnerability_to_diagnostic(vuln))
            .collect();

        // Update document diagnostics
        {
            let mut documents = self.documents.lock().unwrap();
            if let Some(doc) = documents.get_mut(uri) {
                doc.diagnostics = diagnostics.clone();
                doc.last_analysis = Some(Instant::now());
            }
        }

        // Publish diagnostics to client
        self.publish_diagnostics(uri, diagnostics.clone())?;

        Ok(diagnostics)
    }

    async fn analyze_document_debounced(&self, uri: &str) -> Result<()> {
        // Simple debouncing - in a real implementation, you'd use a proper debouncing mechanism
        tokio::time::sleep(std::time::Duration::from_millis(100)).await;
        self.analyze_document(uri).await?;
        Ok(())
    }

    fn vulnerability_to_diagnostic(&self, vuln: Vulnerability) -> LSPDiagnostic {
        LSPDiagnostic {
            range: LSPRange {
                start: LSPPosition {
                    line: (vuln.line_number.saturating_sub(1)) as u32,
                    character: vuln.column_start as u32,
                },
                end: LSPPosition {
                    line: (vuln.line_number.saturating_sub(1)) as u32,
                    character: vuln.column_end as u32,
                },
            },
            severity: self.severity_to_lsp_severity(vuln.severity),
            code: Some(vuln.id),
            source: "DeVAIC Enhanced".to_string(),
            message: format!("{}: {}", vuln.title, vuln.description),
            related_information: None,
        }
    }

    fn severity_to_lsp_severity(&self, severity: Severity) -> LSPSeverity {
        match severity {
            Severity::Critical => LSPSeverity::Error,
            Severity::High => LSPSeverity::Warning,
            Severity::Medium => LSPSeverity::Information,
            Severity::Low => LSPSeverity::Hint,
            Severity::Info => LSPSeverity::Information,
        }
    }

    fn language_from_id(&self, language_id: &str) -> Language {
        match language_id {
            "rust" => Language::Rust,
            "go" => Language::Go,
            "javascript" => Language::Javascript,
            "typescript" => Language::TypeScript,
            "python" => Language::Python,
            "java" => Language::Java,
            "kotlin" => Language::Kotlin,
            "swift" => Language::Swift,
            "c" => Language::C,
            "cpp" => Language::Cpp,
            "csharp" => Language::CSharp,
            "php" => Language::Php,
            "ruby" => Language::Ruby,
            "dart" => Language::Dart,
            _ => Language::Python, // Default fallback
        }
    }

    fn publish_diagnostics(&self, uri: &str, diagnostics: Vec<LSPDiagnostic>) -> Result<()> {
        let notification = json!({
            "jsonrpc": "2.0",
            "method": "textDocument/publishDiagnostics",
            "params": {
                "uri": uri,
                "diagnostics": diagnostics
            }
        });

        self.send_response(notification)?;
        Ok(())
    }

    fn send_response(&self, response: Value) -> Result<()> {
        let content = serde_json::to_string(&response)?;
        let message = format!("Content-Length: {}\r\n\r\n{}", content.len(), content);
        
        print!("{}", message);
        std::io::stdout().flush()?;
        
        Ok(())
    }

}

// CLI entry point for LSP server
pub async fn run_lsp_server() -> Result<()> {
    let server = LSPServer::new()?;
    server.run().await
}