use crate::{
    analyzer::Analyzer,
    config::Config,
    error::Result,
    ml_engine::MLEngine,
    Language, Severity, Vulnerability,
};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::time::{Duration, Instant};
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
    #[allow(dead_code)]
    ml_engine: MLEngine,
    config: Config,
    document_cache: HashMap<Url, DocumentInfo>,
    vulnerability_cache: HashMap<Url, Vec<EnhancedVulnerability>>,
    real_time_settings: RealTimeSettings,
    quick_fix_cache: HashMap<String, Vec<QuickFix>>,
}

#[derive(Debug, Clone)]
pub struct DocumentInfo {
    pub content: String,
    pub language: Option<Language>,
    pub last_modified: Instant,
    pub version: i32,
    pub analysis_in_progress: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EnhancedVulnerability {
    pub base: Vulnerability,
    pub confidence: f32,
    pub context_info: String,
    pub quick_fixes: Vec<QuickFix>,
    pub related_issues: Vec<String>,
    pub impact_analysis: ImpactAnalysis,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct QuickFix {
    pub id: String,
    pub title: String,
    pub description: String,
    pub fix_type: QuickFixType,
    pub text_edits: Vec<TextEditPlaceholder>,
    pub confidence: f32,
    pub safety_level: SafetyLevel,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TextEditPlaceholder {
    pub range_start_line: u32,
    pub range_start_character: u32,
    pub range_end_line: u32,
    pub range_end_character: u32,
    pub new_text: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum QuickFixType {
    AutoFix,          // Can be applied automatically
    SuggestedFix,     // Suggested but requires user approval
    RefactoringFix,   // Requires significant code changes
    ConfigurationFix, // Requires configuration changes
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum SafetyLevel {
    Safe,     // No risk of breaking functionality
    Moderate, // Low risk of breaking functionality
    Risky,    // High risk - requires careful review
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ImpactAnalysis {
    pub security_impact: String,
    pub performance_impact: String,
    pub maintainability_impact: String,
    pub business_risk: String,
}

#[derive(Debug, Clone)]
pub struct RealTimeSettings {
    pub enabled: bool,
    pub debounce_delay: Duration,
    pub max_analysis_time: Duration,
    pub enable_ml_analysis: bool,
    pub severity_threshold: Severity,
}

impl DevaicLanguageServer {
    pub fn new(client: Client) -> Self {
        let config = Config::default();
        let analyzer = Analyzer::new(config.clone()).unwrap_or_else(|_| {
            // Create a default analyzer if creation fails - this is a placeholder
            // In real implementation, we'd handle this error properly
            panic!("Failed to create analyzer")
        });
        let ml_engine = MLEngine::new().unwrap_or_default();
        
        Self {
            client,
            analyzer,
            ml_engine,
            config,
            document_cache: HashMap::new(),
            vulnerability_cache: HashMap::new(),
            real_time_settings: RealTimeSettings {
                enabled: true,
                debounce_delay: Duration::from_millis(500),
                max_analysis_time: Duration::from_secs(10),
                enable_ml_analysis: true,
                severity_threshold: Severity::Medium,
            },
            quick_fix_cache: HashMap::new(),
        }
    }
    
    #[cfg(feature = "ide")]
    async fn analyze_document(&mut self, uri: &Url, content: &str) -> Result<Vec<EnhancedVulnerability>> {
        let start_time = Instant::now();
        
        // Check if analysis is already in progress
        if let Some(doc_info) = self.document_cache.get(uri) {
            if doc_info.analysis_in_progress {
                return Ok(Vec::new());
            }
        }
        
        // Mark analysis as in progress
        if let Some(doc_info) = self.document_cache.get_mut(uri) {
            doc_info.analysis_in_progress = true;
        }
        
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
        
        let mut enhanced_vulnerabilities = Vec::new();
        
        if let Some(lang) = language {
            // Create source file for analysis
            let source_file = crate::parsers::SourceFile {
                path,
                content: content.to_string(),
                language: lang,
            };
            
            // Perform traditional analysis
            let traditional_vulns = self.perform_traditional_analysis(&source_file).await?;
            
            // Perform ML-enhanced analysis if enabled
            let ml_vulns = if self.real_time_settings.enable_ml_analysis {
                self.perform_ml_analysis(&source_file).await?
            } else {
                Vec::new()
            };
            
            // Combine and enhance vulnerabilities
            let all_vulns = [traditional_vulns, ml_vulns].concat();
            
            for vuln in all_vulns {
                if vuln.severity >= self.real_time_settings.severity_threshold {
                    let enhanced = self.enhance_vulnerability(vuln, &source_file).await;
                    enhanced_vulnerabilities.push(enhanced);
                }
            }
        }
        
        // Update cache
        self.vulnerability_cache.insert(uri.clone(), enhanced_vulnerabilities.clone());
        
        // Mark analysis as complete
        if let Some(doc_info) = self.document_cache.get_mut(uri) {
            doc_info.analysis_in_progress = false;
        }
        
        // Log performance metrics
        let analysis_time = start_time.elapsed();
        if analysis_time > Duration::from_secs(1) {
            self.client.log_message(
                MessageType::WARNING,
                format!("Analysis took {:.2}s for {}", analysis_time.as_secs_f32(), uri.path())
            ).await;
        }
        
        Ok(enhanced_vulnerabilities)
    }
    
    #[cfg(feature = "ide")]
    async fn perform_traditional_analysis(&self, source_file: &crate::parsers::SourceFile) -> Result<Vec<Vulnerability>> {
        // Simulate traditional analysis - in real implementation, this would use the analyzer
        let mut vulnerabilities = Vec::new();
        
        // Example: Check for common security patterns
        if source_file.content.contains("eval(") {
            vulnerabilities.push(crate::rules::create_vulnerability(
                "IDE-EVAL-001",
                Some("CWE-95"),
                "Dynamic Code Execution",
                Severity::High,
                "injection",
                "Potential code injection vulnerability detected through eval() usage",
                &source_file.path.to_string_lossy(),
                1,
                0,
                "eval(user_input)",
                "Avoid using eval() with user-controlled input. Consider safer alternatives.",
            ));
        }
        
        if source_file.content.contains("system(") {
            vulnerabilities.push(crate::rules::create_vulnerability(
                "IDE-CMD-001",
                Some("CWE-78"),
                "Command Injection",
                Severity::Critical,
                "injection",
                "Potential command injection vulnerability detected",
                &source_file.path.to_string_lossy(),
                1,
                0,
                "system(user_input)",
                "Sanitize input before passing to system commands or use safer alternatives.",
            ));
        }
        
        Ok(vulnerabilities)
    }
    
    #[cfg(feature = "ide")]
    async fn perform_ml_analysis(&self, source_file: &crate::parsers::SourceFile) -> Result<Vec<Vulnerability>> {
        // Create a dummy AST for ML analysis
        let dummy_ast = crate::parsers::ParsedAst {};
        
        // Use ML engine for analysis
        match self.ml_engine.analyze_with_ml(source_file, &dummy_ast) {
            Ok(ml_vulnerabilities) => Ok(ml_vulnerabilities),
            Err(_) => Ok(Vec::new()), // Gracefully handle ML analysis failures
        }
    }
    
    #[cfg(feature = "ide")]
    async fn enhance_vulnerability(&mut self, vuln: Vulnerability, source_file: &crate::parsers::SourceFile) -> EnhancedVulnerability {
        let quick_fixes = self.generate_quick_fixes(&vuln, source_file).await;
        let impact_analysis = self.analyze_impact(&vuln, source_file).await;
        
        EnhancedVulnerability {
            confidence: self.calculate_confidence(&vuln),
            context_info: self.extract_context_info(&vuln, source_file),
            quick_fixes,
            related_issues: self.find_related_issues(&vuln, source_file),
            impact_analysis,
            base: vuln,
        }
    }
    
    #[cfg(feature = "ide")]
    async fn generate_quick_fixes(&mut self, vuln: &Vulnerability, source_file: &crate::parsers::SourceFile) -> Vec<QuickFix> {
        let mut fixes = Vec::new();
        
        // Cache key for quick fixes
        let cache_key = format!("{}_{}", vuln.id, vuln.vulnerability_type);
        
        // Check cache first
        if let Some(cached_fixes) = self.quick_fix_cache.get(&cache_key) {
            return cached_fixes.clone();
        }
        
        // Generate fixes based on vulnerability type
        match vuln.category.as_str() {
            "injection" => {
                if vuln.vulnerability_type.contains("SQL") {
                    fixes.push(QuickFix {
                        id: "sql_injection_fix_1".to_string(),
                        title: "Use Parameterized Query".to_string(),
                        description: "Replace string concatenation with parameterized query".to_string(),
                        fix_type: QuickFixType::SuggestedFix,
                        text_edits: vec![/* TextEdit would be populated based on actual code analysis */],
                        confidence: 0.9,
                        safety_level: SafetyLevel::Safe,
                    });
                } else if vuln.vulnerability_type.contains("Command") {
                    fixes.push(QuickFix {
                        id: "cmd_injection_fix_1".to_string(),
                        title: "Sanitize Input".to_string(),
                        description: "Add input validation and sanitization".to_string(),
                        fix_type: QuickFixType::SuggestedFix,
                        text_edits: vec![],
                        confidence: 0.8,
                        safety_level: SafetyLevel::Moderate,
                    });
                }
            }
            "crypto" => {
                fixes.push(QuickFix {
                    id: "crypto_fix_1".to_string(),
                    title: "Use Secure Algorithm".to_string(),
                    description: "Replace with cryptographically secure alternative".to_string(),
                    fix_type: QuickFixType::RefactoringFix,
                    text_edits: vec![],
                    confidence: 0.95,
                    safety_level: SafetyLevel::Safe,
                });
            }
            _ => {
                fixes.push(QuickFix {
                    id: "generic_fix_1".to_string(),
                    title: "Apply Security Best Practice".to_string(),
                    description: vuln.recommendation.clone(),
                    fix_type: QuickFixType::SuggestedFix,
                    text_edits: vec![],
                    confidence: 0.7,
                    safety_level: SafetyLevel::Moderate,
                });
            }
        }
        
        // Cache the fixes
        self.quick_fix_cache.insert(cache_key, fixes.clone());
        
        fixes
    }
    
    #[allow(dead_code)]
    async fn analyze_impact(&self, vuln: &Vulnerability, _source_file: &crate::parsers::SourceFile) -> ImpactAnalysis {
        ImpactAnalysis {
            security_impact: match vuln.severity {
                Severity::Critical => "Critical security risk - immediate attention required".to_string(),
                Severity::High => "High security risk - should be fixed soon".to_string(),
                Severity::Medium => "Moderate security risk - address in next release".to_string(),
                Severity::Low => "Low security risk - consider fixing when convenient".to_string(),
                Severity::Info => "Informational - no immediate security impact".to_string(),
            },
            performance_impact: "Minimal performance impact from implementing the fix".to_string(),
            maintainability_impact: "Fixing this issue will improve code maintainability".to_string(),
            business_risk: match vuln.severity {
                Severity::Critical | Severity::High => "High business risk - could lead to data breach or service disruption".to_string(),
                Severity::Medium => "Medium business risk - could affect system reliability".to_string(),
                _ => "Low business risk - minor impact on operations".to_string(),
            },
        }
    }
    
    #[allow(dead_code)]
    fn calculate_confidence(&self, vuln: &Vulnerability) -> f32 {
        // Base confidence on various factors
        let mut confidence: f32 = 0.8;
        
        // Adjust based on vulnerability type certainty
        if vuln.cwe.is_some() {
            confidence += 0.1;
        }
        
        // Adjust based on category
        match vuln.category.as_str() {
            "injection" | "crypto" => confidence += 0.1,
            "performance" | "maintainability" => confidence -= 0.1,
            _ => {}
        }
        
        confidence.min(1.0)
    }
    
    #[allow(dead_code)]
    fn extract_context_info(&self, vuln: &Vulnerability, source_file: &crate::parsers::SourceFile) -> String {
        format!(
            "Found in {} (line {}) - Language: {:?} - Pattern: {}",
            source_file.path.file_name().unwrap_or_default().to_string_lossy(),
            vuln.line_number,
            source_file.language,
            vuln.source_code.chars().take(50).collect::<String>()
        )
    }
    
    #[allow(dead_code)]
    fn find_related_issues(&self, vuln: &Vulnerability, _source_file: &crate::parsers::SourceFile) -> Vec<String> {
        // Find related issues based on the vulnerability type
        match vuln.category.as_str() {
            "injection" => vec![
                "Input Validation".to_string(),
                "Output Encoding".to_string(),
                "Parameterized Queries".to_string(),
            ],
            "crypto" => vec![
                "Key Management".to_string(),
                "Algorithm Selection".to_string(),
                "Secure Random Numbers".to_string(),
            ],
            _ => vec!["Security Best Practices".to_string()],
        }
    }
    
    #[cfg(feature = "ide")]
    fn enhanced_vulnerabilities_to_diagnostics(&self, vulnerabilities: &[EnhancedVulnerability]) -> Vec<Diagnostic> {
        vulnerabilities.iter().map(|enhanced_vuln| {
            let vuln = &enhanced_vuln.base;
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
            
            // Enhanced diagnostic message with confidence and context
            let enhanced_message = format!(
                "{}\n\n**Confidence:** {:.1}%\n**Context:** {}\n**Security Impact:** {}\n\n**Recommendation:** {}",
                vuln.description,
                enhanced_vuln.confidence * 100.0,
                enhanced_vuln.context_info,
                enhanced_vuln.impact_analysis.security_impact,
                vuln.recommendation
            );
            
            Diagnostic {
                range,
                severity: Some(severity),
                code: Some(NumberOrString::String(vuln.id.clone())),
                code_description: vuln.cwe.as_ref().map(|cwe| CodeDescription {
                    href: Url::parse(&format!("https://cwe.mitre.org/data/definitions/{}.html", 
                                             cwe.replace("CWE-", ""))).unwrap(),
                }),
                source: Some("DeVAIC Enhanced".to_string()),
                message: enhanced_message,
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
    
    #[cfg(feature = "ide")]
    async fn perform_real_time_analysis(&mut self, uri: &Url, content: &str) {
        if !self.real_time_settings.enabled {
            return;
        }
        
        // Debounce rapid changes (simplified without tokio)
        std::thread::sleep(self.real_time_settings.debounce_delay);
        
        // Check if the document was modified during the debounce period
        if let Some(cached_content) = self.document_cache.get(uri) {
            if cached_content.content != content {
                return; // Document was modified, skip this analysis
            }
        }
        
        // Perform analysis (simplified without timeout for now)
        let analysis_result = self.analyze_document(uri, content).await;
        
        match analysis_result {
            Ok(Ok(vulnerabilities)) => {
                let diagnostics = self.enhanced_vulnerabilities_to_diagnostics(&vulnerabilities);
                self.publish_diagnostics(uri.clone(), diagnostics).await;
                
                // Send performance metrics if analysis was slow
                if vulnerabilities.len() > 10 {
                    self.client.log_message(
                        MessageType::INFO,
                        format!("Found {} security issues in {}", vulnerabilities.len(), uri.path())
                    ).await;
                }
            }
            Ok(Err(e)) => {
                self.client.log_message(
                    MessageType::ERROR,
                    format!("Analysis error for {}: {}", uri.path(), e)
                ).await;
            }
            Err(_) => {
                self.client.log_message(
                    MessageType::WARNING,
                    format!("Analysis timeout for {}", uri.path())
                ).await;
            }
        }
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
        let version = params.text_document.version;
        
        // Determine language
        let language = if let Some(ext) = std::path::PathBuf::from(uri.path()).extension() {
            if let Some(ext_str) = ext.to_str() {
                Language::from_extension(ext_str)
            } else {
                None
            }
        } else {
            None
        };
        
        // Cache the document content with metadata
        let mut server = self.clone();
        let doc_info = DocumentInfo {
            content: content.clone(),
            language,
            last_modified: Instant::now(),
            version,
            analysis_in_progress: false,
        };
        server.document_cache.insert(uri.clone(), doc_info);
        
        // Perform enhanced analysis
        server.perform_real_time_analysis(&uri, &content).await;
    }
    
    async fn did_change(&self, params: DidChangeTextDocumentParams) {
        let uri = params.text_document.uri;
        let version = params.text_document.version;
        
        if let Some(change) = params.content_changes.into_iter().next() {
            let content = change.text;
            
            // Update cache with new content and metadata
            let mut server = self.clone();
            if let Some(mut doc_info) = server.document_cache.get(&uri).cloned() {
                doc_info.content = content.clone();
                doc_info.last_modified = Instant::now();
                doc_info.version = version;
                server.document_cache.insert(uri.clone(), doc_info);
            }
            
            // Perform real-time analysis with debouncing
            tokio::spawn(async move {
                server.perform_real_time_analysis(&uri, &content).await;
            });
        }
    }
    
    async fn hover(&self, params: HoverParams) -> LspResult<Option<Hover>> {
        let uri = &params.text_document_position_params.text_document.uri;
        let position = params.text_document_position_params.position;
        
        if let Some(enhanced_vulnerabilities) = self.vulnerability_cache.get(uri) {
            for enhanced_vuln in enhanced_vulnerabilities {
                let vuln = &enhanced_vuln.base;
                let vuln_line = (vuln.line_number.saturating_sub(1)) as u32;
                if vuln_line == position.line {
                    let hover_content = format!(
                        "# 🛡️ **Security Issue: {}**\n\n\
                        ## 📋 **Description**\n{}\n\n\
                        ## ⚠️ **Severity:** `{:?}` (Confidence: {:.1}%)\n\n\
                        ## 🔍 **Context**\n{}\n\n\
                        ## 📊 **Impact Analysis**\n\
                        - **Security:** {}\n\
                        - **Business Risk:** {}\n\
                        - **Performance:** {}\n\
                        - **Maintainability:** {}\n\n\
                        ## 🔧 **Quick Fixes Available**\n{}\n\n\
                        ## 💡 **Recommendation**\n{}\n\n\
                        ## 🔗 **Related Issues**\n{}\n\n\
                        ---\n*DeVAIC Enhanced Security Analysis*",
                        vuln.vulnerability_type,
                        vuln.description,
                        vuln.severity,
                        enhanced_vuln.confidence * 100.0,
                        enhanced_vuln.context_info,
                        enhanced_vuln.impact_analysis.security_impact,
                        enhanced_vuln.impact_analysis.business_risk,
                        enhanced_vuln.impact_analysis.performance_impact,
                        enhanced_vuln.impact_analysis.maintainability_impact,
                        if enhanced_vuln.quick_fixes.is_empty() {
                            "*No automatic fixes available*".to_string()
                        } else {
                            enhanced_vuln.quick_fixes.iter()
                                .map(|fix| format!("- **{}**: {}", fix.title, fix.description))
                                .collect::<Vec<_>>()
                                .join("\n")
                        },
                        vuln.recommendation,
                        enhanced_vuln.related_issues.join(", ")
                    );
                    
                    return Ok(Some(Hover {
                        contents: HoverContents::Markup(MarkupContent {
                            kind: MarkupKind::Markdown,
                            value: hover_content,
                        }),
                        range: Some(Range {
                            start: Position {
                                line: vuln_line,
                                character: vuln.column as u32,
                            },
                            end: Position {
                                line: vuln_line,
                                character: (vuln.column + vuln.source_code.len()) as u32,
                            },
                        }),
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
        
        if let Some(enhanced_vulnerabilities) = self.vulnerability_cache.get(uri) {
            for enhanced_vuln in enhanced_vulnerabilities {
                let vuln = &enhanced_vuln.base;
                let vuln_line = (vuln.line_number.saturating_sub(1)) as u32;
                
                if vuln_line >= range.start.line && vuln_line <= range.end.line {
                    // Add quick fix actions for each available fix
                    for (i, quick_fix) in enhanced_vuln.quick_fixes.iter().enumerate() {
                        let action_kind = match quick_fix.fix_type {
                            QuickFixType::AutoFix => CodeActionKind::QUICKFIX,
                            QuickFixType::SuggestedFix => CodeActionKind::QUICKFIX,
                            QuickFixType::RefactoringFix => CodeActionKind::REFACTOR,
                            QuickFixType::ConfigurationFix => CodeActionKind::SOURCE,
                        };
                        
                        let safety_icon = match quick_fix.safety_level {
                            SafetyLevel::Safe => "✅",
                            SafetyLevel::Moderate => "⚠️",
                            SafetyLevel::Risky => "🚨",
                        };
                        
                        let action_title = format!(
                            "{} {} (Confidence: {:.0}%)",
                            safety_icon,
                            quick_fix.title,
                            quick_fix.confidence * 100.0
                        );
                        
                        let action = CodeAction {
                            title: action_title,
                            kind: Some(action_kind),
                            diagnostics: Some(vec![]),
                            edit: if !quick_fix.text_edits.is_empty() {
                                Some(WorkspaceEdit {
                                    changes: Some({
                                        let mut changes = HashMap::new();
                                        changes.insert(uri.clone(), quick_fix.text_edits.clone());
                                        changes
                                    }),
                                    document_changes: None,
                                    change_annotations: None,
                                })
                            } else {
                                // Default fix: add comment with recommendation
                                Some(WorkspaceEdit {
                                    changes: Some({
                                        let mut changes = HashMap::new();
                                        changes.insert(uri.clone(), vec![TextEdit {
                                            range: Range {
                                                start: Position { line: vuln_line, character: 0 },
                                                end: Position { line: vuln_line, character: 0 },
                                            },
                                            new_text: format!("// SECURITY FIX: {}\n", quick_fix.description),
                                        }]);
                                        changes
                                    }),
                                    document_changes: None,
                                    change_annotations: None,
                                })
                            },
                            command: None,
                            data: None,
                            is_preferred: Some(i == 0 && quick_fix.safety_level == SafetyLevel::Safe),
                            disabled: if quick_fix.safety_level == SafetyLevel::Risky {
                                Some(CodeActionDisabled {
                                    reason: "High risk fix - requires manual review".to_string(),
                                })
                            } else {
                                None
                            },
                        };
                        
                        actions.push(CodeActionOrCommand::CodeAction(action));
                    }
                    
                    // Add a "View Impact Analysis" action
                    let impact_action = CodeAction {
                        title: "📊 View Impact Analysis".to_string(),
                        kind: Some(CodeActionKind::SOURCE),
                        diagnostics: Some(vec![]),
                        edit: None,
                        command: Some(Command {
                            title: "Show Impact Analysis".to_string(),
                            command: "devaic.showImpactAnalysis".to_string(),
                            arguments: Some(vec![
                                serde_json::to_value(&enhanced_vuln.impact_analysis).unwrap()
                            ]),
                        }),
                        data: None,
                        is_preferred: Some(false),
                        disabled: None,
                    };
                    
                    actions.push(CodeActionOrCommand::CodeAction(impact_action));
                    
                    // Add "Suppress Warning" action
                    let suppress_action = CodeAction {
                        title: "🔇 Suppress this warning".to_string(),
                        kind: Some(CodeActionKind::SOURCE),
                        diagnostics: Some(vec![]),
                        edit: Some(WorkspaceEdit {
                            changes: Some({
                                let mut changes = HashMap::new();
                                changes.insert(uri.clone(), vec![TextEdit {
                                    range: Range {
                                        start: Position { line: vuln_line, character: 0 },
                                        end: Position { line: vuln_line, character: 0 },
                                    },
                                    new_text: format!("// devaic:ignore {} - Suppressed by user\n", vuln.id),
                                }]);
                                changes
                            }),
                            document_changes: None,
                            change_annotations: None,
                        }),
                        command: None,
                        data: None,
                        is_preferred: Some(false),
                        disabled: None,
                    };
                    
                    actions.push(CodeActionOrCommand::CodeAction(suppress_action));
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
            ml_engine: MLEngine::new().unwrap_or_default(),
            config: self.config.clone(),
            document_cache: self.document_cache.clone(),
            vulnerability_cache: self.vulnerability_cache.clone(),
            real_time_settings: self.real_time_settings.clone(),
            quick_fix_cache: self.quick_fix_cache.clone(),
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