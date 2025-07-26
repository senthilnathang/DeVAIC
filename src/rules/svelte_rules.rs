/// Svelte/SvelteKit Security Rules for DeVAIC
/// 
/// This module implements security analysis rules specific to Svelte and SvelteKit,
/// covering both component security and framework-specific vulnerabilities.
/// 
/// Svelte security concerns include:
/// - XSS vulnerabilities in templates and components
/// - Reactive statement security issues
/// - Store security and data leakage
/// - SSR (Server-Side Rendering) security
/// - SvelteKit-specific vulnerabilities (actions, hooks, endpoints)
/// - Component communication security
/// - HTML binding and sanitization

use crate::parsers::{SourceFile, ParsedAst};
use crate::{Vulnerability, Severity};
use crate::error::Result;
use super::RuleSet;
use regex::Regex;
use std::collections::HashMap;
use lazy_static::lazy_static;

lazy_static! {
    /// Svelte-specific security patterns
    static ref SVELTE_PATTERNS: HashMap<&'static str, Regex> = {
        let mut m = HashMap::new();
        
        // XSS and HTML injection patterns
        m.insert("unsafe_html_binding",
            Regex::new(r"(?i)\{@html\s+[^}]*\}").unwrap()
        );
        
        m.insert("unescaped_user_input",
            Regex::new(r"(?i)\{@html\s+[^}]*(?:params|query|form|user|input|request)[^}]*\}").unwrap()
        );
        
        m.insert("dangerous_innerHTML_equivalent",
            Regex::new(r"(?i)innerHTML\s*=\s*[^;]*(?:\+|template|`|\$\{)").unwrap()
        );
        
        // Reactive statement security
        m.insert("reactive_statement_xss",
            Regex::new(r"(?i)\$:\s*[^;]*(?:innerHTML|outerHTML|document\.write)[^;]*=").unwrap()
        );
        
        m.insert("reactive_eval_risk",
            Regex::new(r"(?i)\$:\s*[^;]*(?:eval|Function|setTimeout|setInterval)\s*\(").unwrap()
        );
        
        m.insert("reactive_dom_manipulation",
            Regex::new(r"(?i)\$:\s*[^;]*document\.[^;]*(?:createElement|appendChild|insertBefore)").unwrap()
        );
        
        // Store security patterns
        m.insert("writable_store_no_validation",
            Regex::new(r"(?i)writable\s*\([^)]*\)").unwrap()
        );
        
        m.insert("derived_store_unsafe_transform",
            Regex::new(r"(?i)derived\s*\([^,]*,\s*[^)]*(?:innerHTML|eval|Function)").unwrap()
        );
        
        m.insert("custom_store_no_validation",
            Regex::new(r"(?i)function\s+\w*[sS]tore\s*\([^)]*\)[^{]*\{[^}]*set\s*:[^}]*\}").unwrap()
        );
        
        // Component security
        m.insert("component_prop_injection",
            Regex::new(r"(?i)export\s+let\s+\w+.*\{@html\s+\w+\}").unwrap()
        );
        
        m.insert("unsafe_component_binding",
            Regex::new(r"(?i)bind:(innerHTML|outerHTML|value)").unwrap()
        );
        
        m.insert("dangerous_action_usage",
            Regex::new(r"(?i)use:(\w+)=\{[^}]*(?:innerHTML|eval|Function|document\.write)").unwrap()
        );
        
        // SvelteKit specific patterns
        m.insert("sveltekit_unsafe_load",
            Regex::new(r"(?i)export\s+async\s+function\s+load\s*\([^)]*\)[^{]*\{[^}]*(?:eval|Function|innerHTML)").unwrap()
        );
        
        m.insert("sveltekit_form_action_no_validation",
            Regex::new(r"(?i)export\s+const\s+actions\s*=").unwrap()
        );
        
        m.insert("sveltekit_endpoint_no_sanitization",
            Regex::new(r"(?i)export\s+async\s+function\s+(GET|POST|PUT|DELETE|PATCH)\s*\([^)]*\)[^{]*\{[^}]*request\.(?:json|formData|text)\(\)").unwrap()
        );
        
        m.insert("sveltekit_hooks_bypass",
            Regex::new(r"(?i)export\s+async\s+function\s+handle\s*\([^)]*\)[^{]*\{[^}]*resolve\s*\([^)]*\)").unwrap()
        );
        
        // SSR security issues
        m.insert("ssr_hydration_mismatch",
            Regex::new(r"(?i)onMount\s*\([^)]*\)[^;]*(?:innerHTML|document\.write|eval)").unwrap()
        );
        
        m.insert("ssr_server_leak",
            Regex::new(r"(?i)if\s*\([^)]*browser\s*\)[^{]*\{[^}]*(?:API_KEY|SECRET|PASSWORD|TOKEN)").unwrap()
        );
        
        // Context and lifecycle security
        m.insert("unsafe_context_sharing",
            Regex::new(r"(?i)setContext\s*\([^,]*,\s*[^)]*(?:password|secret|token|key|credential)").unwrap()
        );
        
        m.insert("lifecycle_timing_attack",
            Regex::new(r"(?i)(?:onMount|afterUpdate|beforeUpdate)\s*\([^)]*\)[^;]*(?:performance\.now|Date\.now).*(?:password|auth|login)").unwrap()
        );
        
        // Event handling security
        m.insert("unsafe_event_handler",
            Regex::new(r"(?i)on:(?:click|submit|input|change)=\{[^}]*(?:eval|Function|innerHTML|document\.write)").unwrap()
        );
        
        m.insert("event_handler_xss",
            Regex::new(r#"(?i)on:\w+=['"][^'"]*(?:\+|template|\$\{)[^'"]*['"]"#).unwrap()
        );
        
        // Template security
        m.insert("template_injection",
            Regex::new(r"(?i)\{[^}]*(?:\+|template|`)[^}]*(?:params|query|user|input|request)[^}]*\}").unwrap()
        );
        
        m.insert("unsafe_iteration_key",
            Regex::new(r"(?i)\{#each[^}]*as[^}]*\([^)]*(?:index|i)\)").unwrap()
        );
        
        // Client-side routing security
        m.insert("unsafe_navigation",
            Regex::new(r"(?i)goto\s*\([^)]*(?:\+|template|`|\$\{)[^)]*\)").unwrap()
        );
        
        m.insert("route_parameter_injection",
            Regex::new(r"(?i)\$page\.params\.[^.]*").unwrap()
        );
        
        // Configuration and environment
        m.insert("hardcoded_api_secrets",
            Regex::new(r#"(?i)(?:API_KEY|SECRET|TOKEN|PASSWORD)\s*=\s*['"][^'"]{10,}['"]"#).unwrap()
        );
        
        m.insert("public_env_secrets",
            Regex::new(r"(?i)PUBLIC_[^=]*(?:KEY|SECRET|TOKEN|PASSWORD)\s*=").unwrap()
        );
        
        // WebSocket and real-time features
        m.insert("websocket_origin_bypass",
            Regex::new(r"(?i)new\s+WebSocket\s*\([^)]*\)").unwrap()
        );
        
        m.insert("sse_no_auth",
            Regex::new(r"(?i)new\s+EventSource\s*\([^)]*\)").unwrap()
        );

        m
    };
}

/// Svelte security rules implementation
pub struct SvelteRules;

impl SvelteRules {
    pub fn new() -> Self {
        Self
    }

    /// Analyze Svelte/SvelteKit source code for security vulnerabilities
    pub fn analyze_source(&self, source_file: &SourceFile) -> Result<Vec<Vulnerability>> {
        let mut vulnerabilities = Vec::new();
        let lines: Vec<&str> = source_file.content.lines().collect();

        for (line_number, line) in lines.iter().enumerate() {
            let line_num = line_number + 1;
            let trimmed_line = line.trim();

            // Skip empty lines and comments
            if trimmed_line.is_empty() || trimmed_line.starts_with("<!--") || trimmed_line.starts_with("//") {
                continue;
            }

            // Check for unsafe HTML binding
            if let Some(captures) = SVELTE_PATTERNS["unsafe_html_binding"].captures(line) {
                vulnerabilities.push(Vulnerability {
                    id: "SVELTE-XSS-001".to_string(),
                    cwe: Some("CWE-79".to_string()),
                    owasp: Some("A03:2021".to_string()),
                    title: "Cross-Site Scripting (XSS)".to_string(),
                    severity: Severity::High,
                    category: "security".to_string(),
                    description: "Unsafe {@html} binding detected - may allow XSS attacks".to_string(),
                    file_path: source_file.path.to_string_lossy().to_string(),
                    line_number: line_num,
                    column_start: captures.get(0).map(|m| m.start()).unwrap_or(0),
                    column_end: captures.get(0).map(|m| m.end()).unwrap_or(0),
                    source_code: trimmed_line.to_string(),
                    recommendation: "Sanitize HTML content or use safe binding alternatives. Consider using a library like DOMPurify.".to_string(),
                    references: vec!["https://owasp.org/www-community/attacks/xss/".to_string()],
                    confidence: 0.9,
                });
            }

            // Check for unescaped user input in HTML
            if let Some(captures) = SVELTE_PATTERNS["unescaped_user_input"].captures(line) {
                vulnerabilities.push(Vulnerability {
                    id: "SVELTE-XSS-002".to_string(),
                    cwe: Some("CWE-79".to_string()),
                    owasp: Some("A03:2021".to_string()),
                    title: "Unescaped User Input".to_string(),
                    severity: Severity::Critical,
                    category: "security".to_string(),
                    description: "User input directly bound to {@html} - critical XSS vulnerability".to_string(),
                    file_path: source_file.path.to_string_lossy().to_string(),
                    line_number: line_num,
                    column_start: captures.get(0).map(|m| m.start()).unwrap_or(0),
                    column_end: captures.get(0).map(|m| m.end()).unwrap_or(0),
                    source_code: trimmed_line.to_string(),
                    recommendation: "Never bind user input directly to {@html}. Implement proper input validation and sanitization.".to_string(),
                    references: vec!["https://owasp.org/www-community/attacks/xss/".to_string()],
                    confidence: 0.95,
                });
            }

            // Check for reactive statement XSS
            if let Some(captures) = SVELTE_PATTERNS["reactive_statement_xss"].captures(line) {
                vulnerabilities.push(Vulnerability {
                    id: "SVELTE-REACTIVE-001".to_string(),
                    cwe: Some("CWE-79".to_string()),
                    owasp: Some("A03:2021".to_string()),
                    title: "Reactive Statement XSS".to_string(),
                    severity: Severity::High,
                    category: "security".to_string(),
                    description: "Reactive statement performing unsafe DOM manipulation".to_string(),
                    file_path: source_file.path.to_string_lossy().to_string(),
                    line_number: line_num,
                    column_start: captures.get(0).map(|m| m.start()).unwrap_or(0),
                    column_end: captures.get(0).map(|m| m.end()).unwrap_or(0),
                    source_code: trimmed_line.to_string(),
                    recommendation: "Avoid direct DOM manipulation in reactive statements. Use Svelte's safe binding mechanisms.".to_string(),
                    references: vec!["https://svelte.dev/docs#component-format-script-3-$-marks-a-statement-as-reactive".to_string()],
                    confidence: 0.85,
                });
            }

            // Check for reactive eval risks
            if let Some(captures) = SVELTE_PATTERNS["reactive_eval_risk"].captures(line) {
                vulnerabilities.push(Vulnerability {
                    id: "SVELTE-REACTIVE-002".to_string(),
                    cwe: Some("CWE-95".to_string()),
                    owasp: Some("A03:2021".to_string()),
                    title: "Code Injection".to_string(),
                    severity: Severity::Critical,
                    category: "security".to_string(),
                    description: "Reactive statement using eval or Function constructor - code injection risk".to_string(),
                    file_path: source_file.path.to_string_lossy().to_string(),
                    line_number: line_num,
                    column_start: captures.get(0).map(|m| m.start()).unwrap_or(0),
                    column_end: captures.get(0).map(|m| m.end()).unwrap_or(0),
                    source_code: trimmed_line.to_string(),
                    recommendation: "Never use eval, Function, or timer functions with dynamic content in reactive statements.".to_string(),
                    references: vec!["https://owasp.org/www-community/attacks/Code_Injection".to_string()],
                    confidence: 0.95,
                });
            }

            // Check for writable store without validation
            if let Some(captures) = SVELTE_PATTERNS["writable_store_no_validation"].captures(line) {
                vulnerabilities.push(Vulnerability {
                    id: "SVELTE-STORE-001".to_string(),
                    cwe: Some("CWE-20".to_string()),
                    owasp: Some("A03:2021".to_string()),
                    title: "Insufficient Input Validation".to_string(),
                    severity: Severity::Medium,
                    category: "security".to_string(),
                    description: "Writable store without input validation - may accept malicious data".to_string(),
                    file_path: source_file.path.to_string_lossy().to_string(),
                    line_number: line_num,
                    column_start: captures.get(0).map(|m| m.start()).unwrap_or(0),
                    column_end: captures.get(0).map(|m| m.end()).unwrap_or(0),
                    source_code: trimmed_line.to_string(),
                    recommendation: "Implement validation functions for writable stores to prevent malicious data injection.".to_string(),
                    references: vec!["https://svelte.dev/docs#run-time-svelte-store-writable".to_string()],
                    confidence: 0.7,
                });
            }

            // Check for SvelteKit form actions without validation
            if let Some(captures) = SVELTE_PATTERNS["sveltekit_form_action_no_validation"].captures(line) {
                vulnerabilities.push(Vulnerability {
                    id: "SVELTE-KIT-001".to_string(),
                    cwe: Some("CWE-20".to_string()),
                    owasp: Some("A03:2021".to_string()),
                    title: "Form Action Without Validation".to_string(),
                    severity: Severity::High,
                    category: "security".to_string(),
                    description: "SvelteKit form action without input validation".to_string(),
                    file_path: source_file.path.to_string_lossy().to_string(),
                    line_number: line_num,
                    column_start: captures.get(0).map(|m| m.start()).unwrap_or(0),
                    column_end: captures.get(0).map(|m| m.end()).unwrap_or(0),
                    source_code: trimmed_line.to_string(),
                    recommendation: "Implement comprehensive input validation and sanitization for all form actions.".to_string(),
                    references: vec!["https://kit.svelte.dev/docs/form-actions".to_string()],
                    confidence: 0.8,
                });
            }

            // Check for SvelteKit endpoint without sanitization
            if let Some(captures) = SVELTE_PATTERNS["sveltekit_endpoint_no_sanitization"].captures(line) {
                vulnerabilities.push(Vulnerability {
                    id: "SVELTE-KIT-002".to_string(),
                    cwe: Some("CWE-20".to_string()),
                    owasp: Some("A03:2021".to_string()),
                    title: "API Endpoint Without Validation".to_string(),
                    severity: Severity::High,
                    category: "security".to_string(),
                    description: "SvelteKit API endpoint processing request data without validation".to_string(),
                    file_path: source_file.path.to_string_lossy().to_string(),
                    line_number: line_num,
                    column_start: captures.get(0).map(|m| m.start()).unwrap_or(0),
                    column_end: captures.get(0).map(|m| m.end()).unwrap_or(0),
                    source_code: trimmed_line.to_string(),
                    recommendation: "Validate and sanitize all request data in API endpoints before processing.".to_string(),
                    references: vec!["https://kit.svelte.dev/docs/routing#server".to_string()],
                    confidence: 0.8,
                });
            }

            // Check for SvelteKit hooks bypass
            if let Some(captures) = SVELTE_PATTERNS["sveltekit_hooks_bypass"].captures(line) {
                vulnerabilities.push(Vulnerability {
                    id: "SVELTE-KIT-003".to_string(),
                    cwe: Some("CWE-862".to_string()),
                    owasp: Some("A01:2021".to_string()),
                    title: "Missing Authorization".to_string(),
                    severity: Severity::High,
                    category: "security".to_string(),
                    description: "SvelteKit handle hook without authorization checks".to_string(),
                    file_path: source_file.path.to_string_lossy().to_string(),
                    line_number: line_num,
                    column_start: captures.get(0).map(|m| m.start()).unwrap_or(0),
                    column_end: captures.get(0).map(|m| m.end()).unwrap_or(0),
                    source_code: trimmed_line.to_string(),
                    recommendation: "Implement proper authentication and authorization checks in handle hooks.".to_string(),
                    references: vec!["https://kit.svelte.dev/docs/hooks#server-hooks-handle".to_string()],
                    confidence: 0.75,
                });
            }

            // Check for unsafe context sharing
            if let Some(captures) = SVELTE_PATTERNS["unsafe_context_sharing"].captures(line) {
                vulnerabilities.push(Vulnerability {
                    id: "SVELTE-CONTEXT-001".to_string(),
                    cwe: Some("CWE-200".to_string()),
                    owasp: Some("A02:2021".to_string()),
                    title: "Information Exposure".to_string(),
                    severity: Severity::Medium,
                    category: "security".to_string(),
                    description: "Sensitive data shared through Svelte context - may leak to child components".to_string(),
                    file_path: source_file.path.to_string_lossy().to_string(),
                    line_number: line_num,
                    column_start: captures.get(0).map(|m| m.start()).unwrap_or(0),
                    column_end: captures.get(0).map(|m| m.end()).unwrap_or(0),
                    source_code: trimmed_line.to_string(),
                    recommendation: "Avoid sharing sensitive data through context. Use secure state management alternatives.".to_string(),
                    references: vec!["https://svelte.dev/docs#run-time-svelte-setcontext".to_string()],
                    confidence: 0.65,
                });
            }

            // Check for unsafe event handlers
            if let Some(captures) = SVELTE_PATTERNS["unsafe_event_handler"].captures(line) {
                vulnerabilities.push(Vulnerability {
                    id: "SVELTE-EVENT-001".to_string(),
                    cwe: Some("CWE-79".to_string()),
                    owasp: Some("A03:2021".to_string()),
                    title: "Event Handler XSS".to_string(),
                    severity: Severity::High,
                    category: "security".to_string(),
                    description: "Event handler performing unsafe operations - XSS risk".to_string(),
                    file_path: source_file.path.to_string_lossy().to_string(),
                    line_number: line_num,
                    column_start: captures.get(0).map(|m| m.start()).unwrap_or(0),
                    column_end: captures.get(0).map(|m| m.end()).unwrap_or(0),
                    source_code: trimmed_line.to_string(),
                    recommendation: "Sanitize data and avoid unsafe operations in event handlers.".to_string(),
                    references: vec!["https://svelte.dev/docs#template-syntax-element-directives-on-eventname".to_string()],
                    confidence: 0.8,
                });
            }

            // Check for template injection
            if let Some(captures) = SVELTE_PATTERNS["template_injection"].captures(line) {
                vulnerabilities.push(Vulnerability {
                    id: "SVELTE-TEMPLATE-001".to_string(),
                    cwe: Some("CWE-94".to_string()),
                    owasp: Some("A03:2021".to_string()),
                    title: "Template Injection".to_string(),
                    severity: Severity::High,
                    category: "security".to_string(),
                    description: "Template expression using user input - potential injection vulnerability".to_string(),
                    file_path: source_file.path.to_string_lossy().to_string(),
                    line_number: line_num,
                    column_start: captures.get(0).map(|m| m.start()).unwrap_or(0),
                    column_end: captures.get(0).map(|m| m.end()).unwrap_or(0),
                    source_code: trimmed_line.to_string(),
                    recommendation: "Validate and sanitize user input before using in template expressions.".to_string(),
                    references: vec!["https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/07-Input_Validation_Testing/18-Testing_for_Server_Side_Template_Injection".to_string()],
                    confidence: 0.85,
                });
            }

            // Check for unsafe navigation
            if let Some(captures) = SVELTE_PATTERNS["unsafe_navigation"].captures(line) {
                vulnerabilities.push(Vulnerability {
                    id: "SVELTE-NAV-001".to_string(),
                    cwe: Some("CWE-601".to_string()),
                    owasp: Some("A01:2021".to_string()),
                    title: "Open Redirect".to_string(),
                    severity: Severity::Medium,
                    category: "security".to_string(),
                    description: "Dynamic navigation target - potential open redirect vulnerability".to_string(),
                    file_path: source_file.path.to_string_lossy().to_string(),
                    line_number: line_num,
                    column_start: captures.get(0).map(|m| m.start()).unwrap_or(0),
                    column_end: captures.get(0).map(|m| m.end()).unwrap_or(0),
                    source_code: trimmed_line.to_string(),
                    recommendation: "Validate navigation targets against allowlist before using goto().".to_string(),
                    references: vec!["https://cheatsheetseries.owasp.org/cheatsheets/Unvalidated_Redirects_and_Forwards_Cheat_Sheet.html".to_string()],
                    confidence: 0.7,
                });
            }

            // Check for route parameter injection
            if let Some(captures) = SVELTE_PATTERNS["route_parameter_injection"].captures(line) {
                vulnerabilities.push(Vulnerability {
                    id: "SVELTE-ROUTE-001".to_string(),
                    cwe: Some("CWE-20".to_string()),
                    owasp: Some("A03:2021".to_string()),
                    title: "Parameter Injection".to_string(),
                    severity: Severity::Medium,
                    category: "security".to_string(),
                    description: "Route parameter used without validation - injection risk".to_string(),
                    file_path: source_file.path.to_string_lossy().to_string(),
                    line_number: line_num,
                    column_start: captures.get(0).map(|m| m.start()).unwrap_or(0),
                    column_end: captures.get(0).map(|m| m.end()).unwrap_or(0),
                    source_code: trimmed_line.to_string(),
                    recommendation: "Validate and sanitize route parameters before use.".to_string(),
                    references: vec!["https://kit.svelte.dev/docs/routing#page-params".to_string()],
                    confidence: 0.7,
                });
            }

            // Check for hardcoded API secrets
            if let Some(captures) = SVELTE_PATTERNS["hardcoded_api_secrets"].captures(line) {
                vulnerabilities.push(Vulnerability {
                    id: "SVELTE-SECRET-001".to_string(),
                    cwe: Some("CWE-798".to_string()),
                    owasp: Some("A07:2021".to_string()),
                    title: "Hardcoded Secrets".to_string(),
                    severity: Severity::Critical,
                    category: "authentication".to_string(),
                    description: "Hardcoded API secret detected in Svelte code".to_string(),
                    file_path: source_file.path.to_string_lossy().to_string(),
                    line_number: line_num,
                    column_start: captures.get(0).map(|m| m.start()).unwrap_or(0),
                    column_end: captures.get(0).map(|m| m.end()).unwrap_or(0),
                    source_code: trimmed_line.to_string(),
                    recommendation: "Move secrets to environment variables and use proper secret management.".to_string(),
                    references: vec!["https://cheatsheetseries.owasp.org/cheatsheets/Secrets_Management_Cheat_Sheet.html".to_string()],
                    confidence: 0.9,
                });
            }

            // Check for public environment secrets
            if let Some(captures) = SVELTE_PATTERNS["public_env_secrets"].captures(line) {
                vulnerabilities.push(Vulnerability {
                    id: "SVELTE-ENV-001".to_string(),
                    cwe: Some("CWE-200".to_string()),
                    owasp: Some("A02:2021".to_string()),
                    title: "Public Environment Secret".to_string(),
                    severity: Severity::High,
                    category: "security".to_string(),
                    description: "Secret value in PUBLIC_ environment variable - will be exposed to client".to_string(),
                    file_path: source_file.path.to_string_lossy().to_string(),
                    line_number: line_num,
                    column_start: captures.get(0).map(|m| m.start()).unwrap_or(0),
                    column_end: captures.get(0).map(|m| m.end()).unwrap_or(0),
                    source_code: trimmed_line.to_string(),
                    recommendation: "Never put secrets in PUBLIC_ environment variables. Use server-side environment variables instead.".to_string(),
                    references: vec!["https://kit.svelte.dev/docs/modules#$env-static-public".to_string()],
                    confidence: 0.85,
                });
            }

            // Check for WebSocket origin bypass
            if let Some(captures) = SVELTE_PATTERNS["websocket_origin_bypass"].captures(line) {
                vulnerabilities.push(Vulnerability {
                    id: "SVELTE-WS-001".to_string(),
                    cwe: Some("CWE-346".to_string()),
                    owasp: Some("A05:2021".to_string()),
                    title: "Origin Validation Bypass".to_string(),
                    severity: Severity::Medium,
                    category: "security".to_string(),
                    description: "WebSocket connection without origin validation".to_string(),
                    file_path: source_file.path.to_string_lossy().to_string(),
                    line_number: line_num,
                    column_start: captures.get(0).map(|m| m.start()).unwrap_or(0),
                    column_end: captures.get(0).map(|m| m.end()).unwrap_or(0),
                    source_code: trimmed_line.to_string(),
                    recommendation: "Implement origin validation for WebSocket connections to prevent CSRF attacks.".to_string(),
                    references: vec!["https://cheatsheetseries.owasp.org/cheatsheets/HTML5_Security_Cheat_Sheet.html#websockets".to_string()],
                    confidence: 0.75,
                });
            }
        }

        Ok(vulnerabilities)
    }
}

impl Default for SvelteRules {
    fn default() -> Self {
        Self::new()
    }
}

impl RuleSet for SvelteRules {
    fn analyze(&self, source_file: &SourceFile, _ast: &ParsedAst) -> Result<Vec<Vulnerability>> {
        self.analyze_source(source_file)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::Language;
    use std::path::PathBuf;

    #[test]
    fn test_svelte_unsafe_html_binding() {
        let rules = SvelteRules::new();
        let source_file = SourceFile {
            path: PathBuf::from("test.svelte"),
            content: r#"
<script>
  export let userContent;
</script>

<div>{@html userContent}</div>
"#.to_string(),
            language: Language::Javascript,
        };

        let result = rules.analyze_source(&source_file).unwrap();
        assert!(result.iter().any(|v| v.id == "SVELTE-XSS-001"));
    }

    #[test]
    fn test_svelte_reactive_eval_risk() {
        let rules = SvelteRules::new();
        let source_file = SourceFile {
            path: PathBuf::from("test.svelte"),
            content: r#"
<script>
  let code;
  $: result = eval(code);
</script>
"#.to_string(),
            language: Language::Javascript,
        };

        let result = rules.analyze_source(&source_file).unwrap();
        assert!(result.iter().any(|v| v.id == "SVELTE-REACTIVE-002"));
    }

    #[test]
    fn test_sveltekit_form_action_no_validation() {
        let rules = SvelteRules::new();
        let source_file = SourceFile {
            path: PathBuf::from("test.js"),
            content: r#"
export const actions = {
  default: async ({ request }) => {
    const data = await request.formData();
    return { success: true };
  }
};
"#.to_string(),
            language: Language::Javascript,
        };

        let result = rules.analyze_source(&source_file).unwrap();
        assert!(result.iter().any(|v| v.id == "SVELTE-KIT-001"));
    }

    #[test]
    fn test_svelte_hardcoded_secrets() {
        let rules = SvelteRules::new();
        let source_file = SourceFile {
            path: PathBuf::from("test.svelte"),
            content: r#"
<script>
  const API_KEY = "sk_live_1234567890abcdef";
  const SECRET = "super_secret_key_123";
</script>
"#.to_string(),
            language: Language::Javascript,
        };

        let result = rules.analyze_source(&source_file).unwrap();
        assert!(result.iter().any(|v| v.id == "SVELTE-SECRET-001"));
    }
}