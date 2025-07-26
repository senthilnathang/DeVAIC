/// Astro Framework Security Rules for DeVAIC
/// 
/// This module implements security analysis rules specific to Astro,
/// a modern static site generator with hybrid rendering capabilities.
/// 
/// Astro security concerns include:
/// - Component security (Astro components, framework components)
/// - Server-side rendering (SSR) security
/// - Static site generation (SSG) security
/// - API endpoints security
/// - Client-side hydration security
/// - Content collections security
/// - Middleware security

use crate::parsers::{SourceFile, ParsedAst};
use crate::{Vulnerability, Severity};
use crate::error::Result;
use super::RuleSet;
use regex::Regex;
use std::collections::HashMap;
use lazy_static::lazy_static;

lazy_static! {
    /// Astro-specific security patterns
    static ref ASTRO_PATTERNS: HashMap<&'static str, Regex> = {
        let mut m = HashMap::new();
        
        // Component security patterns
        m.insert("unsafe_html_fragment",
            Regex::new(r"(?i)<Fragment\s+set:html=\{[^}]*\}").unwrap()
        );
        
        m.insert("unescaped_user_content",
            Regex::new(r"(?i)set:html=\{[^}]*(?:params|query|form|user|input|request)[^}]*\}").unwrap()
        );
        
        m.insert("dangerous_component_prop",
            Regex::new(r"(?i)<\w+[^>]*\s+(?:innerHTML|dangerouslySetInnerHTML)=\{[^}]*\}").unwrap()
        );
        
        // Astro component script security
        m.insert("frontmatter_code_injection",
            Regex::new(r"(?i)---[\s\S]*?(?:eval|Function|setTimeout|setInterval)\s*\([\s\S]*?---").unwrap()
        );
        
        m.insert("frontmatter_hardcoded_secrets",
            Regex::new(r#"(?i)---[\s\S]*?(?:API_KEY|SECRET|TOKEN|PASSWORD)\s*=\s*['"][^'"]{10,}['"][\s\S]*?---"#).unwrap()
        );
        
        m.insert("unsafe_astro_request_access",
            Regex::new(r"(?i)---[\s\S]*?Astro\.request\.(?:url|headers|body)[\s\S]*?---").unwrap()
        );
        
        // Client-side hydration security
        m.insert("unsafe_client_directive",
            Regex::new(r"(?i)client:(?:load|idle|visible)\s*=\{[^}]*(?:eval|Function|innerHTML)[^}]*\}").unwrap()
        );
        
        m.insert("hydration_xss_risk",
            Regex::new(r"(?i)client:(?:load|idle|visible|media).*\{[^}]*(?:\+|template|`|\$\{)[^}]*\}").unwrap()
        );
        
        // API endpoint security
        m.insert("api_endpoint_no_validation",
            Regex::new(r"(?i)export\s+async\s+function\s+(GET|POST|PUT|DELETE|PATCH)").unwrap()
        );
        
        m.insert("api_endpoint_unsafe_response",
            Regex::new(r"(?i)return\s+new\s+Response\s*\([^)]*(?:\+|template|`|\$\{)[^)]*\)").unwrap()
        );
        
        m.insert("api_cors_wildcard",
            Regex::new(r#"(?i)Access-Control-Allow-Origin['"]\s*:\s*['"]?\*['"]?"#).unwrap()
        );
        
        // Server-side rendering security
        m.insert("ssr_server_leak",
            Regex::new(r"(?i)---[\s\S]*?if\s*\([^)]*import\.meta\.env\.SSR[^)]*\)[^{]*\{[^}]*(?:API_KEY|SECRET|PASSWORD|TOKEN)[\s\S]*?---").unwrap()
        );
        
        m.insert("ssr_environment_exposure",
            Regex::new(r"(?i)import\.meta\.env\.(?:SECRET|PRIVATE|API_KEY|TOKEN|PASSWORD)").unwrap()
        );
        
        // Content collections security
        m.insert("unsafe_content_query",
            Regex::new(r"(?i)getCollection\s*\([^)]*\)\s*\.filter\s*\([^)]*(?:eval|Function)[^)]*\)").unwrap()
        );
        
        m.insert("content_xss_risk",
            Regex::new(r"(?i)entry\.data\.(?:content|body|description).*set:html").unwrap()
        );
        
        // Middleware security
        m.insert("middleware_no_auth",
            Regex::new(r"(?i)export\s+function\s+onRequest\s*\([^)]*\)\s*\{[^}]*next\(\)").unwrap()
        );
        
        m.insert("middleware_unsafe_redirect",
            Regex::new(r"(?i)return\s+(?:Response\.)?redirect\s*\([^)]*(?:\+|template|`|\$\{)[^)]*\)").unwrap()
        );
        
        // Static generation security
        m.insert("getstaticpaths_injection",
            Regex::new(r"(?i)export\s+async\s+function\s+getStaticPaths\s*\([^)]*\)\s*\{[^}]*(?:eval|Function)[^}]*\}").unwrap()
        );
        
        m.insert("dynamic_route_no_validation",
            Regex::new(r"(?i)params\.[^.]*").unwrap()
        );
        
        // Image optimization security
        m.insert("unsafe_image_src",
            Regex::new(r"(?i)<Image[^>]*src=\{[^}]*(?:\+|template|`|\$\{)[^}]*\}").unwrap()
        );
        
        m.insert("image_path_traversal",
            Regex::new(r#"(?i)<Image[^>]*src=['"][^'"]*\.\./"#).unwrap()
        );
        
        // Configuration security
        m.insert("astro_config_secrets",
            Regex::new(r#"(?i)(?:apiKey|secret|password|token)\s*:\s*['"][^'"]{10,}['"]"#).unwrap()
        );
        
        m.insert("unsafe_integration_config",
            Regex::new(r"(?i)integrations:\s*\[[^]]*eval|Function[^]]*\]").unwrap()
        );
        
        // View transitions security
        m.insert("view_transition_xss",
            Regex::new(r"(?i)transition:(?:name|animate)=\{[^}]*(?:\+|template|`|\$\{)[^}]*\}").unwrap()
        );
        
        // Script and style security
        m.insert("inline_script_injection",
            Regex::new(r"(?i)<script[^>]*>[^<]*(?:\+|template|`|\$\{)[^<]*</script>").unwrap()
        );
        
        m.insert("style_injection",
            Regex::new(r"(?i)<style[^>]*>[^<]*(?:\+|template|`|\$\{)[^<]*</style>").unwrap()
        );
        
        // Import security
        m.insert("dynamic_import_injection",
            Regex::new(r"(?i)import\s*\([^)]*(?:\+|template|`|\$\{)[^)]*\)").unwrap()
        );
        
        m.insert("unsafe_module_import",
            Regex::new(r#"(?i)import\s+.*\s+from\s+['"][^'"]*(?:\+|template|`|\$\{)"#).unwrap()
        );

        m
    };
}

/// Astro security rules implementation
pub struct AstroRules;

impl AstroRules {
    pub fn new() -> Self {
        Self
    }

    /// Analyze Astro source code for security vulnerabilities
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

            // Check for unsafe HTML fragment
            if let Some(captures) = ASTRO_PATTERNS["unsafe_html_fragment"].captures(line) {
                vulnerabilities.push(Vulnerability {
id: "ASTRO-XSS-001".to_string(),
                    cwe: Some("CWE-79".to_string()),
                    title: "Cross-Site Scripting (XSS)".to_string(),
                    severity: Severity::High,
                    category: "security".to_string(),
                    description: "Unsafe Fragment with set:html - XSS vulnerability".to_string(),
                    file_path: source_file.path.to_string_lossy().to_string(),
                    line_number: line_num,
                    column_start: captures.get(0).map(|m| m.start()).unwrap_or(0),
                    column_end: captures.get(0).map(|m| m.end()).unwrap_or(0),
                    source_code: trimmed_line.to_string(),
                    recommendation: "Sanitize HTML content before using set:html or use safe alternatives.".to_string(),
                    owasp: None,
                    references: vec![],
                    confidence: 0.8,
                });
            }

            // Check for unescaped user content
            if let Some(captures) = ASTRO_PATTERNS["unescaped_user_content"].captures(line) {
                vulnerabilities.push(Vulnerability {
id: "ASTRO-XSS-002".to_string(),
                    cwe: Some("CWE-79".to_string()),
                    title: "Unescaped User Input".to_string(),
                    severity: Severity::Critical,
                    category: "security".to_string(),
                    description: "User input directly used in set:html - critical XSS vulnerability".to_string(),
                    file_path: source_file.path.to_string_lossy().to_string(),
                    line_number: line_num,
                    column_start: captures.get(0).map(|m| m.start()).unwrap_or(0),
                    column_end: captures.get(0).map(|m| m.end()).unwrap_or(0),
                    source_code: trimmed_line.to_string(),
                    recommendation: "Never use user input directly in set:html. Implement proper sanitization.".to_string(),
                    owasp: None,
                    references: vec![],
                    confidence: 0.9,
                });
            }

            // Check for frontmatter code injection
            if let Some(captures) = ASTRO_PATTERNS["frontmatter_code_injection"].captures(&source_file.content) {
                vulnerabilities.push(Vulnerability {
id: "ASTRO-INJECT-001".to_string(),
                    cwe: Some("CWE-95".to_string()),
                    title: "Code Injection".to_string(),
                    severity: Severity::Critical,
                    category: "security".to_string(),
                    description: "Code injection risk in Astro frontmatter".to_string(),
                    file_path: source_file.path.to_string_lossy().to_string(),
                    line_number: line_num,
                    column_start: captures.get(0).map(|m| m.start()).unwrap_or(0),
                    column_end: captures.get(0).map(|m| m.end()).unwrap_or(0),
                    source_code: trimmed_line.to_string(),
                    recommendation: "Avoid eval, Function, and timer functions with dynamic content in frontmatter.".to_string(),
                    owasp: None,
                    references: vec![],
                    confidence: 0.9,
                });
            }

            // Check for frontmatter hardcoded secrets
            if let Some(captures) = ASTRO_PATTERNS["frontmatter_hardcoded_secrets"].captures(&source_file.content) {
                vulnerabilities.push(Vulnerability {
id: "ASTRO-SECRET-001".to_string(),
                    cwe: Some("CWE-798".to_string()),
                    title: "Hardcoded Secrets".to_string(),
                    severity: Severity::Critical,
                    category: "authentication".to_string(),
                    description: "Hardcoded secrets in Astro frontmatter".to_string(),
                    file_path: source_file.path.to_string_lossy().to_string(),
                    line_number: line_num,
                    column_start: captures.get(0).map(|m| m.start()).unwrap_or(0),
                    column_end: captures.get(0).map(|m| m.end()).unwrap_or(0),
                    source_code: trimmed_line.to_string(),
                    recommendation: "Move secrets to environment variables and use proper secret management.".to_string(),
                    owasp: None,
                    references: vec![],
                    confidence: 0.9,
                });
            }

            // Check for API endpoint without validation
            if let Some(captures) = ASTRO_PATTERNS["api_endpoint_no_validation"].captures(line) {
                vulnerabilities.push(Vulnerability {
id: "ASTRO-API-001".to_string(),
                    cwe: Some("CWE-20".to_string()),
                    title: "API Endpoint Without Validation".to_string(),
                    severity: Severity::High,
                    category: "security".to_string(),
                    description: "Astro API endpoint processing request data without validation".to_string(),
                    file_path: source_file.path.to_string_lossy().to_string(),
                    line_number: line_num,
                    column_start: captures.get(0).map(|m| m.start()).unwrap_or(0),
                    column_end: captures.get(0).map(|m| m.end()).unwrap_or(0),
                    source_code: trimmed_line.to_string(),
                    recommendation: "Validate and sanitize all request data in API endpoints.".to_string(),
                    owasp: None,
                    references: vec![],
                    confidence: 0.8,
                });
            }

            // Check for unsafe client directive
            if let Some(captures) = ASTRO_PATTERNS["unsafe_client_directive"].captures(line) {
                vulnerabilities.push(Vulnerability {
id: "ASTRO-HYDRATION-001".to_string(),
                    cwe: Some("CWE-79".to_string()),
                    title: "Client Hydration XSS".to_string(),
                    severity: Severity::High,
                    category: "security".to_string(),
                    description: "Unsafe operations in client hydration directive".to_string(),
                    file_path: source_file.path.to_string_lossy().to_string(),
                    line_number: line_num,
                    column_start: captures.get(0).map(|m| m.start()).unwrap_or(0),
                    column_end: captures.get(0).map(|m| m.end()).unwrap_or(0),
                    source_code: trimmed_line.to_string(),
                    recommendation: "Avoid unsafe operations in client directives. Use safe hydration patterns.".to_string(),
                    owasp: None,
                    references: vec![],
                    confidence: 0.8,
                });
            }

            // Check for SSR environment exposure
            if let Some(captures) = ASTRO_PATTERNS["ssr_environment_exposure"].captures(line) {
                vulnerabilities.push(Vulnerability {
                    id: "ASTRO-ENV-001".to_string(),
                    cwe: Some("CWE-200".to_string()),
                    title: "Environment Variable Exposure".to_string(),
                    severity: Severity::High,
                    category: "security".to_string(),
                    description: "Private environment variable potentially exposed to client".to_string(),
                    file_path: source_file.path.to_string_lossy().to_string(),
                    line_number: line_num,
                    column_start: captures.get(0).map(|m| m.start()).unwrap_or(0),
                    column_end: captures.get(0).map(|m| m.end()).unwrap_or(0),
                    source_code: trimmed_line.to_string(),
                    recommendation: "Use PUBLIC_ prefix only for client-safe environment variables.".to_string(),
                    owasp: Some("A03:2021 – Injection".to_string()),
                    references: vec!["https://cwe.mitre.org/data/definitions/200.html".to_string()],
                    confidence: 0.8,
                });
            }

            // Check for middleware without auth
            if let Some(captures) = ASTRO_PATTERNS["middleware_no_auth"].captures(line) {
                vulnerabilities.push(Vulnerability {
id: "ASTRO-MIDDLEWARE-001".to_string(),
                    cwe: Some("CWE-862".to_string()),
                    title: "Missing Authorization".to_string(),
                    severity: Severity::Medium,
                    category: "security".to_string(),
                    description: "Astro middleware without authorization checks".to_string(),
                    file_path: source_file.path.to_string_lossy().to_string(),
                    line_number: line_num,
                    column_start: captures.get(0).map(|m| m.start()).unwrap_or(0),
                    column_end: captures.get(0).map(|m| m.end()).unwrap_or(0),
                    source_code: trimmed_line.to_string(),
                    recommendation: "Implement proper authentication and authorization in middleware.".to_string(),
                    owasp: None,
                    references: vec![],
                    confidence: 0.75,
                });
            }

            // Check for unsafe image source
            if let Some(captures) = ASTRO_PATTERNS["unsafe_image_src"].captures(line) {
                vulnerabilities.push(Vulnerability {
id: "ASTRO-IMAGE-001".to_string(),
                    cwe: Some("CWE-79".to_string()),
                    title: "Image Source Injection".to_string(),
                    severity: Severity::Medium,
                    category: "security".to_string(),
                    description: "Dynamic image source - potential XSS or path traversal".to_string(),
                    file_path: source_file.path.to_string_lossy().to_string(),
                    line_number: line_num,
                    column_start: captures.get(0).map(|m| m.start()).unwrap_or(0),
                    column_end: captures.get(0).map(|m| m.end()).unwrap_or(0),
                    source_code: trimmed_line.to_string(),
                    recommendation: "Validate image sources and use allowlisted domains.".to_string(),
                    owasp: None,
                    references: vec![],
                    confidence: 0.75,
                });
            }

            // Check for image path traversal
            if let Some(captures) = ASTRO_PATTERNS["image_path_traversal"].captures(line) {
                vulnerabilities.push(Vulnerability {
id: "ASTRO-PATH-001".to_string(),
                    cwe: Some("CWE-22".to_string()),
                    title: "Path Traversal".to_string(),
                    severity: Severity::High,
                    category: "security".to_string(),
                    description: "Image path contains directory traversal pattern".to_string(),
                    file_path: source_file.path.to_string_lossy().to_string(),
                    line_number: line_num,
                    column_start: captures.get(0).map(|m| m.start()).unwrap_or(0),
                    column_end: captures.get(0).map(|m| m.end()).unwrap_or(0),
                    source_code: trimmed_line.to_string(),
                    recommendation: "Use absolute paths or properly validate relative paths.".to_string(),
                    owasp: None,
                    references: vec![],
                    confidence: 0.8,
                });
            }

            // Check for dynamic route without validation
            if let Some(captures) = ASTRO_PATTERNS["dynamic_route_no_validation"].captures(line) {
                vulnerabilities.push(Vulnerability {
id: "ASTRO-ROUTE-001".to_string(),
                    cwe: Some("CWE-20".to_string()),
                    title: "Route Parameter Injection".to_string(),
                    severity: Severity::Medium,
                    category: "security".to_string(),
                    description: "Route parameter used without validation".to_string(),
                    file_path: source_file.path.to_string_lossy().to_string(),
                    line_number: line_num,
                    column_start: captures.get(0).map(|m| m.start()).unwrap_or(0),
                    column_end: captures.get(0).map(|m| m.end()).unwrap_or(0),
                    source_code: trimmed_line.to_string(),
                    recommendation: "Validate and sanitize route parameters before use.".to_string(),
                    owasp: None,
                    references: vec![],
                    confidence: 0.75,
                });
            }

            // Check for inline script injection
            if let Some(captures) = ASTRO_PATTERNS["inline_script_injection"].captures(line) {
                vulnerabilities.push(Vulnerability {
id: "ASTRO-SCRIPT-001".to_string(),
                    cwe: Some("CWE-79".to_string()),
                    title: "Script Injection".to_string(),
                    severity: Severity::High,
                    category: "security".to_string(),
                    description: "Dynamic content in inline script - XSS risk".to_string(),
                    file_path: source_file.path.to_string_lossy().to_string(),
                    line_number: line_num,
                    column_start: captures.get(0).map(|m| m.start()).unwrap_or(0),
                    column_end: captures.get(0).map(|m| m.end()).unwrap_or(0),
                    source_code: trimmed_line.to_string(),
                    recommendation: "Avoid dynamic content in inline scripts. Use external scripts or safe data passing.".to_string(),
                    owasp: None,
                    references: vec![],
                    confidence: 0.8,
                });
            }
        }

        Ok(vulnerabilities)
    }
}

impl Default for AstroRules {
    fn default() -> Self {
        Self::new()
    }
}

impl RuleSet for AstroRules {
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
    fn test_astro_unsafe_html_fragment() {
        let rules = AstroRules::new();
        let source_file = SourceFile {
            path: PathBuf::from("test.astro"),
            content: r#"
---
const userContent = "<script>alert('xss')</script>";
---

<Fragment set:html={userContent} />
"#.to_string(),
            language: Language::Javascript,
        };

        let result = rules.analyze_source(&source_file).unwrap();
        assert!(result.iter().any(|v| v.id == "ASTRO-XSS-001"));
    }

    #[test]
    fn test_astro_api_endpoint_no_validation() {
        let rules = AstroRules::new();
        let source_file = SourceFile {
            path: PathBuf::from("api/test.ts"),
            content: r#"
export async function POST({ request }) {
  const data = await request.json();
  return new Response(JSON.stringify({ data }));
}
"#.to_string(),
            language: Language::TypeScript,
        };

        let result = rules.analyze_source(&source_file).unwrap();
        assert!(result.iter().any(|v| v.id == "ASTRO-API-001"));
    }

    #[test]
    fn test_astro_image_path_traversal() {
        let rules = AstroRules::new();
        let source_file = SourceFile {
            path: PathBuf::from("test.astro"),
            content: r#"
<Image src="../../../etc/passwd" alt="test" />
"#.to_string(),
            language: Language::Javascript,
        };

        let result = rules.analyze_source(&source_file).unwrap();
        assert!(result.iter().any(|v| v.id == "ASTRO-PATH-001"));
    }
}