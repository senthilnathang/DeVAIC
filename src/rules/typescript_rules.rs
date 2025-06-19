use super::{create_vulnerability, RuleSet};
use crate::{
    error::Result,
    parsers::{ParsedAst, Parser, SourceFile},
    Severity, Vulnerability,
};
use regex::Regex;
use tree_sitter::Node;

pub struct TypeScriptRules {
    xss_patterns: Vec<Regex>,
    prototype_pollution_patterns: Vec<Regex>,
    eval_patterns: Vec<Regex>,
    dom_patterns: Vec<Regex>,
    crypto_patterns: Vec<Regex>,
    hardcoded_secrets_patterns: Vec<Regex>,
    type_assertion_patterns: Vec<Regex>,
    any_type_patterns: Vec<Regex>,
}

impl TypeScriptRules {
    pub fn new() -> Self {
        Self {
            xss_patterns: vec![
                Regex::new(r"\.innerHTML\s*=\s*[^;]*\+").unwrap(),
                Regex::new(r"\.outerHTML\s*=\s*[^;]*\+").unwrap(),
                Regex::new(r"document\.write\s*\(\s*[^)]*\+").unwrap(),
                Regex::new(r"document\.writeln\s*\(\s*[^)]*\+").unwrap(),
                Regex::new(r"\.insertAdjacentHTML\s*\(\s*[^,]*,\s*[^)]*\+").unwrap(),
            ],
            prototype_pollution_patterns: vec![
                Regex::new(r"\[['`]__proto__['`]\]").unwrap(),
                Regex::new(r"\.constructor\.prototype").unwrap(),
                Regex::new(r"Object\.setPrototypeOf\s*\(").unwrap(),
                Regex::new(r"\[['`]prototype['`]\]").unwrap(),
            ],
            eval_patterns: vec![
                Regex::new(r"\beval\s*\(").unwrap(),
                Regex::new(r"new\s+Function\s*\(").unwrap(),
                Regex::new(r"setTimeout\s*\(\s*[`'\x22]").unwrap(),
                Regex::new(r"setInterval\s*\(\s*[`'\x22]").unwrap(),
            ],
            dom_patterns: vec![
                Regex::new(r"\.src\s*=\s*[^;]*\+").unwrap(),
                Regex::new(r"\.href\s*=\s*[^;]*\+").unwrap(),
                Regex::new(r"window\.location\s*=\s*[^;]*\+").unwrap(),
                Regex::new(r"location\.href\s*=\s*[^;]*\+").unwrap(),
            ],
            crypto_patterns: vec![
                Regex::new(r"Math\.random\s*\(\s*\)").unwrap(),
                Regex::new(r"new\s+Date\s*\(\s*\)\.getTime\s*\(\s*\)").unwrap(),
                Regex::new(r"btoa\s*\(").unwrap(),
                Regex::new(r"atob\s*\(").unwrap(),
            ],
            hardcoded_secrets_patterns: vec![
                Regex::new(r#"(?i)(password|pwd|secret|key|token|api_key)\s*[:=]\s*['"][^'"]{8,}['"]"#).unwrap(),
                Regex::new(r#"(?i)(bearer|basic)\s+['"][^'"]+['"]"#).unwrap(),
                Regex::new(r#"(?i)authorization\s*[:=]\s*['"][^'"]+['"]"#).unwrap(),
            ],
            type_assertion_patterns: vec![
                Regex::new(r"as\s+any\b").unwrap(),
                Regex::new(r"<any>").unwrap(),
                Regex::new(r"as\s+unknown\s+as\s+").unwrap(),
            ],
            any_type_patterns: vec![
                Regex::new(r":\s*any\b").unwrap(),
                Regex::new(r"<any>").unwrap(),
                Regex::new(r"Array<any>").unwrap(),
                Regex::new(r"Promise<any>").unwrap(),
            ],
        }
    }

    fn check_xss_vulnerabilities(&self, source_file: &SourceFile, ast: &ParsedAst) -> Result<Vec<Vulnerability>> {
        let mut vulnerabilities = Vec::new();
        let lines: Vec<&str> = ast.source.lines().collect();

        for (line_num, line) in lines.iter().enumerate() {
            for pattern in &self.xss_patterns {
                if pattern.is_match(line) {
                    vulnerabilities.push(create_vulnerability(
                        "TS001",
                        Severity::High,
                        "injection",
                        "Potential Cross-Site Scripting (XSS) vulnerability",
                        &source_file.path.to_string_lossy(),
                        line_num + 1,
                        0,
                        line,
                        "Sanitize user input before inserting into DOM. Use textContent instead of innerHTML where possible",
                    ));
                }
            }

            if line.contains("dangerouslySetInnerHTML") {
                vulnerabilities.push(create_vulnerability(
                    "TS002",
                    Severity::High,
                    "injection",
                    "React dangerouslySetInnerHTML usage detected",
                    &source_file.path.to_string_lossy(),
                    line_num + 1,
                    0,
                    line,
                    "Sanitize HTML content before using dangerouslySetInnerHTML or avoid it entirely",
                ));
            }
        }

        Ok(vulnerabilities)
    }

    fn check_prototype_pollution(&self, source_file: &SourceFile, ast: &ParsedAst) -> Result<Vec<Vulnerability>> {
        let mut vulnerabilities = Vec::new();
        let lines: Vec<&str> = ast.source.lines().collect();

        for (line_num, line) in lines.iter().enumerate() {
            for pattern in &self.prototype_pollution_patterns {
                if pattern.is_match(line) {
                    vulnerabilities.push(create_vulnerability(
                        "TS003",
                        Severity::High,
                        "injection",
                        "Potential prototype pollution vulnerability",
                        &source_file.path.to_string_lossy(),
                        line_num + 1,
                        0,
                        line,
                        "Avoid modifying Object.prototype or use Object.create(null) for safe objects",
                    ));
                }
            }

            if line.contains("JSON.parse") && (line.contains("req.body") || line.contains("request.body")) {
                vulnerabilities.push(create_vulnerability(
                    "TS004",
                    Severity::Medium,
                    "deserialization",
                    "Unsafe JSON parsing from user input",
                    &source_file.path.to_string_lossy(),
                    line_num + 1,
                    0,
                    line,
                    "Validate JSON structure and use schema validation before parsing user input",
                ));
            }
        }

        Ok(vulnerabilities)
    }

    fn check_eval_usage(&self, source_file: &SourceFile, ast: &ParsedAst) -> Result<Vec<Vulnerability>> {
        let mut vulnerabilities = Vec::new();
        let lines: Vec<&str> = ast.source.lines().collect();

        for (line_num, line) in lines.iter().enumerate() {
            for pattern in &self.eval_patterns {
                if pattern.is_match(line) {
                    let severity = if line.contains("eval(") {
                        Severity::Critical
                    } else {
                        Severity::High
                    };

                    vulnerabilities.push(create_vulnerability(
                        "TS005",
                        severity,
                        "injection",
                        "Code execution via eval() or Function constructor",
                        &source_file.path.to_string_lossy(),
                        line_num + 1,
                        0,
                        line,
                        "Avoid eval() and Function constructor. Use safer alternatives for dynamic code execution",
                    ));
                }
            }
        }

        Ok(vulnerabilities)
    }

    fn check_dom_manipulation(&self, source_file: &SourceFile, ast: &ParsedAst) -> Result<Vec<Vulnerability>> {
        let mut vulnerabilities = Vec::new();
        let lines: Vec<&str> = ast.source.lines().collect();

        for (line_num, line) in lines.iter().enumerate() {
            for pattern in &self.dom_patterns {
                if pattern.is_match(line) {
                    vulnerabilities.push(create_vulnerability(
                        "TS006",
                        Severity::Medium,
                        "injection",
                        "Unsafe DOM manipulation with user input",
                        &source_file.path.to_string_lossy(),
                        line_num + 1,
                        0,
                        line,
                        "Validate and sanitize URLs before setting src/href attributes",
                    ));
                }
            }

            if line.contains("document.cookie") && line.contains("=") {
                vulnerabilities.push(create_vulnerability(
                    "TS007",
                    Severity::Medium,
                    "authentication",
                    "Cookie manipulation detected",
                    &source_file.path.to_string_lossy(),
                    line_num + 1,
                    0,
                    line,
                    "Ensure cookies are set with secure flags (HttpOnly, Secure, SameSite)",
                ));
            }
        }

        Ok(vulnerabilities)
    }

    fn check_weak_cryptography(&self, source_file: &SourceFile, ast: &ParsedAst) -> Result<Vec<Vulnerability>> {
        let mut vulnerabilities = Vec::new();
        let lines: Vec<&str> = ast.source.lines().collect();

        for (line_num, line) in lines.iter().enumerate() {
            for pattern in &self.crypto_patterns {
                if pattern.is_match(line) {
                    let (id, message, recommendation) = if line.contains("Math.random") {
                        ("TS008", "Insecure random number generation", "Use crypto.getRandomValues() for cryptographic purposes")
                    } else if line.contains("getTime") {
                        ("TS009", "Timestamp used for randomness", "Use crypto.getRandomValues() instead of timestamps for security")
                    } else if line.contains("btoa") || line.contains("atob") {
                        ("TS010", "Base64 encoding/decoding is not encryption", "Use proper encryption algorithms, base64 is encoding not encryption")
                    } else {
                        ("TS011", "Weak cryptographic practice", "Use proper cryptographic libraries and methods")
                    };

                    vulnerabilities.push(create_vulnerability(
                        id,
                        Severity::Medium,
                        "cryptographic",
                        message,
                        &source_file.path.to_string_lossy(),
                        line_num + 1,
                        0,
                        line,
                        recommendation,
                    ));
                }
            }
        }

        Ok(vulnerabilities)
    }

    fn check_hardcoded_secrets(&self, source_file: &SourceFile, ast: &ParsedAst) -> Result<Vec<Vulnerability>> {
        let mut vulnerabilities = Vec::new();
        let lines: Vec<&str> = ast.source.lines().collect();

        for (line_num, line) in lines.iter().enumerate() {
            for pattern in &self.hardcoded_secrets_patterns {
                if pattern.is_match(line) {
                    vulnerabilities.push(create_vulnerability(
                        "TS012",
                        Severity::Critical,
                        "authentication",
                        "Hardcoded secrets or credentials detected",
                        &source_file.path.to_string_lossy(),
                        line_num + 1,
                        0,
                        line,
                        "Store secrets in environment variables or secure configuration, never in source code",
                    ));
                }
            }
        }

        Ok(vulnerabilities)
    }

    fn check_type_safety(&self, source_file: &SourceFile, ast: &ParsedAst) -> Result<Vec<Vulnerability>> {
        let mut vulnerabilities = Vec::new();
        let lines: Vec<&str> = ast.source.lines().collect();

        for (line_num, line) in lines.iter().enumerate() {
            for pattern in &self.type_assertion_patterns {
                if pattern.is_match(line) {
                    vulnerabilities.push(create_vulnerability(
                        "TS013",
                        Severity::Medium,
                        "validation",
                        "Unsafe type assertion bypassing TypeScript type checking",
                        &source_file.path.to_string_lossy(),
                        line_num + 1,
                        0,
                        line,
                        "Avoid 'as any' and unsafe type assertions. Use proper type guards and validation",
                    ));
                }
            }

            for pattern in &self.any_type_patterns {
                if pattern.is_match(line) && !line.trim_start().starts_with("//") {
                    vulnerabilities.push(create_vulnerability(
                        "TS014",
                        Severity::Low,
                        "validation",
                        "Usage of 'any' type defeats TypeScript benefits",
                        &source_file.path.to_string_lossy(),
                        line_num + 1,
                        0,
                        line,
                        "Use specific types instead of 'any' to maintain type safety",
                    ));
                }
            }
        }

        Ok(vulnerabilities)
    }

    fn check_security_headers(&self, source_file: &SourceFile, ast: &ParsedAst) -> Result<Vec<Vulnerability>> {
        let mut vulnerabilities = Vec::new();
        let content = &ast.source;

        if content.contains("express") && content.contains("app.use") {
            if !content.contains("helmet") && !content.contains("X-Frame-Options") {
                vulnerabilities.push(create_vulnerability(
                    "TS015",
                    Severity::Medium,
                    "validation",
                    "Missing security headers middleware",
                    &source_file.path.to_string_lossy(),
                    1,
                    0,
                    "Express app without security headers",
                    "Use helmet.js or manually set security headers (X-Frame-Options, CSP, etc.)",
                ));
            }
        }

        Ok(vulnerabilities)
    }

    fn check_unsafe_redirects(&self, source_file: &SourceFile, ast: &ParsedAst) -> Result<Vec<Vulnerability>> {
        let mut vulnerabilities = Vec::new();
        let root_node = ast.root_node();
        
        self.traverse_node(&root_node, &ast.source, |node, source_slice| {
            if node.kind() == "call_expression" {
                let expr_text = &source_slice[node.byte_range()];
                
                if expr_text.contains("res.redirect") && expr_text.contains("req.") {
                    let start_pos = node.start_position();
                    vulnerabilities.push(create_vulnerability(
                        "TS016",
                        Severity::Medium,
                        "validation",
                        "Open redirect vulnerability - user input in redirect",
                        &source_file.path.to_string_lossy(),
                        start_pos.row + 1,
                        start_pos.column,
                        expr_text,
                        "Validate redirect URLs against whitelist of allowed domains",
                    ));
                }
            }
        });

        Ok(vulnerabilities)
    }

    fn check_nosql_injection(&self, source_file: &SourceFile, ast: &ParsedAst) -> Result<Vec<Vulnerability>> {
        let mut vulnerabilities = Vec::new();
        let lines: Vec<&str> = ast.source.lines().collect();

        for (line_num, line) in lines.iter().enumerate() {
            if (line.contains("find(") || line.contains("findOne(") || line.contains("update(")) &&
               line.contains("req.") && !line.contains("$") {
                vulnerabilities.push(create_vulnerability(
                    "TS017",
                    Severity::High,
                    "injection",
                    "Potential NoSQL injection vulnerability",
                    &source_file.path.to_string_lossy(),
                    line_num + 1,
                    0,
                    line,
                    "Sanitize and validate user input for NoSQL queries. Use parameterized queries",
                ));
            }
        }

        Ok(vulnerabilities)
    }

    fn traverse_node<F>(&self, node: &Node, source: &str, mut callback: F)
    where
        F: FnMut(&Node, &str),
    {
        let mut cursor = node.walk();
        
        loop {
            callback(&cursor.node(), source);
            
            if cursor.goto_first_child() {
                continue;
            }
            
            if cursor.goto_next_sibling() {
                continue;
            }
            
            loop {
                if !cursor.goto_parent() {
                    return;
                }
                
                if cursor.goto_next_sibling() {
                    break;
                }
            }
        }
    }
}

impl RuleSet for TypeScriptRules {
    fn analyze(&self, source_file: &SourceFile, ast: &ParsedAst) -> Result<Vec<Vulnerability>> {
        let mut all_vulnerabilities = Vec::new();

        all_vulnerabilities.extend(self.check_xss_vulnerabilities(source_file, ast)?);
        all_vulnerabilities.extend(self.check_prototype_pollution(source_file, ast)?);
        all_vulnerabilities.extend(self.check_eval_usage(source_file, ast)?);
        all_vulnerabilities.extend(self.check_dom_manipulation(source_file, ast)?);
        all_vulnerabilities.extend(self.check_weak_cryptography(source_file, ast)?);
        all_vulnerabilities.extend(self.check_hardcoded_secrets(source_file, ast)?);
        all_vulnerabilities.extend(self.check_type_safety(source_file, ast)?);
        all_vulnerabilities.extend(self.check_security_headers(source_file, ast)?);
        all_vulnerabilities.extend(self.check_unsafe_redirects(source_file, ast)?);
        all_vulnerabilities.extend(self.check_nosql_injection(source_file, ast)?);

        Ok(all_vulnerabilities)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{parsers::typescript_parser::TypeScriptParser, Language};
    use std::path::PathBuf;

    #[test]
    fn test_type_assertion_detection() {
        let rules = TypeScriptRules::new();
        let parser = TypeScriptParser::new();
        
        let source = r#"
function processData(data: unknown) {
    const userData = data as any;
    return userData.sensitiveInfo;
}
"#;
        
        let source_file = SourceFile::new(
            PathBuf::from("test.ts"),
            source.to_string(),
            Language::TypeScript,
        );
        
        let ast = parser.parse(&source_file).unwrap();
        let vulnerabilities = rules.analyze(&source_file, &ast).unwrap();
        
        assert!(!vulnerabilities.is_empty());
        assert!(vulnerabilities.iter().any(|v| v.id == "TS013"));
    }

    #[test]
    fn test_any_type_detection() {
        let rules = TypeScriptRules::new();
        let parser = TypeScriptParser::new();
        
        let source = r#"
function processInput(input: any): void {
    console.log(input);
}
"#;
        
        let source_file = SourceFile::new(
            PathBuf::from("test.ts"),
            source.to_string(),
            Language::TypeScript,
        );
        
        let ast = parser.parse(&source_file).unwrap();
        let vulnerabilities = rules.analyze(&source_file, &ast).unwrap();
        
        assert!(!vulnerabilities.is_empty());
        assert!(vulnerabilities.iter().any(|v| v.id == "TS014"));
    }
}