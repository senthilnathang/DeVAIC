use crate::{
    error::Result,
    parsers::{ParsedAst, SourceFile},
    Language, Severity, Vulnerability,
    rules::create_vulnerability,
};
use tree_sitter::Node;

pub struct AstAnalyzer;

impl AstAnalyzer {
    pub fn new() -> Self {
        Self
    }
    
    pub fn analyze_with_ast(&self, source_file: &SourceFile, ast: &ParsedAst) -> Result<Vec<Vulnerability>> {
        let mut vulnerabilities = Vec::new();
        
        if let Some(tree_ref) = &ast.tree {
            let tree = tree_ref.borrow();
            let root_node = tree.root_node();
            
            match source_file.language {
                Language::Rust => {
                    vulnerabilities.extend(self.analyze_rust_ast(&root_node, source_file, &ast.source)?);
                }
                Language::Go => {
                    vulnerabilities.extend(self.analyze_go_ast(&root_node, source_file, &ast.source)?);
                }
                Language::Swift => {
                    vulnerabilities.extend(self.analyze_swift_ast(&root_node, source_file, &ast.source)?);
                }
                Language::Kotlin => {
                    vulnerabilities.extend(self.analyze_kotlin_ast(&root_node, source_file, &ast.source)?);
                }
                _ => {
                    // For other languages, use generic AST analysis
                    vulnerabilities.extend(self.analyze_generic_ast(&root_node, source_file, &ast.source)?);
                }
            }
        }
        
        Ok(vulnerabilities)
    }
    
    fn analyze_rust_ast(&self, root: &Node, source_file: &SourceFile, source: &str) -> Result<Vec<Vulnerability>> {
        let mut vulnerabilities = Vec::new();
        
        // Analyze unsafe blocks with context
        self.traverse_node(root, &mut |node| {
            match node.kind() {
                "unsafe_block" => {
                    let start_pos = node.start_position();
                    let line_num = start_pos.row + 1;
                    let source_code = self.get_node_text(node, source);
                    
                    // Check for specific unsafe operations
                    if source_code.contains("transmute") || source_code.contains("*") {
                        vulnerabilities.push(create_vulnerability(
                            "RUST-AST-UNSAFE-001",
                            Some("CWE-119"),
                            "Unsafe Memory Operation",
                            Severity::High,
                            "memory",
                            "Unsafe memory operation detected in unsafe block",
                            &source_file.path.to_string_lossy(),
                            line_num,
                            start_pos.column,
                            &source_code,
                            "Review unsafe operations and ensure memory safety",
                        ));
                    }
                }
                "macro_invocation" => {
                    let macro_name = self.get_node_text(node, source);
                    if macro_name.starts_with("panic!") || macro_name.starts_with("unwrap") {
                        let start_pos = node.start_position();
                        let line_num = start_pos.row + 1;
                        
                        vulnerabilities.push(create_vulnerability(
                            "RUST-AST-PANIC-001",
                            Some("CWE-248"),
                            "Panic in Code",
                            Severity::Medium,
                            "reliability",
                            "Code that can panic detected",
                            &source_file.path.to_string_lossy(),
                            line_num,
                            start_pos.column,
                            &macro_name,
                            "Use proper error handling instead of panicking",
                        ));
                    }
                }
                _ => {}
            }
        });
        
        Ok(vulnerabilities)
    }
    
    fn analyze_go_ast(&self, root: &Node, source_file: &SourceFile, source: &str) -> Result<Vec<Vulnerability>> {
        let mut vulnerabilities = Vec::new();
        
        // Analyze Go-specific patterns
        self.traverse_node(root, &mut |node| {
            match node.kind() {
                "go_statement" => {
                    let start_pos = node.start_position();
                    let line_num = start_pos.row + 1;
                    let source_code = self.get_node_text(node, source);
                    
                    vulnerabilities.push(create_vulnerability(
                        "GO-AST-GOROUTINE-001",
                        Some("CWE-362"),
                        "Goroutine Usage",
                        Severity::Medium,
                        "concurrency",
                        "Goroutine usage detected - ensure proper synchronization",
                        &source_file.path.to_string_lossy(),
                        line_num,
                        start_pos.column,
                        &source_code,
                        "Use channels or sync primitives for safe concurrent access",
                    ));
                }
                "call_expression" => {
                    let call_text = self.get_node_text(node, source);
                    if call_text.contains("exec.Command") {
                        let start_pos = node.start_position();
                        let line_num = start_pos.row + 1;
                        
                        vulnerabilities.push(create_vulnerability(
                            "GO-AST-EXEC-001",
                            Some("CWE-78"),
                            "Command Execution",
                            Severity::High,
                            "injection",
                            "Command execution detected - validate inputs",
                            &source_file.path.to_string_lossy(),
                            line_num,
                            start_pos.column,
                            &call_text,
                            "Validate and sanitize all inputs to command execution",
                        ));
                    }
                }
                _ => {}
            }
        });
        
        Ok(vulnerabilities)
    }
    
    fn analyze_swift_ast(&self, root: &Node, source_file: &SourceFile, source: &str) -> Result<Vec<Vulnerability>> {
        let mut vulnerabilities = Vec::new();
        
        // Analyze Swift-specific patterns
        self.traverse_node(root, &mut |node| {
            match node.kind() {
                "force_unwrap_expression" => {
                    let start_pos = node.start_position();
                    let line_num = start_pos.row + 1;
                    let source_code = self.get_node_text(node, source);
                    
                    vulnerabilities.push(create_vulnerability(
                        "SWIFT-AST-UNWRAP-001",
                        Some("CWE-476"),
                        "Force Unwrapping",
                        Severity::Medium,
                        "reliability",
                        "Force unwrapping detected - potential crash risk",
                        &source_file.path.to_string_lossy(),
                        line_num,
                        start_pos.column,
                        &source_code,
                        "Use optional binding or guard statements instead",
                    ));
                }
                "call_expression" => {
                    let call_text = self.get_node_text(node, source);
                    if call_text.contains("evaluateJavaScript") {
                        let start_pos = node.start_position();
                        let line_num = start_pos.row + 1;
                        
                        vulnerabilities.push(create_vulnerability(
                            "SWIFT-AST-JS-001",
                            Some("CWE-79"),
                            "JavaScript Evaluation",
                            Severity::High,
                            "injection",
                            "JavaScript evaluation in WebView detected",
                            &source_file.path.to_string_lossy(),
                            line_num,
                            start_pos.column,
                            &call_text,
                            "Sanitize JavaScript code and validate inputs",
                        ));
                    }
                }
                _ => {}
            }
        });
        
        Ok(vulnerabilities)
    }
    
    fn analyze_kotlin_ast(&self, root: &Node, source_file: &SourceFile, source: &str) -> Result<Vec<Vulnerability>> {
        let mut vulnerabilities = Vec::new();
        
        // Analyze Kotlin-specific patterns
        self.traverse_node(root, &mut |node| {
            match node.kind() {
                "call_expression" => {
                    let call_text = self.get_node_text(node, source);
                    if call_text.contains("execSQL") || call_text.contains("rawQuery") {
                        let start_pos = node.start_position();
                        let line_num = start_pos.row + 1;
                        
                        vulnerabilities.push(create_vulnerability(
                            "KOTLIN-AST-SQL-001",
                            Some("CWE-89"),
                            "SQL Query",
                            Severity::High,
                            "injection",
                            "SQL query detected - check for injection vulnerabilities",
                            &source_file.path.to_string_lossy(),
                            line_num,
                            start_pos.column,
                            &call_text,
                            "Use parameterized queries to prevent SQL injection",
                        ));
                    }
                }
                _ => {}
            }
        });
        
        Ok(vulnerabilities)
    }
    
    fn analyze_generic_ast(&self, root: &Node, source_file: &SourceFile, source: &str) -> Result<Vec<Vulnerability>> {
        let mut vulnerabilities = Vec::new();
        
        // Generic AST analysis for function calls, string literals, etc.
        self.traverse_node(root, &mut |node| {
            match node.kind() {
                "string_literal" | "string" => {
                    let text = self.get_node_text(node, source);
                    if text.len() > 50 && (text.contains("password") || text.contains("secret") || text.contains("key")) {
                        let start_pos = node.start_position();
                        let line_num = start_pos.row + 1;
                        
                        vulnerabilities.push(create_vulnerability(
                            "AST-SECRET-001",
                            Some("CWE-798"),
                            "Potential Hardcoded Secret",
                            Severity::Medium,
                            "secrets",
                            "Potential hardcoded secret detected in string literal",
                            &source_file.path.to_string_lossy(),
                            line_num,
                            start_pos.column,
                            &text,
                            "Move secrets to environment variables or secure storage",
                        ));
                    }
                }
                _ => {}
            }
        });
        
        Ok(vulnerabilities)
    }
    
    fn traverse_node<F>(&self, node: &Node, callback: &mut F)
    where
        F: FnMut(&Node),
    {
        callback(node);
        
        let mut cursor = node.walk();
        for child in node.children(&mut cursor) {
            self.traverse_node(&child, callback);
        }
    }
    
    fn get_node_text(&self, node: &Node, source: &str) -> String {
        let start_byte = node.start_byte();
        let end_byte = node.end_byte();
        
        if end_byte <= source.len() {
            source[start_byte..end_byte].to_string()
        } else {
            String::new()
        }
    }
}