pub mod c_parser;
pub mod cpp_parser;
pub mod python_parser;
pub mod java_parser;
pub mod javascript_parser;
pub mod typescript_parser;
pub mod go_parser;
pub mod php_parser;
pub mod ruby_parser;
pub mod kotlin_parser;
pub mod csharp_parser;
pub mod bash_parser;
pub mod scada_parser;
pub mod cobol_parser;
pub mod pascal_parser;
pub mod dart_parser;
pub mod swift_parser;
pub mod rust_parser;
pub mod delphi_parser;

use crate::{error::Result, Language};
use std::path::PathBuf;
use std::rc::Rc;
use std::cell::RefCell;
use tree_sitter::{Node, Tree};

#[derive(Debug, Clone)]
pub struct SourceFile {
    pub path: PathBuf,
    pub content: String,
    pub language: Language,
}

impl SourceFile {
    pub fn new(path: PathBuf, content: String, language: Language) -> Self {
        Self {
            path,
            content,
            language,
        }
    }
}

#[derive(Debug)]
pub struct ParsedAst {
    pub tree: Option<Rc<RefCell<Tree>>>,
    pub source: String,
    pub language: Option<Language>,
    pub parse_errors: Vec<String>,
    pub metadata: AstMetadata,
}

#[derive(Debug, Default)]
pub struct AstMetadata {
    pub parse_time_ms: Option<u64>,
    pub node_count: Option<usize>,
    pub max_depth: Option<usize>,
    pub has_syntax_errors: bool,
    pub file_size_bytes: usize,
}

impl Default for ParsedAst {
    fn default() -> Self {
        Self {
            tree: None,
            source: String::new(),
            language: None,
            parse_errors: Vec::new(),
            metadata: AstMetadata::default(),
        }
    }
}

impl ParsedAst {
    pub fn new(tree: Tree, source: String) -> Self {
        let has_errors = tree.root_node().has_error();
        let node_count = Self::count_nodes(&tree);
        let max_depth = Self::calculate_depth(&tree);
        
        Self { 
            tree: Some(Rc::new(RefCell::new(tree))), 
            source: source.clone(),
            language: None,
            parse_errors: Vec::new(),
            metadata: AstMetadata {
                parse_time_ms: None,
                node_count: Some(node_count),
                max_depth: Some(max_depth),
                has_syntax_errors: has_errors,
                file_size_bytes: source.len(),
            },
        }
    }
    
    pub fn new_with_language(tree: Tree, source: String, language: Language) -> Self {
        let mut ast = Self::new(tree, source);
        ast.language = Some(language);
        ast
    }
    
    pub fn new_source_only(source: String) -> Self {
        Self { 
            tree: None, 
            source: source.clone(),
            language: None,
            parse_errors: Vec::new(),
            metadata: AstMetadata {
                parse_time_ms: None,
                node_count: None,
                max_depth: None,
                has_syntax_errors: false,
                file_size_bytes: source.len(),
            },
        }
    }

    pub fn root_node(&self) -> Option<Node> {
        // Return None for now to avoid lifetime issues
        // In a full implementation, this would return a reference-counted node
        None
    }
    
    pub fn with_tree<T, F>(&self, f: F) -> Option<T>
    where
        F: FnOnce(&Tree) -> T,
    {
        self.tree.as_ref().map(|t| f(&t.borrow()))
    }
    
    pub fn has_parse_errors(&self) -> bool {
        !self.parse_errors.is_empty() || self.metadata.has_syntax_errors
    }
    
    pub fn is_valid(&self) -> bool {
        self.tree.is_some() && !self.has_parse_errors()
    }
    
    pub fn get_language(&self) -> Option<Language> {
        self.language
    }
    
    pub fn add_parse_error(&mut self, error: String) {
        self.parse_errors.push(error);
    }
    
    pub fn set_parse_time(&mut self, time_ms: u64) {
        self.metadata.parse_time_ms = Some(time_ms);
    }
    
    // Helper function to count nodes in the AST
    fn count_nodes(tree: &Tree) -> usize {
        fn count_recursive(node: Node) -> usize {
            let mut count = 1;
            for i in 0..node.child_count() {
                if let Some(child) = node.child(i) {
                    count += count_recursive(child);
                }
            }
            count
        }
        
        count_recursive(tree.root_node())
    }
    
    // Helper function to calculate maximum depth of the AST
    fn calculate_depth(tree: &Tree) -> usize {
        fn depth_recursive(node: Node) -> usize {
            let mut max_child_depth = 0;
            for i in 0..node.child_count() {
                if let Some(child) = node.child(i) {
                    max_child_depth = max_child_depth.max(depth_recursive(child));
                }
            }
            1 + max_child_depth
        }
        
        depth_recursive(tree.root_node())
    }
    
    // Enhanced query capabilities for language-specific analysis
    pub fn query_patterns(&self, _patterns: &[&str]) -> Vec<String> {
        // This would implement tree-sitter query functionality for advanced AST analysis
        // For now, return empty vector as placeholder
        Vec::new()
    }
    
    // Extract function/method definitions from the AST
    pub fn extract_functions(&self) -> Vec<FunctionInfo> {
        // This would extract function definitions based on language-specific patterns
        Vec::new()
    }
    
    // Extract security-relevant patterns from the AST
    pub fn extract_security_patterns(&self) -> Vec<SecurityPattern> {
        // This would identify security-relevant code patterns using AST analysis
        Vec::new()
    }
}

#[derive(Debug, Clone)]
pub struct FunctionInfo {
    pub name: String,
    pub line_start: usize,
    pub line_end: usize,
    pub parameters: Vec<String>,
    pub return_type: Option<String>,
    pub is_unsafe: bool,
    pub is_public: bool,
}

#[derive(Debug, Clone)]
pub struct SecurityPattern {
    pub pattern_type: String,
    pub line_number: usize,
    pub column: usize,
    pub severity: crate::Severity,
    pub description: String,
    pub code_snippet: String,
}

pub trait Parser {
    fn parse(&mut self, source_file: &SourceFile) -> Result<ParsedAst>;
    fn language(&self) -> Language;
}

pub struct ParserFactory;

impl ParserFactory {
    pub fn create_parser(language: &Language) -> Result<Box<dyn Parser>> {
        match language {
            Language::C => Ok(Box::new(c_parser::CParser::new()?)),
            Language::Cpp => Ok(Box::new(cpp_parser::CppParser::new()?)),
            Language::Python => Ok(Box::new(python_parser::PythonParser::new()?)),
            Language::Java => Ok(Box::new(java_parser::JavaParser::new()?)),
            Language::Javascript => Ok(Box::new(javascript_parser::JavascriptParser::new()?)),
            Language::TypeScript => Ok(Box::new(typescript_parser::TypeScriptParser::new()?)),
            Language::Go => Ok(Box::new(go_parser::GoParser::new()?)),
            Language::Php => Ok(Box::new(php_parser::PhpParser::new()?)),
            Language::Ruby => Ok(Box::new(ruby_parser::RubyParser::new()?)),
            Language::Kotlin => Ok(Box::new(kotlin_parser::KotlinParser::new()?)),
            Language::CSharp => Ok(Box::new(csharp_parser::CSharpParser::new()?)),
            Language::Bash => Ok(Box::new(bash_parser::BashParser::new()?)),
            Language::Scada => Ok(Box::new(scada_parser::ScadaParser::new()?)),
            Language::Cobol => Ok(Box::new(cobol_parser::CobolParser::new()?)),
            Language::Pascal => Ok(Box::new(pascal_parser::PascalParser::new()?)),
            Language::Dart => Ok(Box::new(dart_parser::DartParser::new()?)),
            Language::Swift => Ok(Box::new(swift_parser::SwiftParser::new()?)),
            Language::Rust => Ok(Box::new(rust_parser::RustParser::new()?)),
            Language::Delphi => Ok(Box::new(delphi_parser::DelphiParser::new())),
        }
    }
}