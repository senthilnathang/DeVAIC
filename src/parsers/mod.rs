pub mod c_parser;
pub mod cpp_parser;
pub mod python_parser;
pub mod java_parser;
pub mod javascript_parser;
pub mod typescript_parser;
pub mod scada_parser;

use crate::{error::Result, Language};
use std::path::PathBuf;
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
    pub tree: Option<Tree>,
    pub source: String,
}

impl ParsedAst {
    pub fn new(tree: Tree, source: String) -> Self {
        Self { tree: Some(tree), source }
    }
    
    pub fn new_source_only(source: String) -> Self {
        Self { tree: None, source }
    }

    pub fn root_node(&self) -> Option<Node> {
        self.tree.as_ref().map(|t| t.root_node())
    }
}

pub trait Parser {
    fn parse(&self, source_file: &SourceFile) -> Result<ParsedAst>;
    fn language(&self) -> Language;
}

pub struct ParserFactory;

impl ParserFactory {
    pub fn create_parser(language: &Language) -> Result<Box<dyn Parser>> {
        match language {
            Language::C => Ok(Box::new(c_parser::CParser::new())),
            Language::Cpp => Ok(Box::new(cpp_parser::CppParser::new())),
            Language::Python => Ok(Box::new(python_parser::PythonParser::new())),
            Language::Java => Ok(Box::new(java_parser::JavaParser::new())),
            Language::Javascript => Ok(Box::new(javascript_parser::JavascriptParser::new())),
            Language::TypeScript => Ok(Box::new(typescript_parser::TypeScriptParser::new())),
            Language::Scada => Ok(Box::new(scada_parser::ScadaParser::new())),
        }
    }
}