pub mod c_parser;
pub mod python_parser;
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
    pub tree: Tree,
    pub source: String,
}

impl ParsedAst {
    pub fn new(tree: Tree, source: String) -> Self {
        Self { tree, source }
    }

    pub fn root_node(&self) -> Node {
        self.tree.root_node()
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
            Language::Python => Ok(Box::new(python_parser::PythonParser::new())),
            Language::Scada => Ok(Box::new(scada_parser::ScadaParser::new())),
        }
    }
}