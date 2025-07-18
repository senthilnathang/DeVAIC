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
}

impl ParsedAst {
    pub fn new(tree: Tree, source: String) -> Self {
        Self { 
            tree: Some(Rc::new(RefCell::new(tree))), 
            source 
        }
    }
    
    pub fn new_source_only(source: String) -> Self {
        Self { tree: None, source }
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
        }
    }
}