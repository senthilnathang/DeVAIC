use crate::{
    error::{DevaicError, Result},
    parsers::{ParsedAst, Parser, SourceFile},
    Language,
};
use tree_sitter::{Parser as TreeSitterParser};

pub struct RustParser {
    parser: TreeSitterParser,
}

impl RustParser {
    pub fn new() -> Result<Self> {
        let mut parser = TreeSitterParser::new();
        parser
            .set_language(tree_sitter_rust::language())
            .map_err(|e| DevaicError::TreeSitter(format!("Error loading Rust grammar: {}", e)))?;
        Ok(Self { parser })
    }
}

impl Parser for RustParser {
    fn parse(&mut self, source_file: &SourceFile) -> Result<ParsedAst> {
        // Validate input size to prevent DoS
        if source_file.content.len() > 50 * 1024 * 1024 { // 50MB limit
            return Err(DevaicError::Analysis("File too large for parsing".to_string()));
        }
        
        let start_time = std::time::Instant::now();
        
        let tree = self.parser
            .parse(&source_file.content, None)
            .ok_or_else(|| DevaicError::Parse("Failed to parse Rust code - syntax error or timeout".to_string()))?;
        
        let parse_time = start_time.elapsed().as_millis() as u64;
        let mut ast = ParsedAst::new_with_language(tree, source_file.content.clone(), Language::Rust);
        ast.set_parse_time(parse_time);
        
        log::debug!("Rust file parsed successfully in {}ms", parse_time);
        Ok(ast)
    }

    fn language(&self) -> Language {
        Language::Rust
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::PathBuf;

    #[test]
    fn test_rust_parser_basic() {
        let mut parser = RustParser::new().unwrap();
        let source = r#"
fn main() {
    println!("Hello, world!");
}

struct Person {
    name: String,
    age: u32,
}

impl Person {
    fn new(name: String, age: u32) -> Self {
        Person { name, age }
    }
    
    fn greet(&self) {
        println!("Hello, my name is {} and I am {} years old.", self.name, self.age);
    }
}
"#;
        
        let source_file = SourceFile::new(
            PathBuf::from("test.rs"),
            source.to_string(),
            Language::Rust,
        );
        
        let result = parser.parse(&source_file);
        assert!(result.is_ok());
        
        let ast = result.unwrap();
        assert!(ast.tree.as_ref().unwrap().borrow().root_node().has_error() == false);
    }

    #[test]
    fn test_rust_parser_unsafe_code() {
        let mut parser = RustParser::new().unwrap();
        let source = r#"
use std::ptr;

fn unsafe_operations() {
    unsafe {
        let x = 42;
        let raw_ptr = &x as *const i32;
        let value = *raw_ptr;
        println!("Value: {}", value);
    }
}

fn main() {
    unsafe_operations();
}
"#;
        
        let source_file = SourceFile::new(
            PathBuf::from("unsafe_test.rs"),
            source.to_string(),
            Language::Rust,
        );
        
        let result = parser.parse(&source_file);
        assert!(result.is_ok());
    }
}