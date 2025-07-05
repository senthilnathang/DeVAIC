use super::{ParsedAst, Parser, SourceFile};
use crate::{error::DevaicError, Language, Result};
use tree_sitter::Parser as TreeSitterParser;

pub struct PythonParser {
    parser: TreeSitterParser,
}

impl PythonParser {
    pub fn new() -> Result<Self> {
        let mut parser = TreeSitterParser::new();
        parser
            .set_language(tree_sitter_python::language())
            .map_err(|e| DevaicError::TreeSitter(format!("Error loading Python grammar: {}", e)))?;
        
        Ok(Self { parser })
    }
}

impl Parser for PythonParser {
    fn parse(&self, source_file: &SourceFile) -> Result<ParsedAst> {
        let mut parser = TreeSitterParser::new();
        parser.set_language(tree_sitter_python::language())
            .expect("Error loading Python grammar");
        
        let tree = parser
            .parse(&source_file.content, None)
            .ok_or_else(|| DevaicError::Parse("Failed to parse Python source code".to_string()))?;
        
        Ok(ParsedAst::new(tree, source_file.content.clone()))
    }

    fn language(&self) -> Language {
        Language::Python
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::PathBuf;

    #[test]
    fn test_python_parser_basic() {
        let parser = PythonParser::new();
        let source = r#"
import os
import sys

def main():
    print("Hello, World!")
    return 0

if __name__ == "__main__":
    main()
"#;
        
        let source_file = SourceFile::new(
            PathBuf::from("test.py"),
            source.to_string(),
            Language::Python,
        );
        
        let result = parser.parse(&source_file);
        assert!(result.is_ok());
        
        let ast = result.unwrap();
        assert!(!ast.tree.as_ref().unwrap().root_node().has_error());
    }
}