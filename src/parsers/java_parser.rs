use super::{ParsedAst, Parser, SourceFile};
use crate::{error::DevaicError, Language, Result};
use tree_sitter::Parser as TreeSitterParser;

pub struct JavaParser {
    parser: TreeSitterParser,
}

impl JavaParser {
    pub fn new() -> Self {
        let mut parser = TreeSitterParser::new();
        parser
            .set_language(tree_sitter_java::language())
            .expect("Error loading Java grammar");
        
        Self { parser }
    }
}

impl Parser for JavaParser {
    fn parse(&self, source_file: &SourceFile) -> Result<ParsedAst> {
        let mut parser = TreeSitterParser::new();
        parser.set_language(tree_sitter_java::language())
            .expect("Error loading Java grammar");
        
        let tree = parser
            .parse(&source_file.content, None)
            .ok_or_else(|| DevaicError::Parse("Failed to parse Java source code".to_string()))?;
        
        Ok(ParsedAst::new(tree, source_file.content.clone()))
    }

    fn language(&self) -> Language {
        Language::Java
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::PathBuf;

    #[test]
    fn test_java_parser_basic() {
        let parser = JavaParser::new();
        let source = r#"
public class HelloWorld {
    public static void main(String[] args) {
        System.out.println("Hello, World!");
    }
}
"#;
        
        let source_file = SourceFile::new(
            PathBuf::from("HelloWorld.java"),
            source.to_string(),
            Language::Java,
        );
        
        let result = parser.parse(&source_file);
        assert!(result.is_ok());
        
        let ast = result.unwrap();
        assert!(!ast.tree.root_node().has_error());
    }
}