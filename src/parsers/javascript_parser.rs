use super::{ParsedAst, Parser, SourceFile};
use crate::{error::DevaicError, Language, Result};
use tree_sitter::Parser as TreeSitterParser;

pub struct JavascriptParser {
    parser: TreeSitterParser,
}

impl JavascriptParser {
    pub fn new() -> Result<Self> {
        let mut parser = TreeSitterParser::new();
        parser
            .set_language(tree_sitter_javascript::language())
            .map_err(|e| DevaicError::TreeSitter(format!("Error loading JavaScript grammar: {}", e)))?;
        
        Ok(Self { parser })
    }
}

impl Parser for JavascriptParser {
    fn parse(&mut self, source_file: &SourceFile) -> Result<ParsedAst> {
        let tree = self.parser
            .parse(&source_file.content, None)
            .ok_or_else(|| DevaicError::Parse("Failed to parse JavaScript source code".to_string()))?;
        
        Ok(ParsedAst::new(tree, source_file.content.clone()))
    }

    fn language(&self) -> Language {
        Language::Javascript
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::PathBuf;

    #[test]
    fn test_javascript_parser_basic() {
        let mut parser = JavascriptParser::new().unwrap();
        let source = r#"
function greet(name) {
    console.log("Hello, " + name + "!");
}

greet("World");
"#;
        
        let source_file = SourceFile::new(
            PathBuf::from("test.js"),
            source.to_string(),
            Language::Javascript,
        );
        
        let result = parser.parse(&source_file);
        assert!(result.is_ok());
        
        let ast = result.unwrap();
        assert!(ast.tree.as_ref().unwrap().borrow().root_node().has_error() == false);
    }
}