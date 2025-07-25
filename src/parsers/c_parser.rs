use super::{ParsedAst, Parser, SourceFile};
use crate::{error::DevaicError, Language, Result};
use tree_sitter::Parser as TreeSitterParser;

pub struct CParser {
    parser: TreeSitterParser,
}

impl CParser {
    pub fn new() -> Result<Self> {
        let mut parser = TreeSitterParser::new();
        parser
            .set_language(tree_sitter_c::language())
            .map_err(|e| DevaicError::TreeSitter(format!("Error loading C grammar: {}", e)))?;
        
        Ok(Self { parser })
    }
}

impl Parser for CParser {
    fn parse(&mut self, source_file: &SourceFile) -> Result<ParsedAst> {
        let tree = self.parser
            .parse(&source_file.content, None)
            .ok_or_else(|| DevaicError::Parse("Failed to parse C source code".to_string()))?;
        
        Ok(ParsedAst::new(tree, source_file.content.clone()))
    }

    fn language(&self) -> Language {
        Language::C
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::PathBuf;

    #[test]
    fn test_c_parser_basic() {
        let mut parser = CParser::new().unwrap();
        let source = r#"
#include <stdio.h>

int main() {
    printf("Hello, World!\n");
    return 0;
}
"#;
        
        let source_file = SourceFile::new(
            PathBuf::from("test.c"),
            source.to_string(),
            Language::C,
        );
        
        let result = parser.parse(&source_file);
        assert!(result.is_ok());
        
        let ast = result.unwrap();
        assert!(ast.tree.as_ref().unwrap().borrow().root_node().has_error() == false);
    }
}