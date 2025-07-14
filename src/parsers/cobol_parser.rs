use super::{ParsedAst, Parser, SourceFile};
use crate::{Language, Result};

pub struct CobolParser;

impl CobolParser {
    pub fn new() -> Result<Self> {
        Ok(Self)
    }
}

impl Parser for CobolParser {
    fn parse(&mut self, source_file: &SourceFile) -> Result<ParsedAst> {
        // Since there's no tree-sitter parser for COBOL, we'll use source-only parsing
        // This allows for regex-based pattern matching in the rules
        Ok(ParsedAst::new_source_only(source_file.content.clone()))
    }

    fn language(&self) -> Language {
        Language::Cobol
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::PathBuf;

    #[test]
    fn test_cobol_parser_basic() {
        let mut parser = CobolParser::new().unwrap();
        let source = r#"
       IDENTIFICATION DIVISION.
       PROGRAM-ID. HELLO-WORLD.
       
       DATA DIVISION.
       WORKING-STORAGE SECTION.
       01 WS-MESSAGE PIC X(20) VALUE 'HELLO WORLD'.
       
       PROCEDURE DIVISION.
       DISPLAY WS-MESSAGE.
       STOP RUN.
        "#;
        
        let source_file = SourceFile::new(
            PathBuf::from("test.cob"),
            source.to_string(),
            Language::Cobol,
        );
        
        let result = parser.parse(&source_file);
        assert!(result.is_ok());
        
        let ast = result.unwrap();
        assert!(ast.tree.is_none()); // Source-only parsing
        assert_eq!(ast.source, source);
    }
}