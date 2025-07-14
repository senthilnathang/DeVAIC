use super::{ParsedAst, Parser, SourceFile};
use crate::{Language, Result};

pub struct PascalParser;

impl PascalParser {
    pub fn new() -> Result<Self> {
        Ok(Self)
    }
}

impl Parser for PascalParser {
    fn parse(&mut self, source_file: &SourceFile) -> Result<ParsedAst> {
        // Since there's no tree-sitter parser for Pascal, we'll use source-only parsing
        // This allows for regex-based pattern matching in the rules
        Ok(ParsedAst::new_source_only(source_file.content.clone()))
    }

    fn language(&self) -> Language {
        Language::Pascal
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::PathBuf;

    #[test]
    fn test_pascal_parser_basic() {
        let mut parser = PascalParser::new().unwrap();
        let source = r#"
program HelloWorld;
begin
  writeln('Hello, World!');
end.
        "#;
        
        let source_file = SourceFile::new(
            PathBuf::from("test.pas"),
            source.to_string(),
            Language::Pascal,
        );
        
        let result = parser.parse(&source_file);
        assert!(result.is_ok());
        
        let ast = result.unwrap();
        assert!(ast.tree.is_none()); // Source-only parsing
        assert_eq!(ast.source, source);
    }
}