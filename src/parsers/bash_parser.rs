use crate::{
    error::{DevaicError, Result},
    parsers::{ParsedAst, Parser, SourceFile},
    Language,
};
use tree_sitter::{Parser as TreeSitterParser};

pub struct BashParser {
    parser: TreeSitterParser,
}

impl BashParser {
    pub fn new() -> Result<Self> {
        let mut parser = TreeSitterParser::new();
        parser
            .set_language(tree_sitter_bash::language())
            .map_err(|e| DevaicError::TreeSitter(format!("Error loading Bash grammar: {}", e)))?;
        Ok(Self { parser })
    }
}

impl Parser for BashParser {
    fn parse(&mut self, source_file: &SourceFile) -> Result<ParsedAst> {
        // Validate input size to prevent DoS
        if source_file.content.len() > 50 * 1024 * 1024 { // 50MB limit
            return Err(DevaicError::Analysis("File too large for parsing".to_string()));
        }
        
        let tree = self.parser
            .parse(&source_file.content, None)
            .ok_or_else(|| DevaicError::Parse("Failed to parse Bash code - syntax error or timeout".to_string()))?;
        
        Ok(ParsedAst::new(tree, source_file.content.clone()))
    }

    fn language(&self) -> Language {
        Language::Bash
    }
}