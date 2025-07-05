use crate::{
    error::{DevaicError, Result},
    parsers::{ParsedAst, Parser, SourceFile},
    Language,
};
use tree_sitter::{Parser as TreeSitterParser};

pub struct GoParser {
    parser: TreeSitterParser,
}

impl GoParser {
    pub fn new() -> Result<Self> {
        let mut parser = TreeSitterParser::new();
        parser
            .set_language(tree_sitter_go::language())
            .map_err(|e| DevaicError::TreeSitter(format!("Error loading Go grammar: {}", e)))?;
        Ok(Self { parser })
    }
}

impl Parser for GoParser {
    fn parse(&self, source_file: &SourceFile) -> Result<ParsedAst> {
        // Validate input size to prevent DoS
        if source_file.content.len() > 50 * 1024 * 1024 { // 50MB limit
            return Err(DevaicError::Analysis("File too large for parsing".to_string()));
        }
        
        let mut parser = tree_sitter::Parser::new();
        parser
            .set_language(tree_sitter_go::language())
            .map_err(|e| DevaicError::TreeSitter(format!("Error setting Go language: {}", e)))?;
        
        let tree = parser
            .parse(&source_file.content, None)
            .ok_or_else(|| DevaicError::Parse("Failed to parse Go code - syntax error or timeout".to_string()))?;
        
        Ok(ParsedAst::new(tree, source_file.content.clone()))
    }

    fn language(&self) -> Language {
        Language::Go
    }
}