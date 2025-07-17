use super::{ParsedAst, Parser, SourceFile};
use crate::{error::DevaicError, Language, Result};
use tree_sitter::Parser as TreeSitterParser;

pub struct TypeScriptParser {
    parser: TreeSitterParser,
}

impl TypeScriptParser {
    pub fn new() -> Result<Self> {
        let mut parser = TreeSitterParser::new();
        parser
            .set_language(tree_sitter_typescript::language_typescript())
            .map_err(|e| DevaicError::TreeSitter(format!("Error loading TypeScript grammar: {}", e)))?;
        
        Ok(Self { parser })
    }
}

impl Parser for TypeScriptParser {
    fn parse(&mut self, source_file: &SourceFile) -> Result<ParsedAst> {
        let tree = self.parser
            .parse(&source_file.content, None)
            .ok_or_else(|| DevaicError::Parse("Failed to parse TypeScript source code".to_string()))?;
        
        Ok(ParsedAst::new(tree, source_file.content.clone()))
    }

    fn language(&self) -> Language {
        Language::TypeScript
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::PathBuf;

    #[test]
    fn test_typescript_parser_basic() {
        let mut parser = TypeScriptParser::new().unwrap();
        let source = r#"
interface User {
    name: string;
    age: number;
}

function greet(user: User): void {
    console.log(`Hello, ${user.name}!`);
}

const user: User = { name: "World", age: 25 };
greet(user);
"#;
        
        let source_file = SourceFile::new(
            PathBuf::from("test.ts"),
            source.to_string(),
            Language::TypeScript,
        );
        
        let result = parser.parse(&source_file);
        assert!(result.is_ok());
        
        let ast = result.unwrap();
        assert!(ast.tree.as_ref().unwrap().borrow().root_node().has_error() == false);
    }
}