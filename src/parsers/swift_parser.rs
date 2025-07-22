use super::{ParsedAst, Parser, SourceFile};
use crate::{error::DevaicError, Language, Result};
use tree_sitter::Parser as TreeSitterParser;

pub struct SwiftParser {
    parser: TreeSitterParser,
}

impl SwiftParser {
    pub fn new() -> Result<Self> {
        let mut parser = TreeSitterParser::new();
        parser
            .set_language(tree_sitter_swift::language())
            .map_err(|e| DevaicError::TreeSitter(format!("Error loading Swift grammar: {}", e)))?;
        
        Ok(Self { parser })
    }
}

impl Parser for SwiftParser {
    fn parse(&mut self, source_file: &SourceFile) -> Result<ParsedAst> {
        let start_time = std::time::Instant::now();
        
        let tree = self.parser
            .parse(&source_file.content, None)
            .ok_or_else(|| DevaicError::Parse("Failed to parse Swift source code".to_string()))?;
        
        let parse_time = start_time.elapsed().as_millis() as u64;
        let mut ast = ParsedAst::new_with_language(tree, source_file.content.clone(), Language::Swift);
        ast.set_parse_time(parse_time);
        
        log::debug!("Swift file parsed successfully in {}ms", parse_time);
        Ok(ast)
    }

    fn language(&self) -> Language {
        Language::Swift
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::PathBuf;

    #[test]
    fn test_swift_parser_basic() {
        let mut parser = SwiftParser::new().unwrap();
        let source = r#"
import Foundation

class Person {
    var name: String
    var age: Int
    
    init(name: String, age: Int) {
        self.name = name
        self.age = age
    }
    
    func greet() {
        print("Hello, my name is \(name) and I am \(age) years old.")
    }
}

let person = Person(name: "Alice", age: 30)
person.greet()
"#;
        
        let source_file = SourceFile::new(
            PathBuf::from("test.swift"),
            source.to_string(),
            Language::Swift,
        );
        
        let result = parser.parse(&source_file);
        assert!(result.is_ok());
        
        let ast = result.unwrap();
        assert!(ast.tree.as_ref().unwrap().borrow().root_node().has_error() == false);
    }

    #[test]
    fn test_swift_parser_ios_app() {
        let mut parser = SwiftParser::new().unwrap();
        let source = r#"
import UIKit

class ViewController: UIViewController {
    @IBOutlet weak var textField: UITextField!
    @IBOutlet weak var label: UILabel!
    
    override func viewDidLoad() {
        super.viewDidLoad()
    }
    
    @IBAction func buttonTapped(_ sender: UIButton) {
        label.text = textField.text
    }
}
"#;
        
        let source_file = SourceFile::new(
            PathBuf::from("ViewController.swift"),
            source.to_string(),
            Language::Swift,
        );
        
        let result = parser.parse(&source_file);
        assert!(result.is_ok());
    }
}