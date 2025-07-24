/// Delphi Parser for DeVAIC
/// 
/// This module provides parsing support for Delphi/Object Pascal source code.
/// Inspired by the sonar-delphi project (https://github.com/integrated-application-development/sonar-delphi)
/// 
/// Delphi is a high-level, object-oriented programming language based on Object Pascal,
/// primarily used for Windows application development and database applications.

use crate::parsers::{SourceFile, ParsedAst, AstMetadata};
use crate::{Language, Vulnerability, Severity};
use crate::error::Result;
use std::collections::HashMap;
use regex::Regex;

/// Delphi-specific parser implementation
pub struct DelphiParser {
    /// Common Delphi patterns for security analysis
    patterns: HashMap<String, Regex>,
}

impl DelphiParser {
    pub fn new() -> Self {
        let mut patterns = HashMap::new();
        
        // Initialize common Delphi security patterns based on sonar-delphi insights
        patterns.insert(
            "hardcoded_password".to_string(),
            Regex::new(r#"(?i)(password|pwd|pass).*[:=]\s*['"]([^'"]+)['"]"#).unwrap()
        );
        
        patterns.insert(
            "sql_injection".to_string(),
            Regex::new(r"(?i)(SQL\.Text|CommandText)\s*:=.*\+|(?:ExecSQL|Open|Query)\s*\(").unwrap()
        );
        
        patterns.insert(
            "unsafe_cast".to_string(),
            Regex::new(r"(?i)(PChar|PAnsiChar|PWideChar)\s*\(").unwrap()
        );
        
        patterns.insert(
            "unicode_to_ansi_cast".to_string(),
            Regex::new(r"(?i)(AnsiString|PAnsiChar)\s*\(").unwrap()
        );
        
        patterns.insert(
            "uninitialized_variant".to_string(),
            Regex::new(r"(?i)var\s+\w+\s*:\s*Variant\s*;").unwrap()
        );
        
        patterns.insert(
            "unsafe_pointer_arithmetic".to_string(),
            Regex::new(r"(?i)Inc\s*\(\s*P\w+\s*[,)]|Dec\s*\(\s*P\w+\s*[,)]").unwrap()
        );
        
        patterns.insert(
            "format_string_vulnerability".to_string(),
            Regex::new(r#"(?i)Format\s*\(\s*['"'][^'"]*%[sd][^'"]*['"']"#).unwrap()
        );
        
        patterns.insert(
            "dll_injection".to_string(),
            Regex::new(r#"(?i)LoadLibrary\s*\(\s*['"'][^'"]*\.dll['"']"#).unwrap()
        );
        
        patterns.insert(
            "registry_access".to_string(),
            Regex::new(r"(?i)(TRegistry|OpenKey|ReadString|WriteString)").unwrap()
        );
        
        patterns.insert(
            "file_path_traversal".to_string(),
            Regex::new(r"(?i)(ExtractFilePath|ExpandFileName)\s*\([^)]*\.\.[^)]*\)").unwrap()
        );

        Self { patterns }
    }

    /// Parse Delphi source code and extract AST information
    pub fn parse(&self, source_file: &SourceFile) -> Result<ParsedAst> {
        let start_time = std::time::Instant::now();
        
        // For now, we'll do pattern-based parsing since tree-sitter-delphi isn't available
        // In a full implementation, we would integrate with a proper Delphi parser
        
        let mut metadata = AstMetadata::default();
        metadata.parse_time_ms = Some(start_time.elapsed().as_millis() as u64);
        
        Ok(ParsedAst {
            tree: None, // No AST tree for pattern-based parsing
            source: source_file.content.clone(),
            language: Some(Language::Delphi),
            parse_errors: Vec::new(),
            metadata,
        })
    }

    /// Analyze Delphi code for security vulnerabilities
    pub fn analyze_security(&self, source_file: &SourceFile) -> Result<Vec<Vulnerability>> {
        let mut vulnerabilities = Vec::new();
        let lines: Vec<&str> = source_file.content.lines().collect();

        for (line_number, line) in lines.iter().enumerate() {
            let line_num = line_number + 1;

            // Check for hardcoded passwords
            if let Some(captures) = self.patterns["hardcoded_password"].captures(line) {
                vulnerabilities.push(Vulnerability {
                    id: "DELPHI-001".to_string(),
                    cwe: Some("CWE-798".to_string()),
                    vulnerability_type: "Hardcoded Credentials".to_string(),
                    severity: Severity::High,
                    category: "authentication".to_string(),
                    description: "Hardcoded password detected in Delphi code".to_string(),
                    file_path: source_file.path.to_string_lossy().to_string(),
                    line_number: line_num,
                    column: captures.get(0).map(|m| m.start()).unwrap_or(0),
                    source_code: line.trim().to_string(),
                    recommendation: "Store passwords in configuration files or environment variables".to_string(),
                });
            }

            // Check for SQL injection vulnerabilities
            if let Some(captures) = self.patterns["sql_injection"].captures(line) {
                vulnerabilities.push(Vulnerability {
                    id: "DELPHI-002".to_string(),
                    cwe: Some("CWE-89".to_string()),
                    vulnerability_type: "SQL Injection".to_string(),
                    severity: Severity::Critical,
                    category: "injection".to_string(),
                    description: "Potential SQL injection in Delphi database query".to_string(),
                    file_path: source_file.path.to_string_lossy().to_string(),
                    line_number: line_num,
                    column: captures.get(0).map(|m| m.start()).unwrap_or(0),
                    source_code: line.trim().to_string(),
                    recommendation: "Use parameterized queries with TQuery.Params or prepared statements".to_string(),
                });
            }

            // Check for unsafe type casting
            if let Some(captures) = self.patterns["unsafe_cast"].captures(line) {
                vulnerabilities.push(Vulnerability {
                    id: "DELPHI-003".to_string(),
                    cwe: Some("CWE-704".to_string()),
                    vulnerability_type: "Unsafe Type Cast".to_string(),
                    severity: Severity::Medium,
                    category: "security".to_string(),
                    description: "Unsafe pointer cast detected".to_string(),
                    file_path: source_file.path.to_string_lossy().to_string(),
                    line_number: line_num,
                    column: captures.get(0).map(|m| m.start()).unwrap_or(0),
                    source_code: line.trim().to_string(),
                    recommendation: "Validate pointer safety and consider using safer string handling".to_string(),
                });
            }

            // Check for Unicode to ANSI casting (sonar-delphi inspired)
            if let Some(captures) = self.patterns["unicode_to_ansi_cast"].captures(line) {
                vulnerabilities.push(Vulnerability {
                    id: "DELPHI-004".to_string(),
                    cwe: Some("CWE-176".to_string()),
                    vulnerability_type: "Unicode/ANSI Conversion".to_string(),
                    severity: Severity::Medium,
                    category: "security".to_string(),
                    description: "Unicode types should not be cast to ANSI types without proper encoding".to_string(),
                    file_path: source_file.path.to_string_lossy().to_string(),
                    line_number: line_num,
                    column: captures.get(0).map(|m| m.start()).unwrap_or(0),
                    source_code: line.trim().to_string(),
                    recommendation: "Use proper encoding conversion functions like UTF8Encode/UTF8Decode".to_string(),
                });
            }

            // Check for uninitialized variants
            if let Some(captures) = self.patterns["uninitialized_variant"].captures(line) {
                vulnerabilities.push(Vulnerability {
                    id: "DELPHI-005".to_string(),
                    cwe: Some("CWE-457".to_string()),
                    vulnerability_type: "Uninitialized Variable".to_string(),
                    severity: Severity::Medium,
                    category: "vulnerability".to_string(),
                    description: "Variant variable declared but not initialized".to_string(),
                    file_path: source_file.path.to_string_lossy().to_string(),
                    line_number: line_num,
                    column: captures.get(0).map(|m| m.start()).unwrap_or(0),
                    source_code: line.trim().to_string(),
                    recommendation: "Initialize variant variables with VarClear or assign a default value".to_string(),
                });
            }

            // Check for unsafe pointer arithmetic
            if let Some(captures) = self.patterns["unsafe_pointer_arithmetic"].captures(line) {
                vulnerabilities.push(Vulnerability {
                    id: "DELPHI-006".to_string(),
                    cwe: Some("CWE-119".to_string()),
                    vulnerability_type: "Buffer Overflow Risk".to_string(),
                    severity: Severity::High,
                    category: "vulnerability".to_string(),
                    description: "Unsafe pointer arithmetic detected".to_string(),
                    file_path: source_file.path.to_string_lossy().to_string(),
                    line_number: line_num,
                    column: captures.get(0).map(|m| m.start()).unwrap_or(0),
                    source_code: line.trim().to_string(),
                    recommendation: "Use bounds checking and safer memory management practices".to_string(),
                });
            }

            // Check for format string vulnerabilities
            if let Some(captures) = self.patterns["format_string_vulnerability"].captures(line) {
                vulnerabilities.push(Vulnerability {
                    id: "DELPHI-007".to_string(),
                    cwe: Some("CWE-134".to_string()),
                    vulnerability_type: "Format String Vulnerability".to_string(),
                    severity: Severity::High,
                    category: "vulnerability".to_string(),
                    description: "Potentially unsafe format string usage".to_string(),
                    file_path: source_file.path.to_string_lossy().to_string(),
                    line_number: line_num,
                    column: captures.get(0).map(|m| m.start()).unwrap_or(0),
                    source_code: line.trim().to_string(),
                    recommendation: "Validate format string arguments match the format specifiers".to_string(),
                });
            }

            // Check for DLL injection risks
            if let Some(captures) = self.patterns["dll_injection"].captures(line) {
                vulnerabilities.push(Vulnerability {
                    id: "DELPHI-008".to_string(),
                    cwe: Some("CWE-114".to_string()),
                    vulnerability_type: "DLL Injection Risk".to_string(),
                    severity: Severity::High,
                    category: "security".to_string(),
                    description: "Dynamic library loading without path validation".to_string(),
                    file_path: source_file.path.to_string_lossy().to_string(),
                    line_number: line_num,
                    column: captures.get(0).map(|m| m.start()).unwrap_or(0),
                    source_code: line.trim().to_string(),
                    recommendation: "Use full paths for DLL loading and validate library authenticity".to_string(),
                });
            }

            // Check for registry access (potential privilege escalation)
            if let Some(captures) = self.patterns["registry_access"].captures(line) {
                vulnerabilities.push(Vulnerability {
                    id: "DELPHI-009".to_string(),
                    cwe: Some("CWE-250".to_string()),
                    vulnerability_type: "Registry Access".to_string(),
                    severity: Severity::Medium,
                    category: "security".to_string(),
                    description: "Registry access detected - ensure proper permissions".to_string(),
                    file_path: source_file.path.to_string_lossy().to_string(),
                    line_number: line_num,
                    column: captures.get(0).map(|m| m.start()).unwrap_or(0),
                    source_code: line.trim().to_string(),
                    recommendation: "Validate registry access permissions and handle access denied exceptions".to_string(),
                });
            }

            // Check for path traversal vulnerabilities
            if let Some(captures) = self.patterns["file_path_traversal"].captures(line) {
                vulnerabilities.push(Vulnerability {
                    id: "DELPHI-010".to_string(),
                    cwe: Some("CWE-22".to_string()),
                    vulnerability_type: "Path Traversal".to_string(),
                    severity: Severity::High,
                    category: "vulnerability".to_string(),
                    description: "Potential path traversal vulnerability".to_string(),
                    file_path: source_file.path.to_string_lossy().to_string(),
                    line_number: line_num,
                    column: captures.get(0).map(|m| m.start()).unwrap_or(0),
                    source_code: line.trim().to_string(),
                    recommendation: "Sanitize file paths and prevent directory traversal attacks".to_string(),
                });
            }
        }

        Ok(vulnerabilities)
    }

    /// Check if this is a valid Delphi file
    pub fn is_delphi_file(file_path: &std::path::Path) -> bool {
        if let Some(ext) = file_path.extension() {
            if let Some(ext_str) = ext.to_str() {
                matches!(ext_str.to_lowercase().as_str(), "pas" | "dpr" | "dpk" | "dfm" | "fmx")
            } else {
                false
            }
        } else {
            false
        }
    }
}

impl Default for DelphiParser {
    fn default() -> Self {
        Self::new()
    }
}

/// Implementation of the Parser trait for Delphi
impl crate::parsers::Parser for DelphiParser {
    fn parse(&mut self, source_file: &SourceFile) -> Result<ParsedAst> {
        DelphiParser::parse(self, source_file)
    }

    fn language(&self) -> Language {
        Language::Delphi
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::PathBuf;

    #[test]
    fn test_delphi_parser_basic() {
        let parser = DelphiParser::new();
        let source_file = SourceFile {
            path: PathBuf::from("test.pas"),
            content: r#"
program Test;
var
  password: string = 'hardcoded123';
begin
  writeln('Hello Delphi');
end.
"#.to_string(),
            language: Language::Delphi,
        };

        let result = parser.analyze_security(&source_file);
        assert!(result.is_ok());
        let vulnerabilities = result.unwrap();
        assert!(!vulnerabilities.is_empty());
        
        // Should detect hardcoded password
        assert!(vulnerabilities.iter().any(|v| v.id == "DELPHI-001"));
    }

    #[test]
    fn test_delphi_sql_injection_detection() {
        let parser = DelphiParser::new();
        let source_file = SourceFile {
            path: PathBuf::from("test.pas"),
            content: r#"
procedure UnsafeQuery(userInput: string);
begin
  Query1.SQL.Text := 'SELECT * FROM users WHERE name = ' + userInput;
  Query1.ExecSQL();
end;
"#.to_string(),
            language: Language::Delphi,
        };

        let result = parser.analyze_security(&source_file);
        assert!(result.is_ok());
        let vulnerabilities = result.unwrap();
        
        // Should detect SQL injection
        assert!(vulnerabilities.iter().any(|v| v.id == "DELPHI-002"));
    }

    #[test]
    fn test_delphi_unicode_ansi_cast() {
        let parser = DelphiParser::new();
        let source_file = SourceFile {
            path: PathBuf::from("test.pas"),
            content: r#"
var
  unicodeStr: UnicodeString;
  ansiStr: AnsiString;
begin
  ansiStr := AnsiString(unicodeStr);
end;
"#.to_string(),
            language: Language::Delphi,
        };

        let result = parser.analyze_security(&source_file);
        assert!(result.is_ok());
        let vulnerabilities = result.unwrap();
        
        // Should detect unsafe Unicode to ANSI conversion
        assert!(vulnerabilities.iter().any(|v| v.id == "DELPHI-004"));
    }

    #[test]
    fn test_delphi_file_detection() {
        assert!(DelphiParser::is_delphi_file(&PathBuf::from("test.pas")));
        assert!(DelphiParser::is_delphi_file(&PathBuf::from("project.dpr")));
        assert!(DelphiParser::is_delphi_file(&PathBuf::from("package.dpk")));
        assert!(DelphiParser::is_delphi_file(&PathBuf::from("form.dfm")));
        assert!(!DelphiParser::is_delphi_file(&PathBuf::from("test.txt")));
    }
}