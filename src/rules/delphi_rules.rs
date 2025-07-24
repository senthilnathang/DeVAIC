/// Delphi/Object Pascal Security Rules for DeVAIC
/// 
/// This module implements security analysis rules specific to Delphi/Object Pascal,
/// inspired by the sonar-delphi project and common Delphi security patterns.
/// 
/// Delphi security concerns include:
/// - Memory management issues
/// - Unicode/ANSI conversion problems  
/// - Database security (SQL injection)
/// - DLL loading vulnerabilities
/// - Registry access security
/// - Format string vulnerabilities

use crate::parsers::{SourceFile, ParsedAst};
use crate::{Vulnerability, Severity};
use crate::error::Result;
use super::RuleSet;
use regex::Regex;
use std::collections::HashMap;
use lazy_static::lazy_static;

lazy_static! {
    /// Delphi-specific security patterns
    static ref DELPHI_PATTERNS: HashMap<&'static str, Regex> = {
        let mut m = HashMap::new();
        
        // Hardcoded credentials
        m.insert("hardcoded_password", 
            Regex::new(r#"(?i)(password|pwd|pass|secret|key)\s*[:=]\s*['"']([^'"]{3,})['"']"#).unwrap()
        );
        
        // SQL injection patterns
        m.insert("sql_injection_exec", 
            Regex::new(r"(?i)(SQL\.Text|CommandText)\s*:=.*\+|(?:ExecSQL|Open|Query|Execute)\s*\(").unwrap()
        );
        
        m.insert("sql_injection_format", 
            Regex::new(r"(?i)(SQL\.Text|CommandText)\s*:=\s*Format\s*\(").unwrap()
        );
        
        // Unsafe type casting
        m.insert("unsafe_pointer_cast", 
            Regex::new(r"(?i)(PChar|PAnsiChar|PWideChar|Pointer)\s*\(").unwrap()
        );
        
        // Unicode to ANSI conversion (sonar-delphi rule)
        m.insert("unicode_ansi_cast", 
            Regex::new(r"(?i)(AnsiString|PAnsiChar)\s*\(").unwrap()
        );
        
        // Uninitialized variables
        m.insert("uninitialized_variant", 
            Regex::new(r"(?i)var\s+\w+\s*:\s*Variant\s*;").unwrap()
        );
        
        m.insert("uninitialized_pointer", 
            Regex::new(r"(?i)var\s+\w+\s*:\s*P\w+\s*;").unwrap()
        );
        
        // Buffer overflow risks
        m.insert("unsafe_strcpy", 
            Regex::new(r"(?i)(StrCopy|StrLCopy|StrPCopy|StrCat|StrLCat)\s*\(").unwrap()
        );
        
        m.insert("pointer_arithmetic", 
            Regex::new(r"(?i)(Inc|Dec)\s*\(\s*P\w+\s*[,)]").unwrap()
        );
        
        // Format string vulnerabilities
        m.insert("format_vulnerability", 
            Regex::new(r"(?i)Format\s*\(\s*[^,]*,\s*\[.*\]\s*\)").unwrap()
        );
        
        // DLL injection risks
        m.insert("dll_loading", 
            Regex::new(r#"(?i)(LoadLibrary|LoadPackage|GetProcAddress)\s*\(\s*['"'][^'"]*\.dll['"']"#).unwrap()
        );
        
        // Registry access
        m.insert("registry_access", 
            Regex::new(r"(?i)(TRegistry|OpenKey|CreateKey|WriteString|WriteBool|WriteInteger)").unwrap()
        );
        
        // File operations with potential path traversal
        m.insert("file_operations", 
            Regex::new(r"(?i)(FileOpen|FileCreate|CreateFile|OpenFile)\s*\([^)]*\.\.[^)]*\)").unwrap()
        );
        
        // Weak cryptography
        m.insert("weak_crypto", 
            Regex::new(r"(?i)(MD5|SHA1|DES|RC4)").unwrap()
        );
        
        // Process execution
        m.insert("process_execution", 
            Regex::new(r"(?i)(CreateProcess|WinExec|ShellExecute|ExecuteProcess)").unwrap()
        );
        
        // Exception handling issues
        m.insert("empty_exception", 
            Regex::new(r"(?i)except\s*end\s*;").unwrap()
        );
        
        // Insecure random number generation
        m.insert("weak_random", 
            Regex::new(r"(?i)(Random\s*\(|Randomize)").unwrap()
        );
        
        m
    };
}

/// Delphi security rules implementation
pub struct DelphiRules;

impl DelphiRules {
    pub fn new() -> Self {
        Self
    }

    /// Analyze Delphi source code for security vulnerabilities
    pub fn analyze_source(&self, source_file: &SourceFile) -> Result<Vec<Vulnerability>> {
        let mut vulnerabilities = Vec::new();
        let lines: Vec<&str> = source_file.content.lines().collect();

        for (line_number, line) in lines.iter().enumerate() {
            let line_num = line_number + 1;
            let trimmed_line = line.trim();

            // Skip empty lines and comments
            if trimmed_line.is_empty() || trimmed_line.starts_with("//") || trimmed_line.starts_with("(*") {
                continue;
            }

            // Check for hardcoded credentials
            if let Some(captures) = DELPHI_PATTERNS["hardcoded_password"].captures(line) {
                vulnerabilities.push(Vulnerability {
                    id: "DELPHI-CRED-001".to_string(),
                    cwe: Some("CWE-798".to_string()),
                    vulnerability_type: "Hardcoded Credentials".to_string(),
                    severity: Severity::High,
                    category: "authentication".to_string(),
                    description: "Hardcoded password or secret detected in Delphi code".to_string(),
                    file_path: source_file.path.to_string_lossy().to_string(),
                    line_number: line_num,
                    column: captures.get(0).map(|m| m.start()).unwrap_or(0),
                    source_code: trimmed_line.to_string(),
                    recommendation: "Store credentials in configuration files, environment variables, or secure key stores".to_string(),
                });
            }

            // Check for SQL injection vulnerabilities
            if DELPHI_PATTERNS["sql_injection_exec"].is_match(line) || DELPHI_PATTERNS["sql_injection_format"].is_match(line) {
                if let Some(captures) = DELPHI_PATTERNS["sql_injection_exec"].captures(line).or_else(|| DELPHI_PATTERNS["sql_injection_format"].captures(line)) {
                    vulnerabilities.push(Vulnerability {
                        id: "DELPHI-SQLI-001".to_string(),
                        cwe: Some("CWE-89".to_string()),
                        vulnerability_type: "SQL Injection".to_string(),
                        severity: Severity::Critical,
                        category: "injection".to_string(),
                        description: "Potential SQL injection vulnerability in Delphi database query".to_string(),
                        file_path: source_file.path.to_string_lossy().to_string(),
                        line_number: line_num,
                        column: captures.get(0).map(|m| m.start()).unwrap_or(0),
                        source_code: trimmed_line.to_string(),
                        recommendation: "Use parameterized queries with TQuery.Params or TADOQuery.Parameters".to_string(),
                    });
                }
            }

            // Check for unsafe pointer casting
            if let Some(captures) = DELPHI_PATTERNS["unsafe_pointer_cast"].captures(line) {
                vulnerabilities.push(Vulnerability {
                    id: "DELPHI-CAST-001".to_string(),
                    cwe: Some("CWE-704".to_string()),
                    vulnerability_type: "Unsafe Type Cast".to_string(),
                    severity: Severity::Medium,
                    category: "vulnerability".to_string(),
                    description: "Unsafe pointer cast detected - may lead to memory corruption".to_string(),
                    file_path: source_file.path.to_string_lossy().to_string(),
                    line_number: line_num,
                    column: captures.get(0).map(|m| m.start()).unwrap_or(0),
                    source_code: trimmed_line.to_string(),
                    recommendation: "Validate pointer safety and consider using safer string handling functions".to_string(),
                });
            }

            // Check for Unicode to ANSI casting (sonar-delphi inspired)
            if let Some(captures) = DELPHI_PATTERNS["unicode_ansi_cast"].captures(line) {
                vulnerabilities.push(Vulnerability {
                    id: "DELPHI-UNICODE-001".to_string(),
                    cwe: Some("CWE-176".to_string()),
                    vulnerability_type: "Unsafe Unicode/ANSI Conversion".to_string(),
                    severity: Severity::Medium,
                    category: "vulnerability".to_string(),
                    description: "Unicode types should not be cast to ANSI types without proper encoding handling".to_string(),
                    file_path: source_file.path.to_string_lossy().to_string(),
                    line_number: line_num,
                    column: captures.get(0).map(|m| m.start()).unwrap_or(0),
                    source_code: trimmed_line.to_string(),
                    recommendation: "Use proper encoding conversion functions like UTF8Encode/UTF8Decode or AnsiToUtf8".to_string(),
                });
            }

            // Check for uninitialized variables
            if DELPHI_PATTERNS["uninitialized_variant"].is_match(line) || DELPHI_PATTERNS["uninitialized_pointer"].is_match(line) {
                if let Some(captures) = DELPHI_PATTERNS["uninitialized_variant"].captures(line).or_else(|| DELPHI_PATTERNS["uninitialized_pointer"].captures(line)) {
                    vulnerabilities.push(Vulnerability {
                        id: "DELPHI-UNINIT-001".to_string(),
                        cwe: Some("CWE-457".to_string()),
                        vulnerability_type: "Uninitialized Variable".to_string(),
                        severity: Severity::Medium,
                        category: "vulnerability".to_string(),
                        description: "Variable declared but not initialized - may lead to undefined behavior".to_string(),
                        file_path: source_file.path.to_string_lossy().to_string(),
                        line_number: line_num,
                        column: captures.get(0).map(|m| m.start()).unwrap_or(0),
                        source_code: trimmed_line.to_string(),
                        recommendation: "Initialize variables with appropriate default values or use VarClear for variants".to_string(),
                    });
                }
            }

            // Check for unsafe string operations
            if let Some(captures) = DELPHI_PATTERNS["unsafe_strcpy"].captures(line) {
                vulnerabilities.push(Vulnerability {
                    id: "DELPHI-BUFFER-001".to_string(),
                    cwe: Some("CWE-120".to_string()),
                    vulnerability_type: "Buffer Overflow Risk".to_string(),
                    severity: Severity::High,
                    category: "vulnerability".to_string(),
                    description: "Unsafe string operation detected - may lead to buffer overflow".to_string(),
                    file_path: source_file.path.to_string_lossy().to_string(),
                    line_number: line_num,
                    column: captures.get(0).map(|m| m.start()).unwrap_or(0),
                    source_code: trimmed_line.to_string(),
                    recommendation: "Use safer string functions or validate buffer sizes before operations".to_string(),
                });
            }

            // Check for unsafe pointer arithmetic
            if let Some(captures) = DELPHI_PATTERNS["pointer_arithmetic"].captures(line) {
                vulnerabilities.push(Vulnerability {
                    id: "DELPHI-BUFFER-002".to_string(),
                    cwe: Some("CWE-119".to_string()),
                    vulnerability_type: "Unsafe Pointer Arithmetic".to_string(),
                    severity: Severity::High,
                    category: "vulnerability".to_string(),
                    description: "Unsafe pointer arithmetic detected - may lead to buffer overflow".to_string(),
                    file_path: source_file.path.to_string_lossy().to_string(),
                    line_number: line_num,
                    column: captures.get(0).map(|m| m.start()).unwrap_or(0),
                    source_code: trimmed_line.to_string(),
                    recommendation: "Use bounds checking and safer memory management practices".to_string(),
                });
            }

            // Check for format string vulnerabilities
            if let Some(captures) = DELPHI_PATTERNS["format_vulnerability"].captures(line) {
                vulnerabilities.push(Vulnerability {
                    id: "DELPHI-FORMAT-001".to_string(),
                    cwe: Some("CWE-134".to_string()),
                    vulnerability_type: "Format String Vulnerability".to_string(),
                    severity: Severity::Medium,
                    category: "vulnerability".to_string(),
                    description: "Potentially unsafe format string usage - validate format arguments".to_string(),
                    file_path: source_file.path.to_string_lossy().to_string(),
                    line_number: line_num,
                    column: captures.get(0).map(|m| m.start()).unwrap_or(0),
                    source_code: trimmed_line.to_string(),
                    recommendation: "Ensure format string arguments match the format specifiers and validate input".to_string(),
                });
            }

            // Check for DLL loading vulnerabilities
            if let Some(captures) = DELPHI_PATTERNS["dll_loading"].captures(line) {
                vulnerabilities.push(Vulnerability {
                    id: "DELPHI-DLL-001".to_string(),
                    cwe: Some("CWE-114".to_string()),
                    vulnerability_type: "DLL Injection Risk".to_string(),
                    severity: Severity::High,
                    category: "security".to_string(),
                    description: "Dynamic library loading without path validation - DLL hijacking risk".to_string(),
                    file_path: source_file.path.to_string_lossy().to_string(),
                    line_number: line_num,
                    column: captures.get(0).map(|m| m.start()).unwrap_or(0),
                    source_code: trimmed_line.to_string(),
                    recommendation: "Use full paths for DLL loading and validate library authenticity".to_string(),
                });
            }

            // Check for registry access
            if let Some(captures) = DELPHI_PATTERNS["registry_access"].captures(line) {
                vulnerabilities.push(Vulnerability {
                    id: "DELPHI-REG-001".to_string(),
                    cwe: Some("CWE-250".to_string()),
                    vulnerability_type: "Registry Access".to_string(),
                    severity: Severity::Medium,
                    category: "security".to_string(),
                    description: "Registry access detected - ensure proper permissions and error handling".to_string(),
                    file_path: source_file.path.to_string_lossy().to_string(),
                    line_number: line_num,
                    column: captures.get(0).map(|m| m.start()).unwrap_or(0),
                    source_code: trimmed_line.to_string(),
                    recommendation: "Validate registry access permissions and handle access denied exceptions properly".to_string(),
                });
            }

            // Check for file operations with path traversal risks
            if let Some(captures) = DELPHI_PATTERNS["file_operations"].captures(line) {
                vulnerabilities.push(Vulnerability {
                    id: "DELPHI-PATH-001".to_string(),
                    cwe: Some("CWE-22".to_string()),
                    vulnerability_type: "Path Traversal".to_string(),
                    severity: Severity::High,
                    category: "vulnerability".to_string(),
                    description: "Potential path traversal vulnerability in file operations".to_string(),
                    file_path: source_file.path.to_string_lossy().to_string(),
                    line_number: line_num,
                    column: captures.get(0).map(|m| m.start()).unwrap_or(0),
                    source_code: trimmed_line.to_string(),
                    recommendation: "Sanitize file paths and prevent directory traversal attacks".to_string(),
                });
            }

            // Check for weak cryptography
            if let Some(captures) = DELPHI_PATTERNS["weak_crypto"].captures(line) {
                vulnerabilities.push(Vulnerability {
                    id: "DELPHI-CRYPTO-001".to_string(),
                    cwe: Some("CWE-327".to_string()),
                    vulnerability_type: "Weak Cryptography".to_string(),
                    severity: Severity::Medium,
                    category: "cryptographic".to_string(),
                    description: "Weak cryptographic algorithm detected".to_string(),
                    file_path: source_file.path.to_string_lossy().to_string(),
                    line_number: line_num,
                    column: captures.get(0).map(|m| m.start()).unwrap_or(0),
                    source_code: trimmed_line.to_string(),
                    recommendation: "Use stronger cryptographic algorithms like SHA-256, AES, or modern alternatives".to_string(),
                });
            }

            // Check for process execution
            if let Some(captures) = DELPHI_PATTERNS["process_execution"].captures(line) {
                vulnerabilities.push(Vulnerability {
                    id: "DELPHI-EXEC-001".to_string(),
                    cwe: Some("CWE-78".to_string()),
                    vulnerability_type: "Command Injection Risk".to_string(),
                    severity: Severity::High,
                    category: "injection".to_string(),
                    description: "Process execution detected - validate input to prevent command injection".to_string(),
                    file_path: source_file.path.to_string_lossy().to_string(),
                    line_number: line_num,
                    column: captures.get(0).map(|m| m.start()).unwrap_or(0),
                    source_code: trimmed_line.to_string(),
                    recommendation: "Sanitize command arguments and avoid executing user-controlled input".to_string(),
                });
            }

            // Check for empty exception handlers
            if let Some(captures) = DELPHI_PATTERNS["empty_exception"].captures(line) {
                vulnerabilities.push(Vulnerability {
                    id: "DELPHI-EXCEPT-001".to_string(),
                    cwe: Some("CWE-390".to_string()),
                    vulnerability_type: "Empty Exception Handler".to_string(),
                    severity: Severity::Low,
                    category: "security".to_string(),
                    description: "Empty exception handler detected - may hide security issues".to_string(),
                    file_path: source_file.path.to_string_lossy().to_string(),
                    line_number: line_num,
                    column: captures.get(0).map(|m| m.start()).unwrap_or(0),
                    source_code: trimmed_line.to_string(),
                    recommendation: "Implement proper exception handling with logging and appropriate recovery".to_string(),
                });
            }

            // Check for weak random number generation
            if let Some(captures) = DELPHI_PATTERNS["weak_random"].captures(line) {
                vulnerabilities.push(Vulnerability {
                    id: "DELPHI-RANDOM-001".to_string(),
                    cwe: Some("CWE-338".to_string()),
                    vulnerability_type: "Weak Random Number Generation".to_string(),
                    severity: Severity::Medium,
                    category: "cryptographic".to_string(),
                    description: "Weak random number generation detected - not suitable for security purposes".to_string(),
                    file_path: source_file.path.to_string_lossy().to_string(),
                    line_number: line_num,
                    column: captures.get(0).map(|m| m.start()).unwrap_or(0),
                    source_code: trimmed_line.to_string(),
                    recommendation: "Use cryptographically secure random number generators for security-sensitive operations".to_string(),
                });
            }
        }

        Ok(vulnerabilities)
    }
}

impl Default for DelphiRules {
    fn default() -> Self {
        Self::new()
    }
}

impl RuleSet for DelphiRules {
    fn analyze(&self, source_file: &SourceFile, _ast: &ParsedAst) -> Result<Vec<Vulnerability>> {
        self.analyze_source(source_file)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::Language;
    use std::path::PathBuf;

    #[test]
    fn test_delphi_hardcoded_password_detection() {
        let rules = DelphiRules::new();
        let source_file = SourceFile {
            path: PathBuf::from("test.pas"),
            content: r#"
program Test;
const
  PASSWORD = 'hardcoded123';
var
  secret: string = 'mysecret';
begin
  writeln('Hello');
end.
"#.to_string(),
            language: Language::Delphi,
        };

        let result = rules.analyze_source(&source_file).unwrap();
        assert!(!result.is_empty());
        assert!(result.iter().any(|v| v.id == "DELPHI-CRED-001"));
    }

    #[test]
    fn test_delphi_sql_injection_detection() {
        let rules = DelphiRules::new();
        let source_file = SourceFile {
            path: PathBuf::from("test.pas"),
            content: r#"
procedure UnsafeQuery;
begin
  Query1.SQL.Text := 'SELECT * FROM users WHERE id = ' + userInput;
  Query1.ExecSQL();
end;
"#.to_string(),
            language: Language::Delphi,
        };

        let result = rules.analyze_source(&source_file).unwrap();
        assert!(result.iter().any(|v| v.id == "DELPHI-SQLI-001"));
    }

    #[test]
    fn test_delphi_unicode_ansi_conversion() {
        let rules = DelphiRules::new();
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

        let result = rules.analyze_source(&source_file).unwrap();
        assert!(result.iter().any(|v| v.id == "DELPHI-UNICODE-001"));
    }

    #[test]
    fn test_delphi_dll_loading_detection() {
        let rules = DelphiRules::new();
        let source_file = SourceFile {
            path: PathBuf::from("test.pas"),
            content: r#"
procedure LoadUnsafeDLL;
begin
  LoadLibrary('malicious.dll');
end;
"#.to_string(),
            language: Language::Delphi,
        };

        let result = rules.analyze_source(&source_file).unwrap();
        assert!(result.iter().any(|v| v.id == "DELPHI-DLL-001"));
    }
}