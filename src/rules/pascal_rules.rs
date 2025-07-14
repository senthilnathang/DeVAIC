use super::{create_vulnerability, RuleSet};
use crate::{
    error::Result,
    parsers::{ParsedAst, SourceFile},
    Severity, Vulnerability,
};
use regex::Regex;

pub struct PascalRules {
    buffer_overflow_patterns: Vec<Regex>,
    sql_injection_patterns: Vec<Regex>,
    file_access_patterns: Vec<Regex>,
    memory_management_patterns: Vec<Regex>,
    unsafe_type_casting_patterns: Vec<Regex>,
    hardcoded_secrets_patterns: Vec<Regex>,
    input_validation_patterns: Vec<Regex>,
    format_string_patterns: Vec<Regex>,
}

impl PascalRules {
    pub fn new() -> Self {
        Self {
            buffer_overflow_patterns: vec![
                Regex::new(r#"(?i)StrCopy\s*\(\s*[^,]+,\s*[^)]+\)"#).unwrap(),
                Regex::new(r#"(?i)StrCat\s*\(\s*[^,]+,\s*[^)]+\)"#).unwrap(),
                Regex::new(r#"(?i)Move\s*\(\s*[^,]+,\s*[^,]+,\s*\d+\s*\)"#).unwrap(),
                Regex::new(r#"(?i)FillChar\s*\(\s*[^,]+,\s*\d+,\s*[^)]+\)"#).unwrap(),
            ],
            sql_injection_patterns: vec![
                Regex::new(r#"(?i)Query\.SQL\.Add\s*\(\s*['""][^'""]*\+.*['""]"#).unwrap(),
                Regex::new(r#"(?i)ExecSQL\s*\(\s*['""][^'""]*\+.*['""]"#).unwrap(),
                Regex::new(r#"(?i)SQLQuery\s*:=\s*['""][^'""]*\+.*['""]"#).unwrap(),
            ],
            file_access_patterns: vec![
                Regex::new(r#"(?i)Assign\s*\(\s*[^,]+,\s*['""][^'""]*['""]"#).unwrap(),
                Regex::new(r#"(?i)Reset\s*\(\s*[^)]+\)"#).unwrap(),
                Regex::new(r#"(?i)Rewrite\s*\(\s*[^)]+\)"#).unwrap(),
                Regex::new(r#"(?i)ChDir\s*\(\s*['""][^'""]*['""]"#).unwrap(),
            ],
            memory_management_patterns: vec![
                Regex::new(r#"(?i)GetMem\s*\(\s*[^,]+,\s*[^)]+\)"#).unwrap(),
                Regex::new(r#"(?i)New\s*\(\s*[^)]+\)"#).unwrap(),
                Regex::new(r#"(?i)Dispose\s*\(\s*[^)]+\)"#).unwrap(),
                Regex::new(r#"(?i)FreeMem\s*\(\s*[^)]+\)"#).unwrap(),
            ],
            unsafe_type_casting_patterns: vec![
                Regex::new(r#"(?i)(PChar|PAnsiChar|PWideChar)\s*\(\s*[^)]+\)"#).unwrap(),
                Regex::new(r#"(?i)Pointer\s*\(\s*[^)]+\)"#).unwrap(),
                Regex::new(r#"(?i)@[A-Za-z_][A-Za-z0-9_]*\[\s*[^]]+\]"#).unwrap(),
            ],
            hardcoded_secrets_patterns: vec![
                Regex::new(r#"(?i)(password|pwd|secret|key|token)\s*:=\s*['""][^'""]{8,}['""]"#).unwrap(),
                Regex::new(r#"(?i)ConnectionString\s*:=\s*['""][^'""]*password=[^'""]*['""]"#).unwrap(),
                Regex::new(r#"(?i)const\s+[A-Za-z_][A-Za-z0-9_]*\s*=\s*['""][^'""]{20,}['""]"#).unwrap(),
            ],
            input_validation_patterns: vec![
                Regex::new(r#"(?i)ReadLn\s*\(\s*[^)]+\)"#).unwrap(),
                Regex::new(r#"(?i)Read\s*\(\s*[^)]+\)"#).unwrap(),
                Regex::new(r#"(?i)Val\s*\(\s*[^,]+,\s*[^,]+,\s*[^)]+\)"#).unwrap(),
            ],
            format_string_patterns: vec![
                Regex::new(r#"(?i)Format\s*\(\s*[^,]+,\s*\[[^\]]*\]"#).unwrap(),
                Regex::new(r#"(?i)WriteLn\s*\(\s*[^,]*,\s*[^)]*:[^)]*\)"#).unwrap(),
                Regex::new(r#"(?i)Write\s*\(\s*[^,]*,\s*[^)]*:[^)]*\)"#).unwrap(),
            ],
        }
    }
}

impl RuleSet for PascalRules {
    fn analyze(&self, source_file: &SourceFile, _ast: &ParsedAst) -> Result<Vec<Vulnerability>> {
        let mut vulnerabilities = Vec::new();
        let content = &source_file.content;
        let file_path = source_file.path.to_string_lossy();

        // Check for buffer overflow vulnerabilities
        for (line_num, line) in content.lines().enumerate() {
            for pattern in &self.buffer_overflow_patterns {
                if pattern.is_match(line) {
                    vulnerabilities.push(create_vulnerability(
                        "pascal-buffer-overflow",
                        Some("CWE-120"),
                        "Buffer Overflow Risk",
                        Severity::High,
                        "vulnerability",
                        "Potential buffer overflow in string manipulation functions",
                        &file_path,
                        line_num + 1,
                        0,
                        line,
                        "Use length-safe string functions and validate buffer bounds",
                    ));
                }
            }

            // Check for SQL injection vulnerabilities
            for pattern in &self.sql_injection_patterns {
                if pattern.is_match(line) {
                    vulnerabilities.push(create_vulnerability(
                        "pascal-sql-injection",
                        Some("CWE-89"),
                        "SQL Injection",
                        Severity::High,
                        "injection",
                        "Potential SQL injection vulnerability in dynamic query construction",
                        &file_path,
                        line_num + 1,
                        0,
                        line,
                        "Use parameterized queries or prepared statements",
                    ));
                }
            }

            // Check for insecure file access
            for pattern in &self.file_access_patterns {
                if pattern.is_match(line) {
                    vulnerabilities.push(create_vulnerability(
                        "pascal-file-access",
                        Some("CWE-73"),
                        "Insecure File Access",
                        Severity::Medium,
                        "security",
                        "Potentially insecure file access operation",
                        &file_path,
                        line_num + 1,
                        0,
                        line,
                        "Validate file paths and implement proper access controls",
                    ));
                }
            }

            // Check for memory management issues
            for pattern in &self.memory_management_patterns {
                if pattern.is_match(line) {
                    vulnerabilities.push(create_vulnerability(
                        "pascal-memory-management",
                        Some("CWE-401"),
                        "Memory Management Issue",
                        Severity::Medium,
                        "vulnerability",
                        "Manual memory management detected - potential for memory leaks",
                        &file_path,
                        line_num + 1,
                        0,
                        line,
                        "Ensure proper memory deallocation and consider using automatic memory management",
                    ));
                }
            }

            // Check for unsafe type casting
            for pattern in &self.unsafe_type_casting_patterns {
                if pattern.is_match(line) {
                    vulnerabilities.push(create_vulnerability(
                        "pascal-unsafe-type-cast",
                        Some("CWE-843"),
                        "Unsafe Type Casting",
                        Severity::Medium,
                        "vulnerability",
                        "Unsafe type casting to pointer types detected",
                        &file_path,
                        line_num + 1,
                        0,
                        line,
                        "Validate type casts and avoid direct pointer manipulation",
                    ));
                }
            }

            // Check for hardcoded secrets
            for pattern in &self.hardcoded_secrets_patterns {
                if pattern.is_match(line) {
                    vulnerabilities.push(create_vulnerability(
                        "pascal-hardcoded-secrets",
                        Some("CWE-798"),
                        "Hardcoded Credentials",
                        Severity::High,
                        "security",
                        "Hardcoded credentials or secrets detected",
                        &file_path,
                        line_num + 1,
                        0,
                        line,
                        "Store credentials in external configuration or secure credential storage",
                    ));
                }
            }

            // Check for input validation issues
            for pattern in &self.input_validation_patterns {
                if pattern.is_match(line) {
                    vulnerabilities.push(create_vulnerability(
                        "pascal-input-validation",
                        Some("CWE-20"),
                        "Insufficient Input Validation",
                        Severity::Medium,
                        "validation",
                        "User input read without apparent validation",
                        &file_path,
                        line_num + 1,
                        0,
                        line,
                        "Implement proper input validation and sanitization",
                    ));
                }
            }

            // Check for format string vulnerabilities
            for pattern in &self.format_string_patterns {
                if pattern.is_match(line) {
                    vulnerabilities.push(create_vulnerability(
                        "pascal-format-string",
                        Some("CWE-134"),
                        "Format String Vulnerability",
                        Severity::Medium,
                        "vulnerability",
                        "Potential format string vulnerability in output functions",
                        &file_path,
                        line_num + 1,
                        0,
                        line,
                        "Use fixed format strings and validate user input in format operations",
                    ));
                }
            }
        }

        Ok(vulnerabilities)
    }
}