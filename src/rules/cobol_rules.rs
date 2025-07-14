use super::{create_vulnerability, RuleSet};
use crate::{
    error::Result,
    parsers::{ParsedAst, SourceFile},
    Severity, Vulnerability,
};
use regex::Regex;

pub struct CobolRules {
    hardcoded_credentials_patterns: Vec<Regex>,
    sql_injection_patterns: Vec<Regex>,
    file_access_patterns: Vec<Regex>,
    data_exposure_patterns: Vec<Regex>,
    buffer_overflow_patterns: Vec<Regex>,
    db2_security_patterns: Vec<Regex>,
    ims_security_patterns: Vec<Regex>,
}

impl CobolRules {
    pub fn new() -> Self {
        Self {
            hardcoded_credentials_patterns: vec![
                Regex::new(r#"(?i)(PASSWORD|USERID|USER-ID)\s+(PIC|PICTURE)\s+[X9A]+\s+VALUE\s+['""][^'""]{4,}['""]"#).unwrap(),
                Regex::new(r#"(?i)DB2-USERID\s+(PIC|PICTURE)\s+[X9A]+\s+VALUE\s+['""][^'""]{4,}['""]"#).unwrap(),
                Regex::new(r#"(?i)DB2-PASSWORD\s+(PIC|PICTURE)\s+[X9A]+\s+VALUE\s+['""][^'""]{4,}['""]"#).unwrap(),
            ],
            sql_injection_patterns: vec![
                Regex::new(r#"(?i)EXEC\s+SQL\s+SELECT.*INTO.*:.*STRING\(.*\)"#).unwrap(),
                Regex::new(r#"(?i)EXEC\s+SQL\s+(SELECT|UPDATE|DELETE|INSERT).*:.*MOVE.*TO.*WHERE"#).unwrap(),
                Regex::new(r#"(?i)EXEC\s+SQL\s+PREPARE.*FROM.*:.*['""].*['""]"#).unwrap(),
            ],
            file_access_patterns: vec![
                Regex::new(r#"(?i)OPEN\s+(INPUT|OUTPUT|I-O)\s+[A-Z0-9-]+\s+FILE\s+STATUS"#).unwrap(),
                Regex::new(r#"(?i)SELECT\s+[A-Z0-9-]+\s+ASSIGN\s+TO\s+['""][^'""]*['""]"#).unwrap(),
                Regex::new(r#"(?i)ACCEPT\s+[A-Z0-9-]+\s+FROM\s+(COMMAND-LINE|ENVIRONMENT)"#).unwrap(),
            ],
            data_exposure_patterns: vec![
                Regex::new(r#"(?i)DISPLAY\s+['""][^'""]*SSN[^'""]*['""]"#).unwrap(),
                Regex::new(r#"(?i)DISPLAY\s+['""][^'""]*CREDIT[^'""]*CARD[^'""]*['""]"#).unwrap(),
                Regex::new(r#"(?i)DISPLAY\s+['""][^'""]*PASSWORD[^'""]*['""]"#).unwrap(),
                Regex::new(r#"(?i)WRITE\s+.*-REC\s+FROM\s+.*SSN"#).unwrap(),
            ],
            buffer_overflow_patterns: vec![
                Regex::new(r#"(?i)MOVE\s+ALL\s+['""][^'""]*['""].*TO\s+[A-Z0-9-]+\s*\("#).unwrap(),
                Regex::new(r#"(?i)STRING\s+.*DELIMITED\s+BY.*INTO\s+[A-Z0-9-]+\s*\("#).unwrap(),
                Regex::new(r#"(?i)UNSTRING\s+.*INTO\s+[A-Z0-9-]+\s*\("#).unwrap(),
            ],
            db2_security_patterns: vec![
                Regex::new(r#"(?i)EXEC\s+SQL\s+CONNECT\s+TO.*USER.*USING.*['""][^'""]*['""]"#).unwrap(),
                Regex::new(r#"(?i)EXEC\s+SQL\s+GRANT\s+(ALL|SELECT|INSERT|UPDATE|DELETE)"#).unwrap(),
                Regex::new(r#"(?i)SQLCA\s+.*SQLCODE\s+.*0"#).unwrap(),
            ],
            ims_security_patterns: vec![
                Regex::new(r#"(?i)GU\s+[A-Z0-9-]+\s*\(\s*[A-Z0-9-]+=.*\)"#).unwrap(),
                Regex::new(r#"(?i)(REPL|DLET)\s+[A-Z0-9-]+\s*\(\s*[A-Z0-9-]+=.*\)"#).unwrap(),
                Regex::new(r#"(?i)PCB\s+.*CALL\s+['""]CBLTDLI['""]"#).unwrap(),
            ],
        }
    }
}

impl RuleSet for CobolRules {
    fn analyze(&self, source_file: &SourceFile, _ast: &ParsedAst) -> Result<Vec<Vulnerability>> {
        let mut vulnerabilities = Vec::new();
        let content = &source_file.content;
        let file_path = source_file.path.to_string_lossy();

        // Check for hardcoded credentials
        for (line_num, line) in content.lines().enumerate() {
            for pattern in &self.hardcoded_credentials_patterns {
                if pattern.is_match(line) {
                    vulnerabilities.push(create_vulnerability(
                        "cobol-hardcoded-credentials",
                        Some("CWE-798"),
                        "Hardcoded Credentials",
                        Severity::High,
                        "security",
                        "Hardcoded credentials detected in COBOL source code",
                        &file_path,
                        line_num + 1,
                        0,
                        line,
                        "Store credentials in external configuration or use secure credential management systems",
                    ));
                }
            }

            // Check for SQL injection vulnerabilities
            for pattern in &self.sql_injection_patterns {
                if pattern.is_match(line) {
                    vulnerabilities.push(create_vulnerability(
                        "cobol-sql-injection",
                        Some("CWE-89"),
                        "SQL Injection",
                        Severity::High,
                        "injection",
                        "Potential SQL injection vulnerability in COBOL embedded SQL",
                        &file_path,
                        line_num + 1,
                        0,
                        line,
                        "Use parameterized queries and input validation",
                    ));
                }
            }

            // Check for insecure file access
            for pattern in &self.file_access_patterns {
                if pattern.is_match(line) {
                    vulnerabilities.push(create_vulnerability(
                        "cobol-insecure-file-access",
                        Some("CWE-73"),
                        "Insecure File Access",
                        Severity::Medium,
                        "security",
                        "Potentially insecure file access pattern detected",
                        &file_path,
                        line_num + 1,
                        0,
                        line,
                        "Validate file paths and implement proper access controls",
                    ));
                }
            }

            // Check for data exposure
            for pattern in &self.data_exposure_patterns {
                if pattern.is_match(line) {
                    vulnerabilities.push(create_vulnerability(
                        "cobol-data-exposure",
                        Some("CWE-200"),
                        "Information Disclosure",
                        Severity::Medium,
                        "privacy",
                        "Sensitive data may be exposed through display or write operations",
                        &file_path,
                        line_num + 1,
                        0,
                        line,
                        "Avoid displaying or logging sensitive information like SSN, credit cards, or passwords",
                    ));
                }
            }

            // Check for buffer overflow vulnerabilities
            for pattern in &self.buffer_overflow_patterns {
                if pattern.is_match(line) {
                    vulnerabilities.push(create_vulnerability(
                        "cobol-buffer-overflow",
                        Some("CWE-120"),
                        "Buffer Overflow Risk",
                        Severity::High,
                        "vulnerability",
                        "Potential buffer overflow in string operations",
                        &file_path,
                        line_num + 1,
                        0,
                        line,
                        "Use length checking and proper bounds validation in string operations",
                    ));
                }
            }

            // Check for DB2 security issues
            for pattern in &self.db2_security_patterns {
                if pattern.is_match(line) {
                    vulnerabilities.push(create_vulnerability(
                        "cobol-db2-security",
                        Some("CWE-863"),
                        "DB2 Security Issue",
                        Severity::Medium,
                        "security",
                        "DB2 security configuration issue detected",
                        &file_path,
                        line_num + 1,
                        0,
                        line,
                        "Review DB2 security settings and use proper authentication mechanisms",
                    ));
                }
            }

            // Check for IMS security issues
            for pattern in &self.ims_security_patterns {
                if pattern.is_match(line) {
                    vulnerabilities.push(create_vulnerability(
                        "cobol-ims-security",
                        Some("CWE-863"),
                        "IMS Security Issue",
                        Severity::Medium,
                        "security",
                        "IMS database operation security issue detected",
                        &file_path,
                        line_num + 1,
                        0,
                        line,
                        "Review IMS security settings and implement proper access controls",
                    ));
                }
            }
        }

        Ok(vulnerabilities)
    }
}