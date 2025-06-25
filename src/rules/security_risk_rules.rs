use crate::{
    error::Result,
    parsers::{ParsedAst, SourceFile},
    rules::{create_vulnerability, RuleSet},
    Severity, Vulnerability,
};
use regex::Regex;

pub struct SecurityRiskRules {
    access_control_patterns: Vec<SecurityPattern>,
    cryptographic_patterns: Vec<SecurityPattern>,
    data_integrity_patterns: Vec<SecurityPattern>,
    authentication_patterns: Vec<SecurityPattern>,
    logging_patterns: Vec<SecurityPattern>,
    configuration_patterns: Vec<SecurityPattern>,
}

#[derive(Clone)]
struct SecurityPattern {
    id: String,
    name: String,
    pattern: Regex,
    category: String,
    severity: Severity,
    description: String,
    recommendation: String,
    cwe: String,
    owasp_category: String,
}

impl SecurityRiskRules {
    pub fn new() -> Self {
        let mut access_control_patterns = Vec::new();
        let mut cryptographic_patterns = Vec::new();
        let mut data_integrity_patterns = Vec::new();
        let mut authentication_patterns = Vec::new();
        let mut logging_patterns = Vec::new();
        let mut configuration_patterns = Vec::new();

        // Access Control Patterns
        access_control_patterns.extend(vec![
            SecurityPattern {
                id: "weak-file-permissions".to_string(),
                name: "Weak File Permissions".to_string(),
                pattern: Regex::new(r"(?i)(chmod|umask)\s+(777|666|755)").unwrap(),
                category: "security".to_string(),
                severity: Severity::High,
                description: "Overly permissive file permissions detected".to_string(),
                recommendation: "Use restrictive file permissions (644 for files, 755 for directories)".to_string(),
                cwe: "CWE-732".to_string(),
                owasp_category: "A01:2021 – Broken Access Control".to_string(),
            },
            SecurityPattern {
                id: "sudo-without-password".to_string(),
                name: "Sudo Without Password".to_string(),
                pattern: Regex::new(r"(?i)sudo\s+.*NOPASSWD").unwrap(),
                category: "security".to_string(),
                severity: Severity::High,
                description: "Sudo configuration without password requirement detected".to_string(),
                recommendation: "Require password authentication for sudo commands".to_string(),
                cwe: "CWE-284".to_string(),
                owasp_category: "A01:2021 – Broken Access Control".to_string(),
            },
            SecurityPattern {
                id: "world-writable-files".to_string(),
                name: "World Writable Files".to_string(),
                pattern: Regex::new(r"(?i)open.*w").unwrap(),
                category: "security".to_string(),
                severity: Severity::Medium,
                description: "File opened with potentially unsafe write permissions".to_string(),
                recommendation: "Use restrictive file permissions and validate file paths".to_string(),
                cwe: "CWE-732".to_string(),
                owasp_category: "A01:2021 – Broken Access Control".to_string(),
            },
        ]);

        // Cryptographic Patterns
        cryptographic_patterns.extend(vec![
            SecurityPattern {
                id: "weak-hash-algorithm".to_string(),
                name: "Weak Hash Algorithm".to_string(),
                pattern: Regex::new(r"(?i)(md5|sha1|hashlib\.(md5|sha1))\s*\(").unwrap(),
                category: "security".to_string(),
                severity: Severity::High,
                description: "Weak cryptographic hash algorithm detected".to_string(),
                recommendation: "Use secure hash algorithms like SHA-256, SHA-3, or bcrypt for passwords".to_string(),
                cwe: "CWE-327".to_string(),
                owasp_category: "A02:2021 – Cryptographic Failures".to_string(),
            },
            SecurityPattern {
                id: "weak-encryption-algorithm".to_string(),
                name: "Weak Encryption Algorithm".to_string(),
                pattern: Regex::new(r"(?i)(des|3des|rc4|aes-cbc)\s*[\(\[]").unwrap(),
                category: "security".to_string(),
                severity: Severity::High,
                description: "Weak encryption algorithm detected".to_string(),
                recommendation: "Use strong encryption algorithms like AES-256-GCM, ChaCha20-Poly1305".to_string(),
                cwe: "CWE-327".to_string(),
                owasp_category: "A02:2021 – Cryptographic Failures".to_string(),
            },
            SecurityPattern {
                id: "hardcoded-encryption-key".to_string(),
                name: "Hardcoded Encryption Key".to_string(),
                pattern: Regex::new(r"(?i)(key|secret|cipher).*=.*[a-fA-F0-9]{32,}").unwrap(),
                category: "security".to_string(),
                severity: Severity::Critical,
                description: "Hardcoded encryption key or secret detected".to_string(),
                recommendation: "Use secure key management systems and environment variables".to_string(),
                cwe: "CWE-798".to_string(),
                owasp_category: "A02:2021 – Cryptographic Failures".to_string(),
            },
            SecurityPattern {
                id: "weak-random-generator".to_string(),
                name: "Weak Random Number Generator".to_string(),
                pattern: Regex::new(r"(?i)(random\.random|math\.random|rand\(\)|srand\(\))").unwrap(),
                category: "security".to_string(),
                severity: Severity::Medium,
                description: "Weak random number generator used for security purposes".to_string(),
                recommendation: "Use cryptographically secure random number generators (secrets module in Python, crypto.randomBytes in Node.js)".to_string(),
                cwe: "CWE-338".to_string(),
                owasp_category: "A02:2021 – Cryptographic Failures".to_string(),
            },
        ]);

        // Authentication Patterns
        authentication_patterns.extend(vec![
            SecurityPattern {
                id: "weak-password-policy".to_string(),
                name: "Weak Password Policy".to_string(),
                pattern: Regex::new(r"(?i)(password|pwd).{0,30}(length|min).{0,10}[<>=]\s*[1-7]").unwrap(),
                category: "security".to_string(),
                severity: Severity::Medium,
                description: "Weak password policy detected".to_string(),
                recommendation: "Implement strong password policies (minimum 8 characters, complexity requirements)".to_string(),
                cwe: "CWE-521".to_string(),
                owasp_category: "A07:2021 – Identification and Authentication Failures".to_string(),
            },
            SecurityPattern {
                id: "default-credentials".to_string(),
                name: "Default Credentials".to_string(),
                pattern: Regex::new(r"(?i)(admin|root|administrator).*=.*(admin|password|123456|root|default)").unwrap(),
                category: "security".to_string(),
                severity: Severity::Critical,
                description: "Default or weak credentials detected".to_string(),
                recommendation: "Change default credentials and use strong, unique passwords".to_string(),
                cwe: "CWE-798".to_string(),
                owasp_category: "A07:2021 – Identification and Authentication Failures".to_string(),
            },
            SecurityPattern {
                id: "session-without-timeout".to_string(),
                name: "Session Without Timeout".to_string(),
                pattern: Regex::new(r"(?i)(session|cookie).*(timeout|expire|maxage).*(-1|0|null|none)").unwrap(),
                category: "security".to_string(),
                severity: Severity::Medium,
                description: "Session without timeout configuration detected".to_string(),
                recommendation: "Implement session timeouts and proper session management".to_string(),
                cwe: "CWE-613".to_string(),
                owasp_category: "A07:2021 – Identification and Authentication Failures".to_string(),
            },
        ]);

        // Data Integrity Patterns
        data_integrity_patterns.extend(vec![
            SecurityPattern {
                id: "sql-injection-risk".to_string(),
                name: "SQL Injection Risk".to_string(),
                pattern: Regex::new(r"(?i)(execute|query|sql).*\+").unwrap(),
                category: "security".to_string(),
                severity: Severity::Critical,
                description: "Potential SQL injection vulnerability detected".to_string(),
                recommendation: "Use parameterized queries or prepared statements".to_string(),
                cwe: "CWE-89".to_string(),
                owasp_category: "A03:2021 – Injection".to_string(),
            },
            SecurityPattern {
                id: "command-injection-risk".to_string(),
                name: "Command Injection Risk".to_string(),
                pattern: Regex::new(r"(?i)(exec|system|popen|subprocess).*\+").unwrap(),
                category: "security".to_string(),
                severity: Severity::Critical,
                description: "Potential command injection vulnerability detected".to_string(),
                recommendation: "Validate and sanitize input, use subprocess with shell=False".to_string(),
                cwe: "CWE-78".to_string(),
                owasp_category: "A03:2021 – Injection".to_string(),
            },
            SecurityPattern {
                id: "path-traversal-risk".to_string(),
                name: "Path Traversal Risk".to_string(),
                pattern: Regex::new(r"(?i)(open|file|read|write).*\.\./").unwrap(),
                category: "security".to_string(),
                severity: Severity::High,
                description: "Potential path traversal vulnerability detected".to_string(),
                recommendation: "Validate and sanitize file paths, use os.path.join()".to_string(),
                cwe: "CWE-22".to_string(),
                owasp_category: "A01:2021 – Broken Access Control".to_string(),
            },
        ]);

        // Logging and Monitoring Patterns
        logging_patterns.extend(vec![
            SecurityPattern {
                id: "insufficient-logging".to_string(),
                name: "Insufficient Security Logging".to_string(),
                pattern: Regex::new(r"(?i)(login|authentication|access|permission).*(fail|error|denied)").unwrap(),
                category: "security".to_string(),
                severity: Severity::Low,
                description: "Authentication failure without proper logging detected".to_string(),
                recommendation: "Implement comprehensive security logging and monitoring".to_string(),
                cwe: "CWE-778".to_string(),
                owasp_category: "A09:2021 – Security Logging and Monitoring Failures".to_string(),
            },
            SecurityPattern {
                id: "debug-mode-enabled".to_string(),
                name: "Debug Mode Enabled".to_string(),
                pattern: Regex::new(r"(?i)(debug|development)\s*[=:]\s*(true|1|yes|on)").unwrap(),
                category: "security".to_string(),
                severity: Severity::Medium,
                description: "Debug mode enabled in production code detected".to_string(),
                recommendation: "Disable debug mode in production environments".to_string(),
                cwe: "CWE-489".to_string(),
                owasp_category: "A05:2021 – Security Misconfiguration".to_string(),
            },
        ]);

        // Configuration Patterns
        configuration_patterns.extend(vec![
            SecurityPattern {
                id: "insecure-http-methods".to_string(),
                name: "Insecure HTTP Methods".to_string(),
                pattern: Regex::new(r"(?i)(trace|track|debug|options)\s+.*http").unwrap(),
                category: "security".to_string(),
                severity: Severity::Medium,
                description: "Insecure HTTP methods enabled detected".to_string(),
                recommendation: "Disable unnecessary HTTP methods like TRACE, TRACK".to_string(),
                cwe: "CWE-200".to_string(),
                owasp_category: "A05:2021 – Security Misconfiguration".to_string(),
            },
            SecurityPattern {
                id: "cors-wildcard".to_string(),
                name: "CORS Wildcard Configuration".to_string(),
                pattern: Regex::new(r"(?i)(access-control-allow-origin|cors).*\*").unwrap(),
                category: "security".to_string(),
                severity: Severity::High,
                description: "CORS wildcard configuration detected".to_string(),
                recommendation: "Use specific origins instead of wildcard in CORS configuration".to_string(),
                cwe: "CWE-942".to_string(),
                owasp_category: "A05:2021 – Security Misconfiguration".to_string(),
            },
        ]);

        Self {
            access_control_patterns,
            cryptographic_patterns,
            data_integrity_patterns,
            authentication_patterns,
            logging_patterns,
            configuration_patterns,
        }
    }

    fn check_patterns(&self, source_file: &SourceFile, patterns: &[SecurityPattern]) -> Result<Vec<Vulnerability>> {
        let mut vulnerabilities = Vec::new();
        let lines: Vec<&str> = source_file.content.lines().collect();

        for (line_index, line) in lines.iter().enumerate() {
            for pattern in patterns {
                if let Some(captures) = pattern.pattern.captures(line) {
                    if let Some(matched) = captures.get(0) {
                        let vulnerability = create_vulnerability(
                            &pattern.id,
                            Some(&pattern.cwe),
                            &pattern.name,
                            pattern.severity.clone(),
                            &pattern.category,
                            &format!("{} - {}", pattern.description, pattern.owasp_category),
                            &source_file.path.to_string_lossy(),
                            line_index + 1,
                            matched.start(),
                            line.trim(),
                            &pattern.recommendation,
                        );
                        vulnerabilities.push(vulnerability);
                    }
                }
            }
        }

        Ok(vulnerabilities)
    }
}

impl RuleSet for SecurityRiskRules {
    fn analyze(&self, source_file: &SourceFile, _ast: &ParsedAst) -> Result<Vec<Vulnerability>> {
        let mut vulnerabilities = Vec::new();

        // Check all security risk patterns
        vulnerabilities.extend(self.check_patterns(source_file, &self.access_control_patterns)?);
        vulnerabilities.extend(self.check_patterns(source_file, &self.cryptographic_patterns)?);
        vulnerabilities.extend(self.check_patterns(source_file, &self.data_integrity_patterns)?);
        vulnerabilities.extend(self.check_patterns(source_file, &self.authentication_patterns)?);
        vulnerabilities.extend(self.check_patterns(source_file, &self.logging_patterns)?);
        vulnerabilities.extend(self.check_patterns(source_file, &self.configuration_patterns)?);

        Ok(vulnerabilities)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{Language, parsers::SourceFile};
    use std::path::PathBuf;

    #[test]
    fn test_weak_hash_detection() {
        let rules = SecurityRiskRules::new();
        let source = SourceFile::new(
            PathBuf::from("test.py"),
            "import hashlib; hashlib.md5(data)".to_string(),
            Language::Python,
        );
        let ast = crate::parsers::ParsedAst::new_source_only(source.content.clone());
        let vulnerabilities = rules.analyze(&source, &ast).unwrap();
        assert!(!vulnerabilities.is_empty());
        assert_eq!(vulnerabilities[0].id, "weak-hash-algorithm");
    }

    #[test]
    fn test_sql_injection_detection() {
        let rules = SecurityRiskRules::new();
        let source = SourceFile::new(
            PathBuf::from("test.py"),
            "query(\"SELECT * FROM users WHERE id = \" + user_input)".to_string(),
            Language::Python,
        );
        let ast = crate::parsers::ParsedAst::new_source_only(source.content.clone());
        let vulnerabilities = rules.analyze(&source, &ast).unwrap();
        assert!(!vulnerabilities.is_empty());
        assert_eq!(vulnerabilities[0].id, "sql-injection-risk");
    }

    #[test]
    fn test_cors_wildcard_detection() {
        let rules = SecurityRiskRules::new();
        let source = SourceFile::new(
            PathBuf::from("test.js"),
            "app.use(cors({ origin: \"*\" }))".to_string(),
            Language::Javascript,
        );
        let ast = crate::parsers::ParsedAst::new_source_only(source.content.clone());
        let vulnerabilities = rules.analyze(&source, &ast).unwrap();
        assert!(!vulnerabilities.is_empty());
        assert_eq!(vulnerabilities[0].id, "cors-wildcard");
    }
}