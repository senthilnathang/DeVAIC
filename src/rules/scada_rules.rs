use super::{create_vulnerability, RuleSet};
use crate::{
    error::Result,
    parsers::{ParsedAst, SourceFile},
    Severity, Vulnerability,
};
use regex::Regex;

pub struct ScadaRules {
    hardcoded_credentials_patterns: Vec<Regex>,
    insecure_communication_patterns: Vec<Regex>,
    unsafe_memory_operations: Vec<Regex>,
    lack_of_input_validation: Vec<Regex>,
    weak_authentication_patterns: Vec<Regex>,
}

impl ScadaRules {
    pub fn new() -> Self {
        Self {
            hardcoded_credentials_patterns: vec![
                Regex::new(r"(?i)(password|pwd|pass)\s*:=\s*'[^']{3,}'").unwrap(),
                Regex::new(r"(?i)(user|username)\s*:=\s*'admin'").unwrap(),
                Regex::new(r"(?i)default[_-]?(password|pwd)\s*:=").unwrap(),
            ],
            insecure_communication_patterns: vec![
                Regex::new(r"(?i)TCP_CONNECT\s*\(.*port\s*:=\s*23").unwrap(), // Telnet
                Regex::new(r"(?i)HTTP_CLIENT\s*\(.*ssl\s*:=\s*FALSE").unwrap(),
                Regex::new(r"(?i)MODBUS_TCP.*encryption\s*:=\s*FALSE").unwrap(),
            ],
            unsafe_memory_operations: vec![
                Regex::new(r"(?i)MEMCPY\s*\(").unwrap(),
                Regex::new(r"(?i)MEMSET\s*\(").unwrap(),
                Regex::new(r"(?i)POINTER_TO.*:=.*ADR\s*\(").unwrap(),
            ],
            lack_of_input_validation: vec![
                Regex::new(r"(?i)HMI_INPUT.*:=.*WITHOUT.*VALIDATION").unwrap(),
                Regex::new(r"(?i)(REAL|INT|DINT).*:=.*STRING_TO_(REAL|INT|DINT)").unwrap(),
            ],
            weak_authentication_patterns: vec![
                Regex::new(r"(?i)AUTH_LEVEL\s*:=\s*0").unwrap(),
                Regex::new(r"(?i)SECURITY_LEVEL\s*:=\s*(NONE|LOW)").unwrap(),
                Regex::new(r"(?i)BYPASS_AUTH\s*:=\s*TRUE").unwrap(),
            ],
        }
    }

    fn check_hardcoded_credentials(&self, source_file: &SourceFile, ast: &ParsedAst) -> Result<Vec<Vulnerability>> {
        let mut vulnerabilities = Vec::new();
        let lines: Vec<&str> = ast.source.lines().collect();

        for (line_num, line) in lines.iter().enumerate() {
            for pattern in &self.hardcoded_credentials_patterns {
                if pattern.is_match(line) {
                    vulnerabilities.push(create_vulnerability(
                        "SCADA001",
                        Some("CWE-798"),
                        "Hardcoded Credentials",
                        Severity::Critical,
                        "authentication",
                        "Hardcoded credentials detected in SCADA code",
                        &source_file.path.to_string_lossy(),
                        line_num + 1,
                        0,
                        line.trim(),
                        "Use secure credential management and avoid hardcoded passwords",
                    ));
                }
            }
        }

        Ok(vulnerabilities)
    }

    fn check_insecure_communication(&self, source_file: &SourceFile, ast: &ParsedAst) -> Result<Vec<Vulnerability>> {
        let mut vulnerabilities = Vec::new();
        let lines: Vec<&str> = ast.source.lines().collect();

        for (line_num, line) in lines.iter().enumerate() {
            for pattern in &self.insecure_communication_patterns {
                if pattern.is_match(line) {
                    let severity = if line.to_lowercase().contains("telnet") || line.contains("23") {
                        Severity::High
                    } else {
                        Severity::Medium
                    };

                    vulnerabilities.push(create_vulnerability(
                        "SCADA002",
                        Some("CWE-319"),
                        "Insecure Communication",
                        severity,
                        "cryptographic",
                        "Insecure communication protocol detected",
                        &source_file.path.to_string_lossy(),
                        line_num + 1,
                        0,
                        line.trim(),
                        "Use encrypted communication protocols (SSH, HTTPS, secure Modbus)",
                    ));
                }
            }
        }

        Ok(vulnerabilities)
    }

    fn check_unsafe_memory_operations(&self, source_file: &SourceFile, ast: &ParsedAst) -> Result<Vec<Vulnerability>> {
        let mut vulnerabilities = Vec::new();
        let lines: Vec<&str> = ast.source.lines().collect();

        for (line_num, line) in lines.iter().enumerate() {
            for pattern in &self.unsafe_memory_operations {
                if pattern.is_match(line) {
                    vulnerabilities.push(create_vulnerability(
                        "SCADA003",
                        Some("CWE-119"),
                        "Memory Safety Issue",
                        Severity::High,
                        "validation",
                        "Unsafe memory operation detected",
                        &source_file.path.to_string_lossy(),
                        line_num + 1,
                        0,
                        line.trim(),
                        "Validate memory bounds and use safe memory operations",
                    ));
                }
            }
        }

        Ok(vulnerabilities)
    }

    fn check_input_validation(&self, source_file: &SourceFile, ast: &ParsedAst) -> Result<Vec<Vulnerability>> {
        let mut vulnerabilities = Vec::new();
        let lines: Vec<&str> = ast.source.lines().collect();

        for (line_num, line) in lines.iter().enumerate() {
            for pattern in &self.lack_of_input_validation {
                if pattern.is_match(line) {
                    vulnerabilities.push(create_vulnerability(
                        "SCADA004",
                        Some("CWE-20"),
                        "Input Validation",
                        Severity::Medium,
                        "validation",
                        "Lack of input validation detected",
                        &source_file.path.to_string_lossy(),
                        line_num + 1,
                        0,
                        line.trim(),
                        "Implement proper input validation and range checking",
                    ));
                }
            }
        }

        Ok(vulnerabilities)
    }

    fn check_weak_authentication(&self, source_file: &SourceFile, ast: &ParsedAst) -> Result<Vec<Vulnerability>> {
        let mut vulnerabilities = Vec::new();
        let lines: Vec<&str> = ast.source.lines().collect();

        for (line_num, line) in lines.iter().enumerate() {
            for pattern in &self.weak_authentication_patterns {
                if pattern.is_match(line) {
                    vulnerabilities.push(create_vulnerability(
                        "SCADA005",
                        Some("CWE-287"),
                        "Weak Authentication",
                        Severity::High,
                        "authorization",
                        "Weak authentication configuration detected",
                        &source_file.path.to_string_lossy(),
                        line_num + 1,
                        0,
                        line.trim(),
                        "Implement strong authentication and authorization controls",
                    ));
                }
            }
        }

        Ok(vulnerabilities)
    }

    fn check_safety_critical_operations(&self, source_file: &SourceFile, ast: &ParsedAst) -> Result<Vec<Vulnerability>> {
        let mut vulnerabilities = Vec::new();
        let lines: Vec<&str> = ast.source.lines().collect();

        for (line_num, line) in lines.iter().enumerate() {
            let line_lower = line.to_lowercase();
            
            // Check for safety-critical operations without proper checks
            if (line_lower.contains("emergency_stop") || 
                line_lower.contains("safety_shutdown") || 
                line_lower.contains("alarm_reset")) && 
               !line_lower.contains("if") && 
               !line_lower.contains("check") {
                
                vulnerabilities.push(create_vulnerability(
                    "SCADA006",
                    Some("CWE-863"),
                    "Authorization Bypass",
                    Severity::Critical,
                    "authorization",
                    "Safety-critical operation without proper validation",
                    &source_file.path.to_string_lossy(),
                    line_num + 1,
                    0,
                    line.trim(),
                    "Add proper safety checks and validation for critical operations",
                ));
            }
        }

        Ok(vulnerabilities)
    }

    fn check_timing_vulnerabilities(&self, source_file: &SourceFile, ast: &ParsedAst) -> Result<Vec<Vulnerability>> {
        let mut vulnerabilities = Vec::new();
        let lines: Vec<&str> = ast.source.lines().collect();

        for (line_num, line) in lines.iter().enumerate() {
            let line_lower = line.to_lowercase();
            
            // Check for timing-sensitive operations without proper synchronization
            if (line_lower.contains("timer") || line_lower.contains("delay")) && 
               line_lower.contains("critical") && 
               !line_lower.contains("sync") {
                
                vulnerabilities.push(create_vulnerability(
                    "SCADA007",
                    Some("CWE-362"),
                    "Race Condition",
                    Severity::Medium,
                    "validation",
                    "Timing-sensitive operation without proper synchronization",
                    &source_file.path.to_string_lossy(),
                    line_num + 1,
                    0,
                    line.trim(),
                    "Implement proper timing synchronization for critical operations",
                ));
            }
        }

        Ok(vulnerabilities)
    }

    fn check_default_configurations(&self, source_file: &SourceFile, ast: &ParsedAst) -> Result<Vec<Vulnerability>> {
        let mut vulnerabilities = Vec::new();
        let lines: Vec<&str> = ast.source.lines().collect();

        for (line_num, line) in lines.iter().enumerate() {
            let line_lower = line.to_lowercase();
            
            // Check for default configurations that should be changed
            if line_lower.contains("default") && 
               (line_lower.contains("config") || line_lower.contains("setting")) &&
               !line_lower.contains("custom") {
                
                vulnerabilities.push(create_vulnerability(
                    "SCADA008",
                    Some("CWE-1188"),
                    "Default Configuration",
                    Severity::Low,
                    "authentication",
                    "Default configuration detected",
                    &source_file.path.to_string_lossy(),
                    line_num + 1,
                    0,
                    line.trim(),
                    "Change default configurations to secure custom values",
                ));
            }
        }

        Ok(vulnerabilities)
    }
}

impl RuleSet for ScadaRules {
    fn analyze(&self, source_file: &SourceFile, ast: &ParsedAst) -> Result<Vec<Vulnerability>> {
        let mut all_vulnerabilities = Vec::new();

        all_vulnerabilities.extend(self.check_hardcoded_credentials(source_file, ast)?);
        all_vulnerabilities.extend(self.check_insecure_communication(source_file, ast)?);
        all_vulnerabilities.extend(self.check_unsafe_memory_operations(source_file, ast)?);
        all_vulnerabilities.extend(self.check_input_validation(source_file, ast)?);
        all_vulnerabilities.extend(self.check_weak_authentication(source_file, ast)?);
        all_vulnerabilities.extend(self.check_safety_critical_operations(source_file, ast)?);
        all_vulnerabilities.extend(self.check_timing_vulnerabilities(source_file, ast)?);
        all_vulnerabilities.extend(self.check_default_configurations(source_file, ast)?);

        Ok(all_vulnerabilities)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{parsers::{scada_parser::ScadaParser, Parser, SourceFile}, Language};
    use std::path::PathBuf;

    #[test]
    fn test_hardcoded_credentials_detection() {
        let rules = ScadaRules::new();
        let parser = ScadaParser::new();
        
        let source = r#"
PROGRAM MainProgram
VAR
    user_password : STRING := 'admin123';
    default_user : STRING := 'admin';
END_VAR

// This should be detected as a vulnerability
password := 'hardcoded_secret';

END_PROGRAM
"#;
        
        let source_file = SourceFile::new(
            PathBuf::from("test.st"),
            source.to_string(),
            Language::Scada,
        );
        
        let ast = parser.unwrap().parse(&source_file).unwrap();
        let vulnerabilities = rules.analyze(&source_file, &ast).unwrap();
        
        assert!(!vulnerabilities.is_empty());
        assert!(vulnerabilities.iter().any(|v| v.id == "SCADA001"));
    }

    #[test]
    fn test_insecure_communication_detection() {
        let rules = ScadaRules::new();
        let parser = ScadaParser::new();
        
        let source = r#"
PROGRAM NetworkConfig
VAR
    tcp_connection : TCP_CLIENT;
END_VAR

// Insecure Telnet connection
TCP_CONNECT(connection := tcp_connection, port := 23);

END_PROGRAM
"#;
        
        let source_file = SourceFile::new(
            PathBuf::from("test.st"),
            source.to_string(),
            Language::Scada,
        );
        
        let ast = parser.unwrap().parse(&source_file).unwrap();
        let vulnerabilities = rules.analyze(&source_file, &ast).unwrap();
        
        assert!(vulnerabilities.iter().any(|v| v.id == "SCADA002"));
    }
}