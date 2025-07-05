use crate::{
    error::Result,
    parsers::{ParsedAst, SourceFile},
    rules::{create_vulnerability, RuleSet},
    Severity, Vulnerability,
};
use regex::Regex;
use lazy_static::lazy_static;

pub struct RubyRules;

impl RubyRules {
    pub fn new() -> Self {
        Self
    }
}

lazy_static! {
    static ref SQL_INJECTION_PATTERNS: Vec<Regex> = vec![
        Regex::new(r#"\.execute\s*\([^)]*#\{[^}]*\}[^)]*\)"#).unwrap(),
        Regex::new(r#"\.find_by_sql\s*\([^)]*#\{[^}]*\}[^)]*\)"#).unwrap(),
        Regex::new(r#"\.where\s*\([^)]*#\{[^}]*\}[^)]*\)"#).unwrap(),
    ];
    
    static ref COMMAND_INJECTION_PATTERNS: Vec<Regex> = vec![
        Regex::new(r#"system\s*\([^)]*#\{[^}]*\}[^)]*\)"#).unwrap(),
        Regex::new(r#"`[^`]*#\{[^}]*\}[^`]*`"#).unwrap(),
        Regex::new(r#"exec\s*\([^)]*#\{[^}]*\}[^)]*\)"#).unwrap(),
    ];
    
    static ref EVAL_INJECTION_PATTERNS: Vec<Regex> = vec![
        Regex::new(r#"eval\s*\([^)]*params\[[^]]*\][^)]*\)"#).unwrap(),
        Regex::new(r#"instance_eval\s*\([^)]*params\[[^]]*\][^)]*\)"#).unwrap(),
    ];
    
    static ref MASS_ASSIGNMENT_PATTERNS: Vec<Regex> = vec![
        Regex::new(r#"\.new\s*\(\s*params\[[^]]*\]\s*\)"#).unwrap(),
        Regex::new(r#"\.update_attributes\s*\(\s*params\[[^]]*\]\s*\)"#).unwrap(),
        Regex::new(r#"\.attributes\s*=\s*params\[[^]]*\]"#).unwrap(),
    ];
    
    static ref YAML_DESERIALIZATION_PATTERNS: Vec<Regex> = vec![
        Regex::new(r#"YAML\.load\s*\([^)]*params\[[^]]*\][^)]*\)"#).unwrap(),
        Regex::new(r#"YAML\.load_file\s*\([^)]*params\[[^]]*\][^)]*\)"#).unwrap(),
    ];
    
    static ref HARDCODED_SECRET_PATTERNS: Vec<Regex> = vec![
        Regex::new(r#"(?i)(password|secret|key|token)\s*=\s*['"][^'"]{8,}['"]"#).unwrap(),
        Regex::new(r#"(?i)(api_key|apikey)\s*=\s*['"][^'"]{20,}['"]"#).unwrap(),
    ];
}

impl RuleSet for RubyRules {
    fn analyze(&self, source_file: &SourceFile, _ast: &ParsedAst) -> Result<Vec<Vulnerability>> {
        let mut vulnerabilities = Vec::new();
        let content = &source_file.content;
        let lines: Vec<&str> = content.lines().collect();

        for (line_number, line) in lines.iter().enumerate() {
            let line_num = line_number + 1;

            // SQL Injection Detection
            for pattern in SQL_INJECTION_PATTERNS.iter() {
                if pattern.is_match(line) {
                    vulnerabilities.push(create_vulnerability(
                        "RUBY-SQL-001",
                        Some("CWE-89"),
                        "SQL Injection",
                        Severity::High,
                        "injection",
                        "SQL injection vulnerability detected in Ruby database query",
                        &source_file.path.to_string_lossy(),
                        line_num,
                        0,
                        line,
                        "Use parameterized queries: User.where('name = ?', params[:name])",
                    ));
                }
            }

            // Command Injection Detection
            for pattern in COMMAND_INJECTION_PATTERNS.iter() {
                if pattern.is_match(line) {
                    vulnerabilities.push(create_vulnerability(
                        "RUBY-CMD-001",
                        Some("CWE-78"),
                        "Command Injection",
                        Severity::High,
                        "injection",
                        "Command injection vulnerability detected in Ruby system call",
                        &source_file.path.to_string_lossy(),
                        line_num,
                        0,
                        line,
                        "Use system() with array arguments or validate input: system(['ls', user_input])",
                    ));
                }
            }

            // Eval Injection Detection
            for pattern in EVAL_INJECTION_PATTERNS.iter() {
                if pattern.is_match(line) {
                    vulnerabilities.push(create_vulnerability(
                        "RUBY-EVAL-001",
                        Some("CWE-94"),
                        "Code Injection",
                        Severity::Critical,
                        "injection",
                        "Code injection vulnerability detected in Ruby eval",
                        &source_file.path.to_string_lossy(),
                        line_num,
                        0,
                        line,
                        "Avoid using eval with user input. Use safer alternatives like send() with whitelisted methods",
                    ));
                }
            }

            // Mass Assignment Detection
            for pattern in MASS_ASSIGNMENT_PATTERNS.iter() {
                if pattern.is_match(line) {
                    vulnerabilities.push(create_vulnerability(
                        "RUBY-MASS-001",
                        Some("CWE-915"),
                        "Mass Assignment",
                        Severity::Medium,
                        "validation",
                        "Mass assignment vulnerability detected in Ruby model",
                        &source_file.path.to_string_lossy(),
                        line_num,
                        0,
                        line,
                        "Use strong parameters: params.require(:user).permit(:name, :email)",
                    ));
                }
            }

            // YAML Deserialization Detection
            for pattern in YAML_DESERIALIZATION_PATTERNS.iter() {
                if pattern.is_match(line) {
                    vulnerabilities.push(create_vulnerability(
                        "RUBY-YAML-001",
                        Some("CWE-502"),
                        "Unsafe Deserialization",
                        Severity::High,
                        "deserialization",
                        "Unsafe YAML deserialization detected in Ruby code",
                        &source_file.path.to_string_lossy(),
                        line_num,
                        0,
                        line,
                        "Use YAML.safe_load() instead of YAML.load() for untrusted input",
                    ));
                }
            }

            // Hardcoded Secrets Detection
            for pattern in HARDCODED_SECRET_PATTERNS.iter() {
                if pattern.is_match(line) {
                    vulnerabilities.push(create_vulnerability(
                        "RUBY-SECRET-001",
                        Some("CWE-798"),
                        "Hardcoded Credentials",
                        Severity::High,
                        "secrets",
                        "Hardcoded secret detected in Ruby code",
                        &source_file.path.to_string_lossy(),
                        line_num,
                        0,
                        line,
                        "Store secrets in environment variables or Rails credentials",
                    ));
                }
            }
        }

        Ok(vulnerabilities)
    }
}