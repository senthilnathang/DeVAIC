use serde::{Deserialize, Serialize};
use super::metavariable::MetavariableBinding;

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct AutoFix {
    /// Simple string replacement fix
    #[serde(skip_serializing_if = "Option::is_none")]
    pub fix: Option<String>,
    
    /// Fix message explaining the change
    #[serde(skip_serializing_if = "Option::is_none")]
    pub message: Option<String>,
}

impl AutoFix {
    pub fn new(fix: String) -> Self {
        Self {
            fix: Some(fix),
            message: None,
        }
    }
    
    pub fn with_message(mut self, message: String) -> Self {
        self.message = Some(message);
        self
    }
    
    /// Apply the autofix to source code with metavariable interpolation
    pub fn apply(&self, _original_code: &str, bindings: &MetavariableBinding) -> Option<String> {
        if let Some(fix_template) = &self.fix {
            let interpolated_fix = bindings.interpolate_message(fix_template);
            Some(interpolated_fix)
        } else {
            None
        }
    }
    
    /// Get the fix message with metavariable interpolation
    pub fn get_message(&self, bindings: &MetavariableBinding) -> Option<String> {
        if let Some(message_template) = &self.message {
            Some(bindings.interpolate_message(message_template))
        } else {
            None
        }
    }
    
    /// Validate the autofix
    pub fn validate(&self) -> Result<(), String> {
        if self.fix.is_none() {
            return Err("AutoFix must have at least a fix field".to_string());
        }
        
        Ok(())
    }
}

#[derive(Debug, Clone)]
pub struct AutoFixSuggestion {
    pub original_range: tree_sitter::Range,
    pub replacement: String,
    pub message: Option<String>,
    pub confidence: FixConfidence,
}

#[derive(Debug, Clone, PartialEq)]
pub enum FixConfidence {
    High,    // Safe to apply automatically
    Medium,  // Probably safe, but review recommended
    Low,     // Requires manual review
}

impl AutoFixSuggestion {
    pub fn new(
        range: tree_sitter::Range,
        replacement: String,
        confidence: FixConfidence,
    ) -> Self {
        Self {
            original_range: range,
            replacement,
            message: None,
            confidence,
        }
    }
    
    pub fn with_message(mut self, message: String) -> Self {
        self.message = Some(message);
        self
    }
    
    /// Apply this fix to source code
    pub fn apply_to_source(&self, source: &str) -> Result<String, String> {
        let bytes = source.as_bytes();
        
        if self.original_range.start_byte > bytes.len() || self.original_range.end_byte > bytes.len() {
            return Err("Fix range is out of bounds".to_string());
        }
        
        let before = &bytes[..self.original_range.start_byte];
        let after = &bytes[self.original_range.end_byte..];
        
        let before_str = std::str::from_utf8(before)
            .map_err(|_| "Invalid UTF-8 in source before fix range")?;
        let after_str = std::str::from_utf8(after)
            .map_err(|_| "Invalid UTF-8 in source after fix range")?;
        
        Ok(format!("{}{}{}", before_str, self.replacement, after_str))
    }
    
    /// Get the original text that would be replaced
    pub fn get_original_text(&self, source: &str) -> Option<String> {
        let bytes = source.as_bytes();
        
        if self.original_range.start_byte > bytes.len() || self.original_range.end_byte > bytes.len() {
            return None;
        }
        
        let original_bytes = &bytes[self.original_range.start_byte..self.original_range.end_byte];
        std::str::from_utf8(original_bytes).ok().map(|s| s.to_string())
    }
}

/// Helper for creating common autofixes
pub struct AutoFixHelper;

impl AutoFixHelper {
    /// Create a simple replacement autofix
    pub fn simple_replacement(old: &str, new: &str) -> AutoFix {
        AutoFix::new(new.to_string())
            .with_message(format!("Replace '{}' with '{}'", old, new))
    }
    
    /// Create an autofix that removes dangerous function calls
    pub fn remove_dangerous_call(function_name: &str) -> AutoFix {
        AutoFix::new("/* REMOVED DANGEROUS CALL */".to_string())
            .with_message(format!("Remove dangerous call to {}", function_name))
    }
    
    /// Create an autofix that adds security headers
    pub fn add_security_header(header_name: &str, header_value: &str) -> AutoFix {
        AutoFix::new(format!("app.use((req, res, next) => {{\n  res.setHeader('{}', '{}');\n  next();\n}});", header_name, header_value))
            .with_message(format!("Add {} security header", header_name))
    }
    
    /// Create an autofix for unsafe type assertions in TypeScript
    pub fn safe_type_assertion(metavar: &str) -> AutoFix {
        AutoFix::new(format!("({} as unknown) as TargetType", metavar))
            .with_message("Use safer type assertion pattern".to_string())
    }
    
    /// Create an autofix for weak cryptographic functions
    pub fn upgrade_crypto(weak_algo: &str, strong_algo: &str) -> AutoFix {
        AutoFix::new(format!("crypto.createHash('{}')", strong_algo))
            .with_message(format!("Upgrade from {} to {} for better security", weak_algo, strong_algo))
    }
    
    /// Create an autofix for hardcoded secrets
    pub fn externalize_secret(var_name: &str) -> AutoFix {
        AutoFix::new(format!("process.env.{}", var_name.to_uppercase()))
            .with_message("Move secret to environment variable".to_string())
    }
    
    /// Create an autofix for XSS vulnerabilities
    pub fn sanitize_html_output(metavar: &str) -> AutoFix {
        AutoFix::new(format!("DOMPurify.sanitize({})", metavar))
            .with_message("Sanitize HTML content to prevent XSS".to_string())
    }
    
    /// Create an autofix for SQL injection
    pub fn parameterize_query(metavar: &str) -> AutoFix {
        AutoFix::new(format!("db.query('SELECT * FROM users WHERE id = ?', [{}])", metavar))
            .with_message("Use parameterized query to prevent SQL injection".to_string())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::semgrep::metavariable::MetavariableBinding;
    use tree_sitter::{Point, Range};
    
    fn create_test_range() -> Range {
        Range {
            start_byte: 10,
            end_byte: 20,
            start_point: Point { row: 1, column: 5 },
            end_point: Point { row: 1, column: 15 },
        }
    }
    
    #[test]
    fn test_autofix_creation() {
        let autofix = AutoFix::new("safer_function()".to_string())
            .with_message("Use safer function".to_string());
        
        assert_eq!(autofix.fix, Some("safer_function()".to_string()));
        assert_eq!(autofix.message, Some("Use safer function".to_string()));
    }
    
    #[test]
    fn test_autofix_application() {
        let autofix = AutoFix::new("$SAFE_FUNC($ARG)".to_string());
        let mut bindings = MetavariableBinding::new();
        let range = create_test_range();
        
        bindings.bind("$SAFE_FUNC".to_string(), "secureFunction".to_string(), range);
        bindings.bind("$ARG".to_string(), "userInput".to_string(), range);
        
        let result = autofix.apply("original", &bindings);
        assert_eq!(result, Some("secureFunction(userInput)".to_string()));
    }
    
    #[test]
    fn test_autofix_suggestion_application() {
        let range = Range {
            start_byte: 9,  // Start of "dangerous"
            end_byte: 18,   // End of "dangerous"
            start_point: Point { row: 0, column: 9 },
            end_point: Point { row: 0, column: 18 },
        };
        
        let suggestion = AutoFixSuggestion::new(
            range,
            "secureFunction".to_string(),
            FixConfidence::High,
        );
        
        let source = "function dangerous() {}";
        let result = suggestion.apply_to_source(source).unwrap();
        assert_eq!(result, "function secureFunction() {}");
    }
    
    #[test]
    fn test_autofix_helper_methods() {
        let fix = AutoFixHelper::simple_replacement("eval", "JSON.parse");
        assert!(fix.fix.is_some());
        assert!(fix.message.is_some());
        
        let crypto_fix = AutoFixHelper::upgrade_crypto("md5", "sha256");
        assert_eq!(crypto_fix.fix, Some("crypto.createHash('sha256')".to_string()));
        
        let secret_fix = AutoFixHelper::externalize_secret("api_key");
        assert_eq!(secret_fix.fix, Some("process.env.API_KEY".to_string()));
    }
    
    #[test]
    fn test_fix_confidence_levels() {
        let high_confidence = AutoFixSuggestion::new(
            create_test_range(),
            "safe_replacement".to_string(),
            FixConfidence::High,
        );
        
        assert_eq!(high_confidence.confidence, FixConfidence::High);
    }
    
    #[test]
    fn test_autofix_validation() {
        let valid_fix = AutoFix::new("replacement".to_string());
        assert!(valid_fix.validate().is_ok());
        
        let invalid_fix = AutoFix {
            fix: None,
            message: Some("Message without fix".to_string()),
        };
        assert!(invalid_fix.validate().is_err());
    }
}