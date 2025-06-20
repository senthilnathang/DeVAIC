use serde::{Deserialize, Serialize};
use crate::Language;

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub enum PatternOperator {
    /// Basic pattern match - equivalent to Semgrep's `pattern`
    Pattern(String),
    
    /// Regular expression pattern - equivalent to Semgrep's `pattern-regex`
    PatternRegex(String),
    
    /// Logical AND of patterns - equivalent to Semgrep's `patterns`
    Patterns(Vec<PatternOperator>),
    
    /// Logical OR of patterns - equivalent to Semgrep's `pattern-either`
    PatternEither(Vec<PatternOperator>),
    
    /// Negation pattern - equivalent to Semgrep's `pattern-not`
    PatternNot(Box<PatternOperator>),
    
    /// Context-based pattern - equivalent to Semgrep's `pattern-inside`
    PatternInside(Box<PatternOperator>),
    
    /// Negated context pattern - equivalent to Semgrep's `pattern-not-inside`
    PatternNotInside(Box<PatternOperator>),
    
    /// Focus on specific metavariable - equivalent to Semgrep's `focus-metavariable`
    FocusMetavariable(String),
    
    /// Metavariable pattern constraint - equivalent to Semgrep's `metavariable-pattern`
    MetavariablePattern {
        metavariable: String,
        pattern: Box<PatternOperator>,
    },
    
    /// Metavariable regex constraint - equivalent to Semgrep's `metavariable-regex`
    MetavariableRegex {
        metavariable: String,
        regex: String,
    },
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct Pattern {
    pub operator: PatternOperator,
    pub language: Language,
}

impl Pattern {
    pub fn new(operator: PatternOperator, language: Language) -> Self {
        Self { operator, language }
    }
    
    /// Parse a pattern string and extract metavariables
    pub fn extract_metavariables(&self) -> Vec<String> {
        self.extract_metavariables_from_operator(&self.operator)
    }
    
    fn extract_metavariables_from_operator(&self, operator: &PatternOperator) -> Vec<String> {
        let mut metavars = Vec::new();
        
        match operator {
            PatternOperator::Pattern(pattern) | PatternOperator::PatternRegex(pattern) => {
                metavars.extend(self.extract_metavars_from_string(pattern));
            }
            PatternOperator::Patterns(patterns) | PatternOperator::PatternEither(patterns) => {
                for pattern in patterns {
                    metavars.extend(self.extract_metavariables_from_operator(pattern));
                }
            }
            PatternOperator::PatternNot(pattern) 
            | PatternOperator::PatternInside(pattern) 
            | PatternOperator::PatternNotInside(pattern) => {
                metavars.extend(self.extract_metavariables_from_operator(pattern));
            }
            PatternOperator::FocusMetavariable(metavar) => {
                metavars.push(metavar.clone());
            }
            PatternOperator::MetavariablePattern { metavariable, pattern } => {
                metavars.push(metavariable.clone());
                metavars.extend(self.extract_metavariables_from_operator(pattern));
            }
            PatternOperator::MetavariableRegex { metavariable, .. } => {
                metavars.push(metavariable.clone());
            }
        }
        
        metavars.sort();
        metavars.dedup();
        metavars
    }
    
    fn extract_metavars_from_string(&self, pattern: &str) -> Vec<String> {
        let mut metavars = Vec::new();
        let mut chars = pattern.chars().peekable();
        
        while let Some(ch) = chars.next() {
            if ch == '$' {
                let mut metavar = String::new();
                
                // Read the metavariable name
                while let Some(&next_ch) = chars.peek() {
                    if next_ch.is_ascii_uppercase() || next_ch.is_ascii_digit() || next_ch == '_' {
                        metavar.push(chars.next().unwrap());
                    } else {
                        break;
                    }
                }
                
                if !metavar.is_empty() && metavar != "_" {
                    metavars.push(format!("${}", metavar));
                }
            }
        }
        
        metavars
    }
    
    /// Check if pattern contains ellipsis operator
    pub fn has_ellipsis(&self) -> bool {
        self.contains_ellipsis(&self.operator)
    }
    
    fn contains_ellipsis(&self, operator: &PatternOperator) -> bool {
        match operator {
            PatternOperator::Pattern(pattern) | PatternOperator::PatternRegex(pattern) => {
                pattern.contains("...")
            }
            PatternOperator::Patterns(patterns) | PatternOperator::PatternEither(patterns) => {
                patterns.iter().any(|p| self.contains_ellipsis(p))
            }
            PatternOperator::PatternNot(pattern) 
            | PatternOperator::PatternInside(pattern) 
            | PatternOperator::PatternNotInside(pattern) => {
                self.contains_ellipsis(pattern)
            }
            PatternOperator::MetavariablePattern { pattern, .. } => {
                self.contains_ellipsis(pattern)
            }
            _ => false,
        }
    }
    
    /// Validate pattern syntax
    pub fn validate(&self) -> Result<(), String> {
        self.validate_operator(&self.operator)
    }
    
    fn validate_operator(&self, operator: &PatternOperator) -> Result<(), String> {
        match operator {
            PatternOperator::Pattern(pattern) => {
                if pattern.trim().is_empty() {
                    return Err("Pattern cannot be empty".to_string());
                }
                
                // Validate metavariable syntax
                let metavars = self.extract_metavars_from_string(pattern);
                for metavar in metavars {
                    if !self.is_valid_metavariable(&metavar) {
                        return Err(format!("Invalid metavariable syntax: {}", metavar));
                    }
                }
                
                Ok(())
            }
            PatternOperator::PatternRegex(regex) => {
                if regex.trim().is_empty() {
                    return Err("Regex pattern cannot be empty".to_string());
                }
                
                // Validate regex compilation
                match regex::Regex::new(regex) {
                    Ok(_) => Ok(()),
                    Err(e) => Err(format!("Invalid regex pattern: {}", e)),
                }
            }
            PatternOperator::Patterns(patterns) | PatternOperator::PatternEither(patterns) => {
                if patterns.is_empty() {
                    return Err("Pattern list cannot be empty".to_string());
                }
                
                for pattern in patterns {
                    self.validate_operator(pattern)?;
                }
                
                Ok(())
            }
            PatternOperator::PatternNot(pattern) 
            | PatternOperator::PatternInside(pattern) 
            | PatternOperator::PatternNotInside(pattern) => {
                self.validate_operator(pattern)
            }
            PatternOperator::FocusMetavariable(metavar) => {
                if !self.is_valid_metavariable(metavar) {
                    return Err(format!("Invalid metavariable syntax: {}", metavar));
                }
                Ok(())
            }
            PatternOperator::MetavariablePattern { metavariable, pattern } => {
                if !self.is_valid_metavariable(metavariable) {
                    return Err(format!("Invalid metavariable syntax: {}", metavariable));
                }
                self.validate_operator(pattern)
            }
            PatternOperator::MetavariableRegex { metavariable, regex } => {
                if !self.is_valid_metavariable(metavariable) {
                    return Err(format!("Invalid metavariable syntax: {}", metavariable));
                }
                
                match regex::Regex::new(regex) {
                    Ok(_) => Ok(()),
                    Err(e) => Err(format!("Invalid regex pattern: {}", e)),
                }
            }
        }
    }
    
    fn is_valid_metavariable(&self, metavar: &str) -> bool {
        if !metavar.starts_with('$') {
            return false;
        }
        
        let name = &metavar[1..];
        if name.is_empty() || name == "_" {
            return true; // Anonymous metavariable
        }
        
        // Must start with uppercase letter or underscore
        let first_char = name.chars().next().unwrap();
        if !first_char.is_ascii_uppercase() && first_char != '_' {
            return false;
        }
        
        // Rest must be uppercase letters, digits, or underscores
        name.chars().all(|c| c.is_ascii_uppercase() || c.is_ascii_digit() || c == '_')
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    
    #[test]
    fn test_metavariable_extraction() {
        let pattern = Pattern::new(
            PatternOperator::Pattern("function $FUNC($ARG1, $ARG2) { $BODY }".to_string()),
            Language::Javascript,
        );
        
        let metavars = pattern.extract_metavariables();
        assert_eq!(metavars, vec!["$ARG1", "$ARG2", "$BODY", "$FUNC"]);
    }
    
    #[test]
    fn test_ellipsis_detection() {
        let pattern = Pattern::new(
            PatternOperator::Pattern("console.log(...)".to_string()),
            Language::Javascript,
        );
        
        assert!(pattern.has_ellipsis());
    }
    
    #[test]
    fn test_metavariable_validation() {
        let pattern = Pattern::new(
            PatternOperator::Pattern("$VALID_VAR".to_string()),
            Language::Javascript,
        );
        
        assert!(pattern.is_valid_metavariable("$VALID_VAR"));
        assert!(pattern.is_valid_metavariable("$_"));
        assert!(!pattern.is_valid_metavariable("$invalid"));
        assert!(!pattern.is_valid_metavariable("$123"));
    }
    
    #[test]
    fn test_pattern_validation() {
        let valid_pattern = Pattern::new(
            PatternOperator::Pattern("function $FUNC() { ... }".to_string()),
            Language::Javascript,
        );
        
        assert!(valid_pattern.validate().is_ok());
        
        let invalid_pattern = Pattern::new(
            PatternOperator::Pattern("".to_string()),
            Language::Javascript,
        );
        
        assert!(invalid_pattern.validate().is_err());
    }
}