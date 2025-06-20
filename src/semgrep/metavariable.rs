use std::collections::HashMap;
use tree_sitter::Range;

#[derive(Debug, Clone, PartialEq)]
pub struct Metavariable {
    pub name: String,
    pub value: Option<String>,
    pub node_range: Option<Range>,
}

impl Metavariable {
    pub fn new(name: String) -> Self {
        Self {
            name,
            value: None,
            node_range: None,
        }
    }
    
    pub fn with_value(name: String, value: String, range: Range) -> Self {
        Self {
            name,
            value: Some(value),
            node_range: Some(range),
        }
    }
    
    pub fn is_anonymous(&self) -> bool {
        self.name == "$_"
    }
    
    pub fn is_bound(&self) -> bool {
        self.value.is_some()
    }
}

#[derive(Debug, Clone, Default)]
pub struct MetavariableBinding {
    pub bindings: HashMap<String, Metavariable>,
}

impl MetavariableBinding {
    pub fn new() -> Self {
        Self {
            bindings: HashMap::new(),
        }
    }
    
    pub fn bind(&mut self, name: String, value: String, range: Range) -> bool {
        // Don't bind anonymous metavariables
        if name == "$_" {
            return true;
        }
        
        match self.bindings.get(&name) {
            Some(existing) => {
                // Check if the binding is consistent
                match &existing.value {
                    Some(existing_value) => existing_value == &value,
                    None => {
                        // Update the binding with the value
                        self.bindings.insert(name.clone(), Metavariable::with_value(name, value, range));
                        true
                    }
                }
            }
            None => {
                // New binding
                self.bindings.insert(name.clone(), Metavariable::with_value(name, value, range));
                true
            }
        }
    }
    
    pub fn get(&self, name: &str) -> Option<&Metavariable> {
        self.bindings.get(name)
    }
    
    pub fn get_value(&self, name: &str) -> Option<&String> {
        self.bindings.get(name).and_then(|mv| mv.value.as_ref())
    }
    
    pub fn has_binding(&self, name: &str) -> bool {
        self.bindings.contains_key(name)
    }
    
    pub fn clear(&mut self) {
        self.bindings.clear();
    }
    
    pub fn merge(&mut self, other: &MetavariableBinding) -> bool {
        for (name, metavar) in &other.bindings {
            if let Some(value) = &metavar.value {
                if let Some(range) = metavar.node_range {
                    if !self.bind(name.clone(), value.clone(), range) {
                        return false; // Inconsistent binding
                    }
                }
            }
        }
        true
    }
    
    pub fn is_consistent_with(&self, other: &MetavariableBinding) -> bool {
        for (name, metavar) in &self.bindings {
            if let Some(other_metavar) = other.bindings.get(name) {
                if metavar.value != other_metavar.value {
                    return false;
                }
            }
        }
        true
    }
    
    pub fn interpolate_message(&self, message: &str) -> String {
        let mut result = message.to_string();
        
        for (name, metavar) in &self.bindings {
            if let Some(value) = &metavar.value {
                result = result.replace(name, value);
            }
        }
        
        result
    }
    
    pub fn iter(&self) -> impl Iterator<Item = (&String, &Metavariable)> {
        self.bindings.iter()
    }
    
    pub fn len(&self) -> usize {
        self.bindings.len()
    }
    
    pub fn is_empty(&self) -> bool {
        self.bindings.is_empty()
    }
}

#[derive(Debug, Clone)]
pub struct MetavariableMatch {
    pub bindings: MetavariableBinding,
    pub range: Range,
    pub source_text: String,
}

impl MetavariableMatch {
    pub fn new(bindings: MetavariableBinding, range: Range, source_text: String) -> Self {
        Self {
            bindings,
            range,
            source_text,
        }
    }
    
    pub fn get_binding(&self, name: &str) -> Option<&Metavariable> {
        self.bindings.get(name)
    }
    
    pub fn get_bound_value(&self, name: &str) -> Option<&String> {
        self.bindings.get_value(name)
    }
    
    pub fn interpolate_message(&self, message: &str) -> String {
        self.bindings.interpolate_message(message)
    }
}

/// Helper functions for metavariable pattern matching
pub struct MetavariableHelper;

impl MetavariableHelper {
    /// Check if a string looks like a metavariable
    pub fn is_metavariable(text: &str) -> bool {
        if !text.starts_with('$') {
            return false;
        }
        
        let name = &text[1..];
        if name.is_empty() {
            return false;
        }
        
        // Anonymous metavariable
        if name == "_" {
            return true;
        }
        
        // Must start with uppercase or underscore
        let first_char = name.chars().next().unwrap();
        if !first_char.is_ascii_uppercase() && first_char != '_' {
            return false;
        }
        
        // Rest must be uppercase, digits, or underscores
        name.chars().all(|c| c.is_ascii_uppercase() || c.is_ascii_digit() || c == '_')
    }
    
    /// Extract all metavariables from a pattern string
    pub fn extract_metavariables(pattern: &str) -> Vec<String> {
        let mut metavars = Vec::new();
        let mut chars = pattern.chars().peekable();
        
        while let Some(ch) = chars.next() {
            if ch == '$' {
                let mut metavar = String::from("$");
                
                // Read the metavariable name
                while let Some(&next_ch) = chars.peek() {
                    if next_ch.is_ascii_uppercase() 
                        || next_ch.is_ascii_digit() 
                        || next_ch == '_' 
                        || (metavar.len() == 1 && next_ch == '_') {
                        metavar.push(chars.next().unwrap());
                    } else {
                        break;
                    }
                }
                
                if metavar.len() > 1 && Self::is_metavariable(&metavar) {
                    metavars.push(metavar);
                }
            }
        }
        
        metavars.sort();
        metavars.dedup();
        metavars
    }
    
    /// Check if two metavariable bindings are compatible
    pub fn are_bindings_compatible(binding1: &MetavariableBinding, binding2: &MetavariableBinding) -> bool {
        binding1.is_consistent_with(binding2)
    }
    
    /// Merge multiple metavariable bindings
    pub fn merge_bindings(bindings: Vec<MetavariableBinding>) -> Option<MetavariableBinding> {
        if bindings.is_empty() {
            return Some(MetavariableBinding::new());
        }
        
        let mut result = bindings[0].clone();
        
        for binding in bindings.iter().skip(1) {
            if !result.merge(binding) {
                return None; // Inconsistent bindings
            }
        }
        
        Some(result)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tree_sitter::{Point, Range};
    
    fn create_test_range() -> Range {
        Range {
            start_byte: 0,
            end_byte: 10,
            start_point: Point { row: 0, column: 0 },
            end_point: Point { row: 0, column: 10 },
        }
    }
    
    #[test]
    fn test_metavariable_binding() {
        let mut binding = MetavariableBinding::new();
        let range = create_test_range();
        
        assert!(binding.bind("$X".to_string(), "value1".to_string(), range));
        assert_eq!(binding.get_value("$X"), Some(&"value1".to_string()));
        
        // Try to bind same variable to different value - should fail
        assert!(!binding.bind("$X".to_string(), "value2".to_string(), range));
        
        // Bind same variable to same value - should succeed
        assert!(binding.bind("$X".to_string(), "value1".to_string(), range));
    }
    
    #[test]
    fn test_anonymous_metavariable() {
        let mut binding = MetavariableBinding::new();
        let range = create_test_range();
        
        // Anonymous metavariables should always succeed
        assert!(binding.bind("$_".to_string(), "anything".to_string(), range));
        assert!(binding.bind("$_".to_string(), "different".to_string(), range));
        
        // But shouldn't actually store the binding
        assert!(!binding.has_binding("$_"));
    }
    
    #[test]
    fn test_metavariable_extraction() {
        let pattern = "function $FUNC($ARG1, $ARG2) { return $ARG1 + $ARG2; }";
        let metavars = MetavariableHelper::extract_metavariables(pattern);
        
        assert_eq!(metavars, vec!["$ARG1", "$ARG2", "$FUNC"]);
    }
    
    #[test]
    fn test_metavariable_validation() {
        assert!(MetavariableHelper::is_metavariable("$VALID"));
        assert!(MetavariableHelper::is_metavariable("$_"));
        assert!(MetavariableHelper::is_metavariable("$VAR_123"));
        
        assert!(!MetavariableHelper::is_metavariable("$invalid"));
        assert!(!MetavariableHelper::is_metavariable("$123"));
        assert!(!MetavariableHelper::is_metavariable("valid"));
        assert!(!MetavariableHelper::is_metavariable("$"));
    }
    
    #[test]
    fn test_message_interpolation() {
        let mut binding = MetavariableBinding::new();
        let range = create_test_range();
        
        binding.bind("$FUNC".to_string(), "dangerousFunction".to_string(), range);
        binding.bind("$ARG".to_string(), "userInput".to_string(), range);
        
        let message = "Found call to $FUNC with argument $ARG";
        let interpolated = binding.interpolate_message(message);
        
        assert_eq!(interpolated, "Found call to dangerousFunction with argument userInput");
    }
    
    #[test]
    fn test_binding_merge() {
        let mut binding1 = MetavariableBinding::new();
        let mut binding2 = MetavariableBinding::new();
        let range = create_test_range();
        
        binding1.bind("$X".to_string(), "value1".to_string(), range);
        binding2.bind("$Y".to_string(), "value2".to_string(), range);
        
        assert!(binding1.merge(&binding2));
        assert_eq!(binding1.get_value("$X"), Some(&"value1".to_string()));
        assert_eq!(binding1.get_value("$Y"), Some(&"value2".to_string()));
    }
    
    #[test]
    fn test_inconsistent_binding_merge() {
        let mut binding1 = MetavariableBinding::new();
        let mut binding2 = MetavariableBinding::new();
        let range = create_test_range();
        
        binding1.bind("$X".to_string(), "value1".to_string(), range);
        binding2.bind("$X".to_string(), "value2".to_string(), range);
        
        assert!(!binding1.merge(&binding2));
    }
}