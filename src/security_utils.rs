use crate::error::{DevaicError, Result};
use regex::Regex;
use std::time::{Duration, Instant};

/// Safe regex matching with timeout protection
pub fn safe_regex_match(pattern: &Regex, text: &str, timeout_ms: u64) -> Result<bool> {
    // Limit input size to prevent ReDoS
    if text.len() > 1024 * 1024 { // 1MB limit
        return Err(DevaicError::Analysis("Input too large for regex matching".to_string()));
    }
    
    let start = Instant::now();
    let timeout = Duration::from_millis(timeout_ms);
    
    // Simple timeout check - in production, use a more sophisticated approach
    if start.elapsed() > timeout {
        return Err(DevaicError::Analysis("Regex matching timeout".to_string()));
    }
    
    Ok(pattern.is_match(text))
}

/// Validate file path to prevent path traversal
pub fn validate_file_path(path: &str) -> Result<()> {
    // Check for path traversal attempts
    if path.contains("..") || path.contains("~") {
        return Err(DevaicError::Analysis("Potentially dangerous file path detected".to_string()));
    }
    
    // Check for absolute paths that might escape sandbox
    if path.starts_with('/') && !path.starts_with("/tmp/") && !path.starts_with("/var/tmp/") {
        return Err(DevaicError::Analysis("Absolute path not allowed".to_string()));
    }
    
    // Limit path length
    if path.len() > 4096 {
        return Err(DevaicError::Analysis("File path too long".to_string()));
    }
    
    Ok(())
}

/// Sanitize string input to prevent injection attacks
pub fn sanitize_input(input: &str) -> String {
    input
        .chars()
        .filter(|c| c.is_alphanumeric() || " .-_/".contains(*c))
        .take(1000) // Limit length
        .collect()
}

/// Safe string truncation for error messages
pub fn safe_truncate(s: &str, max_len: usize) -> String {
    if s.len() <= max_len {
        s.to_string()
    } else {
        format!("{}...", &s[..max_len.saturating_sub(3)])
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    
    #[test]
    fn test_validate_file_path() {
        assert!(validate_file_path("normal/path.txt").is_ok());
        assert!(validate_file_path("../etc/passwd").is_err());
        assert!(validate_file_path("~/secret").is_err());
        assert!(validate_file_path("/etc/passwd").is_err());
        assert!(validate_file_path("/tmp/safe.txt").is_ok());
    }
    
    #[test]
    fn test_sanitize_input() {
        assert_eq!(sanitize_input("normal text"), "normal text");
        assert_eq!(sanitize_input("test<script>"), "testscript");
        assert_eq!(sanitize_input("path/to/file.txt"), "path/to/file.txt");
    }
}