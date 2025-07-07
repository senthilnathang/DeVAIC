use crate::{
    error::Result,
    parsers::{ParsedAst, SourceFile},
    rules::{create_vulnerability, RuleSet},
    Severity, Vulnerability,
};
use regex::Regex;

pub struct SanitizerRules {
    address_sanitizer_patterns: Vec<SanitizerPattern>,
    thread_sanitizer_patterns: Vec<SanitizerPattern>,
    memory_sanitizer_patterns: Vec<SanitizerPattern>,
    undefined_behavior_patterns: Vec<SanitizerPattern>,
    leak_sanitizer_patterns: Vec<SanitizerPattern>,
    missing_sanitizer_patterns: Vec<SanitizerPattern>,
}

#[derive(Clone)]
struct SanitizerPattern {
    id: String,
    name: String,
    pattern: Regex,
    category: String,
    severity: Severity,
    description: String,
    recommendation: String,
    cwe: String,
    sanitizer_type: SanitizerType,
    languages: Vec<String>,
}

#[derive(Clone, Debug, PartialEq)]
enum SanitizerType {
    AddressSanitizer,    // ASan - detects memory errors
    ThreadSanitizer,     // TSan - detects data races and deadlocks
    MemorySanitizer,     // MSan - detects uninitialized memory
    UndefinedBehavior,   // UBSan - detects undefined behavior
    LeakSanitizer,       // LSan - detects memory leaks
}

impl SanitizerRules {
    pub fn new() -> Self {
        let mut address_sanitizer_patterns = Vec::new();
        let mut thread_sanitizer_patterns = Vec::new();
        let mut memory_sanitizer_patterns = Vec::new();
        let mut undefined_behavior_patterns = Vec::new();
        let mut leak_sanitizer_patterns = Vec::new();
        let mut missing_sanitizer_patterns = Vec::new();

        // AddressSanitizer Patterns - Memory Safety Issues
        address_sanitizer_patterns.extend(vec![
            SanitizerPattern {
                id: "buffer-overflow-risk".to_string(),
                name: "Buffer Overflow Risk".to_string(),
                pattern: Regex::new(r"(?i)(strcpy|strcat|sprintf|gets)\s*\(").unwrap(),
                category: "sanitizer".to_string(),
                severity: Severity::Critical,
                description: "Function prone to buffer overflow - AddressSanitizer recommended".to_string(),
                recommendation: "Use AddressSanitizer (-fsanitize=address) to detect buffer overflows at runtime".to_string(),
                cwe: "CWE-120".to_string(),
                sanitizer_type: SanitizerType::AddressSanitizer,
                languages: vec!["c".to_string(), "cpp".to_string()],
            },
            SanitizerPattern {
                id: "heap-use-after-free-risk".to_string(),
                name: "Use After Free Risk".to_string(),
                pattern: Regex::new(r"(?i)free\s*\(\s*[^)]+\s*\)").unwrap(),
                category: "sanitizer".to_string(),
                severity: Severity::Critical,
                description: "Potential use-after-free vulnerability - AddressSanitizer recommended".to_string(),
                recommendation: "Use AddressSanitizer (-fsanitize=address) to detect use-after-free at runtime".to_string(),
                cwe: "CWE-416".to_string(),
                sanitizer_type: SanitizerType::AddressSanitizer,
                languages: vec!["c".to_string(), "cpp".to_string()],
            },
            SanitizerPattern {
                id: "double-free-risk".to_string(),
                name: "Double Free Risk".to_string(),
                pattern: Regex::new(r"(?i)free\s*\(\s*[^)]+\s*\).*free\s*\(\s*[^)]+\s*\)").unwrap(),
                category: "sanitizer".to_string(),
                severity: Severity::High,
                description: "Potential double-free vulnerability - AddressSanitizer recommended".to_string(),
                recommendation: "Use AddressSanitizer (-fsanitize=address) to detect double-free at runtime".to_string(),
                cwe: "CWE-415".to_string(),
                sanitizer_type: SanitizerType::AddressSanitizer,
                languages: vec!["c".to_string(), "cpp".to_string()],
            },
            SanitizerPattern {
                id: "array-bounds-risk".to_string(),
                name: "Array Bounds Risk".to_string(),
                pattern: Regex::new(r"(?i)\w+\[\s*\w+\s*\]").unwrap(),
                category: "sanitizer".to_string(),
                severity: Severity::Medium,
                description: "Array access without bounds checking - AddressSanitizer recommended".to_string(),
                recommendation: "Use AddressSanitizer (-fsanitize=address) to detect out-of-bounds access".to_string(),
                cwe: "CWE-125".to_string(),
                sanitizer_type: SanitizerType::AddressSanitizer,
                languages: vec!["c".to_string(), "cpp".to_string(), "rust".to_string()],
            },
        ]);

        // ThreadSanitizer Patterns - Data Race and Concurrency Issues
        thread_sanitizer_patterns.extend(vec![
            SanitizerPattern {
                id: "data-race-risk".to_string(),
                name: "Data Race Risk".to_string(),
                pattern: Regex::new(r"(?i)(pthread_create|std::thread|async|go\s+func)").unwrap(),
                category: "sanitizer".to_string(),
                severity: Severity::High,
                description: "Concurrent code detected - ThreadSanitizer recommended for data race detection".to_string(),
                recommendation: "Use ThreadSanitizer (-fsanitize=thread) to detect data races and deadlocks".to_string(),
                cwe: "CWE-362".to_string(),
                sanitizer_type: SanitizerType::ThreadSanitizer,
                languages: vec!["c".to_string(), "cpp".to_string(), "rust".to_string()],
            },
            SanitizerPattern {
                id: "shared-memory-access".to_string(),
                name: "Shared Memory Access".to_string(),
                pattern: Regex::new(r"(?i)(shared_ptr|atomic|volatile|mutex|lock)").unwrap(),
                category: "sanitizer".to_string(),
                severity: Severity::Medium,
                description: "Shared memory access patterns - ThreadSanitizer recommended".to_string(),
                recommendation: "Use ThreadSanitizer (-fsanitize=thread) to ensure thread safety".to_string(),
                cwe: "CWE-362".to_string(),
                sanitizer_type: SanitizerType::ThreadSanitizer,
                languages: vec!["c".to_string(), "cpp".to_string(), "rust".to_string()],
            },
            SanitizerPattern {
                id: "deadlock-risk".to_string(),
                name: "Deadlock Risk".to_string(),
                pattern: Regex::new(r"(?i)(lock|mutex).*lock").unwrap(),
                category: "sanitizer".to_string(),
                severity: Severity::High,
                description: "Multiple lock acquisition - potential deadlock risk".to_string(),
                recommendation: "Use ThreadSanitizer (-fsanitize=thread) to detect deadlocks".to_string(),
                cwe: "CWE-833".to_string(),
                sanitizer_type: SanitizerType::ThreadSanitizer,
                languages: vec!["c".to_string(), "cpp".to_string(), "rust".to_string()],
            },
        ]);

        // MemorySanitizer Patterns - Uninitialized Memory Issues
        memory_sanitizer_patterns.extend(vec![
            SanitizerPattern {
                id: "uninitialized-variable".to_string(),
                name: "Uninitialized Variable".to_string(),
                pattern: Regex::new(r"(?i)(int|char|float|double)\s+\w+\s*;").unwrap(),
                category: "sanitizer".to_string(),
                severity: Severity::Medium,
                description: "Variable declared without initialization - MemorySanitizer recommended".to_string(),
                recommendation: "Use MemorySanitizer (-fsanitize=memory) to detect uninitialized memory reads".to_string(),
                cwe: "CWE-457".to_string(),
                sanitizer_type: SanitizerType::MemorySanitizer,
                languages: vec!["c".to_string(), "cpp".to_string()],
            },
            SanitizerPattern {
                id: "malloc-without-init".to_string(),
                name: "Malloc Without Initialization".to_string(),
                pattern: Regex::new(r"(?i)malloc\s*\(.*\)").unwrap(),
                category: "sanitizer".to_string(),
                severity: Severity::Medium,
                description: "malloc() used without initialization - MemorySanitizer recommended".to_string(),
                recommendation: "Use MemorySanitizer (-fsanitize=memory) or calloc() for zero-initialized memory".to_string(),
                cwe: "CWE-457".to_string(),
                sanitizer_type: SanitizerType::MemorySanitizer,
                languages: vec!["c".to_string(), "cpp".to_string()],
            },
        ]);

        // UndefinedBehaviorSanitizer Patterns
        undefined_behavior_patterns.extend(vec![
            SanitizerPattern {
                id: "integer-overflow-risk".to_string(),
                name: "Integer Overflow Risk".to_string(),
                pattern: Regex::new(r"(?i)(int|long)\s+.*\+.*\*").unwrap(),
                category: "sanitizer".to_string(),
                severity: Severity::Medium,
                description: "Complex arithmetic - potential integer overflow".to_string(),
                recommendation: "Use UndefinedBehaviorSanitizer (-fsanitize=undefined) to detect overflow".to_string(),
                cwe: "CWE-190".to_string(),
                sanitizer_type: SanitizerType::UndefinedBehavior,
                languages: vec!["c".to_string(), "cpp".to_string()],
            },
            SanitizerPattern {
                id: "null-pointer-dereference".to_string(),
                name: "Null Pointer Dereference Risk".to_string(),
                pattern: Regex::new(r"(?i)\*\s*\w+").unwrap(),
                category: "sanitizer".to_string(),
                severity: Severity::High,
                description: "Pointer dereference without null check".to_string(),
                recommendation: "Use UndefinedBehaviorSanitizer (-fsanitize=undefined) to detect null dereferences".to_string(),
                cwe: "CWE-476".to_string(),
                sanitizer_type: SanitizerType::UndefinedBehavior,
                languages: vec!["c".to_string(), "cpp".to_string()],
            },
        ]);

        // LeakSanitizer Patterns
        leak_sanitizer_patterns.extend(vec![
            SanitizerPattern {
                id: "memory-leak-risk".to_string(),
                name: "Memory Leak Risk".to_string(),
                pattern: Regex::new(r"(?i)malloc\s*\(.*\)").unwrap(),
                category: "sanitizer".to_string(),
                severity: Severity::Medium,
                description: "Dynamic memory allocation without corresponding free()".to_string(),
                recommendation: "Use LeakSanitizer (-fsanitize=leak) to detect memory leaks".to_string(),
                cwe: "CWE-401".to_string(),
                sanitizer_type: SanitizerType::LeakSanitizer,
                languages: vec!["c".to_string(), "cpp".to_string()],
            },
        ]);

        // Missing Sanitizer Configuration Patterns
        missing_sanitizer_patterns.extend(vec![
            SanitizerPattern {
                id: "missing-asan-config".to_string(),
                name: "Missing AddressSanitizer Configuration".to_string(),
                pattern: Regex::new(r"(?i)#.*ifdef.*DEBUG").unwrap(),
                category: "sanitizer".to_string(),
                severity: Severity::Info,
                description: "Debug configuration found - consider enabling AddressSanitizer".to_string(),
                recommendation: "Add -fsanitize=address to debug builds for memory error detection".to_string(),
                cwe: "CWE-1173".to_string(),
                sanitizer_type: SanitizerType::AddressSanitizer,
                languages: vec!["c".to_string(), "cpp".to_string()],
            },
            SanitizerPattern {
                id: "missing-tsan-config".to_string(),
                name: "Missing ThreadSanitizer Configuration".to_string(),
                pattern: Regex::new(r"(?i)(pthread|thread|async|concurrent)").unwrap(),
                category: "sanitizer".to_string(),
                severity: Severity::Info,
                description: "Threading code found - consider enabling ThreadSanitizer".to_string(),
                recommendation: "Add -fsanitize=thread to builds for data race detection".to_string(),
                cwe: "CWE-362".to_string(),
                sanitizer_type: SanitizerType::ThreadSanitizer,
                languages: vec!["c".to_string(), "cpp".to_string()],
            },
        ]);

        Self {
            address_sanitizer_patterns,
            thread_sanitizer_patterns,
            memory_sanitizer_patterns,
            undefined_behavior_patterns,
            leak_sanitizer_patterns,
            missing_sanitizer_patterns,
        }
    }

    fn check_patterns(&self, source_file: &SourceFile, patterns: &[SanitizerPattern]) -> Result<Vec<Vulnerability>> {
        let mut vulnerabilities = Vec::new();
        let lines: Vec<&str> = source_file.content.lines().collect();
        let file_language = source_file.language.to_string().to_lowercase();

        for (line_index, line) in lines.iter().enumerate() {
            for pattern in patterns {
                // Check if pattern applies to this language
                if !pattern.languages.is_empty() && !pattern.languages.contains(&file_language) {
                    continue;
                }

                if let Some(captures) = pattern.pattern.captures(line) {
                    if let Some(matched) = captures.get(0) {
                        let vulnerability = create_vulnerability(
                            &pattern.id,
                            Some(&pattern.cwe),
                            &pattern.name,
                            pattern.severity.clone(),
                            &pattern.category,
                            &format!("{} (Google Sanitizers: {:?})", pattern.description, pattern.sanitizer_type),
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

impl RuleSet for SanitizerRules {
    fn analyze(&self, source_file: &SourceFile, _ast: &ParsedAst) -> Result<Vec<Vulnerability>> {
        let mut vulnerabilities = Vec::new();

        // Check AddressSanitizer patterns
        vulnerabilities.extend(self.check_patterns(source_file, &self.address_sanitizer_patterns)?);

        // Check ThreadSanitizer patterns
        vulnerabilities.extend(self.check_patterns(source_file, &self.thread_sanitizer_patterns)?);

        // Check MemorySanitizer patterns
        vulnerabilities.extend(self.check_patterns(source_file, &self.memory_sanitizer_patterns)?);

        // Check UndefinedBehaviorSanitizer patterns
        vulnerabilities.extend(self.check_patterns(source_file, &self.undefined_behavior_patterns)?);

        // Check LeakSanitizer patterns
        vulnerabilities.extend(self.check_patterns(source_file, &self.leak_sanitizer_patterns)?);

        // Check missing sanitizer configuration patterns
        vulnerabilities.extend(self.check_patterns(source_file, &self.missing_sanitizer_patterns)?);

        Ok(vulnerabilities)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{Language, parsers::SourceFile};
    use std::path::PathBuf;

    #[test]
    fn test_buffer_overflow_detection() {
        let rules = SanitizerRules::new();
        let source = SourceFile::new(
            PathBuf::from("test.c"),
            "strcpy(dest, src);".to_string(),
            Language::C,
        );
        let ast = crate::parsers::ParsedAst::new_source_only(source.content.clone());
        let vulnerabilities = rules.analyze(&source, &ast).unwrap();
        assert!(!vulnerabilities.is_empty());
        assert_eq!(vulnerabilities[0].id, "buffer-overflow-risk");
    }

    #[test]
    fn test_thread_sanitizer_detection() {
        let rules = SanitizerRules::new();
        let source = SourceFile::new(
            PathBuf::from("test.cpp"),
            "std::thread t(worker_function);".to_string(),
            Language::Cpp,
        );
        let ast = crate::parsers::ParsedAst::new_source_only(source.content.clone());
        let vulnerabilities = rules.analyze(&source, &ast).unwrap();
        assert!(!vulnerabilities.is_empty());
        assert_eq!(vulnerabilities[0].id, "data-race-risk");
    }

    #[test]
    fn test_memory_sanitizer_detection() {
        let rules = SanitizerRules::new();
        let source = SourceFile::new(
            PathBuf::from("test.c"),
            "int uninitialized_var;".to_string(),
            Language::C,
        );
        let ast = crate::parsers::ParsedAst::new_source_only(source.content.clone());
        let vulnerabilities = rules.analyze(&source, &ast).unwrap();
        assert!(!vulnerabilities.is_empty());
        assert_eq!(vulnerabilities[0].id, "uninitialized-variable");
    }

    #[test]
    fn test_leak_sanitizer_detection() {
        let rules = SanitizerRules::new();
        let source = SourceFile::new(
            PathBuf::from("test.c"),
            "char* ptr = malloc(100);".to_string(),
            Language::C,
        );
        let ast = crate::parsers::ParsedAst::new_source_only(source.content.clone());
        let vulnerabilities = rules.analyze(&source, &ast).unwrap();
        assert!(!vulnerabilities.is_empty());
        // Should detect both memory leak risk and uninitialized memory
        assert!(vulnerabilities.iter().any(|v| v.id == "memory-leak-risk"));
    }
}