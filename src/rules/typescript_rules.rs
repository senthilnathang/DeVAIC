use super::{create_vulnerability, RuleSet};
use crate::{
    error::Result,
    parsers::{ParsedAst, Parser, SourceFile},
    Severity, Vulnerability,
};
use regex::Regex;
use tree_sitter::Node;

pub struct TypeScriptRules {
    xss_patterns: Vec<Regex>,
    prototype_pollution_patterns: Vec<Regex>,
    eval_patterns: Vec<Regex>,
    dom_patterns: Vec<Regex>,
    crypto_patterns: Vec<Regex>,
    hardcoded_secrets_patterns: Vec<Regex>,
    type_assertion_patterns: Vec<Regex>,
    any_type_patterns: Vec<Regex>,
    strict_null_patterns: Vec<Regex>,
    enum_patterns: Vec<Regex>,
    decorator_patterns: Vec<Regex>,
    redos_patterns: Vec<Regex>,
    supply_chain_patterns: Vec<Regex>,
    path_traversal_patterns: Vec<Regex>,
    template_injection_patterns: Vec<Regex>,
    weak_random_patterns: Vec<Regex>,
    typescript_specific_patterns: Vec<Regex>,
}

impl TypeScriptRules {
    pub fn new() -> Self {
        Self {
            xss_patterns: vec![
                // Enhanced XSS patterns for modern TypeScript/JavaScript
                Regex::new(r"\.innerHTML\s*[+]?=\s*[^;]*[\+&]").unwrap(),
                Regex::new(r"\.outerHTML\s*[+]?=\s*[^;]*[\+&]").unwrap(),
                Regex::new(r"document\.write\s*\(\s*[^)]*[\+&]").unwrap(),
                Regex::new(r"document\.writeln\s*\(\s*[^)]*[\+&]").unwrap(),
                Regex::new(r"\.insertAdjacentHTML\s*\(\s*[^,]*,\s*[^)]*[\+&]").unwrap(),
                // React/Vue specific patterns with TypeScript
                Regex::new(r"dangerouslySetInnerHTML.*__html.*\+").unwrap(),
                Regex::new(r"v-html\s*=\s*[^>]*[\+&]").unwrap(),
                Regex::new(r"\$\{[^}]*\+[^}]*\}").unwrap(), // Template literal injection
                // Angular specific patterns
                Regex::new(r"\[innerHTML\]\s*=\s*[^>]*\+").unwrap(),
                Regex::new(r"bypassSecurityTrustHtml\s*\(").unwrap(),
                // jQuery patterns
                Regex::new(r"\$\([^)]*\)\.html\s*\(\s*[^)]*[\+&]").unwrap(),
                Regex::new(r"\.append\s*\(\s*[^)]*[\+&]").unwrap(),
                Regex::new(r"\.prepend\s*\(\s*[^)]*[\+&]").unwrap(),
                // Modern DOM APIs
                Regex::new(r"\.createDocumentFragment\(\).*innerHTML").unwrap(),
                Regex::new(r"Range\(\)\.createContextualFragment\s*\(").unwrap(),
            ],
            prototype_pollution_patterns: vec![
                // Enhanced prototype pollution patterns
                Regex::new(r"\[['`]__proto__['`]\]").unwrap(),
                Regex::new(r"\.constructor\.prototype").unwrap(),
                Regex::new(r"Object\.setPrototypeOf\s*\(").unwrap(),
                Regex::new(r"\[['`]prototype['`]\]").unwrap(),
                Regex::new(r"\[['`]constructor['`]\]").unwrap(),
                // Merge/assign operations without protection
                Regex::new(r"Object\.assign\s*\([^,]*,\s*[^)]*\.\w+").unwrap(),
                Regex::new(r"\.\.\.spread\s*\(\s*[^)]*\.\w+").unwrap(),
                Regex::new(r"lodash\.merge\s*\(").unwrap(),
                Regex::new(r"_\.merge\s*\(").unwrap(),
                // JSON.parse with user input
                Regex::new(r"JSON\.parse\s*\(\s*req\.").unwrap(),
                // TypeScript specific merge operations
                Regex::new(r"Object\.assign\s*\(<[^>]*>,\s*[^)]*req\.").unwrap(),
            ],
            eval_patterns: vec![
                // Enhanced eval patterns including modern variants
                Regex::new(r"\beval\s*\(").unwrap(),
                Regex::new(r"new\s+Function\s*\(").unwrap(),
                Regex::new(r"setTimeout\s*\(\s*[`\x27\x22]\s*.*\+").unwrap(),
                Regex::new(r"setInterval\s*\(\s*[`\x27\x22]\s*.*\+").unwrap(),
                // Dynamic imports with user input
                Regex::new(r"import\s*\(\s*.*\+").unwrap(),
                Regex::new(r"require\s*\(\s*.*\+").unwrap(),
                // VM module usage
                Regex::new(r"vm\.runInThisContext\s*\(").unwrap(),
                Regex::new(r"vm\.runInNewContext\s*\(").unwrap(),
                // Web Workers with dynamic scripts
                Regex::new(r"new\s+Worker\s*\(\s*.*\+").unwrap(),
                // Script tag injection
                Regex::new(r"createElement\s*\(\s*[\x27\x22]script[\x27\x22]").unwrap(),
                // TypeScript specific dynamic compilation
                Regex::new(r"ts\.transpile\s*\(\s*.*\+").unwrap(),
            ],
            dom_patterns: vec![
                // Enhanced DOM manipulation patterns
                Regex::new(r"\.src\s*=\s*[^;]*[\+&]").unwrap(),
                Regex::new(r"\.href\s*=\s*[^;]*[\+&]").unwrap(),
                Regex::new(r"window\.location\s*=\s*[^;]*[\+&]").unwrap(),
                Regex::new(r"location\.href\s*=\s*[^;]*[\+&]").unwrap(),
                Regex::new(r"\.action\s*=\s*[^;]*[\+&]").unwrap(), // Form action manipulation
                Regex::new(r"\.formAction\s*=\s*[^;]*[\+&]").unwrap(),
                // iframe and embed sources
                Regex::new(r"\.srcdoc\s*=\s*[^;]*[\+&]").unwrap(),
                Regex::new(r"\.data\s*=\s*[^;]*[\+&]").unwrap(), // object/embed data
                // Event handlers
                Regex::new(r"\.onclick\s*=\s*[^;]*[\+&]").unwrap(),
                Regex::new(r"\.onload\s*=\s*[^;]*[\+&]").unwrap(),
                Regex::new(r"\.onerror\s*=\s*[^;]*[\+&]").unwrap(),
                // postMessage with user data
                Regex::new(r"\.postMessage\s*\(\s*[^,]*\+").unwrap(),
                // Angular specific
                Regex::new(r"\[src\]\s*=\s*[^>]*\+").unwrap(),
                Regex::new(r"\[href\]\s*=\s*[^>]*\+").unwrap(),
            ],
            crypto_patterns: vec![
                // Enhanced cryptography patterns
                Regex::new(r"Math\.random\s*\(\s*\)").unwrap(),
                Regex::new(r"new\s+Date\s*\(\s*\)\.getTime\s*\(\s*\)").unwrap(),
                Regex::new(r"Date\.now\s*\(\s*\)").unwrap(),
                Regex::new(r"btoa\s*\(").unwrap(),
                Regex::new(r"atob\s*\(").unwrap(),
                // Weak crypto algorithms
                Regex::new(r"crypto\.createHash\s*\(\s*[\x27\x22]md5[\x27\x22]").unwrap(),
                Regex::new(r"crypto\.createHash\s*\(\s*[\x27\x22]sha1[\x27\x22]").unwrap(),
                Regex::new(r"crypto\.createCipher\s*\(\s*[\x27\x22]des").unwrap(),
                Regex::new(r"crypto\.createCipher\s*\(\s*[\x27\x22]rc4").unwrap(),
                // Insecure random for security purposes
                Regex::new(r"Math\.random\s*\(\s*\)\s*\*.*password").unwrap(),
                Regex::new(r"Math\.random\s*\(\s*\)\s*\*.*token").unwrap(),
                Regex::new(r"Math\.random\s*\(\s*\)\s*\*.*key").unwrap(),
            ],
            hardcoded_secrets_patterns: vec![
                // Enhanced secret detection patterns
                Regex::new(r#"(?i)(password|pwd|secret|key|token|api_key)\s*[:=]\s*['"][^'"]{8,}['"]"#).unwrap(),
                Regex::new(r#"(?i)(bearer|basic)\s+['"][^'"]+['"]"#).unwrap(),
                Regex::new(r#"(?i)authorization\s*[:=]\s*['"][^'"]+['"]"#).unwrap(),
                // AWS keys
                Regex::new(r"AKIA[0-9A-Z]{16}").unwrap(),
                Regex::new(r"aws_secret_access_key\s*=\s*[A-Za-z0-9/+=]{40}").unwrap(),
                // GitHub tokens
                Regex::new(r"ghp_[A-Za-z0-9]{36}").unwrap(),
                Regex::new(r"github_pat_[A-Za-z0-9_]{82}").unwrap(),
                // JWT tokens
                Regex::new(r"eyJ[A-Za-z0-9_/+=]+\.eyJ[A-Za-z0-9_/+=]+\.[A-Za-z0-9_/+=]*").unwrap(),
                // Database URLs
                Regex::new(r"mongodb://[^:]+:[^@]+@").unwrap(),
                Regex::new(r"postgres://[^:]+:[^@]+@").unwrap(),
                // Private keys
                Regex::new(r"-----BEGIN\s+(RSA\s+)?PRIVATE\s+KEY-----").unwrap(),
                // TypeScript specific const secrets
                Regex::new(r"const\s+\w*[Ss]ecret\w*\s*=\s*[\x27\x22][^\x27\x22]{8,}[\x27\x22]").unwrap(),
            ],
            type_assertion_patterns: vec![
                // Enhanced type assertion patterns
                Regex::new(r"as\s+any\b").unwrap(),
                Regex::new(r"<any>").unwrap(),
                Regex::new(r"as\s+unknown\s+as\s+").unwrap(),
                Regex::new(r"as\s+\{\s*\[key:\s*string\]\s*:\s*any\s*\}").unwrap(),
                // Dangerous casting patterns
                Regex::new(r"as\s+\w+\[\]").unwrap(), // Casting to array without validation
                Regex::new(r"<\w+\[\]>").unwrap(),
                // Non-null assertion operator overuse
                Regex::new(r"\.!\s*\.!\s*\.").unwrap(), // Multiple non-null assertions
                // Type assertion on user input
                Regex::new(r"req\.\w+\s+as\s+").unwrap(),
            ],
            any_type_patterns: vec![
                // Enhanced any type patterns
                Regex::new(r":\s*any\b").unwrap(),
                Regex::new(r"<any>").unwrap(),
                Regex::new(r"Array<any>").unwrap(),
                Regex::new(r"Promise<any>").unwrap(),
                Regex::new(r"Record<string,\s*any>").unwrap(),
                Regex::new(r"Map<\w+,\s*any>").unwrap(),
                Regex::new(r"Set<any>").unwrap(),
                // Function with any parameters
                Regex::new(r"function\s+\w*\s*\([^)]*:\s*any").unwrap(),
                Regex::new(r"=>\s*\([^)]*:\s*any").unwrap(),
                // Generic with any
                Regex::new(r"<[^>]*any[^>]*>").unwrap(),
            ],
            strict_null_patterns: vec![
                // Strict null check bypass patterns
                Regex::new(r"!\s*\.\s*").unwrap(), // Non-null assertion
                Regex::new(r"as\s+\w+").unwrap(), // Type assertion potentially bypassing null checks
                Regex::new(r"\?\.\w+\s*!").unwrap(), // Optional chaining followed by non-null assertion
            ],
            enum_patterns: vec![
                // Enum security patterns
                Regex::new(r"enum\s+\w+\s*\{[^}]*\d+[^}]*\}").unwrap(), // Numeric enums can be unsafe
                Regex::new(r"Object\.values\s*\(\s*\w*Enum\s*\)").unwrap(), // Enum iteration
            ],
            decorator_patterns: vec![
                // Decorator security patterns
                Regex::new(r"@\w*[Aa]uth\w*\s*\(\s*[\x27\x22]?\w*[\x27\x22]?\s*\)").unwrap(), // Weak auth decorators
                Regex::new(r"@[Pp]ublic\s*\(\s*\)").unwrap(), // Public decorator without restrictions
                Regex::new(r"@[Bb]ypass\w*").unwrap(), // Bypass decorators
            ],
            redos_patterns: vec![
                // Regular Expression Denial of Service patterns
                Regex::new(r"\(\.\*\)\+").unwrap(), // (.*)+
                Regex::new(r"\(\.\+\)\+").unwrap(), // (.+)+
                Regex::new(r"\(\[\^.\]\*\)\+").unwrap(), // ([^.]*)+
                Regex::new(r"\(\[\^.\]\+\)\+").unwrap(), // ([^.]+)+
                Regex::new(r"\(\w\*\)\+").unwrap(), // (\w*)+
                Regex::new(r"\(\w\+\)\+").unwrap(), // (\w+)+
                // Nested quantifiers
                Regex::new(r"\([^)]*\*[^)]*\)\*").unwrap(),
                Regex::new(r"\([^)]*\+[^)]*\)\+").unwrap(),
                // Alternation with overlapping patterns
                Regex::new(r"\([^|]*\|\.\*\)").unwrap(),
            ],
            supply_chain_patterns: vec![
                // Supply chain attack patterns
                Regex::new(r"cdn\.polyfill\.io").unwrap(),
                Regex::new(r"polyfill\.io").unwrap(),
                // Suspicious CDN patterns
                Regex::new(r"https?://[^/]*\.tk/").unwrap(),
                Regex::new(r"https?://[^/]*\.ml/").unwrap(),
                Regex::new(r"https?://[^/]*\.ga/").unwrap(),
                // Base64 encoded scripts
                Regex::new(r"eval\s*\(\s*atob\s*\(").unwrap(),
                Regex::new(r"Function\s*\(\s*atob\s*\(").unwrap(),
                // Dynamic script loading from user input
                Regex::new(r"document\.createElement\s*\(\s*[\x27\x22]script[\x27\x22].*src.*\+").unwrap(),
                // Suspicious domain patterns
                Regex::new(r"https?://[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}").unwrap(),
            ],
            path_traversal_patterns: vec![
                // Path traversal patterns
                Regex::new(r"\.\.[\\/]").unwrap(),
                Regex::new(r"\.\.[\\/]\.\.[\\/]").unwrap(),
                Regex::new(r"\.\.%2[fF]").unwrap(),
                Regex::new(r"\.\.%5[cC]").unwrap(),
                // Node.js specific
                Regex::new(r"require\s*\(\s*.*\.\.").unwrap(),
                Regex::new(r"fs\.readFile\s*\(\s*.*\.\.").unwrap(),
                Regex::new(r"fs\.writeFile\s*\(\s*.*\.\.").unwrap(),
                Regex::new(r"path\.join\s*\(\s*.*req\.").unwrap(), // User input in path.join
            ],
            template_injection_patterns: vec![
                // Template injection patterns
                Regex::new(r"\{\{\s*.*\|\s*safe\s*\}\}").unwrap(), // Safe filter bypass
                Regex::new(r"\{\{\s*.*constructor").unwrap(),
                Regex::new(r"\{\{\s*.*__proto__").unwrap(),
                // Handlebars specific
                Regex::new(r"\{\{\{.*\}\}\}").unwrap(), // Triple braces
                Regex::new(r"\{\{\s*lookup\s+.*\}\}").unwrap(),
                // EJS specific
                Regex::new(r"<%-.*%>").unwrap(), // Unescaped output
                Regex::new(r"<%.*eval.*%>").unwrap(),
                // Mustache/similar
                Regex::new(r"\{\&.*\}").unwrap(),
                // Angular template injection
                Regex::new(r"\{\{\s*.*constructor.*\}\}").unwrap(),
            ],
            weak_random_patterns: vec![
                // Weak randomness in security contexts
                Regex::new(r"Math\.random\(\).*session").unwrap(),
                Regex::new(r"Math\.random\(\).*token").unwrap(),
                Regex::new(r"Math\.random\(\).*password").unwrap(),
                Regex::new(r"Math\.random\(\).*salt").unwrap(),
                Regex::new(r"Math\.random\(\).*nonce").unwrap(),
                Regex::new(r"Math\.random\(\).*csrf").unwrap(),
                Regex::new(r"Date\.now\(\).*token").unwrap(),
                Regex::new(r"Date\.now\(\).*session").unwrap(),
            ],
            typescript_specific_patterns: vec![
                // TypeScript compiler options that reduce security
                Regex::new(r#""strict"\s*:\s*false"#).unwrap(),
                Regex::new(r#""noImplicitAny"\s*:\s*false"#).unwrap(),
                Regex::new(r#""strictNullChecks"\s*:\s*false"#).unwrap(),
                // Unsafe module declarations
                Regex::new(r"declare\s+module\s+[\x27\x22][^\x27\x22]*[\x27\x22]").unwrap(),
                Regex::new(r"declare\s+global\s*\{").unwrap(),
                // Module augmentation without validation
                Regex::new(r"module\s+[\x27\x22][^\x27\x22]*[\x27\x22].*\{.*any").unwrap(),
            ],
        }
    }

    fn check_xss_vulnerabilities(&self, source_file: &SourceFile, ast: &ParsedAst) -> Result<Vec<Vulnerability>> {
        let mut vulnerabilities = Vec::new();
        let lines: Vec<&str> = ast.source.lines().collect();

        for (line_num, line) in lines.iter().enumerate() {
            for pattern in &self.xss_patterns {
                if pattern.is_match(line) {
                    let severity = if line.contains("dangerouslySetInnerHTML") || 
                                      line.contains("bypassSecurityTrustHtml") ||
                                      line.contains("v-html") ||
                                      line.contains("createContextualFragment") {
                        Severity::Critical
                    } else {
                        Severity::High
                    };

                    vulnerabilities.push(create_vulnerability(
                        "TS001",
                        Some("CWE-79"),
                        "Cross-Site Scripting (XSS)",
                        severity,
                        "injection",
                        "Potential Cross-Site Scripting (XSS) vulnerability",
                        &source_file.path.to_string_lossy(),
                        line_num + 1,
                        0,
                        line,
                        "Sanitize user input before inserting into DOM. Use textContent instead of innerHTML where possible",
                    ));
                }
            }
        }

        Ok(vulnerabilities)
    }

    fn check_prototype_pollution(&self, source_file: &SourceFile, ast: &ParsedAst) -> Result<Vec<Vulnerability>> {
        let mut vulnerabilities = Vec::new();
        let lines: Vec<&str> = ast.source.lines().collect();

        for (line_num, line) in lines.iter().enumerate() {
            for pattern in &self.prototype_pollution_patterns {
                if pattern.is_match(line) {
                    let severity = if line.contains("JSON.parse") && line.contains("req.") {
                        Severity::Critical
                    } else {
                        Severity::High
                    };

                    vulnerabilities.push(create_vulnerability(
                        "TS003",
                        Some("CWE-1321"),
                        "Prototype Pollution",
                        severity,
                        "injection",
                        "Potential prototype pollution vulnerability",
                        &source_file.path.to_string_lossy(),
                        line_num + 1,
                        0,
                        line,
                        "Avoid modifying Object.prototype, use Object.create(null) for safe objects, validate JSON input",
                    ));
                }
            }
        }

        Ok(vulnerabilities)
    }

    fn check_eval_usage(&self, source_file: &SourceFile, ast: &ParsedAst) -> Result<Vec<Vulnerability>> {
        let mut vulnerabilities = Vec::new();
        let lines: Vec<&str> = ast.source.lines().collect();

        for (line_num, line) in lines.iter().enumerate() {
            for pattern in &self.eval_patterns {
                if pattern.is_match(line) {
                    let severity = if line.contains("eval(") || line.contains("vm.runIn") || line.contains("ts.transpile") {
                        Severity::Critical
                    } else {
                        Severity::High
                    };

                    vulnerabilities.push(create_vulnerability(
                        "TS005",
                        Some("CWE-94"),
                        "Code Injection",
                        severity,
                        "injection",
                        "Code execution via eval() or dynamic code execution",
                        &source_file.path.to_string_lossy(),
                        line_num + 1,
                        0,
                        line,
                        "Avoid eval(), Function constructor, and dynamic imports with user input. Use safer alternatives",
                    ));
                }
            }
        }

        Ok(vulnerabilities)
    }

    fn check_dom_manipulation(&self, source_file: &SourceFile, ast: &ParsedAst) -> Result<Vec<Vulnerability>> {
        let mut vulnerabilities = Vec::new();
        let lines: Vec<&str> = ast.source.lines().collect();

        for (line_num, line) in lines.iter().enumerate() {
            for pattern in &self.dom_patterns {
                if pattern.is_match(line) {
                    vulnerabilities.push(create_vulnerability(
                        "TS006",
                        Some("CWE-79"),
                        "Cross-Site Scripting (XSS)",
                        Severity::Medium,
                        "injection",
                        "Unsafe DOM manipulation with user input",
                        &source_file.path.to_string_lossy(),
                        line_num + 1,
                        0,
                        line,
                        "Validate and sanitize URLs/data before setting DOM attributes",
                    ));
                }
            }

            if line.contains("document.cookie") && line.contains("=") {
                vulnerabilities.push(create_vulnerability(
                    "TS007",
                    Some("CWE-1004"),
                    "Sensitive Cookie Without Secure Flag",
                    Severity::Medium,
                    "authentication",
                    "Cookie manipulation detected",
                    &source_file.path.to_string_lossy(),
                    line_num + 1,
                    0,
                    line,
                    "Ensure cookies are set with secure flags (HttpOnly, Secure, SameSite)",
                ));
            }
        }

        Ok(vulnerabilities)
    }

    fn check_weak_cryptography(&self, source_file: &SourceFile, ast: &ParsedAst) -> Result<Vec<Vulnerability>> {
        let mut vulnerabilities = Vec::new();
        let lines: Vec<&str> = ast.source.lines().collect();

        for (line_num, line) in lines.iter().enumerate() {
            for pattern in &self.crypto_patterns {
                if pattern.is_match(line) {
                    let (id, message, recommendation, severity) = if line.contains("Math.random") {
                        ("TS008", "Insecure random number generation", "Use crypto.getRandomValues() for cryptographic purposes", Severity::Medium)
                    } else if line.contains("md5") || line.contains("sha1") {
                        ("TS019", "Weak hash algorithm", "Use SHA-256 or stronger hash algorithms", Severity::High)
                    } else if line.contains("des") || line.contains("rc4") {
                        ("TS020", "Weak encryption algorithm", "Use AES or other strong encryption algorithms", Severity::High)
                    } else if line.contains("btoa") || line.contains("atob") {
                        ("TS010", "Base64 encoding/decoding is not encryption", "Use proper encryption algorithms, base64 is encoding not encryption", Severity::Low)
                    } else {
                        ("TS011", "Weak cryptographic practice", "Use proper cryptographic libraries and methods", Severity::Medium)
                    };

                    vulnerabilities.push(create_vulnerability(
                        id,
                        Some("CWE-327"),
                        "Weak Cryptography",
                        severity,
                        "cryptographic",
                        message,
                        &source_file.path.to_string_lossy(),
                        line_num + 1,
                        0,
                        line,
                        recommendation,
                    ));
                }
            }
        }

        Ok(vulnerabilities)
    }

    fn check_hardcoded_secrets(&self, source_file: &SourceFile, ast: &ParsedAst) -> Result<Vec<Vulnerability>> {
        let mut vulnerabilities = Vec::new();
        let lines: Vec<&str> = ast.source.lines().collect();

        for (line_num, line) in lines.iter().enumerate() {
            for pattern in &self.hardcoded_secrets_patterns {
                if pattern.is_match(line) {
                    let severity = if line.contains("AKIA") || line.contains("ghp_") || line.contains("-----BEGIN") {
                        Severity::Critical
                    } else {
                        Severity::High
                    };

                    vulnerabilities.push(create_vulnerability(
                        "TS012",
                        Some("CWE-798"),
                        "Hardcoded Credentials",
                        severity,
                        "authentication",
                        "Hardcoded secrets or credentials detected",
                        &source_file.path.to_string_lossy(),
                        line_num + 1,
                        0,
                        line,
                        "Store secrets in environment variables or secure vaults, never in source code",
                    ));
                }
            }
        }

        Ok(vulnerabilities)
    }

    fn check_type_safety(&self, source_file: &SourceFile, ast: &ParsedAst) -> Result<Vec<Vulnerability>> {
        let mut vulnerabilities = Vec::new();
        let lines: Vec<&str> = ast.source.lines().collect();

        for (line_num, line) in lines.iter().enumerate() {
            // Check type assertions
            for pattern in &self.type_assertion_patterns {
                if pattern.is_match(line) {
                    let severity = if line.contains("req.") || line.contains("as unknown as") {
                        Severity::High
                    } else {
                        Severity::Medium
                    };

                    vulnerabilities.push(create_vulnerability(
                        "TS013",
                        Some("CWE-704"),
                        "Unsafe Type Assertion",
                        severity,
                        "validation",
                        "Unsafe type assertion bypassing TypeScript type checking",
                        &source_file.path.to_string_lossy(),
                        line_num + 1,
                        0,
                        line,
                        "Avoid 'as any' and unsafe type assertions. Use proper type guards and validation",
                    ));
                }
            }

            // Check any types
            for pattern in &self.any_type_patterns {
                if pattern.is_match(line) && !line.trim_start().starts_with("//") {
                    vulnerabilities.push(create_vulnerability(
                        "TS014",
                        Some("CWE-704"),
                        "Use of Any Type",
                        Severity::Low,
                        "validation",
                        "Usage of 'any' type defeats TypeScript benefits",
                        &source_file.path.to_string_lossy(),
                        line_num + 1,
                        0,
                        line,
                        "Use specific types instead of 'any' to maintain type safety",
                    ));
                }
            }

            // Check strict null patterns
            for pattern in &self.strict_null_patterns {
                if pattern.is_match(line) {
                    vulnerabilities.push(create_vulnerability(
                        "TS021",
                        Some("CWE-476"),
                        "Null Pointer Dereference Risk",
                        Severity::Medium,
                        "validation",
                        "Non-null assertion operator may cause runtime errors",
                        &source_file.path.to_string_lossy(),
                        line_num + 1,
                        0,
                        line,
                        "Use proper null checks instead of non-null assertion operator",
                    ));
                }
            }
        }

        Ok(vulnerabilities)
    }

    fn check_typescript_specific_vulnerabilities(&self, source_file: &SourceFile, ast: &ParsedAst) -> Result<Vec<Vulnerability>> {
        let mut vulnerabilities = Vec::new();
        let lines: Vec<&str> = ast.source.lines().collect();

        for (line_num, line) in lines.iter().enumerate() {
            // Check TypeScript-specific patterns
            for pattern in &self.typescript_specific_patterns {
                if pattern.is_match(line) {
                    let (severity, message) = if line.contains("strict") && line.contains("false") {
                        (Severity::High, "Strict mode disabled reduces type safety")
                    } else if line.contains("declare") {
                        (Severity::Medium, "Unsafe module declaration detected")
                    } else {
                        (Severity::Low, "TypeScript configuration may reduce security")
                    };

                    vulnerabilities.push(create_vulnerability(
                        "TS022",
                        Some("CWE-693"),
                        "TypeScript Configuration Issue",
                        severity,
                        "configuration",
                        message,
                        &source_file.path.to_string_lossy(),
                        line_num + 1,
                        0,
                        line,
                        "Use strict TypeScript configuration and avoid unsafe declarations",
                    ));
                }
            }

            // Check enum patterns
            for pattern in &self.enum_patterns {
                if pattern.is_match(line) {
                    vulnerabilities.push(create_vulnerability(
                        "TS023",
                        Some("CWE-704"),
                        "Unsafe Enum Usage",
                        Severity::Low,
                        "validation",
                        "Numeric enums or enum iteration may be unsafe",
                        &source_file.path.to_string_lossy(),
                        line_num + 1,
                        0,
                        line,
                        "Use string enums and avoid iterating over enum values with user input",
                    ));
                }
            }

            // Check decorator patterns
            for pattern in &self.decorator_patterns {
                if pattern.is_match(line) {
                    vulnerabilities.push(create_vulnerability(
                        "TS024",
                        Some("CWE-284"),
                        "Insecure Decorator Usage",
                        Severity::Medium,
                        "authorization",
                        "Potentially insecure decorator configuration",
                        &source_file.path.to_string_lossy(),
                        line_num + 1,
                        0,
                        line,
                        "Review decorator configuration and ensure proper access controls",
                    ));
                }
            }
        }

        Ok(vulnerabilities)
    }

    fn check_redos_vulnerabilities(&self, source_file: &SourceFile, ast: &ParsedAst) -> Result<Vec<Vulnerability>> {
        let mut vulnerabilities = Vec::new();
        let lines: Vec<&str> = ast.source.lines().collect();

        for (line_num, line) in lines.iter().enumerate() {
            for pattern in &self.redos_patterns {
                if pattern.is_match(line) {
                    vulnerabilities.push(create_vulnerability(
                        "TS025",
                        Some("CWE-1333"),
                        "Regular Expression Denial of Service (ReDoS)",
                        Severity::High,
                        "validation",
                        "Potentially vulnerable regular expression that could cause ReDoS",
                        &source_file.path.to_string_lossy(),
                        line_num + 1,
                        0,
                        line,
                        "Review regex for nested quantifiers and alternation. Use non-backtracking patterns",
                    ));
                }
            }
        }

        Ok(vulnerabilities)
    }

    fn check_supply_chain_attacks(&self, source_file: &SourceFile, ast: &ParsedAst) -> Result<Vec<Vulnerability>> {
        let mut vulnerabilities = Vec::new();
        let lines: Vec<&str> = ast.source.lines().collect();

        for (line_num, line) in lines.iter().enumerate() {
            for pattern in &self.supply_chain_patterns {
                if pattern.is_match(line) {
                    let severity = if line.contains("polyfill.io") || line.contains("eval(atob") {
                        Severity::Critical
                    } else {
                        Severity::Medium
                    };

                    vulnerabilities.push(create_vulnerability(
                        "TS026",
                        Some("CWE-829"),
                        "Supply Chain Attack",
                        severity,
                        "configuration",
                        "Potentially malicious or compromised external resource",
                        &source_file.path.to_string_lossy(),
                        line_num + 1,
                        0,
                        line,
                        "Use trusted CDNs, implement SRI (Subresource Integrity), avoid suspicious domains",
                    ));
                }
            }
        }

        Ok(vulnerabilities)
    }

    fn check_path_traversal(&self, source_file: &SourceFile, ast: &ParsedAst) -> Result<Vec<Vulnerability>> {
        let mut vulnerabilities = Vec::new();
        let lines: Vec<&str> = ast.source.lines().collect();

        for (line_num, line) in lines.iter().enumerate() {
            for pattern in &self.path_traversal_patterns {
                if pattern.is_match(line) {
                    vulnerabilities.push(create_vulnerability(
                        "TS027",
                        Some("CWE-22"),
                        "Path Traversal",
                        Severity::High,
                        "validation",
                        "Potential path traversal vulnerability",
                        &source_file.path.to_string_lossy(),
                        line_num + 1,
                        0,
                        line,
                        "Validate and sanitize file paths, use path.resolve() and check against allowed directories",
                    ));
                }
            }
        }

        Ok(vulnerabilities)
    }

    fn check_template_injection(&self, source_file: &SourceFile, ast: &ParsedAst) -> Result<Vec<Vulnerability>> {
        let mut vulnerabilities = Vec::new();
        let lines: Vec<&str> = ast.source.lines().collect();

        for (line_num, line) in lines.iter().enumerate() {
            for pattern in &self.template_injection_patterns {
                if pattern.is_match(line) {
                    vulnerabilities.push(create_vulnerability(
                        "TS028",
                        Some("CWE-94"),
                        "Template Injection",
                        Severity::High,
                        "injection",
                        "Potential server-side template injection vulnerability",
                        &source_file.path.to_string_lossy(),
                        line_num + 1,
                        0,
                        line,
                        "Sanitize template inputs, use safe template rendering modes, avoid unescaped output",
                    ));
                }
            }
        }

        Ok(vulnerabilities)
    }

    fn check_weak_randomness(&self, source_file: &SourceFile, ast: &ParsedAst) -> Result<Vec<Vulnerability>> {
        let mut vulnerabilities = Vec::new();
        let lines: Vec<&str> = ast.source.lines().collect();

        for (line_num, line) in lines.iter().enumerate() {
            for pattern in &self.weak_random_patterns {
                if pattern.is_match(line) {
                    vulnerabilities.push(create_vulnerability(
                        "TS029",
                        Some("CWE-338"),
                        "Weak Random Number Generation",
                        Severity::High,
                        "cryptographic",
                        "Weak randomness used in security-sensitive context",
                        &source_file.path.to_string_lossy(),
                        line_num + 1,
                        0,
                        line,
                        "Use crypto.getRandomValues() or crypto.randomBytes() for security-sensitive randomness",
                    ));
                }
            }
        }

        Ok(vulnerabilities)
    }

    fn check_security_headers(&self, source_file: &SourceFile, ast: &ParsedAst) -> Result<Vec<Vulnerability>> {
        let mut vulnerabilities = Vec::new();
        let content = &ast.source;

        if content.contains("express") && content.contains("app.use") {
            if !content.contains("helmet") && !content.contains("X-Frame-Options") && !content.contains("Content-Security-Policy") {
                vulnerabilities.push(create_vulnerability(
                    "TS015",
                    Some("CWE-693"),
                    "Protection Mechanism Failure",
                    Severity::Medium,
                    "validation",
                    "Missing security headers middleware",
                    &source_file.path.to_string_lossy(),
                    1,
                    0,
                    "Express app without security headers",
                    "Use helmet.js or manually set security headers (X-Frame-Options, CSP, HSTS, etc.)",
                ));
            }
        }

        Ok(vulnerabilities)
    }

    fn check_unsafe_redirects(&self, source_file: &SourceFile, ast: &ParsedAst) -> Result<Vec<Vulnerability>> {
        let mut vulnerabilities = Vec::new();
        
        if let Some(root_node) = ast.root_node() {
            self.traverse_node(&root_node, &ast.source, |node, source_slice| {
            if node.kind() == "call_expression" {
                let expr_text = &source_slice[node.byte_range()];
                
                if expr_text.contains("res.redirect") && expr_text.contains("req.") {
                    let start_pos = node.start_position();
                    vulnerabilities.push(create_vulnerability(
                        "TS016",
                        Some("CWE-601"),
                        "Open Redirect",
                        Severity::Medium,
                        "validation",
                        "Open redirect vulnerability - user input in redirect",
                        &source_file.path.to_string_lossy(),
                        start_pos.row + 1,
                        start_pos.column,
                        expr_text,
                        "Validate redirect URLs against whitelist of allowed domains",
                    ));
                }
            }
            });
        }

        Ok(vulnerabilities)
    }

    fn check_nosql_injection(&self, source_file: &SourceFile, ast: &ParsedAst) -> Result<Vec<Vulnerability>> {
        let mut vulnerabilities = Vec::new();
        let lines: Vec<&str> = ast.source.lines().collect();

        for (line_num, line) in lines.iter().enumerate() {
            if (line.contains("find(") || line.contains("findOne(") || line.contains("update(") || line.contains("aggregate(")) &&
               line.contains("req.") && !line.contains("$") {
                vulnerabilities.push(create_vulnerability(
                    "TS017",
                    Some("CWE-943"),
                    "NoSQL Injection",
                    Severity::High,
                    "injection",
                    "Potential NoSQL injection vulnerability",
                    &source_file.path.to_string_lossy(),
                    line_num + 1,
                    0,
                    line,
                    "Sanitize and validate user input for NoSQL queries. Use parameterized queries and input validation",
                ));
            }
        }

        Ok(vulnerabilities)
    }

    fn traverse_node<F>(&self, node: &Node, source: &str, mut callback: F)
    where
        F: FnMut(&Node, &str),
    {
        let mut cursor = node.walk();
        
        loop {
            callback(&cursor.node(), source);
            
            if cursor.goto_first_child() {
                continue;
            }
            
            if cursor.goto_next_sibling() {
                continue;
            }
            
            loop {
                if !cursor.goto_parent() {
                    return;
                }
                
                if cursor.goto_next_sibling() {
                    break;
                }
            }
        }
    }
}

impl RuleSet for TypeScriptRules {
    fn analyze(&self, source_file: &SourceFile, ast: &ParsedAst) -> Result<Vec<Vulnerability>> {
        let mut all_vulnerabilities = Vec::new();

        all_vulnerabilities.extend(self.check_xss_vulnerabilities(source_file, ast)?);
        all_vulnerabilities.extend(self.check_prototype_pollution(source_file, ast)?);
        all_vulnerabilities.extend(self.check_eval_usage(source_file, ast)?);
        all_vulnerabilities.extend(self.check_dom_manipulation(source_file, ast)?);
        all_vulnerabilities.extend(self.check_weak_cryptography(source_file, ast)?);
        all_vulnerabilities.extend(self.check_hardcoded_secrets(source_file, ast)?);
        all_vulnerabilities.extend(self.check_type_safety(source_file, ast)?);
        all_vulnerabilities.extend(self.check_typescript_specific_vulnerabilities(source_file, ast)?);
        all_vulnerabilities.extend(self.check_redos_vulnerabilities(source_file, ast)?);
        all_vulnerabilities.extend(self.check_supply_chain_attacks(source_file, ast)?);
        all_vulnerabilities.extend(self.check_path_traversal(source_file, ast)?);
        all_vulnerabilities.extend(self.check_template_injection(source_file, ast)?);
        all_vulnerabilities.extend(self.check_weak_randomness(source_file, ast)?);
        all_vulnerabilities.extend(self.check_security_headers(source_file, ast)?);
        all_vulnerabilities.extend(self.check_unsafe_redirects(source_file, ast)?);
        all_vulnerabilities.extend(self.check_nosql_injection(source_file, ast)?);

        Ok(all_vulnerabilities)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{parsers::typescript_parser::TypeScriptParser, Language};
    use std::path::PathBuf;

    #[test]
    fn test_type_assertion_detection() {
        let rules = TypeScriptRules::new();
        let parser = TypeScriptParser::new();
        
        let source = r#"
function processData(data: unknown) {
    const userData = data as any;
    return userData.sensitiveInfo;
}
"#;
        
        let source_file = SourceFile::new(
            PathBuf::from("test.ts"),
            source.to_string(),
            Language::TypeScript,
        );
        
        let ast = parser.parse(&source_file).unwrap();
        let vulnerabilities = rules.analyze(&source_file, &ast).unwrap();
        
        assert!(!vulnerabilities.is_empty());
        assert!(vulnerabilities.iter().any(|v| v.id == "TS013"));
    }

    #[test]
    fn test_any_type_detection() {
        let rules = TypeScriptRules::new();
        let parser = TypeScriptParser::new();
        
        let source = r#"
function processInput(input: any): void {
    console.log(input);
}
"#;
        
        let source_file = SourceFile::new(
            PathBuf::from("test.ts"),
            source.to_string(),
            Language::TypeScript,
        );
        
        let ast = parser.parse(&source_file).unwrap();
        let vulnerabilities = rules.analyze(&source_file, &ast).unwrap();
        
        assert!(!vulnerabilities.is_empty());
        assert!(vulnerabilities.iter().any(|v| v.id == "TS014"));
    }

    #[test]
    fn test_non_null_assertion_detection() {
        let rules = TypeScriptRules::new();
        let parser = TypeScriptParser::new();
        
        let source = r#"
const value = possiblyNull!.property!.method();
"#;
        
        let source_file = SourceFile::new(
            PathBuf::from("test.ts"),
            source.to_string(),
            Language::TypeScript,
        );
        
        let ast = parser.parse(&source_file).unwrap();
        let vulnerabilities = rules.analyze(&source_file, &ast).unwrap();
        
        assert!(!vulnerabilities.is_empty());
        assert!(vulnerabilities.iter().any(|v| v.id == "TS021"));
    }

    #[test]
    fn test_unsafe_type_assertion_on_request() {
        let rules = TypeScriptRules::new();
        let parser = TypeScriptParser::new();
        
        let source = r#"
const userInput = req.body as UserInterface;
"#;
        
        let source_file = SourceFile::new(
            PathBuf::from("test.ts"),
            source.to_string(),
            Language::TypeScript,
        );
        
        let ast = parser.parse(&source_file).unwrap();
        let vulnerabilities = rules.analyze(&source_file, &ast).unwrap();
        
        assert!(!vulnerabilities.is_empty());
        assert!(vulnerabilities.iter().any(|v| v.id == "TS013" && v.severity == Severity::High));
    }
}