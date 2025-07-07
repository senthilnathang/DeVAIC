use super::{create_vulnerability, RuleSet};
use crate::{
    error::Result,
    parsers::{ParsedAst, SourceFile},
    Severity, Vulnerability,
};
use regex::Regex;
use tree_sitter::Node;

pub struct JavascriptRules {
    xss_patterns: Vec<Regex>,
    prototype_pollution_patterns: Vec<Regex>,
    eval_patterns: Vec<Regex>,
    dom_patterns: Vec<Regex>,
    crypto_patterns: Vec<Regex>,
    hardcoded_secrets_patterns: Vec<Regex>,
    redos_patterns: Vec<Regex>,
    supply_chain_patterns: Vec<Regex>,
    path_traversal_patterns: Vec<Regex>,
    template_injection_patterns: Vec<Regex>,
    weak_random_patterns: Vec<Regex>,
    xxe_patterns: Vec<Regex>,
    deserialization_patterns: Vec<Regex>,
    command_injection_patterns: Vec<Regex>,
}

impl JavascriptRules {
    pub fn new() -> Self {
        Self {
            xss_patterns: vec![
                // Enhanced XSS patterns for modern JavaScript
                Regex::new(r"\.innerHTML\s*[+]?=\s*[^;]*[\+&]").unwrap(),
                Regex::new(r"\.outerHTML\s*[+]?=\s*[^;]*[\+&]").unwrap(),
                Regex::new(r"document\.write\s*\(\s*[^)]*[\+&]").unwrap(),
                Regex::new(r"document\.writeln\s*\(\s*[^)]*[\+&]").unwrap(),
                Regex::new(r"\.insertAdjacentHTML\s*\(\s*[^,]*,\s*[^)]*[\+&]").unwrap(),
                // React/Vue specific patterns
                Regex::new(r"v-html\s*=\s*[^>]*[\+&]").unwrap(),
                Regex::new(r"\$\{[^}]*\+[^}]*\}").unwrap(), // Template literal injection
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
            ],
            eval_patterns: vec![
                // Enhanced eval patterns including modern variants
                Regex::new(r"\beval\s*\(").unwrap(),
                Regex::new(r"new\s+Function\s*\(").unwrap(),
                Regex::new(r"setTimeout\s*\(\s*[`'\x22]\s*.*\+").unwrap(),
                Regex::new(r"setInterval\s*\(\s*[`'\x22]\s*.*\+").unwrap(),
                
                // Dynamic imports with user input
                Regex::new(r"import\s*\(\s*.*\+").unwrap(),
                Regex::new(r"require\s*\(\s*.*\+").unwrap(),
                
                // VM module usage
                Regex::new(r"vm\.runInThisContext\s*\(").unwrap(),
                Regex::new(r"vm\.runInNewContext\s*\(").unwrap(),
                Regex::new(r"vm\.runInContext\s*\(").unwrap(),
                Regex::new(r"vm\.createScript\s*\(").unwrap(),
                
                // Web Workers with dynamic scripts
                Regex::new(r"new\s+Worker\s*\(\s*.*\+").unwrap(),
                Regex::new(r"new\s+SharedWorker\s*\(\s*.*\+").unwrap(),
                
                // Script tag injection
                Regex::new(r"createElement\s*\(\s*['\x22]script['\x22]").unwrap(),
                
                // Additional code execution vectors
                Regex::new(r"execScript\s*\(").unwrap(), // IE-specific
                Regex::new(r"msWriteProfilerMark\s*\(").unwrap(), // IE-specific
                Regex::new(r#"window\[['"`][^'"`]*['"`]\]\s*\("#).unwrap(), // window["func"]()
                
                // WebAssembly dynamic compilation
                Regex::new(r"WebAssembly\.compile\s*\(.*\+").unwrap(),
                Regex::new(r"WebAssembly\.instantiate\s*\(.*\+").unwrap(),
                
                // Service Worker registration with dynamic content
                Regex::new(r"navigator\.serviceWorker\.register\s*\(.*\+").unwrap(),
                
                // Dynamic module loading
                Regex::new(r"importScripts\s*\(.*\+").unwrap(),
                
                // Eval-like functions in libraries
                Regex::new(r"lodash\.template\s*\(.*\+").unwrap(),
                Regex::new(r"_.template\s*\(.*\+").unwrap(),
                Regex::new(r"Handlebars\.compile\s*\(.*\+").unwrap(),
                
                // Node.js specific
                Regex::new(r"child_process\.exec\s*\(.*\+").unwrap(),
                Regex::new(r"child_process\.spawn\s*\(.*\+").unwrap(),
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
            ],
            redos_patterns: vec![
                // Enhanced Regular Expression Denial of Service patterns
                // Super-linear backtracking patterns - exponential complexity
                Regex::new(r"\(\.\*\)\+").unwrap(), // (.*)+
                Regex::new(r"\(\.\+\)\+").unwrap(), // (.+)+
                Regex::new(r"\(\[\^.\]\*\)\+").unwrap(), // ([^.]*)+
                Regex::new(r"\(\[\^.\]\+\)\+").unwrap(), // ([^.]+)+
                Regex::new(r"\(\w\*\)\+").unwrap(), // (\w*)+
                Regex::new(r"\(\w\+\)\+").unwrap(), // (\w+)+
                
                // Additional super-linear backtracking patterns
                Regex::new(r"\([^)]*\?\)\*").unwrap(), // (x?)*
                Regex::new(r"\([^)]*\?\)\+").unwrap(), // (x?)+
                Regex::new(r"\([^)]*\*\?\)\*").unwrap(), // (x*?)*
                Regex::new(r"\([^)]*\+\?\)\+").unwrap(), // (x+?)+
                
                // Nested quantifiers - polynomial complexity
                Regex::new(r"\([^)]*\*[^)]*\)\*").unwrap(),
                Regex::new(r"\([^)]*\+[^)]*\)\+").unwrap(),
                Regex::new(r"\([^)]*\{[0-9]*,[0-9]*\}[^)]*\)\*").unwrap(), // (x{n,m})*
                Regex::new(r"\([^)]*\{[0-9]*,[0-9]*\}[^)]*\)\+").unwrap(), // (x{n,m})+
                
                // Alternation with overlapping patterns - ambiguous matching
                Regex::new(r"\([^|]*\|\.\*\)").unwrap(),
                Regex::new(r"\([^|]*\|\.\+\)").unwrap(),
                Regex::new(r"\([^|]*\|[^)]*\.\*[^)]*\)").unwrap(),
                
                // Character class patterns that can cause issues
                Regex::new(r"\([\[\^]*\.\*[\]]*\)\+").unwrap(), // ([.*])+
                Regex::new(r"\([\[\^]*\.\+[\]]*\)\+").unwrap(), // ([.+])+
                
                // Common ReDoS patterns from real attacks
                Regex::new(r"\(a\+\)\+b").unwrap(), // (a+)+b - classic ReDoS pattern
                Regex::new(r"\(a\*\)\*").unwrap(), // (a*)*
                Regex::new(r"\(\.\*a\)\*").unwrap(), // (.*a)*
                Regex::new(r"\(a\|a\)\*").unwrap(), // (a|a)*
                
                // Super-linear move patterns - quadratic runtime
                Regex::new(r"a\+b").unwrap(), // a+b - can cause O(n²) moves
                Regex::new(r"\w\+@").unwrap(), // \w+@ - email validation ReDoS
                Regex::new(r"\d\+\.\d\+").unwrap(), // \d+\.\d+ - decimal number ReDoS
                Regex::new(r"[a-zA-Z]\+[0-9]\+").unwrap(), // [a-zA-Z]+[0-9]+ - alphanumeric ReDoS
                
                // Lookahead/lookbehind with quantifiers
                Regex::new(r"\(\?\=[^)]*\*[^)]*\)").unwrap(), // (?=.**)
                Regex::new(r"\(\?\=[^)]*\+[^)]*\)").unwrap(), // (?=.*+)
                Regex::new(r"\(\?\<=[^)]*\*[^)]*\)").unwrap(), // (?<=.**)
                
                // Word boundary issues
                Regex::new(r"\\b[^\\]*\\b\*").unwrap(), // \b...\b*
                Regex::new(r"\\b[^\\]*\\b\+").unwrap(), // \b...\b+
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
            xxe_patterns: vec![
                // XML External Entity (XXE) patterns
                Regex::new(r"new\s+DOMParser\s*\(\s*\)").unwrap(),
                Regex::new(r"parseFromString\s*\(.*req\.").unwrap(),
                Regex::new(r"XMLHttpRequest\s*\(\s*\)").unwrap(),
                Regex::new(r"libxmljs\.parseXml\s*\(").unwrap(),
                Regex::new(r"xml2js\.parseString\s*\(").unwrap(),
                Regex::new(r#"new\s+ActiveXObject\s*\(\s*['"]Microsoft\.XMLDOM['"]"#).unwrap(),
                // XML parsing without disabling external entities
                Regex::new(r"\.resolveExternals\s*=\s*true").unwrap(),
                Regex::new(r"\.validateOnParse\s*=\s*true").unwrap(),
            ],
            deserialization_patterns: vec![
                // Unsafe deserialization patterns
                Regex::new(r"JSON\.parse\s*\(\s*.*req\.").unwrap(),
                Regex::new(r"eval\s*\(\s*.*JSON\.stringify").unwrap(),
                Regex::new(r"Function\s*\(\s*.*JSON\.stringify").unwrap(),
                // Node.js serialization
                Regex::new(r"serialize-javascript").unwrap(),
                Regex::new(r"node-serialize").unwrap(),
                Regex::new(r"serialize\s*\(\s*.*req\.").unwrap(),
                Regex::new(r"unserialize\s*\(\s*.*req\.").unwrap(),
                // YAML deserialization
                Regex::new(r"yaml\.load\s*\(\s*.*req\.").unwrap(),
                Regex::new(r"yaml\.safeLoad\s*\(\s*.*req\.").unwrap(),
                // Pickle-like libraries
                Regex::new(r"v8\.deserialize\s*\(").unwrap(),
            ],
            command_injection_patterns: vec![
                // Command injection patterns
                Regex::new(r"child_process\.exec\s*\(\s*.*req\.").unwrap(),
                Regex::new(r"child_process\.execSync\s*\(\s*.*req\.").unwrap(),
                Regex::new(r"child_process\.spawn\s*\(\s*.*req\.").unwrap(),
                Regex::new(r"child_process\.spawnSync\s*\(\s*.*req\.").unwrap(),
                Regex::new(r"child_process\.execFile\s*\(\s*.*req\.").unwrap(),
                Regex::new(r"child_process\.fork\s*\(\s*.*req\.").unwrap(),
                // Shell command patterns
                Regex::new(r"shelljs\.exec\s*\(\s*.*req\.").unwrap(),
                Regex::new(r"shell\.exec\s*\(\s*.*req\.").unwrap(),
                // Dangerous shell characters in commands
                Regex::new(r#"['"][^'"]*\$\{.*req\..*\}[^'"]*['"]"#).unwrap(),
                Regex::new(r#"['"][^'"]*[;&|`][^'"]*['"]"#).unwrap(),
                // Process execution with concatenation
                Regex::new(r"process\.exec\s*\(\s*.*\+").unwrap(),
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
                                      line.contains("v-html") ||
                                      line.contains("createContextualFragment") {
                        Severity::Critical
                    } else {
                        Severity::High
                    };

                    vulnerabilities.push(create_vulnerability(
                        "JS001",
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
                        "JS003",
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
                    let severity = if line.contains("eval(") || line.contains("vm.runIn") {
                        Severity::Critical
                    } else {
                        Severity::High
                    };

                    vulnerabilities.push(create_vulnerability(
                        "JS005",
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
                        "JS006",
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
                    "JS007",
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
                        ("JS008", "Insecure random number generation", "Use crypto.getRandomValues() for cryptographic purposes", Severity::Medium)
                    } else if line.contains("md5") || line.contains("sha1") {
                        ("JS019", "Weak hash algorithm", "Use SHA-256 or stronger hash algorithms", Severity::High)
                    } else if line.contains("des") || line.contains("rc4") {
                        ("JS020", "Weak encryption algorithm", "Use AES or other strong encryption algorithms", Severity::High)
                    } else if line.contains("btoa") || line.contains("atob") {
                        ("JS010", "Base64 encoding/decoding is not encryption", "Use proper encryption algorithms, base64 is encoding not encryption", Severity::Low)
                    } else {
                        ("JS011", "Weak cryptographic practice", "Use proper cryptographic libraries and methods", Severity::Medium)
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
                        "JS012",
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

    fn check_redos_vulnerabilities(&self, source_file: &SourceFile, ast: &ParsedAst) -> Result<Vec<Vulnerability>> {
        let mut vulnerabilities = Vec::new();
        let lines: Vec<&str> = ast.source.lines().collect();

        for (line_num, line) in lines.iter().enumerate() {
            for pattern in &self.redos_patterns {
                if pattern.is_match(line) {
                    vulnerabilities.push(create_vulnerability(
                        "JS021",
                        Some("CWE-1333"),
                        "Regular Expression Denial of Service (ReDoS)",
                        Severity::High,
                        "validation",
                        "Potentially vulnerable regular expression that could cause ReDoS",
                        &source_file.path.to_string_lossy(),
                        line_num + 1,
                        0,
                        line,
                        "Review regex for nested quantifiers and alternation. Use non-backtracking patterns or input validation",
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
                        "JS022",
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
                        "JS023",
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
                        "JS024",
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
                        "JS025",
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
                    "JS013",
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
                        "JS014",
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
                    "JS015",
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

    fn check_xxe_vulnerabilities(&self, source_file: &SourceFile, ast: &ParsedAst) -> Result<Vec<Vulnerability>> {
        let mut vulnerabilities = Vec::new();
        let lines: Vec<&str> = ast.source.lines().collect();

        for (line_num, line) in lines.iter().enumerate() {
            for pattern in &self.xxe_patterns {
                if pattern.is_match(line) {
                    vulnerabilities.push(create_vulnerability(
                        "JS026",
                        Some("CWE-611"),
                        "XML External Entity (XXE)",
                        Severity::High,
                        "injection",
                        "Potential XML External Entity (XXE) vulnerability",
                        &source_file.path.to_string_lossy(),
                        line_num + 1,
                        0,
                        line,
                        "Disable external entity processing in XML parsers and use secure XML parsing libraries",
                    ));
                }
            }
        }

        Ok(vulnerabilities)
    }

    fn check_deserialization_vulnerabilities(&self, source_file: &SourceFile, ast: &ParsedAst) -> Result<Vec<Vulnerability>> {
        let mut vulnerabilities = Vec::new();
        let lines: Vec<&str> = ast.source.lines().collect();

        for (line_num, line) in lines.iter().enumerate() {
            for pattern in &self.deserialization_patterns {
                if pattern.is_match(line) {
                    let severity = if line.contains("node-serialize") || line.contains("serialize-javascript") {
                        Severity::Critical
                    } else {
                        Severity::High
                    };

                    vulnerabilities.push(create_vulnerability(
                        "JS027",
                        Some("CWE-502"),
                        "Unsafe Deserialization",
                        severity,
                        "injection",
                        "Unsafe deserialization of user input",
                        &source_file.path.to_string_lossy(),
                        line_num + 1,
                        0,
                        line,
                        "Validate and sanitize serialized data, use safe parsing methods, avoid deserializing untrusted data",
                    ));
                }
            }
        }

        Ok(vulnerabilities)
    }

    fn check_command_injection(&self, source_file: &SourceFile, ast: &ParsedAst) -> Result<Vec<Vulnerability>> {
        let mut vulnerabilities = Vec::new();
        let lines: Vec<&str> = ast.source.lines().collect();

        for (line_num, line) in lines.iter().enumerate() {
            for pattern in &self.command_injection_patterns {
                if pattern.is_match(line) {
                    vulnerabilities.push(create_vulnerability(
                        "JS028",
                        Some("CWE-78"),
                        "Command Injection",
                        Severity::Critical,
                        "injection",
                        "Command injection vulnerability through user input",
                        &source_file.path.to_string_lossy(),
                        line_num + 1,
                        0,
                        line,
                        "Use parameterized commands, validate input, avoid shell execution with user data",
                    ));
                }
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

impl RuleSet for JavascriptRules {
    fn analyze(&self, source_file: &SourceFile, ast: &ParsedAst) -> Result<Vec<Vulnerability>> {
        let mut all_vulnerabilities = Vec::new();

        all_vulnerabilities.extend(self.check_xss_vulnerabilities(source_file, ast)?);
        all_vulnerabilities.extend(self.check_prototype_pollution(source_file, ast)?);
        all_vulnerabilities.extend(self.check_eval_usage(source_file, ast)?);
        all_vulnerabilities.extend(self.check_dom_manipulation(source_file, ast)?);
        all_vulnerabilities.extend(self.check_weak_cryptography(source_file, ast)?);
        all_vulnerabilities.extend(self.check_hardcoded_secrets(source_file, ast)?);
        all_vulnerabilities.extend(self.check_redos_vulnerabilities(source_file, ast)?);
        all_vulnerabilities.extend(self.check_supply_chain_attacks(source_file, ast)?);
        all_vulnerabilities.extend(self.check_path_traversal(source_file, ast)?);
        all_vulnerabilities.extend(self.check_template_injection(source_file, ast)?);
        all_vulnerabilities.extend(self.check_weak_randomness(source_file, ast)?);
        all_vulnerabilities.extend(self.check_security_headers(source_file, ast)?);
        all_vulnerabilities.extend(self.check_unsafe_redirects(source_file, ast)?);
        all_vulnerabilities.extend(self.check_nosql_injection(source_file, ast)?);
        all_vulnerabilities.extend(self.check_xxe_vulnerabilities(source_file, ast)?);
        all_vulnerabilities.extend(self.check_deserialization_vulnerabilities(source_file, ast)?);
        all_vulnerabilities.extend(self.check_command_injection(source_file, ast)?);

        Ok(all_vulnerabilities)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{parsers::{javascript_parser::JavascriptParser, Parser}, Language};
    use std::path::PathBuf;

    #[test]
    fn test_xss_detection() {
        let rules = JavascriptRules::new();
        let mut parser = JavascriptParser::new().unwrap();
        
        let source = r#"
function updateDOM(userInput) {
    document.getElementById('content').innerHTML = '<div>' + userInput + '</div>';
}
"#;
        
        let source_file = SourceFile::new(
            PathBuf::from("test.js"),
            source.to_string(),
            Language::Javascript,
        );
        
        let ast = parser.parse(&source_file).unwrap();
        let vulnerabilities = rules.analyze(&source_file, &ast).unwrap();
        
        assert!(!vulnerabilities.is_empty());
        assert!(vulnerabilities.iter().any(|v| v.id == "JS001"));
    }

    #[test]
    fn test_redos_detection() {
        let rules = JavascriptRules::new();
        let mut parser = JavascriptParser::new().unwrap();
        
        let source = r#"
const regex = /(.*)+ /;
const input = userInput.match(regex);
"#;
        
        let source_file = SourceFile::new(
            PathBuf::from("test.js"),
            source.to_string(),
            Language::Javascript,
        );
        
        let ast = parser.parse(&source_file).unwrap();
        let vulnerabilities = rules.analyze(&source_file, &ast).unwrap();
        
        assert!(!vulnerabilities.is_empty());
        assert!(vulnerabilities.iter().any(|v| v.id == "JS021"));
    }

    #[test]
    fn test_supply_chain_detection() {
        let rules = JavascriptRules::new();
        let mut parser = JavascriptParser::new().unwrap();
        
        let source = r#"
<script src="https://cdn.polyfill.io/v2/polyfill.min.js"></script>
"#;
        
        let source_file = SourceFile::new(
            PathBuf::from("test.js"),
            source.to_string(),
            Language::Javascript,
        );
        
        let ast = parser.parse(&source_file).unwrap();
        let vulnerabilities = rules.analyze(&source_file, &ast).unwrap();
        
        assert!(!vulnerabilities.is_empty());
        assert!(vulnerabilities.iter().any(|v| v.id == "JS022"));
    }
}