# DeVAIC - Advanced Vulnerability Analysis with Bearer-Inspired Privacy & Security Detection

A high-performance static code analyzer for comprehensive vulnerability, security risk, and privacy detection in C, C++, Java, JavaScript, TypeScript, Python, Rust, and SCADA programming languages, built in Rust.

DeVAIC provides enterprise-grade security analysis combining Bearer-inspired privacy risk detection with traditional vulnerability scanning. Originally designed for industrial control systems and embedded devices, it now offers comprehensive security analysis suitable for any codebase, from web applications to critical infrastructure.

## Key Features

### 🔒 **Bearer-Inspired Privacy & Security Analysis**
- **Privacy Risk Detection**: Comprehensive PII/PHI detection and data flow analysis
- **Security Risk Assessment**: Enterprise-grade security risk patterns and OWASP coverage
- **Sensitive Data Protection**: Advanced detection of exposed personal and health information
- **Data Flow Tracking**: Analysis of how sensitive data moves through your application

### 🛡️ **Comprehensive Vulnerability Detection**
- **Multi-language Support**: C, C++, Java, JavaScript, TypeScript, Python, Rust, and SCADA
- **OWASP Coverage**: Top 10 2021, LLM Top 10, and CWE Top 25 vulnerabilities
- **Language-Specific Risks**: Tailored detection for each programming language
- **Industrial Security**: Specialized rules for SCADA and embedded systems

### ⚡ **Advanced Analysis Engine**
- **AST-based Analysis**: Deep code understanding through Abstract Syntax Trees
- **Semgrep Integration**: Sophisticated pattern matching with metavariable support
- **High Performance**: Built with Rust for enterprise-scale analysis
- **Configurable Rules**: Customizable severity thresholds and rule categories

### 📊 **Enterprise Reporting**
- **Multiple Formats**: Table, JSON, SARIF, PDF, and Excel outputs
- **Compliance Ready**: Reports suitable for security audits and compliance reviews
- **Detailed Insights**: Comprehensive vulnerability information with fix suggestions
- **CI/CD Integration**: SARIF support for seamless DevSecOps workflows

## Detection Capabilities

### 🔐 **Privacy Risk Detection (Bearer-Inspired)**

**Personally Identifiable Information (PII)**
- Social Security Numbers, Credit Card Numbers, Passport Numbers
- Email addresses, Phone numbers, Physical addresses
- Driver's license numbers, Government IDs

**Protected Health Information (PHI)**
- Medical Record Numbers (MRN), Health Insurance Numbers
- Patient identifiers, Medical device IDs
- Healthcare provider information, Insurance policy numbers

**Data Flow & Exposure Analysis**
- Database queries selecting sensitive data
- API responses containing PII/PHI
- Logging and debugging output with sensitive information
- Client-side storage of sensitive data (localStorage, sessionStorage)
- DOM exposure of sensitive information

**Compliance & Regulatory Support**
- HIPAA compliance checking for healthcare applications
- PCI-DSS considerations for payment processing
- GDPR data protection requirements
- SOX financial data protection

### 🛡️ **Security Risk Assessment**

**Access Control & Authentication**
- Weak file permissions and privilege escalation risks
- Default or hardcoded credentials detection
- Session management vulnerabilities
- Authentication bypass patterns
- Authorization flaws and broken access control

**Cryptographic Security**
- Weak hash algorithms (MD5, SHA1) detection
- Insecure encryption methods (DES, RC4)
- Hardcoded encryption keys and secrets
- Weak random number generation for security purposes
- Certificate validation issues

**Data Integrity & Injection**
- SQL injection vulnerability patterns
- Command injection and OS command execution
- Path traversal and directory traversal
- LDAP injection and XML injection
- NoSQL injection patterns

**Configuration & Infrastructure**
- Debug mode enabled in production
- CORS wildcard configurations
- SSL/TLS verification disabled
- Insecure HTTP methods enabled
- Security headers missing

### ⚔️ **Enhanced Vulnerability Detection**

**CWE Top 25 Most Dangerous Weaknesses**
- CWE-79: Cross-site Scripting (XSS)
- CWE-89: SQL Injection
- CWE-78: OS Command Injection
- CWE-22: Path Traversal
- CWE-125: Out-of-bounds Read
- CWE-120: Buffer Copy without Checking Size
- CWE-502: Deserialization of Untrusted Data
- And 18 more critical weakness patterns

**OWASP Top 10 2021 Coverage**
- A01: Broken Access Control
- A02: Cryptographic Failures  
- A03: Injection
- A04: Insecure Design
- A05: Security Misconfiguration
- A06: Vulnerable and Outdated Components
- A07: Identification and Authentication Failures
- A08: Software and Data Integrity Failures
- A09: Security Logging and Monitoring Failures
- A10: Server-Side Request Forgery

**Language-Specific Vulnerabilities**
- **Python**: Import injection, Pickle deserialization, YAML loading
- **JavaScript**: Prototype pollution, Client-side injection, DOM manipulation
- **Java**: XXE vulnerabilities, Unsafe deserialization, JNDI injection
- **C/C++**: Buffer overflows, Format string bugs, Memory corruption
- **TypeScript**: Type safety violations, Prototype pollution
- **Rust**: Unsafe operations, Memory safety issues

### C/C++ Language
- Buffer overflow vulnerabilities
- Format string vulnerabilities
- Integer overflow detection
- Null pointer dereference
- Unsafe function usage
- Memory management issues

### Java Language
- Injection vulnerabilities (SQL, Command, LDAP)
- Deserialization attacks
- Hardcoded credentials
- Weak cryptographic implementations
- Input validation issues

### JavaScript/TypeScript
- Cross-site scripting (XSS) vulnerabilities
- Code injection (eval, Function constructor)
- Prototype pollution
- Insecure direct object references
- Type safety violations (TypeScript)

### Python Language
- Hardcoded secrets and credentials
- SQL injection vulnerabilities
- Command injection
- Unsafe deserialization (pickle, yaml)
- Weak cryptographic algorithms
- Debug mode detection
- Insecure random number generation

### Rust Language
- Unsafe operations and memory safety
- Cryptographic vulnerabilities
- Secrets and API token detection

### OWASP LLM Top 10 (AI/ML Security)
- **LLM01**: Prompt Injection - Untrusted input manipulation of LLM behavior
- **LLM03**: Training Data Poisoning - Malicious data compromising model integrity
- **LLM04**: Model Denial of Service - Resource exhaustion attacks
- **LLM06**: Sensitive Information Disclosure - Exposure of confidential data
- **LLM07**: Insecure Plugin Design - Unsafe plugin architectures
- **LLM08**: Excessive Agency - Over-privileged LLM systems

### SCADA Languages
- Hardcoded credentials
- Insecure communication protocols
- Unsafe memory operations
- Lack of input validation
- Weak authentication configurations
- Safety-critical operation validation
- Timing vulnerabilities
- Default configuration detection

### Secrets and API Token Detection
- **API Tokens**: Artifactory, AWS Client ID, Facebook Access Token, Google API Key, GitHub Token, Slack Token, Stripe API Key
- **Authentication**: Basic Auth credentials, Twitter OAuth tokens
- **Network**: IPv4 addresses, hardcoded HTTP URLs
- **Generic Secrets**: Passwords, private keys, database connection strings
- **Cloud Providers**: AWS, Azure, GCP credential patterns

### Regular Expression Denial of Service (ReDoS)
- **Exponential Backtracking**: Detection of nested quantifiers like `(a+)+`, `(a*)*` that cause exponential time complexity
- **Polynomial Backtracking**: Patterns that may cause polynomial time complexity with multiple consecutive quantified groups
- **Catastrophic Backtracking**: Known vulnerable patterns prone to catastrophic backtracking
- **User Input Vulnerabilities**: Critical detection when user input is used in potentially vulnerable regex patterns
- **Language-Specific Patterns**: Specialized detection for regex libraries across all supported languages (Python re, JavaScript RegExp, Java Pattern, C POSIX regex, C++ std::regex, Rust regex crate)
- **Industrial Control Systems**: SCADA-specific regex vulnerabilities in PLC data validation, HMI input processing, and protocol parsing

## Installation

### Prerequisites

- Rust 1.70.0 or later
- Cargo package manager

### From Source

```bash
git clone https://github.com/dessertlab/DeVAIC.git
cd DeVAIC
cargo build --release
```

The binary will be available at `target/release/devaic`.

### Install System-wide

```bash
cargo install --path .
```

This will install `devaic` to your system PATH.

## Quick Start

### Basic Analysis
```bash
# Analyze a single file for all vulnerability types
devaic path/to/your/file.py

# Comprehensive analysis of a directory
devaic --severity medium ./my-application/

# Generate detailed report for security review
devaic --format pdf --output security-report.pdf ./src/
```

### Bearer-Inspired Privacy & Security Analysis
```bash
# Privacy-focused analysis for PII/PHI detection
devaic --categories "privacy" --severity high ./healthcare-app/

# Security risk assessment for enterprise applications
devaic --categories "security,vulnerability" --format excel --output security-risks.xlsx ./enterprise-app/

# Comprehensive Bearer-style analysis (recommended)
devaic --categories "privacy,security,vulnerability,cryptographic,authentication" ./application/

# Compliance-ready analysis with detailed reporting
devaic --categories "privacy,security" --format pdf --output compliance-report.pdf --severity medium ./sensitive-app/
```

### Specialized Analysis
```bash
# Focus on injection vulnerabilities
devaic --categories "injection,validation" --severity high ./web-app/

# Cryptographic security review
devaic --categories "cryptographic,authentication" ./crypto-app/

# Industrial control systems analysis
devaic --categories "security,vulnerability" ./scada-programs/
```

For detailed usage examples and advanced configuration, see [USAGE.md](USAGE.md).

### Command Line Options

```
Usage: devaic [OPTIONS] <PATH>

Arguments:
  <PATH>  Target directory or file to analyze

Options:
  -f, --format <FORMAT>           Output format [default: table] [possible values: table, json, sarif, pdf, excel]
  -o, --output <OUTPUT>           Output file (if not specified, prints to stdout; required for pdf and excel formats)
  -c, --config <CONFIG>           Configuration file path
  -s, --severity <SEVERITY>       Severity threshold [default: low]
  -v, --verbose                   Enable verbose output
      --no-color                  Disable colored output
      --categories <CATEGORIES>   Categories to analyze (comma-separated)
      --max-file-size <MAX_FILE_SIZE>  Maximum file size to analyze in bytes [default: 10485760]
  -h, --help                      Print help
  -V, --version                   Print version
```

### Configuration File

Create a `devaic.toml` configuration file:

```toml
[rules]
enabled_categories = [
    "injection",
    "authentication", 
    "authorization",
    "cryptographic",
    "deserialization",
    "logging",
    "validation",
    "privacy",
    "security",
    "vulnerability"
]
severity_threshold = "LOW"

[output]
format = "table"
verbose = false
colors = true

[analysis]
max_file_size = 10485760  # 10MB
exclude_patterns = [
    "*.git/*",
    "target/*", 
    "node_modules/*"
]
include_patterns = [
    "*.c",
    "*.h", 
    "*.py",
    "*.st",
    "*.scl"
]
follow_symlinks = false
```

## Output Formats

### Table Format (Default)
Human-readable table showing vulnerabilities with syntax highlighting.

### JSON Format
Machine-readable JSON for integration with other tools:

```bash
devaic --format json --output report.json path/to/project/
```

### SARIF Format
Static Analysis Results Interchange Format for integration with IDEs and CI/CD:

```bash
devaic --format sarif --output report.sarif path/to/project/
```

### PDF Format
Formatted PDF report with comprehensive vulnerability analysis:

```bash
devaic --format pdf --output security-report.pdf path/to/project/
```

Features:
- Professional formatted report with title and summary
- Vulnerability breakdown by severity with visual indicators
- Detailed list of all detected vulnerabilities
- Automatic page breaks for long reports
- File path and line number references

### Excel Format
Comprehensive Excel workbook with detailed analysis:

```bash
devaic --format excel --output security-analysis.xlsx path/to/project/
```

Features:
- **Summary Sheet**: Analysis metrics, severity breakdown, and overview statistics
- **Vulnerabilities Sheet**: Detailed vulnerability data with filtering capabilities
- Color-coded severity indicators for easy identification
- Auto-fitted columns and professional formatting
- Suitable for sharing with stakeholders and management

## CI/CD Integration

DeVAIC exits with status code 1 if critical or high severity vulnerabilities are found, making it suitable for CI/CD pipelines:

```yaml
# GitHub Actions example
- name: Run Security Analysis
  run: |
    ./devaic --severity high --format sarif --output security-report.sarif ./src/
    
- name: Upload SARIF to GitHub
  uses: github/codeql-action/upload-sarif@v2
  with:
    sarif_file: security-report.sarif
```

## Supported File Extensions

- **C/C++**: `.c`, `.cpp`, `.h`, `.hpp`
- **Java**: `.java`
- **JavaScript**: `.js`
- **TypeScript**: `.ts`, `.tsx`
- **Python**: `.py`
- **Rust**: `.rs`
- **SCADA**: `.st`, `.scl`, `.fbd`, `.ld`, `.il`

## Real-World Usage Examples

### 🏥 **Healthcare Application Privacy Analysis**
```bash
# HIPAA compliance check for healthcare applications
devaic --categories "privacy" --severity medium --format pdf \
  --output hipaa-compliance-report.pdf ./healthcare-app/

# Detect PII/PHI exposure in medical software
devaic --categories "privacy,security" --severity high ./medical-device-software/
```

### 🏦 **Financial Services Security Assessment**
```bash
# PCI-DSS compliance and financial data protection
devaic --categories "privacy,cryptographic,authentication" \
  --format excel --output pci-compliance.xlsx ./payment-system/

# Detect credit card data exposure and weak cryptography
devaic --categories "privacy,security,vulnerability" --severity critical ./fintech-app/
```

### 🌐 **Enterprise Web Application Analysis**
```bash
# Comprehensive security assessment for web applications
devaic --categories "security,vulnerability,injection,authentication" \
  --format sarif --output web-security.sarif ./webapp/

# Bearer-style privacy and security analysis
devaic --categories "privacy,security,vulnerability" \
  --format excel --output enterprise-security-report.xlsx ./enterprise-app/
```

### 🏭 **Industrial Control Systems (SCADA)**
```bash
# Critical infrastructure security analysis
devaic --categories "security,vulnerability" --severity high \
  --format pdf --output scada-security-report.pdf ./scada-programs/

# Industrial system vulnerability assessment
devaic --categories "authentication,cryptographic,validation" ./industrial-control/
```

### 📱 **Mobile Application Security**
```bash
# Mobile app privacy and security analysis
devaic --categories "privacy,security,cryptographic" \
  --severity medium ./mobile-app-backend/

# API security assessment for mobile backends
devaic --categories "injection,authentication,security" \
  --format json --output mobile-api-security.json ./api-server/
```

### 🚀 **DevSecOps Integration Examples**
```bash
# CI/CD security gate with SARIF output
devaic --categories "security,vulnerability" --severity high \
  --format sarif --output security-gate.sarif ./src/

# Pre-commit privacy check
devaic --categories "privacy" --severity critical ./changed-files/

# Comprehensive security review for releases
devaic --categories "privacy,security,vulnerability,cryptographic,authentication" \
  --format excel --output release-security-review.xlsx ./release-candidate/
```

### 🎯 **Specialized Security Analysis**
```bash
# Cryptographic security review
devaic --categories "cryptographic,authentication" \
  --format table --severity medium ./crypto-library/

# Injection vulnerability assessment
devaic --categories "injection,validation" --severity high \
  --format json --output injection-analysis.json ./web-api/

# Memory safety analysis for C/C++ projects
devaic --categories "vulnerability,security" --severity medium \
  --format pdf --output memory-safety-report.pdf ./native-code/
```

## Development

### Building from Source

```bash
cargo build
```

### Running Tests

```bash
cargo test
```

### Adding New Rules

1. **Traditional Rules**: Add rule patterns to the appropriate rule file (`src/rules/c_rules.rs`, `src/rules/python_rules.rs`, etc.)
2. **Semgrep Rules**: Create YAML rule files in the `rules/` directory with pattern matching syntax
3. **OWASP LLM Rules**: Extend `src/rules/owasp_llm_rules.rs` for AI/ML security patterns
4. Implement the detection logic and add comprehensive tests
5. Update documentation with new vulnerability categories

### Semgrep Integration

DeVAIC includes a powerful Semgrep-compatible engine for advanced pattern matching:

```yaml
# Example rule in rules/javascript/security/eval-injection.yml
rules:
  - id: eval-injection
    patterns:
      - pattern: eval($USER_INPUT)
      - pattern-not: eval("...")
    message: "Direct use of eval() with user input detected"
    severity: ERROR
    languages: [javascript, typescript]
```

Features:
- **Pattern Matching**: Support for complex code patterns with metavariables
- **Autofix**: Automatic code fix suggestions
- **SARIF Output**: Standards-compliant security report format
- **Rule Composition**: Combine multiple patterns with logical operators

### AST-Based Analysis

DeVAIC leverages Abstract Syntax Tree (AST) parsing for deep code understanding:

- **Tree-sitter Integration**: Uses tree-sitter parsers for accurate language parsing
- **Semantic Analysis**: Goes beyond regex patterns to understand code structure and context
- **Cross-references**: Tracks variable usage, function calls, and data flow
- **Contextual Rules**: Enables sophisticated vulnerability detection based on code semantics
- **Language Support**: AST analysis available for C, C++, Java, JavaScript, TypeScript, Python, and Rust

The AST-based approach enables detection of complex vulnerabilities that traditional pattern matching might miss, such as:
- Data flow analysis for tracking tainted input
- Control flow analysis for identifying unreachable code
- Type analysis for detecting type confusion vulnerabilities
- Scope analysis for identifying variable shadowing issues

## Bearer vs DeVAIC Comparison

| Feature | Bearer | DeVAIC | Notes |
|---------|--------|--------|-------|
| **Privacy Detection** | ✅ Core Focus | ✅ Bearer-Inspired | PII/PHI detection, data flow analysis |
| **Security Risks** | ✅ Enterprise | ✅ Enhanced | OWASP coverage, crypto, authentication |
| **Vulnerability Scanning** | ✅ Basic | ✅ Comprehensive | CWE Top 25, language-specific patterns |
| **Languages Supported** | 7 languages | **8+ languages** | Includes SCADA/industrial languages |
| **Industrial/SCADA** | ❌ Not Supported | ✅ **Specialized** | Critical infrastructure focus |
| **Output Formats** | JSON, SARIF | **5 formats** | Table, JSON, SARIF, PDF, Excel |
| **Performance** | Go-based | **Rust-based** | Higher performance, memory safety |
| **AST Analysis** | ✅ Supported | ✅ **Tree-sitter** | Deep semantic analysis |
| **Open Source** | CLI only | ✅ **Fully Open** | Complete source code available |
| **Compliance Focus** | General | **Industry-Specific** | HIPAA, PCI-DSS, SCADA standards |

**DeVAIC Advantages:**
- 🏭 **Industrial Control Systems**: Only tool with specialized SCADA/PLC analysis
- ⚡ **Performance**: Rust-based for enterprise-scale analysis  
- 📊 **Rich Reporting**: PDF and Excel formats for stakeholder communication
- 🔓 **Fully Open Source**: Complete transparency and customization
- 🎯 **Compliance Ready**: Industry-specific regulatory support

## Architecture

DeVAIC features a modular, high-performance architecture inspired by Bearer's approach but enhanced for industrial and enterprise use:

### Core Analysis Engines
- **Privacy Engine**: Bearer-inspired PII/PHI detection with data flow analysis
- **Security Risk Engine**: Comprehensive OWASP-based security risk assessment
- **Vulnerability Scanner**: CWE Top 25 and language-specific vulnerability detection
- **Industrial Security Engine**: Specialized SCADA and embedded systems analysis

### Language Processing Layer
- **AST Parsers**: Tree-sitter integration for C/C++, Java, JavaScript, TypeScript, Python, Rust
- **SCADA Parser**: Custom parsing for Structured Text, SCL, FBD, and other industrial languages
- **Semantic Analysis**: Deep code understanding beyond pattern matching

### Pattern Matching & Rules
- **Semgrep Integration**: Advanced pattern matching with metavariable support
- **Rule Engine**: 500+ rules covering OWASP Top 10, CWE Top 25, privacy risks
- **Custom Rules**: Extensible YAML-based rule definitions
- **Language-Specific Rules**: Tailored detection for each programming language

### Enterprise Reporting
- **Multi-Format Output**: Table, JSON, SARIF, PDF, Excel
- **Compliance Reports**: HIPAA, PCI-DSS, SOX-ready documentation  
- **Executive Dashboards**: Excel reports with charts and metrics
- **CI/CD Integration**: SARIF output for GitHub Advanced Security

## Contributing

1. Fork the repository
2. Create a feature branch
3. Add tests for new functionality
4. Ensure all tests pass
5. Submit a pull request

## License

MIT License - see LICENSE file for details.

## References & Acknowledgments

### Academic Research
- Domenico Cotroneo, Roberta De Luca, and Pietro Liguori
- Information and Software Technology journal
- Original DeVAIC repository: https://github.com/dessertlab/DeVAIC

### Industry Inspiration
- **Bearer**: Privacy and security risk detection methodology ([Bearer.com](https://bearer.com))
- **OWASP**: Top 10 Web Application Security Risks and LLM Security
- **CWE**: Common Weakness Enumeration Top 25 Most Dangerous Software Weaknesses
- **NIST**: Cybersecurity Framework and Industrial Control Systems guidance

### Open Source Community
- **Tree-sitter**: Incremental parsing system for syntax highlighting and code analysis
- **Semgrep**: Static analysis framework for custom rule development
- **Rust Security**: Memory-safe systems programming community

## License

MIT License - see LICENSE file for details.

## Support & Community

- 📖 **Documentation**: [Full documentation and examples](USAGE.md)
- 🐛 **Issues**: [Report bugs and request features](https://github.com/dessertlab/DeVAIC/issues)
- 💬 **Discussions**: [Community discussions and support](https://github.com/dessertlab/DeVAIC/discussions)
- 🚀 **Contributing**: [Contribution guidelines](CONTRIBUTING.md)

---

**DeVAIC**: Enterprise-grade security analysis with Bearer-inspired privacy detection for modern applications and critical infrastructure. Built with ❤️ in Rust.