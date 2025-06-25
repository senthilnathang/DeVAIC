# DeVAIC - Vulnerability Analysis for Industrial Control Systems

A high-performance static code analyzer for vulnerability detection in C, C++, Java, JavaScript, TypeScript, Python, Rust, and SCADA programming languages, built in Rust.

DeVAIC provides comprehensive security analysis specifically designed for industrial control systems, embedded devices, and critical infrastructure code. It combines traditional vulnerability detection patterns with specialized rules for SCADA/PLC programming languages.

## Features

- **Multi-language Support**: Analyzes C, C++, Java, JavaScript, TypeScript, Python, Rust, and SCADA (Structured Text) code
- **Comprehensive Vulnerability Detection**: Covers OWASP Top 10, OWASP LLM Top 10, secrets detection, and industrial control system specific vulnerabilities
- **Advanced Pattern Matching**: Integrated Semgrep engine for sophisticated vulnerability detection
- **AST-based Analysis**: Abstract Syntax Tree parsing for deep code understanding
- **LLM Security**: Specialized rules for AI/ML application security (OWASP LLM Top 10)
- **Multiple Output Formats**: Table, JSON, SARIF, PDF, and Excel formats
- **Configurable Rules**: Customizable severity thresholds and rule categories
- **Fast Analysis**: Built with Rust for high performance
- **Industrial Focus**: Specialized rules for SCADA and embedded systems security
- **Secrets Detection**: Advanced patterns for API tokens, credentials, and hardcoded secrets across all languages

## Supported Vulnerability Categories

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

```bash
# Analyze a single file
devaic path/to/your/file.c

# Analyze a directory with JSON output
devaic --format json --output report.json ./src/

# Analyze only high-severity vulnerabilities
devaic --severity high ./embedded-project/

# Focus on specific vulnerability categories
devaic --categories "injection,authentication" ./python-app/
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
    "validation"
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

## Examples

### Analyzing a C Project

```bash
devaic --format table --severity medium ./embedded-project/
```

### Analyzing Python Code with JSON Output

```bash
devaic --format json --categories "injection,deserialization" ./python-app/ --output security-report.json
```

### Generating PDF Report

```bash
devaic --format pdf --output comprehensive-security-report.pdf ./enterprise-application/
```

### Creating Excel Report for Management

```bash
devaic --format excel --severity medium --output security-analysis.xlsx ./critical-infrastructure/
```

### SCADA Analysis

```bash
devaic --format table --verbose ./scada-programs/
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

## Architecture

DeVAIC is built with a modular architecture:

- **Parser Layer**: Language-specific parsers using tree-sitter for AST generation (C/C++, Java, JavaScript, TypeScript, Python, Rust) and custom regex-based parsing for SCADA
- **Semgrep Engine**: Advanced pattern matching engine for sophisticated vulnerability detection with metavariable support
- **Analysis Engine**: Multi-layered vulnerability detection combining regex patterns, AST analysis, and semantic rules
- **Rule Engine**: Configurable rules supporting OWASP Top 10, OWASP LLM Top 10, and language-specific vulnerabilities
- **Reporting**: Multiple output formats (Table, JSON, SARIF) with detailed vulnerability information and fix suggestions

## Contributing

1. Fork the repository
2. Create a feature branch
3. Add tests for new functionality
4. Ensure all tests pass
5. Submit a pull request

## License

MIT License - see LICENSE file for details.

## References

Based on research from:
- Domenico Cotroneo, Roberta De Luca, and Pietro Liguori
- Information and Software Technology journal
- Original DeVAIC repository: https://github.com/dessertlab/DeVAIC

## Acknowledgments

This tool is inspired by the original DeVAIC project and extends it to support industrial control systems and embedded programming languages.