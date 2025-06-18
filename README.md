# DeVAIC - Vulnerability Analysis for Industrial Control Systems

A high-performance static code analyzer for vulnerability detection in embedded C, Python, and SCADA programming languages, built in Rust.

DeVAIC provides comprehensive security analysis specifically designed for industrial control systems, embedded devices, and critical infrastructure code. It combines traditional vulnerability detection patterns with specialized rules for SCADA/PLC programming languages.

## Features

- **Multi-language Support**: Analyzes C, Python, and SCADA (Structured Text) code
- **Comprehensive Vulnerability Detection**: Covers OWASP Top 10 and industrial control system specific vulnerabilities
- **Multiple Output Formats**: Table, JSON, and SARIF formats
- **Configurable Rules**: Customizable severity thresholds and rule categories
- **Fast Analysis**: Built with Rust for high performance
- **Industrial Focus**: Specialized rules for SCADA and embedded systems security

## Supported Vulnerability Categories

### C Language
- Buffer overflow vulnerabilities
- Format string vulnerabilities
- Integer overflow detection
- Null pointer dereference
- Unsafe function usage

### Python Language
- Hardcoded secrets and credentials
- SQL injection vulnerabilities
- Command injection
- Unsafe deserialization (pickle, yaml)
- Weak cryptographic algorithms
- Debug mode detection
- Insecure random number generation

### SCADA Languages
- Hardcoded credentials
- Insecure communication protocols
- Unsafe memory operations
- Lack of input validation
- Weak authentication configurations
- Safety-critical operation validation
- Timing vulnerabilities
- Default configuration detection

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
  -f, --format <FORMAT>           Output format [default: table] [possible values: table, json, sarif]
  -o, --output <OUTPUT>           Output file (if not specified, prints to stdout)
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

- **C/C++**: `.c`, `.h`
- **Python**: `.py`
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

1. Add rule patterns to the appropriate rule file (`src/rules/c_rules.rs`, `src/rules/python_rules.rs`, or `src/rules/scada_rules.rs`)
2. Implement the detection logic
3. Add tests for the new rule
4. Update documentation

## Architecture

DeVAIC is built with a modular architecture:

- **Parser Layer**: Language-specific parsers using tree-sitter for C/Python and custom regex-based parsing for SCADA
- **Analysis Engine**: Core vulnerability detection logic
- **Rule Engine**: Configurable rules for different vulnerability categories
- **Reporting**: Multiple output formats with detailed vulnerability information

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