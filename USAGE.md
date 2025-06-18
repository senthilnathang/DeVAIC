# DeVAIC Usage Guide

This comprehensive guide covers all aspects of using DeVAIC (Vulnerability Analysis for Industrial Control Systems) - a high-performance static code analyzer for detecting vulnerabilities in C, Python, and SCADA programming languages.

## Table of Contents

1. [Quick Start](#quick-start)
2. [Command Line Interface](#command-line-interface)
3. [Configuration](#configuration)
4. [Output Formats](#output-formats)
5. [Language-Specific Analysis](#language-specific-analysis)
6. [Advanced Usage](#advanced-usage)
7. [CI/CD Integration](#cicd-integration)
8. [Rule Management](#rule-management)
9. [Examples](#examples)
10. [Troubleshooting](#troubleshooting)

## Quick Start

### Basic Analysis

Analyze a single file:
```bash
devaic path/to/file.c
```

Analyze a directory:
```bash
devaic ./src/
```

### Common Options

Generate JSON report:
```bash
devaic --format json --output report.json ./project/
```

Filter by severity:
```bash
devaic --severity high ./critical-code/
```

Enable verbose output:
```bash
devaic --verbose ./project/
```

## Command Line Interface

### Basic Syntax
```
devaic [OPTIONS] <PATH>
```

### Arguments

- `<PATH>` - Target directory or file to analyze (required)

### Options

#### Output Control
- `-f, --format <FORMAT>` - Output format: `table` (default), `json`, `sarif`
- `-o, --output <OUTPUT>` - Output file path (stdout if not specified)
- `--no-color` - Disable colored output
- `-v, --verbose` - Enable detailed output

#### Analysis Control
- `-s, --severity <SEVERITY>` - Minimum severity threshold: `critical`, `high`, `medium`, `low` (default), `info`
- `--categories <CATEGORIES>` - Comma-separated vulnerability categories to analyze
- `--max-file-size <SIZE>` - Maximum file size in bytes (default: 10485760 = 10MB)

#### Configuration
- `-c, --config <CONFIG>` - Custom configuration file path

#### Help
- `-h, --help` - Show help information
- `-V, --version` - Show version information

### Exit Codes

- `0` - Analysis completed successfully, no critical/high severity vulnerabilities found
- `1` - Critical or high severity vulnerabilities detected
- `2` - Error occurred during analysis

## Configuration

### Configuration File

DeVAIC uses a TOML configuration file (`devaic.toml`) for customization:

```toml
[rules]
# Categories of vulnerabilities to analyze
enabled_categories = [
    "injection",
    "authentication",
    "authorization", 
    "cryptographic",
    "deserialization",
    "logging",
    "validation"
]

# Minimum severity level to report
severity_threshold = "LOW"

# Custom rule overrides
[rules.custom_rules]
# "C001" = false  # Disable specific rule

[output]
format = "table"        # table, json, sarif
verbose = false
colors = true

[analysis]
max_file_size = 10485760  # 10MB

# File patterns to exclude
exclude_patterns = [
    "*.git/*",
    "target/*",
    "build/*",
    "node_modules/*",
    "*.min.js",
    "vendor/*"
]

# File patterns to include
include_patterns = [
    "*.c", "*.h", "*.cpp", "*.hpp",  # C/C++
    "*.py",                          # Python
    "*.st", "*.scl", "*.fbd", "*.ld", "*.il"  # SCADA
]

follow_symlinks = false
```

### Configuration Priority

Configuration is loaded in this order (later overrides earlier):
1. Default built-in configuration
2. System-wide configuration (`/etc/devaic/devaic.toml`)
3. User configuration (`~/.config/devaic/devaic.toml`)
4. Project configuration (`./devaic.toml`)
5. Command-line arguments

### Environment Variables

- `DEVAIC_CONFIG` - Path to configuration file
- `DEVAIC_LOG_LEVEL` - Log level: `error`, `warn`, `info`, `debug`, `trace`
- `NO_COLOR` - Disable colored output (any non-empty value)

## Output Formats

### Table Format (Default)

Human-readable table with syntax highlighting:

```
┌─────────┬──────────┬─────────────────┬─────────────────────────────────────┬──────────────┬──────┐
│ ID      │ Severity │ Category        │ Description                         │ File         │ Line │
├─────────┼──────────┼─────────────────┼─────────────────────────────────────┼──────────────┼──────┤
│ PY001   │ Critical │ authentication  │ Hardcoded secret detected           │ vulnerable.py│ 9    │
│ PY002   │ High     │ injection       │ SQL injection vulnerability         │ vulnerable.py│ 18   │
└─────────┴──────────┴─────────────────┴─────────────────────────────────────┴──────────────┴──────┘
```

### JSON Format

Machine-readable format for integration:

```json
{
  "summary": {
    "total_vulnerabilities": 15,
    "by_severity": {
      "CRITICAL": 7,
      "HIGH": 5,
      "MEDIUM": 3
    },
    "by_category": {
      "injection": 4,
      "authentication": 4,
      "cryptographic": 5,
      "deserialization": 1,
      "logging": 1
    },
    "by_language": {
      "Python": 15
    }
  },
  "vulnerabilities": [
    {
      "id": "PY001",
      "severity": "Critical",
      "category": "authentication",
      "description": "Hardcoded secret or credential detected",
      "file_path": "examples/vulnerable.py",
      "line_number": 9,
      "column": 0,
      "source_code": "API_KEY = \"sk-1234567890abcdef1234567890abcdef\"",
      "recommendation": "Use environment variables or secure credential management systems"
    }
  ],
  "files_analyzed": 1,
  "analysis_duration": {
    "secs": 0,
    "nanos": 11933408
  }
}
```

### SARIF Format

Static Analysis Results Interchange Format for IDE and tool integration:

```bash
devaic --format sarif --output report.sarif ./src/
```

SARIF files can be imported into:
- GitHub Security tab
- Visual Studio Code
- IntelliJ IDEA
- SonarQube
- Other SARIF-compatible tools

## Language-Specific Analysis

### C/C++ Analysis

**Supported Extensions:** `.c`, `.h`, `.cpp`, `.hpp`

**Vulnerability Categories:**
- Buffer overflow vulnerabilities
- Format string vulnerabilities
- Integer overflow detection
- Null pointer dereference
- Unsafe function usage

**Example:**
```bash
devaic --categories "validation,cryptographic" ./embedded-project/
```

### Python Analysis

**Supported Extensions:** `.py`

**Vulnerability Categories:**
- Hardcoded secrets and credentials
- SQL injection vulnerabilities
- Command injection
- Unsafe deserialization (pickle, yaml)
- Weak cryptographic algorithms
- Debug mode detection
- Insecure random number generation

**Example:**
```bash
devaic --format json --categories "injection,deserialization" ./python-app/
```

### SCADA Analysis

**Supported Extensions:** `.st` (Structured Text), `.scl` (Sequential Control Language), `.fbd` (Function Block Diagram), `.ld` (Ladder Diagram), `.il` (Instruction List)

**Vulnerability Categories:**
- Hardcoded credentials
- Insecure communication protocols
- Unsafe memory operations
- Lack of input validation
- Weak authentication configurations
- Safety-critical operation validation
- Timing vulnerabilities
- Default configuration detection

**Example:**
```bash
devaic --severity medium --verbose ./scada-programs/
```

## Advanced Usage

### Filtering Analysis

**By Severity:**
```bash
# Only critical and high severity
devaic --severity high ./src/

# All severities (default)
devaic --severity info ./src/
```

**By Categories:**
```bash
# Specific categories only
devaic --categories "injection,authentication,cryptographic" ./src/

# Multiple categories
devaic --categories "injection,deserialization" ./python-code/
```

**By File Size:**
```bash
# Analyze files up to 5MB
devaic --max-file-size 5242880 ./large-project/
```

### Batch Analysis

Analyze multiple projects:
```bash
#!/bin/bash
for project in project1 project2 project3; do
    echo "Analyzing $project..."
    devaic --format json --output "${project}-report.json" "./$project/"
done
```

### Custom Configuration per Project

Create project-specific `devaic.toml`:
```bash
cd my-project/
cat > devaic.toml << EOF
[rules]
enabled_categories = ["injection", "authentication"]
severity_threshold = "MEDIUM"

[analysis]
exclude_patterns = ["tests/*", "docs/*"]
EOF

devaic ./
```

## CI/CD Integration

### GitHub Actions

```yaml
name: Security Analysis

on: [push, pull_request]

jobs:
  security-scan:
    runs-on: ubuntu-latest
    steps:
    - uses: actions/checkout@v3
    
    - name: Install Rust
      uses: actions-rs/toolchain@v1
      with:
        toolchain: stable
    
    - name: Build DeVAIC
      run: |
        git clone https://github.com/dessertlab/DeVAIC.git
        cd DeVAIC
        cargo build --release
        sudo cp target/release/devaic /usr/local/bin/
    
    - name: Run Security Analysis
      run: |
        devaic --format sarif --output security-report.sarif ./src/
        devaic --format json --output security-report.json ./src/
    
    - name: Upload SARIF to GitHub
      uses: github/codeql-action/upload-sarif@v2
      with:
        sarif_file: security-report.sarif
    
    - name: Upload Reports
      uses: actions/upload-artifact@v3
      with:
        name: security-reports
        path: |
          security-report.sarif
          security-report.json
```

### GitLab CI

```yaml
stages:
  - security

security-scan:
  stage: security
  image: rust:latest
  script:
    - git clone https://github.com/dessertlab/DeVAIC.git
    - cd DeVAIC && cargo build --release
    - cp target/release/devaic /usr/local/bin/
    - cd $CI_PROJECT_DIR
    - devaic --format json --output security-report.json ./src/
    - devaic --severity high ./src/  # Fail on high/critical issues
  artifacts:
    reports:
      sast: security-report.json
    expire_in: 1 week
  allow_failure: false
```

### Jenkins Pipeline

```groovy
pipeline {
    agent any
    
    stages {
        stage('Security Analysis') {
            steps {
                script {
                    // Build DeVAIC
                    sh '''
                        git clone https://github.com/dessertlab/DeVAIC.git
                        cd DeVAIC
                        cargo build --release
                        sudo cp target/release/devaic /usr/local/bin/
                    '''
                    
                    // Run analysis
                    sh 'devaic --format json --output security-report.json ./src/'
                    
                    // Archive results
                    archiveArtifacts artifacts: 'security-report.json'
                    
                    // Fail build on high/critical issues
                    sh 'devaic --severity high ./src/'
                }
            }
        }
    }
}
```

## Rule Management

### Available Vulnerability Categories

1. **injection** - SQL injection, command injection, code injection
2. **authentication** - Hardcoded credentials, weak authentication
3. **authorization** - Access control issues, privilege escalation
4. **cryptographic** - Weak encryption, insecure hashing, poor randomness
5. **deserialization** - Unsafe object deserialization
6. **logging** - Information disclosure, debug mode
7. **validation** - Input validation, buffer overflows

### Rule IDs

Rules are identified by language prefix and number:
- **C001-C999** - C/C++ rules
- **PY001-PY999** - Python rules
- **SC001-SC999** - SCADA rules

### Disabling Specific Rules

In `devaic.toml`:
```toml
[rules.custom_rules]
"PY001" = false  # Disable hardcoded credentials check
"C005" = false   # Disable specific C rule
```

### Custom Severity Overrides

```toml
[rules.severity_overrides]
"PY007" = "HIGH"  # Upgrade insecure random from MEDIUM to HIGH
```

## Examples

### Example 1: Analyze Embedded C Project

```bash
# Focus on critical vulnerabilities in embedded C code
devaic --format table \
       --severity high \
       --categories "validation,cryptographic" \
       --verbose \
       ./embedded-firmware/
```

### Example 2: Python Web Application Security Scan

```bash
# Comprehensive Python security analysis
devaic --format json \
       --output webapp-security.json \
       --categories "injection,authentication,deserialization" \
       --max-file-size 5242880 \
       ./django-project/
```

### Example 3: SCADA System Analysis

```bash
# Industrial control system security scan
devaic --format sarif \
       --output scada-security.sarif \
       --severity medium \
       --verbose \
       ./plc-programs/
```

### Example 4: Multi-Language Project

```bash
# Analyze mixed C/Python project
devaic --format json \
       --output mixed-report.json \
       --categories "injection,authentication,validation" \
       ./iot-project/
```

### Example 5: Configuration-Driven Analysis

Create `security-scan.toml`:
```toml
[rules]
enabled_categories = ["injection", "cryptographic", "authentication"]
severity_threshold = "MEDIUM"

[output]
format = "json"
verbose = true

[analysis]
max_file_size = 2097152  # 2MB
exclude_patterns = ["test/*", "docs/*", "vendor/*"]
```

Run with custom config:
```bash
devaic --config security-scan.toml --output security-results.json ./src/
```

## Troubleshooting

### Common Issues

**Issue: "No vulnerabilities found" but expecting some**
```bash
# Check if files are being analyzed
devaic --verbose ./src/

# Verify file patterns in config
devaic --config ./devaic.toml --verbose ./src/

# Lower severity threshold
devaic --severity info ./src/
```

**Issue: "File too large" warnings**
```bash
# Increase file size limit
devaic --max-file-size 52428800 ./src/  # 50MB

# Or in config file
echo 'max_file_size = 52428800' >> devaic.toml
```

**Issue: Missing SARIF output in GitHub**
```bash
# Ensure correct SARIF format
devaic --format sarif --output results.sarif ./src/

# Validate SARIF file
cat results.sarif | jq .
```

### Debug Mode

Enable detailed logging:
```bash
DEVAIC_LOG_LEVEL=debug devaic --verbose ./src/
```

### Performance Issues

For large codebases:
```bash
# Exclude unnecessary directories
devaic --config devaic.toml ./large-project/

# Limit file size
devaic --max-file-size 1048576 ./large-project/  # 1MB

# Focus on specific categories
devaic --categories "injection,authentication" ./large-project/
```

### Reporting Issues

If you encounter bugs or have feature requests:

1. Check existing issues: https://github.com/dessertlab/DeVAIC/issues
2. Create a new issue with:
   - DeVAIC version (`devaic --version`)
   - Command used
   - Expected vs actual behavior
   - Sample code (if applicable)
   - System information

### Getting Help

- **Documentation**: https://github.com/dessertlab/DeVAIC
- **Issues**: https://github.com/dessertlab/DeVAIC/issues
- **Discussions**: https://github.com/dessertlab/DeVAIC/discussions

---

This usage guide covers the comprehensive functionality of DeVAIC. For the latest updates and additional examples, refer to the project repository and documentation.