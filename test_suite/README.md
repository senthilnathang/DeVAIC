# DeVAIC Test Suite

This directory contains all test files and testing resources for the DeVAIC security analyzer, organized into logical categories for better maintainability and clarity.

## 📁 Directory Structure

### `unit/` - Unit Tests
- **Purpose**: Rust unit tests for core functionality
- **Files**: `*.rs` test files for individual components
- **Coverage**: Analyzer, parsers, rule engines, configuration
- **Usage**: `cargo test`

### `integration/` - Integration Tests  
- **Purpose**: End-to-end testing of complete workflows
- **Files**: Complex test scenarios across multiple components
- **Coverage**: Full analysis pipelines, multi-language support
- **Usage**: `cargo test --test integration_test`

### `samples/` - Sample Vulnerable Files
- **Purpose**: Representative vulnerable code samples for testing
- **Languages**: Python, JavaScript, Java, C/C++, Go, Rust, etc.
- **Coverage**: Common vulnerability patterns (CWE mappings)
- **Usage**: Manual testing and validation

### `performance/` - Large-Scale Performance Tests
- **Purpose**: Performance benchmarking with large codebases
- **Structure**: Realistic project directory structures
- **Files**: Generated test files in various languages
- **Usage**: Performance regression testing, scalability validation

### `vscode_extension/` - VS Code Extension Tests
- **Purpose**: Test files specifically for VS Code extension validation
- **Files**: Vulnerable samples with known expected results
- **Coverage**: Real-time linting, hover providers, code actions
- **Usage**: Manual VS Code extension testing

## 🧪 Test Categories

### Security Vulnerability Tests
- **SQL Injection** (CWE-89)
- **Command Injection** (CWE-78)
- **Cross-Site Scripting** (CWE-79)
- **Hardcoded Credentials** (CWE-798)
- **Buffer Overflow** (CWE-120)
- **Weak Cryptography** (CWE-327)
- **Unsafe Deserialization** (CWE-502)
- **And 200+ other CWE patterns**

### Language Coverage
- **Compiled**: C, C++, Rust, Go, Java, C#, Kotlin, Swift
- **Interpreted**: Python, JavaScript, TypeScript, PHP, Ruby
- **Domain-Specific**: SCADA, Pascal, COBOL, Dart
- **Configuration**: YAML rule patterns

### Performance Test Scenarios
- **Small Projects**: < 1,000 files
- **Medium Projects**: 1,000 - 10,000 files  
- **Large Projects**: 10,000+ files
- **Enterprise Scale**: Complex directory structures

## 🚀 Running Tests

### Unit Tests
```bash
# Run all unit tests
cargo test

# Run specific test module
cargo test test_analyzer

# Run with verbose output
cargo test -- --nocapture
```

### Integration Tests
```bash
# Run integration tests
cargo test --test integration_test

# Run advanced features tests
cargo test --test advanced_features_test
```

### Performance Tests
```bash
# Run performance benchmarks
./scripts/performance/performance_test.py

# Quick performance test
./scripts/performance/quick_perf_test.py

# Full performance report
./scripts/performance/final_performance_report.py
```

### VS Code Extension Tests
```bash
# Build and test extension
cd ide_extensions/vscode
./build.sh

# Manual testing with sample files
code test_suite/vscode_extension/vulnerable_sample.js
```

## 📊 Test Metrics

### Coverage Goals
- **Code Coverage**: > 85%
- **Vulnerability Detection**: > 95% for known patterns
- **False Positive Rate**: < 5%
- **Performance**: < 100ms per file (typical)

### Validation Criteria
- ✅ All unit tests pass
- ✅ Integration tests cover end-to-end workflows
- ✅ Performance tests meet benchmarks
- ✅ Sample files detect expected vulnerabilities
- ✅ VS Code extension demonstrates real-time linting

## 🔧 Adding New Tests

### Unit Tests
1. Add test functions to existing `*.rs` files in `unit/`
2. Follow naming convention: `test_function_name`
3. Use descriptive assertions and error messages
4. Include both positive and negative test cases

### Sample Files
1. Add vulnerable code samples to `samples/`
2. Include comments describing expected vulnerabilities
3. Cover multiple CWE categories per file
4. Ensure realistic code patterns

### Performance Tests
1. Add test scenarios to `performance/` with realistic directory structures
2. Include various file sizes and complexity levels
3. Document expected performance benchmarks
4. Test memory usage and analysis speed

## 📝 Test Documentation

Each test category includes:
- **README.md**: Specific documentation for the test type
- **Expected Results**: Known vulnerability counts and types
- **Usage Instructions**: How to run and interpret tests
- **Maintenance Notes**: How to update and extend tests

## 🔄 Continuous Integration

Tests are automatically run on:
- Pull requests to main branch
- Nightly performance regression testing
- Release candidate validation
- Multi-platform compatibility checks

## 🐛 Troubleshooting

### Common Issues
- **Missing Dependencies**: Run `cargo build` first
- **Path Issues**: Ensure working directory is project root
- **Permission Issues**: Check file permissions on test files
- **Performance Variance**: Run tests multiple times for stability

### Test Failures
1. Check error messages and stack traces
2. Verify test file integrity and expected results
3. Run individual tests to isolate issues
4. Check system resources and environment

---

**Test Suite Version**: 1.0.0  
**Last Updated**: $(date)  
**Total Test Files**: 500+ across all categories  
**Vulnerability Patterns**: 200+ CWE mappings covered