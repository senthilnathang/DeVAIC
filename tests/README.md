# Tests Directory

This directory contains test files and testing utilities for DeVAIC.

## Structure

- `samples/` - Sample vulnerable code files for testing
- `integration/` - Integration test files and data

## Sample Files (`samples/`)

- `test_java_vulnerable.java` - Java file with various vulnerability patterns for testing

## Integration Tests (`integration/`)

Integration tests and test data will be placed here.

## Test Files Directory

The main test files are located in the root `test_files/` directory, which contains:
- Sample code files in various languages
- Nested directory structures for testing directory traversal
- Vulnerable code patterns for security testing

## Running Tests

```bash
# Run DeVAIC on test samples
devaic tests/samples/

# Run on main test files
devaic test_files/

# Test specific vulnerabilities
devaic tests/samples/test_java_vulnerable.java
```

## Adding New Test Files

When adding new test files:
1. Place language-specific samples in `samples/`
2. Use descriptive filenames that indicate the type of vulnerabilities
3. Include comments in the code explaining what vulnerabilities should be detected
4. Update test documentation when adding new patterns