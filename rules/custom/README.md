# Custom Rules Directory

This directory contains custom security rules that can be loaded by DeVAIC for organization-specific or project-specific security analysis.

## Usage

```bash
# Load custom rules from this directory
devaic /path/to/code --custom-rules-dir rules/custom

# Specify in configuration (Cargo.toml)
custom_rules_directory = "rules/custom"
```

## Rule Format

Custom rules should be in YAML format following the DeVAIC rule schema. Example:

```yaml
name: "Custom Security Rules"
version: "1.0.0" 
rules:
  - id: "CUSTOM-001"
    name: "Hardcoded Secret"
    description: "Detects hardcoded secrets in code"
    severity: "High"
    category: "secrets"
    languages: ["python", "javascript"]
    pattern_type: "Regex"
    patterns:
      - 'secret\s*=\s*["''][^"'']{10,}["'']'
```

## Directory Structure

Place your custom rule files in this directory:
- `security-rules.yml` - General security rules
- `privacy-rules.yml` - Privacy-specific rules  
- `compliance-rules.yml` - Compliance-specific rules
- Or organize by project/team as needed

The analyzer will automatically load all `.yml` and `.yaml` files from this directory.