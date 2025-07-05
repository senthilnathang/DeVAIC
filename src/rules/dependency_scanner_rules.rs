use crate::{
    error::Result,
    parsers::{ParsedAst, SourceFile},
    rules::{create_vulnerability, RuleSet},
    Severity, Vulnerability,
};
use regex::Regex;
use std::collections::HashMap;

pub struct DependencyScannerRules {
    vulnerable_packages: HashMap<String, VulnerablePackage>,
    package_patterns: Vec<PackagePattern>,
}

#[derive(Clone)]
struct VulnerablePackage {
    name: String,
    vulnerable_versions: Vec<String>,
    severity: Severity,
    cve: String,
    description: String,
    recommendation: String,
}

#[derive(Clone)]
struct PackagePattern {
    id: String,
    name: String,
    pattern: Regex,
    file_patterns: Vec<String>,
    category: String,
    severity: Severity,
    description: String,
    recommendation: String,
    languages: Vec<String>,
}

impl DependencyScannerRules {
    pub fn new() -> Self {
        let mut vulnerable_packages = HashMap::new();
        let mut package_patterns = Vec::new();

        // Known vulnerable packages inspired by sast-scan patterns
        vulnerable_packages.insert("requests".to_string(), VulnerablePackage {
            name: "requests".to_string(),
            vulnerable_versions: vec!["2.0.0".to_string(), "2.1.0".to_string(), "2.2.0".to_string()],
            severity: Severity::Medium,
            cve: "CVE-2023-32681".to_string(),
            description: "Vulnerable version of requests library".to_string(),
            recommendation: "Update to requests >= 2.31.0".to_string(),
        });

        vulnerable_packages.insert("jackson-databind".to_string(), VulnerablePackage {
            name: "jackson-databind".to_string(),
            vulnerable_versions: vec!["2.9.0".to_string(), "2.9.1".to_string(), "2.9.2".to_string()],
            severity: Severity::Critical,
            cve: "CVE-2020-36518".to_string(),
            description: "Jackson Databind deserialization vulnerability".to_string(),
            recommendation: "Update to jackson-databind >= 2.12.7.1".to_string(),
        });

        vulnerable_packages.insert("lodash".to_string(), VulnerablePackage {
            name: "lodash".to_string(),
            vulnerable_versions: vec!["4.17.0".to_string(), "4.17.1".to_string(), "4.17.15".to_string()],
            severity: Severity::High,
            cve: "CVE-2021-23337".to_string(),
            description: "Lodash prototype pollution vulnerability".to_string(),
            recommendation: "Update to lodash >= 4.17.21".to_string(),
        });

        vulnerable_packages.insert("log4j-core".to_string(), VulnerablePackage {
            name: "log4j-core".to_string(),
            vulnerable_versions: vec!["2.0.0".to_string(), "2.14.1".to_string(), "2.15.0".to_string()],
            severity: Severity::Critical,
            cve: "CVE-2021-44228".to_string(),
            description: "Log4j remote code execution vulnerability".to_string(),
            recommendation: "Update to log4j-core >= 2.17.1".to_string(),
        });

        // Package detection patterns
        package_patterns.extend(vec![
            // Python packages
            PackagePattern {
                id: "python-requirements-scan".to_string(),
                name: "Python Requirements Vulnerability".to_string(),
                pattern: Regex::new(r"(?i)(requests|django|flask|tornado|pillow|pyyaml)\s*==\s*([0-9]+\.[0-9]+\.[0-9]+)").unwrap(),
                file_patterns: vec!["requirements.txt".to_string(), "setup.py".to_string(), "pyproject.toml".to_string()],
                category: "dependency".to_string(),
                severity: Severity::Medium,
                description: "Potentially vulnerable Python package version detected".to_string(),
                recommendation: "Check for known vulnerabilities and update to latest secure version".to_string(),
                languages: vec!["python".to_string()],
            },
            // Node.js packages
            PackagePattern {
                id: "nodejs-package-scan".to_string(),
                name: "Node.js Package Vulnerability".to_string(),
                pattern: Regex::new(r#""(lodash|moment|axios|express|socket\.io)"\s*:\s*"([0-9]+\.[0-9]+\.[0-9]+)""#).unwrap(),
                file_patterns: vec!["package.json".to_string(), "package-lock.json".to_string()],
                category: "dependency".to_string(),
                severity: Severity::Medium,
                description: "Potentially vulnerable Node.js package version detected".to_string(),
                recommendation: "Run npm audit and update vulnerable packages".to_string(),
                languages: vec!["javascript".to_string(), "typescript".to_string()],
            },
            // Java dependencies
            PackagePattern {
                id: "java-maven-scan".to_string(),
                name: "Maven Dependency Vulnerability".to_string(),
                pattern: Regex::new(r"(?i)<artifactId>(jackson-databind|log4j-core|struts2-core|spring-core)</artifactId>").unwrap(),
                file_patterns: vec!["pom.xml".to_string()],
                category: "dependency".to_string(),
                severity: Severity::High,
                description: "Potentially vulnerable Java Maven dependency detected".to_string(),
                recommendation: "Check Maven dependency versions and update to secure versions".to_string(),
                languages: vec!["java".to_string()],
            },
            // Gradle dependencies
            PackagePattern {
                id: "java-gradle-scan".to_string(),
                name: "Gradle Dependency Vulnerability".to_string(),
                pattern: Regex::new(r"(?i)(jackson-databind|log4j-core|struts|spring):[0-9]+\.[0-9]+\.[0-9]+").unwrap(),
                file_patterns: vec!["build.gradle".to_string(), "build.gradle.kts".to_string()],
                category: "dependency".to_string(),
                severity: Severity::High,
                description: "Potentially vulnerable Java Gradle dependency detected".to_string(),
                recommendation: "Check Gradle dependency versions and update to secure versions".to_string(),
                languages: vec!["java".to_string(), "kotlin".to_string()],
            },
            // Ruby gems
            PackagePattern {
                id: "ruby-gemfile-scan".to_string(),
                name: "Ruby Gem Vulnerability".to_string(),
                pattern: Regex::new(r#"gem\s+['"]+(rails|devise|nokogiri|rack)['"]+"#).unwrap(),
                file_patterns: vec!["Gemfile".to_string(), "Gemfile.lock".to_string()],
                category: "dependency".to_string(),
                severity: Severity::Medium,
                description: "Potentially vulnerable Ruby gem detected".to_string(),
                recommendation: "Run bundle audit and update vulnerable gems".to_string(),
                languages: vec!["ruby".to_string()],
            },
            // Go modules
            PackagePattern {
                id: "go-module-scan".to_string(),
                name: "Go Module Vulnerability".to_string(),
                pattern: Regex::new(r"(?i)(github\.com/gin-gonic/gin|github\.com/gorilla/mux|github\.com/labstack/echo)\s+v[0-9]+\.[0-9]+\.[0-9]+").unwrap(),
                file_patterns: vec!["go.mod".to_string(), "go.sum".to_string()],
                category: "dependency".to_string(),
                severity: Severity::Medium,
                description: "Potentially vulnerable Go module detected".to_string(),
                recommendation: "Run go mod audit and update vulnerable modules".to_string(),
                languages: vec!["go".to_string()],
            },
            // Docker base images
            PackagePattern {
                id: "docker-base-image-scan".to_string(),
                name: "Vulnerable Docker Base Image".to_string(),
                pattern: Regex::new(r"(?i)FROM\s+(ubuntu:16\.04|centos:7|alpine:3\.8|node:10|python:2\.7)").unwrap(),
                file_patterns: vec!["Dockerfile".to_string(), "*.dockerfile".to_string()],
                category: "dependency".to_string(),
                severity: Severity::High,
                description: "Potentially vulnerable Docker base image detected".to_string(),
                recommendation: "Use updated base images with security patches".to_string(),
                languages: vec!["dockerfile".to_string()],
            },
            // Composer dependencies (PHP)
            PackagePattern {
                id: "php-composer-scan".to_string(),
                name: "PHP Composer Vulnerability".to_string(),
                pattern: Regex::new(r#""(symfony/symfony|laravel/framework|monolog/monolog)"\s*:\s*"[0-9]+\.[0-9]+\.[0-9]+""#).unwrap(),
                file_patterns: vec!["composer.json".to_string(), "composer.lock".to_string()],
                category: "dependency".to_string(),
                severity: Severity::Medium,
                description: "Potentially vulnerable PHP Composer package detected".to_string(),
                recommendation: "Run composer audit and update vulnerable packages".to_string(),
                languages: vec!["php".to_string()],
            },
            // Cargo dependencies (Rust)
            PackagePattern {
                id: "rust-cargo-scan".to_string(),
                name: "Rust Cargo Vulnerability".to_string(),
                pattern: Regex::new(r#"(serde|tokio|reqwest|actix-web)\s*=\s*"[0-9]+\.[0-9]+\.[0-9]+""#).unwrap(),
                file_patterns: vec!["Cargo.toml".to_string(), "Cargo.lock".to_string()],
                category: "dependency".to_string(),
                severity: Severity::Medium,
                description: "Potentially vulnerable Rust crate detected".to_string(),
                recommendation: "Run cargo audit and update vulnerable crates".to_string(),
                languages: vec!["rust".to_string()],
            },
        ]);

        Self {
            vulnerable_packages,
            package_patterns,
        }
    }

    fn check_vulnerable_packages(&self, source_file: &SourceFile) -> Result<Vec<Vulnerability>> {
        let mut vulnerabilities = Vec::new();
        let lines: Vec<&str> = source_file.content.lines().collect();
        
        // Check for known vulnerable package versions
        for (line_index, line) in lines.iter().enumerate() {
            for (package_name, vulnerable_package) in &self.vulnerable_packages {
                for vulnerable_version in &vulnerable_package.vulnerable_versions {
                    let version_pattern = format!(r"(?i){}.*{}", package_name, vulnerable_version);
                    if let Ok(regex) = Regex::new(&version_pattern) {
                        if regex.is_match(line) {
                            let vulnerability = create_vulnerability(
                                &format!("dep-{}-{}", package_name, vulnerable_version),
                                Some(&vulnerable_package.cve),
                                &format!("Vulnerable Dependency: {}", vulnerable_package.name),
                                vulnerable_package.severity.clone(),
                                "dependency",
                                &vulnerable_package.description,
                                &source_file.path.to_string_lossy(),
                                line_index + 1,
                                0,
                                line.trim(),
                                &vulnerable_package.recommendation,
                            );
                            vulnerabilities.push(vulnerability);
                        }
                    }
                }
            }
        }

        Ok(vulnerabilities)
    }

    fn check_package_patterns(&self, source_file: &SourceFile) -> Result<Vec<Vulnerability>> {
        let mut vulnerabilities = Vec::new();
        let lines: Vec<&str> = source_file.content.lines().collect();
        let file_name = source_file.path.file_name()
            .and_then(|name| name.to_str())
            .unwrap_or("");

        for pattern in &self.package_patterns {
            // Check if this pattern applies to this file type
            if !pattern.file_patterns.iter().any(|file_pattern| {
                if file_pattern.contains('*') {
                    let pattern_regex = file_pattern.replace("*", ".*");
                    if let Ok(regex) = Regex::new(&pattern_regex) {
                        regex.is_match(file_name)
                    } else {
                        false
                    }
                } else {
                    file_name == file_pattern
                }
            }) {
                continue;
            }

            for (line_index, line) in lines.iter().enumerate() {
                if let Some(captures) = pattern.pattern.captures(line) {
                    if let Some(matched) = captures.get(0) {
                        let vulnerability = create_vulnerability(
                            &pattern.id,
                            None,
                            &pattern.name,
                            pattern.severity.clone(),
                            &pattern.category,
                            &pattern.description,
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

impl RuleSet for DependencyScannerRules {
    fn analyze(&self, source_file: &SourceFile, _ast: &ParsedAst) -> Result<Vec<Vulnerability>> {
        let mut vulnerabilities = Vec::new();

        // Check for known vulnerable packages
        vulnerabilities.extend(self.check_vulnerable_packages(source_file)?);

        // Check package patterns
        vulnerabilities.extend(self.check_package_patterns(source_file)?);

        Ok(vulnerabilities)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{Language, parsers::SourceFile};
    use std::path::PathBuf;

    #[test]
    fn test_python_requirements_scan() {
        let rules = DependencyScannerRules::new();
        let source = SourceFile::new(
            PathBuf::from("requirements.txt"),
            "requests==2.0.0\ndjango==3.2.0".to_string(),
            Language::Python,
        );
        let ast = crate::parsers::ParsedAst::new_source_only(source.content.clone());
        let vulnerabilities = rules.analyze(&source, &ast).unwrap();
        assert!(!vulnerabilities.is_empty());
    }

    #[test]
    fn test_nodejs_package_scan() {
        let rules = DependencyScannerRules::new();
        let source = SourceFile::new(
            PathBuf::from("package.json"),
            r#"{"dependencies": {"lodash": "4.17.0"}}"#.to_string(),
            Language::Javascript,
        );
        let ast = crate::parsers::ParsedAst::new_source_only(source.content.clone());
        let vulnerabilities = rules.analyze(&source, &ast).unwrap();
        assert!(!vulnerabilities.is_empty());
    }

    #[test]
    fn test_vulnerable_docker_image() {
        let rules = DependencyScannerRules::new();
        let source = SourceFile::new(
            PathBuf::from("Dockerfile"),
            "FROM ubuntu:16.04".to_string(),
            Language::Javascript, // Using Javascript as we don't have Dockerfile language
        );
        let ast = crate::parsers::ParsedAst::new_source_only(source.content.clone());
        let vulnerabilities = rules.analyze(&source, &ast).unwrap();
        assert!(!vulnerabilities.is_empty());
    }
}