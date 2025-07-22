use crate::{
    error::Result,
    parsers::{ParsedAst, SourceFile},
    rules::{create_vulnerability, RuleSet},
    Severity, Vulnerability,
};
use regex::Regex;

pub struct OwaspWebRules {
    access_control_patterns: Vec<Regex>,
    crypto_patterns: Vec<Regex>,
    injection_patterns: Vec<Regex>,
    insecure_design_patterns: Vec<Regex>,
    misconfiguration_patterns: Vec<Regex>,
    vulnerable_components_patterns: Vec<Regex>,
    auth_patterns: Vec<Regex>,
    integrity_patterns: Vec<Regex>,
    logging_patterns: Vec<Regex>,
    ssrf_patterns: Vec<Regex>,
}

impl OwaspWebRules {
    pub fn new() -> Self {
        let access_control_patterns = vec![
            Regex::new(r"(?i)(bypass|skip)[_\s]*(auth|authorization|access[_\s]*control)").unwrap(),
            Regex::new(r"(?i)(admin|root|superuser)\s*=\s*true").unwrap(),
            Regex::new(r"(?i)(force[_\s]*browse|direct[_\s]*object[_\s]*reference)").unwrap(),
            Regex::new(r"(?i)(privilege[_\s]*escalation|elevation)").unwrap(),
            Regex::new(r"(?i)(role[_\s]*based[_\s]*access|rbac)").unwrap(),
        ];

        let crypto_patterns = vec![
            Regex::new(r"(?i)(md5|sha1)\s*\(").unwrap(),
            Regex::new(r"(?i)(des|3des|rc4)").unwrap(),
            Regex::new(r"(?i)(hardcoded|hard[_\s]*coded)[_\s]*(key|password|secret)").unwrap(),
            Regex::new(r"(?i)(weak[_\s]*cipher|insecure[_\s]*algorithm)").unwrap(),
            Regex::new(r"(?i)(ssl[_\s]*v[23]|tls[_\s]*v1\.[01])").unwrap(),
            Regex::new(r"(?i)(plain[_\s]*text|cleartext)[_\s]*(password|secret)").unwrap(),
        ];

        let injection_patterns = vec![
            Regex::new(r"(?i)(sql[_\s]*injection|sqli)").unwrap(),
            Regex::new(r"(?i)(xss|cross[_\s]*site[_\s]*scripting)").unwrap(),
            Regex::new(r"(?i)(command[_\s]*injection|code[_\s]*injection)").unwrap(),
            Regex::new(r"(?i)(ldap[_\s]*injection|xpath[_\s]*injection)").unwrap(),
            Regex::new(r"(?i)(nosql[_\s]*injection|os[_\s]*injection)").unwrap(),
            Regex::new(r"(?i)(eval|exec|system)\s*\(.*\$").unwrap(),
        ];

        let insecure_design_patterns = vec![
            Regex::new(r"(?i)(security[_\s]*by[_\s]*obscurity)").unwrap(),
            Regex::new(r"(?i)(insufficient[_\s]*validation|weak[_\s]*validation)").unwrap(),
            Regex::new(r"(?i)(business[_\s]*logic[_\s]*flaw)").unwrap(),
            Regex::new(r"(?i)(race[_\s]*condition|time[_\s]*of[_\s]*check)").unwrap(),
            Regex::new(r"(?i)(threat[_\s]*model|security[_\s]*architecture)").unwrap(),
        ];

        let misconfiguration_patterns = vec![
            Regex::new(r"(?i)(default[_\s]*password|default[_\s]*credential)").unwrap(),
            Regex::new(r"(?i)(debug[_\s]*mode|debug\s*=\s*true)").unwrap(),
            Regex::new(r"(?i)(error[_\s]*disclosure|stack[_\s]*trace)").unwrap(),
            Regex::new(r"(?i)(unnecessary[_\s]*service|unused[_\s]*feature)").unwrap(),
            Regex::new(r"(?i)(cors[_\s]*misconfiguration|permissive[_\s]*cors)").unwrap(),
        ];

        let vulnerable_components_patterns = vec![
            Regex::new(r"(?i)(outdated|deprecated|legacy)[_\s]*(library|framework|component)").unwrap(),
            Regex::new(r"(?i)(known[_\s]*vulnerability|cve[_\s]*\d{4})").unwrap(),
            Regex::new(r"(?i)(unsupported[_\s]*version|end[_\s]*of[_\s]*life)").unwrap(),
            Regex::new(r"(?i)(vulnerable[_\s]*dependency|security[_\s]*patch)").unwrap(),
        ];

        let auth_patterns = vec![
            Regex::new(r"(?i)(weak[_\s]*password|password[_\s]*policy)").unwrap(),
            Regex::new(r"(?i)(session[_\s]*fixation|session[_\s]*hijacking)").unwrap(),
            Regex::new(r"(?i)(brute[_\s]*force|credential[_\s]*stuffing)").unwrap(),
            Regex::new(r"(?i)(multi[_\s]*factor|2fa|mfa)").unwrap(),
            Regex::new(r"(?i)(account[_\s]*lockout|rate[_\s]*limiting)").unwrap(),
        ];

        let integrity_patterns = vec![
            Regex::new(r"(?i)(unsigned[_\s]*code|code[_\s]*signing)").unwrap(),
            Regex::new(r"(?i)(supply[_\s]*chain|dependency[_\s]*confusion)").unwrap(),
            Regex::new(r"(?i)(integrity[_\s]*check|checksum[_\s]*verification)").unwrap(),
            Regex::new(r"(?i)(ci[_\s]*cd[_\s]*pipeline|build[_\s]*process)").unwrap(),
        ];

        let logging_patterns = vec![
            Regex::new(r"(?i)(insufficient[_\s]*logging|inadequate[_\s]*monitoring)").unwrap(),
            Regex::new(r"(?i)(log[_\s]*injection|log[_\s]*forging)").unwrap(),
            Regex::new(r"(?i)(audit[_\s]*trail|security[_\s]*event)").unwrap(),
            Regex::new(r"(?i)(alerting|incident[_\s]*response)").unwrap(),
        ];

        let ssrf_patterns = vec![
            Regex::new(r"(?i)(server[_\s]*side[_\s]*request[_\s]*forgery|ssrf)").unwrap(),
            Regex::new(r"(?i)(internal[_\s]*network|localhost|127\.0\.0\.1)").unwrap(),
            Regex::new(r"(?i)(metadata[_\s]*service|cloud[_\s]*metadata)").unwrap(),
            Regex::new(r"(?i)(url[_\s]*validation|whitelist)").unwrap(),
        ];

        Self {
            access_control_patterns,
            crypto_patterns,
            injection_patterns,
            insecure_design_patterns,
            misconfiguration_patterns,
            vulnerable_components_patterns,
            auth_patterns,
            integrity_patterns,
            logging_patterns,
            ssrf_patterns,
        }
    }

    fn check_broken_access_control(&self, content: &str, file_path: &str) -> Vec<Vulnerability> {
        let mut vulnerabilities = Vec::new();
        
        for (line_num, line) in content.lines().enumerate() {
            for pattern in &self.access_control_patterns {
                if pattern.is_match(line) {
                    vulnerabilities.push(create_vulnerability(
                        "OWASP-A01",
                        Some("CWE-284"),
                        "Broken Access Control",
                        Severity::High,
                        "web_security",
                        "Broken access control vulnerability that may allow unauthorized access to resources.",
                        file_path,
                        line_num + 1,
                        pattern.find(line).unwrap().start(),
                        line,
                        "Implement proper access controls, use principle of least privilege, and validate permissions on every request.",
                    ));
                }
            }
        }
        
        vulnerabilities
    }

    fn check_cryptographic_failures(&self, content: &str, file_path: &str) -> Vec<Vulnerability> {
        let mut vulnerabilities = Vec::new();
        
        for (line_num, line) in content.lines().enumerate() {
            for pattern in &self.crypto_patterns {
                if pattern.is_match(line) {
                    vulnerabilities.push(create_vulnerability(
                        "OWASP-A02",
                        Some("CWE-327"),
                        "Cryptographic Failures",
                        Severity::High,
                        "web_security",
                        "Cryptographic failure that may expose sensitive data or compromise security.",
                        file_path,
                        line_num + 1,
                        pattern.find(line).unwrap().start(),
                        line,
                        "Use strong cryptographic algorithms, properly manage keys, and implement secure protocols.",
                    ));
                }
            }
        }
        
        vulnerabilities
    }

    fn check_injection(&self, content: &str, file_path: &str) -> Vec<Vulnerability> {
        let mut vulnerabilities = Vec::new();
        
        for (line_num, line) in content.lines().enumerate() {
            for pattern in &self.injection_patterns {
                if pattern.is_match(line) {
                    vulnerabilities.push(create_vulnerability(
                        "OWASP-A03",
                        Some("CWE-79"),
                        "Injection",
                        Severity::High,
                        "web_security",
                        "Injection vulnerability that may allow code execution or data manipulation.",
                        file_path,
                        line_num + 1,
                        pattern.find(line).unwrap().start(),
                        line,
                        "Use parameterized queries, input validation, and output encoding to prevent injection attacks.",
                    ));
                }
            }
        }
        
        vulnerabilities
    }

    fn check_insecure_design(&self, content: &str, file_path: &str) -> Vec<Vulnerability> {
        let mut vulnerabilities = Vec::new();
        
        for (line_num, line) in content.lines().enumerate() {
            for pattern in &self.insecure_design_patterns {
                if pattern.is_match(line) {
                    vulnerabilities.push(create_vulnerability(
                        "OWASP-A04",
                        Some("CWE-693"),
                        "Insecure Design",
                        Severity::Medium,
                        "web_security",
                        "Insecure design pattern that may lead to security vulnerabilities.",
                        file_path,
                        line_num + 1,
                        pattern.find(line).unwrap().start(),
                        line,
                        "Implement secure design patterns, threat modeling, and security architecture reviews.",
                    ));
                }
            }
        }
        
        vulnerabilities
    }

    fn check_security_misconfiguration(&self, content: &str, file_path: &str) -> Vec<Vulnerability> {
        let mut vulnerabilities = Vec::new();
        
        for (line_num, line) in content.lines().enumerate() {
            for pattern in &self.misconfiguration_patterns {
                if pattern.is_match(line) {
                    vulnerabilities.push(create_vulnerability(
                        "OWASP-A05",
                        Some("CWE-16"),
                        "Security Misconfiguration",
                        Severity::Medium,
                        "web_security",
                        "Security misconfiguration that may expose the application to attacks.",
                        file_path,
                        line_num + 1,
                        pattern.find(line).unwrap().start(),
                        line,
                        "Implement secure configuration management, remove unnecessary features, and regularly review settings.",
                    ));
                }
            }
        }
        
        vulnerabilities
    }

    fn check_vulnerable_components(&self, content: &str, file_path: &str) -> Vec<Vulnerability> {
        let mut vulnerabilities = Vec::new();
        
        for (line_num, line) in content.lines().enumerate() {
            for pattern in &self.vulnerable_components_patterns {
                if pattern.is_match(line) {
                    vulnerabilities.push(create_vulnerability(
                        "OWASP-A06",
                        Some("CWE-1104"),
                        "Vulnerable and Outdated Components",
                        Severity::Medium,
                        "web_security",
                        "Use of vulnerable or outdated components that may contain known security flaws.",
                        file_path,
                        line_num + 1,
                        pattern.find(line).unwrap().start(),
                        line,
                        "Keep components updated, monitor for vulnerabilities, and remove unused dependencies.",
                    ));
                }
            }
        }
        
        vulnerabilities
    }

    fn check_identification_auth_failures(&self, content: &str, file_path: &str) -> Vec<Vulnerability> {
        let mut vulnerabilities = Vec::new();
        
        for (line_num, line) in content.lines().enumerate() {
            for pattern in &self.auth_patterns {
                if pattern.is_match(line) {
                    vulnerabilities.push(create_vulnerability(
                        "OWASP-A07",
                        Some("CWE-287"),
                        "Identification and Authentication Failures",
                        Severity::High,
                        "web_security",
                        "Authentication failure that may allow unauthorized access to user accounts.",
                        file_path,
                        line_num + 1,
                        pattern.find(line).unwrap().start(),
                        line,
                        "Implement strong authentication mechanisms, session management, and multi-factor authentication.",
                    ));
                }
            }
        }
        
        vulnerabilities
    }

    fn check_software_data_integrity_failures(&self, content: &str, file_path: &str) -> Vec<Vulnerability> {
        let mut vulnerabilities = Vec::new();
        
        for (line_num, line) in content.lines().enumerate() {
            for pattern in &self.integrity_patterns {
                if pattern.is_match(line) {
                    vulnerabilities.push(create_vulnerability(
                        "OWASP-A08",
                        Some("CWE-345"),
                        "Software and Data Integrity Failures",
                        Severity::Medium,
                        "web_security",
                        "Software or data integrity failure that may compromise application security.",
                        file_path,
                        line_num + 1,
                        pattern.find(line).unwrap().start(),
                        line,
                        "Implement integrity checks, use digital signatures, and secure CI/CD pipelines.",
                    ));
                }
            }
        }
        
        vulnerabilities
    }

    fn check_security_logging_monitoring_failures(&self, content: &str, file_path: &str) -> Vec<Vulnerability> {
        let mut vulnerabilities = Vec::new();
        
        for (line_num, line) in content.lines().enumerate() {
            for pattern in &self.logging_patterns {
                if pattern.is_match(line) {
                    vulnerabilities.push(create_vulnerability(
                        "OWASP-A09",
                        Some("CWE-778"),
                        "Security Logging and Monitoring Failures",
                        Severity::Low,
                        "web_security",
                        "Insufficient logging or monitoring that may prevent detection of security incidents.",
                        file_path,
                        line_num + 1,
                        pattern.find(line).unwrap().start(),
                        line,
                        "Implement comprehensive logging, monitoring, and alerting for security events.",
                    ));
                }
            }
        }
        
        vulnerabilities
    }

    fn check_server_side_request_forgery(&self, content: &str, file_path: &str) -> Vec<Vulnerability> {
        let mut vulnerabilities = Vec::new();
        
        for (line_num, line) in content.lines().enumerate() {
            for pattern in &self.ssrf_patterns {
                if pattern.is_match(line) {
                    vulnerabilities.push(create_vulnerability(
                        "OWASP-A10",
                        Some("CWE-918"),
                        "Server-Side Request Forgery (SSRF)",
                        Severity::High,
                        "web_security",
                        "Server-side request forgery vulnerability that may allow access to internal resources.",
                        file_path,
                        line_num + 1,
                        pattern.find(line).unwrap().start(),
                        line,
                        "Validate and sanitize user input, implement URL whitelisting, and network segmentation.",
                    ));
                }
            }
        }
        
        vulnerabilities
    }
}

impl RuleSet for OwaspWebRules {
    fn analyze(&self, source_file: &SourceFile, _ast: &ParsedAst) -> Result<Vec<Vulnerability>> {
        let mut vulnerabilities = Vec::new();
        let content = &source_file.content;
        let file_path = source_file.path.to_string_lossy();

        // Run all OWASP Web Application vulnerability checks
        vulnerabilities.extend(self.check_broken_access_control(content, &file_path));
        vulnerabilities.extend(self.check_cryptographic_failures(content, &file_path));
        vulnerabilities.extend(self.check_injection(content, &file_path));
        vulnerabilities.extend(self.check_insecure_design(content, &file_path));
        vulnerabilities.extend(self.check_security_misconfiguration(content, &file_path));
        vulnerabilities.extend(self.check_vulnerable_components(content, &file_path));
        vulnerabilities.extend(self.check_identification_auth_failures(content, &file_path));
        vulnerabilities.extend(self.check_software_data_integrity_failures(content, &file_path));
        vulnerabilities.extend(self.check_security_logging_monitoring_failures(content, &file_path));
        vulnerabilities.extend(self.check_server_side_request_forgery(content, &file_path));

        Ok(vulnerabilities)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    
    

    #[test]
    fn test_access_control_detection() {
        let rules = OwaspWebRules::new();
        let content = "bypass_auth = true";
        
        let vulnerabilities = rules.check_broken_access_control(content, "test.py");
        assert!(!vulnerabilities.is_empty());
        assert_eq!(vulnerabilities[0].id, "OWASP-A01");
    }

    #[test]
    fn test_crypto_failure_detection() {
        let rules = OwaspWebRules::new();
        let content = "hash = md5(password)";
        
        let vulnerabilities = rules.check_cryptographic_failures(content, "test.py");
        assert!(!vulnerabilities.is_empty());
        assert_eq!(vulnerabilities[0].id, "OWASP-A02");
    }

    #[test]
    fn test_injection_detection() {
        let rules = OwaspWebRules::new();
        let content = "eval($user_input)";
        
        let vulnerabilities = rules.check_injection(content, "test.php");
        assert!(!vulnerabilities.is_empty());
        assert_eq!(vulnerabilities[0].id, "OWASP-A03");
    }

    #[test]
    fn test_ssrf_detection() {
        let rules = OwaspWebRules::new();
        let content = "request to localhost:8080";
        
        let vulnerabilities = rules.check_server_side_request_forgery(content, "test.py");
        assert!(!vulnerabilities.is_empty());
        assert_eq!(vulnerabilities[0].id, "OWASP-A10");
    }
}