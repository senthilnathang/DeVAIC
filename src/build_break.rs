use crate::{
    config::BuildBreakRules,
    error::Result,
    Severity, Vulnerability,
};
use std::collections::HashMap;

#[derive(Debug, Clone)]
pub struct BuildBreakResult {
    pub should_break: bool,
    pub summary: BuildBreakSummary,
    pub violations: Vec<BuildBreakViolation>,
}

#[derive(Debug, Clone)]
pub struct BuildBreakSummary {
    pub total_vulnerabilities: usize,
    pub critical_count: usize,
    pub high_count: usize,
    pub medium_count: usize,
    pub low_count: usize,
    pub analysis_duration: Option<std::time::Duration>,
}

#[derive(Debug, Clone)]
pub struct BuildBreakViolation {
    pub severity: Severity,
    pub threshold: u32,
    pub actual: u32,
    pub message: String,
}

pub struct BuildBreakAnalyzer {
    rules: BuildBreakRules,
}

impl BuildBreakAnalyzer {
    pub fn new(rules: BuildBreakRules) -> Self {
        Self { rules }
    }

    pub fn analyze(&self, vulnerabilities: &[Vulnerability]) -> Result<BuildBreakResult> {
        let summary = self.create_summary(vulnerabilities);
        let violations = self.check_thresholds(&summary);
        let should_break = !violations.is_empty();

        Ok(BuildBreakResult {
            should_break,
            summary,
            violations,
        })
    }

    fn create_summary(&self, vulnerabilities: &[Vulnerability]) -> BuildBreakSummary {
        let mut counts = HashMap::new();
        
        for vulnerability in vulnerabilities {
            let count = counts.entry(vulnerability.severity.clone()).or_insert(0);
            *count += 1;
        }

        BuildBreakSummary {
            total_vulnerabilities: vulnerabilities.len(),
            critical_count: *counts.get(&Severity::Critical).unwrap_or(&0),
            high_count: *counts.get(&Severity::High).unwrap_or(&0),
            medium_count: *counts.get(&Severity::Medium).unwrap_or(&0),
            low_count: *counts.get(&Severity::Low).unwrap_or(&0),
            analysis_duration: None,
        }
    }

    fn check_thresholds(&self, summary: &BuildBreakSummary) -> Vec<BuildBreakViolation> {
        let mut violations = Vec::new();

        // Check critical vulnerabilities
        if summary.critical_count > self.rules.max_critical as usize {
            violations.push(BuildBreakViolation {
                severity: Severity::Critical,
                threshold: self.rules.max_critical,
                actual: summary.critical_count as u32,
                message: format!(
                    "Critical vulnerabilities found: {} (threshold: {})",
                    summary.critical_count, self.rules.max_critical
                ),
            });
        }

        // Check high severity vulnerabilities
        if summary.high_count > self.rules.max_high as usize {
            violations.push(BuildBreakViolation {
                severity: Severity::High,
                threshold: self.rules.max_high,
                actual: summary.high_count as u32,
                message: format!(
                    "High severity vulnerabilities found: {} (threshold: {})",
                    summary.high_count, self.rules.max_high
                ),
            });
        }

        // Check medium severity vulnerabilities
        if summary.medium_count > self.rules.max_medium as usize {
            violations.push(BuildBreakViolation {
                severity: Severity::Medium,
                threshold: self.rules.max_medium,
                actual: summary.medium_count as u32,
                message: format!(
                    "Medium severity vulnerabilities found: {} (threshold: {})",
                    summary.medium_count, self.rules.max_medium
                ),
            });
        }

        // Check low severity vulnerabilities
        if summary.low_count > self.rules.max_low as usize {
            violations.push(BuildBreakViolation {
                severity: Severity::Low,
                threshold: self.rules.max_low,
                actual: summary.low_count as u32,
                message: format!(
                    "Low severity vulnerabilities found: {} (threshold: {})",
                    summary.low_count, self.rules.max_low
                ),
            });
        }

        violations
    }

    pub fn should_fail_build(&self, vulnerabilities: &[Vulnerability]) -> Result<bool> {
        let result = self.analyze(vulnerabilities)?;
        Ok(result.should_break)
    }

    pub fn create_build_status_message(&self, vulnerabilities: &[Vulnerability]) -> Result<String> {
        let result = self.analyze(vulnerabilities)?;
        
        if result.should_break {
            let mut message = String::from("❌ BUILD FAILED - Security threshold violations detected:\n\n");
            
            for violation in &result.violations {
                message.push_str(&format!("• {}\n", violation.message));
            }
            
            message.push_str(&format!(
                "\nSummary:\n• Total vulnerabilities: {}\n• Critical: {}\n• High: {}\n• Medium: {}\n• Low: {}\n",
                result.summary.total_vulnerabilities,
                result.summary.critical_count,
                result.summary.high_count,
                result.summary.medium_count,
                result.summary.low_count
            ));
            
            message.push_str("\nPlease fix the vulnerabilities above the threshold limits to proceed.\n");
            
            Ok(message)
        } else {
            Ok(format!(
                "✅ BUILD PASSED - All security thresholds met:\n• Total vulnerabilities: {}\n• Critical: {} (≤ {})\n• High: {} (≤ {})\n• Medium: {} (≤ {})\n• Low: {} (≤ {})\n",
                result.summary.total_vulnerabilities,
                result.summary.critical_count, self.rules.max_critical,
                result.summary.high_count, self.rules.max_high,
                result.summary.medium_count, self.rules.max_medium,
                result.summary.low_count, self.rules.max_low
            ))
        }
    }

    /// Generate a baseline report that can be used for future comparisons
    pub fn generate_baseline(&self, vulnerabilities: &[Vulnerability]) -> Result<String> {
        let result = self.analyze(vulnerabilities)?;
        
        let baseline = serde_json::json!({
            "timestamp": chrono::Utc::now().to_rfc3339(),
            "total_vulnerabilities": result.summary.total_vulnerabilities,
            "severity_counts": {
                "critical": result.summary.critical_count,
                "high": result.summary.high_count,
                "medium": result.summary.medium_count,
                "low": result.summary.low_count
            },
            "thresholds": {
                "max_critical": self.rules.max_critical,
                "max_high": self.rules.max_high,
                "max_medium": self.rules.max_medium,
                "max_low": self.rules.max_low
            },
            "build_passed": !result.should_break
        });

        Ok(serde_json::to_string_pretty(&baseline)?)
    }

    /// Compare current vulnerabilities against a baseline
    pub fn compare_with_baseline(&self, vulnerabilities: &[Vulnerability], baseline_json: &str) -> Result<String> {
        let baseline: serde_json::Value = serde_json::from_str(baseline_json)?;
        let current_result = self.analyze(vulnerabilities)?;
        
        let baseline_critical = baseline["severity_counts"]["critical"].as_u64().unwrap_or(0) as usize;
        let baseline_high = baseline["severity_counts"]["high"].as_u64().unwrap_or(0) as usize;
        let baseline_medium = baseline["severity_counts"]["medium"].as_u64().unwrap_or(0) as usize;
        let baseline_low = baseline["severity_counts"]["low"].as_u64().unwrap_or(0) as usize;
        let baseline_total = baseline["total_vulnerabilities"].as_u64().unwrap_or(0) as usize;

        let mut message = String::from("📊 BASELINE COMPARISON:\n\n");
        
        message.push_str(&format!("Total vulnerabilities: {} → {} ({})\n",
            baseline_total,
            current_result.summary.total_vulnerabilities,
            self.format_change(baseline_total as i32, current_result.summary.total_vulnerabilities as i32)
        ));
        
        message.push_str(&format!("Critical: {} → {} ({})\n",
            baseline_critical,
            current_result.summary.critical_count,
            self.format_change(baseline_critical as i32, current_result.summary.critical_count as i32)
        ));
        
        message.push_str(&format!("High: {} → {} ({})\n",
            baseline_high,
            current_result.summary.high_count,
            self.format_change(baseline_high as i32, current_result.summary.high_count as i32)
        ));
        
        message.push_str(&format!("Medium: {} → {} ({})\n",
            baseline_medium,
            current_result.summary.medium_count,
            self.format_change(baseline_medium as i32, current_result.summary.medium_count as i32)
        ));
        
        message.push_str(&format!("Low: {} → {} ({})\n",
            baseline_low,
            current_result.summary.low_count,
            self.format_change(baseline_low as i32, current_result.summary.low_count as i32)
        ));

        Ok(message)
    }

    fn format_change(&self, old: i32, new: i32) -> String {
        let diff = new - old;
        if diff > 0 {
            format!("+{}", diff)
        } else if diff < 0 {
            format!("{}", diff)
        } else {
            "±0".to_string()
        }
    }
}

impl Default for BuildBreakAnalyzer {
    fn default() -> Self {
        Self::new(BuildBreakRules {
            max_critical: 0,
            max_high: 2,
            max_medium: 5,
            max_low: 10,
            fail_on_timeout: true,
            require_all_tests_pass: false,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::rules::create_vulnerability;

    #[test]
    fn test_build_break_analysis() {
        let rules = BuildBreakRules {
            max_critical: 0,
            max_high: 1,
            max_medium: 3,
            max_low: 5,
            fail_on_timeout: true,
            require_all_tests_pass: false,
        };
        
        let analyzer = BuildBreakAnalyzer::new(rules);
        
        let vulnerabilities = vec![
            create_vulnerability(
                "test-1", Some("CWE-89"), "SQL Injection", Severity::Critical,
                "injection", "Test description", "test.py", 1, 0, "test code", "Fix it"
            ),
            create_vulnerability(
                "test-2", Some("CWE-79"), "XSS", Severity::High,
                "xss", "Test description", "test.js", 1, 0, "test code", "Fix it"
            ),
        ];
        
        let result = analyzer.analyze(&vulnerabilities).unwrap();
        assert!(result.should_break);
        assert_eq!(result.violations.len(), 1); // Only critical violation
        assert_eq!(result.summary.critical_count, 1);
        assert_eq!(result.summary.high_count, 1);
    }

    #[test]
    fn test_build_success() {
        let rules = BuildBreakRules {
            max_critical: 1,
            max_high: 2,
            max_medium: 5,
            max_low: 10,
            fail_on_timeout: true,
            require_all_tests_pass: false,
        };
        
        let analyzer = BuildBreakAnalyzer::new(rules);
        
        let vulnerabilities = vec![
            create_vulnerability(
                "test-1", Some("CWE-200"), "Info Disclosure", Severity::Medium,
                "info", "Test description", "test.py", 1, 0, "test code", "Fix it"
            ),
        ];
        
        let result = analyzer.analyze(&vulnerabilities).unwrap();
        assert!(!result.should_break);
        assert_eq!(result.violations.len(), 0);
    }
}