use crate::{Severity, Vulnerability};
use colored::*;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use tabled::{Table, Tabled};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Report {
    pub summary: Summary,
    pub vulnerabilities: Vec<Vulnerability>,
    pub files_analyzed: usize,
    pub analysis_duration: std::time::Duration,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Summary {
    pub total_vulnerabilities: usize,
    pub by_severity: HashMap<String, usize>,
    pub by_category: HashMap<String, usize>,
    pub by_language: HashMap<String, usize>,
}

#[derive(Tabled)]
struct VulnerabilityRow {
    #[tabled(rename = "ID")]
    id: String,
    #[tabled(rename = "CWE")]
    cwe: String,
    #[tabled(rename = "Type")]
    vulnerability_type: String,
    #[tabled(rename = "Severity")]
    severity: String,
    #[tabled(rename = "Category")]
    category: String,
    #[tabled(rename = "File")]
    file: String,
    #[tabled(rename = "Line")]
    line: String,
    #[tabled(rename = "Description")]
    description: String,
}

impl Report {
    pub fn new(vulnerabilities: Vec<Vulnerability>, files_analyzed: usize) -> Self {
        let summary = Summary::from_vulnerabilities(&vulnerabilities);
        
        Self {
            summary,
            vulnerabilities,
            files_analyzed,
            analysis_duration: std::time::Duration::from_secs(0),
        }
    }

    pub fn set_duration(&mut self, duration: std::time::Duration) {
        self.analysis_duration = duration;
    }

    pub fn to_json(&self) -> serde_json::Result<String> {
        serde_json::to_string_pretty(self)
    }

    pub fn to_table(&self, use_colors: bool) -> String {
        if self.vulnerabilities.is_empty() {
            return "No vulnerabilities found.".to_string();
        }

        let rows: Vec<VulnerabilityRow> = self
            .vulnerabilities
            .iter()
            .map(|v| {
                let severity_str = if use_colors {
                    match v.severity {
                        Severity::Critical => v.severity.to_string().red().bold().to_string(),
                        Severity::High => v.severity.to_string().red().to_string(),
                        Severity::Medium => v.severity.to_string().yellow().to_string(),
                        Severity::Low => v.severity.to_string().blue().to_string(),
                        Severity::Info => v.severity.to_string().cyan().to_string(),
                    }
                } else {
                    v.severity.to_string()
                };

                VulnerabilityRow {
                    id: v.id.clone(),
                    cwe: v.cwe.as_ref().unwrap_or(&"N/A".to_string()).clone(),
                    vulnerability_type: v.vulnerability_type.clone(),
                    severity: severity_str,
                    category: v.category.clone(),
                    file: v.file_path.clone(),
                    line: v.line_number.to_string(),
                    description: if v.description.len() > 50 {
                        format!("{}...", &v.description[..47])
                    } else {
                        v.description.clone()
                    },
                }
            })
            .collect();

        let table = Table::new(rows).to_string();
        
        format!("{}\n\n{}", self.format_summary(use_colors), table)
    }

    pub fn to_sarif(&self) -> serde_json::Result<String> {
        let sarif_run = SarifRun {
            tool: SarifTool {
                driver: SarifDriver {
                    name: "DeVAIC".to_string(),
                    version: "0.1.0".to_string(),
                    information_uri: "https://github.com/dessertlab/DeVAIC".to_string(),
                },
            },
            results: self.vulnerabilities.iter().map(|v| v.to_sarif()).collect(),
        };

        let sarif_report = SarifReport {
            version: "2.1.0".to_string(),
            schema: "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/master/Schemata/sarif-schema-2.1.0.json".to_string(),
            runs: vec![sarif_run],
        };

        serde_json::to_string_pretty(&sarif_report)
    }

    fn format_summary(&self, use_colors: bool) -> String {
        let mut summary = String::new();
        
        summary.push_str(&format!("Analysis Summary:\n"));
        summary.push_str(&format!("- Files analyzed: {}\n", self.files_analyzed));
        summary.push_str(&format!("- Total vulnerabilities: {}\n", self.summary.total_vulnerabilities));
        summary.push_str(&format!("- Analysis duration: {:.2}s\n", self.analysis_duration.as_secs_f64()));
        
        if !self.summary.by_severity.is_empty() {
            summary.push_str("\nBy Severity:\n");
            for (severity, count) in &self.summary.by_severity {
                let severity_str = if use_colors {
                    match severity.as_str() {
                        "CRITICAL" => severity.red().bold().to_string(),
                        "HIGH" => severity.red().to_string(),
                        "MEDIUM" => severity.yellow().to_string(),
                        "LOW" => severity.blue().to_string(),
                        "INFO" => severity.cyan().to_string(),
                        _ => severity.clone(),
                    }
                } else {
                    severity.clone()
                };
                summary.push_str(&format!("- {}: {}\n", severity_str, count));
            }
        }

        if !self.summary.by_category.is_empty() {
            summary.push_str("\nBy Category:\n");
            for (category, count) in &self.summary.by_category {
                let category_display = match category.as_str() {
                    "llm_security" => "OWASP LLM Security",
                    "web_security" => "OWASP Web Security",
                    _ => category,
                };
                summary.push_str(&format!("- {}: {}\n", category_display, count));
            }
        }

        summary
    }
}

impl Summary {
    fn from_vulnerabilities(vulnerabilities: &[Vulnerability]) -> Self {
        let total_vulnerabilities = vulnerabilities.len();
        
        let mut by_severity = HashMap::new();
        let mut by_category = HashMap::new();
        let mut by_language = HashMap::new();
        
        for vuln in vulnerabilities {
            *by_severity.entry(vuln.severity.to_string()).or_insert(0) += 1;
            *by_category.entry(vuln.category.clone()).or_insert(0) += 1;
            
            // Extract language from file extension
            let language = if vuln.file_path.ends_with(".c") || vuln.file_path.ends_with(".h") {
                "C"
            } else if vuln.file_path.ends_with(".cpp") || vuln.file_path.ends_with(".hpp") {
                "C++"
            } else if vuln.file_path.ends_with(".py") {
                "Python"
            } else if vuln.file_path.ends_with(".java") {
                "Java"
            } else if vuln.file_path.ends_with(".js") || vuln.file_path.ends_with(".jsx") {
                "JavaScript"
            } else if vuln.file_path.ends_with(".ts") || vuln.file_path.ends_with(".tsx") {
                "TypeScript"
            } else if vuln.file_path.ends_with(".st") || vuln.file_path.ends_with(".scl") {
                "SCADA"
            } else {
                "Unknown"
            };
            
            *by_language.entry(language.to_string()).or_insert(0) += 1;
        }
        
        Self {
            total_vulnerabilities,
            by_severity,
            by_category,
            by_language,
        }
    }
}

impl Vulnerability {
    fn to_sarif(&self) -> SarifResult {
        SarifResult {
            rule_id: self.id.clone(),
            message: SarifMessage {
                text: self.description.clone(),
            },
            locations: vec![SarifLocation {
                physical_location: SarifPhysicalLocation {
                    artifact_location: SarifArtifactLocation {
                        uri: self.file_path.clone(),
                    },
                    region: SarifRegion {
                        start_line: self.line_number,
                        start_column: self.column,
                    },
                },
            }],
            level: match self.severity {
                Severity::Critical => "error".to_string(),
                Severity::High => "error".to_string(),
                Severity::Medium => "warning".to_string(),
                Severity::Low => "note".to_string(),
                Severity::Info => "note".to_string(),
            },
        }
    }
}

// SARIF format structures
#[derive(Serialize)]
struct SarifReport {
    #[serde(rename = "$schema")]
    schema: String,
    version: String,
    runs: Vec<SarifRun>,
}

#[derive(Serialize)]
struct SarifRun {
    tool: SarifTool,
    results: Vec<SarifResult>,
}

#[derive(Serialize)]
struct SarifTool {
    driver: SarifDriver,
}

#[derive(Serialize)]
struct SarifDriver {
    name: String,
    version: String,
    #[serde(rename = "informationUri")]
    information_uri: String,
}

#[derive(Serialize)]
struct SarifResult {
    #[serde(rename = "ruleId")]
    rule_id: String,
    message: SarifMessage,
    locations: Vec<SarifLocation>,
    level: String,
}

#[derive(Serialize)]
struct SarifMessage {
    text: String,
}

#[derive(Serialize)]
struct SarifLocation {
    #[serde(rename = "physicalLocation")]
    physical_location: SarifPhysicalLocation,
}

#[derive(Serialize)]
struct SarifPhysicalLocation {
    #[serde(rename = "artifactLocation")]
    artifact_location: SarifArtifactLocation,
    region: SarifRegion,
}

#[derive(Serialize)]
struct SarifArtifactLocation {
    uri: String,
}

#[derive(Serialize)]
struct SarifRegion {
    #[serde(rename = "startLine")]
    start_line: usize,
    #[serde(rename = "startColumn")]
    start_column: usize,
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::Severity;

    #[test]
    fn test_report_creation() {
        let vulnerabilities = vec![
            Vulnerability {
                id: "TEST001".to_string(),
                cwe: Some("CWE-120".to_string()),
                vulnerability_type: "Buffer Overflow".to_string(),
                severity: Severity::High,
                category: "injection".to_string(),
                description: "Test vulnerability".to_string(),
                file_path: "test.c".to_string(),
                line_number: 10,
                column: 5,
                source_code: "strcpy(buffer, input);".to_string(),
                recommendation: "Use strncpy instead".to_string(),
            }
        ];

        let report = Report::new(vulnerabilities, 1);
        
        assert_eq!(report.summary.total_vulnerabilities, 1);
        assert_eq!(report.files_analyzed, 1);
        assert_eq!(report.summary.by_severity.get("HIGH"), Some(&1));
        assert_eq!(report.summary.by_category.get("injection"), Some(&1));
    }

    #[test]
    fn test_json_serialization() {
        let vulnerabilities = vec![
            Vulnerability {
                id: "TEST001".to_string(),
                cwe: Some("CWE-95".to_string()),
                vulnerability_type: "Code Injection".to_string(),
                severity: Severity::Medium,
                category: "validation".to_string(),
                description: "Test vulnerability".to_string(),
                file_path: "test.py".to_string(),
                line_number: 5,
                column: 0,
                source_code: "eval(user_input)".to_string(),
                recommendation: "Avoid using eval".to_string(),
            }
        ];

        let report = Report::new(vulnerabilities, 1);
        let json = report.to_json().unwrap();
        
        assert!(json.contains("TEST001"));
        assert!(json.contains("validation"));
        assert!(json.contains("MEDIUM"));
    }
}