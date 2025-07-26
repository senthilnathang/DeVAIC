use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use crate::{Severity, Vulnerability};
use super::matcher::SemgrepMatch;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SarifOutput {
    #[serde(rename = "$schema")]
    pub schema: String,
    pub version: String,
    pub runs: Vec<SarifRun>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SarifRun {
    pub tool: SarifTool,
    pub results: Vec<SarifResult>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub invocations: Option<Vec<SarifInvocation>>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SarifTool {
    pub driver: SarifDriver,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SarifDriver {
    pub name: String,
    pub version: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub information_uri: Option<String>,
    pub rules: Vec<SarifRule>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SarifRule {
    pub id: String,
    pub name: String,
    #[serde(rename = "shortDescription")]
    pub short_description: SarifMessage,
    #[serde(rename = "fullDescription")]
    pub full_description: SarifMessage,
    #[serde(rename = "defaultConfiguration")]
    pub default_configuration: SarifConfiguration,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub properties: Option<HashMap<String, serde_json::Value>>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SarifMessage {
    pub text: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SarifConfiguration {
    pub level: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SarifResult {
    #[serde(rename = "ruleId")]
    pub rule_id: String,
    #[serde(rename = "ruleIndex")]
    pub rule_index: usize,
    pub level: String,
    pub message: SarifMessage,
    pub locations: Vec<SarifLocation>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub fixes: Option<Vec<SarifFix>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub properties: Option<HashMap<String, serde_json::Value>>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SarifLocation {
    #[serde(rename = "physicalLocation")]
    pub physical_location: SarifPhysicalLocation,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SarifPhysicalLocation {
    #[serde(rename = "artifactLocation")]
    pub artifact_location: SarifArtifactLocation,
    pub region: SarifRegion,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SarifArtifactLocation {
    pub uri: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SarifRegion {
    #[serde(rename = "startLine")]
    pub start_line: usize,
    #[serde(rename = "startColumn")]
    pub start_column: usize,
    #[serde(rename = "endLine")]
    pub end_line: usize,
    #[serde(rename = "endColumn")]
    pub end_column: usize,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub snippet: Option<SarifArtifactContent>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SarifArtifactContent {
    pub text: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SarifFix {
    pub description: SarifMessage,
    #[serde(rename = "artifactChanges")]
    pub artifact_changes: Vec<SarifArtifactChange>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SarifArtifactChange {
    #[serde(rename = "artifactLocation")]
    pub artifact_location: SarifArtifactLocation,
    pub replacements: Vec<SarifReplacement>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SarifReplacement {
    #[serde(rename = "deletedRegion")]
    pub deleted_region: SarifRegion,
    #[serde(rename = "insertedContent")]
    pub inserted_content: SarifArtifactContent,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SarifInvocation {
    #[serde(rename = "executionSuccessful")]
    pub execution_successful: bool,
    #[serde(rename = "startTimeUtc")]
    pub start_time_utc: String,
    #[serde(rename = "endTimeUtc")]
    pub end_time_utc: String,
}

impl SarifOutput {
    pub fn new() -> Self {
        Self {
            schema: "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/master/Schemata/sarif-schema-2.1.0.json".to_string(),
            version: "2.1.0".to_string(),
            runs: Vec::new(),
        }
    }
    
    pub fn add_run(&mut self, run: SarifRun) {
        self.runs.push(run);
    }
    
    pub fn to_json(&self) -> Result<String, serde_json::Error> {
        serde_json::to_string_pretty(self)
    }
    
    pub fn from_vulnerabilities(
        vulnerabilities: &[Vulnerability],
        tool_name: &str,
        tool_version: &str,
    ) -> Self {
        let mut sarif = Self::new();
        
        // Create rules from unique vulnerabilities
        let mut rules = Vec::new();
        let mut rule_map = HashMap::new();
        
        for (index, vuln) in vulnerabilities.iter().enumerate() {
            if !rule_map.contains_key(&vuln.id) {
                rule_map.insert(vuln.id.clone(), index);
                
                let mut properties = HashMap::new();
                if let Some(cwe) = &vuln.cwe {
                    properties.insert("cwe".to_string(), serde_json::Value::String(cwe.clone()));
                }
                properties.insert("category".to_string(), serde_json::Value::String(vuln.category.clone()));
                
                rules.push(SarifRule {
                    id: vuln.id.clone(),
                    name: vuln.title.clone(),
                    short_description: SarifMessage {
                        text: vuln.title.clone(),
                    },
                    full_description: SarifMessage {
                        text: vuln.description.clone(),
                    },
                    default_configuration: SarifConfiguration {
                        level: severity_to_sarif_level(&vuln.severity),
                    },
                    properties: Some(properties),
                });
            }
        }
        
        // Create results
        let results: Vec<SarifResult> = vulnerabilities.iter().map(|vuln| {
            let rule_index = rule_map[&vuln.id];
            
            let mut properties = HashMap::new();
            properties.insert("recommendation".to_string(), 
                serde_json::Value::String(vuln.recommendation.clone()));
            
            SarifResult {
                rule_id: vuln.id.clone(),
                rule_index,
                level: severity_to_sarif_level(&vuln.severity),
                message: SarifMessage {
                    text: vuln.description.clone(),
                },
                locations: vec![SarifLocation {
                    physical_location: SarifPhysicalLocation {
                        artifact_location: SarifArtifactLocation {
                            uri: vuln.file_path.clone(),
                        },
                        region: SarifRegion {
                            start_line: vuln.line_number,
                            start_column: vuln.column_start + 1, // SARIF uses 1-based columns
                            end_line: vuln.line_number,
                            end_column: vuln.column_start + vuln.source_code.len() + 1,
                            snippet: Some(SarifArtifactContent {
                                text: vuln.source_code.clone(),
                            }),
                        },
                    },
                }],
                fixes: None, // Could be populated from AutoFix suggestions
                properties: Some(properties),
            }
        }).collect();
        
        let run = SarifRun {
            tool: SarifTool {
                driver: SarifDriver {
                    name: tool_name.to_string(),
                    version: tool_version.to_string(),
                    information_uri: Some("https://github.com/yourusername/devaic".to_string()),
                    rules,
                },
            },
            results,
            invocations: None,
        };
        
        sarif.add_run(run);
        sarif
    }
    
    pub fn from_semgrep_matches(
        matches: &[SemgrepMatch],
        rule_id: &str,
        rule_description: &str,
        severity: &Severity,
        tool_name: &str,
        tool_version: &str,
    ) -> Self {
        let mut sarif = Self::new();
        
        let rule = SarifRule {
            id: rule_id.to_string(),
            name: rule_id.to_string(),
            short_description: SarifMessage {
                text: rule_description.to_string(),
            },
            full_description: SarifMessage {
                text: rule_description.to_string(),
            },
            default_configuration: SarifConfiguration {
                level: severity_to_sarif_level(severity),
            },
            properties: None,
        };
        
        let results: Vec<SarifResult> = matches.iter().map(|semgrep_match| {
            SarifResult {
                rule_id: rule_id.to_string(),
                rule_index: 0,
                level: severity_to_sarif_level(severity),
                message: SarifMessage {
                    text: format!("Pattern matched: {}", semgrep_match.matched_text),
                },
                locations: vec![SarifLocation {
                    physical_location: SarifPhysicalLocation {
                        artifact_location: SarifArtifactLocation {
                            uri: semgrep_match.file_path.to_string_lossy().to_string(),
                        },
                        region: SarifRegion {
                            start_line: semgrep_match.range.start_point.row + 1,
                            start_column: semgrep_match.range.start_point.column + 1,
                            end_line: semgrep_match.range.end_point.row + 1,
                            end_column: semgrep_match.range.end_point.column + 1,
                            snippet: Some(SarifArtifactContent {
                                text: semgrep_match.matched_text.clone(),
                            }),
                        },
                    },
                }],
                fixes: None,
                properties: None,
            }
        }).collect();
        
        let run = SarifRun {
            tool: SarifTool {
                driver: SarifDriver {
                    name: tool_name.to_string(),
                    version: tool_version.to_string(),
                    information_uri: Some("https://github.com/yourusername/devaic".to_string()),
                    rules: vec![rule],
                },
            },
            results,
            invocations: None,
        };
        
        sarif.add_run(run);
        sarif
    }
}

impl Default for SarifOutput {
    fn default() -> Self {
        Self::new()
    }
}

fn severity_to_sarif_level(severity: &Severity) -> String {
    match severity {
        Severity::Info => "note".to_string(),
        Severity::Low => "note".to_string(),
        Severity::Medium => "warning".to_string(),
        Severity::High => "error".to_string(),
        Severity::Critical => "error".to_string(),
    }
}

/// Helper for creating SARIF output from analysis results
pub struct SarifReporter;

impl SarifReporter {
    pub fn create_report(
        vulnerabilities: &[Vulnerability],
        analysis_duration: std::time::Duration,
    ) -> SarifOutput {
        let mut sarif = SarifOutput::from_vulnerabilities(
            vulnerabilities,
            "DeVAIC",
            env!("CARGO_PKG_VERSION"),
        );
        
        // Add invocation information
        if let Some(run) = sarif.runs.first_mut() {
            let start_time = chrono::Utc::now() - chrono::Duration::from_std(analysis_duration).unwrap_or_default();
            let end_time = chrono::Utc::now();
            
            run.invocations = Some(vec![SarifInvocation {
                execution_successful: true,
                start_time_utc: start_time.to_rfc3339(),
                end_time_utc: end_time.to_rfc3339(),
            }]);
        }
        
        sarif
    }
    
    pub fn write_to_file(
        sarif: &SarifOutput,
        file_path: &std::path::Path,
    ) -> Result<(), Box<dyn std::error::Error>> {
        let json = sarif.to_json()?;
        std::fs::write(file_path, json)?;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{Severity, Vulnerability};
    
    #[test]
    fn test_sarif_creation() {
        let vulnerability = Vulnerability {
            id: "JS001".to_string(),
            cwe: Some("CWE-79".to_string()),
            owasp: Some("A03:2021".to_string()),
            title: "Cross-Site Scripting".to_string(),
            severity: Severity::High,
            category: "injection".to_string(),
            description: "XSS vulnerability detected".to_string(),
            file_path: "test.js".to_string(),
            line_number: 10,
            column_start: 5,
            column_end: 20,
            source_code: "innerHTML = userInput".to_string(),
            recommendation: "Sanitize user input".to_string(),
            references: vec!["https://cwe.mitre.org/data/definitions/79.html".to_string()],
            confidence: 0.85,
        };
        
        let sarif = SarifOutput::from_vulnerabilities(&[vulnerability], "DeVAIC", "1.0.0");
        
        assert_eq!(sarif.runs.len(), 1);
        assert_eq!(sarif.runs[0].tool.driver.name, "DeVAIC");
        assert_eq!(sarif.runs[0].results.len(), 1);
        assert_eq!(sarif.runs[0].results[0].rule_id, "JS001");
        assert_eq!(sarif.runs[0].results[0].level, "error");
    }
    
    #[test]
    fn test_severity_to_sarif_level() {
        assert_eq!(severity_to_sarif_level(&Severity::Info), "note");
        assert_eq!(severity_to_sarif_level(&Severity::Low), "note");
        assert_eq!(severity_to_sarif_level(&Severity::Medium), "warning");
        assert_eq!(severity_to_sarif_level(&Severity::High), "error");
        assert_eq!(severity_to_sarif_level(&Severity::Critical), "error");
    }
    
    #[test]
    fn test_sarif_json_serialization() {
        let sarif = SarifOutput::new();
        let json = sarif.to_json().unwrap();
        
        assert!(json.contains("$schema"));
        assert!(json.contains("2.1.0"));
        assert!(json.contains("runs"));
    }
}