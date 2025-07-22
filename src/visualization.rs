use crate::{Severity, Vulnerability, compliance::ComplianceReport};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::path::Path;

#[cfg(feature = "visualization")]
use plotters::prelude::*;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VisualizationConfig {
    pub output_dir: String,
    pub chart_width: u32,
    pub chart_height: u32,
    pub theme: ChartTheme,
    pub formats: Vec<OutputFormat>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum ChartTheme {
    Light,
    Dark,
    Corporate,
    Security,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum OutputFormat {
    SVG,
    PNG,
    HTML,
    PDF,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SecurityDashboard {
    pub vulnerability_summary: VulnerabilitySummary,
    pub severity_distribution: SeverityDistribution,
    pub language_breakdown: LanguageBreakdown,
    pub category_analysis: CategoryAnalysis,
    pub trend_analysis: TrendAnalysis,
    pub compliance_status: ComplianceStatus,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VulnerabilitySummary {
    pub total_vulnerabilities: usize,
    pub critical_count: usize,
    pub high_count: usize,
    pub medium_count: usize,
    pub low_count: usize,
    pub info_count: usize,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SeverityDistribution {
    pub critical_percentage: f64,
    pub high_percentage: f64,
    pub medium_percentage: f64,
    pub low_percentage: f64,
    pub info_percentage: f64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LanguageBreakdown {
    pub languages: HashMap<String, usize>,
    pub most_vulnerable_language: String,
    pub safest_language: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CategoryAnalysis {
    pub categories: HashMap<String, usize>,
    pub top_risk_category: String,
    pub category_trends: HashMap<String, f64>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TrendAnalysis {
    pub vulnerability_trend: Vec<(String, usize)>, // (date, count)
    pub severity_trends: HashMap<String, Vec<(String, usize)>>,
    pub improvement_rate: f64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ComplianceStatus {
    pub frameworks: HashMap<String, f64>, // framework -> compliance percentage
    pub overall_compliance: f64,
    pub compliance_trend: Vec<(String, f64)>,
}

pub struct VisualizationEngine {
    #[allow(dead_code)]
    config: VisualizationConfig,
}

impl VisualizationEngine {
    pub fn new(config: VisualizationConfig) -> Self {
        Self { config }
    }

    pub fn generate_security_dashboard(&self, vulnerabilities: &[Vulnerability], compliance_reports: &[ComplianceReport]) -> crate::Result<SecurityDashboard> {
        let vulnerability_summary = self.calculate_vulnerability_summary(vulnerabilities);
        let severity_distribution = self.calculate_severity_distribution(vulnerabilities);
        let language_breakdown = self.calculate_language_breakdown(vulnerabilities);
        let category_analysis = self.calculate_category_analysis(vulnerabilities);
        let trend_analysis = self.calculate_trend_analysis(vulnerabilities);
        let compliance_status = self.calculate_compliance_status(compliance_reports);

        Ok(SecurityDashboard {
            vulnerability_summary,
            severity_distribution,
            language_breakdown,
            category_analysis,
            trend_analysis,
            compliance_status,
        })
    }

    #[cfg(feature = "visualization")]
    pub fn create_vulnerability_chart(&self, vulnerabilities: &[Vulnerability], output_path: &Path) -> crate::Result<()> {
        let root = SVGBackend::new(output_path, (self.config.chart_width, self.config.chart_height)).into_drawing_area();
        root.fill(&WHITE)?;

        let severity_counts = self.count_by_severity(vulnerabilities);
        let data: Vec<(&str, usize)> = vec![
            ("Critical", severity_counts.get(&Severity::Critical).unwrap_or(&0).clone()),
            ("High", severity_counts.get(&Severity::High).unwrap_or(&0).clone()),
            ("Medium", severity_counts.get(&Severity::Medium).unwrap_or(&0).clone()),
            ("Low", severity_counts.get(&Severity::Low).unwrap_or(&0).clone()),
            ("Info", severity_counts.get(&Severity::Info).unwrap_or(&0).clone()),
        ];

        let max_count = data.iter().map(|(_, count)| *count).max().unwrap_or(1);

        let mut chart = ChartBuilder::on(&root)
            .caption("Vulnerability Severity Distribution", ("sans-serif", 40))
            .margin(10)
            .x_label_area_size(40)
            .y_label_area_size(50)
            .build_cartesian_2d(0f32..data.len() as f32, 0usize..max_count)?;

        chart.configure_mesh().draw()?;

        chart.draw_series(
            data.iter().enumerate().map(|(i, (label, count))| {
                let color = match label {
                    &"Critical" => &RED,
                    &"High" => &MAGENTA,
                    &"Medium" => &YELLOW,
                    &"Low" => &BLUE,
                    &"Info" => &GREEN,
                    _ => &BLACK,
                };
                Rectangle::new([(i as f32, 0), (i as f32 + 0.8, *count)], color.filled())
            })
        )?
        .label("Vulnerabilities")
        .legend(|(x, y)| PathElement::new(vec![(x, y), (x + 10, y)], &RED));

        chart.configure_series_labels().draw()?;
        root.present()?;

        Ok(())
    }

    #[cfg(feature = "visualization")]
    pub fn create_compliance_chart(&self, compliance_reports: &[ComplianceReport], output_path: &Path) -> crate::Result<()> {
        let root = SVGBackend::new(output_path, (self.config.chart_width, self.config.chart_height)).into_drawing_area();
        root.fill(&WHITE)?;

        let data: Vec<(String, f64)> = compliance_reports.iter()
            .map(|report| (format!("{:?}", report.framework), report.overall_score))
            .collect();

        let mut chart = ChartBuilder::on(&root)
            .caption("Compliance Framework Scores", ("sans-serif", 40))
            .margin(10)
            .x_label_area_size(60)
            .y_label_area_size(50)
            .build_cartesian_2d(0f32..data.len() as f32, 0f64..100f64)?;

        chart.configure_mesh().draw()?;

        chart.draw_series(
            data.iter().enumerate().map(|(i, (framework, score))| {
                let color = if *score >= 90.0 { &GREEN } 
                          else if *score >= 70.0 { &YELLOW } 
                          else { &RED };
                Rectangle::new([(i as f32, 0.0), (i as f32 + 0.8, *score)], color.filled())
            })
        )?
        .label("Compliance Score")
        .legend(|(x, y)| PathElement::new(vec![(x, y), (x + 10, y)], &GREEN));

        chart.configure_series_labels().draw()?;
        root.present()?;

        Ok(())
    }

    pub fn generate_html_dashboard(&self, dashboard: &SecurityDashboard, output_path: &Path) -> crate::Result<()> {
        let html_content = self.create_html_dashboard(dashboard);
        std::fs::write(output_path, html_content)?;
        Ok(())
    }

    fn calculate_vulnerability_summary(&self, vulnerabilities: &[Vulnerability]) -> VulnerabilitySummary {
        let severity_counts = self.count_by_severity(vulnerabilities);
        
        VulnerabilitySummary {
            total_vulnerabilities: vulnerabilities.len(),
            critical_count: severity_counts.get(&Severity::Critical).unwrap_or(&0).clone(),
            high_count: severity_counts.get(&Severity::High).unwrap_or(&0).clone(),
            medium_count: severity_counts.get(&Severity::Medium).unwrap_or(&0).clone(),
            low_count: severity_counts.get(&Severity::Low).unwrap_or(&0).clone(),
            info_count: severity_counts.get(&Severity::Info).unwrap_or(&0).clone(),
        }
    }

    fn calculate_severity_distribution(&self, vulnerabilities: &[Vulnerability]) -> SeverityDistribution {
        let total = vulnerabilities.len() as f64;
        if total == 0.0 {
            return SeverityDistribution {
                critical_percentage: 0.0,
                high_percentage: 0.0,
                medium_percentage: 0.0,
                low_percentage: 0.0,
                info_percentage: 0.0,
            };
        }

        let severity_counts = self.count_by_severity(vulnerabilities);
        
        SeverityDistribution {
            critical_percentage: (*severity_counts.get(&Severity::Critical).unwrap_or(&0) as f64 / total) * 100.0,
            high_percentage: (*severity_counts.get(&Severity::High).unwrap_or(&0) as f64 / total) * 100.0,
            medium_percentage: (*severity_counts.get(&Severity::Medium).unwrap_or(&0) as f64 / total) * 100.0,
            low_percentage: (*severity_counts.get(&Severity::Low).unwrap_or(&0) as f64 / total) * 100.0,
            info_percentage: (*severity_counts.get(&Severity::Info).unwrap_or(&0) as f64 / total) * 100.0,
        }
    }

    fn calculate_language_breakdown(&self, vulnerabilities: &[Vulnerability]) -> LanguageBreakdown {
        let mut language_counts = HashMap::new();
        
        for vuln in vulnerabilities {
            // Extract language from file path extension
            if let Some(ext) = std::path::Path::new(&vuln.file_path).extension() {
                if let Some(ext_str) = ext.to_str() {
                    *language_counts.entry(ext_str.to_string()).or_insert(0) += 1;
                }
            }
        }

        let most_vulnerable_language = language_counts.iter()
            .max_by_key(|(_, count)| *count)
            .map(|(lang, _)| lang.clone())
            .unwrap_or_else(|| "unknown".to_string());

        let safest_language = language_counts.iter()
            .min_by_key(|(_, count)| *count)
            .map(|(lang, _)| lang.clone())
            .unwrap_or_else(|| "unknown".to_string());

        LanguageBreakdown {
            languages: language_counts,
            most_vulnerable_language,
            safest_language,
        }
    }

    fn calculate_category_analysis(&self, vulnerabilities: &[Vulnerability]) -> CategoryAnalysis {
        let mut category_counts = HashMap::new();
        
        for vuln in vulnerabilities {
            *category_counts.entry(vuln.category.clone()).or_insert(0) += 1;
        }

        let top_risk_category = category_counts.iter()
            .max_by_key(|(_, count)| *count)
            .map(|(cat, _)| cat.clone())
            .unwrap_or_else(|| "unknown".to_string());

        // Simulate category trends (in real implementation, this would use historical data)
        let category_trends = category_counts.iter()
            .map(|(cat, count)| (cat.clone(), *count as f64 * 0.1)) // Simulated trend
            .collect();

        CategoryAnalysis {
            categories: category_counts,
            top_risk_category,
            category_trends,
        }
    }

    fn calculate_trend_analysis(&self, vulnerabilities: &[Vulnerability]) -> TrendAnalysis {
        // Simulate trend analysis (in real implementation, this would use historical data)
        let vulnerability_trend = vec![
            ("2024-01".to_string(), vulnerabilities.len()),
            ("2024-02".to_string(), (vulnerabilities.len() as f64 * 0.9) as usize),
            ("2024-03".to_string(), (vulnerabilities.len() as f64 * 0.8) as usize),
        ];

        let mut severity_trends = HashMap::new();
        let severity_counts = self.count_by_severity(vulnerabilities);
        
        for (severity, count) in severity_counts {
            severity_trends.insert(format!("{:?}", severity), vec![
                ("2024-01".to_string(), count),
                ("2024-02".to_string(), (count as f64 * 0.9) as usize),
                ("2024-03".to_string(), (count as f64 * 0.8) as usize),
            ]);
        }

        TrendAnalysis {
            vulnerability_trend,
            severity_trends,
            improvement_rate: 20.0, // 20% improvement simulated
        }
    }

    fn calculate_compliance_status(&self, compliance_reports: &[ComplianceReport]) -> ComplianceStatus {
        let mut frameworks = HashMap::new();
        let mut total_score = 0.0;
        
        for report in compliance_reports {
            frameworks.insert(format!("{:?}", report.framework), report.overall_score);
            total_score += report.overall_score;
        }

        let overall_compliance = if compliance_reports.is_empty() {
            0.0
        } else {
            total_score / compliance_reports.len() as f64
        };

        // Simulate compliance trend
        let compliance_trend = vec![
            ("2024-01".to_string(), overall_compliance * 0.8),
            ("2024-02".to_string(), overall_compliance * 0.9),
            ("2024-03".to_string(), overall_compliance),
        ];

        ComplianceStatus {
            frameworks,
            overall_compliance,
            compliance_trend,
        }
    }

    fn count_by_severity(&self, vulnerabilities: &[Vulnerability]) -> HashMap<Severity, usize> {
        let mut counts = HashMap::new();
        
        for vuln in vulnerabilities {
            *counts.entry(vuln.severity.clone()).or_insert(0) += 1;
        }
        
        counts
    }

    fn create_html_dashboard(&self, dashboard: &SecurityDashboard) -> String {
        format!(r#"
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>DeVAIC Security Dashboard</title>
    <style>
        body {{
            font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif;
            margin: 0;
            padding: 20px;
            background-color: #f5f5f5;
        }}
        .dashboard {{
            max-width: 1200px;
            margin: 0 auto;
        }}
        .header {{
            background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
            color: white;
            padding: 30px;
            border-radius: 10px;
            margin-bottom: 30px;
            text-align: center;
        }}
        .stats-grid {{
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(250px, 1fr));
            gap: 20px;
            margin-bottom: 30px;
        }}
        .stat-card {{
            background: white;
            padding: 25px;
            border-radius: 10px;
            box-shadow: 0 4px 6px rgba(0, 0, 0, 0.1);
            text-align: center;
        }}
        .stat-number {{
            font-size: 2.5em;
            font-weight: bold;
            margin-bottom: 10px;
        }}
        .critical {{ color: #dc3545; }}
        .high {{ color: #fd7e14; }}
        .medium {{ color: #ffc107; }}
        .low {{ color: #17a2b8; }}
        .info {{ color: #28a745; }}
        .compliance-section {{
            background: white;
            padding: 30px;
            border-radius: 10px;
            box-shadow: 0 4px 6px rgba(0, 0, 0, 0.1);
            margin-bottom: 30px;
        }}
        .compliance-bar {{
            background: #e9ecef;
            height: 30px;
            border-radius: 15px;
            overflow: hidden;
            margin: 10px 0;
        }}
        .compliance-fill {{
            height: 100%;
            background: linear-gradient(90deg, #28a745, #20c997);
            transition: width 0.3s ease;
        }}
        .language-grid {{
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(200px, 1fr));
            gap: 15px;
        }}
        .language-item {{
            background: #f8f9fa;
            padding: 15px;
            border-radius: 8px;
            border-left: 4px solid #007bff;
        }}
    </style>
</head>
<body>
    <div class="dashboard">
        <div class="header">
            <h1>🛡️ DeVAIC Security Dashboard</h1>
            <p>Comprehensive Security Analysis Report</p>
        </div>

        <div class="stats-grid">
            <div class="stat-card">
                <div class="stat-number">{}</div>
                <div>Total Vulnerabilities</div>
            </div>
            <div class="stat-card">
                <div class="stat-number critical">{}</div>
                <div>Critical Issues</div>
            </div>
            <div class="stat-card">
                <div class="stat-number high">{}</div>
                <div>High Severity</div>
            </div>
            <div class="stat-card">
                <div class="stat-number medium">{}</div>
                <div>Medium Severity</div>
            </div>
            <div class="stat-card">
                <div class="stat-number low">{}</div>
                <div>Low Severity</div>
            </div>
        </div>

        <div class="compliance-section">
            <h2>📊 Compliance Status</h2>
            <div class="compliance-bar">
                <div class="compliance-fill" style="width: {}%"></div>
            </div>
            <p>Overall Compliance: {:.1}%</p>
            
            <h3>Framework Breakdown:</h3>
            <div class="language-grid">
                {}
            </div>
        </div>

        <div class="compliance-section">
            <h2>🔍 Language Analysis</h2>
            <p><strong>Most Vulnerable:</strong> {}</p>
            <p><strong>Safest Language:</strong> {}</p>
            
            <div class="language-grid">
                {}
            </div>
        </div>

        <div class="compliance-section">
            <h2>📈 Security Trends</h2>
            <p><strong>Improvement Rate:</strong> {:.1}%</p>
            <p><strong>Top Risk Category:</strong> {}</p>
        </div>
    </div>
</body>
</html>
"#,
            dashboard.vulnerability_summary.total_vulnerabilities,
            dashboard.vulnerability_summary.critical_count,
            dashboard.vulnerability_summary.high_count,
            dashboard.vulnerability_summary.medium_count,
            dashboard.vulnerability_summary.low_count,
            dashboard.compliance_status.overall_compliance,
            dashboard.compliance_status.overall_compliance,
            dashboard.compliance_status.frameworks.iter()
                .map(|(framework, score)| format!(
                    r#"<div class="language-item"><strong>{}:</strong> {:.1}%</div>"#,
                    framework, score
                ))
                .collect::<Vec<_>>()
                .join(""),
            dashboard.language_breakdown.most_vulnerable_language,
            dashboard.language_breakdown.safest_language,
            dashboard.language_breakdown.languages.iter()
                .map(|(lang, count)| format!(
                    r#"<div class="language-item"><strong>{}:</strong> {} vulnerabilities</div>"#,
                    lang, count
                ))
                .collect::<Vec<_>>()
                .join(""),
            dashboard.trend_analysis.improvement_rate,
            dashboard.category_analysis.top_risk_category
        )
    }
}

impl Default for VisualizationConfig {
    fn default() -> Self {
        Self {
            output_dir: "reports/visualizations".to_string(),
            chart_width: 800,
            chart_height: 600,
            theme: ChartTheme::Security,
            formats: vec![OutputFormat::SVG, OutputFormat::HTML],
        }
    }
}

#[cfg(not(feature = "visualization"))]
impl VisualizationEngine {
    pub fn create_vulnerability_chart(&self, _vulnerabilities: &[Vulnerability], _output_path: &Path) -> crate::Result<()> {
        Err(crate::error::DevaicError::Analysis("Visualization feature not enabled. Compile with --features visualization".to_string()))
    }

    pub fn create_compliance_chart(&self, _compliance_reports: &[ComplianceReport], _output_path: &Path) -> crate::Result<()> {
        Err(crate::error::DevaicError::Analysis("Visualization feature not enabled. Compile with --features visualization".to_string()))
    }
}