/// Adaptive Rule Prioritization System
/// 
/// This module implements intelligent rule ordering based on historical findings,
/// context awareness, and performance metrics to optimize vulnerability detection.

use std::collections::{HashMap, VecDeque};
use std::sync::{Arc, RwLock};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};
use serde::{Deserialize, Serialize};
use crate::{Language, Severity, Vulnerability};

/// Historical data about rule performance and effectiveness
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RulePerformanceHistory {
    pub rule_id: String,
    pub total_executions: u64,
    pub vulnerabilities_found: u64,
    pub false_positives: u64,
    pub avg_execution_time_ms: f64,
    pub success_rate: f64,
    pub effectiveness_score: f64,
    pub last_successful_detection: Option<u64>, // timestamp
    pub languages_effective: HashMap<Language, f64>, // language -> effectiveness score
    pub severity_distribution: HashMap<Severity, u64>,
    pub recent_performance: VecDeque<RuleExecution>,
}

/// Individual rule execution record
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RuleExecution {
    pub timestamp: u64,
    pub execution_time_ms: u64,
    pub vulnerabilities_found: u32,
    pub false_positives: u32,
    pub language: Language,
    pub file_size: u64,
    pub file_complexity: f64,
}

/// Context information for adaptive rule prioritization
#[derive(Debug, Clone)]
pub struct AnalysisContext {
    pub primary_languages: Vec<Language>,
    pub codebase_size: u64,
    pub frameworks_detected: Vec<String>,
    pub security_focus_areas: Vec<SecurityCategory>,
    pub time_constraints: Option<Duration>,
    pub previous_scan_results: Option<PreviousScanSummary>,
    pub development_phase: DevelopmentPhase,
}

/// Security categories for focused analysis
#[derive(Debug, Clone, PartialEq, Eq, Hash, PartialOrd, Ord, Serialize, Deserialize)]
pub enum SecurityCategory {
    WebSecurity,
    ApiSecurity,
    CryptographicSecurity,
    InputValidation,
    AuthenticationAuthorization,
    DataProtection,
    InfrastructureSecurity,
    DependencyVulnerabilities,
    ConcurrencySafety,
    MemorySafety,
}

/// Development phase context
#[derive(Debug, Clone, PartialEq)]
pub enum DevelopmentPhase {
    Development,
    Testing,
    Staging,
    Production,
    SecurityReview,
    Compliance,
}

/// Summary of previous scan results
#[derive(Debug, Clone)]
pub struct PreviousScanSummary {
    pub total_vulnerabilities: u32,
    pub high_severity_count: u32,
    pub most_common_categories: Vec<SecurityCategory>,
    pub scan_duration: Duration,
    pub timestamp: SystemTime,
}

/// Rule prioritization strategy
#[derive(Debug, Clone)]
pub enum PrioritizationStrategy {
    /// Focus on rules most likely to find vulnerabilities quickly
    HighYield,
    /// Focus on rules that find high-severity vulnerabilities
    HighSeverity,
    /// Balance between speed and thoroughness
    Balanced,
    /// Comprehensive scan prioritizing coverage
    Comprehensive,
    /// Custom strategy with specified weights
    Custom {
        effectiveness_weight: f64,
        speed_weight: f64,
        severity_weight: f64,
        recency_weight: f64,
    },
}

/// Adaptive rule prioritization engine
pub struct AdaptiveRulePrioritizer {
    rule_history: Arc<RwLock<HashMap<String, RulePerformanceHistory>>>,
    context_analyzer: ContextAnalyzer,
    prioritization_strategy: PrioritizationStrategy,
    learning_enabled: bool,
    performance_threshold: f64,
    max_history_entries: usize,
}

/// Context analyzer for codebase characteristics
pub struct ContextAnalyzer {
    language_detectors: HashMap<String, LanguagePattern>,
    framework_detectors: HashMap<String, FrameworkPattern>,
    complexity_analyzers: HashMap<Language, ComplexityAnalyzer>,
}

/// Language detection pattern
#[derive(Debug, Clone)]
pub struct LanguagePattern {
    pub file_extensions: Vec<String>,
    pub characteristic_patterns: Vec<String>,
    pub imports_patterns: Vec<String>,
    pub confidence_threshold: f64,
}

/// Framework detection pattern
#[derive(Debug, Clone)]
pub struct FrameworkPattern {
    pub name: String,
    pub detection_patterns: Vec<String>,
    pub file_indicators: Vec<String>,
    pub security_implications: Vec<SecurityCategory>,
}

/// Code complexity analyzer
#[derive(Debug, Clone)]
pub struct ComplexityAnalyzer {
    pub cyclomatic_complexity_patterns: Vec<String>,
    pub nesting_depth_indicators: Vec<String>,
    pub api_usage_patterns: Vec<String>,
}

impl AdaptiveRulePrioritizer {
    /// Create a new adaptive rule prioritizer
    pub fn new(strategy: PrioritizationStrategy) -> Self {
        Self {
            rule_history: Arc::new(RwLock::new(HashMap::new())),
            context_analyzer: ContextAnalyzer::new(),
            prioritization_strategy: strategy,
            learning_enabled: true,
            performance_threshold: 0.1, // 10% minimum success rate
            max_history_entries: 1000,
        }
    }

    /// Load historical data from persistent storage
    pub fn load_history(&mut self, data: HashMap<String, RulePerformanceHistory>) -> Result<(), Box<dyn std::error::Error>> {
        let mut history = self.rule_history.write().unwrap();
        *history = data;
        Ok(())
    }

    /// Save historical data to persistent storage
    pub fn save_history(&self) -> Result<HashMap<String, RulePerformanceHistory>, Box<dyn std::error::Error>> {
        let history = self.rule_history.read().unwrap();
        Ok(history.clone())
    }

    /// Prioritize rules based on context and historical performance
    pub fn prioritize_rules(&self, available_rules: &[String], context: &AnalysisContext) -> Vec<RulePriority> {
        let history = self.rule_history.read().unwrap();
        let mut priorities = Vec::new();

        for rule_id in available_rules {
            let priority = self.calculate_rule_priority(rule_id, context, &history);
            priorities.push(RulePriority {
                rule_id: rule_id.clone(),
                priority_score: priority.score,
                estimated_execution_time: priority.estimated_time,
                expected_findings: priority.expected_findings,
                confidence: priority.confidence,
                reasoning: priority.reasoning,
            });
        }

        // Sort by priority score (highest first)
        priorities.sort_by(|a, b| b.priority_score.partial_cmp(&a.priority_score).unwrap_or(std::cmp::Ordering::Equal));

        // Apply strategy-specific adjustments
        self.apply_strategy_adjustments(&mut priorities, context);

        priorities
    }

    /// Calculate priority score for a specific rule
    fn calculate_rule_priority(
        &self,
        rule_id: &str,
        context: &AnalysisContext,
        history: &HashMap<String, RulePerformanceHistory>,
    ) -> PriorityCalculation {
        let rule_history = history.get(rule_id);
        
        // Base scores
        let effectiveness_score = self.calculate_effectiveness_score(rule_history, context);
        let speed_score = self.calculate_speed_score(rule_history);
        let severity_score = self.calculate_severity_score(rule_history);
        let recency_score = self.calculate_recency_score(rule_history);
        let context_relevance = self.calculate_context_relevance(rule_id, context);

        // Apply strategy weights
        let weighted_score = match &self.prioritization_strategy {
            PrioritizationStrategy::HighYield => {
                effectiveness_score * 0.5 + speed_score * 0.3 + context_relevance * 0.2
            },
            PrioritizationStrategy::HighSeverity => {
                severity_score * 0.4 + effectiveness_score * 0.3 + context_relevance * 0.3
            },
            PrioritizationStrategy::Balanced => {
                effectiveness_score * 0.3 + speed_score * 0.2 + severity_score * 0.2 + 
                recency_score * 0.1 + context_relevance * 0.2
            },
            PrioritizationStrategy::Comprehensive => {
                effectiveness_score * 0.25 + severity_score * 0.25 + context_relevance * 0.25 + recency_score * 0.25
            },
            PrioritizationStrategy::Custom { effectiveness_weight, speed_weight, severity_weight, recency_weight } => {
                effectiveness_score * effectiveness_weight + speed_score * speed_weight + 
                severity_score * severity_weight + recency_score * recency_weight
            },
        };

        let estimated_time = rule_history
            .map(|h| Duration::from_millis(h.avg_execution_time_ms as u64))
            .unwrap_or(Duration::from_millis(100));

        let expected_findings = rule_history
            .map(|h| (h.success_rate * context_relevance) as u32)
            .unwrap_or(0);

        let confidence = if rule_history.is_some() { 0.8 } else { 0.3 };

        let reasoning = format!(
            "Effectiveness: {:.2}, Speed: {:.2}, Severity: {:.2}, Context: {:.2}",
            effectiveness_score, speed_score, severity_score, context_relevance
        );

        PriorityCalculation {
            score: weighted_score,
            estimated_time,
            expected_findings,
            confidence,
            reasoning,
        }
    }

    /// Calculate effectiveness score based on historical success rate
    fn calculate_effectiveness_score(&self, history: Option<&RulePerformanceHistory>, context: &AnalysisContext) -> f64 {
        match history {
            Some(h) => {
                let base_effectiveness = h.success_rate;
                let language_bonus = context.primary_languages.iter()
                    .map(|lang| h.languages_effective.get(lang).unwrap_or(&0.5))
                    .sum::<f64>() / context.primary_languages.len() as f64;
                
                (base_effectiveness + language_bonus) / 2.0
            },
            None => 0.5, // Default score for new rules
        }
    }

    /// Calculate speed score based on execution time
    fn calculate_speed_score(&self, history: Option<&RulePerformanceHistory>) -> f64 {
        match history {
            Some(h) => {
                // Faster rules get higher scores
                let time_ms = h.avg_execution_time_ms;
                if time_ms <= 10.0 { 1.0 }
                else if time_ms <= 50.0 { 0.8 }
                else if time_ms <= 100.0 { 0.6 }
                else if time_ms <= 500.0 { 0.4 }
                else { 0.2 }
            },
            None => 0.5,
        }
    }

    /// Calculate severity score based on types of vulnerabilities found
    fn calculate_severity_score(&self, history: Option<&RulePerformanceHistory>) -> f64 {
        match history {
            Some(h) => {
                let total_findings = h.severity_distribution.values().sum::<u64>() as f64;
                if total_findings == 0.0 { return 0.0; }

                let weighted_score = h.severity_distribution.iter()
                    .map(|(severity, count)| {
                        let weight = match severity {
                            Severity::Critical => 1.0,
                            Severity::High => 0.8,
                            Severity::Medium => 0.6,
                            Severity::Low => 0.4,
                            Severity::Info => 0.2,
                        };
                        weight * (*count as f64 / total_findings)
                    })
                    .sum::<f64>();

                weighted_score
            },
            None => 0.5,
        }
    }

    /// Calculate recency score based on when rule last found vulnerabilities
    fn calculate_recency_score(&self, history: Option<&RulePerformanceHistory>) -> f64 {
        match history {
            Some(h) => {
                match h.last_successful_detection {
                    Some(timestamp) => {
                        let now = SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_secs();
                        let days_ago = (now - timestamp) / (24 * 3600);
                        
                        if days_ago <= 7 { 1.0 }
                        else if days_ago <= 30 { 0.8 }
                        else if days_ago <= 90 { 0.6 }
                        else if days_ago <= 365 { 0.4 }
                        else { 0.2 }
                    },
                    None => 0.3,
                }
            },
            None => 0.5,
        }
    }

    /// Calculate context relevance for the rule
    fn calculate_context_relevance(&self, rule_id: &str, context: &AnalysisContext) -> f64 {
        // This would be enhanced with actual rule metadata
        // For now, we'll use simple heuristics based on rule naming
        let rule_lower = rule_id.to_lowercase();
        let mut relevance: f64 = 0.5; // Base relevance

        // Language relevance
        for language in &context.primary_languages {
            let lang_str = format!("{:?}", language).to_lowercase();
            if rule_lower.contains(&lang_str) {
                relevance += 0.2;
            }
        }

        // Framework relevance
        for framework in &context.frameworks_detected {
            if rule_lower.contains(&framework.to_lowercase()) {
                relevance += 0.15;
            }
        }

        // Security category relevance
        for category in &context.security_focus_areas {
            let category_str = format!("{:?}", category).to_lowercase();
            if rule_lower.contains(&category_str) || 
               rule_lower.contains(&category_str.replace("security", "")) {
                relevance += 0.1;
            }
        }

        relevance.min(1.0)
    }

    /// Apply strategy-specific adjustments to priorities
    fn apply_strategy_adjustments(&self, priorities: &mut [RulePriority], context: &AnalysisContext) {
        match &self.prioritization_strategy {
            PrioritizationStrategy::HighYield => {
                // Boost rules with high expected findings
                for priority in priorities.iter_mut() {
                    if priority.expected_findings > 0 {
                        priority.priority_score *= 1.2;
                    }
                }
            },
            PrioritizationStrategy::HighSeverity => {
                // Boost rules that typically find high-severity issues
                for priority in priorities.iter_mut() {
                    if priority.rule_id.to_lowercase().contains("critical") || 
                       priority.rule_id.to_lowercase().contains("high") {
                        priority.priority_score *= 1.3;
                    }
                }
            },
            _ => {} // Other strategies don't need post-processing
        }

        // Apply time constraints if specified
        if let Some(time_limit) = context.time_constraints {
            let mut cumulative_time = Duration::ZERO;
            for priority in priorities.iter_mut() {
                cumulative_time += priority.estimated_execution_time;
                if cumulative_time > time_limit {
                    priority.priority_score *= 0.5; // Reduce priority for rules that won't fit
                }
            }
        }
    }

    /// Record execution results for learning
    pub fn record_execution(&self, rule_id: &str, execution: RuleExecution, vulnerabilities: &[Vulnerability]) {
        if !self.learning_enabled {
            return;
        }

        let mut history = self.rule_history.write().unwrap();
        let rule_history = history.entry(rule_id.to_string()).or_insert_with(|| {
            RulePerformanceHistory {
                rule_id: rule_id.to_string(),
                total_executions: 0,
                vulnerabilities_found: 0,
                false_positives: 0,
                avg_execution_time_ms: 0.0,
                success_rate: 0.0,
                effectiveness_score: 0.0,
                last_successful_detection: None,
                languages_effective: HashMap::new(),
                severity_distribution: HashMap::new(),
                recent_performance: VecDeque::new(),
            }
        });

        // Update execution count and timing
        rule_history.total_executions += 1;
        rule_history.avg_execution_time_ms = (rule_history.avg_execution_time_ms * (rule_history.total_executions - 1) as f64 + 
                                             execution.execution_time_ms as f64) / rule_history.total_executions as f64;

        // Update vulnerability counts and severity distribution
        let new_vulns = vulnerabilities.len() as u64;
        rule_history.vulnerabilities_found += new_vulns;
        
        for vuln in vulnerabilities {
            *rule_history.severity_distribution.entry(vuln.severity.clone()).or_insert(0) += 1;
        }

        // Update language effectiveness
        let lang_effectiveness = rule_history.languages_effective.entry(execution.language).or_insert(0.0);
        *lang_effectiveness = (*lang_effectiveness * 0.9) + (execution.vulnerabilities_found as f64 * 0.1);

        // Update success rate and last successful detection
        rule_history.success_rate = rule_history.vulnerabilities_found as f64 / rule_history.total_executions as f64;
        if execution.vulnerabilities_found > 0 {
            rule_history.last_successful_detection = Some(execution.timestamp);
        }

        // Add to recent performance (keep limited history)
        rule_history.recent_performance.push_back(execution);
        if rule_history.recent_performance.len() > self.max_history_entries {
            rule_history.recent_performance.pop_front();
        }

        // Calculate overall effectiveness score
        rule_history.effectiveness_score = self.calculate_overall_effectiveness(rule_history);
    }

    /// Calculate overall effectiveness score for a rule
    fn calculate_overall_effectiveness(&self, history: &RulePerformanceHistory) -> f64 {
        let success_rate_weight = 0.4;
        let severity_weight = 0.3;
        let recency_weight = 0.2;
        let consistency_weight = 0.1;

        let success_component = history.success_rate * success_rate_weight;

        let severity_component = {
            let total_findings = history.severity_distribution.values().sum::<u64>() as f64;
            if total_findings > 0.0 {
                history.severity_distribution.iter()
                    .map(|(severity, count)| {
                        let severity_value = match severity {
                            Severity::Critical => 1.0,
                            Severity::High => 0.8,
                            Severity::Medium => 0.6,
                            Severity::Low => 0.4,
                            Severity::Info => 0.2,
                        };
                        severity_value * (*count as f64 / total_findings)
                    })
                    .sum::<f64>() * severity_weight
            } else {
                0.0
            }
        };

        let recency_component = match history.last_successful_detection {
            Some(timestamp) => {
                let now = SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_secs();
                let days_ago = (now - timestamp) / (24 * 3600);
                let recency_score = if days_ago <= 30 { 1.0 } else { 0.5 };
                recency_score * recency_weight
            },
            None => 0.0,
        };

        let consistency_component = {
            if history.recent_performance.len() >= 5 {
                let recent_success_rates: Vec<f64> = history.recent_performance.iter()
                    .map(|exec| if exec.vulnerabilities_found > 0 { 1.0 } else { 0.0 })
                    .collect();
                let mean = recent_success_rates.iter().sum::<f64>() / recent_success_rates.len() as f64;
                let variance = recent_success_rates.iter()
                    .map(|x| (x - mean).powi(2))
                    .sum::<f64>() / recent_success_rates.len() as f64;
                let consistency = 1.0 - variance; // Lower variance = higher consistency
                consistency * consistency_weight
            } else {
                0.5 * consistency_weight // Default consistency for new rules
            }
        };

        success_component + severity_component + recency_component + consistency_component
    }

    /// Get rules that are underperforming and should be deprioritized
    pub fn get_underperforming_rules(&self) -> Vec<String> {
        let history = self.rule_history.read().unwrap();
        history.values()
            .filter(|h| h.total_executions >= 10 && h.effectiveness_score < self.performance_threshold)
            .map(|h| h.rule_id.clone())
            .collect()
    }

    /// Generate prioritization analytics and insights
    pub fn generate_analytics(&self) -> PrioritizationAnalytics {
        let history = self.rule_history.read().unwrap();
        
        let total_rules = history.len();
        let effective_rules = history.values().filter(|h| h.effectiveness_score > 0.5).count();
        let top_performers: Vec<_> = {
            let mut performers: Vec<_> = history.values().collect();
            performers.sort_by(|a, b| b.effectiveness_score.partial_cmp(&a.effectiveness_score).unwrap_or(std::cmp::Ordering::Equal));
            performers.into_iter().take(10).map(|h| (h.rule_id.clone(), h.effectiveness_score)).collect()
        };

        let language_effectiveness: HashMap<Language, f64> = {
            let mut lang_scores: HashMap<Language, Vec<f64>> = HashMap::new();
            for rule in history.values() {
                for (lang, score) in &rule.languages_effective {
                    lang_scores.entry(*lang).or_default().push(*score);
                }
            }
            lang_scores.into_iter()
                .map(|(lang, scores)| (lang, scores.iter().sum::<f64>() / scores.len() as f64))
                .collect()
        };

        PrioritizationAnalytics {
            total_rules,
            effective_rules,
            effectiveness_rate: effective_rules as f64 / total_rules as f64,
            top_performing_rules: top_performers,
            language_effectiveness,
            strategy_used: format!("{:?}", self.prioritization_strategy),
        }
    }
}

/// Rule priority information
#[derive(Debug, Clone)]
pub struct RulePriority {
    pub rule_id: String,
    pub priority_score: f64,
    pub estimated_execution_time: Duration,
    pub expected_findings: u32,
    pub confidence: f64,
    pub reasoning: String,
}

/// Internal priority calculation result
#[derive(Debug)]
struct PriorityCalculation {
    pub score: f64,
    pub estimated_time: Duration,
    pub expected_findings: u32,
    pub confidence: f64,
    pub reasoning: String,
}

/// Analytics about prioritization effectiveness
#[derive(Debug, Clone)]
pub struct PrioritizationAnalytics {
    pub total_rules: usize,
    pub effective_rules: usize,
    pub effectiveness_rate: f64,
    pub top_performing_rules: Vec<(String, f64)>,
    pub language_effectiveness: HashMap<Language, f64>,
    pub strategy_used: String,
}

impl ContextAnalyzer {
    /// Create a new context analyzer
    pub fn new() -> Self {
        Self {
            language_detectors: Self::initialize_language_detectors(),
            framework_detectors: Self::initialize_framework_detectors(),
            complexity_analyzers: Self::initialize_complexity_analyzers(),
        }
    }

    /// Analyze codebase context for adaptive prioritization
    pub fn analyze_context(&self, file_paths: &[&str], file_contents: &[&str]) -> AnalysisContext {
        let primary_languages = self.detect_primary_languages(file_paths, file_contents);
        let codebase_size = file_contents.iter().map(|content| content.len() as u64).sum();
        let frameworks_detected = self.detect_frameworks(file_contents);
        let security_focus_areas = self.infer_security_focus_areas(&primary_languages, &frameworks_detected);

        AnalysisContext {
            primary_languages,
            codebase_size,
            frameworks_detected,
            security_focus_areas,
            time_constraints: None,
            previous_scan_results: None,
            development_phase: DevelopmentPhase::Development,
        }
    }

    /// Detect primary languages in the codebase
    fn detect_primary_languages(&self, file_paths: &[&str], file_contents: &[&str]) -> Vec<Language> {
        let mut language_scores: HashMap<Language, f64> = HashMap::new();

        for (path, content) in file_paths.iter().zip(file_contents.iter()) {
            // Simple extension-based detection for now
            let extension = std::path::Path::new(path)
                .extension()
                .and_then(|ext| ext.to_str())
                .unwrap_or("");
                
            let lang = match extension {
                "rs" => Some(Language::Rust),
                "js" | "mjs" => Some(Language::Javascript), 
                "py" => Some(Language::Python),
                "java" => Some(Language::Java),
                "cpp" | "cc" | "cxx" => Some(Language::Cpp),
                "c" => Some(Language::C),
                "go" => Some(Language::Go),
                "php" => Some(Language::Php),
                "rb" => Some(Language::Ruby),
                _ => None,
            };
            
            if let Some(lang) = lang {
                let content_score = self.calculate_language_confidence(&lang, content);
                *language_scores.entry(lang).or_insert(0.0) += content_score;
            }
        }

        let mut languages: Vec<_> = language_scores.into_iter().collect();
        languages.sort_by(|a, b| b.1.partial_cmp(&a.1).unwrap_or(std::cmp::Ordering::Equal));
        languages.into_iter().take(5).map(|(lang, _)| lang).collect()
    }

    /// Calculate confidence score for language detection
    fn calculate_language_confidence(&self, language: &Language, content: &str) -> f64 {
        // Simple heuristic based on content patterns
        match language {
            Language::Rust => {
                let rust_patterns = ["fn ", "let ", "mut ", "use ", "impl ", "struct ", "enum "];
                self.count_pattern_matches(content, &rust_patterns) as f64
            },
            Language::Javascript => {
                let js_patterns = ["function ", "const ", "let ", "var ", "=>", "require(", "import "];
                self.count_pattern_matches(content, &js_patterns) as f64
            },
            Language::Python => {
                let py_patterns = ["def ", "import ", "from ", "class ", "if __name__", "print("];
                self.count_pattern_matches(content, &py_patterns) as f64
            },
            _ => 1.0, // Default confidence for other languages
        }
    }

    /// Count pattern matches in content
    fn count_pattern_matches(&self, content: &str, patterns: &[&str]) -> usize {
        patterns.iter().map(|pattern| content.matches(pattern).count()).sum()
    }

    /// Detect frameworks used in the codebase
    fn detect_frameworks(&self, file_contents: &[&str]) -> Vec<String> {
        let mut frameworks = Vec::new();
        
        for content in file_contents {
            // React detection
            if content.contains("import React") || content.contains("from 'react'") {
                frameworks.push("React".to_string());
            }
            
            // Express.js detection
            if content.contains("express()") || content.contains("require('express')") {
                frameworks.push("Express".to_string());
            }
            
            // Django detection
            if content.contains("from django") || content.contains("import django") {
                frameworks.push("Django".to_string());
            }
            
            // Spring Boot detection
            if content.contains("@SpringBootApplication") || content.contains("import org.springframework") {
                frameworks.push("Spring Boot".to_string());
            }
        }
        
        frameworks.sort();
        frameworks.dedup();
        frameworks
    }

    /// Infer security focus areas based on languages and frameworks
    fn infer_security_focus_areas(&self, languages: &[Language], frameworks: &[String]) -> Vec<SecurityCategory> {
        let mut focus_areas = Vec::new();

        // Language-based focus areas
        for language in languages {
            match language {
                Language::Javascript => {
                    focus_areas.extend_from_slice(&[
                        SecurityCategory::WebSecurity,
                        SecurityCategory::InputValidation,
                        SecurityCategory::ApiSecurity,
                    ]);
                },
                Language::Rust | Language::C | Language::Cpp => {
                    focus_areas.extend_from_slice(&[
                        SecurityCategory::MemorySafety,
                        SecurityCategory::ConcurrencySafety,
                    ]);
                },
                Language::Python | Language::Java => {
                    focus_areas.extend_from_slice(&[
                        SecurityCategory::WebSecurity,
                        SecurityCategory::ApiSecurity,
                        SecurityCategory::DependencyVulnerabilities,
                    ]);
                },
                _ => {},
            }
        }

        // Framework-based focus areas
        for framework in frameworks {
            match framework.as_str() {
                "React" | "Vue" | "Angular" => {
                    focus_areas.push(SecurityCategory::WebSecurity);
                },
                "Express" | "Django" | "Spring Boot" => {
                    focus_areas.extend_from_slice(&[
                        SecurityCategory::ApiSecurity,
                        SecurityCategory::AuthenticationAuthorization,
                        SecurityCategory::InputValidation,
                    ]);
                },
                _ => {},
            }
        }

        // Always include these fundamental categories
        focus_areas.extend_from_slice(&[
            SecurityCategory::InputValidation,
            SecurityCategory::DataProtection,
        ]);

        focus_areas.sort();
        focus_areas.dedup();
        focus_areas
    }

    /// Initialize language detection patterns
    fn initialize_language_detectors() -> HashMap<String, LanguagePattern> {
        let mut detectors = HashMap::new();
        
        detectors.insert("rust".to_string(), LanguagePattern {
            file_extensions: vec!["rs".to_string()],
            characteristic_patterns: vec!["fn ".to_string(), "let ".to_string(), "impl ".to_string()],
            imports_patterns: vec!["use ".to_string(), "extern crate".to_string()],
            confidence_threshold: 0.8,
        });

        detectors.insert("javascript".to_string(), LanguagePattern {
            file_extensions: vec!["js".to_string(), "mjs".to_string()],
            characteristic_patterns: vec!["function ".to_string(), "const ".to_string(), "=>".to_string()],
            imports_patterns: vec!["import ".to_string(), "require(".to_string()],
            confidence_threshold: 0.7,
        });

        detectors
    }

    /// Initialize framework detection patterns
    fn initialize_framework_detectors() -> HashMap<String, FrameworkPattern> {
        let mut detectors = HashMap::new();
        
        detectors.insert("react".to_string(), FrameworkPattern {
            name: "React".to_string(),
            detection_patterns: vec!["import React".to_string(), "from 'react'".to_string()],
            file_indicators: vec!["package.json".to_string()],
            security_implications: vec![SecurityCategory::WebSecurity, SecurityCategory::InputValidation],
        });

        detectors
    }

    /// Initialize complexity analyzers
    fn initialize_complexity_analyzers() -> HashMap<Language, ComplexityAnalyzer> {
        let mut analyzers = HashMap::new();
        
        analyzers.insert(Language::Rust, ComplexityAnalyzer {
            cyclomatic_complexity_patterns: vec!["if ".to_string(), "match ".to_string(), "loop ".to_string()],
            nesting_depth_indicators: vec!["{".to_string(), "}".to_string()],
            api_usage_patterns: vec!["unsafe ".to_string(), "transmute".to_string()],
        });

        analyzers
    }
}

impl Default for ContextAnalyzer {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_prioritizer_creation() {
        let prioritizer = AdaptiveRulePrioritizer::new(PrioritizationStrategy::Balanced);
        assert!(prioritizer.learning_enabled);
        assert_eq!(prioritizer.performance_threshold, 0.1);
    }

    #[test]
    fn test_context_analysis() {
        let analyzer = ContextAnalyzer::new();
        let file_paths = &["src/main.rs", "src/lib.rs"];
        let file_contents = &["fn main() { println!(\"Hello\"); }", "pub fn test() {}"];
        
        let context = analyzer.analyze_context(file_paths, file_contents);
        assert!(context.primary_languages.contains(&Language::Rust));
        assert!(context.codebase_size > 0);
    }

    #[test]
    fn test_rule_prioritization() {
        let prioritizer = AdaptiveRulePrioritizer::new(PrioritizationStrategy::HighYield);
        let rules = vec!["sql_injection".to_string(), "xss_detection".to_string()];
        let context = AnalysisContext {
            primary_languages: vec![Language::Javascript],
            codebase_size: 10000,
            frameworks_detected: vec!["React".to_string()],
            security_focus_areas: vec![SecurityCategory::WebSecurity],
            time_constraints: None,
            previous_scan_results: None,
            development_phase: DevelopmentPhase::Development,
        };

        let priorities = prioritizer.prioritize_rules(&rules, &context);
        assert_eq!(priorities.len(), 2);
        assert!(priorities[0].priority_score >= 0.0);
    }

    #[test]
    fn test_execution_recording() {
        let prioritizer = AdaptiveRulePrioritizer::new(PrioritizationStrategy::Balanced);
        let execution = RuleExecution {
            timestamp: SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_secs(),
            execution_time_ms: 50,
            vulnerabilities_found: 2,
            false_positives: 0,
            language: Language::Rust,
            file_size: 1000,
            file_complexity: 0.5,
        };

        let vulnerabilities = vec![
            Vulnerability {
                id: "test-1".to_string(),
                title: "Test Vulnerability".to_string(),
                description: "Test".to_string(),
                severity: Severity::High,
                category: "test".to_string(),
                cwe: None,
                owasp: None,
                file_path: "test.rs".to_string(),
                line_number: 10,
                column_start: 0,
                column_end: 10,
                source_code: "test code".to_string(),
                recommendation: "Fix this".to_string(),
                references: vec![],
                confidence: 0.9,
            }
        ];

        prioritizer.record_execution("test_rule", execution, &vulnerabilities);
        
        // Verify data was recorded
        let analytics = prioritizer.generate_analytics();
        assert_eq!(analytics.total_rules, 1);
    }
}