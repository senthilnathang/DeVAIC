/// Intelligent False Positive Reduction System
/// 
/// This module implements ML-powered false positive reduction that learns from
/// user feedback, code patterns, and historical analysis to minimize false alarms
/// while maintaining high detection accuracy.

use std::collections::{HashMap, VecDeque};
use std::sync::{Arc, RwLock, Mutex};
use std::time::{Duration, SystemTime, UNIX_EPOCH};
use serde::{Deserialize, Serialize};
use crate::{Language, Severity, Vulnerability};

/// ML-powered false positive reduction engine
pub struct FalsePositiveReducer {
    feedback_database: Arc<RwLock<FeedbackDatabase>>,
    pattern_analyzer: PatternAnalyzer,
    confidence_calculator: ConfidenceCalculator,
    ml_models: MLModelSet,
    learning_enabled: bool,
    confidence_threshold: f64,
    feedback_history_limit: usize,
}

/// Database storing user feedback on vulnerability classifications
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FeedbackDatabase {
    pub feedback_entries: HashMap<String, VulnerabilityFeedback>,
    pub pattern_classifications: HashMap<String, PatternClassification>,
    pub user_profiles: HashMap<String, UserProfile>,
    pub rule_performance: HashMap<String, RulePerformanceMetrics>,
    pub temporal_trends: Vec<TemporalTrend>,
}

/// User feedback on a specific vulnerability detection
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VulnerabilityFeedback {
    pub vulnerability_id: String,
    pub rule_id: String,
    pub file_path: String,
    pub user_classification: Classification,
    pub confidence: f64,
    pub feedback_timestamp: u64,
    pub user_id: String,
    pub context: FeedbackContext,
    pub fix_applied: bool,
    pub time_to_feedback: Duration,
}

/// Classification of vulnerability accuracy
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum Classification {
    TruePositive,
    FalsePositive,
    FalseNegative,
    Uncertain,
    RequiresReview,
}

/// Context information for feedback
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FeedbackContext {
    pub code_context: String,
    pub surrounding_functions: Vec<String>,
    pub framework_context: Vec<String>,
    pub business_logic_context: String,
    pub security_implications: String,
    pub remediation_effort: RemediationEffort,
}

/// Estimated effort required to fix the issue
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum RemediationEffort {
    Trivial,        // < 15 minutes
    Minor,          // 15-60 minutes
    Moderate,       // 1-4 hours
    Significant,    // 4-24 hours
    Major,          // > 1 day
}

/// Pattern classification for similar code structures
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PatternClassification {
    pub pattern_hash: String,
    pub pattern_type: PatternType,
    pub accuracy_score: f64,
    pub occurrence_count: u64,
    pub languages: Vec<Language>,
    pub typical_classification: Classification,
    pub confidence_distribution: HashMap<Classification, f64>,
    pub last_updated: u64,
}

/// Types of code patterns
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum PatternType {
    ApiUsage,
    DataFlow,
    ControlFlow,
    SecurityCheck,
    InputValidation,
    OutputEncoding,
    AuthenticationPattern,
    AuthorizationPattern,
    CryptographicUsage,
    DatabaseQuery,
    FileOperation,
    NetworkCommunication,
    ErrorHandling,
    ResourceManagement,
}

/// User profile for personalized false positive reduction
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct UserProfile {
    pub user_id: String,
    pub expertise_level: ExpertiseLevel,
    pub domain_knowledge: Vec<SecurityDomain>,
    pub feedback_accuracy: f64,
    pub response_patterns: ResponsePatterns,
    pub preferred_severity_focus: Vec<Severity>,
    pub framework_familiarity: HashMap<String, f64>,
    pub language_expertise: HashMap<Language, f64>,
}

/// User expertise level
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum ExpertiseLevel {
    Beginner,
    Intermediate,
    Advanced,
    Expert,
    SecuritySpecialist,
}

/// Security domain knowledge areas
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum SecurityDomain {
    WebSecurity,
    MobileAppSecurity,
    CloudSecurity,
    CryptographySecurity,
    NetworkSecurity,
    ApplicationSecurity,
    InfrastructureSecurity,
    ComplianceSecurity,
    IncidentResponse,
    ThreatModeling,
}

/// User response patterns for ML learning
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ResponsePatterns {
    pub average_response_time: Duration,
    pub false_positive_rate: f64,
    pub detail_preference: DetailLevel,
    pub batch_review_tendency: f64,
    pub context_usage_frequency: f64,
}

/// Level of detail preference
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum DetailLevel {
    Summary,
    Standard,
    Detailed,
    Comprehensive,
}

/// Rule performance metrics for false positive analysis
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RulePerformanceMetrics {
    pub rule_id: String,
    pub total_detections: u64,
    pub confirmed_true_positives: u64,
    pub confirmed_false_positives: u64,
    pub pending_review: u64,
    pub accuracy_trend: VecDeque<AccuracyPoint>,
    pub pattern_effectiveness: HashMap<PatternType, f64>,
    pub language_performance: HashMap<Language, RuleLanguagePerformance>,
    pub context_sensitivity: ContextSensitivityMetrics,
}

/// Accuracy measurement at a specific time
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AccuracyPoint {
    pub timestamp: u64,
    pub accuracy: f64,
    pub confidence: f64,
    pub sample_size: u64,
}

/// Rule performance for specific language
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RuleLanguagePerformance {
    pub language: Language,
    pub true_positive_rate: f64,
    pub false_positive_rate: f64,
    pub precision: f64,
    pub recall: f64,
    pub f1_score: f64,
}

/// Context sensitivity analysis
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ContextSensitivityMetrics {
    pub framework_sensitivity: HashMap<String, f64>,
    pub business_logic_sensitivity: f64,
    pub code_complexity_correlation: f64,
    pub team_consistency: f64,
}

/// Temporal trend in feedback patterns
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TemporalTrend {
    pub time_period: TimePeriod,
    pub false_positive_rate: f64,
    pub feedback_volume: u64,
    pub accuracy_improvement: f64,
    pub dominant_patterns: Vec<PatternType>,
}

/// Time period for trend analysis
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum TimePeriod {
    Daily,
    Weekly,
    Monthly,
    Quarterly,
    Yearly,
}

/// Pattern analyzer for code structure analysis
pub struct PatternAnalyzer {
    pattern_extractors: HashMap<Language, Box<dyn PatternExtractor>>,
    similarity_threshold: f64,
    pattern_cache: Arc<Mutex<HashMap<String, ExtractedPattern>>>,
}

/// Extracted code pattern for analysis
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ExtractedPattern {
    pub pattern_hash: String,
    pub pattern_type: PatternType,
    pub ast_signature: String,
    pub control_flow_hash: String,
    pub data_flow_hash: String,
    pub api_calls: Vec<String>,
    pub variable_patterns: Vec<String>,
    pub complexity_metrics: ComplexityMetrics,
}

/// Code complexity metrics
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ComplexityMetrics {
    pub cyclomatic_complexity: f64,
    pub nesting_depth: u32,
    pub api_diversity: f64,
    pub branching_factor: f64,
    pub data_flow_complexity: f64,
}

/// Trait for language-specific pattern extraction
pub trait PatternExtractor: Send + Sync {
    fn extract_patterns(&self, code: &str, file_path: &str) -> Vec<ExtractedPattern>;
    fn calculate_similarity(&self, pattern1: &ExtractedPattern, pattern2: &ExtractedPattern) -> f64;
}

/// Confidence calculator for vulnerability accuracy
pub struct ConfidenceCalculator {
    base_confidence_weights: ConfidenceWeights,
    user_expertise_multipliers: HashMap<ExpertiseLevel, f64>,
    temporal_decay_factor: f64,
}

/// Weights for confidence calculation components
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ConfidenceWeights {
    pub rule_historical_accuracy: f64,
    pub pattern_similarity: f64,
    pub user_feedback_history: f64,
    pub code_context_clarity: f64,
    pub team_consensus: f64,
    pub temporal_relevance: f64,
    pub complexity_adjustment: f64,
}

/// ML model set for false positive prediction
pub struct MLModelSet {
    pub pattern_classifier: Box<dyn MLModel>,
    pub context_analyzer: Box<dyn MLModel>,
    pub user_preference_predictor: Box<dyn MLModel>,
    pub severity_adjuster: Box<dyn MLModel>,
    pub ensemble_coordinator: EnsembleCoordinator,
}

/// ML model trait for different prediction tasks
pub trait MLModel: Send + Sync {
    fn predict(&self, features: &[f64]) -> MLPrediction;
    fn train(&mut self, training_data: &[TrainingExample]) -> Result<(), MLError>;
    fn get_feature_importance(&self) -> Vec<f64>;
    fn save_model(&self, path: &str) -> Result<(), MLError>;
    fn load_model(&mut self, path: &str) -> Result<(), MLError>;
}

/// ML prediction result
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MLPrediction {
    pub probability: f64,
    pub confidence: f64,
    pub feature_contributions: Vec<f64>,
    pub decision_boundary_distance: f64,
}

/// Training example for ML models
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TrainingExample {
    pub features: Vec<f64>,
    pub label: f64,
    pub weight: f64,
    pub metadata: TrainingMetadata,
}

/// Metadata for training examples
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TrainingMetadata {
    pub timestamp: u64,
    pub user_id: String,
    pub rule_id: String,
    pub language: Language,
    pub feedback_confidence: f64,
}

/// ML training and prediction errors
#[derive(Debug)]
pub enum MLError {
    InsufficientData,
    ModelNotTrained,
    FeatureMismatch,
    SerializationError(String),
    TrainingError(String),
}

/// Ensemble coordinator for combining multiple models
pub struct EnsembleCoordinator {
    model_weights: HashMap<String, f64>,
    voting_strategy: VotingStrategy,
    confidence_aggregation: ConfidenceAggregation,
}

/// Voting strategies for ensemble models
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum VotingStrategy {
    Majority,
    Weighted,
    Stacking,
    Adaptive,
}

/// Confidence aggregation methods
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum ConfidenceAggregation {
    Average,
    WeightedAverage,
    Maximum,
    Minimum,
    Harmonic,
}

/// Enhanced vulnerability with false positive probability
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EnhancedVulnerability {
    pub vulnerability: Vulnerability,
    pub false_positive_probability: f64,
    pub confidence_score: f64,
    pub contributing_factors: Vec<ConfidenceFactor>,
    pub similar_patterns: Vec<SimilarPattern>,
    pub user_recommendations: Vec<UserRecommendation>,
    pub suggested_actions: Vec<SuggestedAction>,
}

/// Factors contributing to confidence score
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ConfidenceFactor {
    pub factor_type: FactorType,
    pub weight: f64,
    pub contribution: f64,
    pub explanation: String,
}

/// Types of confidence factors
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum FactorType {
    RuleAccuracy,
    PatternSimilarity,
    UserFeedbackHistory,
    CodeContext,
    TeamConsensus,
    TemporalRelevance,
    ComplexityAdjustment,
}

/// Similar pattern found in feedback database
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SimilarPattern {
    pub pattern_hash: String,
    pub similarity_score: f64,
    pub historical_classification: Classification,
    pub occurrence_frequency: u64,
    pub confidence: f64,
}

/// User-specific recommendation
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct UserRecommendation {
    pub recommendation_type: RecommendationType,
    pub priority: Priority,
    pub explanation: String,
    pub estimated_effort: RemediationEffort,
}

/// Types of recommendations
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum RecommendationType {
    Review,
    Ignore,
    HighPriority,
    BatchReview,
    ExpertConsultation,
    AutomaticSuppression,
}

/// Priority levels
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub enum Priority {
    Low,
    Medium,
    High,
    Critical,
}

/// Suggested actions for handling the vulnerability
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SuggestedAction {
    pub action_type: ActionType,
    pub confidence: f64,
    pub description: String,
    pub automation_possible: bool,
}

/// Types of suggested actions
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum ActionType {
    CodeFix,
    ConfigurationChange,
    ProcessImprovement,
    Documentation,
    Testing,
    Monitoring,
    Suppression,
}

impl FalsePositiveReducer {
    /// Create a new false positive reducer
    pub fn new() -> Self {
        Self {
            feedback_database: Arc::new(RwLock::new(FeedbackDatabase::new())),
            pattern_analyzer: PatternAnalyzer::new(),
            confidence_calculator: ConfidenceCalculator::new(),
            ml_models: MLModelSet::new(),
            learning_enabled: true,
            confidence_threshold: 0.7,
            feedback_history_limit: 10000,
        }
    }

    /// Process vulnerabilities to reduce false positives
    pub fn process_vulnerabilities(&self, vulnerabilities: Vec<Vulnerability>) -> Vec<EnhancedVulnerability> {
        vulnerabilities.into_iter()
            .map(|vuln| self.enhance_vulnerability(vuln))
            .collect()
    }

    /// Enhance a single vulnerability with false positive analysis
    pub fn enhance_vulnerability(&self, vulnerability: Vulnerability) -> EnhancedVulnerability {
        let pattern = self.pattern_analyzer.extract_vulnerability_pattern(&vulnerability);
        let similar_patterns = self.find_similar_patterns(&pattern);
        let false_positive_probability = self.calculate_false_positive_probability(&vulnerability, &similar_patterns);
        let confidence_score = self.confidence_calculator.calculate_confidence(&vulnerability, &similar_patterns);
        let contributing_factors = self.analyze_confidence_factors(&vulnerability, &similar_patterns);
        let user_recommendations = self.generate_user_recommendations(&vulnerability, false_positive_probability);
        let suggested_actions = self.generate_suggested_actions(&vulnerability, false_positive_probability);

        EnhancedVulnerability {
            vulnerability,
            false_positive_probability,
            confidence_score,
            contributing_factors,
            similar_patterns,
            user_recommendations,
            suggested_actions,
        }
    }

    /// Record user feedback for continuous learning
    pub fn record_feedback(&self, feedback: VulnerabilityFeedback) -> Result<(), String> {
        if !self.learning_enabled {
            return Ok(());
        }

        let mut db = self.feedback_database.write().map_err(|e| format!("Lock error: {}", e))?;
        
        // Update feedback database
        db.feedback_entries.insert(feedback.vulnerability_id.clone(), feedback.clone());
        
        // Update pattern classifications
        if let Some(pattern) = self.pattern_analyzer.extract_pattern_from_feedback(&feedback) {
            self.update_pattern_classification(&mut db, pattern, &feedback);
        }

        // Update rule performance metrics
        self.update_rule_performance(&mut db, &feedback);

        // Update user profile
        self.update_user_profile(&mut db, &feedback);

        // Train ML models with new feedback
        if db.feedback_entries.len() % 100 == 0 { // Retrain every 100 feedbacks
            self.retrain_models(&db);
        }

        Ok(())
    }

    /// Calculate false positive probability using ML models
    fn calculate_false_positive_probability(&self, vulnerability: &Vulnerability, similar_patterns: &[SimilarPattern]) -> f64 {
        let features = self.extract_features(vulnerability, similar_patterns);
        let prediction = self.ml_models.pattern_classifier.predict(&features);
        
        // Combine with historical data
        let historical_fp_rate = self.get_historical_false_positive_rate(&vulnerability.id);
        let ml_prediction = prediction.probability;
        
        // Weighted combination
        let ml_weight = prediction.confidence;
        let historical_weight = 1.0 - ml_weight;
        
        (ml_prediction * ml_weight + historical_fp_rate * historical_weight).min(1.0).max(0.0)
    }

    /// Find similar patterns in the feedback database
    fn find_similar_patterns(&self, pattern: &ExtractedPattern) -> Vec<SimilarPattern> {
        let db = self.feedback_database.read().unwrap();
        let mut similar_patterns = Vec::new();

        for (pattern_hash, classification) in &db.pattern_classifications {
            let similarity = self.pattern_analyzer.calculate_pattern_similarity(pattern, pattern_hash);
            
            if similarity > self.pattern_analyzer.similarity_threshold {
                similar_patterns.push(SimilarPattern {
                    pattern_hash: pattern_hash.clone(),
                    similarity_score: similarity,
                    historical_classification: classification.typical_classification.clone(),
                    occurrence_frequency: classification.occurrence_count,
                    confidence: classification.accuracy_score,
                });
            }
        }

        // Sort by similarity score (highest first)
        similar_patterns.sort_by(|a, b| b.similarity_score.partial_cmp(&a.similarity_score).unwrap_or(std::cmp::Ordering::Equal));
        similar_patterns.truncate(10); // Keep top 10 most similar patterns
        
        similar_patterns
    }

    /// Extract features for ML prediction
    fn extract_features(&self, vulnerability: &Vulnerability, similar_patterns: &[SimilarPattern]) -> Vec<f64> {
        let mut features = Vec::new();

        // Vulnerability characteristics
        features.push(self.severity_to_numeric(&vulnerability.severity));
        features.push(vulnerability.confidence);
        features.push(vulnerability.line_number as f64);

        // Pattern similarity features
        if !similar_patterns.is_empty() {
            features.push(similar_patterns[0].similarity_score);
            features.push(similar_patterns.iter().map(|p| p.similarity_score).sum::<f64>() / similar_patterns.len() as f64);
            features.push(similar_patterns.len() as f64);
        } else {
            features.extend_from_slice(&[0.0, 0.0, 0.0]);
        }

        // Historical performance
        let rule_performance = self.get_rule_performance(&vulnerability.id);
        features.push(rule_performance.accuracy);
        features.push(rule_performance.false_positive_rate);

        // Code context features
        features.push(vulnerability.source_code.len() as f64);
        features.push(self.calculate_code_complexity(&vulnerability.source_code));

        features
    }

    /// Convert severity to numeric value
    fn severity_to_numeric(&self, severity: &Severity) -> f64 {
        match severity {
            Severity::Critical => 1.0,
            Severity::High => 0.8,
            Severity::Medium => 0.6,
            Severity::Low => 0.4,
            Severity::Info => 0.2,
        }
    }

    /// Get historical false positive rate for a rule
    fn get_historical_false_positive_rate(&self, rule_id: &str) -> f64 {
        let db = self.feedback_database.read().unwrap();
        
        if let Some(metrics) = db.rule_performance.get(rule_id) {
            if metrics.total_detections > 0 {
                return metrics.confirmed_false_positives as f64 / metrics.total_detections as f64;
            }
        }
        
        0.3 // Default assumption if no historical data
    }

    /// Get rule performance metrics
    fn get_rule_performance(&self, rule_id: &str) -> SimplePerformanceMetrics {
        let db = self.feedback_database.read().unwrap();
        
        if let Some(metrics) = db.rule_performance.get(rule_id) {
            let total = metrics.confirmed_true_positives + metrics.confirmed_false_positives;
            if total > 0 {
                return SimplePerformanceMetrics {
                    accuracy: metrics.confirmed_true_positives as f64 / total as f64,
                    false_positive_rate: metrics.confirmed_false_positives as f64 / metrics.total_detections as f64,
                };
            }
        }
        
        SimplePerformanceMetrics {
            accuracy: 0.7, // Default assumption
            false_positive_rate: 0.3,
        }
    }

    /// Calculate basic code complexity
    fn calculate_code_complexity(&self, code: &str) -> f64 {
        let lines = code.lines().count() as f64;
        let tokens = code.split_whitespace().count() as f64;
        let nesting = code.matches('{').count() as f64;
        
        (lines + tokens * 0.1 + nesting * 2.0) / 100.0
    }

    /// Analyze factors contributing to confidence score
    fn analyze_confidence_factors(&self, vulnerability: &Vulnerability, similar_patterns: &[SimilarPattern]) -> Vec<ConfidenceFactor> {
        let mut factors = Vec::new();

        // Rule accuracy factor
        let rule_perf = self.get_rule_performance(&vulnerability.id);
        factors.push(ConfidenceFactor {
            factor_type: FactorType::RuleAccuracy,
            weight: 0.3,
            contribution: rule_perf.accuracy,
            explanation: format!("Rule has {:.1}% historical accuracy", rule_perf.accuracy * 100.0),
        });

        // Pattern similarity factor
        if !similar_patterns.is_empty() {
            let avg_similarity = similar_patterns.iter().map(|p| p.similarity_score).sum::<f64>() / similar_patterns.len() as f64;
            factors.push(ConfidenceFactor {
                factor_type: FactorType::PatternSimilarity,
                weight: 0.25,
                contribution: avg_similarity,
                explanation: format!("Found {} similar patterns with {:.1}% average similarity", similar_patterns.len(), avg_similarity * 100.0),
            });
        }

        // Code context factor
        let context_clarity = self.assess_code_context_clarity(&vulnerability.source_code);
        factors.push(ConfidenceFactor {
            factor_type: FactorType::CodeContext,
            weight: 0.2,
            contribution: context_clarity,
            explanation: format!("Code context clarity: {:.1}%", context_clarity * 100.0),
        });

        factors
    }

    /// Assess clarity of code context
    fn assess_code_context_clarity(&self, code: &str) -> f64 {
        let has_comments = code.contains("//") || code.contains("/*");
        let has_meaningful_names = code.split_whitespace()
            .filter(|word| word.len() > 3 && word.chars().any(|c| c.is_alphabetic()))
            .count() > 0;
        let complexity = self.calculate_code_complexity(code);
        
        let mut clarity: f64 = 0.5; // Base clarity
        if has_comments { clarity += 0.2; }
        if has_meaningful_names { clarity += 0.2; }
        if complexity < 0.5 { clarity += 0.1; } // Simpler code is clearer
        
        clarity.min(1.0)
    }

    /// Generate user-specific recommendations
    fn generate_user_recommendations(&self, vulnerability: &Vulnerability, fp_probability: f64) -> Vec<UserRecommendation> {
        let mut recommendations = Vec::new();

        if fp_probability > 0.8 {
            recommendations.push(UserRecommendation {
                recommendation_type: RecommendationType::Ignore,
                priority: Priority::Low,
                explanation: "High probability of false positive based on similar patterns".to_string(),
                estimated_effort: RemediationEffort::Trivial,
            });
        } else if fp_probability > 0.6 {
            recommendations.push(UserRecommendation {
                recommendation_type: RecommendationType::BatchReview,
                priority: Priority::Medium,
                explanation: "Moderate false positive probability - consider batch review".to_string(),
                estimated_effort: RemediationEffort::Minor,
            });
        } else if fp_probability < 0.2 {
            recommendations.push(UserRecommendation {
                recommendation_type: RecommendationType::HighPriority,
                priority: Priority::High,
                explanation: "Low false positive probability - likely genuine security issue".to_string(),
                estimated_effort: self.estimate_remediation_effort(vulnerability),
            });
        } else {
            recommendations.push(UserRecommendation {
                recommendation_type: RecommendationType::Review,
                priority: Priority::Medium,
                explanation: "Standard review recommended".to_string(),
                estimated_effort: RemediationEffort::Moderate,
            });
        }

        recommendations
    }

    /// Generate suggested actions
    fn generate_suggested_actions(&self, vulnerability: &Vulnerability, fp_probability: f64) -> Vec<SuggestedAction> {
        let mut actions = Vec::new();

        if fp_probability < 0.3 {
            actions.push(SuggestedAction {
                action_type: ActionType::CodeFix,
                confidence: 1.0 - fp_probability,
                description: "Apply security fix to address the vulnerability".to_string(),
                automation_possible: self.can_automate_fix(vulnerability),
            });
        }

        if fp_probability > 0.7 {
            actions.push(SuggestedAction {
                action_type: ActionType::Suppression,
                confidence: fp_probability,
                description: "Consider suppressing this detection as likely false positive".to_string(),
                automation_possible: true,
            });
        }

        actions
    }

    /// Estimate remediation effort
    fn estimate_remediation_effort(&self, vulnerability: &Vulnerability) -> RemediationEffort {
        match vulnerability.severity {
            Severity::Critical => RemediationEffort::Significant,
            Severity::High => RemediationEffort::Moderate,
            Severity::Medium => RemediationEffort::Minor,
            Severity::Low | Severity::Info => RemediationEffort::Trivial,
        }
    }

    /// Check if fix can be automated
    fn can_automate_fix(&self, vulnerability: &Vulnerability) -> bool {
        // Simple heuristics for automation potential
        vulnerability.category.contains("input") || 
        vulnerability.category.contains("validation") ||
        vulnerability.id.contains("simple")
    }

    /// Update pattern classification based on feedback
    fn update_pattern_classification(&self, db: &mut FeedbackDatabase, pattern: ExtractedPattern, feedback: &VulnerabilityFeedback) {
        let classification = db.pattern_classifications.entry(pattern.pattern_hash.clone())
            .or_insert_with(|| PatternClassification {
                pattern_hash: pattern.pattern_hash.clone(),
                pattern_type: pattern.pattern_type,
                accuracy_score: 0.5,
                occurrence_count: 0,
                languages: Vec::new(),
                typical_classification: Classification::Uncertain,
                confidence_distribution: HashMap::new(),
                last_updated: feedback.feedback_timestamp,
            });

        classification.occurrence_count += 1;
        classification.last_updated = feedback.feedback_timestamp;
        
        // Update confidence distribution
        *classification.confidence_distribution.entry(feedback.user_classification.clone()).or_insert(0.0) += 1.0;
        
        // Update typical classification based on majority
        let total_feedback = classification.confidence_distribution.values().sum::<f64>();
        if let Some((dominant_classification, _)) = classification.confidence_distribution.iter()
            .max_by(|a, b| a.1.partial_cmp(b.1).unwrap_or(std::cmp::Ordering::Equal)) {
            classification.typical_classification = dominant_classification.clone();
            classification.accuracy_score = classification.confidence_distribution[dominant_classification] / total_feedback;
        }
    }

    /// Update rule performance metrics
    fn update_rule_performance(&self, db: &mut FeedbackDatabase, feedback: &VulnerabilityFeedback) {
        let metrics = db.rule_performance.entry(feedback.rule_id.clone())
            .or_insert_with(|| RulePerformanceMetrics {
                rule_id: feedback.rule_id.clone(),
                total_detections: 0,
                confirmed_true_positives: 0,
                confirmed_false_positives: 0,
                pending_review: 0,
                accuracy_trend: VecDeque::new(),
                pattern_effectiveness: HashMap::new(),
                language_performance: HashMap::new(),
                context_sensitivity: ContextSensitivityMetrics {
                    framework_sensitivity: HashMap::new(),
                    business_logic_sensitivity: 0.5,
                    code_complexity_correlation: 0.0,
                    team_consistency: 0.0,
                },
            });

        metrics.total_detections += 1;
        
        match feedback.user_classification {
            Classification::TruePositive => metrics.confirmed_true_positives += 1,
            Classification::FalsePositive => metrics.confirmed_false_positives += 1,
            _ => metrics.pending_review += 1,
        }

        // Update accuracy trend
        let current_accuracy = if metrics.confirmed_true_positives + metrics.confirmed_false_positives > 0 {
            metrics.confirmed_true_positives as f64 / (metrics.confirmed_true_positives + metrics.confirmed_false_positives) as f64
        } else {
            0.5
        };

        metrics.accuracy_trend.push_back(AccuracyPoint {
            timestamp: feedback.feedback_timestamp,
            accuracy: current_accuracy,
            confidence: feedback.confidence,
            sample_size: metrics.total_detections,
        });

        if metrics.accuracy_trend.len() > 100 {
            metrics.accuracy_trend.pop_front();
        }
    }

    /// Update user profile based on feedback
    fn update_user_profile(&self, db: &mut FeedbackDatabase, feedback: &VulnerabilityFeedback) {
        let profile = db.user_profiles.entry(feedback.user_id.clone())
            .or_insert_with(|| UserProfile {
                user_id: feedback.user_id.clone(),
                expertise_level: ExpertiseLevel::Intermediate,
                domain_knowledge: Vec::new(),
                feedback_accuracy: 0.5,
                response_patterns: ResponsePatterns {
                    average_response_time: Duration::from_secs(300),
                    false_positive_rate: 0.3,
                    detail_preference: DetailLevel::Standard,
                    batch_review_tendency: 0.5,
                    context_usage_frequency: 0.5,
                },
                preferred_severity_focus: Vec::new(),
                framework_familiarity: HashMap::new(),
                language_expertise: HashMap::new(),
            });

        // Update response patterns
        let current_count = profile.response_patterns.average_response_time.as_secs() as f64;
        let new_time = feedback.time_to_feedback.as_secs() as f64;
        profile.response_patterns.average_response_time = Duration::from_secs_f64(
            (current_count + new_time) / 2.0
        );

        // Update accuracy based on consensus with other users
        // This would be enhanced with more sophisticated consensus algorithms
    }

    /// Retrain ML models with updated feedback data
    fn retrain_models(&self, db: &FeedbackDatabase) {
        let training_examples = self.prepare_training_data(db);
        
        if training_examples.len() >= 50 { // Minimum training data requirement
            // Note: In a real implementation, this would use Arc<Mutex<>> for thread-safe mutable access
            // For now, we'll just log that retraining would occur
            println!("Would retrain pattern classifier with {} examples", training_examples.len());
        }
    }

    /// Prepare training data from feedback database
    fn prepare_training_data(&self, db: &FeedbackDatabase) -> Vec<TrainingExample> {
        let mut examples = Vec::new();

        for feedback in db.feedback_entries.values() {
            let label = match feedback.user_classification {
                Classification::TruePositive => 0.0,
                Classification::FalsePositive => 1.0,
                _ => continue, // Skip uncertain classifications
            };

            // Extract features for this feedback entry
            let features = self.extract_features_from_feedback(feedback, db);
            
            examples.push(TrainingExample {
                features,
                label,
                weight: feedback.confidence,
                metadata: TrainingMetadata {
                    timestamp: feedback.feedback_timestamp,
                    user_id: feedback.user_id.clone(),
                    rule_id: feedback.rule_id.clone(),
                    language: Language::Javascript, // Would extract from context
                    feedback_confidence: feedback.confidence,
                },
            });
        }

        examples
    }

    /// Extract features from feedback for training
    fn extract_features_from_feedback(&self, feedback: &VulnerabilityFeedback, db: &FeedbackDatabase) -> Vec<f64> {
        let mut features = Vec::new();

        // Basic feedback features
        features.push(feedback.confidence);
        features.push(feedback.time_to_feedback.as_secs() as f64);

        // Rule performance features
        if let Some(rule_metrics) = db.rule_performance.get(&feedback.rule_id) {
            features.push(rule_metrics.confirmed_true_positives as f64);
            features.push(rule_metrics.confirmed_false_positives as f64);
            features.push(rule_metrics.total_detections as f64);
        } else {
            features.extend_from_slice(&[0.0, 0.0, 0.0]);
        }

        // User profile features
        if let Some(user_profile) = db.user_profiles.get(&feedback.user_id) {
            features.push(user_profile.feedback_accuracy);
            features.push(user_profile.response_patterns.false_positive_rate);
        } else {
            features.extend_from_slice(&[0.5, 0.3]);
        }

        // Context features
        features.push(feedback.context.code_context.len() as f64);
        features.push(feedback.context.surrounding_functions.len() as f64);

        features
    }

    /// Get analytics on false positive reduction effectiveness
    pub fn get_analytics(&self) -> FPReductionAnalytics {
        let db = self.feedback_database.read().unwrap();
        
        let total_feedback = db.feedback_entries.len();
        let true_positives = db.feedback_entries.values()
            .filter(|f| f.user_classification == Classification::TruePositive)
            .count();
        let false_positives = db.feedback_entries.values()
            .filter(|f| f.user_classification == Classification::FalsePositive)
            .count();

        let accuracy = if true_positives + false_positives > 0 {
            true_positives as f64 / (true_positives + false_positives) as f64
        } else {
            0.0
        };

        let false_positive_rate = if total_feedback > 0 {
            false_positives as f64 / total_feedback as f64
        } else {
            0.0
        };

        FPReductionAnalytics {
            total_feedback_entries: total_feedback,
            accuracy_rate: accuracy,
            false_positive_rate,
            patterns_learned: db.pattern_classifications.len(),
            users_profiled: db.user_profiles.len(),
            rules_analyzed: db.rule_performance.len(),
            improvement_trend: self.calculate_improvement_trend(&db),
        }
    }

    /// Calculate improvement trend over time
    fn calculate_improvement_trend(&self, db: &FeedbackDatabase) -> f64 {
        // Simple implementation - would be enhanced with proper time series analysis
        let recent_accuracy = db.rule_performance.values()
            .filter_map(|metrics| metrics.accuracy_trend.back())
            .map(|point| point.accuracy)
            .sum::<f64>() / db.rule_performance.len().max(1) as f64;

        let historical_accuracy = db.rule_performance.values()
            .filter_map(|metrics| metrics.accuracy_trend.front())
            .map(|point| point.accuracy)
            .sum::<f64>() / db.rule_performance.len().max(1) as f64;

        recent_accuracy - historical_accuracy
    }
}

/// Simple performance metrics structure
#[derive(Debug, Clone, Serialize, Deserialize)]
struct SimplePerformanceMetrics {
    accuracy: f64,
    false_positive_rate: f64,
}

/// Analytics for false positive reduction system
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FPReductionAnalytics {
    pub total_feedback_entries: usize,
    pub accuracy_rate: f64,
    pub false_positive_rate: f64,
    pub patterns_learned: usize,
    pub users_profiled: usize,
    pub rules_analyzed: usize,
    pub improvement_trend: f64,
}

impl FeedbackDatabase {
    fn new() -> Self {
        Self {
            feedback_entries: HashMap::new(),
            pattern_classifications: HashMap::new(),
            user_profiles: HashMap::new(),
            rule_performance: HashMap::new(),
            temporal_trends: Vec::new(),
        }
    }
}

impl PatternAnalyzer {
    fn new() -> Self {
        Self {
            pattern_extractors: HashMap::new(),
            similarity_threshold: 0.7,
            pattern_cache: Arc::new(Mutex::new(HashMap::new())),
        }
    }

    fn extract_vulnerability_pattern(&self, vulnerability: &Vulnerability) -> ExtractedPattern {
        // Simplified pattern extraction - would be enhanced with AST analysis
        ExtractedPattern {
            pattern_hash: format!("{:x}", md5::compute(&vulnerability.source_code)),
            pattern_type: PatternType::ApiUsage, // Would be inferred from code
            ast_signature: "simplified".to_string(),
            control_flow_hash: "simplified".to_string(),
            data_flow_hash: "simplified".to_string(),
            api_calls: vec!["example_api".to_string()],
            variable_patterns: vec!["user_input".to_string()],
            complexity_metrics: ComplexityMetrics {
                cyclomatic_complexity: 2.0,
                nesting_depth: 1,
                api_diversity: 0.5,
                branching_factor: 1.0,
                data_flow_complexity: 0.3,
            },
        }
    }

    fn extract_pattern_from_feedback(&self, feedback: &VulnerabilityFeedback) -> Option<ExtractedPattern> {
        // Would extract pattern from feedback context
        Some(ExtractedPattern {
            pattern_hash: format!("{:x}", md5::compute(&feedback.context.code_context)),
            pattern_type: PatternType::ApiUsage,
            ast_signature: "from_feedback".to_string(),
            control_flow_hash: "from_feedback".to_string(),
            data_flow_hash: "from_feedback".to_string(),
            api_calls: feedback.context.surrounding_functions.clone(),
            variable_patterns: vec!["extracted".to_string()],
            complexity_metrics: ComplexityMetrics {
                cyclomatic_complexity: 1.0,
                nesting_depth: 1,
                api_diversity: 0.3,
                branching_factor: 1.0,
                data_flow_complexity: 0.2,
            },
        })
    }

    fn calculate_pattern_similarity(&self, pattern: &ExtractedPattern, pattern_hash: &str) -> f64 {
        // Simplified similarity calculation
        if pattern.pattern_hash == *pattern_hash {
            1.0
        } else {
            0.3 // Default low similarity
        }
    }
}

impl ConfidenceCalculator {
    fn new() -> Self {
        Self {
            base_confidence_weights: ConfidenceWeights {
                rule_historical_accuracy: 0.3,
                pattern_similarity: 0.25,
                user_feedback_history: 0.2,
                code_context_clarity: 0.15,
                team_consensus: 0.05,
                temporal_relevance: 0.03,
                complexity_adjustment: 0.02,
            },
            user_expertise_multipliers: {
                let mut map = HashMap::new();
                map.insert(ExpertiseLevel::Beginner, 0.7);
                map.insert(ExpertiseLevel::Intermediate, 0.85);
                map.insert(ExpertiseLevel::Advanced, 1.0);
                map.insert(ExpertiseLevel::Expert, 1.2);
                map.insert(ExpertiseLevel::SecuritySpecialist, 1.3);
                map
            },
            temporal_decay_factor: 0.95,
        }
    }

    fn calculate_confidence(&self, vulnerability: &Vulnerability, similar_patterns: &[SimilarPattern]) -> f64 {
        let mut confidence = vulnerability.confidence;

        // Adjust based on similar patterns
        if !similar_patterns.is_empty() {
            let pattern_confidence = similar_patterns.iter()
                .map(|p| p.confidence * p.similarity_score)
                .sum::<f64>() / similar_patterns.len() as f64;
            
            confidence = (confidence + pattern_confidence) / 2.0;
        }

        confidence.min(1.0).max(0.0)
    }
}

impl MLModelSet {
    fn new() -> Self {
        Self {
            pattern_classifier: Box::new(DummyMLModel::new()),
            context_analyzer: Box::new(DummyMLModel::new()),
            user_preference_predictor: Box::new(DummyMLModel::new()),
            severity_adjuster: Box::new(DummyMLModel::new()),
            ensemble_coordinator: EnsembleCoordinator::new(),
        }
    }
}

impl EnsembleCoordinator {
    fn new() -> Self {
        Self {
            model_weights: HashMap::new(),
            voting_strategy: VotingStrategy::Weighted,
            confidence_aggregation: ConfidenceAggregation::WeightedAverage,
        }
    }
}

/// Dummy ML model implementation for compilation
struct DummyMLModel {
    trained: bool,
}

impl DummyMLModel {
    fn new() -> Self {
        Self { trained: false }
    }
}

impl MLModel for DummyMLModel {
    fn predict(&self, features: &[f64]) -> MLPrediction {
        MLPrediction {
            probability: features.get(0).unwrap_or(&0.5) * 0.7, // Simple prediction
            confidence: 0.6,
            feature_contributions: features.to_vec(),
            decision_boundary_distance: 0.3,
        }
    }

    fn train(&mut self, _training_data: &[TrainingExample]) -> Result<(), MLError> {
        self.trained = true;
        Ok(())
    }

    fn get_feature_importance(&self) -> Vec<f64> {
        vec![0.3, 0.2, 0.15, 0.1, 0.25] // Dummy importance scores
    }

    fn save_model(&self, _path: &str) -> Result<(), MLError> {
        Ok(())
    }

    fn load_model(&mut self, _path: &str) -> Result<(), MLError> {
        self.trained = true;
        Ok(())
    }
}

impl Default for FalsePositiveReducer {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_false_positive_reducer_creation() {
        let reducer = FalsePositiveReducer::new();
        assert!(reducer.learning_enabled);
        assert_eq!(reducer.confidence_threshold, 0.7);
    }

    #[test]
    fn test_vulnerability_enhancement() {
        let reducer = FalsePositiveReducer::new();
        let vulnerability = Vulnerability {
            id: "test-1".to_string(),
            title: "Test Vulnerability".to_string(),
            description: "Test description".to_string(),
            severity: Severity::Medium,
            category: "test".to_string(),
            cwe: Some("CWE-79".to_string()),
            owasp: None,
            file_path: "test.js".to_string(),
            line_number: 10,
            column_start: 5,
            column_end: 15,
            source_code: "let x = user_input;".to_string(),
            recommendation: "Validate input".to_string(),
            references: vec![],
            confidence: 0.8,
        };

        let enhanced = reducer.enhance_vulnerability(vulnerability);
        assert!(enhanced.false_positive_probability >= 0.0);
        assert!(enhanced.false_positive_probability <= 1.0);
        assert!(enhanced.confidence_score >= 0.0);
        assert!(enhanced.confidence_score <= 1.0);
        assert!(!enhanced.contributing_factors.is_empty());
    }

    #[test]
    fn test_feedback_recording() {
        let reducer = FalsePositiveReducer::new();
        let feedback = VulnerabilityFeedback {
            vulnerability_id: "test-1".to_string(),
            rule_id: "js_xss".to_string(),
            file_path: "test.js".to_string(),
            user_classification: Classification::TruePositive,
            confidence: 0.9,
            feedback_timestamp: SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_secs(),
            user_id: "user1".to_string(),
            context: FeedbackContext {
                code_context: "function test() { return user_input; }".to_string(),
                surrounding_functions: vec!["test".to_string()],
                framework_context: vec!["React".to_string()],
                business_logic_context: "User input processing".to_string(),
                security_implications: "XSS risk".to_string(),
                remediation_effort: RemediationEffort::Minor,
            },
            fix_applied: false,
            time_to_feedback: Duration::from_secs(300),
        };

        let result = reducer.record_feedback(feedback);
        assert!(result.is_ok());
    }

    #[test]
    fn test_analytics_generation() {
        let reducer = FalsePositiveReducer::new();
        let analytics = reducer.get_analytics();
        
        assert_eq!(analytics.total_feedback_entries, 0);
        assert_eq!(analytics.patterns_learned, 0);
        assert_eq!(analytics.users_profiled, 0);
    }
}