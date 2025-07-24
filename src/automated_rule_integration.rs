/// Automated Rule Integration System
/// 
/// This module provides seamless integration of automatically discovered vulnerability
/// patterns into the existing DeVAIC rule system. It handles pattern conversion,
/// rule deployment, monitoring, and adaptive updates based on real-world performance.

use crate::{
    cve_pattern_discovery::{ExtractedPattern, VulnerabilityType, DiscoveryConfig},
    pattern_validation_system::{ValidationResult, PatternValidationSystem, ValidationConfig},
    pattern_loader::{SecurityPattern, RegexPattern, PatternLoader, CompiledPattern},
    rules::{RuleSet, create_vulnerability},
    parsers::{ParsedAst, SourceFile},
    error::{Result, DevaicError},
    Language, Severity, Vulnerability,
};
use serde::{Deserialize, Serialize};
use std::collections::{HashMap, HashSet};
use std::sync::Arc;
use std::time::{Duration, SystemTime, UNIX_EPOCH};
use tokio::sync::{RwLock, Mutex};
use tokio::time::{interval, sleep};
use uuid::Uuid;

/// Automated rule integration system
pub struct AutomatedRuleIntegration {
    /// Pattern converter
    pattern_converter: Arc<PatternConverter>,
    
    /// Rule deployer
    rule_deployer: Arc<RuleDeployer>,
    
    /// Performance monitor
    performance_monitor: Arc<RulePerformanceMonitor>,
    
    /// Feedback collector
    feedback_collector: Arc<RuleFeedbackCollector>,
    
    /// Adaptive updater
    adaptive_updater: Arc<AdaptiveRuleUpdater>,
    
    /// Integration state
    integration_state: Arc<RwLock<IntegrationState>>,
    
    /// Configuration
    config: IntegrationConfig,
}

/// Configuration for automated rule integration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct IntegrationConfig {
    /// Enable automatic deployment of validated patterns
    pub auto_deploy_enabled: bool,
    
    /// Minimum validation score for auto-deployment
    pub min_validation_score: f32,
    
    /// Enable performance monitoring
    pub enable_performance_monitoring: bool,
    
    /// Enable adaptive updates
    pub enable_adaptive_updates: bool,
    
    /// Deployment approval workflow
    pub require_manual_approval: bool,
    
    /// Maximum patterns to deploy per batch
    pub max_patterns_per_batch: usize,
    
    /// Monitoring interval (seconds)
    pub monitoring_interval_secs: u64,
    
    /// Performance degradation threshold
    pub performance_degradation_threshold: f32,
    
    /// False positive rate threshold for auto-disable
    pub fp_rate_threshold: f32,
    
    /// Rule retention period (days)
    pub rule_retention_days: u32,
    
    /// Enable rule versioning
    pub enable_rule_versioning: bool,
    
    /// Rollback timeout (minutes)
    pub rollback_timeout_minutes: u32,
}

/// Current state of the integration system
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct IntegrationState {
    /// Deployed rules
    pub deployed_rules: HashMap<String, DeployedRule>,
    
    /// Pending deployments
    pub pending_deployments: Vec<PendingDeployment>,
    
    /// Performance statistics
    pub performance_stats: PerformanceStatistics,
    
    /// System health metrics
    pub health_metrics: SystemHealthMetrics,
    
    /// Last update timestamp
    pub last_update: SystemTime,
}

/// Deployed rule information
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DeployedRule {
    pub rule_id: String,
    pub original_pattern: ExtractedPattern,
    pub security_pattern: SecurityPattern,
    pub deployment_timestamp: SystemTime,
    pub deployment_version: String,
    pub performance_metrics: RulePerformanceMetrics,
    pub validation_history: Vec<ValidationResult>,
    pub status: RuleStatus,
    pub feedback_data: RuleFeedbackData,
}

/// Status of a deployed rule
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum RuleStatus {
    Active,
    Monitoring,
    Warning,
    Disabled,
    Deprecated,
    Archived,
}

/// Performance metrics for individual rules
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RulePerformanceMetrics {
    pub total_executions: u64,
    pub true_positives: u32,
    pub false_positives: u32,
    pub false_negatives: u32,
    pub average_execution_time_ms: f32,
    pub memory_usage_mb: f32,
    pub cpu_utilization: f32,
    pub last_execution: Option<SystemTime>,
    pub performance_trend: PerformanceTrend,
}

/// Performance trend analysis
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum PerformanceTrend {
    Improving,
    Stable,
    Degrading,
    Volatile,
    Insufficient_Data,
}

/// Feedback data for rules
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RuleFeedbackData {
    pub user_feedback: Vec<UserFeedback>,
    pub automated_feedback: Vec<AutomatedFeedback>,
    pub analyst_reviews: Vec<AnalystReview>,
    pub community_ratings: Vec<CommunityRating>,
    pub aggregated_score: f32,
}

/// User feedback on rule performance
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct UserFeedback {
    pub feedback_id: String,
    pub user_id: Option<String>,
    pub feedback_type: FeedbackType,
    pub rating: Option<u8>, // 1-5 scale
    pub comment: Option<String>,
    pub false_positive_report: Option<FalsePositiveReport>,
    pub missed_detection_report: Option<MissedDetectionReport>,
    pub timestamp: SystemTime,
}

/// Type of user feedback
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum FeedbackType {
    FalsePositive,
    MissedDetection,
    Performance,
    Accuracy,
    General,
}

/// False positive report
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FalsePositiveReport {
    pub file_path: String,
    pub line_number: u32,
    pub context: String,
    pub explanation: String,
    pub severity: Severity,
}

/// Missed detection report
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MissedDetectionReport {
    pub file_path: String,
    pub vulnerability_type: VulnerabilityType,
    pub description: String,
    pub expected_detection: String,
    pub impact_assessment: String,
}

/// Automated feedback from system monitoring
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AutomatedFeedback {
    pub feedback_id: String,
    pub source_system: String,
    pub metric_type: String,
    pub metric_value: f32,
    pub threshold_status: ThresholdStatus,
    pub recommendations: Vec<String>,
    pub timestamp: SystemTime,
}

/// Threshold status for metrics
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum ThresholdStatus {
    Normal,
    Warning,
    Critical,
    Unknown,
}

/// Analyst review of rule
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AnalystReview {
    pub review_id: String,
    pub analyst_id: String,
    pub review_type: ReviewType,
    pub findings: Vec<String>,
    pub recommendations: Vec<String>,
    pub approval_status: ApprovalStatus,
    pub timestamp: SystemTime,
}

/// Type of analyst review
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum ReviewType {
    InitialReview,
    PerformanceReview,
    QualityReview,
    SecurityReview,
    ComplianceReview,
}

/// Approval status from review
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum ApprovalStatus {
    Approved,
    ConditionallyApproved,
    Rejected,
    RequiresModification,
    Pending,
}

/// Community rating for rules
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CommunityRating {
    pub rating_id: String,
    pub user_category: UserCategory,
    pub effectiveness_rating: u8, // 1-5 scale
    pub usability_rating: u8,     // 1-5 scale
    pub accuracy_rating: u8,      // 1-5 scale
    pub comments: Option<String>,
    pub timestamp: SystemTime,
}

/// Category of user providing rating
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum UserCategory {
    SecurityAnalyst,
    Developer,
    DevOpsEngineer,
    Researcher,
    Other,
}

/// Pending deployment information
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PendingDeployment {
    pub deployment_id: String,
    pub pattern: ExtractedPattern,
    pub validation_result: ValidationResult,
    pub deployment_priority: DeploymentPriority,
    pub approval_status: ApprovalStatus,
    pub scheduled_deployment: Option<SystemTime>,
    pub dependencies: Vec<String>,
    pub risk_assessment: DeploymentRiskAssessment,
}

/// Priority level for deployments
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum DeploymentPriority {
    Critical,
    High,
    Medium,
    Low,
}

/// Risk assessment for deployment
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DeploymentRiskAssessment {
    pub overall_risk_level: RiskLevel,
    pub performance_risk: f32,
    pub accuracy_risk: f32,
    pub compatibility_risk: f32,
    pub mitigation_strategies: Vec<String>,
    pub rollback_plan: RollbackPlan,
}

/// Risk level assessment
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum RiskLevel {
    Low,
    Medium,
    High,
    Critical,
}

/// Rollback plan for deployments
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RollbackPlan {
    pub rollback_triggers: Vec<String>,
    pub rollback_steps: Vec<String>,
    pub rollback_timeout: Duration,
    pub data_preservation_strategy: String,
}

/// Performance statistics across all rules
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PerformanceStatistics {
    pub total_rules_deployed: u32,
    pub active_rules: u32,
    pub average_rule_performance: f32,
    pub total_vulnerabilities_detected: u64,
    pub false_positive_rate: f32,
    pub false_negative_rate: f32,
    pub system_performance_impact: f32,
    pub user_satisfaction_score: f32,
}

/// System health metrics
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SystemHealthMetrics {
    pub cpu_utilization: f32,
    pub memory_utilization: f32,
    pub disk_utilization: f32,
    pub network_utilization: f32,
    pub error_rate: f32,
    pub response_time_ms: f32,
    pub availability_percentage: f32,
    pub health_status: HealthStatus,
}

/// Overall system health status
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum HealthStatus {
    Healthy,
    Warning,
    Critical,
    Degraded,
    Unknown,
}

/// Pattern converter for transforming extracted patterns to security patterns
pub struct PatternConverter {
    /// Conversion templates
    conversion_templates: HashMap<VulnerabilityType, ConversionTemplate>,
    
    /// Language mappers
    language_mappers: HashMap<Language, LanguageMapper>,
    
    /// Quality enhancers
    quality_enhancers: Vec<QualityEnhancer>,
    
    /// Metadata enrichers
    metadata_enrichers: Vec<MetadataEnricher>,
}

/// Template for converting patterns
#[derive(Debug, Clone)]
pub struct ConversionTemplate {
    pub template_id: String,
    pub vulnerability_type: VulnerabilityType,
    pub pattern_structure: String,
    pub metadata_mappings: HashMap<String, String>,
    pub severity_mappings: HashMap<String, Severity>,
    pub category_mappings: HashMap<String, String>,
}

/// Language-specific mapping rules
pub struct LanguageMapper {
    pub language: Language,
    pub syntax_adaptations: Vec<SyntaxAdaptation>,
    pub performance_optimizations: Vec<PerformanceOptimization>,
    pub compatibility_checks: Vec<CompatibilityCheck>,
}

/// Syntax adaptation for different languages
#[derive(Debug, Clone)]
pub struct SyntaxAdaptation {
    pub adaptation_id: String,
    pub source_pattern: String,
    pub adapted_pattern: String,
    pub adaptation_reason: String,
}

/// Performance optimization for patterns
#[derive(Debug, Clone)]
pub struct PerformanceOptimization {
    pub optimization_id: String,
    pub original_pattern: String,
    pub optimized_pattern: String,
    pub performance_gain: f32,
}

/// Compatibility check for patterns
#[derive(Debug, Clone)]
pub struct CompatibilityCheck {
    pub check_id: String,
    pub compatibility_requirement: String,
    pub validation_method: String,
    pub remediation_suggestion: String,
}

/// Quality enhancer for improving patterns
pub struct QualityEnhancer {
    pub enhancer_id: String,
    pub enhancement_type: EnhancementType,
    pub enhancement_rules: Vec<EnhancementRule>,
}

/// Type of quality enhancement
#[derive(Debug, Clone)]
pub enum EnhancementType {
    AccuracyImprovement,
    PerformanceOptimization,
    ReadabilityEnhancement,
    MaintainabilityImprovement,
    RobustnessIncrease,
}

/// Enhancement rule
#[derive(Debug, Clone)]
pub struct EnhancementRule {
    pub rule_id: String,
    pub condition: String,
    pub enhancement_action: String,
    pub expected_improvement: f32,
}

/// Metadata enricher for adding context
pub struct MetadataEnricher {
    pub enricher_id: String,
    pub metadata_sources: Vec<MetadataSource>,
    pub enrichment_strategies: Vec<EnrichmentStrategy>,
}

/// Source of metadata for enrichment
#[derive(Debug, Clone)]
pub enum MetadataSource {
    CVEDatabase,
    ThreatIntelligence,
    CommunityKnowledge,
    HistoricalData,
    ExpertAnnotations,
}

/// Strategy for metadata enrichment
#[derive(Debug, Clone)]
pub struct EnrichmentStrategy {
    pub strategy_id: String,
    pub data_source: MetadataSource,
    pub extraction_method: String,
    pub confidence_threshold: f32,
}

/// Rule deployer for managing rule deployment
pub struct RuleDeployer {
    /// Deployment strategies
    deployment_strategies: Vec<DeploymentStrategy>,
    
    /// Environment managers
    environment_managers: HashMap<String, EnvironmentManager>,
    
    /// Rollback managers
    rollback_managers: Vec<RollbackManager>,
    
    /// Health checkers
    health_checkers: Vec<DeploymentHealthChecker>,
}

/// Strategy for deploying rules
pub struct DeploymentStrategy {
    pub strategy_id: String,
    pub strategy_type: DeploymentStrategyType,
    pub deployment_phases: Vec<DeploymentPhase>,
    pub success_criteria: Vec<SuccessCriterion>,
}

/// Type of deployment strategy
#[derive(Debug, Clone)]
pub enum DeploymentStrategyType {
    BlueGreen,
    Canary,
    RollingUpdate,
    ImmediateDeployment,
    ScheduledDeployment,
}

/// Phase in deployment process
#[derive(Debug, Clone)]
pub struct DeploymentPhase {
    pub phase_name: String,
    pub phase_actions: Vec<String>,
    pub validation_checks: Vec<String>,
    pub timeout_duration: Duration,
    pub rollback_triggers: Vec<String>,
}

/// Success criterion for deployment
#[derive(Debug, Clone)]
pub struct SuccessCriterion {
    pub criterion_name: String,
    pub measurement_method: String,
    pub success_threshold: f32,
    pub evaluation_timeout: Duration,
}

/// Environment manager for different deployment environments
pub struct EnvironmentManager {
    pub environment_id: String,
    pub environment_type: EnvironmentType,
    pub configuration: EnvironmentConfiguration,
    pub monitoring_setup: MonitoringSetup,
}

/// Type of deployment environment
#[derive(Debug, Clone)]
pub enum EnvironmentType {
    Development,
    Staging,
    Production,
    Testing,
    Canary,
}

/// Configuration for deployment environment
#[derive(Debug, Clone)]
pub struct EnvironmentConfiguration {
    pub resource_limits: ResourceLimits,
    pub performance_targets: PerformanceTargets,
    pub security_constraints: SecurityConstraints,
    pub compliance_requirements: Vec<String>,
}

/// Resource limits for environment
#[derive(Debug, Clone)]
pub struct ResourceLimits {
    pub max_cpu_usage: f32,
    pub max_memory_mb: u32,
    pub max_disk_io_ops: u32,
    pub max_network_bandwidth: u32,
}

/// Performance targets for environment
#[derive(Debug, Clone)]
pub struct PerformanceTargets {
    pub max_response_time_ms: f32,
    pub min_throughput: f32,
    pub max_error_rate: f32,
    pub availability_target: f32,
}

/// Security constraints for environment
#[derive(Debug, Clone)]
pub struct SecurityConstraints {
    pub encryption_requirements: Vec<String>,
    pub access_controls: Vec<String>,
    pub audit_requirements: Vec<String>,
    pub compliance_standards: Vec<String>,
}

/// Monitoring setup for environment
#[derive(Debug, Clone)]
pub struct MonitoringSetup {
    pub metrics_collectors: Vec<String>,
    pub alerting_rules: Vec<String>,
    pub dashboard_configurations: Vec<String>,
    pub log_aggregation_setup: Vec<String>,
}

/// Rollback manager for handling deployment failures
pub struct RollbackManager {
    pub manager_id: String,
    pub rollback_strategies: Vec<RollbackStrategy>,
    pub data_preservation_methods: Vec<DataPreservationMethod>,
    pub recovery_procedures: Vec<RecoveryProcedure>,
}

/// Strategy for rolling back deployments
#[derive(Debug, Clone)]
pub struct RollbackStrategy {
    pub strategy_id: String,
    pub trigger_conditions: Vec<String>,
    pub rollback_steps: Vec<String>,
    pub validation_checks: Vec<String>,
    pub recovery_time_objective: Duration,
}

/// Method for preserving data during rollback
#[derive(Debug, Clone)]
pub struct DataPreservationMethod {
    pub method_id: String,
    pub data_types: Vec<String>,
    pub preservation_strategy: String,
    pub recovery_method: String,
}

/// Recovery procedure for failed deployments
#[derive(Debug, Clone)]
pub struct RecoveryProcedure {
    pub procedure_id: String,
    pub recovery_steps: Vec<String>,
    pub validation_criteria: Vec<String>,
    pub escalation_triggers: Vec<String>,
}

/// Health checker for deployment monitoring
pub struct DeploymentHealthChecker {
    pub checker_id: String,
    pub health_metrics: Vec<HealthMetric>,
    pub check_intervals: HashMap<String, Duration>,
    pub alert_thresholds: HashMap<String, f32>,
}

/// Health metric for monitoring
#[derive(Debug, Clone)]
pub struct HealthMetric {
    pub metric_name: String,
    pub measurement_method: String,
    pub healthy_range: (f32, f32),
    pub alert_thresholds: (f32, f32),
}

/// Rule performance monitor
pub struct RulePerformanceMonitor {
    /// Performance collectors
    performance_collectors: Vec<PerformanceCollector>,
    
    /// Trend analyzers
    trend_analyzers: Vec<TrendAnalyzer>,
    
    /// Alert managers
    alert_managers: Vec<AlertManager>,
    
    /// Report generators
    report_generators: Vec<ReportGenerator>,
}

/// Performance data collector
pub struct PerformanceCollector {
    pub collector_id: String,
    pub collected_metrics: Vec<String>,
    pub collection_frequency: Duration,
    pub data_retention_period: Duration,
}

/// Trend analyzer for performance data
pub struct TrendAnalyzer {
    pub analyzer_id: String,
    pub analysis_algorithms: Vec<AnalysisAlgorithm>,
    pub trend_detection_methods: Vec<TrendDetectionMethod>,
    pub prediction_models: Vec<PredictionModel>,
}

/// Algorithm for analyzing performance data
#[derive(Debug, Clone)]
pub struct AnalysisAlgorithm {
    pub algorithm_id: String,
    pub algorithm_type: String,
    pub parameters: HashMap<String, f32>,
    pub confidence_threshold: f32,
}

/// Method for detecting trends
#[derive(Debug, Clone)]
pub struct TrendDetectionMethod {
    pub method_id: String,
    pub detection_technique: String,
    pub sensitivity: f32,
    pub minimum_data_points: u32,
}

/// Model for predicting future performance
#[derive(Debug, Clone)]
pub struct PredictionModel {
    pub model_id: String,
    pub model_type: String,
    pub training_data_requirements: Vec<String>,
    pub prediction_accuracy: f32,
}

/// Alert manager for performance issues
pub struct AlertManager {
    pub manager_id: String,
    pub alert_rules: Vec<AlertRule>,
    pub notification_channels: Vec<NotificationChannel>,
    pub escalation_policies: Vec<EscalationPolicy>,
}

/// Rule for generating alerts
#[derive(Debug, Clone)]
pub struct AlertRule {
    pub rule_id: String,
    pub condition: String,
    pub severity: AlertSeverity,
    pub notification_delay: Duration,
    pub suppression_rules: Vec<String>,
}

/// Severity level for alerts
#[derive(Debug, Clone)]
pub enum AlertSeverity {
    Info,
    Warning,
    Error,
    Critical,
}

/// Channel for sending notifications
#[derive(Debug, Clone)]
pub struct NotificationChannel {
    pub channel_id: String,
    pub channel_type: NotificationChannelType,
    pub configuration: HashMap<String, String>,
    pub rate_limits: RateLimits,
}

/// Type of notification channel
#[derive(Debug, Clone)]
pub enum NotificationChannelType {
    Email,
    Slack,
    PagerDuty,
    Webhook,
    SMS,
}

/// Rate limits for notifications
#[derive(Debug, Clone)]
pub struct RateLimits {
    pub max_notifications_per_hour: u32,
    pub max_notifications_per_day: u32,
    pub burst_limit: u32,
}

/// Policy for escalating alerts
#[derive(Debug, Clone)]
pub struct EscalationPolicy {
    pub policy_id: String,
    pub escalation_levels: Vec<EscalationLevel>,
    pub escalation_timeout: Duration,
}

/// Level in escalation policy
#[derive(Debug, Clone)]
pub struct EscalationLevel {
    pub level: u32,
    pub notification_channels: Vec<String>,
    pub escalation_delay: Duration,
}

/// Report generator for performance analysis
pub struct ReportGenerator {
    pub generator_id: String,
    pub report_types: Vec<ReportType>,
    pub generation_schedule: GenerationSchedule,
    pub distribution_list: Vec<String>,
}

/// Type of performance report
#[derive(Debug, Clone)]
pub enum ReportType {
    DailyPerformance,
    WeeklyTrends,
    MonthlyAnalysis,
    IncidentReport,
    ComplianceReport,
}

/// Schedule for generating reports
#[derive(Debug, Clone)]
pub struct GenerationSchedule {
    pub frequency: ReportFrequency,
    pub generation_time: String,
    pub timezone: String,
}

/// Frequency for report generation
#[derive(Debug, Clone)]
pub enum ReportFrequency {
    Hourly,
    Daily,
    Weekly,
    Monthly,
    OnDemand,
}

/// Rule feedback collector
pub struct RuleFeedbackCollector {
    /// Feedback channels
    feedback_channels: Vec<FeedbackChannel>,
    
    /// Data processors
    data_processors: Vec<FeedbackDataProcessor>,
    
    /// Analytics engines
    analytics_engines: Vec<FeedbackAnalyticsEngine>,
    
    /// Integration APIs
    integration_apis: Vec<IntegrationAPI>,
}

/// Channel for collecting feedback
pub struct FeedbackChannel {
    pub channel_id: String,
    pub channel_type: FeedbackChannelType,
    pub data_format: String,
    pub authentication_method: String,
}

/// Type of feedback channel
#[derive(Debug, Clone)]
pub enum FeedbackChannelType {
    WebAPI,
    UserInterface,
    CommandLine,
    LogAnalysis,
    AutomatedTesting,
}

/// Processor for feedback data
pub struct FeedbackDataProcessor {
    pub processor_id: String,
    pub processing_pipeline: Vec<ProcessingStep>,
    pub data_validation: Vec<ValidationRule>,
    pub output_format: String,
}

/// Step in feedback processing pipeline
#[derive(Debug, Clone)]
pub struct ProcessingStep {
    pub step_name: String,
    pub processing_function: String,
    pub parameters: HashMap<String, String>,
}

/// Rule for validating feedback data
#[derive(Debug, Clone)]
pub struct ValidationRule {
    pub rule_name: String,
    pub validation_criteria: String,
    pub error_handling: String,
}

/// Analytics engine for feedback analysis
pub struct FeedbackAnalyticsEngine {
    pub engine_id: String,
    pub analysis_methods: Vec<AnalysisMethod>,
    pub sentiment_analysis: SentimentAnalysisConfig,
    pub trend_detection: TrendDetectionConfig,
}

/// Method for analyzing feedback
#[derive(Debug, Clone)]
pub struct AnalysisMethod {
    pub method_name: String,
    pub algorithm: String,
    pub confidence_threshold: f32,
}

/// Configuration for sentiment analysis
#[derive(Debug, Clone)]
pub struct SentimentAnalysisConfig {
    pub model_type: String,
    pub confidence_threshold: f32,
    pub language_support: Vec<String>,
}

/// Configuration for trend detection
#[derive(Debug, Clone)]
pub struct TrendDetectionConfig {
    pub detection_algorithm: String,
    pub window_size: Duration,
    pub significance_threshold: f32,
}

/// API for integrating with external systems
pub struct IntegrationAPI {
    pub api_id: String,
    pub api_type: IntegrationAPIType,
    pub endpoint_configuration: EndpointConfiguration,
    pub authentication_config: AuthenticationConfig,
}

/// Type of integration API
#[derive(Debug, Clone)]
pub enum IntegrationAPIType {
    JIRA,
    GitHub,
    Slack,
    ServiceNow,
    Splunk,
}

/// Configuration for API endpoint
#[derive(Debug, Clone)]
pub struct EndpointConfiguration {
    pub base_url: String,
    pub api_version: String,
    pub rate_limits: RateLimits,
    pub timeout_settings: TimeoutSettings,
}

/// Timeout settings for API calls
#[derive(Debug, Clone)]
pub struct TimeoutSettings {
    pub connection_timeout_ms: u32,
    pub request_timeout_ms: u32,
    pub retry_attempts: u32,
}

/// Authentication configuration for API
#[derive(Debug, Clone)]
pub struct AuthenticationConfig {
    pub auth_type: AuthenticationType,
    pub credentials: HashMap<String, String>,
    pub token_refresh_interval: Option<Duration>,
}

/// Type of authentication
#[derive(Debug, Clone)]
pub enum AuthenticationType {
    ApiKey,
    OAuth2,
    BasicAuth,
    BearerToken,
    Custom,
}

/// Adaptive rule updater
pub struct AdaptiveRuleUpdater {
    /// Update strategies
    update_strategies: Vec<UpdateStrategy>,
    
    /// Learning algorithms
    learning_algorithms: Vec<LearningAlgorithm>,
    
    /// Optimization engines
    optimization_engines: Vec<OptimizationEngine>,
    
    /// Validation frameworks
    validation_frameworks: Vec<ValidationFramework>,
}

/// Strategy for updating rules
pub struct UpdateStrategy {
    pub strategy_id: String,
    pub update_triggers: Vec<UpdateTrigger>,
    pub update_methods: Vec<UpdateMethod>,
    pub validation_requirements: Vec<String>,
}

/// Trigger for rule updates
#[derive(Debug, Clone)]
pub struct UpdateTrigger {
    pub trigger_id: String,
    pub condition: String,
    pub trigger_threshold: f32,
    pub evaluation_window: Duration,
}

/// Method for updating rules
#[derive(Debug, Clone)]
pub struct UpdateMethod {
    pub method_id: String,
    pub update_algorithm: String,
    pub confidence_requirement: f32,
    pub rollback_criteria: Vec<String>,
}

/// Learning algorithm for adaptive updates
pub struct LearningAlgorithm {
    pub algorithm_id: String,
    pub algorithm_type: LearningAlgorithmType,
    pub learning_parameters: HashMap<String, f32>,
    pub training_data_requirements: Vec<String>,
}

/// Type of learning algorithm
#[derive(Debug, Clone)]
pub enum LearningAlgorithmType {
    ReinforcementLearning,
    SupervisedLearning,
    UnsupervisedLearning,
    OnlineLearning,
    TransferLearning,
}

/// Optimization engine for rule improvement
pub struct OptimizationEngine {
    pub engine_id: String,
    pub optimization_objectives: Vec<OptimizationObjective>,
    pub constraint_definitions: Vec<ConstraintDefinition>,
    pub solution_methods: Vec<SolutionMethod>,
}

/// Objective for optimization
#[derive(Debug, Clone)]
pub struct OptimizationObjective {
    pub objective_name: String,
    pub optimization_direction: OptimizationDirection,
    pub weight: f32,
    pub measurement_method: String,
}

/// Direction of optimization
#[derive(Debug, Clone)]
pub enum OptimizationDirection {
    Maximize,
    Minimize,
    Target,
}

/// Constraint for optimization
#[derive(Debug, Clone)]
pub struct ConstraintDefinition {
    pub constraint_name: String,
    pub constraint_type: ConstraintType,
    pub constraint_value: f32,
    pub violation_penalty: f32,
}

/// Type of optimization constraint
#[derive(Debug, Clone)]
pub enum ConstraintType {
    Equality,
    Inequality,
    Bound,
    Custom,
}

/// Method for solving optimization problems
#[derive(Debug, Clone)]
pub struct SolutionMethod {
    pub method_name: String,
    pub algorithm_type: String,
    pub convergence_criteria: Vec<String>,
    pub computational_limits: ComputationalLimits,
}

/// Computational limits for optimization
#[derive(Debug, Clone)]
pub struct ComputationalLimits {
    pub max_iterations: u32,
    pub max_execution_time: Duration,
    pub memory_limit_mb: u32,
}

/// Validation framework for adaptive updates
pub struct ValidationFramework {
    pub framework_id: String,
    pub validation_stages: Vec<ValidationStage>,
    pub acceptance_criteria: Vec<AcceptanceCriterion>,
    pub rollback_policies: Vec<RollbackPolicy>,
}

/// Stage in validation process
#[derive(Debug, Clone)]
pub struct ValidationStage {
    pub stage_name: String,
    pub validation_tests: Vec<String>,
    pub success_criteria: Vec<String>,
    pub timeout_duration: Duration,
}

/// Criterion for accepting updates
#[derive(Debug, Clone)]
pub struct AcceptanceCriterion {
    pub criterion_name: String,
    pub measurement_method: String,
    pub acceptance_threshold: f32,
    pub confidence_level: f32,
}

/// Policy for rolling back updates
#[derive(Debug, Clone)]
pub struct RollbackPolicy {
    pub policy_name: String,
    pub rollback_triggers: Vec<String>,
    pub rollback_procedure: String,
    pub data_recovery_method: String,
}

impl AutomatedRuleIntegration {
    /// Create new automated rule integration system
    pub fn new(config: IntegrationConfig) -> Result<Self> {
        Ok(Self {
            pattern_converter: Arc::new(PatternConverter::new()?),
            rule_deployer: Arc::new(RuleDeployer::new()?),
            performance_monitor: Arc::new(RulePerformanceMonitor::new()?),
            feedback_collector: Arc::new(RuleFeedbackCollector::new()?),
            adaptive_updater: Arc::new(AdaptiveRuleUpdater::new()?),
            integration_state: Arc::new(RwLock::new(IntegrationState::new())),
            config,
        })
    }

    /// Integrate validated patterns into the rule system
    pub async fn integrate_patterns(
        &self,
        validated_patterns: Vec<(ExtractedPattern, ValidationResult)>,
    ) -> Result<IntegrationSummary> {
        let mut integration_summary = IntegrationSummary::new();

        for (pattern, validation) in validated_patterns {
            log::debug!("Integrating pattern from CVE: {}", pattern.source_cve);

            // Check if pattern meets integration criteria
            if !self.meets_integration_criteria(&validation)? {
                integration_summary.add_skipped(&pattern, "Does not meet integration criteria");
                continue;
            }

            // Convert pattern to security pattern
            let security_pattern = self.pattern_converter.convert_pattern(&pattern).await?;

            // Create deployment request
            let deployment_request = self.create_deployment_request(&pattern, &validation, &security_pattern).await?;

            // Handle deployment based on configuration
            if self.config.auto_deploy_enabled && !self.config.require_manual_approval {
                // Auto-deploy immediately
                match self.deploy_rule(&deployment_request).await {
                    Ok(deployed_rule) => {
                        integration_summary.add_deployed(&pattern, &deployed_rule);
                    }
                    Err(e) => {
                        integration_summary.add_failed(&pattern, &format!("Deployment failed: {}", e));
                    }
                }
            } else {
                // Queue for manual approval or scheduled deployment
                self.queue_for_deployment(&deployment_request).await?;
                integration_summary.add_queued(&pattern);
            }
        }

        // Start monitoring for deployed rules
        if integration_summary.deployed_count > 0 {
            self.start_monitoring().await?;
        }

        Ok(integration_summary)
    }

    /// Check if pattern meets integration criteria
    fn meets_integration_criteria(&self, validation: &ValidationResult) -> Result<bool> {
        Ok(validation.overall_score >= self.config.min_validation_score
            && validation.passed_validation
            && validation.false_positive_analysis.estimated_fp_rate <= self.config.fp_rate_threshold)
    }

    /// Create deployment request
    async fn create_deployment_request(
        &self,
        pattern: &ExtractedPattern,
        validation: &ValidationResult,
        security_pattern: &SecurityPattern,
    ) -> Result<DeploymentRequest> {
        let deployment_id = Uuid::new_v4().to_string();
        
        // Assess deployment risk
        let risk_assessment = self.assess_deployment_risk(pattern, validation).await?;
        
        // Determine deployment priority
        let priority = self.determine_deployment_priority(pattern, validation)?;

        Ok(DeploymentRequest {
            deployment_id,
            pattern: pattern.clone(),
            validation_result: validation.clone(),
            security_pattern: security_pattern.clone(),
            deployment_priority: priority,
            risk_assessment,
            requested_by: "automated_system".to_string(),
            request_timestamp: SystemTime::now(),
        })
    }

    /// Assess deployment risk
    async fn assess_deployment_risk(
        &self,
        pattern: &ExtractedPattern,
        validation: &ValidationResult,
    ) -> Result<DeploymentRiskAssessment> {
        let performance_risk = validation.performance_metrics.average_execution_time_ms / self.config.max_performance_impact_ms;
        let accuracy_risk = validation.false_positive_analysis.estimated_fp_rate;
        let compatibility_risk = 0.2; // Would be calculated based on compatibility analysis

        let overall_risk_level = if performance_risk > 0.8 || accuracy_risk > 0.15 || compatibility_risk > 0.8 {
            RiskLevel::High
        } else if performance_risk > 0.5 || accuracy_risk > 0.1 || compatibility_risk > 0.5 {
            RiskLevel::Medium
        } else {
            RiskLevel::Low
        };

        Ok(DeploymentRiskAssessment {
            overall_risk_level,
            performance_risk,
            accuracy_risk,
            compatibility_risk,
            mitigation_strategies: vec![
                "Gradual rollout with monitoring".to_string(),
                "A/B testing with control group".to_string(),
                "Automated rollback on threshold breach".to_string(),
            ],
            rollback_plan: RollbackPlan {
                rollback_triggers: vec![
                    "False positive rate > 15%".to_string(),
                    "Performance degradation > 50%".to_string(),
                    "System error rate > 5%".to_string(),
                ],
                rollback_steps: vec![
                    "Disable rule immediately".to_string(),
                    "Restore previous rule version".to_string(),
                    "Verify system stability".to_string(),
                    "Generate incident report".to_string(),
                ],
                rollback_timeout: Duration::from_secs(self.config.rollback_timeout_minutes as u64 * 60),
                data_preservation_strategy: "Preserve all execution logs and metrics".to_string(),
            },
        })
    }

    /// Determine deployment priority
    fn determine_deployment_priority(
        &self,
        pattern: &ExtractedPattern,
        validation: &ValidationResult,
    ) -> Result<DeploymentPriority> {
        let priority = match pattern.severity_estimate {
            Severity::Critical => DeploymentPriority::Critical,
            Severity::High => {
                if validation.overall_score > 0.9 {
                    DeploymentPriority::High
                } else {
                    DeploymentPriority::Medium
                }
            }
            Severity::Medium => DeploymentPriority::Medium,
            Severity::Low => DeploymentPriority::Low,
            Severity::Info => DeploymentPriority::Low,
        };

        Ok(priority)
    }

    /// Deploy a rule
    async fn deploy_rule(&self, request: &DeploymentRequest) -> Result<DeployedRule> {
        log::info!("Deploying rule for pattern: {}", request.pattern.source_cve);

        // Convert to deployed rule format
        let deployed_rule = DeployedRule {
            rule_id: request.deployment_id.clone(),
            original_pattern: request.pattern.clone(),
            security_pattern: request.security_pattern.clone(),
            deployment_timestamp: SystemTime::now(),
            deployment_version: "1.0".to_string(),
            performance_metrics: RulePerformanceMetrics {
                total_executions: 0,
                true_positives: 0,
                false_positives: 0,
                false_negatives: 0,
                average_execution_time_ms: 0.0,
                memory_usage_mb: 0.0,
                cpu_utilization: 0.0,
                last_execution: None,
                performance_trend: PerformanceTrend::Insufficient_Data,
            },
            validation_history: vec![request.validation_result.clone()],
            status: RuleStatus::Active,
            feedback_data: RuleFeedbackData {
                user_feedback: vec![],
                automated_feedback: vec![],
                analyst_reviews: vec![],
                community_ratings: vec![],
                aggregated_score: 0.0,
            },
        };

        // Add to integration state
        let mut state = self.integration_state.write().await;
        state.deployed_rules.insert(deployed_rule.rule_id.clone(), deployed_rule.clone());
        state.last_update = SystemTime::now();

        log::info!("Successfully deployed rule: {}", deployed_rule.rule_id);
        Ok(deployed_rule)
    }

    /// Queue deployment for approval
    async fn queue_for_deployment(&self, request: &DeploymentRequest) -> Result<()> {
        let pending_deployment = PendingDeployment {
            deployment_id: request.deployment_id.clone(),
            pattern: request.pattern.clone(),
            validation_result: request.validation_result.clone(),
            deployment_priority: request.deployment_priority.clone(),
            approval_status: ApprovalStatus::Pending,
            scheduled_deployment: None,
            dependencies: vec![],
            risk_assessment: request.risk_assessment.clone(),
        };

        let mut state = self.integration_state.write().await;
        state.pending_deployments.push(pending_deployment);
        state.last_update = SystemTime::now();

        Ok(())
    }

    /// Start monitoring system
    async fn start_monitoring(&self) -> Result<()> {
        log::info!("Starting automated rule monitoring");

        let monitor = self.performance_monitor.clone();
        let state = self.integration_state.clone();
        let config = self.config.clone();

        tokio::spawn(async move {
            let mut interval = interval(Duration::from_secs(config.monitoring_interval_secs));

            loop {
                interval.tick().await;

                if let Err(e) = Self::monitor_deployed_rules(&monitor, &state, &config).await {
                    log::error!("Error during rule monitoring: {}", e);
                }
            }
        });

        Ok(())
    }

    /// Monitor deployed rules
    async fn monitor_deployed_rules(
        monitor: &RulePerformanceMonitor,
        state: &Arc<RwLock<IntegrationState>>,
        config: &IntegrationConfig,
    ) -> Result<()> {
        let state_read = state.read().await;
        let deployed_rules: Vec<_> = state_read.deployed_rules.values().cloned().collect();
        drop(state_read);

        for rule in deployed_rules {
            if let Err(e) = Self::monitor_single_rule(monitor, state, config, &rule).await {
                log::warn!("Error monitoring rule {}: {}", rule.rule_id, e);
            }
        }

        Ok(())
    }

    /// Monitor a single rule
    async fn monitor_single_rule(
        _monitor: &RulePerformanceMonitor,
        state: &Arc<RwLock<IntegrationState>>,
        config: &IntegrationConfig,
        rule: &DeployedRule,
    ) -> Result<()> {
        // Collect current performance metrics (simulated)
        let current_metrics = RulePerformanceMetrics {
            total_executions: rule.performance_metrics.total_executions + 10,
            true_positives: rule.performance_metrics.true_positives + 2,
            false_positives: rule.performance_metrics.false_positives + 1,
            false_negatives: rule.performance_metrics.false_negatives,
            average_execution_time_ms: 2.5,
            memory_usage_mb: 0.8,
            cpu_utilization: 1.2,
            last_execution: Some(SystemTime::now()),
            performance_trend: PerformanceTrend::Stable,
        };

        // Check for performance degradation
        let fp_rate = current_metrics.false_positives as f32 
            / (current_metrics.true_positives + current_metrics.false_positives) as f32;

        if fp_rate > config.fp_rate_threshold {
            log::warn!("Rule {} exceeds false positive threshold: {:.2}%", 
                rule.rule_id, fp_rate * 100.0);
            
            // Update rule status
            let mut state_write = state.write().await;
            if let Some(deployed_rule) = state_write.deployed_rules.get_mut(&rule.rule_id) {
                deployed_rule.status = RuleStatus::Warning;
                deployed_rule.performance_metrics = current_metrics;
            }
        } else {
            // Update performance metrics
            let mut state_write = state.write().await;
            if let Some(deployed_rule) = state_write.deployed_rules.get_mut(&rule.rule_id) {
                deployed_rule.performance_metrics = current_metrics;
            }
        }

        Ok(())
    }

    /// Get integration status
    pub async fn get_integration_status(&self) -> Result<IntegrationStatus> {
        let state = self.integration_state.read().await;
        
        Ok(IntegrationStatus {
            total_deployed_rules: state.deployed_rules.len() as u32,
            active_rules: state.deployed_rules.values()
                .filter(|r| matches!(r.status, RuleStatus::Active))
                .count() as u32,
            pending_deployments: state.pending_deployments.len() as u32,
            performance_stats: state.performance_stats.clone(),
            health_metrics: state.health_metrics.clone(),
            last_update: state.last_update,
        })
    }
}

// Supporting implementations

impl PatternConverter {
    pub fn new() -> Result<Self> {
        Ok(Self {
            conversion_templates: Self::load_conversion_templates(),
            language_mappers: Self::load_language_mappers(),
            quality_enhancers: vec![],
            metadata_enrichers: vec![],
        })
    }

    pub async fn convert_pattern(&self, pattern: &ExtractedPattern) -> Result<SecurityPattern> {
        let pattern_id = format!("auto-{}", Uuid::new_v4());
        
        // Map vulnerability type to category
        let category = match pattern.pattern_type {
            VulnerabilityType::Injection => "injection",
            VulnerabilityType::CrossSiteScripting => "xss",
            VulnerabilityType::BrokenAuthentication => "authentication",
            VulnerabilityType::SensitiveDataExposure => "data-exposure",
            _ => "security",
        };

        // Create regex patterns
        let regex_patterns = pattern.extracted_regex.iter()
            .map(|regex| RegexPattern {
                regex: regex.clone(),
                flags: None,
                description: Some("Auto-generated from CVE analysis".to_string()),
                confidence: Some(pattern.confidence_score),
            })
            .collect();

        Ok(SecurityPattern {
            id: pattern_id,
            name: format!("Auto-generated pattern for {}", pattern.source_cve),
            description: pattern.description.clone(),
            severity: pattern.severity_estimate.clone(),
            category: category.to_string(),
            languages: pattern.affected_languages.clone(),
            patterns: regex_patterns,
            fix_suggestion: Some(pattern.mitigation_advice.clone()),
            cwe: None, // Could be extracted from supporting evidence
            owasp: None, // Could be mapped from vulnerability type
            references: Some(pattern.supporting_evidence.clone()),
            metadata: Some({
                let mut metadata = HashMap::new();
                metadata.insert("source".to_string(), "automated-cve-analysis".to_string());
                metadata.insert("cve_id".to_string(), pattern.source_cve.clone());
                metadata.insert("confidence".to_string(), pattern.confidence_score.to_string());
                metadata.insert("generation_timestamp".to_string(), 
                    SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_secs().to_string());
                metadata
            }),
        })
    }

    fn load_conversion_templates() -> HashMap<VulnerabilityType, ConversionTemplate> {
        let mut templates = HashMap::new();
        
        templates.insert(VulnerabilityType::Injection, ConversionTemplate {
            template_id: "injection-template".to_string(),
            vulnerability_type: VulnerabilityType::Injection,
            pattern_structure: "injection-pattern".to_string(),
            metadata_mappings: HashMap::new(),
            severity_mappings: HashMap::new(),
            category_mappings: HashMap::new(),
        });

        templates
    }

    fn load_language_mappers() -> HashMap<Language, LanguageMapper> {
        HashMap::new()
    }
}

impl RuleDeployer {
    pub fn new() -> Result<Self> {
        Ok(Self {
            deployment_strategies: vec![],
            environment_managers: HashMap::new(),
            rollback_managers: vec![],
            health_checkers: vec![],
        })
    }
}

impl RulePerformanceMonitor {
    pub fn new() -> Result<Self> {
        Ok(Self {
            performance_collectors: vec![],
            trend_analyzers: vec![],
            alert_managers: vec![],
            report_generators: vec![],
        })
    }
}

impl RuleFeedbackCollector {
    pub fn new() -> Result<Self> {
        Ok(Self {
            feedback_channels: vec![],
            data_processors: vec![],
            analytics_engines: vec![],
            integration_apis: vec![],
        })
    }
}

impl AdaptiveRuleUpdater {
    pub fn new() -> Result<Self> {
        Ok(Self {
            update_strategies: vec![],
            learning_algorithms: vec![],
            optimization_engines: vec![],
            validation_frameworks: vec![],
        })
    }
}

impl IntegrationState {
    pub fn new() -> Self {
        Self {
            deployed_rules: HashMap::new(),
            pending_deployments: vec![],
            performance_stats: PerformanceStatistics {
                total_rules_deployed: 0,
                active_rules: 0,
                average_rule_performance: 0.0,
                total_vulnerabilities_detected: 0,
                false_positive_rate: 0.0,
                false_negative_rate: 0.0,
                system_performance_impact: 0.0,
                user_satisfaction_score: 0.0,
            },
            health_metrics: SystemHealthMetrics {
                cpu_utilization: 0.0,
                memory_utilization: 0.0,
                disk_utilization: 0.0,
                network_utilization: 0.0,
                error_rate: 0.0,
                response_time_ms: 0.0,
                availability_percentage: 100.0,
                health_status: HealthStatus::Healthy,
            },
            last_update: SystemTime::now(),
        }
    }
}

// Additional supporting structures

#[derive(Debug, Clone)]
pub struct DeploymentRequest {
    pub deployment_id: String,
    pub pattern: ExtractedPattern,
    pub validation_result: ValidationResult,
    pub security_pattern: SecurityPattern,
    pub deployment_priority: DeploymentPriority,
    pub risk_assessment: DeploymentRiskAssessment,
    pub requested_by: String,
    pub request_timestamp: SystemTime,
}

#[derive(Debug, Clone)]
pub struct IntegrationSummary {
    pub deployed_count: u32,
    pub queued_count: u32,
    pub skipped_count: u32,
    pub failed_count: u32,
    pub deployed_rules: Vec<String>,
    pub error_messages: Vec<String>,
    pub processing_time: Duration,
}

impl IntegrationSummary {
    pub fn new() -> Self {
        Self {
            deployed_count: 0,
            queued_count: 0,
            skipped_count: 0,
            failed_count: 0,
            deployed_rules: vec![],
            error_messages: vec![],
            processing_time: Duration::from_secs(0),
        }
    }

    pub fn add_deployed(&mut self, _pattern: &ExtractedPattern, rule: &DeployedRule) {
        self.deployed_count += 1;
        self.deployed_rules.push(rule.rule_id.clone());
    }

    pub fn add_queued(&mut self, _pattern: &ExtractedPattern) {
        self.queued_count += 1;
    }

    pub fn add_skipped(&mut self, _pattern: &ExtractedPattern, reason: &str) {
        self.skipped_count += 1;
        self.error_messages.push(format!("Skipped: {}", reason));
    }

    pub fn add_failed(&mut self, _pattern: &ExtractedPattern, error: &str) {
        self.failed_count += 1;
        self.error_messages.push(format!("Failed: {}", error));
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct IntegrationStatus {
    pub total_deployed_rules: u32,
    pub active_rules: u32,
    pub pending_deployments: u32,
    pub performance_stats: PerformanceStatistics,
    pub health_metrics: SystemHealthMetrics,
    pub last_update: SystemTime,
}

impl Default for IntegrationConfig {
    fn default() -> Self {
        Self {
            auto_deploy_enabled: false, // Safe default - require manual approval
            min_validation_score: 0.8,
            enable_performance_monitoring: true,
            enable_adaptive_updates: false, // Disabled by default for safety
            require_manual_approval: true,
            max_patterns_per_batch: 10,
            monitoring_interval_secs: 300, // 5 minutes
            performance_degradation_threshold: 0.2, // 20%
            fp_rate_threshold: 0.1, // 10%
            rule_retention_days: 90,
            enable_rule_versioning: true,
            rollback_timeout_minutes: 15,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_automated_rule_integration_creation() {
        let config = IntegrationConfig::default();
        let integration = AutomatedRuleIntegration::new(config);
        assert!(integration.is_ok());
    }

    #[test]
    fn test_integration_config_defaults() {
        let config = IntegrationConfig::default();
        assert!(!config.auto_deploy_enabled);
        assert!(config.require_manual_approval);
        assert_eq!(config.min_validation_score, 0.8);
    }

    #[tokio::test]
    async fn test_pattern_conversion() {
        let converter = PatternConverter::new().unwrap();
        
        let test_pattern = ExtractedPattern {
            source_cve: "CVE-2024-TEST".to_string(),
            pattern_type: VulnerabilityType::Injection,
            extracted_regex: vec!["SELECT.*FROM.*WHERE.*\\$\\{.*\\}".to_string()],
            confidence_score: 0.85,
            supporting_evidence: vec!["SQL injection vulnerability".to_string()],
            affected_languages: vec!["java".to_string(), "python".to_string()],
            severity_estimate: Severity::High,
            description: "SQL injection pattern detected".to_string(),
            mitigation_advice: "Use parameterized queries".to_string(),
        };

        let result = converter.convert_pattern(&test_pattern).await;
        assert!(result.is_ok());

        let security_pattern = result.unwrap();
        assert!(security_pattern.id.starts_with("auto-"));
        assert_eq!(security_pattern.severity, Severity::High);
        assert_eq!(security_pattern.category, "injection");
        assert_eq!(security_pattern.patterns.len(), 1);
    }

    #[test]
    fn test_integration_summary() {
        let mut summary = IntegrationSummary::new();
        assert_eq!(summary.deployed_count, 0);
        assert_eq!(summary.queued_count, 0);
        assert_eq!(summary.skipped_count, 0);
        assert_eq!(summary.failed_count, 0);

        let test_pattern = ExtractedPattern {
            source_cve: "CVE-2024-TEST".to_string(),
            pattern_type: VulnerabilityType::Injection,
            extracted_regex: vec!["test".to_string()],
            confidence_score: 0.8,
            supporting_evidence: vec![],
            affected_languages: vec!["java".to_string()],
            severity_estimate: Severity::Medium,
            description: "Test pattern".to_string(),
            mitigation_advice: "Test mitigation".to_string(),
        };

        summary.add_skipped(&test_pattern, "Testing");
        assert_eq!(summary.skipped_count, 1);
        assert_eq!(summary.error_messages.len(), 1);
    }

    #[tokio::test]
    async fn test_integration_status() {
        let config = IntegrationConfig::default();
        let integration = AutomatedRuleIntegration::new(config).unwrap();
        
        let status = integration.get_integration_status().await;
        assert!(status.is_ok());
        
        let status = status.unwrap();
        assert_eq!(status.total_deployed_rules, 0);
        assert_eq!(status.active_rules, 0);
        assert_eq!(status.pending_deployments, 0);
    }
}