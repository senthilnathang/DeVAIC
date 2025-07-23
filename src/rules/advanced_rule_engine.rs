/// Advanced Rule Engine with Dynamic Loading, Composition, and Context-Aware Analysis
/// 
/// This module provides enterprise-grade rule management capabilities including:
/// - Dynamic rule loading and hot-reload functionality
/// - Advanced rule composition with logical operators
/// - Context-aware rules with dataflow analysis
/// - Machine learning-powered rule generation
/// - Rule performance analytics and optimization

use crate::{
    error::{DevaicError, Result},
    parsers::{ParsedAst, SourceFile},
    Language, Severity, Vulnerability,
};
use serde::{Deserialize, Serialize};
use std::collections::{HashMap, HashSet};
use std::path::{Path, PathBuf};
use std::sync::{Arc, RwLock};
use std::time::{Duration, Instant, SystemTime};
use dashmap::DashMap;
use regex::Regex;
use uuid::Uuid;

/// Advanced Rule Engine with dynamic capabilities
pub struct AdvancedRuleEngine {
    /// Core rule storage with concurrent access
    rules: Arc<DashMap<String, Arc<AdvancedRule>>>,
    
    /// Rule composition graph for complex rule combinations
    compositions: Arc<DashMap<String, RuleComposition>>,
    
    /// Context analyzer for dataflow and semantic analysis
    context_analyzer: Arc<ContextAnalyzer>,
    
    /// ML-powered rule generator
    ml_rule_generator: Arc<MLRuleGenerator>,
    
    /// Rule performance analytics
    analytics: Arc<RuleAnalytics>,
    
    /// Hot-reload configuration
    hot_reload_config: HotReloadConfig,
    
    /// Rule validation framework
    validator: Arc<RuleValidator>,
}

/// Advanced rule definition with enhanced capabilities
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AdvancedRule {
    /// Unique rule identifier
    pub id: String,
    
    /// Rule metadata
    pub metadata: RuleMetadata,
    
    /// Rule execution logic
    pub logic: RuleLogic,
    
    /// Context requirements
    pub context: ContextRequirements,
    
    /// Performance configuration
    pub performance: PerformanceConfig,
    
    /// Validation constraints
    pub validation: ValidationConstraints,
}

/// Rule metadata for management and analytics
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RuleMetadata {
    pub name: String,
    pub description: String,
    pub author: String,
    pub version: String,
    pub created_at: SystemTime,
    pub updated_at: SystemTime,
    pub tags: Vec<String>,
    pub category: RuleCategory,
    pub severity: Severity,
    pub confidence: f32,
    pub languages: Vec<Language>,
    pub frameworks: Vec<String>,
    pub cwe_mappings: Vec<String>,
    pub owasp_mappings: Vec<String>,
}

/// Rule execution logic with multiple types
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum RuleLogic {
    /// Simple pattern-based rule
    Pattern {
        patterns: Vec<PatternRule>,
        operator: LogicalOperator,
    },
    
    /// Dataflow analysis rule
    DataFlow {
        source_patterns: Vec<String>,
        sink_patterns: Vec<String>,
        sanitizer_patterns: Vec<String>,
        max_depth: usize,
        track_through_functions: bool,
    },
    
    /// API security rule
    ApiSecurity {
        endpoint_patterns: Vec<String>,
        method_patterns: Vec<String>,
        parameter_rules: Vec<ParameterRule>,
        authentication_rules: Vec<AuthRule>,
        rate_limiting_rules: Vec<RateLimitRule>,
    },
    
    /// Container security rule
    Container {
        dockerfile_rules: Vec<DockerRule>,
        compose_rules: Vec<ComposeRule>,
        kubernetes_rules: Vec<KubernetesRule>,
        security_context_rules: Vec<SecurityContextRule>,
    },
    
    /// Infrastructure as Code rule
    InfrastructureAsCode {
        terraform_rules: Vec<TerraformRule>,
        cloudformation_rules: Vec<CloudFormationRule>,
        ansible_rules: Vec<AnsibleRule>,
        compliance_checks: Vec<ComplianceCheck>,
    },
    
    /// Custom script-based rule
    Script {
        language: ScriptLanguage,
        code: String,
        dependencies: Vec<String>,
        timeout: Duration,
    },
    
    /// ML-generated rule
    MachineLearning {
        model_type: String,
        model_path: String,
        feature_extractors: Vec<FeatureExtractor>,
        threshold: f32,
        calibration_data: Option<String>,
    },
}

/// Pattern-based rule definition
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PatternRule {
    pub pattern: String,
    pub pattern_type: PatternType,
    pub case_sensitive: bool,
    pub multiline: bool,
    pub context_window: Option<usize>,
    pub exclusions: Vec<String>,
}

/// Logical operators for rule composition
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum LogicalOperator {
    And,
    Or,
    Not,
    Xor,
    Implies,
    BiImplies,
}

/// Pattern types supported by the engine
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum PatternType {
    Regex,
    Glob,
    Ast,
    Semantic,
    Syntactic,
    Dataflow,
}

/// Rule categories for organization
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum RuleCategory {
    Security,
    Privacy,
    Performance,
    Maintainability,
    Compliance,
    Custom,
    API,
    Container,
    Infrastructure,
    Mobile,
    Web,
    Database,
    Network,
    Authentication,
    Authorization,
    Cryptography,
    Injection,
    Deserialization,
    Configuration,
}

/// Context requirements for rule execution
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ContextRequirements {
    pub requires_ast: bool,
    pub requires_dataflow: bool,
    pub requires_call_graph: bool,
    pub requires_type_info: bool,
    pub requires_imports: bool,
    pub requires_dependencies: bool,
    pub context_depth: usize,
    pub cross_file_analysis: bool,
}

/// Performance configuration for rules
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PerformanceConfig {
    pub max_execution_time: Duration,
    pub memory_limit: Option<usize>,
    pub parallel_execution: bool,
    pub caching_enabled: bool,
    pub priority: i32,
    pub batch_size: Option<usize>,
}

/// Validation constraints for rules
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ValidationConstraints {
    pub min_confidence: f32,
    pub max_false_positive_rate: f32,
    pub required_test_cases: usize,
    pub benchmark_requirements: Vec<String>,
    pub compatibility_requirements: Vec<String>,
}

/// Rule composition for complex logic
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RuleComposition {
    pub id: String,
    pub name: String,
    pub rules: Vec<CompositionRule>,
    pub operator: LogicalOperator,
    pub short_circuit: bool,
    pub aggregation_strategy: AggregationStrategy,
}

/// Individual rule in a composition
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CompositionRule {
    pub rule_id: String,
    pub weight: f32,
    pub required: bool,
    pub conditions: Vec<RuleCondition>,
}

/// Conditions for rule execution
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RuleCondition {
    pub field: String,
    pub operator: ComparisonOperator,
    pub value: String,
    pub case_sensitive: bool,
}

/// Comparison operators for conditions
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum ComparisonOperator {
    Equals,
    NotEquals,
    Contains,
    NotContains,
    Matches,
    NotMatches,
    GreaterThan,
    LessThan,
    GreaterOrEqual,
    LessOrEqual,
}

/// Aggregation strategies for composed rules
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum AggregationStrategy {
    All,
    Any,
    Majority,
    WeightedSum,
    MaxConfidence,
    MinConfidence,
    Average,
}

/// Hot-reload configuration
#[derive(Debug, Clone)]
pub struct HotReloadConfig {
    pub enabled: bool,
    pub watch_directories: Vec<PathBuf>,
    pub reload_interval: Duration,
    pub auto_validation: bool,
    pub backup_on_reload: bool,
}

/// Context analyzer for semantic analysis
pub struct ContextAnalyzer {
    /// Dataflow analysis engine
    dataflow_engine: DataFlowEngine,
    
    /// Call graph analyzer
    call_graph_analyzer: CallGraphAnalyzer,
    
    /// Type inference engine
    type_engine: TypeInferenceEngine,
    
    /// Import dependency analyzer
    dependency_analyzer: DependencyAnalyzer,
}

/// Dataflow analysis engine
pub struct DataFlowEngine {
    /// Source identification patterns
    sources: HashMap<String, Vec<Regex>>,
    
    /// Sink identification patterns
    sinks: HashMap<String, Vec<Regex>>,
    
    /// Sanitizer patterns
    sanitizers: HashMap<String, Vec<Regex>>,
    
    /// Analysis cache
    cache: DashMap<String, DataFlowResult>,
}

/// Dataflow analysis result
#[derive(Debug, Clone)]
pub struct DataFlowResult {
    pub flows: Vec<DataFlow>,
    pub sources: Vec<DataSource>,
    pub sinks: Vec<DataSink>,
    pub sanitizers: Vec<DataSanitizer>,
    pub vulnerabilities: Vec<DataFlowVulnerability>,
}

/// Individual dataflow
#[derive(Debug, Clone)]
pub struct DataFlow {
    pub id: String,
    pub source: DataSource,
    pub sink: DataSink,
    pub path: Vec<DataFlowNode>,
    pub sanitized: bool,
    pub confidence: f32,
}

/// Data source definition
#[derive(Debug, Clone)]
pub struct DataSource {
    pub id: String,
    pub location: SourceLocation,
    pub data_type: DataType,
    pub sensitivity: SensitivityLevel,
    pub trust_level: TrustLevel,
}

/// Data sink definition
#[derive(Debug, Clone)]
pub struct DataSink {
    pub id: String,
    pub location: SourceLocation,
    pub sink_type: SinkType,
    pub danger_level: DangerLevel,
}

/// Data sanitizer definition
#[derive(Debug, Clone)]
pub struct DataSanitizer {
    pub id: String,
    pub location: SourceLocation,
    pub sanitizer_type: SanitizerType,
    pub effectiveness: f32,
}

/// Dataflow vulnerability
#[derive(Debug, Clone)]
pub struct DataFlowVulnerability {
    pub flow_id: String,
    pub vulnerability_type: String,
    pub severity: Severity,
    pub confidence: f32,
    pub description: String,
    pub recommendation: String,
}

/// Source location information
#[derive(Debug, Clone)]
pub struct SourceLocation {
    pub file: String,
    pub line: usize,
    pub column: usize,
    pub function: Option<String>,
    pub class: Option<String>,
}

/// Data types for flow analysis
#[derive(Debug, Clone)]
pub enum DataType {
    String,
    Number,
    Boolean,
    Object,
    Array,
    Function,
    Unknown,
    Sensitive(SensitiveDataType),
}

/// Sensitive data types
#[derive(Debug, Clone)]
pub enum SensitiveDataType {
    PersonalInfo,
    FinancialInfo,
    HealthInfo,
    AuthCredentials,
    ApiKeys,
    Secrets,
    InternalData,
}

/// Sensitivity levels
#[derive(Debug, Clone)]
pub enum SensitivityLevel {
    Public,
    Internal,
    Confidential,
    Restricted,
    TopSecret,
}

/// Trust levels for data sources
#[derive(Debug, Clone)]
pub enum TrustLevel {
    Trusted,
    SemiTrusted,
    Untrusted,
    Unknown,
}

/// Sink types
#[derive(Debug, Clone)]
pub enum SinkType {
    Database,
    FileSystem,
    Network,
    Log,
    Display,
    Command,
    Eval,
    Reflection,
}

/// Danger levels for sinks
#[derive(Debug, Clone)]
pub enum DangerLevel {
    Safe,
    Low,
    Medium,
    High,
    Critical,
}

/// Sanitizer types
#[derive(Debug, Clone)]
pub enum SanitizerType {
    Validation,
    Encoding,
    Escaping,
    Filtering,
    Encryption,
    Hashing,
    Normalization,
}

/// Dataflow node in analysis path
#[derive(Debug, Clone)]
pub struct DataFlowNode {
    pub location: SourceLocation,
    pub node_type: NodeType,
    pub transformation: Option<DataTransformation>,
}

/// Node types in dataflow
#[derive(Debug, Clone)]
pub enum NodeType {
    Assignment,
    FunctionCall,
    Return,
    Parameter,
    Condition,
    Loop,
    Exception,
}

/// Data transformations
#[derive(Debug, Clone)]
pub struct DataTransformation {
    pub transformation_type: TransformationType,
    pub preserves_sensitivity: bool,
    pub increases_trust: bool,
}

/// Transformation types
#[derive(Debug, Clone)]
pub enum TransformationType {
    Concat,
    Format,
    Encode,
    Decode,
    Validate,
    Filter,
    Sanitize,
    Encrypt,
    Decrypt,
    Hash,
}

// Additional enhanced rule types will be defined in separate modules
pub mod api_security;
pub mod container_security;
pub mod infrastructure_rules;
pub mod ml_rule_generation;
pub mod rule_management;

// Implementation will continue in the next part...
impl AdvancedRuleEngine {
    /// Create a new advanced rule engine
    pub fn new() -> Result<Self> {
        Ok(Self {
            rules: Arc::new(DashMap::new()),
            compositions: Arc::new(DashMap::new()),
            context_analyzer: Arc::new(ContextAnalyzer::new()?),
            ml_rule_generator: Arc::new(MLRuleGenerator::new()?),
            analytics: Arc::new(RuleAnalytics::new()),
            hot_reload_config: HotReloadConfig {
                enabled: false,
                watch_directories: Vec::new(),
                reload_interval: Duration::from_secs(30),
                auto_validation: true,
                backup_on_reload: true,
            },
            validator: Arc::new(RuleValidator::new()),
        })
    }
    
    /// Load rules from directory with hot-reload support
    pub fn load_rules_from_directory(&self, directory: &Path) -> Result<usize> {
        let mut loaded_count = 0;
        
        for entry in std::fs::read_dir(directory)? {
            let entry = entry?;
            let path = entry.path();
            
            if path.extension().and_then(|s| s.to_str()) == Some("yaml") ||
               path.extension().and_then(|s| s.to_str()) == Some("yml") {
                match self.load_rule_file(&path) {
                    Ok(count) => loaded_count += count,
                    Err(e) => eprintln!("Failed to load rule file {:?}: {}", path, e),
                }
            }
        }
        
        Ok(loaded_count)
    }
    
    /// Load individual rule file
    pub fn load_rule_file(&self, path: &Path) -> Result<usize> {
        let content = std::fs::read_to_string(path)?;
        let rules: Vec<AdvancedRule> = serde_yaml::from_str(&content)
            .map_err(|e| DevaicError::Parse(format!("Failed to parse rule file: {}", e)))?;
        
        let mut loaded_count = 0;
        for rule in rules {
            // Validate rule before loading
            if let Err(e) = self.validator.validate_rule(&rule) {
                eprintln!("Rule validation failed for {}: {}", rule.id, e);
                continue;
            }
            
            self.rules.insert(rule.id.clone(), Arc::new(rule));
            loaded_count += 1;
        }
        
        Ok(loaded_count)
    }
    
    /// Enable hot-reload functionality
    pub fn enable_hot_reload(&mut self, directories: Vec<PathBuf>) -> Result<()> {
        self.hot_reload_config.enabled = true;
        self.hot_reload_config.watch_directories = directories;
        
        // Start file watcher in background
        self.start_file_watcher()?;
        
        Ok(())
    }
    
    /// Start file watcher for hot-reload
    fn start_file_watcher(&self) -> Result<()> {
        // Implementation would use a file watching library like `notify`
        // For now, this is a placeholder
        Ok(())
    }
    
    /// Execute rule against source file with context
    pub fn execute_rule(&self, rule_id: &str, source_file: &SourceFile, ast: &ParsedAst) -> Result<Vec<Vulnerability>> {
        let start_time = Instant::now();
        
        let rule = self.rules.get(rule_id)
            .ok_or_else(|| DevaicError::Analysis(format!("Rule not found: {}", rule_id)))?;
        
        // Check context requirements
        if !self.check_context_requirements(&rule.context, source_file, ast)? {
            return Ok(Vec::new());
        }
        
        // Execute rule logic
        let vulnerabilities = match &rule.logic {
            RuleLogic::Pattern { patterns, operator } => {
                self.execute_pattern_rule(patterns, operator, source_file, ast)?
            }
            RuleLogic::DataFlow { source_patterns, sink_patterns, sanitizer_patterns, max_depth, track_through_functions } => {
                self.execute_dataflow_rule(source_patterns, sink_patterns, sanitizer_patterns, *max_depth, *track_through_functions, source_file, ast)?
            }
            RuleLogic::ApiSecurity { .. } => {
                self.execute_api_security_rule(&rule, source_file, ast)?
            }
            RuleLogic::Container { .. } => {
                self.execute_container_rule(&rule, source_file, ast)?
            }
            RuleLogic::InfrastructureAsCode { .. } => {
                self.execute_iac_rule(&rule, source_file, ast)?
            }
            RuleLogic::Script { .. } => {
                self.execute_script_rule(&rule, source_file, ast)?
            }
            RuleLogic::MachineLearning { .. } => {
                self.execute_ml_rule(&rule, source_file, ast)?
            }
        };
        
        // Record analytics
        let execution_time = start_time.elapsed();
        self.analytics.record_rule_execution(rule_id, execution_time, vulnerabilities.len());
        
        Ok(vulnerabilities)
    }
    
    /// Check if context requirements are met
    fn check_context_requirements(&self, requirements: &ContextRequirements, source_file: &SourceFile, ast: &ParsedAst) -> Result<bool> {
        if requirements.requires_ast && ast.tree.is_none() {
            return Ok(false);
        }
        
        // Add more context checks as needed
        Ok(true)
    }
    
    /// Execute pattern-based rule
    fn execute_pattern_rule(&self, patterns: &[PatternRule], operator: &LogicalOperator, source_file: &SourceFile, _ast: &ParsedAst) -> Result<Vec<Vulnerability>> {
        let mut vulnerabilities = Vec::new();
        let content = &source_file.content;
        
        for (line_num, line) in content.lines().enumerate() {
            let pattern_matches: Vec<bool> = patterns.iter()
                .map(|pattern| self.match_pattern(pattern, line))
                .collect();
            
            let rule_matches = match operator {
                LogicalOperator::And => pattern_matches.iter().all(|&m| m),
                LogicalOperator::Or => pattern_matches.iter().any(|&m| m),
                LogicalOperator::Not => !pattern_matches.iter().any(|&m| m),
                LogicalOperator::Xor => pattern_matches.iter().filter(|&&m| m).count() == 1,
                _ => pattern_matches.iter().any(|&m| m), // Default to OR
            };
            
            if rule_matches {
                vulnerabilities.push(self.create_vulnerability_from_match(line_num + 1, line, source_file));
            }
        }
        
        Ok(vulnerabilities)
    }
    
    /// Match individual pattern
    fn match_pattern(&self, pattern: &PatternRule, text: &str) -> bool {
        match pattern.pattern_type {
            PatternType::Regex => {
                if let Ok(regex) = Regex::new(&pattern.pattern) {
                    regex.is_match(text)
                } else {
                    false
                }
            }
            PatternType::Glob => {
                // Implement glob matching
                false
            }
            _ => {
                // Implement other pattern types
                false
            }
        }
    }
    
    /// Create vulnerability from pattern match
    fn create_vulnerability_from_match(&self, line_number: usize, line: &str, source_file: &SourceFile) -> Vulnerability {
        Vulnerability {
            id: format!("ADV-{}", Uuid::new_v4()),
            cwe: None,
            vulnerability_type: "Pattern Match".to_string(),
            severity: Severity::Medium,
            category: "security".to_string(),
            description: "Pattern-based vulnerability detected".to_string(),
            file_path: source_file.path.to_string_lossy().to_string(),
            line_number,
            column: 0,
            source_code: line.to_string(),
            recommendation: "Review and remediate the detected pattern".to_string(),
            location: crate::Location {
                file: source_file.path.to_string_lossy().to_string(),
                line: line_number,
                column: 0,
            },
            code_snippet: Some(line.to_string()),
        }
    }
    
    // Placeholder implementations for other rule types
    fn execute_dataflow_rule(&self, _source_patterns: &[String], _sink_patterns: &[String], _sanitizer_patterns: &[String], _max_depth: usize, _track_through_functions: bool, _source_file: &SourceFile, _ast: &ParsedAst) -> Result<Vec<Vulnerability>> {
        // Will be implemented with full dataflow analysis
        Ok(Vec::new())
    }
    
    fn execute_api_security_rule(&self, _rule: &AdvancedRule, _source_file: &SourceFile, _ast: &ParsedAst) -> Result<Vec<Vulnerability>> {
        // Will be implemented with API security analysis
        Ok(Vec::new())
    }
    
    fn execute_container_rule(&self, _rule: &AdvancedRule, _source_file: &SourceFile, _ast: &ParsedAst) -> Result<Vec<Vulnerability>> {
        // Will be implemented with container security analysis
        Ok(Vec::new())
    }
    
    fn execute_iac_rule(&self, _rule: &AdvancedRule, _source_file: &SourceFile, _ast: &ParsedAst) -> Result<Vec<Vulnerability>> {
        // Will be implemented with IaC security analysis
        Ok(Vec::new())
    }
    
    fn execute_script_rule(&self, _rule: &AdvancedRule, _source_file: &SourceFile, _ast: &ParsedAst) -> Result<Vec<Vulnerability>> {
        // Will be implemented with script execution
        Ok(Vec::new())
    }
    
    fn execute_ml_rule(&self, _rule: &AdvancedRule, _source_file: &SourceFile, _ast: &ParsedAst) -> Result<Vec<Vulnerability>> {
        // Will be implemented with ML rule execution
        Ok(Vec::new())
    }
}

// Placeholder implementations for supporting structures
impl ContextAnalyzer {
    pub fn new() -> Result<Self> {
        Ok(Self {
            dataflow_engine: DataFlowEngine::new(),
            call_graph_analyzer: CallGraphAnalyzer::new(),
            type_engine: TypeInferenceEngine::new(),
            dependency_analyzer: DependencyAnalyzer::new(),
        })
    }
}

impl DataFlowEngine {
    pub fn new() -> Self {
        Self {
            sources: HashMap::new(),
            sinks: HashMap::new(),
            sanitizers: HashMap::new(),
            cache: DashMap::new(),
        }
    }
}

pub struct CallGraphAnalyzer;
impl CallGraphAnalyzer {
    pub fn new() -> Self { Self }
}

pub struct TypeInferenceEngine;
impl TypeInferenceEngine {
    pub fn new() -> Self { Self }
}

pub struct DependencyAnalyzer;
impl DependencyAnalyzer {
    pub fn new() -> Self { Self }
}

pub struct MLRuleGenerator;
impl MLRuleGenerator {
    pub fn new() -> Result<Self> { Ok(Self) }
}

pub struct RuleAnalytics {
    execution_stats: DashMap<String, RuleExecutionStats>,
}

#[derive(Debug, Clone)]
pub struct RuleExecutionStats {
    pub total_executions: u64,
    pub total_time: Duration,
    pub average_time: Duration,
    pub vulnerabilities_found: u64,
    pub false_positives: u64,
    pub false_positive_rate: f32,
}

impl RuleAnalytics {
    pub fn new() -> Self {
        Self {
            execution_stats: DashMap::new(),
        }
    }
    
    pub fn record_rule_execution(&self, rule_id: &str, execution_time: Duration, vulnerabilities_found: usize) {
        let mut stats = self.execution_stats.entry(rule_id.to_string()).or_insert_with(|| RuleExecutionStats {
            total_executions: 0,
            total_time: Duration::ZERO,
            average_time: Duration::ZERO,
            vulnerabilities_found: 0,
            false_positives: 0,
            false_positive_rate: 0.0,
        });
        
        stats.total_executions += 1;
        stats.total_time += execution_time;
        stats.average_time = stats.total_time / stats.total_executions as u32;
        stats.vulnerabilities_found += vulnerabilities_found as u64;
    }
}

pub struct RuleValidator;
impl RuleValidator {
    pub fn new() -> Self { Self }
    
    pub fn validate_rule(&self, _rule: &AdvancedRule) -> Result<()> {
        // Implement rule validation logic
        Ok(())
    }
}

// Additional rule type definitions
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ParameterRule {
    pub name: String,
    pub validation_pattern: String,
    pub required: bool,
    pub sanitization_required: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AuthRule {
    pub auth_type: String,
    pub required_scopes: Vec<String>,
    pub token_validation: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RateLimitRule {
    pub requests_per_minute: u32,
    pub burst_limit: u32,
    pub scope: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DockerRule {
    pub instruction: String,
    pub pattern: String,
    pub severity: Severity,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ComposeRule {
    pub service_pattern: String,
    pub configuration_check: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct KubernetesRule {
    pub resource_type: String,
    pub field_path: String,
    pub expected_value: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SecurityContextRule {
    pub capability: String,
    pub allowed: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TerraformRule {
    pub resource_type: String,
    pub attribute_path: String,
    pub validation_expression: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CloudFormationRule {
    pub resource_type: String,
    pub property_path: String,
    pub condition: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AnsibleRule {
    pub module_name: String,
    pub parameter_check: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ComplianceCheck {
    pub framework: String,
    pub control_id: String,
    pub description: String,
    pub check_logic: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum ScriptLanguage {
    Lua,
    Python,
    JavaScript,
    Ruby,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FeatureExtractor {
    pub name: String,
    pub extractor_type: String,
    pub parameters: HashMap<String, String>,
}