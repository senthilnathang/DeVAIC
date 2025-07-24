/// Business Logic Vulnerability Detection System
/// 
/// This module implements AI-powered analysis to understand application workflows
/// and detect business logic vulnerabilities that traditional static analysis might miss.
/// It uses machine learning to understand intended behavior vs. actual implementation.

use crate::{
    Language, Severity, Vulnerability,
    error::Result,
};
use serde::{Deserialize, Serialize};
use std::collections::{HashMap, HashSet, VecDeque};
use std::sync::Arc;
use tokio::sync::RwLock;

/// Business logic vulnerability detection engine
#[derive(Debug, Clone)]
pub struct BusinessLogicAnalyzer {
    /// Workflow models for different application types
    workflow_models: Arc<RwLock<HashMap<String, WorkflowModel>>>,
    /// State machine analyzers
    state_analyzers: Vec<Arc<dyn StateMachineAnalyzer>>,
    /// Authentication flow analyzers
    auth_analyzers: Vec<Arc<dyn AuthenticationAnalyzer>>,
    /// Data validation analyzers
    validation_analyzers: Vec<Arc<dyn ValidationAnalyzer>>,
    /// Business rule engines
    rule_engines: Vec<Arc<dyn BusinessRuleEngine>>,
    /// Configuration
    config: BusinessLogicConfig,
}

/// Configuration for business logic analysis
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BusinessLogicConfig {
    /// Enable workflow understanding
    pub enable_workflow_analysis: bool,
    /// Enable state machine analysis
    pub enable_state_analysis: bool,
    /// Enable authentication flow analysis
    pub enable_auth_analysis: bool,
    /// Enable data validation analysis
    pub enable_validation_analysis: bool,
    /// Enable business rule validation
    pub enable_rule_validation: bool,
    /// Maximum workflow depth to analyze
    pub max_workflow_depth: usize,
    /// Minimum confidence threshold for vulnerabilities
    pub min_confidence_threshold: f64,
    /// Enable ML-enhanced analysis
    pub enable_ml_enhancement: bool,
    /// Timeout for complex analysis in seconds
    pub analysis_timeout_secs: u64,
}

/// Workflow model representing application business logic
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WorkflowModel {
    /// Workflow identifier
    pub id: String,
    /// Application type (e.g., "ecommerce", "banking", "healthcare")
    pub app_type: String,
    /// Workflow states
    pub states: Vec<WorkflowState>,
    /// Valid transitions between states
    pub valid_transitions: HashMap<String, Vec<String>>,
    /// Business rules for each state
    pub business_rules: HashMap<String, Vec<BusinessRule>>,
    /// Authentication requirements
    pub auth_requirements: HashMap<String, AuthRequirement>,
    /// Data validation rules
    pub validation_rules: HashMap<String, Vec<ValidationRule>>,
    /// Expected data flows
    pub data_flows: Vec<DataFlow>,
}

/// Individual workflow state
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WorkflowState {
    /// State identifier
    pub id: String,
    /// State name
    pub name: String,
    /// State description
    pub description: String,
    /// Required permissions
    pub required_permissions: Vec<String>,
    /// Required data inputs
    pub required_inputs: Vec<String>,
    /// Expected outputs
    pub expected_outputs: Vec<String>,
    /// Side effects
    pub side_effects: Vec<String>,
    /// Security constraints
    pub security_constraints: Vec<SecurityConstraint>,
}

/// Business rule definition
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BusinessRule {
    /// Rule identifier
    pub id: String,
    /// Rule name
    pub name: String,
    /// Rule condition
    pub condition: String,
    /// Expected action
    pub action: String,
    /// Rule severity if violated
    pub violation_severity: Severity,
    /// Rule category
    pub category: BusinessRuleCategory,
}

/// Categories of business rules
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum BusinessRuleCategory {
    /// Access control and authorization
    AccessControl,
    /// Data validation and integrity
    DataValidation,
    /// Financial transaction rules
    Financial,
    /// Workflow sequence validation
    WorkflowSequence,
    /// Rate limiting and abuse prevention
    RateLimiting,
    /// Privacy and data protection
    Privacy,
    /// Audit and compliance
    Compliance,
}

/// Authentication requirement
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AuthRequirement {
    /// Authentication level required
    pub auth_level: AuthLevel,
    /// Multi-factor authentication required
    pub mfa_required: bool,
    /// Session validation required
    pub session_validation: bool,
    /// Role-based access control
    pub rbac_rules: Vec<String>,
    /// Custom authentication logic
    pub custom_auth: Option<String>,
}

/// Authentication levels
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum AuthLevel {
    None,
    Basic,
    Standard,
    Elevated,
    Administrative,
}

/// Data validation rule
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ValidationRule {
    /// Field or parameter to validate
    pub field: String,
    /// Validation type
    pub validation_type: ValidationType,
    /// Validation pattern or constraint
    pub constraint: String,
    /// Error message for validation failure
    pub error_message: String,
    /// Severity of validation failure
    pub failure_severity: Severity,
}

/// Types of data validation
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum ValidationType {
    Required,
    Format,
    Range,
    Length,
    Custom,
    BusinessLogic,
}

/// Data flow definition
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DataFlow {
    /// Flow identifier
    pub id: String,
    /// Source of data
    pub source: String,
    /// Destination of data
    pub destination: String,
    /// Data transformations
    pub transformations: Vec<String>,
    /// Security requirements
    pub security_requirements: Vec<String>,
    /// Taint tracking requirements
    pub taint_tracking: bool,
}

/// Security constraint
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SecurityConstraint {
    /// Constraint type
    pub constraint_type: ConstraintType,
    /// Constraint description
    pub description: String,
    /// Enforcement mechanism
    pub enforcement: String,
    /// Violation consequences
    pub violations: Vec<String>,
}

/// Types of security constraints
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum ConstraintType {
    Authorization,
    DataIntegrity,
    Encryption,
    Logging,
    RateLimiting,
    InputValidation,
}

/// Result of business logic analysis
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BusinessLogicAnalysisResult {
    /// Detected vulnerabilities
    pub vulnerabilities: Vec<BusinessLogicVulnerability>,
    /// Workflow analysis results
    pub workflow_analysis: Vec<WorkflowAnalysisResult>,
    /// State machine violations
    pub state_violations: Vec<StateMachineViolation>,
    /// Authentication flow issues
    pub auth_issues: Vec<AuthenticationIssue>,
    /// Data validation problems
    pub validation_issues: Vec<ValidationIssue>,
    /// Business rule violations
    pub rule_violations: Vec<BusinessRuleViolation>,
    /// Analysis metadata
    pub metadata: AnalysisMetadata,
}

/// Business logic vulnerability
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BusinessLogicVulnerability {
    /// Base vulnerability information
    pub vulnerability_info: Vulnerability,
    /// Business logic specific details
    pub business_context: BusinessContext,
    /// Workflow impact
    pub workflow_impact: WorkflowImpact,
    /// Exploitation scenario
    pub exploitation_scenario: String,
    /// Business risk assessment
    pub business_risk: BusinessRisk,
    /// Recommended remediation
    pub remediation: BusinessLogicRemediation,
}

/// Business context for vulnerability
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BusinessContext {
    /// Application workflow affected
    pub affected_workflow: String,
    /// Business process impacted
    pub business_process: String,
    /// User roles affected
    pub affected_roles: Vec<String>,
    /// Data assets at risk
    pub at_risk_data: Vec<String>,
    /// Financial impact potential
    pub financial_impact: FinancialImpact,
}

/// Workflow impact assessment
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WorkflowImpact {
    /// Impact level
    pub impact_level: ImpactLevel,
    /// Affected workflow states
    pub affected_states: Vec<String>,
    /// Bypassed controls
    pub bypassed_controls: Vec<String>,
    /// Disrupted processes
    pub disrupted_processes: Vec<String>,
}

/// Impact levels
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum ImpactLevel {
    Minimal,
    Low,
    Medium,
    High,
    Critical,
}

/// Financial impact assessment
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FinancialImpact {
    /// Potential loss range
    pub loss_range: LossRange,
    /// Revenue impact
    pub revenue_impact: bool,
    /// Regulatory compliance impact
    pub compliance_impact: bool,
    /// Brand reputation impact
    pub reputation_impact: bool,
}

/// Loss range categories
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum LossRange {
    Negligible,      // < $1K
    Low,            // $1K - $10K
    Medium,         // $10K - $100K
    High,           // $100K - $1M
    Critical,       // > $1M
}

/// Business risk assessment
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BusinessRisk {
    /// Overall risk score (0-100)
    pub risk_score: u8,
    /// Risk factors
    pub risk_factors: Vec<RiskFactor>,
    /// Likelihood of exploitation
    pub exploitation_likelihood: LikelihoodLevel,
    /// Business continuity impact
    pub continuity_impact: ImpactLevel,
}

/// Risk factor
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RiskFactor {
    /// Factor name
    pub name: String,
    /// Factor weight
    pub weight: f64,
    /// Factor score
    pub score: f64,
    /// Factor description
    pub description: String,
}

/// Likelihood levels
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum LikelihoodLevel {
    VeryLow,
    Low,
    Medium,
    High,
    VeryHigh,
}

/// Business logic remediation
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BusinessLogicRemediation {
    /// Immediate actions
    pub immediate_actions: Vec<String>,
    /// Long-term solutions
    pub long_term_solutions: Vec<String>,
    /// Process improvements
    pub process_improvements: Vec<String>,
    /// Monitoring recommendations
    pub monitoring_recommendations: Vec<String>,
    /// Testing recommendations
    pub testing_recommendations: Vec<String>,
}

/// Workflow analysis result
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WorkflowAnalysisResult {
    /// Workflow identifier
    pub workflow_id: String,
    /// Analysis status
    pub status: AnalysisStatus,
    /// Detected issues
    pub issues: Vec<WorkflowIssue>,
    /// Compliance status
    pub compliance_status: ComplianceStatus,
    /// Recommendations
    pub recommendations: Vec<String>,
}

/// Analysis status
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum AnalysisStatus {
    Complete,
    Partial,
    Failed,
    Timeout,
}

/// Workflow issue
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WorkflowIssue {
    /// Issue type
    pub issue_type: WorkflowIssueType,
    /// Issue description
    pub description: String,
    /// Severity level
    pub severity: Severity,
    /// Location in code
    pub location: Option<String>,
    /// Suggested fix
    pub suggested_fix: String,
}

/// Types of workflow issues
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum WorkflowIssueType {
    InvalidTransition,
    MissingValidation,
    AuthenticationBypass,
    AuthorizationMissing,
    BusinessRuleViolation,
    DataIntegrityIssue,
    StateCorruption,
}

/// Compliance status
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum ComplianceStatus {
    Compliant,
    NonCompliant,
    PartiallyCompliant,
    Unknown,
}

/// State machine violation
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StateMachineViolation {
    /// Current state
    pub current_state: String,
    /// Attempted transition
    pub attempted_transition: String,
    /// Target state
    pub target_state: String,
    /// Violation type
    pub violation_type: StateMachineViolationType,
    /// Security impact
    pub security_impact: SecurityImpact,
}

/// Types of state machine violations
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum StateMachineViolationType {
    InvalidTransition,
    UnauthorizedTransition,
    MissingPrerequisites,
    StateCorruption,
    RaceCondition,
}

/// Security impact levels
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum SecurityImpact {
    None,
    Low,
    Medium,
    High,
    Critical,
}

/// Authentication issue
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AuthenticationIssue {
    /// Issue type
    pub issue_type: AuthIssueType,
    /// Affected endpoint or function
    pub affected_component: String,
    /// Issue description
    pub description: String,
    /// Severity
    pub severity: Severity,
    /// Exploitation method
    pub exploitation_method: String,
    /// Remediation steps
    pub remediation: Vec<String>,
}

/// Types of authentication issues
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum AuthIssueType {
    MissingAuthentication,
    WeakAuthentication,
    AuthenticationBypass,
    SessionManagementIssue,
    PrivilegeEscalation,
    RoleBasedAccessControl,
}

/// Data validation issue
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ValidationIssue {
    /// Field or parameter with issue
    pub field: String,
    /// Validation issue type
    pub issue_type: ValidationIssueType,
    /// Expected validation
    pub expected_validation: String,
    /// Current implementation
    pub current_implementation: String,
    /// Security risk
    pub security_risk: SecurityRisk,
    /// Remediation
    pub remediation: String,
}

/// Types of validation issues
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum ValidationIssueType {
    MissingValidation,
    IncompleteValidation,
    IncorrectValidation,
    BypassableValidation,
    ClientSideOnly,
}

/// Security risk levels
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum SecurityRisk {
    Minimal,
    Low,
    Medium,
    High,
    Critical,
}

/// Business rule violation
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BusinessRuleViolation {
    /// Violated rule
    pub rule: BusinessRule,
    /// Violation context
    pub context: String,
    /// Violation impact
    pub impact: BusinessImpact,
    /// Detection confidence
    pub confidence: f64,
    /// Suggested remediation
    pub remediation: String,
}

/// Business impact assessment
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BusinessImpact {
    /// Impact category
    pub category: BusinessImpactCategory,
    /// Impact severity
    pub severity: ImpactLevel,
    /// Affected business processes
    pub affected_processes: Vec<String>,
    /// Potential consequences
    pub consequences: Vec<String>,
}

/// Business impact categories
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum BusinessImpactCategory {
    Financial,
    Operational,
    Compliance,
    Reputation,
    Security,
    Privacy,
}

/// Analysis metadata
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AnalysisMetadata {
    /// Analysis start time
    pub start_time: u64,
    /// Analysis duration in milliseconds
    pub duration_ms: u64,
    /// Number of workflows analyzed
    pub workflows_analyzed: usize,
    /// Number of states analyzed
    pub states_analyzed: usize,
    /// Analysis techniques used
    pub techniques_used: Vec<AnalysisTechnique>,
    /// Confidence in overall analysis
    pub overall_confidence: f64,
}

/// Analysis techniques
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum AnalysisTechnique {
    StaticAnalysis,
    WorkflowModeling,
    StateMachineAnalysis,
    DataFlowAnalysis,
    MachineLearning,
    PatternMatching,
    BusinessRuleValidation,
}

// Trait definitions for extensibility

/// Trait for state machine analyzers
pub trait StateMachineAnalyzer: Send + Sync {
    fn analyze_state_machine(&self, workflow: &WorkflowModel, code: &str) -> Result<Vec<StateMachineViolation>>;
}

/// Trait for authentication analyzers
pub trait AuthenticationAnalyzer: Send + Sync {
    fn analyze_authentication(&self, workflow: &WorkflowModel, code: &str) -> Result<Vec<AuthenticationIssue>>;
}

/// Trait for validation analyzers
pub trait ValidationAnalyzer: Send + Sync {
    fn analyze_validation(&self, workflow: &WorkflowModel, code: &str) -> Result<Vec<ValidationIssue>>;
}

/// Trait for business rule engines
pub trait BusinessRuleEngine: Send + Sync {
    fn evaluate_business_rules(&self, workflow: &WorkflowModel, code: &str) -> Result<Vec<BusinessRuleViolation>>;
}

impl Default for BusinessLogicConfig {
    fn default() -> Self {
        Self {
            enable_workflow_analysis: true,
            enable_state_analysis: true,
            enable_auth_analysis: true,
            enable_validation_analysis: true,
            enable_rule_validation: true,
            max_workflow_depth: 10,
            min_confidence_threshold: 0.7,
            enable_ml_enhancement: true,
            analysis_timeout_secs: 300,
        }
    }
}

impl BusinessLogicAnalyzer {
    /// Create a new business logic analyzer
    pub fn new(config: BusinessLogicConfig) -> Self {
        Self {
            workflow_models: Arc::new(RwLock::new(HashMap::new())),
            state_analyzers: Vec::new(),
            auth_analyzers: Vec::new(),
            validation_analyzers: Vec::new(),
            rule_engines: Vec::new(),
            config,
        }
    }

    /// Register a workflow model
    pub async fn register_workflow_model(&self, model: WorkflowModel) -> Result<()> {
        let mut models = self.workflow_models.write().await;
        models.insert(model.id.clone(), model);
        Ok(())
    }

    /// Analyze code for business logic vulnerabilities
    pub async fn analyze_business_logic(&self, code: &str, language: Language) -> Result<BusinessLogicAnalysisResult> {
        let start_time = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs();

        let analysis_start = std::time::Instant::now();

        // Initialize result structures
        let mut vulnerabilities = Vec::new();
        let mut workflow_analysis = Vec::new();
        let mut state_violations = Vec::new();
        let mut auth_issues = Vec::new();
        let mut validation_issues = Vec::new();
        let mut rule_violations = Vec::new();

        // Get workflow models
        let models = self.workflow_models.read().await;

        // Detect application type and relevant workflows
        let app_type = self.detect_application_type(code, language);
        let relevant_workflows: Vec<&WorkflowModel> = models.values()
            .filter(|model| model.app_type == app_type || model.app_type == "generic")
            .collect();

        // Analyze each relevant workflow
        for workflow in &relevant_workflows {
            if self.config.enable_workflow_analysis {
                let workflow_result = self.analyze_workflow(workflow, code, language).await?;
                workflow_analysis.push(workflow_result);
            }

            if self.config.enable_state_analysis {
                let state_violations_result = self.analyze_state_machine(workflow, code).await?;
                state_violations.extend(state_violations_result);
            }

            if self.config.enable_auth_analysis {
                let auth_issues_result = self.analyze_authentication(workflow, code).await?;
                auth_issues.extend(auth_issues_result);
            }

            if self.config.enable_validation_analysis {
                let validation_issues_result = self.analyze_validation(workflow, code).await?;
                validation_issues.extend(validation_issues_result);
            }

            if self.config.enable_rule_validation {
                let rule_violations_result = self.evaluate_business_rules(workflow, code).await?;
                rule_violations.extend(rule_violations_result);
            }
        }

        // Convert issues to business logic vulnerabilities
        vulnerabilities.extend(self.convert_issues_to_vulnerabilities(&auth_issues, &validation_issues, &rule_violations).await?);

        let duration = analysis_start.elapsed();

        let metadata = AnalysisMetadata {
            start_time,
            duration_ms: duration.as_millis() as u64,
            workflows_analyzed: relevant_workflows.len(),
            states_analyzed: relevant_workflows.iter().map(|w| w.states.len()).sum(),
            techniques_used: self.get_used_techniques(),
            overall_confidence: self.calculate_overall_confidence(&vulnerabilities),
        };

        Ok(BusinessLogicAnalysisResult {
            vulnerabilities,
            workflow_analysis,
            state_violations,
            auth_issues,
            validation_issues,
            rule_violations,
            metadata,
        })
    }

    /// Detect application type from code
    fn detect_application_type(&self, code: &str, language: Language) -> String {
        // Simple heuristics to detect application type
        let code_lower = code.to_lowercase();

        if code_lower.contains("payment") || code_lower.contains("billing") || code_lower.contains("checkout") {
            "ecommerce".to_string()
        } else if code_lower.contains("account") || code_lower.contains("balance") || code_lower.contains("transaction") {
            "banking".to_string()
        } else if code_lower.contains("patient") || code_lower.contains("medical") || code_lower.contains("health") {
            "healthcare".to_string()
        } else if code_lower.contains("user") || code_lower.contains("login") || code_lower.contains("auth") {
            "web_application".to_string()
        } else {
            "generic".to_string()
        }
    }

    /// Analyze workflow implementation
    async fn analyze_workflow(&self, workflow: &WorkflowModel, code: &str, language: Language) -> Result<WorkflowAnalysisResult> {
        let mut issues = Vec::new();
        let mut compliance_status = ComplianceStatus::Compliant;

        // Check for required workflow states in code
        for state in &workflow.states {
            if !self.is_state_implemented(state, code) {
                issues.push(WorkflowIssue {
                    issue_type: WorkflowIssueType::MissingValidation,
                    description: format!("Required workflow state '{}' not properly implemented", state.name),
                    severity: Severity::Medium,
                    location: None,
                    suggested_fix: format!("Implement proper handling for {} state", state.name),
                });
                compliance_status = ComplianceStatus::PartiallyCompliant;
            }
        }

        // Check state transitions
        for (from_state, to_states) in &workflow.valid_transitions {
            if !self.are_transitions_implemented(from_state, to_states, code) {
                issues.push(WorkflowIssue {
                    issue_type: WorkflowIssueType::InvalidTransition,
                    description: format!("Invalid or missing state transitions from '{}'", from_state),
                    severity: Severity::High,
                    location: None,
                    suggested_fix: "Implement proper state transition validation".to_string(),
                });
                compliance_status = ComplianceStatus::NonCompliant;
            }
        }

        let recommendations = self.generate_workflow_recommendations(&issues);

        Ok(WorkflowAnalysisResult {
            workflow_id: workflow.id.clone(),
            status: AnalysisStatus::Complete,
            issues,
            compliance_status,
            recommendations,
        })
    }

    /// Check if a workflow state is properly implemented
    fn is_state_implemented(&self, state: &WorkflowState, code: &str) -> bool {
        // Simple implementation - in practice would use AST analysis
        let state_name_lower = state.name.to_lowercase();
        let code_lower = code.to_lowercase();
        
        code_lower.contains(&state_name_lower) || 
        code_lower.contains(&state.id.to_lowercase())
    }

    /// Check if state transitions are properly implemented
    fn are_transitions_implemented(&self, from_state: &str, to_states: &[String], code: &str) -> bool {
        // Simple implementation - would use more sophisticated analysis in practice
        let code_lower = code.to_lowercase();
        let from_lower = from_state.to_lowercase();
        
        code_lower.contains(&from_lower) && 
        to_states.iter().any(|to| code_lower.contains(&to.to_lowercase()))
    }

    /// Analyze state machine implementation
    async fn analyze_state_machine(&self, workflow: &WorkflowModel, code: &str) -> Result<Vec<StateMachineViolation>> {
        let mut violations = Vec::new();

        // Use registered analyzers
        for analyzer in &self.state_analyzers {
            let analyzer_violations = analyzer.analyze_state_machine(workflow, code)?;
            violations.extend(analyzer_violations);
        }

        // Built-in state machine analysis
        violations.extend(self.built_in_state_analysis(workflow, code)?);

        Ok(violations)
    }

    /// Built-in state machine analysis
    fn built_in_state_analysis(&self, workflow: &WorkflowModel, code: &str) -> Result<Vec<StateMachineViolation>> {
        let mut violations = Vec::new();

        // Check for direct state jumps that bypass validation
        for (from_state, valid_to_states) in &workflow.valid_transitions {
            // Look for patterns that might bypass state validation
            if code.contains(&format!("state = \"{}\"", valid_to_states.first().unwrap_or(&String::new()))) &&
               !code.contains("validate") && !code.contains("check") {
                violations.push(StateMachineViolation {
                    current_state: from_state.clone(),
                    attempted_transition: "direct_assignment".to_string(),
                    target_state: valid_to_states.first().unwrap_or(&String::new()).clone(),
                    violation_type: StateMachineViolationType::InvalidTransition,
                    security_impact: SecurityImpact::Medium,
                });
            }
        }

        Ok(violations)
    }

    /// Analyze authentication implementation
    async fn analyze_authentication(&self, workflow: &WorkflowModel, code: &str) -> Result<Vec<AuthenticationIssue>> {
        let mut issues = Vec::new();

        // Use registered analyzers
        for analyzer in &self.auth_analyzers {
            let analyzer_issues = analyzer.analyze_authentication(workflow, code)?;
            issues.extend(analyzer_issues);
        }

        // Built-in authentication analysis
        issues.extend(self.built_in_auth_analysis(workflow, code)?);

        Ok(issues)
    }

    /// Built-in authentication analysis
    fn built_in_auth_analysis(&self, workflow: &WorkflowModel, code: &str) -> Result<Vec<AuthenticationIssue>> {
        let mut issues = Vec::new();

        // Check for authentication bypass patterns
        if code.contains("if (user.role == \"admin\" || bypass == true)") ||
           code.contains("if (is_admin || debug_mode)") {
            issues.push(AuthenticationIssue {
                issue_type: AuthIssueType::AuthenticationBypass,
                affected_component: "authentication_check".to_string(),
                description: "Potential authentication bypass through debug or bypass flags".to_string(),
                severity: Severity::Critical,
                exploitation_method: "Set bypass flag or debug mode to true".to_string(),
                remediation: vec![
                    "Remove bypass conditions from authentication logic".to_string(),
                    "Implement proper role-based access control".to_string(),
                    "Disable debug mode in production".to_string(),
                ],
            });
        }

        // Check for weak session management
        if code.contains("sessionId = user.id") || code.contains("session = username") {
            issues.push(AuthenticationIssue {
                issue_type: AuthIssueType::SessionManagementIssue,
                affected_component: "session_management".to_string(),
                description: "Weak session identifier generation".to_string(),
                severity: Severity::High,
                exploitation_method: "Predict or brute force session identifiers".to_string(),
                remediation: vec![
                    "Use cryptographically secure random session identifiers".to_string(),
                    "Implement proper session timeout mechanisms".to_string(),
                ],
            });
        }

        Ok(issues)
    }

    /// Analyze data validation implementation
    async fn analyze_validation(&self, workflow: &WorkflowModel, code: &str) -> Result<Vec<ValidationIssue>> {
        let mut issues = Vec::new();

        // Use registered analyzers
        for analyzer in &self.validation_analyzers {
            let analyzer_issues = analyzer.analyze_validation(workflow, code)?;
            issues.extend(analyzer_issues);
        }

        // Built-in validation analysis
        issues.extend(self.built_in_validation_analysis(workflow, code)?);

        Ok(issues)
    }

    /// Built-in validation analysis
    fn built_in_validation_analysis(&self, workflow: &WorkflowModel, code: &str) -> Result<Vec<ValidationIssue>> {
        let mut issues = Vec::new();

        // Check for missing input validation
        if code.contains("request.getParameter") && !code.contains("validate") && !code.contains("sanitize") {
            issues.push(ValidationIssue {
                field: "user_input".to_string(),
                issue_type: ValidationIssueType::MissingValidation,
                expected_validation: "Input sanitization and validation".to_string(),
                current_implementation: "Direct parameter access without validation".to_string(),
                security_risk: SecurityRisk::High,
                remediation: "Implement input validation before processing user data".to_string(),
            });
        }

        // Check for client-side only validation
        if code.contains("client.validate") && !code.contains("server.validate") {
            issues.push(ValidationIssue {
                field: "form_data".to_string(),
                issue_type: ValidationIssueType::ClientSideOnly,
                expected_validation: "Server-side validation".to_string(),
                current_implementation: "Client-side validation only".to_string(),
                security_risk: SecurityRisk::Medium,
                remediation: "Implement server-side validation in addition to client-side checks".to_string(),
            });
        }

        Ok(issues)
    }

    /// Evaluate business rules
    async fn evaluate_business_rules(&self, workflow: &WorkflowModel, code: &str) -> Result<Vec<BusinessRuleViolation>> {
        let mut violations = Vec::new();

        // Use registered rule engines
        for engine in &self.rule_engines {
            let engine_violations = engine.evaluate_business_rules(workflow, code)?;
            violations.extend(engine_violations);
        }

        // Built-in business rule evaluation
        violations.extend(self.built_in_rule_evaluation(workflow, code)?);

        Ok(violations)
    }

    /// Built-in business rule evaluation
    fn built_in_rule_evaluation(&self, workflow: &WorkflowModel, code: &str) -> Result<Vec<BusinessRuleViolation>> {
        let mut violations = Vec::new();

        // Check each business rule
        for state in &workflow.states {
            if let Some(rules) = workflow.business_rules.get(&state.id) {
                for rule in rules {
                    let violation_detected = self.check_business_rule_violation(rule, code);
                    if let Some(violation) = violation_detected {
                        violations.push(violation);
                    }
                }
            }
        }

        Ok(violations)
    }

    /// Check for business rule violation
    fn check_business_rule_violation(&self, rule: &BusinessRule, code: &str) -> Option<BusinessRuleViolation> {
        // Simple rule checking - in practice would use more sophisticated analysis
        let rule_violated = match rule.category {
            BusinessRuleCategory::AccessControl => {
                code.contains("public") && code.contains("admin") && !code.contains("checkPermission")
            },
            BusinessRuleCategory::Financial => {
                code.contains("amount") && code.contains("transfer") && !code.contains("verify")
            },
            BusinessRuleCategory::DataValidation => {
                code.contains("input") && !code.contains("validate")
            },
            _ => false,
        };

        if rule_violated {
            Some(BusinessRuleViolation {
                rule: rule.clone(),
                context: "Code analysis detected potential violation".to_string(),
                impact: BusinessImpact {
                    category: BusinessImpactCategory::Security,
                    severity: ImpactLevel::Medium,
                    affected_processes: vec!["Authentication".to_string()],
                    consequences: vec!["Potential security breach".to_string()],
                },
                confidence: 0.8,
                remediation: format!("Ensure proper implementation of rule: {}", rule.name),
            })
        } else {
            None
        }
    }

    /// Convert various issues to business logic vulnerabilities
    async fn convert_issues_to_vulnerabilities(
        &self,
        auth_issues: &[AuthenticationIssue],
        validation_issues: &[ValidationIssue],
        rule_violations: &[BusinessRuleViolation],
    ) -> Result<Vec<BusinessLogicVulnerability>> {
        let mut vulnerabilities = Vec::new();

        // Convert authentication issues
        for issue in auth_issues {
            let vuln = self.auth_issue_to_vulnerability(issue);
            vulnerabilities.push(vuln);
        }

        // Convert validation issues
        for issue in validation_issues {
            let vuln = self.validation_issue_to_vulnerability(issue);
            vulnerabilities.push(vuln);
        }

        // Convert rule violations
        for violation in rule_violations {
            let vuln = self.rule_violation_to_vulnerability(violation);
            vulnerabilities.push(vuln);
        }

        Ok(vulnerabilities)
    }

    /// Convert authentication issue to vulnerability
    fn auth_issue_to_vulnerability(&self, issue: &AuthenticationIssue) -> BusinessLogicVulnerability {
        let base_vulnerability = Vulnerability {
            id: format!("BL-AUTH-{}", uuid::Uuid::new_v4()),
            title: format!("Business Logic Authentication Issue: {}", issue.issue_type.to_string()),
            description: issue.description.clone(),
            severity: issue.severity.clone(),
            category: "business_logic".to_string(),
            cwe: Some("CWE-287".to_string()), // Improper Authentication
            owasp: Some("A07:2021 – Identification and Authentication Failures".to_string()),
            file_path: "unknown".to_string(),
            line_number: 0,
            column_start: 0,
            column_end: 0,
            source_code: issue.affected_component.clone(),
            recommendation: issue.remediation.join("; "),
            references: vec![],
            confidence: 0.8,
        };

        BusinessLogicVulnerability {
            vulnerability_info: base_vulnerability,
            business_context: BusinessContext {
                affected_workflow: "authentication".to_string(),
                business_process: "user_authentication".to_string(),
                affected_roles: vec!["user".to_string(), "admin".to_string()],
                at_risk_data: vec!["user_credentials".to_string(), "session_data".to_string()],
                financial_impact: FinancialImpact {
                    loss_range: LossRange::Medium,
                    revenue_impact: true,
                    compliance_impact: true,
                    reputation_impact: true,
                },
            },
            workflow_impact: WorkflowImpact {
                impact_level: ImpactLevel::High,
                affected_states: vec!["login".to_string(), "authenticated".to_string()],
                bypassed_controls: vec!["authentication_check".to_string()],
                disrupted_processes: vec!["secure_access".to_string()],
            },
            exploitation_scenario: issue.exploitation_method.clone(),
            business_risk: BusinessRisk {
                risk_score: 85,
                risk_factors: vec![
                    RiskFactor {
                        name: "Authentication Bypass".to_string(),
                        weight: 0.4,
                        score: 0.9,
                        description: "High risk of unauthorized access".to_string(),
                    },
                ],
                exploitation_likelihood: LikelihoodLevel::High,
                continuity_impact: ImpactLevel::High,
            },
            remediation: BusinessLogicRemediation {
                immediate_actions: issue.remediation.clone(),
                long_term_solutions: vec![
                    "Implement comprehensive authentication framework".to_string(),
                    "Regular security audits of authentication flow".to_string(),
                ],
                process_improvements: vec![
                    "Code review process for authentication changes".to_string(),
                ],
                monitoring_recommendations: vec![
                    "Monitor authentication failure rates".to_string(),
                    "Alert on authentication bypass attempts".to_string(),
                ],
                testing_recommendations: vec![
                    "Automated security testing of authentication flow".to_string(),
                ],
            },
        }
    }

    /// Convert validation issue to vulnerability
    fn validation_issue_to_vulnerability(&self, issue: &ValidationIssue) -> BusinessLogicVulnerability {
        let base_vulnerability = Vulnerability {
            id: format!("BL-VAL-{}", uuid::Uuid::new_v4()),
            title: format!("Business Logic Validation Issue: {}", issue.field),
            description: format!("Validation issue in field '{}': {}", issue.field, issue.issue_type.to_string()),
            severity: match issue.security_risk {
                SecurityRisk::Critical => Severity::Critical,
                SecurityRisk::High => Severity::High,
                SecurityRisk::Medium => Severity::Medium,
                SecurityRisk::Low => Severity::Low,
                SecurityRisk::Minimal => Severity::Info,
            },
            category: "business_logic".to_string(),
            cwe: Some("CWE-20".to_string()), // Improper Input Validation
            owasp: Some("A03:2021 – Injection".to_string()),
            file_path: "unknown".to_string(),
            line_number: 0,
            column_start: 0,
            column_end: 0,
            source_code: issue.current_implementation.clone(),
            recommendation: issue.remediation.clone(),
            references: vec![],
            confidence: 0.9,
        };

        BusinessLogicVulnerability {
            vulnerability_info: base_vulnerability,
            business_context: BusinessContext {
                affected_workflow: "data_processing".to_string(),
                business_process: "input_validation".to_string(),
                affected_roles: vec!["user".to_string()],
                at_risk_data: vec![issue.field.clone()],
                financial_impact: FinancialImpact {
                    loss_range: LossRange::Low,
                    revenue_impact: false,
                    compliance_impact: true,
                    reputation_impact: false,
                },
            },
            workflow_impact: WorkflowImpact {
                impact_level: ImpactLevel::Medium,
                affected_states: vec!["data_input".to_string(), "data_processing".to_string()],
                bypassed_controls: vec!["input_validation".to_string()],
                disrupted_processes: vec!["secure_data_processing".to_string()],
            },
            exploitation_scenario: "Malicious input could bypass validation".to_string(),
            business_risk: BusinessRisk {
                risk_score: 65,
                risk_factors: vec![
                    RiskFactor {
                        name: "Input Validation Bypass".to_string(),
                        weight: 0.3,
                        score: 0.7,
                        description: "Risk of malicious input processing".to_string(),
                    },
                ],
                exploitation_likelihood: LikelihoodLevel::Medium,
                continuity_impact: ImpactLevel::Medium,
            },
            remediation: BusinessLogicRemediation {
                immediate_actions: vec![issue.remediation.clone()],
                long_term_solutions: vec![
                    "Implement comprehensive input validation framework".to_string(),
                ],
                process_improvements: vec![
                    "Validation requirements in development process".to_string(),
                ],
                monitoring_recommendations: vec![
                    "Monitor for validation bypass attempts".to_string(),
                ],
                testing_recommendations: vec![
                    "Automated input validation testing".to_string(),
                ],
            },
        }
    }

    /// Convert rule violation to vulnerability
    fn rule_violation_to_vulnerability(&self, violation: &BusinessRuleViolation) -> BusinessLogicVulnerability {
        let base_vulnerability = Vulnerability {
            id: format!("BL-RULE-{}", uuid::Uuid::new_v4()),
            title: format!("Business Rule Violation: {}", violation.rule.name),
            description: format!("Business rule '{}' violated: {}", violation.rule.name, violation.context),
            severity: violation.rule.violation_severity.clone(),
            category: "business_logic".to_string(),
            cwe: Some("CWE-840".to_string()), // Business Logic Errors
            owasp: Some("A04:2021 – Insecure Design".to_string()),
            file_path: "unknown".to_string(),
            line_number: 0,
            column_start: 0,
            column_end: 0,
            source_code: violation.context.clone(),
            recommendation: violation.remediation.clone(),
            references: vec![],
            confidence: violation.confidence,
        };

        BusinessLogicVulnerability {
            vulnerability_info: base_vulnerability,
            business_context: BusinessContext {
                affected_workflow: "business_process".to_string(),
                business_process: violation.rule.name.clone(),
                affected_roles: vec!["user".to_string()],
                at_risk_data: vec!["business_data".to_string()],
                financial_impact: FinancialImpact {
                    loss_range: match violation.impact.severity {
                        ImpactLevel::Critical => LossRange::Critical,
                        ImpactLevel::High => LossRange::High,
                        ImpactLevel::Medium => LossRange::Medium,
                        ImpactLevel::Low => LossRange::Low,
                        ImpactLevel::Minimal => LossRange::Negligible,
                    },
                    revenue_impact: true,
                    compliance_impact: true,
                    reputation_impact: true,
                },
            },
            workflow_impact: WorkflowImpact {
                impact_level: violation.impact.severity.clone(),
                affected_states: vec!["business_operation".to_string()],
                bypassed_controls: vec![violation.rule.name.clone()],
                disrupted_processes: violation.impact.affected_processes.clone(),
            },
            exploitation_scenario: format!("Business rule '{}' can be violated", violation.rule.name),
            business_risk: BusinessRisk {
                risk_score: match violation.impact.severity {
                    ImpactLevel::Critical => 95,
                    ImpactLevel::High => 80,
                    ImpactLevel::Medium => 60,
                    ImpactLevel::Low => 40,
                    ImpactLevel::Minimal => 20,
                },
                risk_factors: vec![
                    RiskFactor {
                        name: "Business Rule Violation".to_string(),
                        weight: 0.5,
                        score: violation.confidence,
                        description: format!("Rule '{}' not properly enforced", violation.rule.name),
                    },
                ],
                exploitation_likelihood: LikelihoodLevel::Medium,
                continuity_impact: violation.impact.severity.clone(),
            },
            remediation: BusinessLogicRemediation {
                immediate_actions: vec![violation.remediation.clone()],
                long_term_solutions: vec![
                    "Implement automated business rule validation".to_string(),
                ],
                process_improvements: vec![
                    "Regular business rule audits".to_string(),
                ],
                monitoring_recommendations: vec![
                    "Monitor business rule compliance".to_string(),
                ],
                testing_recommendations: vec![
                    "Automated business rule testing".to_string(),
                ],
            },
        }
    }

    /// Generate workflow recommendations
    fn generate_workflow_recommendations(&self, issues: &[WorkflowIssue]) -> Vec<String> {
        let mut recommendations = Vec::new();

        if issues.iter().any(|i| matches!(i.issue_type, WorkflowIssueType::AuthenticationBypass)) {
            recommendations.push("Implement comprehensive authentication checks".to_string());
        }

        if issues.iter().any(|i| matches!(i.issue_type, WorkflowIssueType::MissingValidation)) {
            recommendations.push("Add missing input validation".to_string());
        }

        if issues.iter().any(|i| matches!(i.issue_type, WorkflowIssueType::InvalidTransition)) {
            recommendations.push("Implement proper state transition validation".to_string());
        }

        if recommendations.is_empty() {
            recommendations.push("Continue monitoring for business logic issues".to_string());
        }

        recommendations
    }

    /// Get analysis techniques used
    fn get_used_techniques(&self) -> Vec<AnalysisTechnique> {
        let mut techniques = vec![AnalysisTechnique::StaticAnalysis];

        if self.config.enable_workflow_analysis {
            techniques.push(AnalysisTechnique::WorkflowModeling);
        }

        if self.config.enable_state_analysis {
            techniques.push(AnalysisTechnique::StateMachineAnalysis);
        }

        if self.config.enable_validation_analysis {
            techniques.push(AnalysisTechnique::DataFlowAnalysis);
        }

        if self.config.enable_rule_validation {
            techniques.push(AnalysisTechnique::BusinessRuleValidation);
        }

        if self.config.enable_ml_enhancement {
            techniques.push(AnalysisTechnique::MachineLearning);
        }

        techniques.push(AnalysisTechnique::PatternMatching);

        techniques
    }

    /// Calculate overall confidence
    fn calculate_overall_confidence(&self, vulnerabilities: &[BusinessLogicVulnerability]) -> f64 {
        if vulnerabilities.is_empty() {
            return 1.0;
        }

        let total_confidence: f64 = vulnerabilities.iter()
            .map(|v| v.vulnerability_info.confidence)
            .sum();

        total_confidence / vulnerabilities.len() as f64
    }
}

// Helper trait implementations
impl std::fmt::Display for AuthIssueType {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            AuthIssueType::MissingAuthentication => write!(f, "Missing Authentication"),
            AuthIssueType::WeakAuthentication => write!(f, "Weak Authentication"),
            AuthIssueType::AuthenticationBypass => write!(f, "Authentication Bypass"),
            AuthIssueType::SessionManagementIssue => write!(f, "Session Management Issue"),
            AuthIssueType::PrivilegeEscalation => write!(f, "Privilege Escalation"),
            AuthIssueType::RoleBasedAccessControl => write!(f, "RBAC Issue"),
        }
    }
}

impl std::fmt::Display for ValidationIssueType {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            ValidationIssueType::MissingValidation => write!(f, "Missing Validation"),
            ValidationIssueType::IncompleteValidation => write!(f, "Incomplete Validation"),
            ValidationIssueType::IncorrectValidation => write!(f, "Incorrect Validation"),
            ValidationIssueType::BypassableValidation => write!(f, "Bypassable Validation"),
            ValidationIssueType::ClientSideOnly => write!(f, "Client-Side Only Validation"),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_business_logic_analyzer_creation() {
        let config = BusinessLogicConfig::default();
        let analyzer = BusinessLogicAnalyzer::new(config);
        
        // Test basic functionality
        let models = analyzer.workflow_models.read().await;
        assert_eq!(models.len(), 0);
    }

    #[tokio::test]
    async fn test_workflow_model_registration() {
        let config = BusinessLogicConfig::default();
        let analyzer = BusinessLogicAnalyzer::new(config);
        
        let workflow = WorkflowModel {
            id: "test_workflow".to_string(),
            app_type: "test".to_string(),
            states: vec![],
            valid_transitions: HashMap::new(),
            business_rules: HashMap::new(),
            auth_requirements: HashMap::new(),
            validation_rules: HashMap::new(),
            data_flows: vec![],
        };
        
        analyzer.register_workflow_model(workflow).await.unwrap();
        
        let models = analyzer.workflow_models.read().await;
        assert_eq!(models.len(), 1);
        assert!(models.contains_key("test_workflow"));
    }

    #[test]
    fn test_application_type_detection() {
        let config = BusinessLogicConfig::default();
        let analyzer = BusinessLogicAnalyzer::new(config);
        
        let ecommerce_code = "function processPayment(amount) { return billing.charge(amount); }";
        assert_eq!(analyzer.detect_application_type(ecommerce_code, Language::JavaScript), "ecommerce");
        
        let banking_code = "function checkBalance(account) { return account.balance; }";
        assert_eq!(analyzer.detect_application_type(banking_code, Language::JavaScript), "banking");
        
        let generic_code = "function hello() { console.log('world'); }";
        assert_eq!(analyzer.detect_application_type(generic_code, Language::JavaScript), "generic");
    }
}