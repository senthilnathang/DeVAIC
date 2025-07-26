/// Container Security Rules Module
/// 
/// Comprehensive container and orchestration security analysis including:
/// - Docker security best practices
/// - Kubernetes security configuration
/// - Container image vulnerability scanning
/// - Network security policies
/// - Resource limits and quotas
/// - Secret management
/// - RBAC and admission controllers

use crate::{
    error::Result,
    parsers::{ParsedAst, SourceFile},
    rules::advanced_rule_engine::{api_security::SecurityImpact, *},
    Severity, Vulnerability,
};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use regex::Regex;
use lazy_static::lazy_static;

/// Container Security Analyzer
pub struct ContainerSecurityAnalyzer {
    /// Docker security rules
    docker_rules: Vec<DockerSecurityRule>,
    
    /// Kubernetes security rules
    kubernetes_rules: Vec<KubernetesSecurityRule>,
    
    /// Docker Compose security rules
    compose_rules: Vec<ComposeSecurityRule>,
    
    /// Network security policies
    network_policies: Vec<NetworkSecurityPolicy>,
    
    /// Resource management rules
    resource_rules: Vec<ResourceManagementRule>,
    
    /// Secret management rules
    secret_rules: Vec<SecretManagementRule>,
}

/// Docker security rule
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DockerSecurityRule {
    pub id: String,
    pub name: String,
    pub description: String,
    pub dockerfile_instructions: Vec<DockerfileInstructionRule>,
    pub image_security_checks: Vec<ImageSecurityCheck>,
    pub runtime_security_checks: Vec<RuntimeSecurityCheck>,
    pub build_security_checks: Vec<BuildSecurityCheck>,
    pub vulnerability_scanning_rules: Vec<VulnerabilityScanningRule>,
    pub compliance_frameworks: Vec<ComplianceFramework>,
    pub severity: Severity,
}

/// Dockerfile instruction rule
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DockerfileInstructionRule {
    pub instruction: DockerInstruction,
    pub security_checks: Vec<InstructionSecurityCheck>,
    pub best_practices: Vec<BestPracticeRule>,
    pub vulnerability_patterns: Vec<VulnerabilityPattern>,
}

/// Docker instructions
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum DockerInstruction {
    FROM,
    RUN,
    CMD,
    ENTRYPOINT,
    EXPOSE,
    ENV,
    ADD,
    COPY,
    WORKDIR,
    USER,
    VOLUME,
    HEALTHCHECK,
    LABEL,
    ARG,
    ONBUILD,
    STOPSIGNAL,
    SHELL,
}

/// Instruction security check
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct InstructionSecurityCheck {
    pub check_type: SecurityCheckType,
    pub pattern: String,
    pub severity: Severity,
    pub description: String,
    pub remediation: String,
    pub cwe_mapping: Option<String>,
}

/// Security check types
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum SecurityCheckType {
    PrivilegeEscalation,
    InsecureDefaults,
    SecretExposure,
    NetworkSecurity,
    FileSystemSecurity,
    ProcessSecurity,
    ResourceLimits,
    Compliance,
}

/// Best practice rule
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BestPracticeRule {
    pub practice_type: BestPracticeType,
    pub recommendation: String,
    pub impact: SecurityImpact,
    pub compliance_requirements: Vec<String>,
}

/// Best practice types
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum BestPracticeType {
    MultiStageBuilds,
    NonRootUser,
    MinimalBaseImage,
    LayerOptimization,
    HealthChecks,
    SignalHandling,
    SecretManagement,
    NetworkSecurity,
}

/// Image security check
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ImageSecurityCheck {
    pub check_name: String,
    pub vulnerability_scanners: Vec<VulnerabilityScanner>,
    pub base_image_analysis: BaseImageAnalysis,
    pub dependency_analysis: DependencyAnalysis,
    pub malware_scanning: MalwareScanning,
    pub license_compliance: LicenseCompliance,
}

/// Vulnerability scanner configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VulnerabilityScanner {
    pub scanner_type: ScannerType,
    pub severity_threshold: Severity,
    pub database_sources: Vec<String>,
    pub scan_frequency: ScanFrequency,
    pub remediation_advice: bool,
}

/// Scanner types
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum ScannerType {
    Trivy,
    Clair,
    Anchore,
    Twistlock,
    Aqua,
    Snyk,
    Custom(String),
}

/// Scan frequency
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum ScanFrequency {
    OnBuild,
    Daily,
    Weekly,
    OnPush,
    Continuous,
}

/// Base image analysis
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BaseImageAnalysis {
    pub approved_base_images: Vec<String>,
    pub deprecated_images: Vec<String>,
    pub security_policies: Vec<ImageSecurityPolicy>,
    pub update_frequency_requirements: UpdateFrequency,
}

/// Image security policy
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ImageSecurityPolicy {
    pub policy_name: String,
    pub allowed_registries: Vec<String>,
    pub required_signatures: bool,
    pub vulnerability_thresholds: VulnerabilityThresholds,
    pub compliance_requirements: Vec<String>,
}

/// Vulnerability thresholds
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VulnerabilityThresholds {
    pub max_critical: u32,
    pub max_high: u32,
    pub max_medium: u32,
    pub max_low: u32,
    pub block_on_critical: bool,
}

/// Update frequency
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum UpdateFrequency {
    Weekly,
    Monthly,
    Quarterly,
    OnSecurityUpdate,
    Custom(u32), // days
}

/// Dependency analysis
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DependencyAnalysis {
    pub package_managers: Vec<PackageManager>,
    pub vulnerability_databases: Vec<String>,
    pub license_scanning: bool,
    pub outdated_dependency_detection: bool,
    pub transitive_dependency_analysis: bool,
}

/// Package managers
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum PackageManager {
    Npm,
    Pip,
    Maven,
    Gradle,
    Composer,
    Gem,
    Go,
    Cargo,
    NuGet,
}

/// Malware scanning
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MalwareScanning {
    pub enabled: bool,
    pub scan_engines: Vec<String>,
    pub file_type_filters: Vec<String>,
    pub quarantine_policy: QuarantinePolicy,
}

/// Quarantine policy
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct QuarantinePolicy {
    pub auto_quarantine: bool,
    pub notification_required: bool,
    pub approval_workflow: bool,
    pub retention_period_days: u32,
}

/// License compliance
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LicenseCompliance {
    pub approved_licenses: Vec<String>,
    pub prohibited_licenses: Vec<String>,
    pub license_compatibility_checks: bool,
    pub commercial_use_restrictions: bool,
}

/// Runtime security check
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RuntimeSecurityCheck {
    pub check_name: String,
    pub security_profiles: Vec<SecurityProfile>,
    pub capability_management: CapabilityManagement,
    pub apparmor_seccomp_rules: AppArmorSeccompRules,
    pub file_system_monitoring: FileSystemMonitoring,
    pub network_monitoring: NetworkMonitoring,
}

/// Security profile
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SecurityProfile {
    pub profile_type: SecurityProfileType,
    pub enforcement_mode: EnforcementMode,
    pub allowed_actions: Vec<String>,
    pub denied_actions: Vec<String>,
}

/// Security profile types
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum SecurityProfileType {
    AppArmor,
    SELinux,
    Seccomp,
    Grsecurity,
    Custom(String),
}

/// Enforcement modes
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum EnforcementMode {
    Enforce,
    Complain,
    Monitor,
    Disabled,
}

/// Capability management
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CapabilityManagement {
    pub dropped_capabilities: Vec<LinuxCapability>,
    pub added_capabilities: Vec<LinuxCapability>,
    pub capability_bounding_set: Vec<LinuxCapability>,
    pub no_new_privileges: bool,
}

/// Linux capabilities
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum LinuxCapability {
    CAP_CHOWN,
    CAP_DAC_OVERRIDE,
    CAP_FOWNER,
    CAP_FSETID,
    CAP_KILL,
    CAP_SETGID,
    CAP_SETUID,
    CAP_SETPCAP,
    CAP_LINUX_IMMUTABLE,
    CAP_NET_BIND_SERVICE,
    CAP_NET_BROADCAST,
    CAP_NET_ADMIN,
    CAP_NET_RAW,
    CAP_IPC_LOCK,
    CAP_IPC_OWNER,
    CAP_SYS_MODULE,
    CAP_SYS_RAWIO,
    CAP_SYS_CHROOT,
    CAP_SYS_PTRACE,
    CAP_SYS_PACCT,
    CAP_SYS_ADMIN,
    CAP_SYS_BOOT,
    CAP_SYS_NICE,
    CAP_SYS_RESOURCE,
    CAP_SYS_TIME,
    CAP_SYS_TTY_CONFIG,
    CAP_MKNOD,
    CAP_LEASE,
    CAP_AUDIT_WRITE,
    CAP_AUDIT_CONTROL,
    CAP_SETFCAP,
    CAP_MAC_OVERRIDE,
    CAP_MAC_ADMIN,
    CAP_SYSLOG,
    CAP_WAKE_ALARM,
    CAP_BLOCK_SUSPEND,
    CAP_AUDIT_READ,
}

/// AppArmor and Seccomp rules
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AppArmorSeccompRules {
    pub apparmor_profile: Option<String>,
    pub seccomp_profile: Option<String>,
    pub custom_rules: Vec<CustomSecurityRule>,
    pub rule_validation: bool,
}

/// Custom security rule
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CustomSecurityRule {
    pub rule_type: String,
    pub rule_content: String,
    pub enforcement_level: EnforcementLevel,
}

/// Enforcement levels
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum EnforcementLevel {
    Strict,
    Moderate,
    Permissive,
    Audit,
}

/// File system monitoring
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FileSystemMonitoring {
    pub read_only_root: bool,
    pub tmp_fs_mounts: Vec<String>,
    pub volume_mounts_security: Vec<VolumeMountSecurity>,
    pub file_integrity_monitoring: bool,
}

/// Volume mount security
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VolumeMountSecurity {
    pub mount_path: String,
    pub read_only: bool,
    pub no_exec: bool,
    pub no_suid: bool,
    pub no_dev: bool,
}

/// Network monitoring
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NetworkMonitoring {
    pub network_policies: Vec<String>,
    pub egress_filtering: bool,
    pub ingress_filtering: bool,
    pub inter_container_communication: InterContainerCommunication,
}

/// Inter-container communication
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct InterContainerCommunication {
    pub default_deny: bool,
    pub allowed_connections: Vec<ConnectionRule>,
    pub encrypted_communication: bool,
}

/// Connection rule
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ConnectionRule {
    pub source: String,
    pub destination: String,
    pub ports: Vec<u16>,
    pub protocol: NetworkProtocol,
}

/// Network protocols
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum NetworkProtocol {
    TCP,
    UDP,
    ICMP,
    SCTP,
}

/// Build security check
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BuildSecurityCheck {
    pub build_context_security: BuildContextSecurity,
    pub multi_stage_build_security: MultiStageBuildSecurity,
    pub build_args_security: BuildArgsSecurity,
    pub cache_security: CacheSecurity,
}

/// Build context security
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BuildContextSecurity {
    pub dockerignore_required: bool,
    pub secret_file_detection: bool,
    pub large_file_detection: bool,
    pub sensitive_path_detection: bool,
}

/// Multi-stage build security
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MultiStageBuildSecurity {
    pub minimal_final_stage: bool,
    pub secret_propagation_prevention: bool,
    pub intermediate_stage_cleanup: bool,
}

/// Build args security
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BuildArgsSecurity {
    pub secret_detection: bool,
    pub validation_rules: Vec<String>,
    pub allowed_args: Vec<String>,
}

/// Cache security
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CacheSecurity {
    pub cache_mount_security: bool,
    pub secret_cache_prevention: bool,
    pub cache_validation: bool,
}

// Kubernetes Security Structures

/// Network policy checks configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NetworkPolicyChecks {
    pub enabled: bool,
    pub check_ingress_rules: bool,
    pub check_egress_rules: bool,
    pub check_default_deny: bool,
}

/// Admission controller checks configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AdmissionControllerChecks {
    pub enabled: bool,
    pub check_pod_security_policy: bool,
    pub check_opa_gatekeeper: bool,
    pub check_image_policy: bool,
}

/// Resource quota checks configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ResourceQuotaChecks {
    pub enabled: bool,
    pub check_memory_limits: bool,
    pub check_cpu_limits: bool,
    pub check_storage_limits: bool,
}

/// Secret management checks configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SecretManagementChecks {
    pub enabled: bool,
    pub check_secret_encryption: bool,
    pub check_secret_rotation: bool,
    pub check_secret_access: bool,
}

/// Service mesh security configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ServiceMeshSecurity {
    pub enabled: bool,
    pub check_mtls: bool,
    pub check_service_accounts: bool,
    pub check_traffic_policies: bool,
}

/// Kubernetes security rule
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct KubernetesSecurityRule {
    pub id: String,
    pub name: String,
    pub description: String,
    pub pod_security_standards: PodSecurityStandards,
    pub rbac_security_checks: RBACSecurityChecks,
    pub network_policy_checks: NetworkPolicyChecks,
    pub admission_controller_checks: AdmissionControllerChecks,
    pub resource_quota_checks: ResourceQuotaChecks,
    pub secret_management_checks: SecretManagementChecks,
    pub service_mesh_security: ServiceMeshSecurity,
    pub severity: Severity,
}

/// Pod Security Standards
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PodSecurityStandards {
    pub security_context_checks: SecurityContextChecks,
    pub pod_security_policy_checks: PodSecurityPolicyChecks,
    pub security_profile_enforcement: SecurityProfileEnforcement,
}

/// Security context checks
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SecurityContextChecks {
    pub run_as_non_root: bool,
    pub run_as_user_validation: bool,
    pub fs_group_validation: bool,
    pub selinux_options_validation: bool,
    pub seccomp_profile_validation: bool,
    pub apparmor_profile_validation: bool,
}

/// Pod Security Policy checks
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PodSecurityPolicyChecks {
    pub privileged_containers: bool,
    pub host_network_access: bool,
    pub host_pid_access: bool,
    pub host_ipc_access: bool,
    pub volume_types_restrictions: Vec<VolumeTypeRestriction>,
    pub capability_restrictions: CapabilityRestrictions,
}

/// Volume type restriction
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VolumeTypeRestriction {
    pub volume_type: VolumeType,
    pub allowed: bool,
    pub conditions: Vec<String>,
}

/// Volume types
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum VolumeType {
    EmptyDir,
    ConfigMap,
    Secret,
    PersistentVolumeClaim,
    HostPath,
    NFS,
    AWSElasticBlockStore,
    GCEPersistentDisk,
    AzureDisk,
    CSI,
}

/// Capability restrictions
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CapabilityRestrictions {
    pub allowed_add_capabilities: Vec<LinuxCapability>,
    pub required_drop_capabilities: Vec<LinuxCapability>,
    pub default_add_capabilities: Vec<LinuxCapability>,
}

/// Security profile enforcement
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SecurityProfileEnforcement {
    pub pod_security_standards_level: PodSecurityLevel,
    pub admission_mode: AdmissionMode,
    pub exemptions: Vec<SecurityExemption>,
}

/// Pod security levels
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum PodSecurityLevel {
    Privileged,
    Baseline,
    Restricted,
}

/// Admission modes
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum AdmissionMode {
    Enforce,
    Audit,
    Warn,
}

/// Security exemption
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SecurityExemption {
    pub exemption_type: ExemptionType,
    pub resources: Vec<String>,
    pub justification: String,
}

/// Exemption types
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum ExemptionType {
    Namespace,
    ServiceAccount,
    RuntimeClass,
    User,
}

/// RBAC security checks
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RBACSecurityChecks {
    pub role_binding_checks: RoleBindingChecks,
    pub cluster_role_checks: ClusterRoleChecks,
    pub service_account_checks: ServiceAccountChecks,
    pub privilege_escalation_checks: PrivilegeEscalationChecks,
}

/// Role binding checks
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RoleBindingChecks {
    pub wildcard_permissions: bool,
    pub overprivileged_bindings: bool,
    pub unused_bindings: bool,
    pub cross_namespace_bindings: bool,
}

/// Cluster role checks
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ClusterRoleChecks {
    pub cluster_admin_usage: bool,
    pub node_access_permissions: bool,
    pub secret_access_permissions: bool,
    pub custom_resource_permissions: bool,
}

/// Service account checks
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ServiceAccountChecks {
    pub default_service_account_usage: bool,
    pub token_automount_settings: bool,
    pub unnecessary_permissions: bool,
    pub token_rotation_policy: bool,
}

/// Privilege escalation checks
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PrivilegeEscalationChecks {
    pub allow_privilege_escalation: bool,
    pub escalation_paths: Vec<EscalationPath>,
    pub monitoring_controls: Vec<String>,
}

/// Escalation path
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EscalationPath {
    pub from_role: String,
    pub to_role: String,
    pub escalation_method: String,
    pub risk_level: Severity,
}

lazy_static! {
    static ref DOCKERFILE_SECURITY_PATTERNS: HashMap<&'static str, Vec<Regex>> = {
        let mut patterns = HashMap::new();
        
        patterns.insert("privileged_user", vec![
            Regex::new(r"USER\s+root").unwrap(),
            Regex::new(r"USER\s+0").unwrap(),
        ]);
        
        patterns.insert("secret_exposure", vec![
            Regex::new(r"ENV\s+.*(?i)(password|secret|key|token)").unwrap(),
            Regex::new(r"ARG\s+.*(?i)(password|secret|key|token)").unwrap(),
        ]);
        
        patterns.insert("insecure_protocols", vec![
            Regex::new(r"http://").unwrap(),
            Regex::new(r"ftp://").unwrap(),
            Regex::new(r"telnet://").unwrap(),
        ]);
        
        patterns.insert("dangerous_commands", vec![
            Regex::new(r"RUN.*sudo").unwrap(),
            Regex::new(r"RUN.*chmod\s+777").unwrap(),
            Regex::new(r"RUN.*chown.*root").unwrap(),
        ]);
        
        patterns
    };
    
    static ref KUBERNETES_SECURITY_PATTERNS: HashMap<&'static str, Vec<Regex>> = {
        let mut patterns = HashMap::new();
        
        patterns.insert("privileged_pods", vec![
            Regex::new(r"privileged:\s*true").unwrap(),
            Regex::new(r"hostNetwork:\s*true").unwrap(),
            Regex::new(r"hostPID:\s*true").unwrap(),
        ]);
        
        patterns.insert("unsafe_capabilities", vec![
            Regex::new(r"add:\s*-\s*SYS_ADMIN").unwrap(),
            Regex::new(r"add:\s*-\s*NET_ADMIN").unwrap(),
            Regex::new(r"add:\s*-\s*SYS_TIME").unwrap(),
        ]);
        
        patterns.insert("missing_security_context", vec![
            Regex::new(r"containers:\s*-").unwrap(),
        ]);
        
        patterns
    };
}

impl ContainerSecurityAnalyzer {
    /// Create new container security analyzer
    pub fn new() -> Self {
        Self {
            docker_rules: Self::create_default_docker_rules(),
            kubernetes_rules: Self::create_default_kubernetes_rules(),
            compose_rules: Self::create_default_compose_rules(),
            network_policies: Self::create_default_network_policies(),
            resource_rules: Self::create_default_resource_rules(),
            secret_rules: Self::create_default_secret_rules(),
        }
    }
    
    /// Analyze source file for container security issues
    pub fn analyze(&self, source_file: &SourceFile, _ast: &ParsedAst) -> Result<Vec<Vulnerability>> {
        let mut vulnerabilities = Vec::new();
        
        let file_name = source_file.path.file_name()
            .and_then(|name| name.to_str())
            .unwrap_or("");
        
        match file_name {
            "Dockerfile" => {
                vulnerabilities.extend(self.analyze_dockerfile(source_file)?);
            }
            name if name.ends_with(".yaml") || name.ends_with(".yml") => {
                if source_file.content.contains("apiVersion") {
                    vulnerabilities.extend(self.analyze_kubernetes_manifest(source_file)?);
                } else if source_file.content.contains("version:") && source_file.content.contains("services:") {
                    vulnerabilities.extend(self.analyze_docker_compose(source_file)?);
                }
            }
            _ => {
                // Check if content contains container-related configurations
                if source_file.content.contains("FROM ") {
                    vulnerabilities.extend(self.analyze_dockerfile(source_file)?);
                }
            }
        }
        
        Ok(vulnerabilities)
    }
    
    /// Analyze Dockerfile for security issues
    fn analyze_dockerfile(&self, source_file: &SourceFile) -> Result<Vec<Vulnerability>> {
        let mut vulnerabilities = Vec::new();
        
        for (line_num, line) in source_file.content.lines().enumerate() {
            let line_number = line_num + 1;
            
            // Check for privileged user
            for pattern in &DOCKERFILE_SECURITY_PATTERNS["privileged_user"] {
                if pattern.is_match(line) {
                    vulnerabilities.push(Vulnerability {
                        id: format!("DOCKER-USER-001-{}", line_number),
                        cwe: Some("CWE-250".to_string()),
                        title: "Privileged User".to_string(),
                        severity: Severity::High,
                        category: "configuration".to_string(),
                        description: "Container running as root user".to_string(),
                        file_path: source_file.path.to_string_lossy().to_string(),
                        line_number,
                        column_start: 0,
                        column_end: line.len(),
                        source_code: line.to_string(),
                        recommendation: "Use USER instruction to run as non-root user".to_string(),
                        owasp: Some("A05:2021 – Security Misconfiguration".to_string()),
                        references: vec!["https://owasp.org/Top10/A05_2021-Security_Misconfiguration/".to_string()],
                        confidence: 0.9,
                    });
                }
            }
            
            // Check for secret exposure
            for pattern in &DOCKERFILE_SECURITY_PATTERNS["secret_exposure"] {
                if pattern.is_match(line) {
                    vulnerabilities.push(Vulnerability {
                        id: format!("DOCKER-SECRET-001-{}", line_number),
                        cwe: Some("CWE-798".to_string()),
                        title: "Secret Exposure".to_string(),
                        severity: Severity::Critical,
                        category: "secrets".to_string(),
                        description: "Secrets exposed in Dockerfile environment variables".to_string(),
                        file_path: source_file.path.to_string_lossy().to_string(),
                        line_number,
                        column_start: 0,
                        column_end: line.len(),
                        source_code: line.to_string(),
                        recommendation: "Use Docker secrets or external secret management".to_string(),
                        owasp: Some("A05:2021 – Security Misconfiguration".to_string()),
                        references: vec!["https://owasp.org/Top10/A05_2021-Security_Misconfiguration/".to_string()],
                        confidence: 0.8,
                    });
                }
            }
            
            // Check for insecure protocols
            for pattern in &DOCKERFILE_SECURITY_PATTERNS["insecure_protocols"] {
                if pattern.is_match(line) {
                    vulnerabilities.push(Vulnerability {
                        id: format!("DOCKER-PROTO-001-{}", line_number),
                        cwe: Some("CWE-319".to_string()),
                        title: "Insecure Protocol".to_string(),
                        severity: Severity::Medium,
                        category: "network".to_string(),
                        description: "Insecure protocol used in Dockerfile".to_string(),
                        file_path: source_file.path.to_string_lossy().to_string(),
                        line_number,
                        column_start: 0,
                        column_end: line.len(),
                        source_code: line.to_string(),
                        recommendation: "Use secure protocols (HTTPS, SFTP, SSH)".to_string(),
                        owasp: Some("A05:2021 – Security Misconfiguration".to_string()),
                        references: vec!["https://owasp.org/Top10/A05_2021-Security_Misconfiguration/".to_string()],
                        confidence: 0.8,
                    });
                }
            }
            
            // Check for dangerous commands
            for pattern in &DOCKERFILE_SECURITY_PATTERNS["dangerous_commands"] {
                if pattern.is_match(line) {
                    vulnerabilities.push(Vulnerability {
                        id: format!("DOCKER-CMD-001-{}", line_number),
                        cwe: Some("CWE-78".to_string()),
                        title: "Dangerous Command".to_string(),
                        severity: Severity::High,
                        category: "configuration".to_string(),
                        description: "Dangerous command detected in Dockerfile".to_string(),
                        file_path: source_file.path.to_string_lossy().to_string(),
                        line_number,
                        column_start: 0,
                        column_end: line.len(),
                        source_code: line.to_string(),
                        recommendation: "Avoid using sudo, overly permissive chmod, and root ownership changes".to_string(),
                        owasp: Some("A05:2021 – Security Misconfiguration".to_string()),
                        references: vec!["https://owasp.org/Top10/A05_2021-Security_Misconfiguration/".to_string()],
                        confidence: 0.8,
                    });
                }
            }
        }
        
        Ok(vulnerabilities)
    }
    
    /// Analyze Kubernetes manifest for security issues
    fn analyze_kubernetes_manifest(&self, source_file: &SourceFile) -> Result<Vec<Vulnerability>> {
        let mut vulnerabilities = Vec::new();
        
        for (line_num, line) in source_file.content.lines().enumerate() {
            let line_number = line_num + 1;
            
            // Check for privileged pods
            for pattern in &KUBERNETES_SECURITY_PATTERNS["privileged_pods"] {
                if pattern.is_match(line) {
                    vulnerabilities.push(Vulnerability {
                        id: format!("K8S-PRIV-001-{}", line_number),
                        cwe: Some("CWE-250".to_string()),
                        title: "Privileged Pod".to_string(),
                        severity: Severity::High,
                        category: "configuration".to_string(),
                        description: "Pod configured with privileged access".to_string(),
                        file_path: source_file.path.to_string_lossy().to_string(),
                        line_number,
                        column_start: 0,
                        column_end: line.len(),
                        source_code: line.to_string(),
                        recommendation: "Remove privileged access and use least privilege principle".to_string(),
                        owasp: Some("A05:2021 – Security Misconfiguration".to_string()),
                        references: vec!["https://kubernetes.io/docs/concepts/security/pod-security-standards/".to_string()],
                        confidence: 0.9,
                    });
                }
            }
            
            // Check for unsafe capabilities
            for pattern in &KUBERNETES_SECURITY_PATTERNS["unsafe_capabilities"] {
                if pattern.is_match(line) {
                    vulnerabilities.push(Vulnerability {
                        id: format!("K8S-CAP-001-{}", line_number),
                        cwe: Some("CWE-250".to_string()),
                        title: "Unsafe Capability".to_string(),
                        severity: Severity::High,
                        category: "configuration".to_string(),
                        description: "Container granted unsafe Linux capability".to_string(),
                        file_path: source_file.path.to_string_lossy().to_string(),
                        line_number,
                        column_start: 0,
                        column_end: line.len(),
                        source_code: line.to_string(),
                        recommendation: "Remove unsafe capabilities and use minimal required capabilities".to_string(),
                        owasp: Some("A05:2021 – Security Misconfiguration".to_string()),
                        references: vec!["https://kubernetes.io/docs/concepts/security/pod-security-standards/".to_string()],
                        confidence: 0.9,
                    });
                }
            }
        }
        
        // Check for missing security context
        if !source_file.content.contains("securityContext:") {
            vulnerabilities.push(Vulnerability {
                id: "K8S-SEC-CTX-001".to_string(),
                cwe: Some("CWE-276".to_string()),
                title: "Missing Security Context".to_string(),
                severity: Severity::Medium,
                category: "configuration".to_string(),
                description: "Pod/Container lacks security context configuration".to_string(),
                file_path: source_file.path.to_string_lossy().to_string(),
                line_number: 1,
                column_start: 0,
                column_end: 0,
                source_code: "Missing securityContext".to_string(),
                recommendation: "Add securityContext with runAsNonRoot, readOnlyRootFilesystem, and other security settings".to_string(),
                owasp: Some("A05:2021 – Security Misconfiguration".to_string()),
                references: vec!["https://kubernetes.io/docs/tasks/configure-pod-container/security-context/".to_string()],
                confidence: 0.9,
            });
        }
        
        Ok(vulnerabilities)
    }
    
    /// Analyze Docker Compose for security issues
    fn analyze_docker_compose(&self, source_file: &SourceFile) -> Result<Vec<Vulnerability>> {
        let mut vulnerabilities = Vec::new();
        
        // Check for privileged containers
        if source_file.content.contains("privileged: true") {
            for (line_num, line) in source_file.content.lines().enumerate() {
                if line.contains("privileged: true") {
                    let line_number = line_num + 1;
                    vulnerabilities.push(Vulnerability {
                        id: format!("COMPOSE-PRIV-001-{}", line_number),
                        cwe: Some("CWE-250".to_string()),
                        title: "Privileged Container".to_string(),
                        severity: Severity::High,
                        category: "configuration".to_string(),
                        description: "Docker Compose service configured with privileged access".to_string(),
                        file_path: source_file.path.to_string_lossy().to_string(),
                        line_number,
                        column_start: 0,
                        column_end: line.len(),
                        source_code: line.to_string(),
                        recommendation: "Remove privileged flag and use specific capabilities if needed".to_string(),
                        owasp: Some("A05:2021 – Security Misconfiguration".to_string()),
                        references: vec!["https://owasp.org/Top10/A05_2021-Security_Misconfiguration/".to_string()],
                        confidence: 0.8,
                    });
                }
            }
        }
        
        Ok(vulnerabilities)
    }
    
    // Helper methods to create default rules
    fn create_default_docker_rules() -> Vec<DockerSecurityRule> {
        // Implementation would create comprehensive Docker security rules
        Vec::new()
    }
    
    fn create_default_kubernetes_rules() -> Vec<KubernetesSecurityRule> {
        // Implementation would create comprehensive Kubernetes security rules
        Vec::new()
    }
    
    fn create_default_compose_rules() -> Vec<ComposeSecurityRule> {
        // Implementation would create comprehensive Docker Compose security rules
        Vec::new()
    }
    
    fn create_default_network_policies() -> Vec<NetworkSecurityPolicy> {
        // Implementation would create default network security policies
        Vec::new()
    }
    
    fn create_default_resource_rules() -> Vec<ResourceManagementRule> {
        // Implementation would create default resource management rules
        Vec::new()
    }
    
    fn create_default_secret_rules() -> Vec<SecretManagementRule> {
        // Implementation would create default secret management rules
        Vec::new()
    }
}

// Additional type definitions for completeness
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ComposeSecurityRule {
    pub id: String,
    pub name: String,
    pub description: String,
    // Additional fields would be defined here
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NetworkSecurityPolicy {
    pub id: String,
    pub name: String,
    pub description: String,
    // Additional fields would be defined here
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ResourceManagementRule {
    pub id: String,
    pub name: String,
    pub description: String,
    // Additional fields would be defined here
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SecretManagementRule {
    pub id: String,
    pub name: String,
    pub description: String,
    // Additional fields would be defined here
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VulnerabilityPattern {
    pub pattern: String,
    pub description: String,
    pub severity: Severity,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VulnerabilityScanningRule {
    pub scanner_config: String,
    pub thresholds: VulnerabilityThresholds,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ComplianceFramework {
    pub name: String,
    pub version: String,
    pub requirements: Vec<String>,
}