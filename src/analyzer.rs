use crate::{
    config::Config,
    error::{DevaicError, Result},
    parsers::{ParserFactory, SourceFile},
    rules::{RuleEngine, custom_pattern_rules::CustomPatternRules},
    pattern_loader::PatternLoader,
    cache::get_global_cache,
    optimized_reader::OptimizedFileReader,
    parallel_scanner::{ParallelDirectoryScanner},
    semantic_similarity_engine::{SemanticSimilarityEngine, SimilarityConfig},
    business_logic_analyzer::{BusinessLogicAnalyzer, BusinessLogicConfig},
    progress_reporter::{ProgressReporter, ProgressEvent},
    false_positive_reduction::{FalsePositiveReducer, EnhancedVulnerability},
    impact_assessment::{ImpactAssessmentEngine, AssessedVulnerability},
    Language, Vulnerability,
};
use std::path::Path;
use std::time::{Duration, Instant};
use walkdir::WalkDir;
use tokio::sync::broadcast;

pub struct Analyzer {
    config: Config,
    rule_engine: RuleEngine,
    optimized_reader: OptimizedFileReader,
    parallel_enabled: bool,
    max_depth: usize,
    semantic_engine: Option<SemanticSimilarityEngine>,
    business_logic_analyzer: Option<BusinessLogicAnalyzer>,
    enable_ai_analysis: bool,
    progress_reporter: Option<ProgressReporter>,
    false_positive_reducer: Option<FalsePositiveReducer>,
    impact_assessment_engine: Option<ImpactAssessmentEngine>,
}

impl Analyzer {
    pub fn new(config: Config) -> Result<Self> {
        let rule_engine = RuleEngine::new(&config.rules);
        let optimized_reader = OptimizedFileReader::new(true); // Enable caching
        
        // Initialize AI engines if enabled
        let semantic_engine = if config.enable_ai_analysis.unwrap_or(false) {
            match SemanticSimilarityEngine::new(SimilarityConfig::default()) {
                Ok(engine) => Some(engine),
                Err(_) => None,
            }
        } else {
            None
        };
        
        let business_logic_analyzer = if config.enable_ai_analysis.unwrap_or(false) {
            Some(BusinessLogicAnalyzer::new(BusinessLogicConfig::default()))
        } else {
            None
        };
        
        let enable_ai_analysis = config.enable_ai_analysis.unwrap_or(false);
        
        // Initialize false positive reducer if AI analysis is enabled
        let false_positive_reducer = if enable_ai_analysis {
            Some(FalsePositiveReducer::new())
        } else {
            None
        };
        
        // Initialize impact assessment engine if AI analysis is enabled
        let impact_assessment_engine = if enable_ai_analysis {
            match ImpactAssessmentEngine::new() {
                Ok(engine) => Some(engine),
                Err(_) => None,
            }
        } else {
            None
        };
        
        Ok(Self {
            config,
            rule_engine,
            optimized_reader,
            parallel_enabled: true,
            max_depth: 100,
            semantic_engine,
            business_logic_analyzer,
            enable_ai_analysis,
            progress_reporter: None,
            false_positive_reducer,
            impact_assessment_engine,
        })
    }

    pub fn new_with_custom_patterns(config: Config, pattern_loader: PatternLoader) -> Self {
        let mut rule_engine = RuleEngine::new(&config.rules);
        let custom_rules = CustomPatternRules::new(pattern_loader);
        rule_engine.set_custom_pattern_rules(custom_rules);
        
        let optimized_reader = OptimizedFileReader::new(true); // Enable caching
        
        // Initialize AI engines if enabled
        let semantic_engine = if config.enable_ai_analysis.unwrap_or(false) {
            match SemanticSimilarityEngine::new(SimilarityConfig::default()) {
                Ok(engine) => Some(engine),
                Err(_) => None,
            }
        } else {
            None
        };
        
        let business_logic_analyzer = if config.enable_ai_analysis.unwrap_or(false) {
            Some(BusinessLogicAnalyzer::new(BusinessLogicConfig::default()))
        } else {
            None
        };
        
        let enable_ai_analysis = config.enable_ai_analysis.unwrap_or(false);
        
        // Initialize false positive reducer if AI analysis is enabled
        let false_positive_reducer = if enable_ai_analysis {
            Some(FalsePositiveReducer::new())
        } else {
            None
        };
        
        // Initialize impact assessment engine if AI analysis is enabled
        let impact_assessment_engine = if enable_ai_analysis {
            match ImpactAssessmentEngine::new() {
                Ok(engine) => Some(engine),
                Err(_) => None,
            }
        } else {
            None
        };
        
        Self {
            config,
            rule_engine,
            optimized_reader,
            parallel_enabled: true,
            max_depth: 100,
            semantic_engine,
            business_logic_analyzer,
            enable_ai_analysis,
            progress_reporter: None,
            false_positive_reducer,
            impact_assessment_engine,
        }
    }

    /// Enable or disable parallel processing
    pub fn set_parallel_enabled(&mut self, enabled: bool) {
        self.parallel_enabled = enabled;
    }

    /// Set maximum recursion depth for directory scanning
    pub fn set_max_depth(&mut self, max_depth: usize) {
        self.max_depth = max_depth;
    }

    /// Get cache statistics
    pub fn get_cache_stats(&self) -> crate::cache::CacheStats {
        get_global_cache().get_stats()
    }

    /// Clear all caches
    pub fn clear_caches(&self) {
        get_global_cache().clear_all();
    }

    /// Enable real-time progress reporting
    pub fn enable_progress_reporting(&mut self, show_progress_bar: bool, show_detailed_stats: bool, verbose_mode: bool) {
        self.progress_reporter = Some(ProgressReporter::new(show_progress_bar, show_detailed_stats, verbose_mode));
    }

    /// Get progress event receiver
    pub fn get_progress_receiver(&self) -> Option<broadcast::Receiver<ProgressEvent>> {
        self.progress_reporter.as_ref().map(|p| p.subscribe())
    }

    /// Enable intelligent false positive reduction
    pub fn enable_false_positive_reduction(&mut self) {
        if self.false_positive_reducer.is_none() {
            self.false_positive_reducer = Some(FalsePositiveReducer::new());
        }
    }

    /// Analyze directory with enhanced vulnerability processing
    pub async fn analyze_directory_enhanced(&self, path: &Path) -> Result<Vec<EnhancedVulnerability>> {
        // Get regular vulnerabilities
        let vulnerabilities = self.analyze_directory(path).await?;
        
        // Apply false positive reduction if enabled
        if let Some(ref reducer) = self.false_positive_reducer {
            Ok(reducer.process_vulnerabilities(vulnerabilities))
        } else {
            // Convert to enhanced vulnerabilities without ML processing
            Ok(vulnerabilities.into_iter().map(|vuln| EnhancedVulnerability {
                vulnerability: vuln,
                false_positive_probability: 0.3, // Default assumption
                confidence_score: 0.7,
                contributing_factors: Vec::new(),
                similar_patterns: Vec::new(),
                user_recommendations: Vec::new(),
                suggested_actions: Vec::new(),
            }).collect())
        }
    }

    /// Record user feedback for continuous learning
    pub fn record_vulnerability_feedback(&self, feedback: crate::false_positive_reduction::VulnerabilityFeedback) -> Result<()> {
        if let Some(ref reducer) = self.false_positive_reducer {
            reducer.record_feedback(feedback)
                .map_err(|e| DevaicError::Analysis(format!("Failed to record feedback: {}", e)))?;
        }
        Ok(())
    }

    /// Get false positive reduction analytics
    pub fn get_false_positive_analytics(&self) -> Option<crate::false_positive_reduction::FPReductionAnalytics> {
        self.false_positive_reducer.as_ref().map(|reducer| reducer.get_analytics())
    }

    /// Analyze directory with comprehensive impact assessment
    pub async fn analyze_directory_with_impact_assessment(&self, path: &Path) -> Result<Vec<AssessedVulnerability>> {
        // First get enhanced vulnerabilities
        let enhanced_vulns = self.analyze_directory_enhanced(path).await?;
        
        // Apply impact assessment if enabled
        if let Some(ref impact_engine) = self.impact_assessment_engine {
            impact_engine.assess_vulnerabilities_batch(&enhanced_vulns)
                .map_err(|e| DevaicError::Analysis(format!("Impact assessment failed: {}", e)))
        } else {
            // Convert to assessed vulnerabilities without impact assessment
            let assessed_vulns: Result<Vec<AssessedVulnerability>> = enhanced_vulns.into_iter().map(|enhanced_vuln| {
                // Create a minimal assessed vulnerability without full impact analysis
                self.create_minimal_assessed_vulnerability(enhanced_vuln)
            }).collect();
            assessed_vulns
        }
    }

    /// Assess impact for a single enhanced vulnerability
    pub fn assess_vulnerability_impact(&self, enhanced_vuln: &EnhancedVulnerability) -> Result<AssessedVulnerability> {
        if let Some(ref impact_engine) = self.impact_assessment_engine {
            impact_engine.assess_vulnerability_impact(enhanced_vuln)
        } else {
            self.create_minimal_assessed_vulnerability(enhanced_vuln.clone())
        }
    }

    /// Enable impact assessment functionality
    pub fn enable_impact_assessment(&mut self) -> Result<()> {
        if self.impact_assessment_engine.is_none() {
            self.impact_assessment_engine = Some(ImpactAssessmentEngine::new()?);
        }
        Ok(())
    }

    /// Get impact assessment analytics
    pub fn get_impact_assessment_analytics(&self) -> Option<crate::impact_assessment::AssessmentAnalytics> {
        self.impact_assessment_engine.as_ref().and_then(|engine| {
            engine.get_assessment_analytics().ok()
        })
    }

    /// Create minimal assessed vulnerability without full impact analysis
    fn create_minimal_assessed_vulnerability(&self, enhanced_vuln: EnhancedVulnerability) -> Result<AssessedVulnerability> {
        use crate::impact_assessment::*;
        use std::time::SystemTime;
        
        // Create basic CVSS assessment
        let cvss_assessment = CvssAssessment {
            version: CvssVersion::V3_1,
            base_metrics: CvssBaseMetrics {
                attack_vector: AttackVector::Network,
                attack_complexity: AttackComplexity::Low,
                privileges_required: PrivilegesRequired::None,
                user_interaction: UserInteraction::None,
                scope: Scope::Unchanged,
                confidentiality_impact: Impact::High,
                integrity_impact: Impact::High,
                availability_impact: Impact::High,
            },
            temporal_metrics: CvssTemporalMetrics {
                exploit_code_maturity: ExploitCodeMaturity::ProofOfConcept,
                remediation_level: RemediationLevel::OfficialFix,
                report_confidence: ReportConfidence::Confirmed,
            },
            environmental_metrics: CvssEnvironmentalMetrics {
                confidentiality_requirement: SecurityRequirement::High,
                integrity_requirement: SecurityRequirement::High,
                availability_requirement: SecurityRequirement::High,
                modified_attack_vector: None,
                modified_attack_complexity: None,
                modified_privileges_required: None,
                modified_user_interaction: None,
                modified_scope: None,
                modified_confidentiality_impact: None,
                modified_integrity_impact: None,
                modified_availability_impact: None,
            },
            scores: CvssScores {
                base_score: match enhanced_vuln.vulnerability.severity {
                    crate::Severity::Critical => 9.5,
                    crate::Severity::High => 8.0,
                    crate::Severity::Medium => 6.0,
                    crate::Severity::Low => 3.0,
                    crate::Severity::Info => 1.0,
                },
                temporal_score: 0.0,
                environmental_score: 0.0,
                overall_score: match enhanced_vuln.vulnerability.severity {
                    crate::Severity::Critical => 9.5,
                    crate::Severity::High => 8.0,
                    crate::Severity::Medium => 6.0,
                    crate::Severity::Low => 3.0,
                    crate::Severity::Info => 1.0,
                },
                severity_rating: match enhanced_vuln.vulnerability.severity {
                    crate::Severity::Critical => CvssSeverityRating::Critical,
                    crate::Severity::High => CvssSeverityRating::High,
                    crate::Severity::Medium => CvssSeverityRating::Medium,
                    crate::Severity::Low => CvssSeverityRating::Low,
                    crate::Severity::Info => CvssSeverityRating::None,
                },
            },
            contextual_adjustments: vec![],
            confidence_metrics: ConfidenceMetrics {
                base_confidence: enhanced_vuln.confidence_score,
                temporal_confidence: 0.7,
                environmental_confidence: 0.5,
                overall_confidence: enhanced_vuln.confidence_score * 0.8,
                uncertainty_factors: vec!["Limited context analysis".to_string()],
            },
        };

        // Create basic risk assessment
        let risk_classification = match enhanced_vuln.vulnerability.severity {
            crate::Severity::Critical => RiskClassification::Critical,
            crate::Severity::High => RiskClassification::High,
            crate::Severity::Medium => RiskClassification::Moderate,
            crate::Severity::Low => RiskClassification::Low,
            crate::Severity::Info => RiskClassification::Negligible,
        };

        let risk_assessment = OverallRiskAssessment {
            composite_risk_score: cvss_assessment.scores.overall_score,
            risk_classification: risk_classification.clone(),
            risk_factors: RiskFactorsBreakdown {
                technical_factors: 0.7,
                business_factors: 0.5,
                environmental_factors: 0.5,
                threat_factors: 0.6,
                control_factors: 0.5,
            },
            uncertainty_analysis: UncertaintyAnalysis {
                confidence_interval: (0.3, 0.9),
                uncertainty_sources: vec!["Simplified assessment".to_string()],
                sensitivity_analysis: vec![],
            },
            risk_trend: RiskTrendPrediction {
                trend_direction: TrendDirection::Stable,
                trend_magnitude: 0.0,
                prediction_confidence: 0.5,
                time_horizon: std::time::Duration::from_secs(30 * 24 * 3600),
            },
            critical_paths: vec![],
        };

        // Create basic remediation guidance
        let remediation_priority = match risk_classification {
            RiskClassification::Critical | RiskClassification::Catastrophic => RemediationPriority::Critical,
            RiskClassification::High | RiskClassification::Severe => RemediationPriority::High,
            RiskClassification::Moderate => RemediationPriority::Medium,
            RiskClassification::Low => RemediationPriority::Low,
            RiskClassification::Negligible => RemediationPriority::Planning,
        };

        let remediation_guidance = RemediationGuidance {
            priority_level: remediation_priority,
            recommended_timeline: RemediationTimeline {
                emergency_patch: None,
                temporary_mitigation: None,
                full_remediation: std::time::Duration::from_secs(30 * 24 * 3600),
                testing_period: std::time::Duration::from_secs(3 * 24 * 3600),
                deployment_window: None,
            },
            remediation_strategies: vec![],
            resource_requirements: ResourceRequirements {
                personnel_hours: 16.0,
                skill_requirements: vec!["Security Engineering".to_string()],
                technology_requirements: vec!["Patch Management".to_string()],
                budget_estimate: 5000.0,
            },
            risk_reduction_potential: RiskReductionPotential {
                risk_reduction_percentage: 80.0,
                residual_risk_level: 2.0,
                effectiveness_confidence: 0.7,
            },
            interim_mitigations: vec![],
        };

        Ok(AssessedVulnerability {
            enhanced_vulnerability: enhanced_vuln,
            cvss_assessment,
            business_impact: BusinessImpactAnalysis::default(),
            environmental_impact: EnvironmentalImpact {
                environment_type: EnvironmentType::Production,
                network_exposure: NetworkExposureAnalysis {
                    internet_facing: false,
                    network_segmentation: NetworkSegmentationLevel::Basic,
                    firewall_protection: FirewallProtectionLevel::Basic,
                    access_controls: AccessControlLevel::Basic,
                },
                data_sensitivity: DataSensitivityAssessment {
                    contains_pii: false,
                    contains_financial_data: false,
                    contains_health_data: false,
                    contains_trade_secrets: false,
                    data_sensitivity_score: 5.0,
                },
                system_criticality: SystemCriticalityAssessment {
                    business_criticality: 5.0,
                    technical_criticality: 5.0,
                    dependency_criticality: 5.0,
                    overall_criticality: 5.0,
                },
                security_controls: SecurityControlsAssessment {
                    preventive_controls: 5.0,
                    detective_controls: 5.0,
                    corrective_controls: 5.0,
                    overall_control_effectiveness: 5.0,
                },
                detection_capabilities: DetectionCapabilitiesAssessment {
                    monitoring_coverage: 5.0,
                    alerting_effectiveness: 5.0,
                    incident_response_readiness: 5.0,
                    forensic_capabilities: 5.0,
                },
            },
            exploitability: ExploitabilityAssessment {
                exploit_availability: ExploitAvailability {
                    public_exploits_available: false,
                    exploit_maturity: ExploitMaturityLevel::ProofOfConcept,
                    exploit_reliability: 0.5,
                    weaponization_difficulty: 0.7,
                },
                attack_complexity_analysis: AttackComplexityAnalysis {
                    technical_complexity: 0.5,
                    resource_requirements: 0.5,
                    skill_requirements: 0.5,
                    time_requirements: std::time::Duration::from_secs(8 * 3600),
                },
                attacker_requirements: AttackerRequirements {
                    required_skills: vec!["Basic security knowledge".to_string()],
                    required_resources: vec!["Standard tools".to_string()],
                    required_access: vec!["Network access".to_string()],
                    overall_difficulty: 0.5,
                },
                attack_vectors: vec![],
                weaponization_potential: WeaponizationPotential {
                    automation_potential: 0.5,
                    scalability: 0.5,
                    persistence_capability: 0.5,
                    evasion_capability: 0.5,
                },
                exploit_reliability: ExploitReliability {
                    success_rate: 0.5,
                    consistency: 0.5,
                    environmental_dependency: 0.5,
                },
                time_to_exploit: TimeToExploit {
                    minimum_time: std::time::Duration::from_secs(1 * 3600),
                    average_time: std::time::Duration::from_secs(8 * 3600),
                    maximum_time: std::time::Duration::from_secs(24 * 3600),
                    time_variance: std::time::Duration::from_secs(4 * 3600),
                },
            },
            compliance_impact: ComplianceImpactAnalysis::default(),
            risk_correlations: vec![],
            risk_assessment,
            remediation_guidance,
            assessment_metadata: AssessmentMetadata {
                assessed_at: SystemTime::now(),
                engine_version: "DeVAIC-minimal".to_string(),
                data_sources: vec!["Basic Assessment".to_string()],
                overall_confidence: 0.6,
                reviewer: None,
                last_updated: SystemTime::now(),
            },
        })
    }

    pub async fn analyze_directory(&self, path: &Path) -> Result<Vec<Vulnerability>> {
        // Count total files for progress reporting
        let total_files = if self.progress_reporter.is_some() {
            self.count_files_in_directory(path)
        } else {
            0
        };

        // Start progress reporting if enabled
        if let Some(ref reporter) = self.progress_reporter {
            let total_rules = self.rule_engine.get_rule_count();
            reporter.start_analysis(total_files, total_rules);
        }
        if self.parallel_enabled {
            // Use parallel scanner for better performance
            let scanner = ParallelDirectoryScanner::new(
                self.config.clone(),
                None, // Use default thread count
                true, // Enable caching
                Some(self.max_depth), // Use configured max depth
                Some(true), // Use fast walker
            );
            
            match scanner.scan_directory(path) {
                Ok(results) => {
                    log::info!("Parallel scan completed: {} files, {} vulnerabilities, {}ms", 
                              results.files_scanned, results.vulnerabilities.len(), results.scan_time_ms);
                    
                    // Complete progress reporting
                    if let Some(ref reporter) = self.progress_reporter {
                        reporter.complete_analysis(results.vulnerabilities.len());
                    }
                    
                    Ok(results.vulnerabilities)
                }
                Err(e) => {
                    log::warn!("Parallel scan failed, falling back to sequential: {}", e);
                    self.analyze_directory_sequential(path).await
                }
            }
        } else {
            self.analyze_directory_sequential(path).await
        }
    }

    /// Sequential directory analysis (fallback)
    async fn analyze_directory_sequential(&self, path: &Path) -> Result<Vec<Vulnerability>> {
        // Use smart file filter for better performance
        let mut vulnerabilities = Vec::new();
        let mut file_index = 0;
        
        for entry in WalkDir::new(path)
            .follow_links(self.config.analysis.follow_symlinks)
            .into_iter()
            .filter_map(|e| e.ok())
        {
            if entry.file_type().is_file() {
                let file_path = entry.path();
                
                // Report file start
                if let Some(ref reporter) = self.progress_reporter {
                    let file_size = entry.metadata().map(|m| m.len()).unwrap_or(0);
                    reporter.file_started(file_path.display().to_string(), file_size, file_index);
                }
                
                let file_start_time = Instant::now();
                log::debug!("Analyzing file: {}", file_path.display());
                
                match self.analyze_file(file_path).await {
                    Ok(mut file_vulns) => {
                        let vuln_count = file_vulns.len();
                        
                        // Report each vulnerability as it's found
                        if let Some(ref reporter) = self.progress_reporter {
                            for vuln in &file_vulns {
                                reporter.vulnerability_found(vuln.clone(), file_path.display().to_string(), Duration::from_millis(1));
                            }
                        }
                        
                        vulnerabilities.append(&mut file_vulns);
                        
                        // Report file completion
                        if let Some(ref reporter) = self.progress_reporter {
                            let processing_time = file_start_time.elapsed();
                            reporter.file_completed(file_path.display().to_string(), vuln_count, processing_time, file_index);
                        }
                    },
                    Err(e) => {
                        log::debug!("Skipped file {}: {}", file_path.display(), e);
                        
                        // Report file completion with 0 vulnerabilities
                        if let Some(ref reporter) = self.progress_reporter {
                            let processing_time = file_start_time.elapsed();
                            reporter.file_completed(file_path.display().to_string(), 0, processing_time, file_index);
                        }
                    }
                }
                
                file_index += 1;
            }
        }

        // Complete progress reporting
        if let Some(ref reporter) = self.progress_reporter {
            reporter.complete_analysis(vulnerabilities.len());
        }

        Ok(vulnerabilities)
    }

    pub async fn analyze_file(&self, path: &Path) -> Result<Vec<Vulnerability>> {
        let extension = match path.extension().and_then(|ext| ext.to_str()) {
            Some(ext) => ext,
            None => {
                // Skip files without extensions
                return Ok(Vec::new());
            }
        };

        // Get language with caching
        let language = {
            let cache = get_global_cache();
            if let Some(cached_lang) = cache.get_language_for_extension(extension) {
                match cached_lang {
                    Some(lang) => lang,
                    None => {
                        log::debug!("Unsupported language extension: {} for file: {}", extension, path.display());
                        return Ok(Vec::new());
                    }
                }
            } else {
                let lang = Language::from_extension(extension);
                cache.cache_language_for_extension(extension.to_string(), lang);
                match lang {
                    Some(lang) => lang,
                    None => {
                        log::debug!("Unsupported language extension: {} for file: {}", extension, path.display());
                        return Ok(Vec::new());
                    }
                }
            }
        };

        // Use optimized reader for better performance
        let content = self.optimized_reader.read_file(path)
            .map_err(|e| DevaicError::Analysis(format!("Failed to read file {}: {}", path.display(), e)))?;

        // Check if content has changed using cache
        let cache = get_global_cache();
        if !cache.has_content_changed(path, &content) {
            // Content hasn't changed, could return cached analysis results
            // For now, we'll continue with analysis
            log::debug!("File content unchanged: {}", path.display());
        }

        let source_file = SourceFile::new(path.to_path_buf(), content, language);
        let mut parser = ParserFactory::create_parser(&source_file.language)?;
        let ast = parser.parse(&source_file)?;

        let mut vulnerabilities = self.rule_engine.analyze(&source_file, &ast)?;
        
        // Perform AI-enhanced analysis if enabled
        if self.enable_ai_analysis {
            let ai_vulnerabilities = self.perform_ai_analysis(&source_file).await?;
            vulnerabilities.extend(ai_vulnerabilities);
        }
        
        // Report vulnerabilities in real-time for single file analysis
        if let Some(ref reporter) = self.progress_reporter {
            for vuln in &vulnerabilities {
                reporter.vulnerability_found(vuln.clone(), path.display().to_string(), Duration::from_millis(1));
            }
        }
        
        Ok(vulnerabilities)
    }

    /// Perform AI-enhanced analysis using semantic similarity and business logic detection
    async fn perform_ai_analysis(&self, source_file: &SourceFile) -> Result<Vec<Vulnerability>> {
        let mut ai_vulnerabilities = Vec::new();
        
        // Semantic Similarity Analysis
        if let Some(ref semantic_engine) = self.semantic_engine {
            match semantic_engine.find_similar_vulnerabilities(&source_file.content, &source_file.language.to_string()).await {
                Ok(similarity_result) => {
                    for similarity_match in similarity_result {
                        // Convert similarity match to vulnerability
                        let vulnerability = Vulnerability {
                            id: format!("AI-SIM-{}", uuid::Uuid::new_v4()),
                            title: format!("Semantic Similarity: {}", similarity_match.pattern_info.title),
                            description: format!("Similar pattern detected: {}", similarity_match.pattern_info.title),
                            severity: match similarity_match.similarity_score {
                                s if s >= 0.9 => crate::Severity::Critical,
                                s if s >= 0.7 => crate::Severity::High,
                                s if s >= 0.5 => crate::Severity::Medium,
                                s if s >= 0.3 => crate::Severity::Low,
                                _ => crate::Severity::Info,
                            },
                            category: "ai_semantic_similarity".to_string(),
                            cwe: None,
                            owasp: None,
                            file_path: source_file.path.display().to_string(),
                            line_number: similarity_match.pattern_info.location.line_start,
                            column_start: similarity_match.pattern_info.location.column_start,
                            column_end: similarity_match.pattern_info.location.column_end,
                            source_code: similarity_match.pattern_info.code_snippet.clone(),
                            recommendation: format!("Similar to known vulnerability pattern: {}. Similarity score: {:.3}. {}", 
                                similarity_match.pattern_info.title, 
                                similarity_match.similarity_score,
                                similarity_match.recommendations.join("; ")),
                            references: vec![],
                            confidence: similarity_match.detection_confidence as f64,
                        };
                        ai_vulnerabilities.push(vulnerability);
                    }
                }
                Err(e) => {
                    log::warn!("Semantic similarity analysis failed: {}", e);
                }
            }
        }
        
        // Business Logic Analysis
        if let Some(ref business_analyzer) = self.business_logic_analyzer {
            match business_analyzer.analyze_business_logic(&source_file.content, source_file.language.clone()).await {
                Ok(business_result) => {
                    for business_vuln in business_result.vulnerabilities {
                        // Convert business logic vulnerability to standard vulnerability
                        let vulnerability = Vulnerability {
                            id: business_vuln.vulnerability_info.id,
                            title: business_vuln.vulnerability_info.title,
                            description: business_vuln.vulnerability_info.description,
                            severity: business_vuln.vulnerability_info.severity,
                            category: "ai_business_logic".to_string(),
                            cwe: business_vuln.vulnerability_info.cwe,
                            owasp: business_vuln.vulnerability_info.owasp,
                            file_path: source_file.path.display().to_string(),
                            line_number: business_vuln.vulnerability_info.line_number,
                            column_start: business_vuln.vulnerability_info.column_start,
                            column_end: business_vuln.vulnerability_info.column_end,
                            source_code: business_vuln.vulnerability_info.source_code,
                            recommendation: format!("{} | Business Risk Score: {} | Impact: {:?}", 
                                business_vuln.vulnerability_info.recommendation,
                                business_vuln.business_risk.risk_score,
                                business_vuln.workflow_impact.impact_level
                            ),
                            references: business_vuln.vulnerability_info.references,
                            confidence: business_vuln.vulnerability_info.confidence,
                        };
                        ai_vulnerabilities.push(vulnerability);
                    }
                }
                Err(e) => {
                    log::warn!("Business logic analysis failed: {}", e);
                }
            }
        }
        
        Ok(ai_vulnerabilities)
    }

    /// Enable AI-enhanced analysis
    pub fn enable_ai_analysis(&mut self) {
        self.enable_ai_analysis = true;
        
        if self.semantic_engine.is_none() {
            self.semantic_engine = match SemanticSimilarityEngine::new(SimilarityConfig::default()) {
                Ok(engine) => Some(engine),
                Err(_) => None,
            };
        }
        
        if self.business_logic_analyzer.is_none() {
            self.business_logic_analyzer = Some(BusinessLogicAnalyzer::new(BusinessLogicConfig::default()));
        }
    }

    /// Disable AI-enhanced analysis
    pub fn disable_ai_analysis(&mut self) {
        self.enable_ai_analysis = false;
    }

    /// Get semantic similarity engine
    pub fn get_semantic_engine(&self) -> Option<&SemanticSimilarityEngine> {
        self.semantic_engine.as_ref()
    }

    /// Get business logic analyzer
    pub fn get_business_logic_analyzer(&self) -> Option<&BusinessLogicAnalyzer> {
        self.business_logic_analyzer.as_ref()
    }

    /// Count files in directory for progress tracking
    fn count_files_in_directory(&self, path: &Path) -> usize {
        WalkDir::new(path)
            .follow_links(self.config.analysis.follow_symlinks)
            .into_iter()
            .filter_map(|e| e.ok())
            .filter(|e| e.file_type().is_file())
            .count()
    }

}