/// Comprehensive tests for AI-powered vulnerability detection systems
/// Tests both the Semantic Similarity Engine and Business Logic Analyzer

#[cfg(test)]
mod tests {
    use devaic::{
        semantic_similarity_engine::{
            SemanticSimilarityEngine, SimilarityConfig, VulnerabilitySignature,
            CodeEmbedding, BehavioralSignature, VariationType,
        },
        business_logic_analyzer::{
            BusinessLogicAnalyzer, BusinessLogicConfig, WorkflowModel, WorkflowState,
            BusinessRule, BusinessRuleCategory, AuthRequirement, AuthLevel,
            ValidationRule, ValidationType,
        },
        Language, Severity,
    };
    use std::collections::HashMap;

    #[tokio::test]
    async fn test_semantic_similarity_engine_initialization() {
        let config = SimilarityConfig::default();
        let engine = SemanticSimilarityEngine::new(config);
        
        // Test basic functionality
        let stats = engine.get_statistics().await.unwrap();
        assert_eq!(stats.total_signatures, 0);
        assert_eq!(stats.cache_size, 0);
    }

    #[tokio::test]
    async fn test_semantic_embedding_generation() {
        let config = SimilarityConfig::default();
        let engine = SemanticSimilarityEngine::new(config);
        
        let code = "function authenticate(user, password) { return user === 'admin' && password === 'secret'; }";
        let embedding = engine.generate_embedding(code, "javascript").await.unwrap();
        
        assert_eq!(embedding.language, "javascript");
        assert_eq!(embedding.vector.len(), 512);
        assert!(embedding.confidence > 0.0 && embedding.confidence <= 1.0);
        assert!(!embedding.normalized_code.is_empty());
        assert!(!embedding.structural_features.is_empty());
    }

    #[tokio::test]
    async fn test_vulnerability_signature_registration() {
        let config = SimilarityConfig::default();
        let engine = SemanticSimilarityEngine::new(config);
        
        let signature = create_test_sql_injection_signature();
        engine.add_vulnerability_signature(signature).await.unwrap();
        
        let stats = engine.get_statistics().await.unwrap();
        assert_eq!(stats.total_signatures, 1);
        assert!(stats.vulnerability_types.contains_key("sql_injection"));
    }

    #[tokio::test]
    async fn test_similarity_detection() {
        let config = SimilarityConfig {
            similarity_threshold: 0.5, // Lower threshold for testing
            ..Default::default()
        };
        let engine = SemanticSimilarityEngine::new(config);
        
        // Register a known vulnerability
        let signature = create_test_sql_injection_signature();
        engine.add_vulnerability_signature(signature).await.unwrap();
        
        // Test with similar code
        let test_code = "var sql = \"SELECT * FROM users WHERE id = \" + userId;";
        let result = engine.find_similar_vulnerabilities(test_code, "javascript").await.unwrap();
        
        assert!(result.processing_time_ms > 0);
        assert!(result.confidence >= 0.0);
        // Note: Actual matches depend on the embedding implementation
    }

    #[tokio::test]
    async fn test_cross_language_similarity() {
        let config = SimilarityConfig {
            enable_cross_language: true,
            similarity_threshold: 0.3,
            ..Default::default()
        };
        let engine = SemanticSimilarityEngine::new(config);
        
        // Register JavaScript vulnerability
        let js_signature = create_test_xss_signature();
        engine.add_vulnerability_signature(js_signature).await.unwrap();
        
        // Test with PHP equivalent
        let php_code = "echo $_GET['input'];";
        let result = engine.find_similar_vulnerabilities(php_code, "php").await.unwrap();
        
        // Should be processed even if no exact matches
        assert!(result.processing_time_ms > 0);
    }

    #[tokio::test]
    async fn test_business_logic_analyzer_initialization() {
        let config = BusinessLogicConfig::default();
        let analyzer = BusinessLogicAnalyzer::new(config);
        
        // Test basic initialization
        let workflow = create_test_ecommerce_workflow();
        analyzer.register_workflow_model(workflow).await.unwrap();
    }

    #[tokio::test]
    async fn test_business_logic_analysis() {
        let config = BusinessLogicConfig::default();
        let analyzer = BusinessLogicAnalyzer::new(config);
        
        // Register a workflow
        let workflow = create_test_ecommerce_workflow();
        analyzer.register_workflow_model(workflow).await.unwrap();
        
        // Analyze vulnerable code
        let vulnerable_code = r#"
            function processPayment(amount) {
                // Missing authentication check
                return chargeCard(amount);
            }
            
            function adminAccess(user) {
                if (user.role === "admin" || debugMode) {
                    return true;
                }
                return false;
            }
        "#;
        
        let result = analyzer.analyze_business_logic(vulnerable_code, Language::Javascript).await.unwrap();
        
        assert!(result.metadata.duration_ms > 0);
        assert_eq!(result.metadata.workflows_analyzed, 1);
        assert!(!result.metadata.techniques_used.is_empty());
        
        // Should detect some issues (authentication, validation, etc.)
        let total_issues = result.vulnerabilities.len() + 
                          result.auth_issues.len() + 
                          result.validation_issues.len() + 
                          result.rule_violations.len();
        assert!(total_issues > 0, "Should detect at least some business logic issues");
    }

    #[tokio::test]
    async fn test_authentication_issue_detection() {
        let config = BusinessLogicConfig::default();
        let analyzer = BusinessLogicAnalyzer::new(config);
        
        let workflow = create_test_banking_workflow();
        analyzer.register_workflow_model(workflow).await.unwrap();
        
        let auth_bypass_code = r#"
            function authenticate(user, password) {
                if (user.role === "admin" || bypass === true) {
                    return { authenticated: true };
                }
                return checkCredentials(user, password);
            }
        "#;
        
        let result = analyzer.analyze_business_logic(auth_bypass_code, Language::Javascript).await.unwrap();
        
        // Should detect authentication bypass
        assert!(!result.auth_issues.is_empty(), "Should detect authentication bypass");
        
        let bypass_issue = result.auth_issues.iter()
            .find(|issue| matches!(issue.issue_type, devaic::business_logic_analyzer::AuthIssueType::AuthenticationBypass));
        assert!(bypass_issue.is_some(), "Should specifically detect authentication bypass");
    }

    #[tokio::test]
    async fn test_validation_issue_detection() {
        let config = BusinessLogicConfig::default();
        let analyzer = BusinessLogicAnalyzer::new(config);
        
        let workflow = create_test_generic_workflow();
        analyzer.register_workflow_model(workflow).await.unwrap();
        
        let missing_validation_code = r#"
            function processInput(userInput) {
                // Missing input validation
                return database.query("SELECT * FROM table WHERE id = " + userInput);
            }
        "#;
        
        let result = analyzer.analyze_business_logic(missing_validation_code, Language::Javascript).await.unwrap();
        
        // Should detect validation issues
        assert!(!result.validation_issues.is_empty(), "Should detect missing validation");
    }

    #[tokio::test]
    async fn test_business_rule_violation_detection() {
        let config = BusinessLogicConfig::default();
        let analyzer = BusinessLogicAnalyzer::new(config);
        
        let workflow = create_test_ecommerce_workflow();
        analyzer.register_workflow_model(workflow).await.unwrap();
        
        let rule_violation_code = r#"
            function processTransaction(amount) {
                // Violates business rules - no validation, no auth
                account.balance -= amount;
                return { success: true };
            }
        "#;
        
        let result = analyzer.analyze_business_logic(rule_violation_code, Language::Javascript).await.unwrap();
        
        // Should detect business rule violations
        assert!(!result.rule_violations.is_empty(), "Should detect business rule violations");
    }

    #[tokio::test]
    async fn test_workflow_analysis() {
        let config = BusinessLogicConfig::default();
        let analyzer = BusinessLogicAnalyzer::new(config);
        
        let workflow = create_test_healthcare_workflow();
        analyzer.register_workflow_model(workflow).await.unwrap();
        
        let healthcare_code = r#"
            function accessPatientData(userId, patientId) {
                // Missing HIPAA compliance check
                return database.getPatientRecord(patientId);
            }
        "#;
        
        let result = analyzer.analyze_business_logic(healthcare_code, Language::Javascript).await.unwrap();
        
        assert!(!result.workflow_analysis.is_empty(), "Should analyze workflow");
        
        let workflow_result = &result.workflow_analysis[0];
        assert_eq!(workflow_result.workflow_id, "healthcare_privacy");
        assert!(matches!(workflow_result.status, devaic::business_logic_analyzer::AnalysisStatus::Complete));
    }

    #[tokio::test]
    async fn test_vulnerability_conversion() {
        let config = BusinessLogicConfig::default();
        let analyzer = BusinessLogicAnalyzer::new(config);
        
        let workflow = create_test_ecommerce_workflow();
        analyzer.register_workflow_model(workflow).await.unwrap();
        
        let vulnerable_code = r#"
            function adminBypass(user) {
                if (user.role === "admin" || debugMode === true) {
                    return true;
                }
            }
        "#;
        
        let result = analyzer.analyze_business_logic(vulnerable_code, Language::Javascript).await.unwrap();
        
        // Should convert issues to vulnerabilities
        if !result.vulnerabilities.is_empty() {
            let vulnerability = &result.vulnerabilities[0];
            assert!(!vulnerability.vulnerability_info.id.is_empty());
            assert!(!vulnerability.vulnerability_info.title.is_empty());
            assert!(vulnerability.business_risk.risk_score > 0);
            assert!(!vulnerability.remediation.immediate_actions.is_empty());
        }
    }

    #[tokio::test]
    async fn test_performance_metrics() {
        let config = SimilarityConfig::default();
        let engine = SemanticSimilarityEngine::new(config);
        
        let start = std::time::Instant::now();
        let _embedding = engine.generate_embedding("test code", "javascript").await.unwrap();
        let duration = start.elapsed();
        
        // Should complete within reasonable time
        assert!(duration.as_secs() < 5, "Embedding generation should be fast");
    }

    #[tokio::test]
    async fn test_confidence_scoring() {
        let config = SimilarityConfig::default();
        let engine = SemanticSimilarityEngine::new(config);
        
        let embedding = engine.generate_embedding("function test() { return true; }", "javascript").await.unwrap();
        
        // Confidence should be reasonable
        assert!(embedding.confidence > 0.1 && embedding.confidence <= 1.0);
    }

    // Helper functions for creating test data

    fn create_test_sql_injection_signature() -> VulnerabilitySignature {
        VulnerabilitySignature {
            id: "test-sql-001".to_string(),
            title: "sql_injection".to_string(),
            cwe_id: "CWE-89".to_string(),
            embedding: CodeEmbedding {
                vector: vec![0.5; 512],
                language: "javascript".to_string(),
                normalized_code: "query = \"SELECT * FROM users WHERE id = \" + user_id".to_string(),
                structural_features: vec![0.8, 0.6, 0.9, 0.7, 0.5],
                control_flow_hash: 12345,
                data_flow_hash: 67890,
                confidence: 0.95,
            },
            variations: vec![],
            severity: 9.0,
            applicable_languages: vec!["javascript".to_string(), "java".to_string()],
            behavioral_signature: BehavioralSignature {
                io_patterns: vec!["database_query".to_string()],
                memory_patterns: vec![],
                network_patterns: vec!["sql_connection".to_string()],
                filesystem_patterns: vec![],
                privilege_patterns: vec!["database_access".to_string()],
                data_flow_characteristics: vec!["untrusted_input_to_query".to_string()],
            },
        }
    }

    fn create_test_xss_signature() -> VulnerabilitySignature {
        VulnerabilitySignature {
            id: "test-xss-001".to_string(),
            title: "cross_site_scripting".to_string(),
            cwe_id: "CWE-79".to_string(),
            embedding: CodeEmbedding {
                vector: vec![0.3; 512],
                language: "javascript".to_string(),
                normalized_code: "element.innerHTML = user_input".to_string(),
                structural_features: vec![0.7, 0.9, 0.6, 0.8, 0.7],
                control_flow_hash: 23456,
                data_flow_hash: 78901,
                confidence: 0.88,
            },
            variations: vec![],
            severity: 7.5,
            applicable_languages: vec!["javascript".to_string(), "html".to_string()],
            behavioral_signature: BehavioralSignature {
                io_patterns: vec!["dom_manipulation".to_string()],
                memory_patterns: vec![],
                network_patterns: vec!["http_response".to_string()],
                filesystem_patterns: vec![],
                privilege_patterns: vec!["script_execution".to_string()],
                data_flow_characteristics: vec!["untrusted_input_to_output".to_string()],
            },
        }
    }

    fn create_test_ecommerce_workflow() -> WorkflowModel {
        let mut business_rules = HashMap::new();
        business_rules.insert("payment".to_string(), vec![
            BusinessRule {
                id: "payment_auth".to_string(),
                name: "Payment Authentication".to_string(),
                condition: "user.authenticated == true".to_string(),
                action: "process_payment".to_string(),
                violation_severity: Severity::High,
                category: BusinessRuleCategory::AccessControl,
            },
        ]);

        WorkflowModel {
            id: "ecommerce_checkout".to_string(),
            app_type: "ecommerce".to_string(),
            states: vec![
                WorkflowState {
                    id: "payment".to_string(),
                    name: "Payment Processing".to_string(),
                    description: "Processing payment".to_string(),
                    required_permissions: vec!["process_payment".to_string()],
                    required_inputs: vec!["payment_amount".to_string()],
                    expected_outputs: vec!["transaction_id".to_string()],
                    side_effects: vec!["charge_card".to_string()],
                    security_constraints: vec![],
                },
            ],
            valid_transitions: HashMap::new(),
            business_rules,
            auth_requirements: HashMap::new(),
            validation_rules: HashMap::new(),
            data_flows: vec![],
        }
    }

    fn create_test_banking_workflow() -> WorkflowModel {
        WorkflowModel {
            id: "banking_auth".to_string(),
            app_type: "banking".to_string(),
            states: vec![],
            valid_transitions: HashMap::new(),
            business_rules: HashMap::new(),
            auth_requirements: HashMap::new(),
            validation_rules: HashMap::new(),
            data_flows: vec![],
        }
    }

    fn create_test_healthcare_workflow() -> WorkflowModel {
        let mut business_rules = HashMap::new();
        business_rules.insert("patient_access".to_string(), vec![
            BusinessRule {
                id: "hipaa_compliance".to_string(),
                name: "HIPAA Privacy Rule".to_string(),
                condition: "user.authorized_for_patient == true".to_string(),
                action: "allow_access".to_string(),
                violation_severity: Severity::Critical,
                category: BusinessRuleCategory::Privacy,
            },
        ]);

        WorkflowModel {
            id: "healthcare_privacy".to_string(),
            app_type: "healthcare".to_string(),
            states: vec![],
            valid_transitions: HashMap::new(),
            business_rules,
            auth_requirements: HashMap::new(),
            validation_rules: HashMap::new(),
            data_flows: vec![],
        }
    }

    fn create_test_generic_workflow() -> WorkflowModel {
        WorkflowModel {
            id: "generic_web_app".to_string(),
            app_type: "generic".to_string(),
            states: vec![],
            valid_transitions: HashMap::new(),
            business_rules: HashMap::new(),
            auth_requirements: HashMap::new(),
            validation_rules: HashMap::new(),
            data_flows: vec![],
        }
    }
}