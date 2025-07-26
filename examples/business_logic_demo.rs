/// Business Logic Vulnerability Detection Demonstration
/// 
/// This example demonstrates how the business logic analyzer can understand
/// application workflows and detect vulnerabilities that traditional static
/// analysis might miss.

use devaic::{
    business_logic_analyzer::{
        BusinessLogicAnalyzer, BusinessLogicConfig, WorkflowModel, WorkflowState,
        BusinessRule, BusinessRuleCategory, AuthRequirement, AuthLevel,
        ValidationRule, ValidationType, DataFlow, SecurityConstraint, ConstraintType,
    },
    Language, Severity,
};
use std::collections::HashMap;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    println!("🧠 Business Logic Vulnerability Detection Demo");
    println!("==============================================\n");

    // Initialize the business logic analyzer
    let config = BusinessLogicConfig {
        enable_workflow_analysis: true,
        enable_state_analysis: true,
        enable_auth_analysis: true,
        enable_validation_analysis: true,
        enable_rule_validation: true,
        max_workflow_depth: 10,
        min_confidence_threshold: 0.7,
        enable_ml_enhancement: true,
        analysis_timeout_secs: 300,
    };

    let analyzer = BusinessLogicAnalyzer::new(config);
    println!("✅ Initialized Business Logic Analyzer");

    // Register workflow models
    register_ecommerce_workflow(&analyzer).await?;
    register_banking_workflow(&analyzer).await?;
    register_healthcare_workflow(&analyzer).await?;

    println!("✅ Registered workflow models\n");

    // Demonstrate business logic vulnerability detection
    println!("🔍 Analyzing Business Logic Vulnerabilities");
    println!("-------------------------------------------");

    // Test Case 1: E-commerce Payment Processing
    println!("\n1. E-commerce Payment Processing Analysis:");
    demo_ecommerce_analysis(&analyzer).await?;

    // Test Case 2: Banking Authentication Flow
    println!("\n2. Banking Authentication Flow Analysis:");
    demo_banking_analysis(&analyzer).await?;

    // Test Case 3: Healthcare Data Access
    println!("\n3. Healthcare Data Access Analysis:");
    demo_healthcare_analysis(&analyzer).await?;

    // Test Case 4: Generic Web Application
    println!("\n4. Generic Web Application Analysis:");
    demo_generic_application_analysis(&analyzer).await?;

    println!("\n🎉 Business Logic Analysis Demo Complete!");
    Ok(())
}

/// Register e-commerce workflow model
async fn register_ecommerce_workflow(analyzer: &BusinessLogicAnalyzer) -> Result<(), Box<dyn std::error::Error>> {
    let mut valid_transitions = HashMap::new();
    valid_transitions.insert("browsing".to_string(), vec!["cart".to_string(), "login".to_string()]);
    valid_transitions.insert("cart".to_string(), vec!["checkout".to_string(), "browsing".to_string()]);
    valid_transitions.insert("checkout".to_string(), vec!["payment".to_string(), "cart".to_string()]);
    valid_transitions.insert("payment".to_string(), vec!["confirmation".to_string(), "checkout".to_string()]);
    valid_transitions.insert("login".to_string(), vec!["browsing".to_string(), "checkout".to_string()]);

    let mut business_rules = HashMap::new();
    business_rules.insert("payment".to_string(), vec![
        BusinessRule {
            id: "payment_amount_validation".to_string(),
            name: "Payment Amount Validation".to_string(),
            condition: "amount > 0 AND amount <= account_balance".to_string(),
            action: "process_payment".to_string(),
            violation_severity: Severity::High,
            category: BusinessRuleCategory::Financial,
        },
        BusinessRule {
            id: "payment_authentication".to_string(),
            name: "Payment Authentication Required".to_string(),
            condition: "user.authenticated == true AND payment_method.verified == true".to_string(),
            action: "verify_payment_credentials".to_string(),
            violation_severity: Severity::Critical,
            category: BusinessRuleCategory::AccessControl,
        },
    ]);

    let mut auth_requirements = HashMap::new();
    auth_requirements.insert("payment".to_string(), AuthRequirement {
        auth_level: AuthLevel::Elevated,
        mfa_required: true,
        session_validation: true,
        rbac_rules: vec!["customer".to_string(), "verified_user".to_string()],
        custom_auth: Some("payment_pin_verification".to_string()),
    });

    let mut validation_rules = HashMap::new();
    validation_rules.insert("payment".to_string(), vec![
        ValidationRule {
            field: "payment_amount".to_string(),
            validation_type: ValidationType::Range,
            constraint: "0.01 <= amount <= 10000.00".to_string(),
            error_message: "Payment amount must be between $0.01 and $10,000".to_string(),
            failure_severity: Severity::High,
        },
        ValidationRule {
            field: "credit_card_number".to_string(),
            validation_type: ValidationType::Format,
            constraint: "luhn_algorithm_valid".to_string(),
            error_message: "Invalid credit card number".to_string(),
            failure_severity: Severity::High,
        },
    ]);

    let workflow = WorkflowModel {
        id: "ecommerce_checkout".to_string(),
        app_type: "ecommerce".to_string(),
        states: vec![
            WorkflowState {
                id: "browsing".to_string(),
                name: "Product Browsing".to_string(),
                description: "User browsing products".to_string(),
                required_permissions: vec![],
                required_inputs: vec![],
                expected_outputs: vec!["product_list".to_string()],
                side_effects: vec!["tracking_cookies".to_string()],
                security_constraints: vec![],
            },
            WorkflowState {
                id: "payment".to_string(),
                name: "Payment Processing".to_string(),
                description: "Processing customer payment".to_string(),
                required_permissions: vec!["process_payment".to_string()],
                required_inputs: vec!["payment_method".to_string(), "amount".to_string()],
                expected_outputs: vec!["transaction_id".to_string()],
                side_effects: vec!["charge_credit_card".to_string(), "update_inventory".to_string()],
                security_constraints: vec![
                    SecurityConstraint {
                        constraint_type: ConstraintType::Authorization,
                        description: "User must be authenticated and authorized for payment".to_string(),
                        enforcement: "check_payment_authorization".to_string(),
                        violations: vec!["unauthorized_payment_attempt".to_string()],
                    },
                ],
            },
        ],
        valid_transitions,
        business_rules,
        auth_requirements,
        validation_rules,
        data_flows: vec![
            DataFlow {
                id: "payment_flow".to_string(),
                source: "user_input".to_string(),
                destination: "payment_processor".to_string(),
                transformations: vec!["encryption".to_string(), "validation".to_string()],
                security_requirements: vec!["PCI_DSS_compliance".to_string()],
                taint_tracking: true,
            },
        ],
    };

    analyzer.register_workflow_model(workflow).await?;
    Ok(())
}

/// Register banking workflow model
async fn register_banking_workflow(analyzer: &BusinessLogicAnalyzer) -> Result<(), Box<dyn std::error::Error>> {
    let mut valid_transitions = HashMap::new();
    valid_transitions.insert("unauthenticated".to_string(), vec!["login_attempt".to_string()]);
    valid_transitions.insert("login_attempt".to_string(), vec!["authenticated".to_string(), "unauthenticated".to_string()]);
    valid_transitions.insert("authenticated".to_string(), vec!["account_access".to_string(), "transaction".to_string()]);
    valid_transitions.insert("transaction".to_string(), vec!["confirmation".to_string(), "authenticated".to_string()]);

    let mut business_rules = HashMap::new();
    business_rules.insert("transaction".to_string(), vec![
        BusinessRule {
            id: "daily_limit_check".to_string(),
            name: "Daily Transaction Limit".to_string(),
            condition: "daily_total + amount <= daily_limit".to_string(),
            action: "allow_transaction".to_string(),
            violation_severity: Severity::High,
            category: BusinessRuleCategory::Financial,
        },
        BusinessRule {
            id: "fraud_detection".to_string(),
            name: "Fraud Detection Check".to_string(),
            condition: "fraud_score < threshold AND location_consistent == true".to_string(),
            action: "process_transaction".to_string(),
            violation_severity: Severity::Critical,
            category: BusinessRuleCategory::Financial,
        },
    ]);

    let workflow = WorkflowModel {
        id: "banking_transaction".to_string(),
        app_type: "banking".to_string(),
        states: vec![
            WorkflowState {
                id: "authenticated".to_string(),
                name: "Authenticated Session".to_string(),
                description: "User has successfully authenticated".to_string(),
                required_permissions: vec!["banking_access".to_string()],
                required_inputs: vec!["valid_session".to_string()],
                expected_outputs: vec!["account_dashboard".to_string()],
                side_effects: vec!["log_access".to_string()],
                security_constraints: vec![
                    SecurityConstraint {
                        constraint_type: ConstraintType::Authorization,
                        description: "Valid banking session required".to_string(),
                        enforcement: "session_validation".to_string(),
                        violations: vec!["session_hijacking_attempt".to_string()],
                    },
                ],
            },
        ],
        valid_transitions,
        business_rules,
        auth_requirements: HashMap::new(),
        validation_rules: HashMap::new(),
        data_flows: vec![],
    };

    analyzer.register_workflow_model(workflow).await?;
    Ok(())
}

/// Register healthcare workflow model
async fn register_healthcare_workflow(analyzer: &BusinessLogicAnalyzer) -> Result<(), Box<dyn std::error::Error>> {
    let mut business_rules = HashMap::new();
    business_rules.insert("patient_data_access".to_string(), vec![
        BusinessRule {
            id: "hipaa_compliance".to_string(),
            name: "HIPAA Privacy Compliance".to_string(),
            condition: "user.role IN ['doctor', 'nurse'] AND patient.assigned_to_user == true".to_string(),
            action: "allow_data_access".to_string(),
            violation_severity: Severity::Critical,
            category: BusinessRuleCategory::Privacy,
        },
    ]);

    let workflow = WorkflowModel {
        id: "healthcare_data_access".to_string(),
        app_type: "healthcare".to_string(),
        states: vec![],
        valid_transitions: HashMap::new(),
        business_rules,
        auth_requirements: HashMap::new(),
        validation_rules: HashMap::new(),
        data_flows: vec![],
    };

    analyzer.register_workflow_model(workflow).await?;
    Ok(())
}

/// Demonstrate e-commerce vulnerability analysis
async fn demo_ecommerce_analysis(analyzer: &BusinessLogicAnalyzer) -> Result<(), Box<dyn std::error::Error>> {
    let vulnerable_code = r#"
        function processPayment(amount, cardNumber) {
            // VULNERABILITY: Missing authentication check
            if (amount > 0) {
                return chargeCard(cardNumber, amount);
            }
            
            // VULNERABILITY: No payment amount validation
            // VULNERABILITY: Direct state transition without validation
            orderStatus = "completed";
            return { success: true, transactionId: generateId() };
        }
        
        function adminBypass(user) {
            // VULNERABILITY: Authentication bypass
            if (user.role === "admin" || debugMode === true) {
                return true;
            }
            return checkAuthentication(user);
        }
    "#;

    let result = analyzer.analyze_business_logic(vulnerable_code, Language::Javascript).await?;
    
    println!("   📊 Analysis Results:");
    println!("      Vulnerabilities Found: {}", result.vulnerabilities.len());
    println!("      Authentication Issues: {}", result.auth_issues.len());
    println!("      Validation Issues: {}", result.validation_issues.len());
    println!("      Business Rule Violations: {}", result.rule_violations.len());

    // Display specific vulnerabilities
    for vulnerability in &result.vulnerabilities {
        println!("\n   🚨 {}", vulnerability.vulnerability_info.title);
        println!("      Severity: {:?}", vulnerability.vulnerability_info.severity);
        println!("      Business Impact: {:?}", vulnerability.business_context.financial_impact.loss_range);
        println!("      Risk Score: {}", vulnerability.business_risk.risk_score);
        println!("      Exploitation: {}", vulnerability.exploitation_scenario);
    }

    // Display authentication issues
    for auth_issue in &result.auth_issues {
        println!("\n   🔒 Authentication Issue: {:?}", auth_issue.issue_type);
        println!("      Component: {}", auth_issue.affected_component);
        println!("      Description: {}", auth_issue.description);
        println!("      Exploitation: {}", auth_issue.exploitation_method);
    }

    Ok(())
}

/// Demonstrate banking vulnerability analysis
async fn demo_banking_analysis(analyzer: &BusinessLogicAnalyzer) -> Result<(), Box<dyn std::error::Error>> {
    let vulnerable_code = r#"
        function performTransfer(fromAccount, toAccount, amount) {
            // VULNERABILITY: Missing daily limit check
            // VULNERABILITY: No fraud detection
            if (amount > 0 && fromAccount.balance >= amount) {
                fromAccount.balance -= amount;
                toAccount.balance += amount;
                
                // VULNERABILITY: State transition without proper validation
                transactionStatus = "completed";
                return { success: true };
            }
            return { success: false };
        }
        
        function validateSession(sessionId) {
            // VULNERABILITY: Weak session validation
            if (sessionId === userId.toString()) {
                return true;
            }
            return false;
        }
    "#;

    let result = analyzer.analyze_business_logic(vulnerable_code, Language::Javascript).await?;
    
    println!("   📊 Banking Analysis Results:");
    println!("      Total Issues Found: {}", 
        result.vulnerabilities.len() + result.auth_issues.len() + result.validation_issues.len()
    );

    for vulnerability in &result.vulnerabilities {
        println!("\n   💰 Banking Vulnerability: {}", vulnerability.vulnerability_info.title);
        println!("      Financial Impact: {:?}", vulnerability.business_context.financial_impact.loss_range);
        println!("      Compliance Impact: {}", vulnerability.business_context.financial_impact.compliance_impact);
    }

    Ok(())
}

/// Demonstrate healthcare vulnerability analysis
async fn demo_healthcare_analysis(analyzer: &BusinessLogicAnalyzer) -> Result<(), Box<dyn std::error::Error>> {
    let vulnerable_code = r#"
        function accessPatientData(userId, patientId) {
            // VULNERABILITY: Missing HIPAA compliance check
            // No verification of user's right to access this patient's data
            return database.getPatientRecord(patientId);
        }
        
        function sharePatientData(patientData, recipient) {
            // VULNERABILITY: No consent validation
            // VULNERABILITY: No data minimization
            return sendEmail(recipient, patientData);
        }
    "#;

    let result = analyzer.analyze_business_logic(vulnerable_code, Language::Javascript).await?;
    
    println!("   📊 Healthcare Analysis Results:");
    println!("      Privacy Violations: {}", result.rule_violations.len());
    
    for violation in &result.rule_violations {
        println!("\n   ⚕️ Healthcare Violation: {}", violation.rule.name);
        println!("      Category: {:?}", violation.rule.category);
        println!("      Impact: {:?}", violation.impact.category);
        println!("      Consequences: {:?}", violation.impact.consequences);
    }

    Ok(())
}

/// Demonstrate generic application analysis
async fn demo_generic_application_analysis(analyzer: &BusinessLogicAnalyzer) -> Result<(), Box<dyn std::error::Error>> {
    let vulnerable_code = r#"
        function processUserInput(input) {
            // VULNERABILITY: Missing input validation
            return database.query("SELECT * FROM users WHERE name = " + input);
        }
        
        function authenticateUser(username, password) {
            // VULNERABILITY: Authentication bypass through debug mode
            if (debugMode || username === "admin") {
                return { authenticated: true, role: "admin" };
            }
            
            return checkCredentials(username, password);
        }
        
        function updateUserProfile(userId, profileData) {
            // VULNERABILITY: Missing authorization check
            // Any user can update any profile
            return database.updateUser(userId, profileData);
        }
    "#;

    let result = analyzer.analyze_business_logic(vulnerable_code, Language::Javascript).await?;
    
    println!("   📊 Generic Application Analysis:");
    println!("      Total Vulnerabilities: {}", result.vulnerabilities.len());
    println!("      Analysis Duration: {}ms", result.metadata.duration_ms);
    println!("      Overall Confidence: {:.2}", result.metadata.overall_confidence);

    // Group vulnerabilities by type
    let mut vulnerability_types = HashMap::new();
    for vulnerability in &result.vulnerabilities {
        let entry = vulnerability_types.entry(vulnerability.vulnerability_info.category.clone()).or_insert(0);
        *entry += 1;
    }

    println!("\n   📈 Vulnerability Breakdown:");
    for (category, count) in vulnerability_types {
        println!("      {}: {} issues", category, count);
    }

    // Show top recommendations
    println!("\n   💡 Top Recommendations:");
    let mut all_recommendations = Vec::new();
    for vulnerability in &result.vulnerabilities {
        all_recommendations.extend(vulnerability.remediation.immediate_actions.iter().cloned());
    }
    
    // Get unique recommendations
    all_recommendations.sort();
    all_recommendations.dedup();
    
    for (i, recommendation) in all_recommendations.iter().take(3).enumerate() {
        println!("      {}. {}", i + 1, recommendation);
    }

    Ok(())
}