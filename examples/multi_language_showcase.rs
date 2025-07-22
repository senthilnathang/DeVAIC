/// Multi-Language Security Analysis Showcase
/// 
/// This example demonstrates DeVAIC's enhanced multi-language support with
/// comprehensive parsers and security rules for Swift, Dart/Flutter, and Rust.
/// 
/// Features showcased:
/// - Advanced AST parsing with tree-sitter integration
/// - Mobile security rules for iOS (Swift) and Android/Flutter (Dart)
/// - Memory safety analysis for Rust
/// - Performance pattern detection
/// - Privacy violation detection

use devaic::{
    analyzer::Analyzer,
    parsers::{SourceFile, ParserFactory},
    Language,
};
use std::path::PathBuf;

fn main() -> Result<(), Box<dyn std::error::Error>> {
    println!("🌍 Multi-Language Security Analysis Showcase");
    println!("============================================");
    
    // Swift iOS Security Example
    println!("\n📱 Swift iOS Security Analysis");
    println!("------------------------------");
    
    let swift_code = r#"
import UIKit
import LocalAuthentication
import CryptoKit

class SecurityController: UIViewController {
    @IBOutlet weak var passwordField: UITextField!
    
    // Vulnerable: Hardcoded API key
    let apiKey = "sk-1234567890abcdefghijklmnopqrstuvwxyz"
    
    // Vulnerable: Force unwrapping
    let userData = UserDefaults.standard.string(forKey: "user_data")!
    
    override func viewDidLoad() {
        super.viewDidLoad()
        
        // Vulnerable: Weak cryptography
        let hasher = Insecure.MD5()
        let hash = hasher.finalize()
        
        // Vulnerable: Insecure WebView
        webView.loadHTMLString("<script>eval(userInput)</script>", baseURL: nil)
        
        // Vulnerable: Insecure keychain access
        let query: [String: Any] = [
            kSecClass as String: kSecClassGenericPassword,
            kSecAttrAccessible as String: kSecAttrAccessibleAlways
        ]
        
        // Good: Biometric authentication
        authenticateWithBiometrics()
    }
    
    func authenticateWithBiometrics() {
        let context = LAContext()
        let reason = "Authenticate to access secure data"
        
        // Potentially vulnerable: Allowing fallback
        context.evaluatePolicy(.deviceOwnerAuthentication, localizedReason: reason) { success, error in
            // Handle authentication result
        }
    }
    
    // Vulnerable: Memory leak risk
    func startTimer() {
        Timer.scheduledTimer(withTimeInterval: 1.0, repeats: true) { _ in
            self.updateUI() // Strong reference cycle
        }
    }
}
"#;
    
    analyze_language_sample("Swift iOS App", swift_code, Language::Swift)?;
    
    // Dart Flutter Security Example
    println!("\n📱 Dart Flutter Security Analysis");
    println!("----------------------------------");
    
    let dart_code = r#"
import 'package:flutter/material.dart';
import 'package:http/http.dart' as http;
import 'package:shared_preferences/shared_preferences.dart';
import 'package:local_auth/local_auth.dart';
import 'package:geolocator/geolocator.dart';

class SecurityApp extends StatefulWidget {
  @override
  _SecurityAppState createState() => _SecurityAppState();
}

class _SecurityAppState extends State<SecurityApp> {
  final LocalAuthentication localAuth = LocalAuthentication();
  
  // Vulnerable: Hardcoded secrets
  final String apiKey = "AIzaSyDdVgKwhZl-rlYuA1XKmMZK8dVkA1qKfG8";
  final String databasePassword = "super_secret_password";
  
  @override
  Widget build(BuildContext context) {
    return Scaffold(
      appBar: AppBar(title: Text('Security Demo')),
      body: Column(
        children: [
          // Vulnerable: PII collection without consent
          TextField(
            decoration: InputDecoration(hintText: 'Enter your SSN'),
          ),
          TextField(
            decoration: InputDecoration(hintText: 'Enter your email address'),
          ),
          ElevatedButton(
            onPressed: () => performInsecureOperations(),
            child: Text('Submit'),
          ),
        ],
      ),
    );
  }
  
  void performInsecureOperations() async {
    // Vulnerable: HTTP instead of HTTPS
    final response = await http.get(Uri.parse('http://api.example.com/data'));
    
    // Vulnerable: Insecure local storage
    final prefs = await SharedPreferences.getInstance();
    await prefs.setString('user_password', databasePassword);
    await prefs.setString('api_token', apiKey);
    
    // Vulnerable: Debug information exposure
    print('User password: $databasePassword');
    print('API response: ${response.body}');
    
    // Vulnerable: Weak biometric authentication
    await localAuth.authenticate(
      localizedReason: 'Authenticate',
      biometricOnly: false, // Allows PIN/password fallback
    );
    
    // Vulnerable: Location tracking without clear consent
    Position position = await Geolocator.getCurrentPosition(
      desiredAccuracy: LocationAccuracy.best,
    );
    
    // Vulnerable: Insecure file handling
    final file = File('/data/user/0/com.example.app/${userInput}.txt');
    await file.writeAsString('Sensitive data');
    
    // Vulnerable: Dynamic code execution
    eval(userInput);
  }
  
  // Vulnerable: Memory leak risk
  StreamController controller = StreamController();
  
  @override
  void dispose() {
    // Missing: controller.close(); - causes memory leak
    super.dispose();
  }
}

// Vulnerable: Insecure WebView configuration
class WebViewExample extends StatelessWidget {
  @override
  Widget build(BuildContext context) {
    return WebView(
      initialUrl: 'https://example.com',
      javascriptMode: JavascriptMode.unrestricted,
      debuggingEnabled: true, // Should be false in production
    );
  }
}
"#;
    
    analyze_language_sample("Dart Flutter App", dart_code, Language::Dart)?;
    
    // Rust Security Example
    println!("\n🦀 Rust Security Analysis");
    println!("--------------------------");
    
    let rust_code = r#"
use std::fs::File;
use std::io::Read;
use std::process::Command;
use std::ptr;

// Vulnerable: Hardcoded secrets
const API_KEY: &str = "sk-1234567890abcdefghijklmnopqrstuvwxyz";
const DATABASE_PASSWORD: &str = "super_secret_db_password";

struct SecurityDemo {
    data: Vec<u8>,
}

impl SecurityDemo {
    fn new() -> Self {
        Self {
            data: Vec::new(),
        }
    }
    
    // Vulnerable: Unsafe operations
    unsafe fn dangerous_memory_operations(&mut self) {
        let raw_ptr = self.data.as_ptr();
        
        // Vulnerable: Unsafe pointer dereferencing
        let value = *raw_ptr;
        
        // Vulnerable: Memory transmutation
        let transmuted: u64 = std::mem::transmute(value);
        
        // Vulnerable: Uninitialized memory
        let uninit: u8 = std::mem::uninitialized();
        
        // Vulnerable: Zeroed memory for non-zero types
        let zeroed: Box<String> = std::mem::zeroed();
    }
    
    // Vulnerable: Potential panics
    fn panic_prone_operations(&self) {
        let data = vec![1, 2, 3];
        
        // Vulnerable: Unwrap can panic
        let value = data.get(10).unwrap();
        
        // Vulnerable: Array indexing can panic
        let item = data[100];
        
        // Vulnerable: String parsing can panic
        let number: i32 = "not_a_number".parse().unwrap();
        
        // Vulnerable: Explicit panic
        panic!("Something went wrong!");
    }
    
    // Vulnerable: Command injection
    fn execute_user_command(&self, user_input: &str) {
        // Vulnerable: Unsanitized user input in command
        let output = Command::new("sh")
            .arg("-c")
            .arg(&format!("ls {}", user_input))
            .output()
            .unwrap();
    }
    
    // Vulnerable: Path traversal
    fn read_user_file(&self, filename: &str) -> Result<String, std::io::Error> {
        // Vulnerable: No path validation
        let mut file = File::open(&format!("/app/data/{}", filename))?;
        let mut contents = String::new();
        file.read_to_string(&mut contents)?;
        Ok(contents)
    }
    
    // Vulnerable: Weak cryptography
    fn weak_crypto_operations(&self) {
        // Vulnerable: MD5 hash
        let digest = md5::compute(b"sensitive data");
        
        // Vulnerable: SHA1 hash
        let sha1_digest = sha1::Sha1::digest(b"more sensitive data");
    }
    
    // Vulnerable: Insecure network communication
    async fn insecure_network_request(&self) {
        // Vulnerable: HTTP instead of HTTPS
        let response = reqwest::get("http://api.example.com/secret-data").await;
    }
    
    // Vulnerable: Unsafe deserialization
    fn deserialize_untrusted_data(&self, data: &[u8]) {
        // Vulnerable: Deserializing untrusted data with pickle
        let deserialized: MyStruct = serde_pickle::from_slice(data).unwrap();
        
        // Vulnerable: Binary deserialization without validation
        let binary_data: MyStruct = bincode::deserialize(data).unwrap();
    }
    
    // Performance issues
    fn performance_antipatterns(&self) {
        let data = "test".to_string();
        
        // Vulnerable: Double clone
        let cloned = data.clone().clone();
        
        // Vulnerable: Unnecessary String conversion
        let converted = String::from(&data).as_str();
        
        // Vulnerable: Inefficient string operations
        let result = data.to_string().as_str();
    }
    
    // Memory leak patterns
    fn memory_leak_risks(&self) {
        let data = Box::new(vec![1, 2, 3, 4, 5]);
        
        // Vulnerable: Intentional memory leak
        Box::leak(data);
        
        // Vulnerable: Manual memory management
        let manual = std::mem::ManuallyDrop::new(Box::new("leaked"));
        
        // Vulnerable: Forgetting to drop
        std::mem::forget(Box::new("forgotten"));
    }
}

#[derive(serde::Deserialize)]
struct MyStruct {
    field: String,
}

fn main() {
    let mut demo = SecurityDemo::new();
    
    unsafe {
        demo.dangerous_memory_operations();
    }
    
    // These would panic in real execution
    // demo.panic_prone_operations();
}
"#;
    
    analyze_language_sample("Rust Security Demo", rust_code, Language::Rust)?;
    
    println!("\n✅ Multi-Language Security Analysis Complete!");
    println!("   Enhanced support includes:");
    println!("   • Swift: iOS security, biometric auth, keychain, memory leaks");
    println!("   • Dart: Flutter security, privacy, mobile permissions, performance");
    println!("   • Rust: Memory safety, unsafe operations, performance, crypto");
    println!("   • All: Advanced AST parsing, timing metrics, error handling");
    
    Ok(())
}

fn analyze_language_sample(name: &str, code: &str, language: Language) -> Result<(), Box<dyn std::error::Error>> {
    println!("Analyzing: {}", name);
    
    // Create source file
    let source_file = SourceFile::new(
        PathBuf::from(format!("example.{}", match language {
            Language::Swift => "swift",
            Language::Dart => "dart", 
            Language::Rust => "rs",
            _ => "txt",
        })),
        code.to_string(),
        language,
    );
    
    // Parse with enhanced AST
    let mut parser = ParserFactory::create_parser(&language)?;
    let parsed_ast = parser.parse(&source_file)?;
    
    // Display parsing metrics
    if let Some(parse_time) = parsed_ast.metadata.parse_time_ms {
        println!("  Parse time: {}ms", parse_time);
    }
    if let Some(node_count) = parsed_ast.metadata.node_count {
        println!("  AST nodes: {}", node_count);
    }
    if let Some(max_depth) = parsed_ast.metadata.max_depth {
        println!("  Max depth: {}", max_depth);
    }
    println!("  File size: {} bytes", parsed_ast.metadata.file_size_bytes);
    println!("  Parse errors: {}", parsed_ast.parse_errors.len());
    
    // Analyze for vulnerabilities
    let mut analyzer = Analyzer::new();
    let results = analyzer.analyze_file(&source_file)?;
    
    println!("  🔍 Found {} vulnerabilities:", results.vulnerabilities.len());
    
    // Group by severity
    let mut critical = 0;
    let mut high = 0; 
    let mut medium = 0;
    let mut low = 0;
    
    for vuln in &results.vulnerabilities {
        match vuln.severity {
            devaic::Severity::Critical => critical += 1,
            devaic::Severity::High => high += 1,
            devaic::Severity::Medium => medium += 1,
            devaic::Severity::Low => low += 1,
            devaic::Severity::Info => low += 1,
        }
    }
    
    if critical > 0 { println!("    🚨 Critical: {}", critical); }
    if high > 0 { println!("    ⚠️  High: {}", high); }
    if medium > 0 { println!("    📋 Medium: {}", medium); }
    if low > 0 { println!("    ℹ️  Low: {}", low); }
    
    // Show top 3 vulnerabilities
    for (i, vuln) in results.vulnerabilities.iter().take(3).enumerate() {
        println!("    {}. {} (Line {}) - {:?}", 
            i + 1, vuln.vulnerability_type, vuln.line_number, vuln.severity);
    }
    
    if results.vulnerabilities.len() > 3 {
        println!("    ... and {} more", results.vulnerabilities.len() - 3);
    }
    
    Ok(())
}