// Example Dart file with various security vulnerabilities for testing

import 'dart:io';
import 'dart:convert';
import 'dart:math';
import 'package:flutter/material.dart';
import 'package:http/http.dart' as http;
import 'package:shared_preferences/shared_preferences.dart';

class VulnerableApp {
  // Hardcoded secrets - CWE-798
  static const String apiKey = "sk-1234567890abcdef1234567890abcdef";
  static const String secretKey = "my-super-secret-key-12345";
  static const String password = "admin123";
  
  // Weak encryption - CWE-327
  void weakEncryption() {
    var key = "hardcoded-key-123";
    // Using weak encryption mode
    // AES.new(key, AESMode.ecb);
  }
  
  // SQL injection vulnerability - CWE-89
  Future<void> sqlInjection(String userInput) async {
    var query = "SELECT * FROM users WHERE name = '${userInput}'";
    // database.rawQuery(query);
  }
  
  // Command injection - CWE-78
  Future<void> commandInjection(String userInput) async {
    await Process.run('ls', ['-la', userInput]);
    await Process.start('cat', ['/etc/passwd', userInput]);
  }
  
  // HTTP injection - CWE-20
  Future<void> httpInjection(String userInput) async {
    var url = "https://api.example.com/data?query=${userInput}";
    await http.get(Uri.parse(url));
  }
  
  // Insecure data storage - CWE-312
  Future<void> insecureStorage() async {
    final prefs = await SharedPreferences.getInstance();
    await prefs.setString('user_password', 'secret123');
    await prefs.setString('api_secret', 'my-secret-token');
    
    // Writing sensitive data to file
    final file = File('/tmp/secrets.txt');
    await file.writeAsString('password: admin123');
  }
  
  // Insecure HTTP communication - CWE-295
  Future<void> insecureHttp() async {
    var response = await http.get(Uri.parse('http://api.example.com/data'));
    print(response.body);
  }
  
  // Weak random number generation - CWE-338
  String generateToken() {
    var random = Random();
    var token = '';
    for (int i = 0; i < 32; i++) {
      token += random.nextInt(10).toString();
    }
    return token;
  }
  
  // Debug information exposure - CWE-489
  void debugExposure() {
    var sensitiveData = {'password': 'secret123', 'token': 'abc123'};
    print('Debug: User data: $sensitiveData');
    debugPrint('Secret token: ${apiKey}');
  }
  
  // Path traversal - CWE-22
  Future<String> readFile(String filename) async {
    var file = File('../../../etc/passwd/$filename');
    return await file.readAsString();
  }
  
  // Insecure WebView - CWE-79
  Widget insecureWebView() {
    return WebView(
      initialUrl: 'https://example.com',
      javascriptMode: JavascriptMode.unrestricted,
      allowsInlineMediaPlayback: true,
    );
  }
  
  // Disabled certificate validation - CWE-295
  void disableCertValidation() {
    HttpOverrides.global = MyHttpOverrides();
  }
}

class MyHttpOverrides extends HttpOverrides {
  @override
  HttpClient createHttpClient(SecurityContext? context) {
    return super.createHttpClient(context)
      ..badCertificateCallback = (X509Certificate cert, String host, int port) => true;
  }
}

// Flutter widget with security issues
class InsecureWidget extends StatelessWidget {
  final String userInput;
  
  const InsecureWidget({Key? key, required this.userInput}) : super(key: key);
  
  @override
  Widget build(BuildContext context) {
    return Scaffold(
      appBar: AppBar(
        title: Text('Insecure App'),
      ),
      body: Column(
        children: [
          // XSS-like vulnerability in Flutter
          Text('User input: $userInput'), // Unvalidated user input
          
          // Debug information in production
          if (kDebugMode) Text('Debug: API Key: ${VulnerableApp.apiKey}'),
          
          // Insecure WebView
          Expanded(
            child: WebView(
              initialUrl: 'https://example.com?data=$userInput',
              javascriptMode: JavascriptMode.unrestricted,
            ),
          ),
        ],
      ),
    );
  }
}

void main() {
  // More debug exposure
  print('Starting app with secret: ${VulnerableApp.secretKey}');
  
  runApp(MaterialApp(
    home: InsecureWidget(userInput: 'test'),
  ));
}