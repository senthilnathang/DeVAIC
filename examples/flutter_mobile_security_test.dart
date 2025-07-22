// Flutter Mobile Security Test - Examples of mobile security vulnerabilities

import 'package:flutter/material.dart';
import 'package:flutter/services.dart';
import 'package:flutter_secure_storage/flutter_secure_storage.dart';
import 'package:local_auth/local_auth.dart';
import 'dart:io';

class MobileSecurityIssueApp extends StatefulWidget {
  @override
  _MobileSecurityIssueAppState createState() => _MobileSecurityIssueAppState();
}

class _MobileSecurityIssueAppState extends State<MobileSecurityIssueApp> {
  
  // Security issue: Insecure storage configuration
  final FlutterSecureStorage insecureStorage = FlutterSecureStorage(
    aOptions: AndroidOptions(
      encryptedSharedPreferences: false, // Security vulnerability
    ),
  );
  
  final LocalAuthentication localAuth = LocalAuthentication();
  
  // Security issue: Insecure method channel names with user input
  static const MethodChannel _insecureChannel = MethodChannel('com.example.insecure');

  @override
  void initState() {
    super.initState();
    _checkSecurityFeatures();
  }

  Future<void> _checkSecurityFeatures() async {
    // Security issue: Root detection bypass
    bool isRooted = await _checkRootStatus();
    if (isRooted) {
      // Security issue: Continuing execution on rooted device
      print('Device is rooted, but continuing anyway');
    }
    
    // Security issue: Insecure biometric authentication
    await _setupInsecureBiometrics();
  }

  // Security issue: Weak root detection
  Future<bool> _checkRootStatus() async {
    try {
      // Security issue: Easily bypassed root detection
      // return RootBeer().isRooted(); // This would return false if bypassed
      return false; // Security issue: Always returning false
    } catch (e) {
      return false; // Security issue: Ignoring detection errors
    }
  }

  // Security issue: Insecure biometric setup
  Future<void> _setupInsecureBiometrics() async {
    bool authenticated = await localAuth.authenticate(
      localizedReason: 'Please authenticate',
      options: AuthenticationOptions(
        biometricOnly: false, // Security issue: Allowing fallback to PIN/password
        stickyAuth: false,
        useErrorDialogs: true,
        localizedFallbackTitle: null, // Security issue: No fallback title
      ),
    );
  }

  // Security issue: Insecure deep link handling
  void _handleDeepLink(String deepLinkData) {
    // Security issue: No validation of deep link data
    Navigator.pushNamed(context, '/details', arguments: deepLinkData);
    
    // Security issue: Dynamic route with user input
    String route = '/user/${deepLinkData}';
    Navigator.pushNamed(context, route);
  }

  // Security issue: Insecure inter-app communication
  Future<void> _insecureMethodChannelCall(String userInput) async {
    try {
      // Security issue: Method channel with user input
      final String channelName = 'com.example.${userInput}';
      const MethodChannel dynamicChannel = MethodChannel(channelName);
      
      // Security issue: Invoking method with unvalidated input
      await dynamicChannel.invokeMethod('processData', userInput);
      
      // Security issue: Event channel with user input
      final String eventChannelName = 'com.example.events.${userInput}';
      const EventChannel eventChannel = EventChannel(eventChannelName);
      
      eventChannel.receiveBroadcastStream(userInput).listen((data) {
        print('Received: $data');
      });
      
    } catch (e) {
      print('Error: $e');
    }
  }

  // Security issue: Insecure file operations
  Future<void> _insecureFileOperations(String userPath) async {
    // Security issue: File path with user input
    final File userFile = File('/data/app/${userPath}');
    
    // Security issue: Writing to file with broad permissions
    await userFile.writeAsString('sensitive data', mode: FileMode.write);
    
    // Security issue: Creating directory recursively
    final Directory userDir = Directory('/data/app/user/${userPath}');
    await userDir.create(recursive: true);
    
    // Security issue: Dynamic file path construction
    String dynamicPath = '/storage/emulated/0/${userPath}';
    final File dynamicFile = File(dynamicPath);
    await dynamicFile.writeAsString('user data');
  }

  // Security issue: Insecure certificate handling
  void _setupInsecureHttpClient() {
    HttpOverrides.global = InsecureHttpOverrides();
  }

  @override
  Widget build(BuildContext context) {
    return Scaffold(
      appBar: AppBar(
        title: Text('Mobile Security Issues Demo'),
      ),
      body: Column(
        children: [
          ElevatedButton(
            onPressed: () => _handleDeepLink('../../etc/passwd'),
            child: Text('Test Deep Link'),
          ),
          
          ElevatedButton(
            onPressed: () => _insecureMethodChannelCall('../../../system'),
            child: Text('Test Method Channel'),
          ),
          
          ElevatedButton(
            onPressed: () => _insecureFileOperations('../../../etc/shadow'),
            child: Text('Test File Operations'),
          ),
          
          ElevatedButton(
            onPressed: _setupInsecureHttpClient,
            child: Text('Setup Insecure HTTP'),
          ),
          
          TextField(
            decoration: InputDecoration(
              hintText: 'Enter path for file operation',
            ),
            onSubmitted: (value) => _insecureFileOperations(value),
          ),
        ],
      ),
    );
  }
}

// Security issue: Insecure HTTP overrides
class InsecureHttpOverrides extends HttpOverrides {
  @override
  HttpClient createHttpClient(SecurityContext? context) {
    return super.createHttpClient(context)
      // Security issue: Accepting all certificates
      ..badCertificateCallback = (X509Certificate cert, String host, int port) => true;
  }
}

// Security issue: Insecure keystore access
class InsecureKeystoreManager {
  // Security issue: Keystore with weak accessibility
  static const FlutterSecureStorage weakStorage = FlutterSecureStorage(
    iOptions: IOSOptions(
      accessibility: IOSAccessibility.whenUnlocked, // Security issue: Too permissive
    ),
    aOptions: AndroidOptions(
      encryptedSharedPreferences: false, // Security issue: No encryption
    ),
  );
  
  Future<void> storeCredentials(String username, String password) async {
    // Security issue: Storing credentials in weak storage
    await weakStorage.write(key: 'username', value: username);
    await weakStorage.write(key: 'password', value: password);
  }
}

void main() {
  runApp(MaterialApp(
    home: MobileSecurityIssueApp(),
  ));
}