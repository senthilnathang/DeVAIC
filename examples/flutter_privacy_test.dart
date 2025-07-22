// Flutter Privacy Test - Examples of privacy violations in mobile apps

import 'package:flutter/material.dart';
import 'package:geolocator/geolocator.dart';
import 'package:device_info_plus/device_info_plus.dart';
import 'package:contacts_service/contacts_service.dart';
import 'package:firebase_analytics/firebase_analytics.dart';
import 'package:local_auth/local_auth.dart';
import 'package:camera/camera.dart';
import 'package:record/record.dart';

class PrivacyViolationApp extends StatefulWidget {
  @override
  _PrivacyViolationAppState createState() => _PrivacyViolationAppState();
}

class _PrivacyViolationAppState extends State<PrivacyViolationApp> {
  final DeviceInfoPlugin deviceInfo = DeviceInfoPlugin();
  final FirebaseAnalytics analytics = FirebaseAnalytics.instance;
  final LocalAuthentication localAuth = LocalAuthentication();
  final Record audioRecorder = Record();

  @override
  void initState() {
    super.initState();
    // Privacy violation: Collecting device info without consent
    _collectDeviceInfo();
    // Privacy violation: Starting location tracking immediately
    _startLocationTracking();
    // Privacy violation: Accessing contacts without permission explanation
    _loadContacts();
    // Privacy violation: Setting up analytics tracking
    _setupAnalytics();
  }

  // Device fingerprinting without consent
  Future<void> _collectDeviceInfo() async {
    if (Platform.isAndroid) {
      AndroidDeviceInfo androidInfo = await deviceInfo.androidInfo;
      String deviceId = androidInfo.androidId; // Privacy violation
      String model = androidInfo.model;
      String manufacturer = androidInfo.manufacturer;
      
      // Sending device fingerprint to analytics
      analytics.setUserId(deviceId); // Privacy violation
    } else if (Platform.isIOS) {
      IosDeviceInfo iosInfo = await deviceInfo.iosInfo;
      String deviceId = iosInfo.identifierForVendor; // Privacy violation
      String systemVersion = Platform.operatingSystemVersion; // Privacy violation
    }
  }

  // Location tracking without explicit consent
  Future<void> _startLocationTracking() async {
    // Privacy violation: High accuracy location without clear purpose
    Position position = await Geolocator.getCurrentPosition(
      desiredAccuracy: LocationAccuracy.best
    );
    
    // Privacy violation: Continuous location tracking
    Geolocator.getPositionStream(
      locationSettings: LocationSettings(
        accuracy: LocationAccuracy.high,
        distanceFilter: 0, // Track every movement
      ),
    ).listen((Position position) {
      // Sending location to analytics without consent
      analytics.logEvent(
        name: 'location_update',
        parameters: {
          'latitude': position.latitude,
          'longitude': position.longitude,
        },
      );
    });
  }

  // Contact access without clear purpose
  Future<void> _loadContacts() async {
    // Privacy violation: Accessing all contacts without explanation
    Iterable<Contact> contacts = await ContactsService.getContacts();
    
    for (Contact contact in contacts) {
      // Privacy violation: Sending contact data to analytics
      analytics.logEvent(
        name: 'contact_accessed',
        parameters: {
          'contact_name': contact.displayName,
          'phone_numbers': contact.phones?.map((p) => p.value).join(','),
        },
      );
    }
  }

  // Analytics setup with PII
  Future<void> _setupAnalytics() async {
    String userId = "user_${DateTime.now().millisecondsSinceEpoch}";
    
    // Privacy violation: Setting user ID without consent
    await analytics.setUserId(userId);
    
    // Privacy violation: Logging sensitive user properties
    await analytics.setUserProperty(
      name: 'device_id',
      value: await _getDeviceId(),
    );
  }

  Future<String> _getDeviceId() async {
    if (Platform.isAndroid) {
      AndroidDeviceInfo info = await deviceInfo.androidInfo;
      return info.androidId;
    } else {
      IosDeviceInfo info = await deviceInfo.iosInfo;
      return info.identifierForVendor;
    }
  }

  @override
  Widget build(BuildContext context) {
    return Scaffold(
      appBar: AppBar(
        title: Text('Privacy Violation Demo'),
      ),
      body: Column(
        children: [
          // Privacy violation: Collecting PII without consent notice
          TextField(
            decoration: InputDecoration(
              hintText: 'Enter your email address', // PII collection
            ),
          ),
          TextField(
            decoration: InputDecoration(
              hintText: 'Enter your phone number', // PII collection
            ),
          ),
          TextField(
            decoration: InputDecoration(
              hintText: 'Enter your home address', // PII collection
            ),
          ),
          TextField(
            decoration: InputDecoration(
              hintText: 'Enter your SSN', // Sensitive PII collection
            ),
          ),
          
          ElevatedButton(
            onPressed: _requestBiometrics,
            child: Text('Enable Biometrics'),
          ),
          
          ElevatedButton(
            onPressed: _startRecording,
            child: Text('Start Recording'),
          ),
          
          ElevatedButton(
            onPressed: _accessCamera,
            child: Text('Access Camera'),
          ),
        ],
      ),
    );
  }

  // Biometric data collection without proper consent
  Future<void> _requestBiometrics() async {
    // Privacy violation: Collecting biometric data
    List<BiometricType> availableBiometrics = await localAuth.getAvailableBiometrics();
    
    bool authenticated = await localAuth.authenticate(
      localizedReason: 'Please authenticate',
      options: AuthenticationOptions(
        biometricOnly: false, // Privacy violation: allowing fallback
        stickyAuth: true,
      ),
    );
    
    if (authenticated) {
      // Privacy violation: Storing biometric success in analytics
      analytics.logEvent(
        name: 'biometric_auth_success',
        parameters: {
          'available_biometrics': availableBiometrics.map((b) => b.toString()).join(','),
          'timestamp': DateTime.now().toIso8601String(),
        },
      );
    }
  }

  // Audio recording without clear purpose
  Future<void> _startRecording() async {
    // Privacy violation: Starting audio recording
    if (await audioRecorder.hasPermission()) {
      await audioRecorder.start();
      
      // Privacy violation: Logging audio recording activity
      analytics.logEvent(
        name: 'audio_recording_started',
        parameters: {
          'timestamp': DateTime.now().toIso8601String(),
        },
      );
    }
  }

  // Camera access without clear purpose
  Future<void> _accessCamera() async {
    // Privacy violation: Initializing camera without clear purpose
    List<CameraDescription> cameras = await availableCameras();
    if (cameras.isNotEmpty) {
      CameraController controller = CameraController(
        cameras[0],
        ResolutionPreset.high,
        enableAudio: true, // Privacy violation: enabling audio
      );
      
      await controller.initialize();
      
      // Privacy violation: Logging camera access
      analytics.logEvent(
        name: 'camera_accessed',
        parameters: {
          'camera_count': cameras.length,
          'resolution': 'high',
          'audio_enabled': true,
        },
      );
    }
  }
}

void main() {
  runApp(MaterialApp(
    home: PrivacyViolationApp(),
  ));
}