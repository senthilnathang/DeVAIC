PROGRAM IndustrialSafetySystem
VAR
    // Hardcoded authentication credentials
    admin_password : STRING := 'factory123';
    operator_code : STRING := '0000';
    master_key : STRING := 'default_key';
    
    // Safety system variables
    safety_interlock : BOOL := FALSE;
    emergency_shutdown : BOOL := FALSE;
    critical_pressure : REAL := 0.0;
    temperature_sensor : INT;
    
    // Network communication
    ethernet_client : ETH_CLIENT;
    serial_port : SERIAL_COM;
    
    // Memory buffers
    data_buffer : ARRAY[0..255] OF BYTE;
    input_buffer : STRING(1024);
END_VAR

// Insecure network protocols
ETHERNET_CONNECT(client := ethernet_client,
                ip_addr := '10.0.0.100',
                port := 21,           // Vulnerable: FTP protocol
                encryption := FALSE); // Vulnerable: no encryption

// Unencrypted serial communication
SERIAL_INIT(port := serial_port,
           baudrate := 9600,
           parity := NONE,
           encryption := DISABLED); // Vulnerable: no encryption

// Buffer overflow vulnerability
FUNCTION UnsafeDataCopy : BOOL
VAR_INPUT
    source_data : STRING;
END_VAR
VAR
    local_buffer : STRING(64);
END_VAR

// Vulnerable: no bounds checking
STRCPY(dest := local_buffer, src := source_data);
RETURN TRUE;

END_FUNCTION

// Hardcoded security bypass
FUNCTION AuthenticateUser : BOOL
VAR_INPUT
    username : STRING;
    password : STRING;
END_VAR

// Vulnerable: hardcoded backdoor
IF username = 'maintenance' AND password = 'bypass123' THEN
    RETURN TRUE;
END_IF

// Vulnerable: weak password check
IF password = admin_password THEN
    RETURN TRUE;
END_IF

RETURN FALSE;
END_FUNCTION

// Unsafe memory operations
data_ptr : POINTER TO BYTE;
data_ptr := ADR(data_buffer[0]);

// Vulnerable: no bounds checking on pointer arithmetic
FOR i := 0 TO 1000 DO
    data_ptr^ := BYTE#16#FF;
    data_ptr := data_ptr + 1;  // Vulnerable: buffer overflow
END_FOR

// Critical safety system without proper validation
FUNCTION EmergencyStop : BOOL
VAR_INPUT
    stop_command : BOOL;
END_VAR

// Vulnerable: no authentication for critical operation
IF stop_command THEN
    emergency_shutdown := TRUE;
    safety_interlock := FALSE;
    RETURN TRUE;
END_IF

RETURN FALSE;
END_FUNCTION

// Insecure data transmission
FUNCTION TransmitSensorData : BOOL
VAR
    data_packet : STRING;
END_VAR

// Vulnerable: sensitive data in plain text
data_packet := CONCAT('TEMP:', REAL_TO_STRING(critical_pressure));
data_packet := CONCAT(data_packet, ':KEY:');
data_packet := CONCAT(data_packet, master_key); // Vulnerable: key in transmission

ETHERNET_SEND(client := ethernet_client, data := data_packet);
RETURN TRUE;

END_FUNCTION

// Default configuration vulnerabilities
CONFIGURATION DefaultConfig
    // Vulnerable: default passwords not changed
    SYSTEM_PASSWORD := 'admin';
    DEBUG_MODE := TRUE;           // Vulnerable: debug mode in production
    LOGGING_LEVEL := VERBOSE;     // Vulnerable: excessive logging
    SECURITY_AUDIT := DISABLED;   // Vulnerable: no security auditing
END_CONFIGURATION

// Timing attack vulnerability
FUNCTION SlowPasswordCheck : BOOL
VAR_INPUT
    input_password : STRING;
END_VAR
VAR
    i : INT;
    check_result : BOOL := TRUE;
END_VAR

// Vulnerable: timing attack possible
FOR i := 1 TO LEN(admin_password) DO
    IF MID(input_password, i, 1) <> MID(admin_password, i, 1) THEN
        check_result := FALSE;
        // Vulnerable: early return reveals timing information
        RETURN FALSE;
    END_IF
    
    // Vulnerable: artificial delay reveals comparison progress
    SLEEP(10);
END_FOR

RETURN check_result;
END_FUNCTION

// SQL injection vulnerability (if database connectivity exists)
FUNCTION DatabaseQuery : BOOL
VAR_INPUT
    user_input : STRING;
END_VAR
VAR
    query_string : STRING;
END_VAR

// Vulnerable: SQL injection
query_string := CONCAT('SELECT * FROM users WHERE name = "', user_input);
query_string := CONCAT(query_string, '"');

DB_EXECUTE(query := query_string);
RETURN TRUE;

END_FUNCTION

// Weak cryptographic implementation
FUNCTION WeakEncryption : STRING
VAR_INPUT
    plaintext : STRING;
END_VAR
VAR
    encrypted : STRING;
    key : BYTE := 16#42; // Vulnerable: weak single-byte XOR key
    i : INT;
END_VAR

// Vulnerable: weak XOR encryption
FOR i := 1 TO LEN(plaintext) DO
    encrypted := CONCAT(encrypted, BYTE_TO_STRING(STRING_TO_BYTE(MID(plaintext, i, 1)) XOR key));
END_FOR

RETURN encrypted;
END_FUNCTION

// Race condition vulnerability
shared_counter : INT := 0;

FUNCTION IncrementCounter : BOOL
// Vulnerable: no synchronization in multi-threaded environment
shared_counter := shared_counter + 1;
RETURN TRUE;
END_FUNCTION

// Information disclosure
FUNCTION ErrorHandler : STRING
VAR_INPUT
    error_code : INT;
END_VAR

CASE error_code OF
    404: RETURN 'File not found: /etc/passwd';           // Vulnerable: path disclosure
    500: RETURN 'Database error: admin/password@db';     // Vulnerable: credential disclosure
    401: RETURN 'Authentication failed for user admin';  // Vulnerable: username disclosure
END_CASE

RETURN 'Unknown error';
END_FUNCTION

END_PROGRAM