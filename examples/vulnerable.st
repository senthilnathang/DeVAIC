PROGRAM IndustrialControl
VAR
    // Hardcoded credentials - security vulnerability
    operator_password : STRING := 'admin123';
    maintenance_user : STRING := 'admin';
    default_password : STRING := 'password';
    
    // System variables
    emergency_stop : BOOL := FALSE;
    safety_system_active : BOOL := TRUE;
    temperature_reading : REAL;
    pressure_value : INT;
    
    // Network configuration
    tcp_connection : TCP_CLIENT;
    modbus_connection : MODBUS_TCP_CLIENT;
END_VAR

// Insecure network communication - Telnet usage
TCP_CONNECT(connection := tcp_connection, 
           ip_address := '192.168.1.100', 
           port := 23);  // Vulnerable: Telnet port

// Insecure HTTP communication
HTTP_CLIENT(connection := tcp_connection,
           url := 'http://unsafe-server.com/api',
           ssl := FALSE);  // Vulnerable: no encryption

// Unsafe memory operations
MEMCPY(source := pressure_value, 
       destination := temperature_reading, 
       size := 1024);  // Vulnerable: no bounds checking

// Lack of input validation
temperature_reading := STRING_TO_REAL(user_input);  // Vulnerable: no validation

// Weak authentication
AUTH_LEVEL := 0;  // Vulnerable: no authentication required
SECURITY_LEVEL := NONE;  // Vulnerable: no security

// Safety-critical operation without proper checks
emergency_stop := TRUE;  // Vulnerable: no validation for critical operation

// Bypass authentication
BYPASS_AUTH := TRUE;  // Vulnerable: authentication bypass

// Default configuration not changed
default_config := TRUE;  // Vulnerable: using default settings

// Timing-sensitive operation without synchronization
IF critical_timer > 5000 THEN
    safety_shutdown();  // Vulnerable: no proper timing sync
END_IF

// Modbus without encryption
MODBUS_TCP(connection := modbus_connection,
          ip := '192.168.1.50',
          port := 502,
          encryption := FALSE);  // Vulnerable: no encryption

// Function block with hardcoded values
FUNCTION_BLOCK SecureAccess
VAR_INPUT
    user_password : STRING;
END_VAR
VAR
    access_granted : BOOL := FALSE;
END_VAR

// Vulnerable: hardcoded password comparison
IF user_password = 'secret123' THEN
    access_granted := TRUE;
END_IF

END_FUNCTION_BLOCK

// Unsafe pointer operations
VAR
    data_pointer : POINTER TO INT;
    unsafe_address : DWORD;
END_VAR

data_pointer := ADR(pressure_value);  // Vulnerable: unsafe pointer usage
unsafe_address := data_pointer^;  // Vulnerable: dereferencing without checks

END_PROGRAM