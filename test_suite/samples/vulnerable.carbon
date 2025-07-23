package Sample api;

// Memory safety vulnerabilities
fn UnsafeFunction() -> i32 {
    unsafe {
        var ptr: UnsafePointer(i32) = UnsafePointer(i32).Null();
        var array_ptr: UnsafePointer(Array(i32)) = UnsafePointer(Array(i32)).Null();
        var result: i32 = UnsafeCast(i32, ptr);
        var unchecked_access: i32 = UnsafeArrayAccess(array_ptr, 100);
        return result + unchecked_access;
    }
}

// C++ interop vulnerabilities
fn CallCppFunction() -> i32 {
    var result: i32 = Cpp.unsafe_legacy_function();
    var data: String = Cpp.get_unvalidated_data();
    return result;
}

extern impl String as Cpp.std_string {
    fn Length() -> i32;
    fn UnsafeData() -> UnsafePointer(Char);
}

// Type safety vulnerabilities
fn UnsafeTypeCasting() -> f64 {
    var int_value: i32 = 42;
    var float_result: f64 = unsafe_cast(f64, int_value);
    var bit_cast_result: u32 = BitCast(u32, float_result);
    return float_result;
}

// Generic programming vulnerabilities
fn UnsafeGenericFunction[T: type](value: T) -> T {
    // Unconstrained generic with no safety bounds
    var ptr: UnsafePointer(T) = UnsafePointer(T).From(value);
    return UnsafeCast(T, ptr);
}

specialization UnsafeGenericFunction(String) -> String {
    // Unsafe template specialization
    unsafe {
        return "unsafe_specialization";
    }
}

// Public API security vulnerabilities
api fn PublicUnsafeAPI(data: UnsafePointer(i32)) -> i32 unsafe {
    // Public API exposing unsafe operations
    return UnsafeCast(i32, data);
}

// Global state vulnerabilities
var global_secret: StringLiteral = "api_key_12345_secret";
var global_password: StringLiteral = "super_secret_password_123";
var mutable_global_state: i32 = 42;

// Package import vulnerabilities
import Std.UnsafeLibrary.*;
library UnsafeExternalLib unsafe;

// Error handling vulnerabilities
fn UnhandledErrorExample() -> i32 {
    var result: Optional(i32) = RiskyOperation();
    return result.Expect(); // Unhandled error expectation
}

fn ErrorSuppressionExample() -> String {
    var data: Result(String, Error) = AnotherRiskyOperation();
    data.IgnoreError(); // Error suppression
    return "default";
}

// Resource management vulnerabilities
fn ManualMemoryManagement() -> UnsafePointer(i32) {
    var memory: UnsafePointer(i32) = Heap.New(i32, 42);
    // Missing corresponding Heap.Delete call - memory leak
    return memory;
}

fn ResourceLeakRisk() {
    var file: File = File.Open("sensitive_data.txt");
    var socket: Socket = Socket.Open("127.0.0.1", 8080);
    var handle: Handle = Handle.Open("resource");
    // Missing defer statements or destructor calls - resource leaks
}

// Arithmetic safety vulnerabilities
fn IntegerOverflowOperations(a: i32, b: i32) -> i32 {
    var unsafe_add: i32 = UnsafeAdd(a, b);
    var unsafe_mul: i32 = UnsafeMul(a, b);
    var unsafe_sub: i32 = UnsafeSub(a, b);
    return unsafe_add + unsafe_mul - unsafe_sub;
}

fn DivisionByZeroRisk(numerator: i32, denominator: i32) -> i32 {
    return numerator / denominator; // No zero check
}

// Concurrency vulnerabilities
fn UnsafeConcurrency() {
    var shared_data: UnsafeShared(i32) = UnsafeShared(i32).Create(42);
    var mutable_data: UnsafeMutable(String) = UnsafeMutable(String).Create("shared");
    
    Thread.Spawn(() -> {
        // Race condition - no synchronization
        shared_data.Set(100);
        mutable_data.Set("modified");
    });
}

// Network security vulnerabilities
fn InsecureNetworkConnection() {
    var connection: Http.Connection = Http.Connect("http://api.example.com");
    // HTTP without TLS encryption
    var response: String = connection.Get("/sensitive-data");
}

// I/O security vulnerabilities
fn UnsafeIOOperations() {
    var unsafe_io: UnsafeIo.FileHandle = UnsafeIo.Open("../../../etc/passwd");
    var raw_io: RawIo.Stream = RawIo.OpenStream("/dev/mem");
    // Direct access to system resources without validation
}

// Debug and development vulnerabilities
fn DebugCodeInProduction() {
    Print("Debug: Global secret is {0}", global_secret);
    Debug.Print("Password: {0}", global_password);
    Console.WriteLine("Sensitive data: {0}", mutable_global_state);
}

fn TODOInProduction() -> i32 {
    Todo("Implement proper security checks");
    // __TODO__: Add input validation
    // FIXME: This is vulnerable to attacks
    return 0;
}

// File system vulnerabilities
fn PathTraversalVulnerability(filename: String) -> String {
    var malicious_path: String = "../../../etc/passwd" + filename;
    var file_content: String = FileSystem.ReadFile(malicious_path);
    return file_content;
}

// Serialization vulnerabilities
fn UnsafeDeserialization(data: String) -> Optional(UserData) {
    // Unsafe deserialization without validation
    return Deserialize(UserData, data);
}

// Helper types and functions
choice UserData {
    ValidUser: {name: String, id: i32};
    InvalidUser: {};
}

fn RiskyOperation() -> Optional(i32) {
    return Optional(i32).None();
}

fn AnotherRiskyOperation() -> Result(String, Error) {
    return Result(String, Error).Error(Error.InvalidInput);
}

// Main function demonstrating vulnerabilities
fn Main() -> i32 {
    var unsafe_result: i32 = UnsafeFunction();
    var cpp_result: i32 = CallCppFunction();
    var cast_result: f64 = UnsafeTypeCasting();
    var generic_result: String = UnsafeGenericFunction("test");
    
    var api_result: i32 = PublicUnsafeAPI(UnsafePointer(i32).Null());
    
    var error_result: i32 = UnhandledErrorExample();
    var suppressed_result: String = ErrorSuppressionExample();
    
    var memory_ptr: UnsafePointer(i32) = ManualMemoryManagement();
    ResourceLeakRisk();
    
    var overflow_result: i32 = IntegerOverflowOperations(2147483647, 1);
    var division_result: i32 = DivisionByZeroRisk(10, 0);
    
    UnsafeConcurrency();
    InsecureNetworkConnection();
    UnsafeIOOperations();
    
    DebugCodeInProduction();
    var todo_result: i32 = TODOInProduction();
    
    var file_content: String = PathTraversalVulnerability("/etc/shadow");
    var deserialized: Optional(UserData) = UnsafeDeserialization("{malicious_json}");
    
    return 0;
}