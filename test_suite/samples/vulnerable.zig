const std = @import("std");

// Memory safety vulnerabilities
pub fn unsafePointerCast() void {
    var some_address: usize = 0x12345678;
    var ptr = @ptrCast(*u32, some_address); // Unsafe pointer cast
    _ = ptr;
}

pub fn undefinedBehaviorExample() void {
    var result = undefined; // Undefined behavior
    std.debug.print("Result: {}\n", .{result});
}

pub fn memoryLeakExample(allocator: std.mem.Allocator) !void {
    var memory = try allocator.alloc(u8, 1024); // Missing defer allocator.free(memory);
    _ = memory;
    // Memory leak - no defer statement for cleanup
}

// Integer overflow vulnerabilities
pub fn wrappingArithmetic(a: u32, b: u32) u32 {
    return a +% b; // Wrapping addition - potential overflow
}

pub fn uncheckedIntegerConversion(value: i64) u32 {
    return @intCast(u32, value); // Unchecked integer cast
}

// Error handling vulnerabilities
pub fn ignoredErrorHandling() void {
    var result = riskyFunction() catch |err| {}; // Ignored error
    _ = result;
}

pub fn unreachablePanic() void {
    if (false) {
        unreachable; // Unreachable code - panic condition
    }
}

// C interop vulnerabilities
const c = @cImport({
    @cInclude("stdio.h"); // C import - external dependency
});

extern fn dangerous_c_function() void; // External C function

pub fn callDangerousCFunction() void {
    dangerous_c_function();
}

// Hardcoded credentials
const api_key = "sk_live_1234567890abcdef"; // Hardcoded API key
const database_password = "super_secret_password_123"; // Hardcoded password

// Debug code in production
pub fn debugExample() void {
    std.debug.print("Debug: API Key is {s}\n", .{api_key}); // Debug statement
    std.debug.warn("Warning: This is debug code\n", .{});
}

// File operations without validation
pub fn unsafeFileOperations() !void {
    const file = try std.fs.cwd().createFile("../../../etc/passwd", .{}); // Path traversal
    defer file.close();
    
    try file.writeAll("malicious content");
}

// Network operations without TLS
pub fn insecureNetworkConnection() !void {
    const allocator = std.heap.page_allocator;
    var connection = try std.net.tcpConnectToHost(allocator, "example.com", 80); // HTTP without TLS
    defer connection.close();
}

// Bit manipulation operations
pub fn unsafeBitCast(value: f32) u32 {
    return @bitCast(u32, value); // Unsafe bit cast
}

// Raw memory operations
pub fn rawMemoryAccess() void {
    var address: usize = 0x1000;
    var ptr = @intToPtr(*u8, address); // Raw memory access
    var int_val = @ptrToInt(ptr); // Pointer to integer conversion
    _ = int_val;
}

// Helper function that can fail
fn riskyFunction() !u32 {
    return error.SomethingWentWrong;
}

// Compile-time unsafe operations
comptime {
    var compile_time_ptr = @ptrCast(*u32, @as(usize, 0x1234)); // Compile-time unsafe cast
    _ = compile_time_ptr;
}

// Allocator usage without proper cleanup
pub fn allocatorMisuse() !void {
    const allocator = std.heap.page_allocator;
    
    // Multiple allocations without proper cleanup
    var data1 = try allocator.alloc(u8, 100);
    var data2 = try allocator.alloc(u32, 50);
    var data3 = try allocator.create(u64);
    
    // Missing defer statements:
    // defer allocator.free(data1);
    // defer allocator.free(data2); 
    // defer allocator.destroy(data3);
    
    _ = data1;
    _ = data2;
    _ = data3;
}

// Unchecked arithmetic with overflow potential
pub fn overflowArithmetic(x: u8, y: u8) u8 {
    return x *% y; // Wrapping multiplication
}

pub fn divisionByZero(a: u32, b: u32) u32 {
    return a / b; // Potential division by zero
}

test "vulnerable zig code test" {
    unsafePointerCast();
    undefinedBehaviorExample();
    
    const allocator = std.testing.allocator;
    try memoryLeakExample(allocator);
    try allocatorMisuse();
    
    _ = wrappingArithmetic(255, 1);
    _ = uncheckedIntegerConversion(-1);
    
    ignoredErrorHandling();
    unreachablePanic();
    
    callDangerousCFunction();
    debugExample();
    
    try unsafeFileOperations();
    try insecureNetworkConnection();
    
    _ = unsafeBitCast(3.14);
    rawMemoryAccess();
    
    _ = overflowArithmetic(200, 200);
    _ = divisionByZero(10, 0);
}