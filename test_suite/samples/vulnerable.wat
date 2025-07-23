(module
  ;; Memory and table declarations
  (memory 1)
  (table 10 funcref)
  
  ;; Dangerous imports that should trigger security warnings
  (import "env" "eval" (func $eval (param i32) (result i32)))
  (import "fs" "readFile" (func $readFile (param i32 i32) (result i32)))
  (import "env" "system" (func $system (param i32) (result i32)))
  (import "crypto" "random" (func $random (param i32) (result i32)))
  (import "env" "performance.now" (func $perf_now (result f64)))
  
  ;; Hardcoded sensitive data in data section
  (data (i32.const 0) "api_key_12345_secret_token")
  (data (i32.const 32) "password_admin123")
  (data (i32.const 64) "https://internal.api.company.com/secret")
  
  ;; Global variables with sensitive names
  (global $secret_key (mut i32) (i32.const 0))
  (global $auth_token (mut i32) (i32.const 32))
  
  ;; Function with unrestricted memory growth
  (func $memory_exhaust (param $size i32)
    local.get $size
    memory.grow  ;; No bounds checking or validation comment
    drop
  )
  
  ;; Function with unsafe memory operations
  (func $unsafe_memory_ops (param $addr i32) (param $val i32)
    local.get $addr
    local.get $val
    i32.store  ;; No validation comment
    
    local.get $addr
    i32.load offset=1000 align=1  ;; Potentially unaligned access
    drop
  )
  
  ;; Function with dangerous indirect calls
  (func $indirect_call_risk (param $idx i32)
    local.get $idx
    call_indirect (type 0)  ;; No validation comment
  )
  
  ;; Function with dynamic table manipulation
  (func $table_manipulation (param $idx i32) (param $func i32)
    local.get $idx
    local.get $func
    table.set  ;; No bounds check comment
  )
  
  ;; Function with timing-sensitive cryptographic operations
  (func $crypto_timing_issue (param $password i32) (param $expected i32) (result i32)
    local.get $password
    local.get $expected
    i32.eq
    if (result i32)
      i32.const 1
    else
      ;; Variable-time comparison on secret data
      local.get $password
      i32.const 0
      select  ;; This creates timing differences
    end
  )
  
  ;; Function with timing-sensitive branch on authentication
  (func $auth_timing (param $user_input i32) (result i32)
    local.get $user_input
    global.get $secret_key
    i32.eq
    br_if 0  ;; Timing-sensitive branch on secret
    i32.const 0
  )
  
  ;; Function demonstrating potential infinite loop
  (func $potential_infinite_loop
    loop $loop
      ;; Missing break condition - potential infinite loop
      br $loop
    end
  )
  
  ;; Function with large memory allocation
  (func $large_allocation
    i32.const 1000000  ;; Allocating 1 million pages
    memory.grow
    drop
  )
  
  ;; Function with recursive call risk
  (func $recursive_risk (param $n i32) (result i32)
    local.get $n
    i32.const 0
    i32.eq
    if (result i32)
      i32.const 1
    else
      local.get $n
      i32.const 1
      i32.sub
      call $recursive_risk  ;; Recursive call without depth limit
      local.get $n
      i32.mul
    end
  )
  
  ;; Function calling host functions without error checking
  (func $unchecked_host_calls (param $cmd i32)
    local.get $cmd
    call $system  ;; No error check comment
    drop
    
    i32.const 0
    i32.const 100
    call $readFile  ;; No error check comment
    drop
  )
  
  ;; Functions for timing attack demonstration
  (func $constant_time_violation (param $secret i32) (param $guess i32) (result i32)
    local.get $secret
    local.get $guess
    i32.eq
    br_table 0 1 0  ;; Variable timing based on secret comparison
  )
  
  ;; Problematic exports
  (export "memory" (memory 0))
  (export "__heap_base" (global $secret_key))
  (export "main" (func $memory_exhaust))
  (export "_start" (func $unsafe_memory_ops))
  
  ;; Export functions for testing
  (export "test_memory" (func $memory_exhaust))
  (export "test_timing" (func $crypto_timing_issue))
  (export "test_indirect" (func $indirect_call_risk))
  (export "test_recursive" (func $recursive_risk))
)