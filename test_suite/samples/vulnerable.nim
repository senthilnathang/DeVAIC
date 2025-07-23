import os, strutils, json, marshal, httpclient, net, asyncdispatch

# Memory safety vulnerabilities
proc unsafeMemoryOperations() =
    var someVar = 42
    var ptr = cast[ptr int](unsafeAddr(someVar))  # Unsafe memory access
    var raw_memory = alloc(1024)  # Manual memory allocation without dealloc
    var unsafe_ptr = unsafeNew(seq[int], 100)  # Unsafe allocation
    
    # Pointer arithmetic vulnerability
    var offset_ptr = cast[ptr int](cast[int](ptr) + 8)
    echo "Unsafe pointer: ", repr(offset_ptr)

# FFI and C interop vulnerabilities
{.compile: "external_lib.c".}  # Compile-time code execution

proc dangerous_c_function(data: ptr cchar): cint {.importc, cdecl.}
proc another_c_function() {.exportc, stdcall.}
proc unsafe_dynlib_function(): cint {.dynlib: "unsafe_lib.so", importc.}

{.header: "unsafe_header.h".}

proc unsafeCInterop() =
    var data = "unsafe data"
    var result = dangerous_c_function(data.cstring)
    echo "C function result: ", result

# Macro system vulnerabilities
macro unsafeMacroDefinition(code: untyped): untyped =
    # Unsafe macro with untyped parameters
    result = quote do:
        `code`

template unsafeTemplateWithUntyped(body: untyped): untyped =
    body

# Threading and concurrency vulnerabilities
{.experimental: "parallel".}

var globalSharedData {.global.}: int = 42  # Global shared state

proc unsafeThreading() {.thread, gcsafe.} =
    # Unsafe threading without proper synchronization
    globalSharedData = 100
    echo "Thread modified global data"

proc concurrencyIssues() =
    var channels: Channel[string]
    channels.open()
    
    # Unsafe channel operations without proper error handling
    channels.send("unsafe data")
    var received = channels.recv()
    echo "Received: ", received

# Error handling vulnerabilities
proc ignoredExceptionHandling() =
    try:
        var risky_result = riskyOperation()
        echo "Result: ", risky_result
    except:
        discard  # Ignored exception

proc unsafeAssertions() =
    assert false  # Unsafe assertion that will always fail

proc uncheckedOptionAccess() =
    var maybe_value: Option[int] = none(int)
    var value = maybe_value.get()  # Unchecked access to None option
    echo "Value: ", value

# File system vulnerabilities
proc unsafeFileOperations(filename: string) =
    var malicious_path = "../../../etc/passwd" & filename
    var content = readFile(malicious_path)  # Path traversal
    writeFile("./output/" & filename, content)
    removeFile("../sensitive/" & filename)

proc tempFileRaceCondition() =
    var temp_dir = getTempDir()
    var temp_file = createTempFile("unsafe", ".tmp")
    echo "Created temp file: ", temp_file

# Network security vulnerabilities
proc insecureNetworkOperations() =
    var socket = newSocket()
    socket.connect("example.com", Port(80))  # Unencrypted connection
    
    var client = newHttpClient()
    client.headers = newHttpHeaders({"User-Agent": "NimHttpClient"})
    var response = client.getContent("http://api.example.com/data")  # HTTP without TLS

proc insecureSocketWithDisabledVerification() =
    var socket = newSocket(verify = false)  # Disabled SSL verification
    socket.connect("https://example.com", Port(443))

# String and buffer vulnerabilities
proc bufferOverflowRisk() =
    var source = "source data with potential overflow"
    var dest: array[10, char]
    copyMem(addr dest[0], source.cstring, source.len)  # Buffer overflow risk
    
    var another_dest: array[5, char]
    moveMem(addr another_dest[0], source.cstring, 20)  # Buffer overflow
    zeroMem(addr dest[0], 1000)  # Potential memory corruption

proc unsafeStringOperations() =
    var unsafe_cstring = cstring("unsafe")
    if unsafe_cstring.isNil:
        echo "String is nil"
    echo "Length: ", unsafe_cstring.len

# Hardcoded secrets and credentials
const api_key = "sk_live_1234567890abcdef"  # Hardcoded API key
const secret_token = "ghp_xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx"  # Hardcoded secret
const password = "super_secret_password_123"  # Hardcoded password

const database_host = "production-db.company.com"  # Hardcoded database info
const database_user = "admin"
const database_password = "db_password_123"

# Debug and development vulnerabilities
proc debugStatements() =
    echo "Debug: API key is ", api_key  # Debug with secrets
    debugEcho "Debug echo: Password is ", password
    dump(secret_token)  # Debug dump of sensitive data

{.debugger.}  # Debug pragma
{.lineTrace: on.}  # Line tracing enabled

# Unsafe pragmas and compiler directives
{.checks: off.}  # Safety checks disabled
{.boundChecks: off.}  # Bounds checking disabled
{.optimization: none.}  # Optimization disabled

{.emit: """
// Unsafe code generation
printf("Direct C code emission\n");  
""".}

# Command execution vulnerabilities
proc commandInjectionRisk(user_input: string) =
    var command = "ls -la " & user_input  # Command injection
    var result = execCmd(command)
    echo "Command result: ", result
    
    var process_result = execProcess("rm -rf " & user_input)
    echo "Process result: ", process_result
    
    var started_process = startProcess("dangerous_command", args = [user_input])

proc systemCallsWithoutValidation() =
    var result = os.execv("/bin/sh", ["-c", "malicious_command"])
    discard os.system("rm -rf /")

# Serialization vulnerabilities
proc unsafeDeserialization(data: string) =
    # Unsafe JSON parsing without validation
    var json_data = parseJson(data)
    echo "Parsed JSON: ", json_data
    
    # Unsafe marshaling operations
    var marshaled_data = marshal.to[string](data)
    var unmarshaled = marshal.to[JsonNode](marshaled_data)

# Generic programming vulnerabilities
proc unconstrainedGeneric[T](value: T): T =
    # Unconstrained generic procedure
    var ptr = cast[ptr T](alloc(sizeof(T)))
    ptr[] = value
    return ptr[]

# Pickle-like deserialization (if available)
proc pickleDeserialization(data: string) =
    # Simulated unsafe deserialization similar to Python's pickle
    var loaded_data = loads(data)  # Hypothetical unsafe loader
    echo "Loaded data: ", loaded_data

# Helper functions
proc riskyOperation(): int =
    raise newException(ValueError, "Something went wrong")

proc loads(data: string): string =
    # Simulated unsafe data loader
    return data

# Main procedure demonstrating vulnerabilities
proc main() =
    echo "Nim Language Security Test"
    
    # Memory safety issues
    unsafeMemoryOperations()
    
    # C interop issues
    unsafeCInterop()
    
    # Threading issues
    var thread: Thread[void]
    createThread(thread, unsafeThreading)
    joinThread(thread)
    
    concurrencyIssues()
    
    # Error handling issues
    ignoredExceptionHandling()
    unsafeAssertions()
    try:
        uncheckedOptionAccess()
    except:
        echo "Option access failed"
    
    # File system issues
    unsafeFileOperations("test.txt")
    tempFileRaceCondition()
    
    # Network issues
    insecureNetworkOperations()
    insecureSocketWithDisabledVerification()
    
    # Buffer issues
    bufferOverflowRisk()
    unsafeStringOperations()
    
    # Debug and development issues
    debugStatements()
    
    # Command injection issues
    commandInjectionRisk("; rm -rf /")
    systemCallsWithoutValidation()
    
    # Serialization issues
    unsafeDeserialization("""{"key": "value"}""")
    pickleDeserialization("malicious_data")
    
    # Generic programming issues
    var generic_result = unconstrainedGeneric[string]("unsafe")
    echo "Generic result: ", generic_result

# Async vulnerabilities
proc unsafeAsyncOperations() {.async.} =
    var future_result = riskyAsyncOperation()
    # Missing await - potential race condition
    echo "Async operation started"

proc riskyAsyncOperation() {.async.} =
    await sleepAsync(1000)
    raise newException(ValueError, "Async operation failed")

when isMainModule:
    main()
    
    # Async execution without proper error handling
    asyncdispatch.runForever()