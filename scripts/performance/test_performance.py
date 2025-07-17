#!/usr/bin/env python3
"""
Test script to demonstrate DeVAIC performance improvements.
Creates a test directory with various file types and sizes to benchmark scanning.
"""

import os
import subprocess
import time
import tempfile
import shutil
from pathlib import Path

def create_test_files(test_dir):
    """Create test files of various sizes and types"""
    
    # Create small files
    small_files = []
    for i in range(50):
        file_path = test_dir / f"small_{i}.py"
        with open(file_path, 'w') as f:
            f.write(f"""
def vulnerable_function_{i}():
    password = "hardcoded_password_{i}"
    sql_query = "SELECT * FROM users WHERE id = " + str(user_id)
    os.system("rm -rf " + user_input)
    return password, sql_query
""")
        small_files.append(file_path)
    
    # Create medium files
    medium_files = []
    for i in range(20):
        file_path = test_dir / f"medium_{i}.java"
        with open(file_path, 'w') as f:
            f.write(f"""
public class VulnerableClass{i} {{
    private String password = "hardcoded_password_{i}";
    
    public void vulnerableMethod() {{
        // SQL Injection vulnerability
        String sql = "SELECT * FROM users WHERE id = " + userId;
        Statement stmt = connection.createStatement();
        ResultSet rs = stmt.executeQuery(sql);
        
        // Command injection vulnerability
        Runtime.getRuntime().exec("ping " + userInput);
        
        // Hard-coded credentials
        String apiKey = "sk-1234567890abcdef";
        
        // Buffer overflow potential
        char buffer[256];
        strcpy(buffer, userInput);
        
        // Use after free
        free(ptr);
        *ptr = 42;
    }}
}}
""")
        medium_files.append(file_path)
    
    # Create large files
    large_files = []
    for i in range(5):
        file_path = test_dir / f"large_{i}.cpp"
        with open(file_path, 'w') as f:
            f.write(f"""
#include <iostream>
#include <string>
#include <cstring>
#include <cstdlib>

class VulnerableClass{i} {{
private:
    std::string password = "hardcoded_password_{i}";
    
public:
    void vulnerableMethod() {{
        // Buffer overflow vulnerabilities
        char buffer[256];
        char* userInput = getenv("USER_INPUT");
        strcpy(buffer, userInput);  // CWE-787
        
        // Use after free
        char* ptr = (char*)malloc(100);
        free(ptr);
        *ptr = 'X';  // CWE-416
        
        // Memory leaks
        char* leak = (char*)malloc(1024);
        // Never freed
        
        // Command injection
        std::string cmd = "ping " + std::string(userInput);
        system(cmd.c_str());  // CWE-78
        
        // SQL injection simulation
        std::string sql = "SELECT * FROM users WHERE id = " + std::string(userInput);
        
        // More vulnerable patterns to increase file size
""")
            # Add repetitive vulnerable code to make files larger
            for j in range(100):
                f.write(f"""
        // More vulnerable code block {j}
        char vuln_buffer_{j}[128];
        strcpy(vuln_buffer_{j}, userInput);
        
        std::string sql_{j} = "SELECT * FROM table_{j} WHERE id = " + std::string(userInput);
        system(("rm -rf " + std::string(userInput)).c_str());
        
        char* ptr_{j} = (char*)malloc(64);
        free(ptr_{j});
        *ptr_{j} = 'A';
""")
            f.write("""
    }
};
""")
        large_files.append(file_path)
    
    # Create some binary files to test filtering
    binary_files = []
    for i in range(10):
        file_path = test_dir / f"binary_{i}.exe"
        with open(file_path, 'wb') as f:
            f.write(b'\x00\x01\x02\x03' * 1000)  # Fake binary data
        binary_files.append(file_path)
    
    return small_files, medium_files, large_files, binary_files

def run_benchmark(test_dir):
    """Run DeVAIC performance benchmark"""
    print(f"Running performance benchmark on {test_dir}")
    
    try:
        # Run with benchmark flag
        result = subprocess.run([
            'cargo', 'run', '--release', '--',
            '--benchmark',
            str(test_dir)
        ], capture_output=True, text=True, cwd='/home/sen/DeVAIC')
        
        print("Benchmark Results:")
        print(result.stdout)
        
        if result.stderr:
            print("Warnings/Errors:")
            print(result.stderr)
            
        return result.returncode == 0
        
    except Exception as e:
        print(f"Error running benchmark: {e}")
        return False

def run_cache_test(test_dir):
    """Test cache performance"""
    print(f"\nTesting cache performance on {test_dir}")
    
    try:
        # First run (cold cache)
        print("1. First run (cold cache):")
        start_time = time.time()
        result1 = subprocess.run([
            'cargo', 'run', '--release', '--',
            '--clear-cache',
            '--cache-stats',
            '--verbose',
            str(test_dir)
        ], capture_output=True, text=True, cwd='/home/sen/DeVAIC')
        cold_time = time.time() - start_time
        
        print(f"Cold cache time: {cold_time:.2f}s")
        
        # Second run (warm cache)
        print("2. Second run (warm cache):")
        start_time = time.time()
        result2 = subprocess.run([
            'cargo', 'run', '--release', '--',
            '--cache-stats',
            '--verbose',
            str(test_dir)
        ], capture_output=True, text=True, cwd='/home/sen/DeVAIC')
        warm_time = time.time() - start_time
        
        print(f"Warm cache time: {warm_time:.2f}s")
        
        if warm_time > 0:
            speedup = cold_time / warm_time
            print(f"Cache speedup: {speedup:.2f}x")
        
        return True
        
    except Exception as e:
        print(f"Error running cache test: {e}")
        return False

def main():
    """Main test function"""
    print("DeVAIC Performance Test")
    print("=" * 50)
    
    # Create temporary test directory
    with tempfile.TemporaryDirectory() as temp_dir:
        test_dir = Path(temp_dir) / "test_project"
        test_dir.mkdir()
        
        print(f"Creating test files in {test_dir}")
        small_files, medium_files, large_files, binary_files = create_test_files(test_dir)
        
        print(f"Created {len(small_files)} small files")
        print(f"Created {len(medium_files)} medium files")
        print(f"Created {len(large_files)} large files")
        print(f"Created {len(binary_files)} binary files")
        
        # Calculate total test project size
        total_size = sum(f.stat().st_size for f in test_dir.rglob('*') if f.is_file())
        print(f"Total test project size: {total_size / 1024 / 1024:.2f} MB")
        
        # Build project first
        print("\nBuilding DeVAIC in release mode...")
        build_result = subprocess.run([
            'cargo', 'build', '--release'
        ], capture_output=True, text=True, cwd='/home/sen/DeVAIC')
        
        if build_result.returncode != 0:
            print("Build failed!")
            print(build_result.stderr)
            return False
        
        print("Build successful!")
        
        # Run performance benchmark
        print("\n" + "=" * 50)
        benchmark_success = run_benchmark(test_dir)
        
        # Run cache test
        print("\n" + "=" * 50)
        cache_success = run_cache_test(test_dir)
        
        if benchmark_success and cache_success:
            print("\n✅ All performance tests completed successfully!")
            return True
        else:
            print("\n❌ Some performance tests failed!")
            return False

if __name__ == "__main__":
    success = main()
    exit(0 if success else 1)