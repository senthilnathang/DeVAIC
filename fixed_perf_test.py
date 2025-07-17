#!/usr/bin/env python3
"""
Fixed performance test for DeVAIC optimizations with proper timeout handling
"""

import subprocess
import time
import sys

def run_devaic_safe(args, timeout=120):
    """Run DeVAIC with proper timeout handling"""
    start_time = time.time()
    
    try:
        print(f"Running: devaic {' '.join(args)}")
        result = subprocess.run(
            ['./target/release/devaic'] + args,
            capture_output=True,
            text=True,
            cwd='/home/sen/DeVAIC',
            timeout=timeout
        )
        
        end_time = time.time()
        duration = end_time - start_time
        
        # Count vulnerabilities found
        vuln_count = result.stdout.count('CWE-')
        
        success = result.returncode == 0
        if not success:
            print(f"Error: {result.stderr}")
        
        return duration, vuln_count, success
        
    except subprocess.TimeoutExpired:
        print(f"❌ Timeout after {timeout}s")
        return timeout, 0, False
    except Exception as e:
        print(f"❌ Error: {e}")
        return 0, 0, False

def main():
    """Run performance comparison with realistic timeouts"""
    print("DeVAIC Performance Comparison")
    print("=" * 50)
    
    # Test on both small and large directories
    test_dirs = [
        ("Small Directory", "test_files/", 30),
        ("Large Directory", "large_test_files/", 120),
    ]
    
    for dir_name, test_dir, timeout in test_dirs:
        print(f"\n{dir_name}: {test_dir}")
        print("-" * 30)
        
        tests = [
            ("Fast Walker (default)", [test_dir]),
            ("Legacy Walker", ['--legacy-walker', test_dir]),
            ("Max Depth 2", ['--max-depth', '2', test_dir]),
            ("Max Depth 3", ['--max-depth', '3', test_dir]),
            ("Sequential Mode", ['--no-parallel', test_dir]),
        ]
        
        results = []
        
        for name, args in tests:
            print(f"\nTesting {name}...")
            duration, vulns, success = run_devaic_safe(args, timeout)
            
            if success:
                print(f"  ✅ {duration:.2f}s, {vulns} vulnerabilities")
                results.append((name, duration, vulns))
            else:
                print(f"  ❌ Failed or timed out")
        
        # Results summary
        if results:
            print(f"\n{dir_name} Results:")
            print("-" * 40)
            
            # Sort by time
            results.sort(key=lambda x: x[1])
            
            baseline = results[0][1]
            
            for i, (name, duration, vulns) in enumerate(results):
                speedup = baseline / duration if duration > 0 else 0
                print(f"{i+1}. {name}: {duration:.2f}s ({speedup:.2f}x) - {vulns} vulnerabilities")
            
            print(f"\n🏆 Fastest: {results[0][0]} ({results[0][1]:.2f}s)")
        else:
            print(f"❌ No successful runs for {dir_name}")
    
    return True

if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print("\n❌ Interrupted by user")
        sys.exit(1)