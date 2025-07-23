#!/usr/bin/env python3
"""
Quick performance test for DeVAIC optimizations
"""

import subprocess
import time

def run_devaic_quick(args):
    """Run DeVAIC and measure basic performance"""
    start_time = time.time()
    
    try:
        # Get the absolute path to the DeVAIC root directory  
        import os
        devaic_root = os.path.abspath(os.path.join(os.path.dirname(__file__), '../../'))
        devaic_binary = os.path.join(devaic_root, 'target/release/devaic')
        
        result = subprocess.run(
            [devaic_binary] + args,
            capture_output=True,
            text=True,
            cwd=devaic_root,
            timeout=30  # 30 second timeout
        )
        
        end_time = time.time()
        duration = end_time - start_time
        
        # Count vulnerabilities found
        vuln_count = result.stdout.count('CWE-')
        
        return duration, vuln_count, result.returncode == 0
        
    except subprocess.TimeoutExpired:
        return 30.0, 0, False
    except Exception as e:
        return 0, 0, False

def main():
    """Run quick performance comparison"""
    print("Quick Performance Test")
    print("=" * 40)
    
    tests = [
        ("Fast Walker", ['test_suite/unit/fixtures/']),
        ("Legacy Walker", ['--legacy-walker', 'test_suite/unit/fixtures/']),
        ("Depth 1", ['--max-depth', '1', 'test_suite/unit/fixtures/']),
        ("Depth 2", ['--max-depth', '2', 'test_suite/unit/fixtures/']),
        ("Sequential", ['--no-parallel', 'test_suite/unit/fixtures/']),
    ]
    
    results = []
    
    for name, args in tests:
        print(f"\nTesting {name}...")
        duration, vulns, success = run_devaic_quick(args)
        
        if success:
            print(f"  ✅ {duration:.2f}s, {vulns} vulnerabilities")
            results.append((name, duration, vulns))
        else:
            print(f"  ❌ Failed or timed out")
    
    # Summary
    print("\n" + "=" * 40)
    print("RESULTS SUMMARY")
    print("=" * 40)
    
    if results:
        # Sort by time
        results.sort(key=lambda x: x[1])
        
        baseline = results[0][1]
        
        for i, (name, duration, vulns) in enumerate(results):
            speedup = baseline / duration if duration > 0 else 0
            print(f"{i+1}. {name}: {duration:.2f}s ({speedup:.2f}x) - {vulns} vulnerabilities")
        
        print(f"\n🏆 Fastest: {results[0][0]} ({results[0][1]:.2f}s)")
    
    return True

if __name__ == "__main__":
    main()