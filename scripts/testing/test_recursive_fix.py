#!/usr/bin/env python3
"""
Test script to demonstrate the recursive scanning fix in DeVAIC.
"""

import os
import subprocess
import tempfile
import shutil
from pathlib import Path

def run_devaic(args, cwd=None):
    """Run DeVAIC with given arguments"""
    try:
        result = subprocess.run(
            ['./target/release/devaic'] + args,
            capture_output=True,
            text=True,
            cwd=cwd or '/home/sen/DeVAIC'
        )
        return result.returncode == 0, result.stdout, result.stderr
    except Exception as e:
        return False, "", str(e)

def count_vulnerabilities_in_output(output):
    """Count vulnerabilities in DeVAIC output"""
    lines = output.strip().split('\n')
    vuln_count = 0
    for line in lines:
        if line.startswith('|') and 'CWE-' in line:
            vuln_count += 1
    return vuln_count

def test_recursive_scanning():
    """Test recursive scanning functionality"""
    print("Testing Recursive Directory Scanning")
    print("=" * 50)
    
    # Test 1: Sequential vs Parallel mode should find same number of files
    print("\n1. Testing Sequential vs Parallel Mode Parity")
    print("-" * 30)
    
    # Sequential mode
    success, seq_output, seq_err = run_devaic(['--no-parallel', 'tests/fixtures/'])
    seq_nested_count = seq_output.count('nested')
    seq_total_vulns = count_vulnerabilities_in_output(seq_output)
    
    # Parallel mode
    success, par_output, par_err = run_devaic(['tests/fixtures/'])
    par_nested_count = par_output.count('nested')
    par_total_vulns = count_vulnerabilities_in_output(par_output)
    
    print(f"Sequential mode: {seq_nested_count} nested files, {seq_total_vulns} total vulnerabilities")
    print(f"Parallel mode:   {par_nested_count} nested files, {par_total_vulns} total vulnerabilities")
    
    if seq_nested_count == par_nested_count and seq_total_vulns == par_total_vulns:
        print("✅ PASS: Both modes find the same number of vulnerabilities")
    else:
        print("❌ FAIL: Sequential and parallel modes have different results")
        return False
    
    # Test 2: Depth limit functionality
    print("\n2. Testing Depth Limit Functionality")
    print("-" * 30)
    
    depth_results = {}
    for depth in [0, 1, 2, 10, 100]:
        success, output, err = run_devaic(['--max-depth', str(depth), 'tests/fixtures/'])
        nested_count = output.count('nested')
        total_vulns = count_vulnerabilities_in_output(output)
        depth_results[depth] = {'nested': nested_count, 'total': total_vulns}
        print(f"Depth {depth}: {nested_count} nested files, {total_vulns} total vulnerabilities")
    
    # Verify depth limits work correctly
    if (depth_results[0]['nested'] < depth_results[1]['nested'] < 
        depth_results[2]['nested'] <= depth_results[10]['nested'] <= 
        depth_results[100]['nested']):
        print("✅ PASS: Depth limits work correctly")
    else:
        print("❌ FAIL: Depth limits are not working as expected")
        return False
    
    # Test 3: Specific nested file detection
    print("\n3. Testing Specific Nested File Detection")
    print("-" * 30)
    
    success, output, err = run_devaic(['tests/fixtures/'])
    
    expected_files = [
        'tests/fixtures/nested/nested.py',
        'tests/fixtures/nested/nested.c',
        'tests/fixtures/nested/deep/deep.py',
        'tests/fixtures/nested/deep/deeper/deeper.py'
    ]
    
    found_files = []
    for file_path in expected_files:
        if file_path in output:
            found_files.append(file_path)
            print(f"✅ Found: {file_path}")
        else:
            print(f"❌ Missing: {file_path}")
    
    if len(found_files) == len(expected_files):
        print("✅ PASS: All nested files detected")
    else:
        print(f"❌ FAIL: Only {len(found_files)}/{len(expected_files)} nested files found")
        return False
    
    # Test 4: Performance benchmark with nested files
    print("\n4. Testing Performance with Nested Files")
    print("-" * 30)
    
    success, output, err = run_devaic(['--benchmark', 'tests/fixtures/'])
    
    if success and 'Performance Benchmark Results' in output:
        print("✅ PASS: Performance benchmark completed successfully")
        
        # Check that all benchmark modes find the same number of vulnerabilities
        lines = output.split('\n')
        vuln_counts = []
        for line in lines:
            if 'vulnerabilities' in line and 'Benchmark Results' not in line:
                # Extract vulnerability count from line like "Sequential (no cache): 2.01s, 247 vulnerabilities"
                parts = line.split(',')
                for part in parts:
                    if 'vulnerabilities' in part:
                        count = int(part.strip().split()[0])
                        vuln_counts.append(count)
                        break
        
        if len(set(vuln_counts)) == 1:
            print(f"✅ PASS: All benchmark modes find {vuln_counts[0]} vulnerabilities")
        else:
            print(f"❌ FAIL: Benchmark modes find different vulnerability counts: {vuln_counts}")
            return False
    else:
        print("❌ FAIL: Performance benchmark failed")
        return False
    
    print("\n" + "=" * 50)
    print("🎉 All recursive scanning tests passed!")
    print("The recursive directory scanning fix is working correctly.")
    return True

def main():
    """Main test function"""
    print("DeVAIC Recursive Scanning Test")
    print("Testing the fix for recursive folder scanning issue")
    print()
    
    # Ensure we're in the right directory and project is built
    os.chdir('/home/sen/DeVAIC')
    
    # Check if binary exists
    if not os.path.exists('./target/release/devaic'):
        print("Building DeVAIC...")
        build_result = subprocess.run(['cargo', 'build', '--release'], 
                                    capture_output=True, text=True)
        if build_result.returncode != 0:
            print("❌ Build failed!")
            print(build_result.stderr)
            return False
        print("✅ Build successful!")
    
    # Run the tests
    if test_recursive_scanning():
        print("\n✅ All tests passed! Recursive scanning is working correctly.")
        return True
    else:
        print("\n❌ Some tests failed. Please check the output above.")
        return False

if __name__ == "__main__":
    success = main()
    exit(0 if success else 1)