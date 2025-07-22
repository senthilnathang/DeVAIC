#!/usr/bin/env python3
"""
Comprehensive performance test for DeVAIC scanning optimizations
"""

import subprocess
import time
import statistics

def run_devaic_with_timing(args):
    """Run DeVAIC and measure performance"""
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
            cwd=devaic_root
        )
        
        end_time = time.time()
        duration = end_time - start_time
        
        # Count vulnerabilities found
        vuln_count = result.stdout.count('CWE-')
        
        return {
            'duration': duration,
            'vulnerabilities': vuln_count,
            'success': result.returncode == 0,
            'stdout': result.stdout,
            'stderr': result.stderr
        }
        
    except Exception as e:
        return {
            'duration': 0,
            'vulnerabilities': 0,
            'success': False,
            'error': str(e)
        }

def run_performance_tests():
    """Run comprehensive performance tests"""
    
    test_cases = [
        {
            'name': 'Fast Walker (default)',
            'args': ['large_tests/fixtures/'],
            'description': 'Using optimized fast walker with directory filtering'
        },
        {
            'name': 'Legacy Walker',
            'args': ['--legacy-walker', 'large_tests/fixtures/'],
            'description': 'Using legacy cached walker'
        },
        {
            'name': 'Sequential Mode',
            'args': ['--no-parallel', 'large_tests/fixtures/'],
            'description': 'Sequential processing with fast walker'
        },
        {
            'name': 'Max Depth 3',
            'args': ['--max-depth', '3', 'large_tests/fixtures/'],
            'description': 'Limited depth scanning'
        },
        {
            'name': 'Max Depth 1',
            'args': ['--max-depth', '1', 'large_tests/fixtures/'],
            'description': 'Shallow scanning'
        },
        {
            'name': 'No Cache',
            'args': ['--no-cache', 'large_tests/fixtures/'],
            'description': 'Fast walker without caching'
        },
    ]
    
    print("DeVAIC Performance Test Results")
    print("=" * 60)
    
    results = {}
    
    for test_case in test_cases:
        print(f"\nTesting: {test_case['name']}")
        print(f"Description: {test_case['description']}")
        print(f"Command: devaic {' '.join(test_case['args'])}")
        
        # Run test multiple times for average
        times = []
        vulns = []
        
        for run in range(3):
            print(f"  Run {run + 1}/3...", end=" ")
            result = run_devaic_with_timing(test_case['args'])
            
            if result['success']:
                times.append(result['duration'])
                vulns.append(result['vulnerabilities'])
                print(f"{result['duration']:.2f}s, {result['vulnerabilities']} vulns")
            else:
                print("FAILED")
                if result.get('stderr'):
                    print(f"  Stderr: {result['stderr']}")
                if result.get('stdout'):
                    print(f"  Stdout: {result['stdout']}")
                if result.get('error'):
                    print(f"  Error: {result['error']}")
                break
        
        if times:
            avg_time = statistics.mean(times)
            avg_vulns = statistics.mean(vulns)
            min_time = min(times)
            max_time = max(times)
            
            results[test_case['name']] = {
                'avg_time': avg_time,
                'min_time': min_time,
                'max_time': max_time,
                'avg_vulns': avg_vulns,
                'description': test_case['description']
            }
            
            print(f"  Average: {avg_time:.2f}s (min: {min_time:.2f}s, max: {max_time:.2f}s)")
            print(f"  Vulnerabilities: {avg_vulns:.0f}")
    
    # Print summary
    print("\n" + "=" * 60)
    print("PERFORMANCE SUMMARY")
    print("=" * 60)
    
    if results:
        # Sort by average time
        sorted_results = sorted(results.items(), key=lambda x: x[1]['avg_time'])
        
        baseline_time = sorted_results[0][1]['avg_time']
        
        for i, (name, data) in enumerate(sorted_results):
            speedup = baseline_time / data['avg_time']
            print(f"{i+1}. {name}: {data['avg_time']:.2f}s ({speedup:.2f}x)")
            print(f"   {data['description']}")
        
        # Best performing configuration
        best_name, best_data = sorted_results[0]
        print(f"\n🏆 Best Performance: {best_name}")
        print(f"   Time: {best_data['avg_time']:.2f}s")
        print(f"   Vulnerabilities: {best_data['avg_vulns']:.0f}")
    
    return results

def test_directory_filtering():
    """Test directory filtering effectiveness"""
    print("\n" + "=" * 60)
    print("DIRECTORY FILTERING TEST")
    print("=" * 60)
    
    # Test with and without filtering
    with_filtering = run_devaic_with_timing(['large_tests/fixtures/'])
    without_filtering = run_devaic_with_timing(['--legacy-walker', 'large_tests/fixtures/'])
    
    print(f"With directory filtering: {with_filtering['duration']:.2f}s")
    print(f"Without directory filtering: {without_filtering['duration']:.2f}s")
    
    if with_filtering['success'] and without_filtering['success']:
        speedup = without_filtering['duration'] / with_filtering['duration']
        print(f"Speedup from filtering: {speedup:.2f}x")
        
        if with_filtering['vulnerabilities'] == without_filtering['vulnerabilities']:
            print("✅ Same number of vulnerabilities found")
        else:
            print(f"⚠️  Different vulnerability counts: {with_filtering['vulnerabilities']} vs {without_filtering['vulnerabilities']}")

def main():
    """Main test function"""
    print("Building DeVAIC in release mode...")
    
    # Get the absolute path to the DeVAIC root directory
    import os
    devaic_root = os.path.abspath(os.path.join(os.path.dirname(__file__), '../../'))
    
    build_result = subprocess.run(
        ['cargo', 'build', '--release'],
        capture_output=True,
        text=True,
        cwd=devaic_root
    )
    
    if build_result.returncode != 0:
        print("❌ Build failed!")
        print(build_result.stderr)
        return False
    
    print("✅ Build successful!\n")
    
    # Run performance tests
    results = run_performance_tests()
    
    # Test directory filtering
    test_directory_filtering()
    
    print("\n" + "=" * 60)
    print("🎉 Performance testing completed!")
    
    return True

if __name__ == "__main__":
    success = main()
    exit(0 if success else 1)