#!/usr/bin/env python3
"""
Final performance report for DeVAIC optimizations
"""

import subprocess
import time

def get_analysis_time(output_file):
    """Extract analysis duration from output file"""
    try:
        with open(output_file, 'r') as f:
            content = f.read()
            for line in content.split('\n'):
                if 'Analysis duration:' in line:
                    time_str = line.split(':')[1].strip().replace('s', '')
                    return float(time_str)
    except:
        pass
    return None

def run_test(name, args, output_file, timeout=60):
    """Run a single test"""
    print(f"Testing {name}...")
    start_time = time.time()
    
    try:
        result = subprocess.run(
            ['../../target/release/devaic'] + args,
            capture_output=True,
            text=True,
            cwd='/home/sen/DeVAIC',
            timeout=timeout
        )
        
        with open(output_file, 'w') as f:
            f.write(result.stdout)
            f.write(result.stderr)
        
        analysis_time = get_analysis_time(output_file)
        wall_time = time.time() - start_time
        
        if result.returncode == 0 and analysis_time:
            vuln_count = result.stdout.count('CWE-')
            return {
                'success': True,
                'analysis_time': analysis_time,
                'wall_time': wall_time,
                'vulnerabilities': vuln_count
            }
    except subprocess.TimeoutExpired:
        print(f"  ❌ Timeout after {timeout}s")
    except Exception as e:
        print(f"  ❌ Error: {e}")
    
    return {'success': False}

def main():
    print("DeVAIC Performance Optimization - Final Report")
    print("=" * 60)
    
    test_sets = [
        {
            'name': 'Small Directory (test_files/)',
            'path': 'test_files/',
            'timeout': 30
        },
        {
            'name': 'Large Directory (large_test_files/)',
            'path': 'large_test_files/',
            'timeout': 60
        }
    ]
    
    for test_set in test_sets:
        print(f"\n{test_set['name']}")
        print("-" * 40)
        
        tests = [
            ('Optimized Fast Walker', [test_set['path']]),
            ('Legacy Walker', ['--legacy-walker', test_set['path']]),
            ('Max Depth 3', ['--max-depth', '3', test_set['path']]),
            ('Sequential Mode', ['--no-parallel', test_set['path']]),
        ]
        
        results = []
        
        for test_name, args in tests:
            output_file = f"/tmp/{test_name.lower().replace(' ', '_')}_output.txt"
            result = run_test(test_name, args, output_file, test_set['timeout'])
            
            if result['success']:
                results.append((test_name, result))
                print(f"  ✅ {test_name}: {result['analysis_time']:.2f}s ({result['vulnerabilities']} vulns)")
            else:
                print(f"  ❌ {test_name}: Failed")
        
        if results:
            print("\nPerformance Ranking:")
            results.sort(key=lambda x: x[1]['analysis_time'])
            baseline = results[0][1]['analysis_time']
            
            for i, (name, result) in enumerate(results):
                speedup = baseline / result['analysis_time']
                improvement = ((result['analysis_time'] - baseline) / baseline) * 100
                status = "🏆" if i == 0 else f"+{improvement:.1f}%" if improvement > 0 else f"{improvement:.1f}%"
                print(f"  {i+1}. {name}: {result['analysis_time']:.2f}s ({speedup:.2f}x) {status}")
    
    print(f"\n🎉 Performance optimization completed!")
    print("Key improvements:")
    print("- Removed caching overhead")  
    print("- Simplified to depth-first traversal")
    print("- Optimized directory filtering")
    print("- Maintained file type detection optimizations")

if __name__ == "__main__":
    main()