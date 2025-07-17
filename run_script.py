#!/usr/bin/env python3
"""
DeVAIC Script Runner - Utility to run scripts from the project root directory
"""

import sys
import subprocess
import os
from pathlib import Path

def main():
    if len(sys.argv) < 2:
        print("Usage: python3 run_script.py <script_path> [args...]")
        print("\nAvailable scripts:")
        print("Performance testing:")
        print("  scripts/performance/quick_perf_test.py")
        print("  scripts/performance/performance_test.py")
        print("  scripts/performance/final_performance_report.py")
        print("\nTesting utilities:")
        print("  scripts/testing/create_large_test.py")
        print("  scripts/testing/test_enhanced.py")
        print("\nExamples:")
        print("  python3 run_script.py scripts/performance/quick_perf_test.py")
        print("  python3 run_script.py scripts/testing/create_large_test.py")
        return 1
    
    script_path = sys.argv[1]
    script_args = sys.argv[2:]
    
    # Get the project root directory
    project_root = Path(__file__).parent.absolute()
    full_script_path = project_root / script_path
    
    if not full_script_path.exists():
        print(f"Error: Script not found: {full_script_path}")
        return 1
    
    # Change to project root and run the script
    try:
        result = subprocess.run([
            sys.executable, str(full_script_path)
        ] + script_args, cwd=project_root)
        return result.returncode
    except KeyboardInterrupt:
        print("\nScript interrupted by user")
        return 1
    except Exception as e:
        print(f"Error running script: {e}")
        return 1

if __name__ == "__main__":
    exit(main())