# Scripts Directory

This directory contains utility scripts for DeVAIC development and testing.

## Structure

- `performance/` - Performance testing and benchmarking scripts
- `testing/` - Test data generation and testing utilities

## Performance Scripts (`performance/`)

- `performance_test.py` - Comprehensive performance testing suite
- `quick_perf_test.py` - Quick performance comparison script
- `final_performance_report.py` - Final performance report generator
- `fixed_perf_test.py` - Fixed performance test with proper timeout handling
- `test_performance.py` - Performance testing utilities

## Testing Scripts (`testing/`)

- `create_large_test.py` - Generates large test directory structures for performance testing
- `test_enhanced.py` - Enhanced testing utilities
- `test_recursive_fix.py` - Recursive testing and fix validation

## Usage

### Using the Script Runner (Recommended)

```bash
# Run from project root using the script runner
python3 run_script.py scripts/performance/quick_perf_test.py
python3 run_script.py scripts/performance/performance_test.py
python3 run_script.py scripts/testing/create_large_test.py
```

### Direct Execution

```bash
# Run performance benchmarks (from project root)
python3 scripts/performance/performance_test.py

# Generate test data (from project root)
python3 scripts/testing/create_large_test.py

# Quick performance comparison (from project root)
python3 scripts/performance/quick_perf_test.py
```

All scripts are designed to be run from the DeVAIC root directory. The script runner (`run_script.py`) automatically handles directory management and provides a consistent interface.