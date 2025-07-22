# DeVAIC File Organization

This document describes the recent file organization improvements made to the DeVAIC project.

## 📁 New Directory Structure

### Scripts (`scripts/`)
Utility scripts have been organized into logical subdirectories:

**Performance Testing (`scripts/performance/`)**:
- `performance_test.py` - Comprehensive performance testing suite
- `quick_perf_test.py` - Quick performance comparison tool
- `final_performance_report.py` - Final performance report generator
- `fixed_perf_test.py` - Fixed performance test with timeout handling
- `test_performance.py` - Performance testing utilities

**Testing Utilities (`scripts/testing/`)**:
- `create_large_test.py` - Large test directory structure generator
- `test_enhanced.py` - Enhanced testing utilities
- `test_recursive_fix.py` - Recursive testing and fix validation

### Tests (`tests/`)
Test files and samples organized for better maintenance:

**Sample Files (`tests/samples/`)**:
- `test_java_vulnerable.java` - Java vulnerability testing file

**Integration Tests (`tests/integration/`)**:
- Reserved for future integration test data

### Reports (`reports/`)
Sample reports and analysis outputs:
- `test-report.json` - JSON format sample report
- `test-report.pdf` - PDF format sample report
- `test-report.xlsx` - Excel format sample report
- `bearer-analysis.json` - Bearer-style analysis sample

## 🛠️ Script Runner

A new script runner (`run_script.py`) has been added to simplify script execution:

```bash
# Easy script execution from project root
python3 run_script.py scripts/performance/quick_perf_test.py
python3 run_script.py scripts/testing/create_large_test.py
```

## 📝 Benefits of Organization

### 🎯 **Improved Maintainability**
- Clear separation of concerns
- Logical grouping of related files
- Easier navigation and discovery

### 🔍 **Better Development Experience** 
- Reduced clutter in project root
- Structured approach to testing
- Consistent script execution interface

### 📊 **Enhanced Project Structure**
- Professional project layout
- Scalable organization for future growth
- Clear documentation for each area

## 🔄 Migration Notes

### Files Moved:
- Performance scripts: `root/` → `scripts/performance/`
- Testing scripts: `root/` → `scripts/testing/`  
- Test samples: `root/` → `tests/samples/`
- Reports: `root/` → `reports/`

### Scripts Updated:
- All Python scripts updated with correct relative paths
- Script runner added for consistent execution
- README files added for each directory

### Compatibility:
- All existing functionality preserved
- Build system unaffected
- CLI interface unchanged
- Test files remain accessible

## 🚀 Future Improvements

This organization provides a foundation for:
- Additional testing utilities
- More comprehensive benchmarking
- Expanded sample file collections
- Enhanced development tools

The file organization aligns with Rust project conventions and provides a scalable structure for continued development of DeVAIC.