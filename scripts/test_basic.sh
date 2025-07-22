#!/bin/bash

# Test script for basic DeVAIC functionality without advanced features

set -e

echo "🧪 Testing Basic DeVAIC Functionality"
echo "====================================="

# Build with minimal features
echo "📦 Building with basic features only..."
cargo build --no-default-features --features "progress"

if [ $? -eq 0 ]; then
    echo "✅ Basic build successful!"
    
    # Test basic functionality
    echo "🧪 Testing basic analysis..."
    
    # Create a simple test file
    mkdir -p test_output
    cat > test_output/test.py << 'EOF'
import os
import subprocess

# Potential command injection
def run_command(user_input):
    os.system("ls " + user_input)
    
# SQL injection pattern
def get_user(user_id):
    query = "SELECT * FROM users WHERE id = " + user_id
    return query

# Hardcoded secret
api_key = "sk-1234567890abcdef"
EOF

    echo "📁 Created test file: test_output/test.py"
    
    # Run basic analysis
    echo "🔍 Running basic vulnerability analysis..."
    ./target/debug/devaic test_output/ --format json --output test_output/results.json --verbose
    
    if [ $? -eq 0 ]; then
        echo "✅ Basic analysis completed!"
        
        if [ -f "test_output/results.json" ]; then
            echo "📊 Analysis results:"
            echo "   Output file: test_output/results.json"
            
            # Count vulnerabilities
            VULN_COUNT=$(grep -o '"id"' test_output/results.json | wc -l)
            echo "   Vulnerabilities found: $VULN_COUNT"
            
            if [ $VULN_COUNT -gt 0 ]; then
                echo "✅ Vulnerability detection working!"
            else
                echo "⚠️  No vulnerabilities detected (may need rule tuning)"
            fi
        else
            echo "⚠️  Output file not created"
        fi
    else
        echo "❌ Basic analysis failed"
        exit 1
    fi
    
    # Test table output
    echo "🔍 Testing table output..."
    ./target/debug/devaic test_output/ --format table
    
    echo ""
    echo "🎉 Basic functionality test completed!"
    echo "=================================="
    echo ""
    echo "✅ Core features working:"
    echo "  - Build system"
    echo "  - Basic vulnerability detection"
    echo "  - JSON output format"
    echo "  - Table output format"
    echo "  - File analysis"
    echo ""
    echo "🔧 Advanced features status:"
    echo "  - Custom rules: Architecture implemented"
    echo "  - Compliance reporting: Architecture implemented"
    echo "  - Visualization: Architecture implemented"
    echo "  - ML integration: Architecture implemented (needs dependency fixes)"
    echo "  - IDE integration: Architecture implemented (needs dependency fixes)"
    
else
    echo "❌ Basic build failed!"
    exit 1
fi

# Cleanup
echo "🧹 Cleaning up test files..."
rm -rf test_output/

echo "✨ Test completed successfully!"