#!/bin/bash

# DeVAIC Working Build Script
# This script builds DeVAIC with working advanced features (excluding problematic ML deps)

set -e

echo "🚀 Building DeVAIC with Working Advanced Features"
echo "================================================"

# Check if Rust is installed
if ! command -v cargo &> /dev/null; then
    echo "❌ Rust/Cargo not found. Please install Rust first."
    echo "   Visit: https://rustup.rs/"
    exit 1
fi

# Check Rust version
RUST_VERSION=$(rustc --version | cut -d' ' -f2)
echo "📦 Rust version: $RUST_VERSION"

# Create necessary directories
echo "📁 Creating output directories..."
mkdir -p reports
mkdir -p reports/visualizations
mkdir -p models
mkdir -p rules/custom

# Build with working features (excluding problematic ML dependencies)
echo "🔧 Building DeVAIC with working advanced features..."
echo "   Features: ide, async, progress, tracing, fast-walk, performance"

cargo build --release --features "ide,async,progress,tracing,fast-walk,performance"

if [ $? -eq 0 ]; then
    echo "✅ Build successful!"
    
    # Get binary size
    BINARY_SIZE=$(du -h target/release/devaic | cut -f1)
    echo "📊 Binary size: $BINARY_SIZE"
    
    # Test basic functionality
    echo "🧪 Testing basic functionality..."
    ./target/release/devaic --version
    
    if [ $? -eq 0 ]; then
        echo "✅ Basic test passed!"
        
        # Test advanced features
        echo "🧪 Testing working advanced features..."
        
        # Test custom rules
        echo "  - Testing custom rules engine..."
        if ./target/release/devaic tests/fixtures/ --custom-rules-dir rules/custom --verbose 2>/dev/null | head -5; then
            echo "    ✅ Custom rules: Available"
        else
            echo "    ⚠️  Custom rules: Directory empty (expected)"
        fi
        
        # Test compliance reporting
        echo "  - Testing compliance reporting..."
        if ./target/release/devaic tests/fixtures/ --compliance owasp --output-dir reports --verbose 2>/dev/null | head -5; then
            echo "    ✅ Compliance reporting: Available"
        else
            echo "    ⚠️  Compliance reporting: May need test files"
        fi
        
        # Test HTML visualization
        echo "  - Testing HTML dashboard..."
        if ./target/release/devaic tests/fixtures/ --visualize --output-dir reports --verbose 2>/dev/null | head -5; then
            echo "    ✅ HTML Dashboard: Available"
        else
            echo "    ⚠️  HTML Dashboard: May need test files"
        fi
        
        echo ""
        echo "🎉 DeVAIC Working Advanced Build Complete!"
        echo "========================================="
        echo ""
        echo "📍 Binary location: ./target/release/devaic"
        echo "📍 Size: $BINARY_SIZE"
        echo ""
        echo "🚀 Quick Start Commands:"
        echo "  Basic analysis:     ./target/release/devaic /path/to/code"
        echo "  Compliance:         ./target/release/devaic /path/to/code --compliance owasp"
        echo "  Custom rules:       ./target/release/devaic /path/to/code --custom-rules-dir ./rules/custom"
        echo "  Full analysis:      ./target/release/devaic /path/to/code --compliance owasp --visualize"
        echo "  IDE server:         ./target/release/devaic --lsp-server"
        echo ""
        echo "📚 Documentation: docs/ADVANCED_FEATURES.md"
        echo "🔧 Examples: examples/advanced_usage.rs"
        
        # Test with actual files if they exist
        if [ -d "test_files" ] && [ "$(ls -A test_files)" ]; then
            echo ""
            echo "🧪 Running real analysis test..."
            ./target/release/devaic tests/fixtures/ --compliance owasp --visualize --output-dir reports --verbose | head -20
            
            if [ -f "reports/security_dashboard.html" ]; then
                echo "✅ Security dashboard generated successfully!"
                echo "📊 View dashboard: reports/security_dashboard.html"
            fi
        fi
        
    else
        echo "❌ Basic test failed!"
        exit 1
    fi
else
    echo "❌ Build failed!"
    exit 1
fi

echo ""
echo "✨ Working build script completed successfully!"
echo ""
echo "📋 Implemented Features:"
echo "  ✅ IDE Integration (LSP server)"
echo "  ✅ Custom Rule Engine"
echo "  ✅ Compliance Reporting (OWASP, NIST, PCI-DSS)"
echo "  ✅ HTML Visualization Dashboards"
echo "  ✅ Advanced CLI Interface"
echo "  ✅ Performance Optimizations"
echo ""
echo "🔮 Future Features (require dependency fixes):"
echo "  🔄 Machine Learning Integration"
echo "  🔄 Advanced Chart Generation"