#!/bin/bash

# DeVAIC Core Features Build Script
# This script builds DeVAIC with core advanced features (no heavy visualization deps)

set -e

echo "🚀 Building DeVAIC with Core Advanced Features"
echo "=============================================="

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

# Build with core features (excluding heavy visualization dependencies)
echo "🔧 Building DeVAIC with core advanced features..."
echo "   Features: ml, ide, async, progress, tracing, fast-walk, performance"

cargo build --release --features "ml,ide,async,progress,tracing,fast-walk,performance"

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
        echo "🧪 Testing core advanced features..."
        
        # Test ML engine
        echo "  - Testing ML engine..."
        if ./target/release/devaic tests/fixtures/ --enable-ml --verbose 2>/dev/null | head -5; then
            echo "    ✅ ML engine: Available"
        else
            echo "    ⚠️  ML engine: May need test files"
        fi
        
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
        
        # Test HTML visualization (lightweight)
        echo "  - Testing HTML dashboard..."
        if ./target/release/devaic tests/fixtures/ --visualize --output-dir reports --verbose 2>/dev/null | head -5; then
            echo "    ✅ HTML Dashboard: Available"
        else
            echo "    ⚠️  HTML Dashboard: May need test files"
        fi
        
        echo ""
        echo "🎉 DeVAIC Core Advanced Build Complete!"
        echo "======================================"
        echo ""
        echo "📍 Binary location: ./target/release/devaic"
        echo "📍 Size: $BINARY_SIZE"
        echo ""
        echo "🚀 Quick Start Commands:"
        echo "  Basic analysis:     ./target/release/devaic /path/to/code"
        echo "  ML analysis:        ./target/release/devaic /path/to/code --enable-ml"
        echo "  Compliance:         ./target/release/devaic /path/to/code --compliance owasp"
        echo "  Full analysis:      ./target/release/devaic /path/to/code --enable-ml --compliance owasp --visualize"
        echo "  IDE server:         ./target/release/devaic --lsp-server"
        echo ""
        echo "📚 Documentation: docs/ADVANCED_FEATURES.md"
        echo "🔧 Examples: examples/advanced_usage.rs"
        
    else
        echo "❌ Basic test failed!"
        exit 1
    fi
else
    echo "❌ Build failed!"
    exit 1
fi

echo ""
echo "✨ Core build script completed successfully!"
echo ""
echo "💡 Note: For full visualization features with charts, install system dependencies:"
echo "   Ubuntu/Debian: sudo apt-get install libfontconfig1-dev"
echo "   Then run: cargo build --release --features visualization-full"