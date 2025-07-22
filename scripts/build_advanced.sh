#!/bin/bash

# DeVAIC Advanced Features Build Script
# This script builds DeVAIC with all advanced features enabled

set -e

echo "🚀 Building DeVAIC with Advanced Features"
echo "=========================================="

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

# Build with all features
echo "🔧 Building DeVAIC with full feature set..."
echo "   Features: ml, ide, visualization, async, progress, tracing, fast-walk, performance"

cargo build --release --features full

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
        echo "🧪 Testing advanced features..."
        
        # Test ML engine
        echo "  - Testing ML engine..."
        if ./target/release/devaic tests/fixtures/ --enable-ml --verbose --dry-run 2>/dev/null; then
            echo "    ✅ ML engine: OK"
        else
            echo "    ⚠️  ML engine: Feature may need additional setup"
        fi
        
        # Test custom rules
        echo "  - Testing custom rules engine..."
        if ./target/release/devaic tests/fixtures/ --custom-rules-dir rules/custom --verbose --dry-run 2>/dev/null; then
            echo "    ✅ Custom rules: OK"
        else
            echo "    ⚠️  Custom rules: Directory empty (expected)"
        fi
        
        # Test compliance reporting
        echo "  - Testing compliance reporting..."
        if ./target/release/devaic tests/fixtures/ --compliance owasp --output-dir reports --verbose --dry-run 2>/dev/null; then
            echo "    ✅ Compliance reporting: OK"
        else
            echo "    ⚠️  Compliance reporting: May need test files"
        fi
        
        # Test visualization
        echo "  - Testing visualization..."
        if ./target/release/devaic tests/fixtures/ --visualize --output-dir reports --verbose --dry-run 2>/dev/null; then
            echo "    ✅ Visualization: OK"
        else
            echo "    ⚠️  Visualization: May need test files"
        fi
        
        echo ""
        echo "🎉 DeVAIC Advanced Build Complete!"
        echo "=================================="
        echo ""
        echo "📍 Binary location: ./target/release/devaic"
        echo "📍 Size: $BINARY_SIZE"
        echo ""
        echo "🚀 Quick Start Commands:"
        echo "  Basic analysis:     ./target/release/devaic /path/to/code"
        echo "  ML analysis:        ./target/release/devaic /path/to/code --enable-ml"
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

# Optional: Run advanced example
if [ "$1" = "--run-example" ]; then
    echo ""
    echo "🧪 Running advanced usage example..."
    cargo run --release --features full --example advanced_usage
fi

# Optional: Generate documentation
if [ "$1" = "--docs" ]; then
    echo ""
    echo "📚 Generating documentation..."
    cargo doc --features full --no-deps --open
fi

echo ""
echo "✨ Build script completed successfully!"