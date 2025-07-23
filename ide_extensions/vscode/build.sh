#!/bin/bash

# VS Code Extension Build and Test Script
set -e

echo "🚀 Building DeVAIC VS Code Extension..."

# Check if Node.js is installed
if ! command -v node &> /dev/null; then
    echo "❌ Node.js is not installed. Please install Node.js 16 or later."
    exit 1
fi

# Check if npm is installed
if ! command -v npm &> /dev/null; then
    echo "❌ npm is not installed. Please install npm."
    exit 1
fi

# Navigate to extension directory
cd "$(dirname "$0")"

echo "📦 Installing dependencies..."
npm install

echo "🔧 Compiling TypeScript..."
npm run compile

echo "🧹 Running linter..."
npm run lint || echo "⚠️  Linting warnings detected (continuing...)"

echo "📋 Validating package.json..."
if ! command -v vsce &> /dev/null; then
    echo "📦 Installing vsce globally..."
    npm install -g vsce
fi

# Create .vscodeignore if it doesn't exist
if [ ! -f .vscodeignore ]; then
    echo "Creating .vscodeignore..."
    cat > .vscodeignore << 'EOF'
.vscode/**
.vscode-test/**
out/test/**
src/**
.gitignore
vsc-extension-quickstart.md
**/tsconfig.json
**/tslint.json
**/*.map
**/*.ts
.eslintrc.json
tsconfig.json
node_modules/**
.git/**
**/.DS_Store
coverage/**
build.sh
README.md
EOF
fi

echo "🔍 Validating extension package..."
vsce package --out devaic-security-extension.vsix

echo "✅ Extension built successfully!"
echo ""
echo "📄 Extension package: devaic-security-extension.vsix"
echo ""
echo "🧪 To test the extension:"
echo "  1. Install DeVAIC binary: cargo build --release"
echo "  2. Add DeVAIC to PATH or set devaic.languageServerPath in VS Code"
echo "  3. Install extension: code --install-extension devaic-security-extension.vsix"
echo "  4. Reload VS Code window"
echo "  5. Open a supported file (.rs, .py, .js, etc.)"
echo ""
echo "🔧 For development:"
echo "  1. Open this directory in VS Code"
echo "  2. Press F5 to launch Extension Development Host"
echo "  3. Test with sample vulnerable files"
echo ""
echo "📊 Features to test:"
echo "  - Real-time linting as you type"
echo "  - Command palette: 'DeVAIC: Analyze Current File'"
echo "  - Command palette: 'DeVAIC: Analyze Entire Workspace'"
echo "  - Hover over vulnerabilities for details"
echo "  - Quick fixes for common security issues"
echo "  - Status bar shows DeVAIC status"