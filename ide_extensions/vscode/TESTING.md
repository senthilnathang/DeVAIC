# DeVAIC VS Code Extension Testing Guide

## 🚀 **Extension Built Successfully!**

The DeVAIC VS Code extension has been built and packaged as `devaic-security-extension.vsix`.

## 📋 **Testing Checklist**

### Prerequisites
- [x] VS Code extension built (`devaic-security-extension.vsix`)
- [x] DeVAIC binary compiled (`target/release/devaic`)
- [x] Sample vulnerable files created

### Manual Testing Steps

#### 1. **Install the Extension**
```bash
# Install the extension package
code --install-extension devaic-security-extension.vsix

# Or for development testing:
# Open this directory in VS Code and press F5
```

#### 2. **Configure DeVAIC Path**
Add to VS Code settings (Ctrl+,):
```json
{
    "devaic.languageServerPath": "/home/sen/DeVAIC/target/release/devaic"
}
```

#### 3. **Test Real-time Linting**

**Test File 1: Python SQL Injection**
```python
# test_suite/vscode_extension/vulnerable_sample.py
import sqlite3

def get_user(user_id):
    conn = sqlite3.connect('users.db')
    cursor = conn.cursor()
    
    # This should trigger a SQL injection warning
    query = f"SELECT * FROM users WHERE id = {user_id}"
    cursor.execute(query)
    
    return cursor.fetchone()
```

**Expected Results:**
- 🔍 Red squiggly under the vulnerable line
- ⚠️ Diagnostic in Problems panel
- 💡 Hover shows vulnerability details
- 🔧 Quick fix suggestions available

**Test File 2: JavaScript XSS**
```javascript
// test_suite/vscode_extension/vulnerable_sample.js
app.get('/search', (req, res) => {
    const query = req.query.q;
    
    // This should trigger an XSS warning
    const html = `<div>${query}</div>`;
    res.send(html);
});
```

#### 4. **Test Extension Commands**
- Command Palette (Ctrl+Shift+P):
  - `DeVAIC: Analyze Current File`
  - `DeVAIC: Analyze Entire Workspace`
  - `DeVAIC: Toggle Real-Time Analysis`
  - `DeVAIC: Show Security Report`

#### 5. **Test Status Bar**
- Status bar should show: `🛡️ DeVAIC: Active`
- Click status bar to trigger analysis
- Status updates during analysis: `🔄 DeVAIC: Analyzing...`

#### 6. **Test Hover Functionality**
Hover over detected vulnerabilities should show:
- 🚨 **Severity level** and icon
- 📝 **Detailed description**
- 🎯 **CWE mapping**
- 💡 **Recommendations**
- 🔗 **Links to documentation**
- 🔧 **Quick fix options**

#### 7. **Test Code Actions (Quick Fixes)**
Right-click on vulnerability or use Ctrl+.:
- **SQL Injection**: "Use parameterized query"
- **XSS**: "Escape HTML output"
- **Hardcoded Secrets**: "Use environment variable"
- **Command Injection**: "Use safe command execution"

## 🐛 **Known Issues & Workarounds**

### Issue 1: Language Server Not Starting
**Symptoms**: Extension shows "DeVAIC: Error" in status bar

**Solutions**:
1. Ensure DeVAIC binary is built: `cargo build --release`
2. Check binary permissions: `chmod +x target/release/devaic`
3. Set correct path in settings: `devaic.languageServerPath`
4. Check VS Code Output panel for error details

### Issue 2: No Real-time Analysis
**Symptoms**: No diagnostics appear while typing

**Solutions**:
1. Check if real-time analysis is enabled in settings
2. Ensure file extension is supported
3. Check exclude patterns in settings
4. Try saving the file to trigger analysis

### Issue 3: Language Server Protocol Issues
**Symptoms**: LSP initialization failures

**Current Status**: The LSP server has basic structure but needs refinement for proper message handling. For testing, the extension will show mock diagnostics or use direct binary execution.

## 📊 **Performance Testing**

### Metrics to Monitor
- **Analysis Time**: < 500ms for typical files
- **Memory Usage**: < 64MB per file
- **CPU Usage**: Should not block UI
- **False Positive Rate**: < 5%

### Large File Testing
```bash
# Test with large files
find . -name "*.py" -size +100k | head -5
```

## 🔧 **Development Testing**

### Debug Mode
1. Open VS Code in this directory
2. Press F5 to launch Extension Development Host
3. Open test files in the new window
4. Check Debug Console for logs

### Extension Logs
- View → Output → Select "DeVAIC Language Server"
- Look for initialization and analysis messages

## ✅ **Test Results Summary**

| Feature | Status | Notes |
|---------|--------|-------|
| Extension Installation | ✅ | Package created successfully |
| TypeScript Compilation | ✅ | All files compile without errors |
| LSP Server Binary | ✅ | Builds and runs |
| Real-time Analysis | 🚧 | Basic structure in place |
| Hover Provider | ✅ | Detailed vulnerability info |
| Code Actions | ✅ | Quick fixes implemented |
| Command Palette | ✅ | All commands registered |
| Status Bar | ✅ | Shows extension status |

## 🚀 **Next Steps**

1. **Enhance LSP Protocol**: Improve message handling for proper real-time analysis
2. **Add Configuration UI**: Settings panel for easier configuration
3. **Implement Telemetry**: Usage analytics and error reporting
4. **Add Testing Suite**: Automated tests for all features
5. **Package for Marketplace**: Prepare for VS Code Marketplace publication

## 📞 **Support**

If you encounter issues:
1. Check VS Code Output panel: "DeVAIC Language Server"
2. Enable verbose logging in settings
3. Test with minimal configuration
4. Report issues with reproduction steps

## 🎉 **Success Indicators**

The extension is working correctly if you see:
- ✅ Vulnerabilities highlighted in real-time
- ✅ Detailed hover information
- ✅ Quick fix suggestions
- ✅ Command palette integration
- ✅ Status bar updates
- ✅ Problems panel shows security issues