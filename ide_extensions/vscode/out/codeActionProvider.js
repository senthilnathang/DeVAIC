"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
exports.CodeActionProvider = void 0;
const vscode = require("vscode");
class CodeActionProvider {
    async provideCodeActions(document, range, context, token) {
        const codeActions = [];
        // Filter for DeVAIC diagnostics
        const devaicDiagnostics = context.diagnostics.filter(diagnostic => diagnostic.source === 'DeVAIC Enhanced');
        for (const diagnostic of devaicDiagnostics) {
            codeActions.push(...this.createQuickFixes(document, diagnostic));
        }
        return codeActions;
    }
    createQuickFixes(document, diagnostic) {
        const quickFixes = [];
        const diagnosticCode = diagnostic.code?.toString() || '';
        // SQL Injection fixes
        if (diagnosticCode.includes('SQL_INJECTION') || diagnostic.message.toLowerCase().includes('sql injection')) {
            quickFixes.push(this.createSqlInjectionFix(document, diagnostic));
        }
        // XSS fixes
        if (diagnosticCode.includes('XSS') || diagnostic.message.toLowerCase().includes('cross-site scripting')) {
            quickFixes.push(this.createXssFix(document, diagnostic));
        }
        // Hard-coded secrets fixes
        if (diagnosticCode.includes('HARDCODED_SECRET') || diagnostic.message.toLowerCase().includes('hardcoded')) {
            quickFixes.push(this.createSecretFix(document, diagnostic));
        }
        // Insecure random fixes
        if (diagnosticCode.includes('WEAK_RANDOM') || diagnostic.message.toLowerCase().includes('weak random')) {
            quickFixes.push(this.createSecureRandomFix(document, diagnostic));
        }
        // Command injection fixes
        if (diagnosticCode.includes('COMMAND_INJECTION') || diagnostic.message.toLowerCase().includes('command injection')) {
            quickFixes.push(this.createCommandInjectionFix(document, diagnostic));
        }
        // Buffer overflow fixes
        if (diagnosticCode.includes('BUFFER_OVERFLOW') || diagnostic.message.toLowerCase().includes('buffer overflow')) {
            quickFixes.push(this.createBufferOverflowFix(document, diagnostic));
        }
        // Add generic "Show documentation" action
        quickFixes.push(this.createShowDocumentationAction(diagnostic));
        return quickFixes;
    }
    createSqlInjectionFix(document, diagnostic) {
        const fix = new vscode.CodeAction('Use parameterized query', vscode.CodeActionKind.QuickFix);
        fix.diagnostics = [diagnostic];
        fix.isPreferred = true;
        const line = document.lineAt(diagnostic.range.start.line);
        const lineText = line.text;
        // Create a simple parameterized query suggestion
        let fixedCode = lineText;
        // Python example
        if (document.languageId === 'python') {
            if (lineText.includes('cursor.execute(') && lineText.includes('f"') || lineText.includes('format(')) {
                fixedCode = lineText.replace(/f"([^"]*\{[^}]*\}[^"]*)"/, '"$1"').replace(/\{[^}]*\}/g, '%s');
                fix.edit = new vscode.WorkspaceEdit();
                fix.edit.replace(document.uri, diagnostic.range, fixedCode + ', (param1, param2)  # Use parameters');
            }
        }
        // Java example
        if (document.languageId === 'java') {
            if (lineText.includes('executeQuery(') || lineText.includes('executeUpdate(')) {
                fix.edit = new vscode.WorkspaceEdit();
                const suggestion = '// Use PreparedStatement with parameters\n// PreparedStatement pstmt = conn.prepareStatement("SELECT * FROM users WHERE id = ?");\n// pstmt.setInt(1, userId);';
                fix.edit.replace(document.uri, diagnostic.range, suggestion);
            }
        }
        return fix;
    }
    createXssFix(document, diagnostic) {
        const fix = new vscode.CodeAction('Escape HTML output', vscode.CodeActionKind.QuickFix);
        fix.diagnostics = [diagnostic];
        fix.isPreferred = true;
        const line = document.lineAt(diagnostic.range.start.line);
        const lineText = line.text;
        fix.edit = new vscode.WorkspaceEdit();
        if (document.languageId === 'javascript' || document.languageId === 'typescript') {
            if (lineText.includes('innerHTML')) {
                const suggestion = lineText.replace('innerHTML', 'textContent  // Use textContent to prevent XSS');
                fix.edit.replace(document.uri, diagnostic.range, suggestion);
            }
        }
        if (document.languageId === 'python') {
            if (lineText.includes('render_template_string')) {
                const suggestion = '# Use render_template with auto-escaping enabled\n# Consider using Markup.escape() for user input';
                fix.edit.replace(document.uri, diagnostic.range, suggestion);
            }
        }
        return fix;
    }
    createSecretFix(document, diagnostic) {
        const fix = new vscode.CodeAction('Use environment variable', vscode.CodeActionKind.QuickFix);
        fix.diagnostics = [diagnostic];
        fix.isPreferred = true;
        fix.edit = new vscode.WorkspaceEdit();
        if (document.languageId === 'python') {
            const suggestion = 'os.environ.get("SECRET_KEY")  # Move secret to environment variable';
            fix.edit.replace(document.uri, diagnostic.range, suggestion);
        }
        else if (document.languageId === 'javascript' || document.languageId === 'typescript') {
            const suggestion = 'process.env.SECRET_KEY  // Move secret to environment variable';
            fix.edit.replace(document.uri, diagnostic.range, suggestion);
        }
        else if (document.languageId === 'java') {
            const suggestion = 'System.getenv("SECRET_KEY")  // Move secret to environment variable';
            fix.edit.replace(document.uri, diagnostic.range, suggestion);
        }
        return fix;
    }
    createSecureRandomFix(document, diagnostic) {
        const fix = new vscode.CodeAction('Use cryptographically secure random', vscode.CodeActionKind.QuickFix);
        fix.diagnostics = [diagnostic];
        fix.isPreferred = true;
        fix.edit = new vscode.WorkspaceEdit();
        if (document.languageId === 'python') {
            const suggestion = 'secrets.randbelow(n)  # Use secrets module for cryptographic randomness';
            fix.edit.replace(document.uri, diagnostic.range, suggestion);
        }
        else if (document.languageId === 'javascript' || document.languageId === 'typescript') {
            const suggestion = 'crypto.getRandomValues(new Uint32Array(1))[0]  // Use crypto.getRandomValues()';
            fix.edit.replace(document.uri, diagnostic.range, suggestion);
        }
        else if (document.languageId === 'java') {
            const suggestion = 'SecureRandom.getInstanceStrong().nextInt()  // Use SecureRandom';
            fix.edit.replace(document.uri, diagnostic.range, suggestion);
        }
        return fix;
    }
    createCommandInjectionFix(document, diagnostic) {
        const fix = new vscode.CodeAction('Use safe command execution', vscode.CodeActionKind.QuickFix);
        fix.diagnostics = [diagnostic];
        fix.isPreferred = true;
        fix.edit = new vscode.WorkspaceEdit();
        if (document.languageId === 'python') {
            const suggestion = 'subprocess.run([cmd, arg1, arg2], check=True)  # Use array form with subprocess';
            fix.edit.replace(document.uri, diagnostic.range, suggestion);
        }
        else if (document.languageId === 'javascript' || document.languageId === 'typescript') {
            const suggestion = 'child_process.execFile(cmd, [arg1, arg2])  // Use execFile with array arguments';
            fix.edit.replace(document.uri, diagnostic.range, suggestion);
        }
        return fix;
    }
    createBufferOverflowFix(document, diagnostic) {
        const fix = new vscode.CodeAction('Use safe string functions', vscode.CodeActionKind.QuickFix);
        fix.diagnostics = [diagnostic];
        fix.isPreferred = true;
        fix.edit = new vscode.WorkspaceEdit();
        if (document.languageId === 'c' || document.languageId === 'cpp') {
            const line = document.lineAt(diagnostic.range.start.line);
            const lineText = line.text;
            if (lineText.includes('strcpy(')) {
                const suggestion = lineText.replace('strcpy(', 'strncpy(') + '  // Use strncpy with size limit';
                fix.edit.replace(document.uri, diagnostic.range, suggestion);
            }
            else if (lineText.includes('sprintf(')) {
                const suggestion = lineText.replace('sprintf(', 'snprintf(') + '  // Use snprintf with size limit';
                fix.edit.replace(document.uri, diagnostic.range, suggestion);
            }
        }
        return fix;
    }
    createShowDocumentationAction(diagnostic) {
        const action = new vscode.CodeAction('Show security documentation', vscode.CodeActionKind.Empty);
        action.diagnostics = [diagnostic];
        const diagnosticCode = diagnostic.code?.toString() || '';
        let documentationUrl = 'https://docs.devaic.io/security-guidelines';
        // Map specific vulnerabilities to documentation
        if (diagnosticCode.includes('SQL_INJECTION')) {
            documentationUrl = 'https://docs.devaic.io/vulnerabilities/sql-injection';
        }
        else if (diagnosticCode.includes('XSS')) {
            documentationUrl = 'https://docs.devaic.io/vulnerabilities/xss';
        }
        else if (diagnosticCode.includes('COMMAND_INJECTION')) {
            documentationUrl = 'https://docs.devaic.io/vulnerabilities/command-injection';
        }
        action.command = {
            title: 'Open Documentation',
            command: 'vscode.open',
            arguments: [vscode.Uri.parse(documentationUrl)]
        };
        return action;
    }
}
exports.CodeActionProvider = CodeActionProvider;
CodeActionProvider.providedCodeActionKinds = [
    vscode.CodeActionKind.QuickFix,
    vscode.CodeActionKind.Refactor,
    vscode.CodeActionKind.RefactorRewrite
];
//# sourceMappingURL=codeActionProvider.js.map