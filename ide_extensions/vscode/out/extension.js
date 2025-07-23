"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
exports.deactivate = exports.activate = void 0;
const vscode = require("vscode");
const languageServer_1 = require("./languageServer");
const codeActionProvider_1 = require("./codeActionProvider");
const hoverProvider_1 = require("./hoverProvider");
const diagnosticProvider_1 = require("./diagnosticProvider");
let languageServer;
let codeActionProvider;
let hoverProvider;
let diagnosticProvider;
function activate(context) {
    console.log('DeVAIC Security Analyzer is now active!');
    // Initialize enhanced language server
    languageServer = new languageServer_1.DeVAICLanguageServer(context);
    // Initialize providers
    codeActionProvider = new codeActionProvider_1.CodeActionProvider();
    hoverProvider = new hoverProvider_1.HoverProvider();
    diagnosticProvider = new diagnosticProvider_1.DiagnosticProvider();
    // Register providers
    registerProviders(context);
    // Register commands
    registerCommands(context);
    // Start language server
    languageServer.start().catch(error => {
        console.error('Failed to start DeVAIC Language Server:', error);
        vscode.window.showErrorMessage(`Failed to start DeVAIC Language Server: ${error.message}`);
    });
}
exports.activate = activate;
function registerProviders(context) {
    if (!codeActionProvider || !hoverProvider || !diagnosticProvider) {
        return;
    }
    const supportedLanguages = [
        'rust', 'go', 'javascript', 'typescript', 'python', 'java',
        'kotlin', 'swift', 'c', 'cpp', 'csharp', 'php', 'ruby', 'dart'
    ];
    // Register code action provider for quick fixes
    context.subscriptions.push(vscode.languages.registerCodeActionsProvider(supportedLanguages, codeActionProvider));
    // Register hover provider for vulnerability details
    context.subscriptions.push(vscode.languages.registerHoverProvider(supportedLanguages, hoverProvider));
    // Register diagnostic provider
    context.subscriptions.push(diagnosticProvider);
}
function registerCommands(context) {
    // Analyze current file
    const analyzeFileCommand = vscode.commands.registerCommand('devaic.analyzeFile', async () => {
        if (!languageServer) {
            vscode.window.showErrorMessage('DeVAIC Language Server not initialized');
            return;
        }
        await languageServer.analyzeCurrentFile();
    });
    // Analyze workspace
    const analyzeWorkspaceCommand = vscode.commands.registerCommand('devaic.analyzeWorkspace', async () => {
        if (!languageServer) {
            vscode.window.showErrorMessage('DeVAIC Language Server not initialized');
            return;
        }
        await languageServer.analyzeWorkspace();
    });
    // Toggle real-time analysis
    const toggleRealTimeCommand = vscode.commands.registerCommand('devaic.toggleRealTimeAnalysis', async () => {
        if (!languageServer) {
            vscode.window.showErrorMessage('DeVAIC Language Server not initialized');
            return;
        }
        languageServer.toggleRealTimeAnalysis();
    });
    // Show security report
    const showReportCommand = vscode.commands.registerCommand('devaic.showSecurityReport', async () => {
        const panel = vscode.window.createWebviewPanel('devaicReport', 'DeVAIC Security Report', vscode.ViewColumn.Two, { enableScripts: true });
        panel.webview.html = generateSecurityReportHTML();
    });
    // Show impact analysis
    const showImpactAnalysisCommand = vscode.commands.registerCommand('devaic.showImpactAnalysis', async (impactAnalysis) => {
        const panel = vscode.window.createWebviewPanel('devaicImpact', 'Security Impact Analysis', vscode.ViewColumn.Two, { enableScripts: true });
        panel.webview.html = generateImpactAnalysisHTML(impactAnalysis);
    });
    context.subscriptions.push(analyzeFileCommand, analyzeWorkspaceCommand, toggleRealTimeCommand, showReportCommand, showImpactAnalysisCommand);
}
function generateSecurityReportHTML() {
    return `
    <!DOCTYPE html>
    <html>
    <head>
        <meta charset="UTF-8">
        <meta name="viewport" content="width=device-width, initial-scale=1.0">
        <title>DeVAIC Security Report</title>
        <style>
            body { font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif; margin: 20px; }
            .header { border-bottom: 2px solid #007acc; padding-bottom: 10px; margin-bottom: 20px; }
            .metric { background: #f8f9fa; padding: 15px; margin: 10px 0; border-radius: 5px; }
            .critical { border-left: 4px solid #dc3545; }
            .high { border-left: 4px solid #fd7e14; }
            .medium { border-left: 4px solid #ffc107; }
            .low { border-left: 4px solid #28a745; }
        </style>
    </head>
    <body>
        <div class="header">
            <h1>🛡️ DeVAIC Security Report</h1>
            <p>Enhanced AI-powered security analysis results</p>
        </div>
        
        <div class="metric critical">
            <h3>🚨 Critical Issues: <span id="critical-count">0</span></h3>
            <p>Issues requiring immediate attention</p>
        </div>
        
        <div class="metric high">
            <h3>⚠️ High Priority: <span id="high-count">0</span></h3>
            <p>Important security vulnerabilities</p>
        </div>
        
        <div class="metric medium">
            <h3>📋 Medium Priority: <span id="medium-count">0</span></h3>
            <p>Moderate security concerns</p>
        </div>
        
        <div class="metric low">
            <h3>ℹ️ Low Priority: <span id="low-count">0</span></h3>
            <p>Minor issues and recommendations</p>
        </div>
        
        <script>
            // This would be populated with actual data from the language server
            console.log('Security report loaded');
        </script>
    </body>
    </html>`;
}
function generateImpactAnalysisHTML(impactAnalysis) {
    return `
    <!DOCTYPE html>
    <html>
    <head>
        <meta charset="UTF-8">
        <meta name="viewport" content="width=device-width, initial-scale=1.0">
        <title>Security Impact Analysis</title>
        <style>
            body { font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif; margin: 20px; }
            .impact-section { background: #f8f9fa; padding: 15px; margin: 10px 0; border-radius: 5px; border-left: 4px solid #007acc; }
            .header { border-bottom: 2px solid #007acc; padding-bottom: 10px; margin-bottom: 20px; }
        </style>
    </head>
    <body>
        <div class="header">
            <h1>📊 Security Impact Analysis</h1>
        </div>
        
        <div class="impact-section">
            <h3>🔒 Security Impact</h3>
            <p>${impactAnalysis?.security_impact || 'No analysis available'}</p>
        </div>
        
        <div class="impact-section">
            <h3>💼 Business Risk</h3>
            <p>${impactAnalysis?.business_risk || 'No analysis available'}</p>
        </div>
        
        <div class="impact-section">
            <h3>⚡ Performance Impact</h3>
            <p>${impactAnalysis?.performance_impact || 'No analysis available'}</p>
        </div>
        
        <div class="impact-section">
            <h3>🔧 Maintainability Impact</h3>
            <p>${impactAnalysis?.maintainability_impact || 'No analysis available'}</p>
        </div>
    </body>
    </html>`;
}
function deactivate() {
    if (!languageServer) {
        return undefined;
    }
    return languageServer.stop();
}
exports.deactivate = deactivate;
//# sourceMappingURL=extension.js.map