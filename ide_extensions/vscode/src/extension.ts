import * as vscode from 'vscode';
import * as path from 'path';
import { LanguageClient, LanguageClientOptions, ServerOptions } from 'vscode-languageclient/node';

let client: LanguageClient | undefined;

export function activate(context: vscode.ExtensionContext) {
    console.log('DeVAIC Security Analyzer is now active!');

    // Initialize Language Server
    initializeLanguageServer(context);
    
    // Register commands
    registerCommands(context);
    
    // Setup status bar
    setupStatusBar(context);
    
    // Setup configuration change listener
    setupConfigurationListener(context);
}

function initializeLanguageServer(context: vscode.ExtensionContext) {
    const config = vscode.workspace.getConfiguration('devaic');
    
    // Determine language server path
    let serverPath = config.get<string>('languageServerPath');
    if (!serverPath) {
        // Auto-detect based on platform
        const platform = process.platform;
        const extension = platform === 'win32' ? '.exe' : '';
        serverPath = path.join(context.extensionPath, 'server', `devaic-lsp${extension}`);
    }
    
    // Server options
    const serverOptions: ServerOptions = {
        run: { command: serverPath, args: ['--lsp'] },
        debug: { command: serverPath, args: ['--lsp', '--verbose'] }
    };
    
    // Client options
    const clientOptions: LanguageClientOptions = {
        documentSelector: [
            { scheme: 'file', language: 'rust' },
            { scheme: 'file', language: 'go' },
            { scheme: 'file', language: 'javascript' },
            { scheme: 'file', language: 'typescript' },
            { scheme: 'file', language: 'python' },
            { scheme: 'file', language: 'java' },
            { scheme: 'file', language: 'kotlin' },
            { scheme: 'file', language: 'swift' },
            { scheme: 'file', language: 'c' },
            { scheme: 'file', language: 'cpp' },
            { scheme: 'file', language: 'csharp' },
            { scheme: 'file', language: 'php' },
            { scheme: 'file', language: 'ruby' },
            { scheme: 'file', language: 'dart' }
        ],
        synchronize: {
            fileEvents: vscode.workspace.createFileSystemWatcher('**/.{rs,go,js,ts,py,java,kt,swift,c,cpp,cs,php,rb,dart}')
        }
    };
    
    // Create language client
    client = new LanguageClient(
        'devaic-lsp',
        'DeVAIC Language Server',
        serverOptions,
        clientOptions
    );
    
    // Start the client
    client.start().then(() => {
        console.log('DeVAIC Language Server started successfully');
        updateStatusBar('$(shield) DeVAIC: Active');
    }).catch(err => {
        console.error('Failed to start DeVAIC Language Server:', err);
        updateStatusBar('$(error) DeVAIC: Error');
        vscode.window.showErrorMessage(`Failed to start DeVAIC Language Server: ${err.message}`);
    });
}

function registerCommands(context: vscode.ExtensionContext) {
    // Analyze current file
    const analyzeFileCommand = vscode.commands.registerCommand('devaic.analyzeFile', async () => {
        const editor = vscode.window.activeTextEditor;
        if (!editor) {
            vscode.window.showWarningMessage('No active editor found');
            return;
        }
        
        updateStatusBar('$(loading~spin) DeVAIC: Analyzing...');
        
        try {
            // Trigger analysis through language server
            await vscode.commands.executeCommand('vscode.executeDocumentDiagnostics', editor.document.uri);
            
            const diagnostics = vscode.languages.getDiagnostics(editor.document.uri);
            const securityIssues = diagnostics.filter(d => d.source === 'DeVAIC Enhanced');
            
            if (securityIssues.length > 0) {
                const message = `Found ${securityIssues.length} security issue(s)`;
                vscode.window.showInformationMessage(message, 'Show Problems').then(selection => {
                    if (selection === 'Show Problems') {
                        vscode.commands.executeCommand('workbench.panel.markers.view.focus');
                    }
                });
            } else {
                vscode.window.showInformationMessage('No security issues found! 🎉');
            }
            
            updateStatusBar('$(shield) DeVAIC: Active');
        } catch (error) {
            console.error('Analysis failed:', error);
            vscode.window.showErrorMessage('Analysis failed. Check the output panel for details.');
            updateStatusBar('$(error) DeVAIC: Error');
        }
    });
    
    // Analyze workspace
    const analyzeWorkspaceCommand = vscode.commands.registerCommand('devaic.analyzeWorkspace', async () => {
        const workspaceFolders = vscode.workspace.workspaceFolders;
        if (!workspaceFolders) {
            vscode.window.showWarningMessage('No workspace folder found');
            return;
        }
        
        updateStatusBar('$(loading~spin) DeVAIC: Analyzing workspace...');
        
        // Show progress
        vscode.window.withProgress({
            location: vscode.ProgressLocation.Notification,
            title: 'DeVAIC Security Analysis',
            cancellable: true
        }, async (progress, token) => {
            progress.report({ increment: 0, message: 'Scanning files...' });
            
            try {
                // Get all supported files in workspace
                const files = await vscode.workspace.findFiles(
                    '**/*.{rs,go,js,ts,py,java,kt,swift,c,cpp,cs,php,rb,dart}',
                    '**/node_modules/**'
                );
                
                progress.report({ increment: 25, message: `Found ${files.length} files to analyze` });
                
                let analyzed = 0;
                for (const file of files) {
                    if (token.isCancellationRequested) {
                        break;
                    }
                    
                    await vscode.commands.executeCommand('vscode.executeDocumentDiagnostics', file);
                    analyzed++;
                    
                    const percentage = Math.floor((analyzed / files.length) * 75);
                    progress.report({ 
                        increment: percentage / files.length, 
                        message: `Analyzed ${analyzed}/${files.length} files` 
                    });
                }
                
                progress.report({ increment: 100, message: 'Analysis complete!' });
                
                // Show results
                const allDiagnostics = files.flatMap(file => 
                    vscode.languages.getDiagnostics(file).filter(d => d.source === 'DeVAIC Enhanced')
                );
                
                const message = `Workspace analysis complete! Found ${allDiagnostics.length} security issues.`;
                vscode.window.showInformationMessage(message, 'Show Problems').then(selection => {
                    if (selection === 'Show Problems') {
                        vscode.commands.executeCommand('workbench.panel.markers.view.focus');
                    }
                });
                
                updateStatusBar('$(shield) DeVAIC: Active');
            } catch (error) {
                console.error('Workspace analysis failed:', error);
                vscode.window.showErrorMessage('Workspace analysis failed. Check the output panel for details.');
                updateStatusBar('$(error) DeVAIC: Error');
            }
        });
    });
    
    // Toggle real-time analysis
    const toggleRealTimeCommand = vscode.commands.registerCommand('devaic.toggleRealTimeAnalysis', async () => {
        const config = vscode.workspace.getConfiguration('devaic');
        const currentValue = config.get<boolean>('enableRealTimeAnalysis', true);
        
        await config.update('enableRealTimeAnalysis', !currentValue, vscode.ConfigurationTarget.Global);
        
        const status = !currentValue ? 'enabled' : 'disabled';
        vscode.window.showInformationMessage(`Real-time analysis ${status}`);
        
        updateStatusBar(!currentValue ? '$(shield) DeVAIC: Active (Real-time)' : '$(shield) DeVAIC: Active');
    });
    
    // Show security report
    const showReportCommand = vscode.commands.registerCommand('devaic.showSecurityReport', async () => {
        const panel = vscode.window.createWebviewPanel(
            'devaicReport',
            'DeVAIC Security Report',
            vscode.ViewColumn.Two,
            { enableScripts: true }
        );
        
        panel.webview.html = generateSecurityReportHTML();
    });
    
    // Show impact analysis
    const showImpactAnalysisCommand = vscode.commands.registerCommand('devaic.showImpactAnalysis', async (impactAnalysis) => {
        const panel = vscode.window.createWebviewPanel(
            'devaicImpact',
            'Security Impact Analysis',
            vscode.ViewColumn.Two,
            { enableScripts: true }
        );
        
        panel.webview.html = generateImpactAnalysisHTML(impactAnalysis);
    });
    
    context.subscriptions.push(
        analyzeFileCommand,
        analyzeWorkspaceCommand,
        toggleRealTimeCommand,
        showReportCommand,
        showImpactAnalysisCommand
    );
}

let statusBarItem: vscode.StatusBarItem;

function setupStatusBar(context: vscode.ExtensionContext) {
    statusBarItem = vscode.window.createStatusBarItem(vscode.StatusBarAlignment.Left, 100);
    statusBarItem.command = 'devaic.analyzeFile';
    statusBarItem.tooltip = 'Click to analyze current file with DeVAIC';
    statusBarItem.text = '$(shield) DeVAIC: Initializing...';
    statusBarItem.show();
    
    context.subscriptions.push(statusBarItem);
}

function updateStatusBar(text: string) {
    if (statusBarItem) {
        statusBarItem.text = text;
    }
}

function setupConfigurationListener(context: vscode.ExtensionContext) {
    const configListener = vscode.workspace.onDidChangeConfiguration(event => {
        if (event.affectsConfiguration('devaic')) {
            // Restart language server if necessary
            if (client) {
                client.stop().then(() => {
                    initializeLanguageServer(context);
                });
            }
        }
    });
    
    context.subscriptions.push(configListener);
}

function generateSecurityReportHTML(): string {
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

function generateImpactAnalysisHTML(impactAnalysis: any): string {
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

export function deactivate(): Thenable<void> | undefined {
    if (!client) {
        return undefined;
    }
    return client.stop();
}