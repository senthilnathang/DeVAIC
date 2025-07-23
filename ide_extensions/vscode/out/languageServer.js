"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
exports.DeVAICLanguageServer = void 0;
const vscode = require("vscode");
const cp = require("child_process");
const node_1 = require("vscode-languageclient/node");
class DeVAICLanguageServer {
    constructor(context) {
        this.context = context;
        this.realTimeAnalysisEnabled = true;
        this.outputChannel = vscode.window.createOutputChannel('DeVAIC Language Server');
        this.diagnosticCollection = vscode.languages.createDiagnosticCollection('devaic');
        this.statusBarItem = vscode.window.createStatusBarItem(vscode.StatusBarAlignment.Left, 100);
        this.setupStatusBar();
        this.loadConfiguration();
    }
    setupStatusBar() {
        this.statusBarItem.command = 'devaic.analyzeFile';
        this.statusBarItem.tooltip = 'Click to analyze current file with DeVAIC';
        this.statusBarItem.text = '$(shield) DeVAIC: Initializing...';
        this.statusBarItem.show();
        this.context.subscriptions.push(this.statusBarItem);
    }
    loadConfiguration() {
        const config = vscode.workspace.getConfiguration('devaic');
        this.realTimeAnalysisEnabled = config.get('enableRealTimeAnalysis', true);
    }
    async start() {
        try {
            this.updateStatus('$(loading~spin) DeVAIC: Starting...', 'Starting language server...');
            // Create the language server
            const serverOptions = await this.createServerOptions();
            const clientOptions = this.createClientOptions();
            this.client = new node_1.LanguageClient('devaic', 'DeVAIC Security Analyzer', serverOptions, clientOptions);
            // Register event handlers
            this.registerEventHandlers();
            // Start the client
            await this.client.start();
            this.updateStatus('$(shield) DeVAIC: Active', 'Language server started successfully');
            this.outputChannel.appendLine('DeVAIC Language Server started successfully');
        }
        catch (error) {
            this.handleStartupError(error);
        }
    }
    async createServerOptions() {
        const config = vscode.workspace.getConfiguration('devaic');
        let serverPath = config.get('languageServerPath');
        if (!serverPath) {
            // Try to find the DeVAIC binary
            serverPath = await this.findDeVAICBinary();
        }
        if (!serverPath) {
            throw new Error('DeVAIC binary not found. Please install DeVAIC or set the languageServerPath configuration.');
        }
        this.outputChannel.appendLine(`Using DeVAIC binary: ${serverPath}`);
        return {
            run: {
                command: serverPath,
                args: ['--lsp'],
                options: {
                    cwd: vscode.workspace.workspaceFolders?.[0]?.uri.fsPath
                }
            },
            debug: {
                command: serverPath,
                args: ['--lsp', '--verbose'],
                options: {
                    cwd: vscode.workspace.workspaceFolders?.[0]?.uri.fsPath
                }
            }
        };
    }
    createClientOptions() {
        const config = vscode.workspace.getConfiguration('devaic');
        const excludePatterns = config.get('excludePatterns', []);
        return {
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
                fileEvents: vscode.workspace.createFileSystemWatcher('**/*.{rs,go,js,ts,py,java,kt,swift,c,cpp,cs,php,rb,dart}'),
                configurationSection: 'devaic'
            },
            outputChannel: this.outputChannel,
            revealOutputChannelOn: node_1.RevealOutputChannelOn.Error,
            errorHandler: {
                error: (error, message, count) => {
                    this.outputChannel.appendLine(`Language server error: ${error.message}`);
                    return { action: node_1.ErrorAction.Continue };
                },
                closed: () => {
                    this.outputChannel.appendLine('Language server connection closed');
                    return { action: node_1.CloseAction.Restart };
                }
            },
            initializationOptions: {
                enableRealTimeAnalysis: this.realTimeAnalysisEnabled,
                severityThreshold: config.get('severityThreshold', 'Medium'),
                enableMLAnalysis: config.get('enableMLAnalysis', true),
                debounceDelay: config.get('debounceDelay', 500),
                maxAnalysisTime: config.get('maxAnalysisTime', 10000),
                excludePatterns: excludePatterns
            }
        };
    }
    registerEventHandlers() {
        if (!this.client)
            return;
        // Handle client state changes
        this.client.onDidChangeState((event) => {
            this.outputChannel.appendLine(`Language server state changed: ${node_1.State[event.oldState]} -> ${node_1.State[event.newState]}`);
            switch (event.newState) {
                case node_1.State.Running:
                    this.updateStatus('$(shield) DeVAIC: Active', 'Language server is running');
                    break;
                case node_1.State.Starting:
                    this.updateStatus('$(loading~spin) DeVAIC: Starting...', 'Language server is starting');
                    break;
                case node_1.State.Stopped:
                    this.updateStatus('$(error) DeVAIC: Stopped', 'Language server stopped');
                    break;
            }
        });
        // Setup real-time analysis
        this.setupRealTimeAnalysis();
        // Handle configuration changes
        vscode.workspace.onDidChangeConfiguration(event => {
            if (event.affectsConfiguration('devaic')) {
                this.loadConfiguration();
                this.client?.sendNotification('workspace/didChangeConfiguration', {
                    settings: vscode.workspace.getConfiguration('devaic')
                });
            }
        });
    }
    setupRealTimeAnalysis() {
        // Document change handler for real-time analysis
        vscode.workspace.onDidChangeTextDocument(event => {
            if (!this.realTimeAnalysisEnabled)
                return;
            const config = vscode.workspace.getConfiguration('devaic');
            const debounceDelay = config.get('debounceDelay', 500);
            // Clear existing timer
            if (this.analysisDebounceTimer) {
                clearTimeout(this.analysisDebounceTimer);
            }
            // Set new timer for debounced analysis
            this.analysisDebounceTimer = setTimeout(() => {
                this.analyzeDocument(event.document);
            }, debounceDelay);
        });
        // Document open handler
        vscode.workspace.onDidOpenTextDocument(document => {
            if (this.realTimeAnalysisEnabled) {
                this.analyzeDocument(document);
            }
        });
        // Document save handler
        vscode.workspace.onDidSaveTextDocument(document => {
            this.analyzeDocument(document);
        });
    }
    async analyzeDocument(document) {
        if (!this.client || this.client.state !== node_1.State.Running) {
            return;
        }
        // Check if document should be analyzed
        if (!this.shouldAnalyzeDocument(document)) {
            return;
        }
        try {
            this.updateStatus('$(loading~spin) DeVAIC: Analyzing...', 'Analyzing document...');
            // Send analysis request to language server
            const params = {
                textDocument: {
                    uri: document.uri.toString(),
                    version: document.version
                }
            };
            const diagnostics = await this.client.sendRequest('textDocument/analyze', params);
            // Convert to VS Code diagnostics
            const vscDiagnostics = this.convertDiagnostics(Array.isArray(diagnostics) ? diagnostics : []);
            this.diagnosticCollection.set(document.uri, vscDiagnostics);
            this.updateStatus('$(shield) DeVAIC: Active', `Found ${vscDiagnostics.length} issues`);
        }
        catch (error) {
            this.outputChannel.appendLine(`Analysis failed: ${error}`);
            this.updateStatus('$(error) DeVAIC: Error', 'Analysis failed');
        }
    }
    shouldAnalyzeDocument(document) {
        // Check if document language is supported
        const supportedLanguages = [
            'rust', 'go', 'javascript', 'typescript', 'python', 'java',
            'kotlin', 'swift', 'c', 'cpp', 'csharp', 'php', 'ruby', 'dart'
        ];
        if (!supportedLanguages.includes(document.languageId)) {
            return false;
        }
        // Check exclude patterns
        const config = vscode.workspace.getConfiguration('devaic');
        const excludePatterns = config.get('excludePatterns', []);
        for (const pattern of excludePatterns) {
            if (document.uri.fsPath.includes(pattern.replace('**/', '').replace('/**', ''))) {
                return false;
            }
        }
        return true;
    }
    convertDiagnostics(serverDiagnostics) {
        return serverDiagnostics.map(diag => {
            const diagnostic = new vscode.Diagnostic(new vscode.Range(new vscode.Position(diag.range.start.line, diag.range.start.character), new vscode.Position(diag.range.end.line, diag.range.end.character)), diag.message, this.convertSeverity(diag.severity));
            diagnostic.source = 'DeVAIC Enhanced';
            diagnostic.code = diag.code;
            if (diag.relatedInformation) {
                diagnostic.relatedInformation = diag.relatedInformation.map((info) => ({
                    location: new vscode.Location(vscode.Uri.parse(info.location.uri), new vscode.Range(new vscode.Position(info.location.range.start.line, info.location.range.start.character), new vscode.Position(info.location.range.end.line, info.location.range.end.character))),
                    message: info.message
                }));
            }
            return diagnostic;
        });
    }
    convertSeverity(severity) {
        switch (severity.toLowerCase()) {
            case 'critical':
            case 'error':
                return vscode.DiagnosticSeverity.Error;
            case 'high':
            case 'warning':
                return vscode.DiagnosticSeverity.Warning;
            case 'medium':
            case 'info':
                return vscode.DiagnosticSeverity.Information;
            case 'low':
            case 'hint':
                return vscode.DiagnosticSeverity.Hint;
            default:
                return vscode.DiagnosticSeverity.Warning;
        }
    }
    async findDeVAICBinary() {
        const possiblePaths = [
            // Common installation paths
            'devaic',
            '/usr/local/bin/devaic',
            '/usr/bin/devaic',
            // Cargo installation
            `${process.env.HOME}/.cargo/bin/devaic`,
            // Development paths
            './target/release/devaic',
            '../target/release/devaic',
            // Platform-specific paths
            process.platform === 'win32' ? 'devaic.exe' : 'devaic'
        ];
        for (const binPath of possiblePaths) {
            try {
                await this.checkBinaryExists(binPath);
                return binPath;
            }
            catch {
                // Continue to next path
            }
        }
        return undefined;
    }
    checkBinaryExists(path) {
        return new Promise((resolve, reject) => {
            cp.exec(`"${path}" --version`, (error, stdout, stderr) => {
                if (error) {
                    reject(error);
                }
                else if (stdout.includes('devaic') || stdout.includes('DeVAIC')) {
                    resolve();
                }
                else {
                    reject(new Error('Not a DeVAIC binary'));
                }
            });
        });
    }
    handleStartupError(error) {
        this.updateStatus('$(error) DeVAIC: Error', 'Failed to start language server');
        this.outputChannel.appendLine(`Failed to start language server: ${error.message}`);
        const message = 'Failed to start DeVAIC Language Server. Please check that DeVAIC is installed and accessible.';
        vscode.window.showErrorMessage(message, 'Show Output', 'Install DeVAIC').then(selection => {
            switch (selection) {
                case 'Show Output':
                    this.outputChannel.show();
                    break;
                case 'Install DeVAIC':
                    vscode.env.openExternal(vscode.Uri.parse('https://github.com/dessertlab/DeVAIC'));
                    break;
            }
        });
    }
    updateStatus(text, tooltip) {
        this.statusBarItem.text = text;
        if (tooltip) {
            this.statusBarItem.tooltip = tooltip;
        }
    }
    async analyzeCurrentFile() {
        const editor = vscode.window.activeTextEditor;
        if (!editor) {
            vscode.window.showWarningMessage('No active editor found');
            return;
        }
        await this.analyzeDocument(editor.document);
        const diagnostics = this.diagnosticCollection.get(editor.document.uri) || [];
        const securityIssues = diagnostics.filter(d => d.source === 'DeVAIC Enhanced');
        if (securityIssues.length > 0) {
            const message = `Found ${securityIssues.length} security issue(s)`;
            vscode.window.showInformationMessage(message, 'Show Problems').then(selection => {
                if (selection === 'Show Problems') {
                    vscode.commands.executeCommand('workbench.panel.markers.view.focus');
                }
            });
        }
        else {
            vscode.window.showInformationMessage('No security issues found! 🎉');
        }
    }
    async analyzeWorkspace() {
        const workspaceFolders = vscode.workspace.workspaceFolders;
        if (!workspaceFolders) {
            vscode.window.showWarningMessage('No workspace folder found');
            return;
        }
        this.updateStatus('$(loading~spin) DeVAIC: Analyzing workspace...', 'Analyzing workspace...');
        await vscode.window.withProgress({
            location: vscode.ProgressLocation.Notification,
            title: 'DeVAIC Security Analysis',
            cancellable: true
        }, async (progress, token) => {
            progress.report({ increment: 0, message: 'Scanning files...' });
            try {
                const files = await vscode.workspace.findFiles('**/*.{rs,go,js,ts,py,java,kt,swift,c,cpp,cs,php,rb,dart}', '{**/node_modules/**,**/target/**,**/build/**}');
                progress.report({ increment: 25, message: `Found ${files.length} files to analyze` });
                let analyzed = 0;
                const totalIssues = [];
                for (const fileUri of files) {
                    if (token.isCancellationRequested) {
                        break;
                    }
                    try {
                        const document = await vscode.workspace.openTextDocument(fileUri);
                        await this.analyzeDocument(document);
                        const diagnostics = this.diagnosticCollection.get(fileUri) || [];
                        totalIssues.push(...diagnostics);
                    }
                    catch (error) {
                        this.outputChannel.appendLine(`Failed to analyze ${fileUri.fsPath}: ${error}`);
                    }
                    analyzed++;
                    const percentage = Math.floor((analyzed / files.length) * 75);
                    progress.report({
                        increment: percentage / files.length,
                        message: `Analyzed ${analyzed}/${files.length} files`
                    });
                }
                progress.report({ increment: 100, message: 'Analysis complete!' });
                const message = `Workspace analysis complete! Found ${totalIssues.length} security issues.`;
                vscode.window.showInformationMessage(message, 'Show Problems').then(selection => {
                    if (selection === 'Show Problems') {
                        vscode.commands.executeCommand('workbench.panel.markers.view.focus');
                    }
                });
                this.updateStatus('$(shield) DeVAIC: Active', `Workspace analysis complete: ${totalIssues.length} issues`);
            }
            catch (error) {
                this.outputChannel.appendLine(`Workspace analysis failed: ${error}`);
                vscode.window.showErrorMessage('Workspace analysis failed. Check the output panel for details.');
                this.updateStatus('$(error) DeVAIC: Error', 'Workspace analysis failed');
            }
        });
    }
    toggleRealTimeAnalysis() {
        this.realTimeAnalysisEnabled = !this.realTimeAnalysisEnabled;
        const config = vscode.workspace.getConfiguration('devaic');
        config.update('enableRealTimeAnalysis', this.realTimeAnalysisEnabled, vscode.ConfigurationTarget.Global);
        const status = this.realTimeAnalysisEnabled ? 'enabled' : 'disabled';
        vscode.window.showInformationMessage(`Real-time analysis ${status}`);
        this.updateStatus(this.realTimeAnalysisEnabled ? '$(shield) DeVAIC: Active (Real-time)' : '$(shield) DeVAIC: Active', `Real-time analysis ${status}`);
    }
    async stop() {
        if (this.analysisDebounceTimer) {
            clearTimeout(this.analysisDebounceTimer);
        }
        this.diagnosticCollection.clear();
        this.diagnosticCollection.dispose();
        if (this.client) {
            await this.client.stop();
            this.client = undefined;
        }
        this.updateStatus('$(shield) DeVAIC: Stopped', 'Language server stopped');
    }
    isRunning() {
        return this.client?.state === node_1.State.Running;
    }
    getClient() {
        return this.client;
    }
}
exports.DeVAICLanguageServer = DeVAICLanguageServer;
//# sourceMappingURL=languageServer.js.map