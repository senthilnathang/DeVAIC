import * as vscode from 'vscode';

export class DiagnosticProvider implements vscode.Disposable {
    private diagnosticCollection: vscode.DiagnosticCollection;
    private disposables: vscode.Disposable[] = [];

    constructor() {
        this.diagnosticCollection = vscode.languages.createDiagnosticCollection('devaic');
        this.registerEventHandlers();
    }

    private registerEventHandlers() {
        // Clear diagnostics when documents are closed
        this.disposables.push(
            vscode.workspace.onDidCloseTextDocument(document => {
                this.diagnosticCollection.delete(document.uri);
            })
        );

        // Clear diagnostics when files are deleted
        this.disposables.push(
            vscode.workspace.onDidDeleteFiles(event => {
                event.files.forEach(fileUri => {
                    this.diagnosticCollection.delete(fileUri);
                });
            })
        );

        // Update diagnostics when configuration changes
        this.disposables.push(
            vscode.workspace.onDidChangeConfiguration(event => {
                if (event.affectsConfiguration('devaic.severityThreshold')) {
                    this.refreshAllDiagnostics();
                }
            })
        );
    }

    public setDiagnostics(uri: vscode.Uri, diagnostics: vscode.Diagnostic[]): void {
        // Filter diagnostics based on severity threshold
        const filteredDiagnostics = this.filterDiagnosticsBySeverity(diagnostics);
        this.diagnosticCollection.set(uri, filteredDiagnostics);
    }

    public addDiagnostic(uri: vscode.Uri, diagnostic: vscode.Diagnostic): void {
        const existingDiagnostics = [...(this.diagnosticCollection.get(uri) || [])];
        
        // Check if this diagnostic already exists
        const isDuplicate = existingDiagnostics.some(existing => 
            existing.range.isEqual(diagnostic.range) &&
            existing.message === diagnostic.message &&
            existing.code === diagnostic.code
        );

        if (!isDuplicate && this.shouldIncludeDiagnostic(diagnostic)) {
            existingDiagnostics.push(diagnostic);
            this.diagnosticCollection.set(uri, existingDiagnostics);
        }
    }

    public removeDiagnostic(uri: vscode.Uri, range: vscode.Range): void {
        const existingDiagnostics = [...(this.diagnosticCollection.get(uri) || [])];
        const filteredDiagnostics = existingDiagnostics.filter(diagnostic => 
            !diagnostic.range.intersection(range)
        );
        this.diagnosticCollection.set(uri, filteredDiagnostics);
    }

    public clearDiagnostics(uri?: vscode.Uri): void {
        if (uri) {
            this.diagnosticCollection.delete(uri);
        } else {
            this.diagnosticCollection.clear();
        }
    }

    public getDiagnostics(uri: vscode.Uri): vscode.Diagnostic[] {
        return [...(this.diagnosticCollection.get(uri) || [])];
    }

    public getAllDiagnostics(): [vscode.Uri, vscode.Diagnostic[]][] {
        const allDiagnostics: [vscode.Uri, vscode.Diagnostic[]][] = [];
        this.diagnosticCollection.forEach((uri, diagnostics) => {
            if (diagnostics.length > 0) {
                allDiagnostics.push([uri, [...diagnostics]]);
            }
        });
        return allDiagnostics;
    }

    public getStatistics(): DiagnosticStatistics {
        const stats: DiagnosticStatistics = {
            totalFiles: 0,
            totalIssues: 0,
            criticalIssues: 0,
            highIssues: 0,
            mediumIssues: 0,
            lowIssues: 0,
            byLanguage: new Map(),
            byCategory: new Map()
        };

        this.diagnosticCollection.forEach((uri, diagnostics) => {
            if (diagnostics.length > 0) {
                stats.totalFiles++;
                stats.totalIssues += diagnostics.length;

                // Get language from file extension
                const fileName = uri.fsPath;
                const language = this.getLanguageFromFileName(fileName);
                const languageCount = stats.byLanguage.get(language) || 0;
                stats.byLanguage.set(language, languageCount + diagnostics.length);

                diagnostics.forEach(diagnostic => {
                    // Count by severity
                    switch (diagnostic.severity) {
                        case vscode.DiagnosticSeverity.Error:
                            stats.criticalIssues++;
                            break;
                        case vscode.DiagnosticSeverity.Warning:
                            stats.highIssues++;
                            break;
                        case vscode.DiagnosticSeverity.Information:
                            stats.mediumIssues++;
                            break;
                        case vscode.DiagnosticSeverity.Hint:
                            stats.lowIssues++;
                            break;
                    }

                    // Count by category (extracted from diagnostic code)
                    const category = this.getCategoryFromDiagnostic(diagnostic);
                    const categoryCount = stats.byCategory.get(category) || 0;
                    stats.byCategory.set(category, categoryCount + 1);
                });
            }
        });

        return stats;
    }

    private filterDiagnosticsBySeverity(diagnostics: vscode.Diagnostic[]): vscode.Diagnostic[] {
        const config = vscode.workspace.getConfiguration('devaic');
        const severityThreshold = config.get<string>('severityThreshold', 'Medium');
        
        const minSeverity = this.getSeverityLevel(severityThreshold);
        
        return diagnostics.filter(diagnostic => {
            const diagnosticSeverityLevel = this.getSeverityLevel(this.mapDiagnosticSeverityToString(diagnostic.severity));
            return diagnosticSeverityLevel >= minSeverity;
        });
    }

    private shouldIncludeDiagnostic(diagnostic: vscode.Diagnostic): boolean {
        const config = vscode.workspace.getConfiguration('devaic');
        const severityThreshold = config.get<string>('severityThreshold', 'Medium');
        
        const minSeverity = this.getSeverityLevel(severityThreshold);
        const diagnosticSeverityLevel = this.getSeverityLevel(this.mapDiagnosticSeverityToString(diagnostic.severity));
        
        return diagnosticSeverityLevel >= minSeverity;
    }

    private getSeverityLevel(severity: string): number {
        switch (severity.toLowerCase()) {
            case 'critical':
                return 4;
            case 'high':
                return 3;
            case 'medium':
                return 2;
            case 'low':
                return 1;
            default:
                return 2; // Default to medium
        }
    }

    private mapDiagnosticSeverityToString(severity: vscode.DiagnosticSeverity): string {
        switch (severity) {
            case vscode.DiagnosticSeverity.Error:
                return 'Critical';
            case vscode.DiagnosticSeverity.Warning:
                return 'High';
            case vscode.DiagnosticSeverity.Information:
                return 'Medium';
            case vscode.DiagnosticSeverity.Hint:
                return 'Low';
            default:
                return 'Medium';
        }
    }

    private getLanguageFromFileName(fileName: string): string {
        const extension = fileName.split('.').pop()?.toLowerCase() || '';
        
        const extensionMap: { [key: string]: string } = {
            'js': 'JavaScript',
            'ts': 'TypeScript',
            'py': 'Python',
            'java': 'Java',
            'c': 'C',
            'cpp': 'C++',
            'cs': 'C#',
            'php': 'PHP',
            'rb': 'Ruby',
            'go': 'Go',
            'rs': 'Rust',
            'kt': 'Kotlin',
            'swift': 'Swift',
            'dart': 'Dart'
        };

        return extensionMap[extension] || 'Unknown';
    }

    private getCategoryFromDiagnostic(diagnostic: vscode.Diagnostic): string {
        const code = diagnostic.code?.toString().toLowerCase() || '';
        const message = diagnostic.message.toLowerCase();

        if (code.includes('sql') || message.includes('sql injection')) {
            return 'SQL Injection';
        }
        if (code.includes('xss') || message.includes('cross-site scripting')) {
            return 'XSS';
        }
        if (code.includes('command') || message.includes('command injection')) {
            return 'Command Injection';
        }
        if (code.includes('secret') || message.includes('hardcoded')) {
            return 'Hardcoded Secrets';
        }
        if (code.includes('buffer') || message.includes('buffer overflow')) {
            return 'Buffer Overflow';
        }
        if (code.includes('random') || message.includes('weak random')) {
            return 'Weak Cryptography';
        }
        if (code.includes('auth') || message.includes('authentication')) {
            return 'Authentication';
        }
        if (code.includes('access') || message.includes('authorization')) {
            return 'Authorization';
        }
        if (code.includes('crypto') || message.includes('cryptographic')) {
            return 'Cryptography';
        }
        if (code.includes('input') || message.includes('validation')) {
            return 'Input Validation';
        }

        return 'Other';
    }

    private refreshAllDiagnostics(): void {
        // Get all current diagnostics and refilter them
        const allDiagnostics: [vscode.Uri, vscode.Diagnostic[]][] = [];
        
        this.diagnosticCollection.forEach((uri, diagnostics) => {
            allDiagnostics.push([uri, [...diagnostics]]);
        });

        // Clear and reapply with new filtering
        this.diagnosticCollection.clear();
        
        allDiagnostics.forEach(([uri, diagnostics]) => {
            const filteredDiagnostics = this.filterDiagnosticsBySeverity([...diagnostics]);
            if (filteredDiagnostics.length > 0) {
                this.diagnosticCollection.set(uri, filteredDiagnostics);
            }
        });
    }

    public exportDiagnostics(): ExportedDiagnostics {
        const exported: ExportedDiagnostics = {
            timestamp: new Date().toISOString(),
            statistics: this.getStatistics(),
            diagnostics: []
        };

        this.diagnosticCollection.forEach((uri, diagnostics) => {
            diagnostics.forEach(diagnostic => {
                exported.diagnostics.push({
                    file: vscode.workspace.asRelativePath(uri),
                    line: diagnostic.range.start.line + 1,
                    column: diagnostic.range.start.character + 1,
                    severity: this.mapDiagnosticSeverityToString(diagnostic.severity),
                    code: diagnostic.code?.toString() || '',
                    message: diagnostic.message,
                    category: this.getCategoryFromDiagnostic(diagnostic)
                });
            });
        });

        return exported;
    }

    dispose(): void {
        this.diagnosticCollection.dispose();
        this.disposables.forEach(disposable => disposable.dispose());
        this.disposables = [];
    }
}

export interface DiagnosticStatistics {
    totalFiles: number;
    totalIssues: number;
    criticalIssues: number;
    highIssues: number;
    mediumIssues: number;
    lowIssues: number;
    byLanguage: Map<string, number>;
    byCategory: Map<string, number>;
}

export interface ExportedDiagnostic {
    file: string;
    line: number;
    column: number;
    severity: string;
    code: string;
    message: string;
    category: string;
}

export interface ExportedDiagnostics {
    timestamp: string;
    statistics: DiagnosticStatistics;
    diagnostics: ExportedDiagnostic[];
}