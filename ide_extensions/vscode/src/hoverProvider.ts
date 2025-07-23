import * as vscode from 'vscode';

export class HoverProvider implements vscode.HoverProvider {
    async provideHover(
        document: vscode.TextDocument,
        position: vscode.Position,
        token: vscode.CancellationToken
    ): Promise<vscode.Hover | null> {
        // Get diagnostics for the current position
        const diagnostics = vscode.languages.getDiagnostics(document.uri);
        const devaicDiagnostics = diagnostics.filter(diagnostic => 
            diagnostic.source === 'DeVAIC Enhanced' &&
            diagnostic.range.contains(position)
        );

        if (devaicDiagnostics.length === 0) {
            return null;
        }

        const diagnostic = devaicDiagnostics[0];
        const hoverContent = await this.createHoverContent(diagnostic, document, position);

        return new vscode.Hover(hoverContent, diagnostic.range);
    }

    private async createHoverContent(
        diagnostic: vscode.Diagnostic,
        document: vscode.TextDocument,
        position: vscode.Position
    ): Promise<vscode.MarkdownString[]> {
        const content: vscode.MarkdownString[] = [];
        
        // Main vulnerability description
        const mainContent = new vscode.MarkdownString();
        mainContent.isTrusted = true;
        mainContent.supportHtml = true;

        // Header with severity
        const severityIcon = this.getSeverityIcon(diagnostic.severity);
        const severityText = this.getSeverityText(diagnostic.severity);
        
        mainContent.appendMarkdown(`### ${severityIcon} ${severityText} Security Issue\n\n`);
        mainContent.appendMarkdown(`**${diagnostic.message}**\n\n`);

        // Add vulnerability details
        const diagnosticCode = diagnostic.code?.toString() || '';
        const vulnerabilityDetails = this.getVulnerabilityDetails(diagnosticCode, diagnostic.message);
        
        if (vulnerabilityDetails) {
            mainContent.appendMarkdown(`**Description:** ${vulnerabilityDetails.description}\n\n`);
            mainContent.appendMarkdown(`**Impact:** ${vulnerabilityDetails.impact}\n\n`);
            mainContent.appendMarkdown(`**CWE:** [${vulnerabilityDetails.cwe}](https://cwe.mitre.org/data/definitions/${vulnerabilityDetails.cwe.split('-')[1]}.html)\n\n`);
        }

        // Add code context
        const codeContext = this.getCodeContext(document, position);
        if (codeContext) {
            mainContent.appendMarkdown(`**Vulnerable Code:**\n\`\`\`${document.languageId}\n${codeContext}\n\`\`\`\n\n`);
        }

        // Add recommendations
        const recommendations = this.getRecommendations(diagnosticCode, document.languageId);
        if (recommendations.length > 0) {
            mainContent.appendMarkdown(`**Recommendations:**\n`);
            recommendations.forEach(rec => {
                mainContent.appendMarkdown(`• ${rec}\n`);
            });
            mainContent.appendMarkdown(`\n`);
        }

        // Add example fix
        const exampleFix = this.getExampleFix(diagnosticCode, document.languageId);
        if (exampleFix) {
            mainContent.appendMarkdown(`**Example Fix:**\n\`\`\`${document.languageId}\n${exampleFix}\n\`\`\`\n\n`);
        }

        // Add links
        mainContent.appendMarkdown(`---\n`);
        mainContent.appendMarkdown(`[Quick Fix](command:vscode.executeCodeActionProvider?${encodeURIComponent(JSON.stringify([document.uri, diagnostic.range]))}) | `);
        mainContent.appendMarkdown(`[Show Documentation](https://docs.devaic.io/vulnerabilities) | `);
        mainContent.appendMarkdown(`[Report False Positive](command:devaic.reportFalsePositive?${encodeURIComponent(JSON.stringify([diagnostic]))})`);

        content.push(mainContent);

        // Add related information if available
        if (diagnostic.relatedInformation && diagnostic.relatedInformation.length > 0) {
            const relatedContent = new vscode.MarkdownString();
            relatedContent.appendMarkdown(`### Related Information\n\n`);
            
            diagnostic.relatedInformation.forEach(info => {
                const relativeUri = vscode.workspace.asRelativePath(info.location.uri);
                const line = info.location.range.start.line + 1;
                relatedContent.appendMarkdown(`• [${relativeUri}:${line}](${info.location.uri}#L${line}): ${info.message}\n`);
            });
            
            content.push(relatedContent);
        }

        return content;
    }

    private getSeverityIcon(severity: vscode.DiagnosticSeverity): string {
        switch (severity) {
            case vscode.DiagnosticSeverity.Error:
                return '🚨';
            case vscode.DiagnosticSeverity.Warning:
                return '⚠️';
            case vscode.DiagnosticSeverity.Information:
                return 'ℹ️';
            case vscode.DiagnosticSeverity.Hint:
                return '💡';
            default:
                return '⚠️';
        }
    }

    private getSeverityText(severity: vscode.DiagnosticSeverity): string {
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
                return 'Unknown';
        }
    }

    private getVulnerabilityDetails(code: string, message: string): {
        description: string;
        impact: string;
        cwe: string;
    } | null {
        const lowerMessage = message.toLowerCase();
        
        if (code.includes('SQL_INJECTION') || lowerMessage.includes('sql injection')) {
            return {
                description: 'SQL injection vulnerabilities occur when user input is directly concatenated into SQL queries without proper sanitization.',
                impact: 'Attackers can execute arbitrary SQL commands, potentially accessing, modifying, or deleting sensitive data.',
                cwe: 'CWE-89'
            };
        }
        
        if (code.includes('XSS') || lowerMessage.includes('cross-site scripting')) {
            return {
                description: 'Cross-site scripting occurs when user input is rendered in web pages without proper encoding.',
                impact: 'Attackers can execute malicious scripts in users\' browsers, steal cookies, or perform actions on behalf of users.',
                cwe: 'CWE-79'
            };
        }
        
        if (code.includes('COMMAND_INJECTION') || lowerMessage.includes('command injection')) {
            return {
                description: 'Command injection occurs when user input is passed directly to system commands without validation.',
                impact: 'Attackers can execute arbitrary system commands, potentially gaining full control of the server.',
                cwe: 'CWE-78'
            };
        }
        
        if (code.includes('HARDCODED_SECRET') || lowerMessage.includes('hardcoded')) {
            return {
                description: 'Hardcoded secrets in source code can be easily discovered by anyone with access to the code.',
                impact: 'Secrets can be compromised, leading to unauthorized access to systems and data.',
                cwe: 'CWE-798'
            };
        }
        
        if (code.includes('BUFFER_OVERFLOW') || lowerMessage.includes('buffer overflow')) {
            return {
                description: 'Buffer overflows occur when data written to a buffer exceeds its allocated size.',
                impact: 'Can lead to crashes, data corruption, or arbitrary code execution.',
                cwe: 'CWE-120'
            };
        }
        
        if (code.includes('WEAK_RANDOM') || lowerMessage.includes('weak random')) {
            return {
                description: 'Using weak random number generators for security-sensitive operations.',
                impact: 'Predictable random values can be exploited by attackers to break cryptographic operations.',
                cwe: 'CWE-338'
            };
        }

        return null;
    }

    private getCodeContext(document: vscode.TextDocument, position: vscode.Position): string | null {
        const line = document.lineAt(position.line);
        const startLine = Math.max(0, position.line - 1);
        const endLine = Math.min(document.lineCount - 1, position.line + 1);
        
        const contextLines: string[] = [];
        for (let i = startLine; i <= endLine; i++) {
            const lineText = document.lineAt(i).text;
            const marker = i === position.line ? '→ ' : '  ';
            contextLines.push(`${marker}${lineText}`);
        }
        
        return contextLines.join('\n');
    }

    private getRecommendations(code: string, languageId: string): string[] {
        const recommendations: string[] = [];
        const lowerCode = code.toLowerCase();
        
        if (lowerCode.includes('sql_injection')) {
            recommendations.push('Use parameterized queries or prepared statements');
            recommendations.push('Implement input validation and sanitization');
            recommendations.push('Use an ORM with built-in SQL injection protection');
            recommendations.push('Apply the principle of least privilege to database accounts');
        }
        
        if (lowerCode.includes('xss')) {
            recommendations.push('Always encode user input before displaying in HTML');
            recommendations.push('Use Content Security Policy (CSP) headers');
            recommendations.push('Prefer textContent over innerHTML when possible');
            recommendations.push('Implement proper input validation on the server side');
        }
        
        if (lowerCode.includes('command_injection')) {
            recommendations.push('Use parameterized command execution');
            recommendations.push('Implement strict input validation');
            recommendations.push('Use allow-lists for acceptable input values');
            recommendations.push('Run commands with minimal privileges');
        }
        
        if (lowerCode.includes('hardcoded_secret')) {
            recommendations.push('Move secrets to environment variables');
            recommendations.push('Use a secure key management system');
            recommendations.push('Implement proper secret rotation');
            recommendations.push('Never commit secrets to version control');
        }
        
        if (lowerCode.includes('buffer_overflow')) {
            recommendations.push('Use safe string functions (strncpy, snprintf)');
            recommendations.push('Enable compiler security features (stack protectors)');
            recommendations.push('Implement bounds checking');
            recommendations.push('Consider using memory-safe languages');
        }
        
        if (lowerCode.includes('weak_random')) {
            recommendations.push('Use cryptographically secure random number generators');
            if (languageId === 'python') {
                recommendations.push('Use the secrets module instead of random');
            } else if (languageId === 'javascript' || languageId === 'typescript') {
                recommendations.push('Use crypto.getRandomValues() instead of Math.random()');
            } else if (languageId === 'java') {
                recommendations.push('Use SecureRandom instead of Random');
            }
        }
        
        return recommendations;
    }

    private getExampleFix(code: string, languageId: string): string | null {
        const lowerCode = code.toLowerCase();
        
        if (lowerCode.includes('sql_injection')) {
            switch (languageId) {
                case 'python':
                    return 'cursor.execute("SELECT * FROM users WHERE id = %s", (user_id,))';
                case 'java':
                    return 'PreparedStatement pstmt = conn.prepareStatement("SELECT * FROM users WHERE id = ?");\npstmt.setInt(1, userId);';
                case 'javascript':
                    return 'const query = "SELECT * FROM users WHERE id = ?";\ndb.query(query, [userId]);';
                default:
                    return null;
            }
        }
        
        if (lowerCode.includes('xss')) {
            switch (languageId) {
                case 'javascript':
                    return 'element.textContent = userInput; // Safe\n// Instead of: element.innerHTML = userInput;';
                case 'python':
                    return 'from markupsafe import escape\noutput = escape(user_input)';
                default:
                    return null;
            }
        }
        
        if (lowerCode.includes('hardcoded_secret')) {
            switch (languageId) {
                case 'python':
                    return 'import os\napi_key = os.environ.get("API_KEY")';
                case 'javascript':
                    return 'const apiKey = process.env.API_KEY;';
                case 'java':
                    return 'String apiKey = System.getenv("API_KEY");';
                default:
                    return null;
            }
        }
        
        return null;
    }
}