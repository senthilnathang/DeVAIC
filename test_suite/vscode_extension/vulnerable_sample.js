// Sample vulnerable JavaScript file for testing DeVAIC VS Code Extension
// This file contains various security vulnerabilities for demonstration

const express = require('express');
const mysql = require('mysql');
const crypto = require('crypto');
const { exec } = require('child_process');

const app = express();

// 1. Hardcoded secrets (CWE-798)
const API_KEY = 'abc123def456';
const DB_PASSWORD = 'password123';

// 2. SQL Injection vulnerability (CWE-89)
app.get('/user/:id', (req, res) => {
    const userId = req.params.id;
    
    // Vulnerable: String concatenation in SQL query
    const query = `SELECT * FROM users WHERE id = ${userId}`;
    
    connection.query(query, (error, results) => {
        if (error) throw error;
        res.json(results);
    });
});

// 3. Command Injection vulnerability (CWE-78)
app.get('/execute', (req, res) => {
    const command = req.query.cmd;
    
    // Vulnerable: Direct command execution
    exec(`ls ${command}`, (error, stdout, stderr) => {
        if (error) {
            res.status(500).send(error.message);
            return;
        }
        res.send(stdout);
    });
});

// 4. Cross-Site Scripting (XSS) vulnerability (CWE-79)
app.get('/search', (req, res) => {
    const query = req.query.q;
    
    // Vulnerable: Unescaped user input in HTML
    const html = `
        <html>
            <body>
                <h1>Search Results for: ${query}</h1>
                <div id="results"></div>
                <script>
                    document.getElementById('results').innerHTML = '${query}';
                </script>
            </body>
        </html>
    `;
    res.send(html);
});

// 5. Insecure randomness (CWE-338)
function generateToken() {
    // Vulnerable: Using Math.random() for security-sensitive operations
    return Math.random().toString(36).substring(2);
}

// 6. Information disclosure (CWE-200)
app.get('/debug', (req, res) => {
    // Vulnerable: Exposing sensitive information
    res.json({
        environment: process.env,
        nodeVersion: process.version,
        platform: process.platform,
        apiKey: API_KEY,
        dbPassword: DB_PASSWORD
    });
});

// 7. Prototype pollution (CWE-1321)
function merge(target, source) {
    for (let key in source) {
        // Vulnerable: No check for __proto__ or constructor
        if (typeof source[key] === 'object' && source[key] !== null) {
            if (!target[key]) target[key] = {};
            merge(target[key], source[key]);
        } else {
            target[key] = source[key];
        }
    }
    return target;
}

app.post('/merge', (req, res) => {
    const result = {};
    // Vulnerable: Merging untrusted user input
    merge(result, req.body);
    res.json(result);
});

// 8. Weak cryptographic practices (CWE-327)
function hashPassword(password) {
    // Vulnerable: Using MD5 for password hashing
    return crypto.createHash('md5').update(password).digest('hex');
}

// 9. Path traversal vulnerability (CWE-22)
app.get('/file', (req, res) => {
    const filename = req.query.file;
    
    // Vulnerable: No path validation
    const fs = require('fs');
    fs.readFile(filename, 'utf8', (err, data) => {
        if (err) {
            res.status(500).send(err.message);
            return;
        }
        res.send(data);
    });
});

// 10. Insecure direct object reference (CWE-639)
const users = {
    '1': { name: 'Admin', role: 'admin', ssn: '123-45-6789' },
    '2': { name: 'User', role: 'user', ssn: '987-65-4321' }
};

app.get('/profile/:id', (req, res) => {
    const userId = req.params.id;
    
    // Vulnerable: No authorization check
    const user = users[userId];
    if (user) {
        res.json(user); // Exposes sensitive data
    } else {
        res.status(404).send('User not found');
    }
});

// 11. Eval injection (CWE-95)
app.post('/calculate', (req, res) => {
    const expression = req.body.expr;
    
    // Vulnerable: Using eval with user input
    try {
        const result = eval(expression);
        res.json({ result: result });
    } catch (error) {
        res.status(400).json({ error: error.message });
    }
});

// 12. Missing CSRF protection
app.post('/transfer', (req, res) => {
    const { from, to, amount } = req.body;
    
    // Vulnerable: No CSRF token validation
    // This endpoint can be called from any origin
    
    console.log(`Transferring $${amount} from ${from} to ${to}`);
    res.json({ success: true });
});

// 13. Weak JWT implementation
const jwt = require('jsonwebtoken');

function createToken(user) {
    // Vulnerable: Weak secret, no expiration
    return jwt.sign(user, 'secret', { algorithm: 'none' });
}

// 14. Regular expression DoS (ReDoS) (CWE-1333)
function validateEmail(email) {
    // Vulnerable: Catastrophic backtracking
    const regex = /^([a-zA-Z0-9_\.-]+)@([\da-z\.-]+)\.([a-z\.]{2,6})$/;
    return regex.test(email);
}

// 15. Unvalidated redirects (CWE-601)
app.get('/redirect', (req, res) => {
    const url = req.query.url;
    
    // Vulnerable: No URL validation
    res.redirect(url);
});

// Start server
const PORT = process.env.PORT || 3000;
app.listen(PORT, () => {
    console.log(`Server running on port ${PORT}`);
});

module.exports = app;