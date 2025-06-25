// Security Risk Detection Test File
// This file contains various security risks for testing Bearer-inspired features

const crypto = require('crypto');
const fs = require('fs');

// Cryptographic Failures
const md5Hash = crypto.createHash('md5');  // Weak hash algorithm
const desEncryption = crypto.createCipher('des', 'weak-key');  // Weak encryption

// Hardcoded Secrets
const apiKey = "AIzaSyB1234567890abcdefghijklmnop";  // Hardcoded API key
const secret = "super-secret-key-123456789";  // Hardcoded secret
const awsKey = "AKIA1234567890ABCDEF";  // AWS access key

// Access Control Issues
function setPermissions() {
    fs.chmod('sensitive-file.txt', 0o777, (err) => {  // Overly permissive
        if (err) console.error(err);
    });
}

// CORS Misconfiguration
const corsOptions = {
    origin: "*",  // CORS wildcard - security risk
    credentials: true
};

// XSS Vulnerabilities
function displayUserInput(userInput) {
    document.getElementById('content').innerHTML = userInput;  // XSS vulnerability
    document.write('<div>' + userInput + '</div>');  // XSS via document.write
}

// Prototype Pollution
function merge(target, source) {
    for (let key in source) {
        if (key === '__proto__') {  // Prototype pollution vulnerability
            target[key] = source[key];
        }
    }
}

// Code Injection
function executeUserCode(userInput) {
    eval(userInput);  // Code injection via eval
    Function(userInput)();  // Code injection via Function constructor
    setTimeout(userInput, 1000);  // Code injection via setTimeout
}

// Client-side Authentication (Insecure)
function checkAuth() {
    const userRole = localStorage.getItem('role');  // Client-side auth bypass
    if (userRole === 'admin') {
        showAdminPanel();
    }
}

// Insecure Random Number Generation
function generateToken() {
    return Math.random().toString(36).substr(2, 9);  // Weak randomness for token
}

// SQL Injection Risk (in template strings)
function getUserData(userId) {
    const query = `SELECT * FROM users WHERE id = ${userId}`;  // SQL injection risk
    return database.query(query);
}

// Command Injection Risk
const { exec } = require('child_process');
function processFile(filename) {
    exec(`cat ${filename}`, (error, stdout, stderr) => {  // Command injection
        console.log(stdout);
    });
}

// Insecure HTTP Methods
app.trace('/debug', (req, res) => {  // Insecure HTTP method
    res.send('Debug information');
});

// Debug Mode in Production
const config = {
    debug: true,  // Debug mode enabled
    development: true
};

// SSL/TLS Verification Disabled
const https = require('https');
const agent = new https.Agent({
    rejectUnauthorized: false  // SSL verification disabled
});

// Default Credentials
const credentials = {
    username: 'admin',
    password: 'admin'  // Default credentials
};

// Session Without Timeout
const session = {
    timeout: -1,  // No session timeout
    maxAge: null
};

// Logging Sensitive Operations
function loginAttempt(username, password) {
    if (authenticate(username, password)) {
        console.log('Login successful');
    } else {
        // Missing security logging for failed attempts
        console.log('Login failed');
    }
}

// Path Traversal
function readFile(path) {
    return fs.readFileSync('../../../etc/passwd');  // Path traversal
}

module.exports = {
    setPermissions,
    displayUserInput,
    executeUserCode,
    checkAuth,
    generateToken,
    processFile
};