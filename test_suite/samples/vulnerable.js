// JavaScript Vulnerability Examples for DeVAIC Testing

// JS012 - Hardcoded secrets and credentials
const API_KEY = "sk_live_abcdef123456789012345678";
const JWT_SECRET = "super-secret-jwt-key-dont-share";
const DATABASE_PASSWORD = "admin123password";
const bearer_token = "Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9";
const authorization = "Basic YWRtaW46cGFzc3dvcmQ=";

// JS001, JS002 - XSS Vulnerabilities
function updateUserProfile(userInput) {
    // Direct innerHTML manipulation with user input
    document.getElementById('profile').innerHTML = '<h1>Welcome ' + userInput + '</h1>';
    
    // outerHTML manipulation
    document.querySelector('.greeting').outerHTML = '<div>Hello ' + userInput + '</div>';
    
    // document.write vulnerability
    document.write('<script>alert("' + userInput + '")</script>');
    
    // React dangerouslySetInnerHTML
    const element = React.createElement('div', {
        dangerouslySetInnerHTML: { __html: userInput }
    });
}

// JS003, JS004 - Prototype pollution and unsafe JSON parsing
function processUserData(userData) {
    // Direct prototype pollution
    userData.__proto__.isAdmin = true;
    
    // Constructor prototype manipulation
    userData.constructor.prototype.hasAccess = true;
    
    // Object.setPrototypeOf vulnerability
    Object.setPrototypeOf(userData, { role: 'admin' });
    
    // Unsafe JSON parsing from user input
    const parsed = JSON.parse(req.body.data);  // No validation
    
    // Prototype pollution via merge
    function merge(target, source) {
        for (let key in source) {
            if (key === '__proto__') continue;  // Insufficient protection
            target[key] = source[key];
        }
    }
}

// JS005 - eval() and Function constructor vulnerabilities
function executeUserCode(userCode) {
    // Critical - direct eval usage
    eval(userCode);
    
    // Dynamic function creation
    const dynamicFunc = new Function('return ' + userCode);
    dynamicFunc();
    
    // setTimeout with string (acts like eval)
    setTimeout(userCode, 1000);
    
    // setInterval with string
    setInterval('console.log("' + userCode + '")', 5000);
}

// JS006, JS007 - DOM manipulation and cookie vulnerabilities
function handleRedirect(url) {
    // Unsafe URL manipulation
    document.querySelector('iframe').src = 'https://example.com/' + url;
    document.querySelector('a').href = 'javascript:' + url;
    
    // Location manipulation
    window.location = 'https://redirect.com?next=' + url;
    location.href = url;
    
    // Cookie manipulation without security
    document.cookie = 'sessionId=' + Math.random() + '; path=/';
    document.cookie = 'userRole=' + userRole + '; domain=.example.com';
}

// JS008, JS009, JS010, JS011 - Weak cryptography
function generateSessionData() {
    // Insecure random number generation
    const sessionId = Math.random().toString(36);
    
    // Timestamp for randomness (predictable)
    const token = new Date().getTime().toString();
    
    // Base64 is not encryption
    const encoded = btoa('secret data');
    const decoded = atob('c2VjcmV0IGRhdGE=');
    
    // Weak session generation
    function generateWeakToken() {
        return Math.random().toString(16) + new Date().getTime();
    }
    
    return {
        sessionId: sessionId,
        token: token,
        data: encoded
    };
}

// JS013 - Missing security headers (Express.js example)
const express = require('express');
const app = express();

app.use(express.json());

// Missing helmet or security headers
app.get('/api/data', (req, res) => {
    res.json({ data: 'sensitive information' });
});

// JS014 - Open redirect vulnerability
app.get('/redirect', (req, res) => {
    const redirectUrl = req.query.url;
    res.redirect(redirectUrl);  // Open redirect - no validation
});

// JS015 - NoSQL injection vulnerability
const mongoose = require('mongoose');

function findUser(userId) {
    // Direct user input in query - NoSQL injection
    return User.find({ _id: userId });  // Should validate userId
}

function updateUserData(req, res) {
    const userQuery = req.body.query;
    // NoSQL injection via query object
    User.findOne(userQuery, (err, user) => {
        if (user) {
            res.json(user);
        }
    });
}

// Complex vulnerability example - simulated web application
class VulnerableWebApp {
    constructor() {
        this.users = [];
        this.sessions = {};
    }
    
    // Multiple vulnerabilities in authentication
    authenticate(username, password) {
        // Weak session generation
        const sessionId = Math.random().toString();
        
        // XSS in error messages
        if (!username) {
            throw new Error('Username ' + username + ' is required');
        }
        
        // Hardcoded admin backdoor
        if (username === 'admin' && password === 'secret123') {
            return { role: 'admin', sessionId };
        }
        
        // Prototype pollution in user lookup
        const user = this.users.find(u => u.username === username);
        if (user && user.__proto__.isAdmin) {
            return { role: 'admin', sessionId };
        }
        
        return null;
    }
    
    // File upload with path traversal
    uploadFile(filename, content) {
        const uploadPath = '/uploads/' + filename;  // Path traversal possible
        require('fs').writeFileSync(uploadPath, content);
    }
    
    // Template injection
    renderTemplate(template, userData) {
        // Direct template interpolation - template injection
        const rendered = template.replace('{{user}}', userData.name);
        return rendered;
    }
    
    // Command injection (Node.js)
    executeCommand(userInput) {
        const { exec } = require('child_process');
        exec('ls -la ' + userInput, (error, stdout, stderr) => {
            console.log(stdout);
        });
    }
}

// Browser-specific vulnerabilities
function browserVulnerabilities() {
    // LocalStorage of sensitive data
    localStorage.setItem('authToken', jwt_token);
    localStorage.setItem('userCredentials', JSON.stringify({
        username: 'admin',
        password: 'password123'
    }));
    
    // PostMessage without origin validation
    window.addEventListener('message', function(event) {
        // No origin check - accepts messages from any domain
        eval(event.data);  // Double vulnerability: no origin check + eval
    });
    
    // WebSocket without proper validation
    const ws = new WebSocket('wss://api.example.com/ws');
    ws.onmessage = function(event) {
        const data = JSON.parse(event.data);
        document.body.innerHTML = data.content;  // XSS via WebSocket
    };
}

// Export vulnerabilities for testing
module.exports = {
    updateUserProfile,
    processUserData,
    executeUserCode,
    handleRedirect,
    generateSessionData,
    VulnerableWebApp,
    browserVulnerabilities
};

// Run examples if script is executed directly
if (require.main === module) {
    console.log('Running vulnerable code examples...');
    
    // Trigger various vulnerabilities
    updateUserProfile('<script>alert("XSS")</script>');
    executeUserCode('alert("Code injection")');
    
    const app = new VulnerableWebApp();
    app.authenticate('admin', 'secret123');
    app.uploadFile('../../../etc/passwd', 'malicious content');
    app.executeCommand('; rm -rf /');
    
    browserVulnerabilities();
}