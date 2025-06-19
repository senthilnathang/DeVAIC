// TypeScript vulnerable code examples
interface User {
    name: string;
    email: string;
    password: string;
}

// Hardcoded secrets vulnerability
const API_KEY = "sk-1234567890abcdef1234567890abcdef";
const authToken = "Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9";

// Type safety issues
function processData(data: any): void {
    const user = data as any;
    console.log(user.sensitiveInfo);
}

// XSS vulnerability
function updateContent(userInput: string): void {
    document.getElementById('output')!.innerHTML = '<div>' + userInput + '</div>';
}

// Weak cryptography
function generateId(): string {
    return Math.random().toString(36);
}

// Code injection
function executeCode(code: string): void {
    eval(code);
}

// Unsafe redirect
function redirect(req: any, res: any): void {
    res.redirect(req.query.returnUrl);
}

// NoSQL injection
async function findUser(req: any): Promise<User[]> {
    return await db.collection('users').find(req.body.query).toArray();
}

// Prototype pollution
function mergeObjects(target: any, source: any): any {
    for (let key in source) {
        target[key] = source[key];
    }
    return target;
}