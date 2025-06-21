// Test file for TypeScript vulnerability detection
// This file contains intentionally vulnerable TypeScript code patterns

interface User {
    name: string;
    email: string;
}

// XSS vulnerabilities in TypeScript
class DOMManipulator {
    updateContent(userInput: string): void {
        document.getElementById('content')!.innerHTML = '<div>' + userInput + '</div>';
        document.body.outerHTML = 'Content: ' + userInput;
    }
    
    // Angular-specific XSS
    setHtml(content: string): void {
        this.sanitizer.bypassSecurityTrustHtml('<span>' + content + '</span>');
    }
}

// Type assertion vulnerabilities
function processData(data: unknown): User {
    return data as User; // Unsafe type assertion
    const user = <User>data; // Another unsafe assertion
    return user!; // Non-null assertion without validation
}

// Any type usage
function handleResponse(response: any): void {
    console.log(response.sensitiveData);
    eval(response.code); // Dangerous with any type
}

// Strict null check bypasses
function getName(user?: User): string {
    return user!.name; // Bypassing null check
    return (user as User).name; // Unsafe assertion
}

// Enum security issues
enum Permission {
    READ = "read",
    WRITE = "write",
    ADMIN = "admin"
}

function checkPermission(perm: string): boolean {
    return Object.values(Permission).includes(perm as Permission); // Unsafe cast
}

// Decorator security patterns
@Injectable()
class UnsafeService {
    @Inject('UNSAFE_TOKEN') private token: any;
    
    @Post('/admin')
    adminAction(@Body() data: any): void {
        eval(data.command); // Dangerous decorator combination
    }
}

// Prototype pollution in TypeScript
// Rule: unsafe-object-property-assignment
function basicProtoPollution(obj: any, key: string, value: any) {
    obj[key] = value; // DETECT: obj[keyVariable] = value
}

function eventProtoPollution(obj: any, event: any) {
    obj[event.target.name] = event.target.value; // DETECT: obj[event.target.name] = value
}

function reqProtoPollution(obj: any, req: any) {
    obj[req.params.id] = "data"; // DETECT: obj[req.params.id] = value (covered by req.$PARAM)
}

function safeProtoPollution(obj: any, value: any) {
    obj["fixedProperty"] = value; // SAFE: obj["literalKey"] = value
}

// Existing related code (for context, not direct match for the modified rule)
function merge<T>(target: T, source: any): T {
    return Object.assign(target, source.__proto__); // Not $OBJ[$KEY] = $VALUE
}

// Eval patterns in TypeScript
// Rule: eval-dangerous-call (testing in TS context)
let tsVar = "typescript code";
eval(tsVar); // DETECT: eval(variable)
eval('foo' + tsVar + 'bar'); // DETECT: eval('...' + var + '...')
eval(`foo ${tsVar} bar`); // DETECT: eval(\`...\${VAR}...\`)
eval("console.log('safe eval')"); // SAFE: eval("literal")

// Rule: settimeout-string-injection-dynamic (testing in TS context)
let tsTimeoutCmd = "console.log('ts timeout')";
setTimeout(tsTimeoutCmd, 100); // DETECT
setTimeout('logTS("' + tsVar + '")', 1000); // DETECT
setTimeout(`logger.logTS("${tsVar}")`, 100); // DETECT
setInterval(tsTimeoutCmd, 200); // DETECT
setInterval('logIntervalTS("' + tsVar + '")', 2000); // DETECT
setInterval(`logger.intervalTS("${tsVar}")`, 200); // DETECT

setTimeout("console.log('Safe TS timeout')", 100); // SAFE
setInterval("console.log('Safe TS interval')", 100); // SAFE


// TypeScript-specific template injection
const templateString: string = `Hello ${userInput}`;
const unsafeTemplate = `<div>${(userInput as any)}</div>`;

// Weak crypto with TypeScript types
interface CryptoConfig {
    algorithm: string;
    key: string;
}

const config: CryptoConfig = {
    algorithm: 'md5', // Weak algorithm
    key: 'hardcoded-key-123'
};

// Type-unsafe API calls
async function fetchUserData(id: string): Promise<any> {
    const response = await fetch(`/api/users/${id}`);
    return response.json() as User; // Unsafe cast from API response
}

// Hardcoded secrets in TypeScript
const API_CONFIG = {
    key: "sk-1234567890abcdefghijklmnopqrstuvwxyz",
    secret: "very-secret-key-123",
    token: "bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9..."
} as const;

// ReDoS with TypeScript regex
const emailRegex: RegExp = /(.+)+@(.+)+\..+/;
const phoneRegex: RegExp = /(\d+)+\-(\d+)+/;

// Supply chain in TypeScript imports
import { suspiciousLibrary } from 'https://cdn.polyfill.io/v2/polyfill.min.js';
import * as malware from 'suspicious-package';

// Path traversal with TypeScript
import * as fs from 'fs';
import * as path from 'path';

function readUserFile(filename: string): Promise<string> {
    const filePath = path.join('../../../', filename); // Vulnerable path
    return fs.promises.readFile(filePath, 'utf8');
}

// Template injection with TypeScript templates
const render = (template: string, data: Record<string, any>): string => {
    return template.replace(/\{\{(.+?)\}\}/g, (match, key) => {
        return data[key] || match; // Unsafe template rendering
    });
};

// Weak randomness in TypeScript
class TokenGenerator {
    generateSessionToken(): string {
        return Math.random().toString(36); // Weak for security
    }
    
    generateCsrfToken(): string {
        return Date.now().toString(); // Predictable
    }
}

// TypeScript-specific vulnerabilities
namespace Security {
    export function unsafeDeserialization(data: string): any {
        return JSON.parse(data) as any; // No validation
    }
    
    export function dynamicImport(moduleName: string): Promise<any> {
        return import(moduleName + '.js'); // Dynamic import with user input
    }
}

// Generic type vulnerabilities
function processGeneric<T extends Record<string, any>>(data: T): T {
    return { ...data, ...data.__proto__ }; // Prototype pollution with generics
}

// Module augmentation vulnerabilities
declare global {
    interface Window {
        unsafeGlobal: any;
    }
}

window.unsafeGlobal = eval; // Global pollution