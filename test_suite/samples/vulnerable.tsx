import React from 'react';

interface Props {
    userContent: string;
    userData: any; // Type safety issue
}

// React component with XSS vulnerability
const UnsafeComponent: React.FC<Props> = ({ userContent, userData }) => {
    const user = userData as any; // Unsafe type assertion
    
    return (
        <div>
            {/* XSS vulnerability */}
            <div dangerouslySetInnerHTML={{ __html: userContent }} />
            
            {/* User data rendering */}
            <p>{user.name}</p>
        </div>
    );
};

// Hardcoded API key
const config = {
    apiKey: "AIzaSyDOCAbC123dEf456GhI789jKl01MnO2PqR",
    secret: "super-secret-key-12345"
};

// Weak random generation
function generateSessionId(): string {
    return Math.random().toString(36).substring(2);
}

// Code execution vulnerability
function executeUserCode(code: string): void {
    setTimeout(code, 1000); // String-based setTimeout
}

export default UnsafeComponent;