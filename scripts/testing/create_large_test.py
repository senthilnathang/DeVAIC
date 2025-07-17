#!/usr/bin/env python3
"""
Create a large test directory structure to demonstrate performance improvements
"""

import os
import random
from pathlib import Path

def create_large_test_structure():
    """Create a large directory structure for performance testing"""
    base_path = Path("../../large_test_files")
    
    # Clear existing content
    if base_path.exists():
        import shutil
        shutil.rmtree(base_path)
    
    base_path.mkdir(parents=True)
    
    # Create directory structure
    directories = [
        "src/main/java/com/example/project",
        "src/test/java/com/example/project",
        "src/main/resources",
        "target/classes",
        "target/test-classes",
        "frontend/src/components",
        "frontend/src/services",
        "frontend/node_modules/react",
        "frontend/node_modules/lodash",
        "backend/controllers",
        "backend/models",
        "backend/services",
        "database/migrations",
        "database/seeds",
        "config/environments",
        "scripts/deployment",
        "tests/unit",
        "tests/integration",
        "docs/api",
        "docs/guides",
        ".git/objects",
        ".git/refs",
        "build/outputs",
        "dist/assets",
        "coverage/reports",
        "logs/application",
        "tmp/cache",
        "vendor/packages",
        "lib/external",
        "bin/executables",
    ]
    
    # Create all directories
    for dir_path in directories:
        full_path = base_path / dir_path
        full_path.mkdir(parents=True, exist_ok=True)
        print(f"Created directory: {dir_path}")
    
    # Create files with vulnerabilities
    vulnerabilities = [
        ("sql_injection", "user_id = input('Enter ID: ')\\nquery = 'SELECT * FROM users WHERE id = ' + user_id"),
        ("command_injection", "filename = input('Enter filename: ')\\nos.system('cat ' + filename)"),
        ("hardcoded_password", "password = 'admin123'\\napi_key = 'sk-1234567890abcdef'"),
        ("weak_crypto", "import hashlib\\nhash = hashlib.md5(b'password').hexdigest()"),
        ("buffer_overflow", "char buffer[256];\\nstrcpy(buffer, user_input);"),
        ("use_after_free", "free(ptr);\\n*ptr = 42;"),
        ("xss", "innerHTML = '<div>' + user_input + '</div>';"),
        ("path_traversal", "filename = request.getParameter('file');\\nFileReader reader = new FileReader(filename);"),
    ]
    
    # File templates
    file_templates = {
        ".py": "#!/usr/bin/env python3\n\ndef vulnerable_function():\n    {code}\n\nif __name__ == '__main__':\n    vulnerable_function()",
        ".java": "public class VulnerableClass {{\n    public void vulnerableMethod() {{\n        {code}\n    }}\n}}",
        ".js": "function vulnerableFunction() {{\n    {code}\n}}\nvulnerableFunction();",
        ".c": "#include <stdio.h>\n#include <stdlib.h>\n\nvoid vulnerable_function() {{\n    {code}\n}}\n\nint main() {{\n    vulnerable_function();\n    return 0;\n}}",
        ".cpp": "#include <iostream>\n#include <cstring>\n\nvoid vulnerable_function() {{\n    {code}\n}}\n\nint main() {{\n    vulnerable_function();\n    return 0;\n}}",
        ".ts": "function vulnerableFunction(): void {{\n    {code}\n}}\nvulnerableFunction();",
        ".php": "<?php\nfunction vulnerable_function() {{\n    {code}\n}}\nvulnerable_function();\n?>",
        ".rb": "def vulnerable_function\n    {code}\nend\nvulnerable_function",
        ".go": "package main\nimport \"fmt\"\n\nfunc vulnerableFunction() {{\n    {code}\n}}\n\nfunc main() {{\n    vulnerableFunction()\n}}",
        ".cs": "using System;\nclass VulnerableClass {{\n    public void VulnerableMethod() {{\n        {code}\n    }}\n}}",
    }
    
    # Create files in each directory
    file_count = 0
    for dir_path in directories:
        full_dir_path = base_path / dir_path
        
        # Skip certain directories
        if any(skip in dir_path for skip in ['node_modules', 'target', 'build', 'dist', '.git', 'coverage', 'vendor']):
            continue
            
        # Create 3-8 files per directory
        num_files = random.randint(3, 8)
        
        for i in range(num_files):
            # Choose random file extension
            ext = random.choice(list(file_templates.keys()))
            filename = f"file_{i}{ext}"
            file_path = full_dir_path / filename
            
            # Choose random vulnerability
            vuln_name, vuln_code = random.choice(vulnerabilities)
            
            # Create file content
            template = file_templates[ext]
            content = template.format(code=vuln_code)
            
            # Write file
            with open(file_path, 'w') as f:
                f.write(content)
            
            file_count += 1
    
    print(f"\nCreated {file_count} files across {len(directories)} directories")
    print(f"Test structure created in: {base_path}")
    
    return base_path

if __name__ == "__main__":
    create_large_test_structure()