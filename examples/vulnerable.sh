#!/bin/bash

# Bash/Shell vulnerable code examples

# Command injection vulnerabilities
vulnerable_command_injection() {
    local user_input="$1"
    
    # Direct command injection
    eval "$user_input"
    
    # Command substitution injection
    result=$(echo "$user_input")
    
    # Backtick command injection
    output=`ls $user_input`
    
    # Another command injection pattern
    sh -c "ping $user_input"
    
    # Bash -c injection
    bash -c "echo $user_input"
}

# Path traversal vulnerabilities
vulnerable_file_operations() {
    local filename="$1"
    
    # Path traversal in file operations
    cat "/var/data/$filename"
    
    # File write with user input
    echo "data" > "/tmp/$filename"
    
    # Another path traversal
    less "/home/user/files/$filename"
    
    # Head command with user input
    head "/var/log/$filename"
    
    # Tail command vulnerability
    tail "/etc/$filename"
    
    # File copy with user input
    cp "/source/$filename" "/dest/"
    
    # Move operation
    mv "/old/$filename" "/new/"
    
    # Remove operation (dangerous)
    rm "/temp/$filename"
}

# SSRF vulnerabilities via curl/wget
vulnerable_http_requests() {
    local url="$1"
    
    # SSRF via curl
    curl "$url"
    
    # Wget SSRF
    wget "$url" -O output.txt
    
    # Another curl pattern
    curl -X POST "$url" -d "data=value"
    
    # Curl with user-controlled headers
    curl -H "Authorization: Bearer $url" http://api.example.com
}

# Hardcoded secrets
vulnerable_secrets() {
    # Hardcoded database password
    DB_PASSWORD="super_secret_db_password_123"
    mysql -u root -p"$DB_PASSWORD" -e "SELECT * FROM users"
    
    # Hardcoded API key
    API_KEY="sk-1234567890abcdef1234567890abcdef"
    curl -H "Authorization: Bearer $API_KEY" https://api.example.com
    
    # Hardcoded SSH key
    SSH_KEY="-----BEGIN PRIVATE KEY-----
MIIEvQIBADANBgkqhkiG9w0BAQEFAASCBKcwggSjAgEAAoIBAQC7..."
    
    # Hardcoded encryption key
    ENCRYPTION_KEY="my_secret_encryption_key_32_chars"
    echo "data" | openssl enc -aes-256-cbc -k "$ENCRYPTION_KEY"
}

# Unsafe file permissions
vulnerable_permissions() {
    local filename="$1"
    
    # World-writable permissions
    chmod 777 "$filename"
    
    # World-readable sensitive files
    chmod 666 "/etc/passwd"
    
    # Unsafe umask
    umask 000
    
    # Another unsafe permission
    chmod 755 "/etc/shadow"
    
    # Recursive permission change (dangerous)
    chmod -R 777 "/var/www/"
}

# Process and environment vulnerabilities
vulnerable_process_handling() {
    local user_input="$1"
    
    # Unsafe process execution
    $user_input &
    
    # Background process with user input
    nohup $user_input &
    
    # Process substitution vulnerability
    diff <(echo "$user_input") <(echo "expected")
    
    # Unsafe variable expansion
    echo ${user_input}
    
    # Command substitution in variable
    result=$($user_input)
}

# Network vulnerabilities
vulnerable_network_operations() {
    local host="$1"
    local port="$2"
    
    # Netcat with user input
    nc "$host" "$port"
    
    # Telnet vulnerability
    telnet "$host" "$port"
    
    # SSH with user input
    ssh "user@$host"
    
    # SCP with user input
    scp "file.txt" "user@$host:/path/"
    
    # Rsync vulnerability
    rsync -av "/local/" "user@$host:/remote/"
}

# Logging sensitive information
vulnerable_logging() {
    local password="$1"
    local credit_card="$2"
    
    # Logging sensitive data to files
    echo "User password: $password" >> /var/log/app.log
    echo "Credit card: $credit_card" >> /var/log/transactions.log
    
    # Logging to syslog
    logger "API Key: $(get_api_key)"
    
    # Debug output with sensitive data
    set -x  # Enable debug mode
    echo "Processing payment for card: $credit_card"
    set +x  # Disable debug mode
}

# Insecure temporary file handling
vulnerable_temp_files() {
    local data="$1"
    
    # Predictable temp file names
    temp_file="/tmp/app_$$"
    echo "$data" > "$temp_file"
    
    # World-readable temp files
    temp_file2="/tmp/sensitive_data.tmp"
    echo "$data" > "$temp_file2"
    chmod 644 "$temp_file2"
    
    # Using /tmp without proper cleanup
    echo "secret" > /tmp/secret.txt
    # File not cleaned up - information disclosure
}

# Regular expression vulnerabilities (if using grep/sed)
vulnerable_regex() {
    local user_input="$1"
    
    # ReDoS via grep (if input is crafted)
    echo "$user_input" | grep -E '^(a+)+$'
    echo "$user_input" | grep -E '^(a*)*$'
    echo "$user_input" | grep -E '^(a|a)*$'
    
    # Sed with user input
    echo "text" | sed "s/old/$user_input/g"
}

# SQL injection in shell scripts
vulnerable_database_operations() {
    local user_id="$1"
    
    # SQL injection via mysql command
    mysql -u root -p"password" -e "SELECT * FROM users WHERE id = $user_id"
    
    # Another SQL injection pattern
    sqlite3 database.db "DELETE FROM users WHERE name = '$user_id'"
    
    # PostgreSQL injection
    psql -d mydb -c "UPDATE users SET status = 'active' WHERE email = '$user_id'"
}

# Race condition vulnerabilities
vulnerable_race_conditions() {
    local filename="$1"
    
    # TOCTOU (Time of Check Time of Use)
    if [ -f "$filename" ]; then
        # Race condition: file could be changed between check and use
        cat "$filename"
    fi
    
    # Unsafe temp file creation
    temp_file="/tmp/race_condition_$$"
    if [ ! -f "$temp_file" ]; then
        # Race condition: file could be created by attacker
        echo "data" > "$temp_file"
    fi
}

# Helper function
get_api_key() {
    echo "hardcoded_api_key_12345"
}

# Main execution
main() {
    echo "Bash/Shell Vulnerability Examples"
    echo "These examples demonstrate common security vulnerabilities in shell scripts."
    echo "DO NOT use these patterns in production scripts!"
    
    # Example usage (would be dangerous in real scripts)
    if [ $# -gt 0 ]; then
        echo "Running vulnerability examples with input: $1"
        
        # These would trigger security issues in real scripts
        # vulnerable_command_injection "$1"
        # vulnerable_file_operations "$1"
        # vulnerable_http_requests "$1"
        # vulnerable_permissions "$1"
        
        echo "Examples completed. Remember: these are for testing purposes only!"
    else
        echo "Usage: $0 <test_input>"
        echo "Example: $0 'test_input'"
    fi
}

# Execute main function if script is run directly
if [ "${BASH_SOURCE[0]}" == "${0}" ]; then
    main "$@"
fi