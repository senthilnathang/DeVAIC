<?php
// SQL Injection vulnerabilities
function vulnerableQuery($userInput) {
    // CWE-89: SQL Injection
    $query = "SELECT * FROM users WHERE id = " . $_GET['id'];
    mysql_query($query);
    
    // Another SQL injection
    mysqli_query($connection, "SELECT * FROM products WHERE name = '" . $_POST['name'] . "'");
    
    // PDO SQL injection
    $pdo->query("SELECT * FROM orders WHERE user_id = " . $_GET['user_id']);
}

// Command Injection vulnerabilities
function vulnerableCommand() {
    // CWE-78: Command Injection
    exec($_GET['cmd']);
    system($_POST['command']);
    shell_exec($_REQUEST['shell']);
    passthru($_GET['exec']);
    
    // Code injection
    eval($_POST['code']);
}

// File Inclusion vulnerabilities
function vulnerableInclusion() {
    // CWE-98: File Inclusion
    include($_GET['page']);
    require($_POST['file']);
    include_once($_REQUEST['module']);
    require_once($_GET['lib']);
}

// Cross-Site Scripting (XSS)
function vulnerableOutput() {
    // CWE-79: XSS
    echo $_GET['message'];
    print $_POST['content'];
    printf($_REQUEST['data']);
}

// Path Traversal vulnerabilities
function vulnerableFileAccess() {
    // CWE-22: Path Traversal
    file_get_contents($_GET['file']);
    file_put_contents($_POST['filename'], "data");
    fopen($_REQUEST['path'], "r");
    readfile($_GET['document']);
}

// Weak Cryptography
function weakCrypto($data) {
    // CWE-327: Weak cryptographic algorithms
    $hash1 = md5($data);
    $hash2 = sha1($data);
    $encrypted = crypt($data);
    
    return $hash1 . $hash2 . $encrypted;
}

// Hardcoded Secrets
function hardcodedCredentials() {
    // CWE-798: Hardcoded credentials
    $password = "admin123";
    $apiKey = "sk_live_abcdef1234567890";
    $dbPassword = "SuperSecretDBPass!";
    $secretKey = "MySecretEncryptionKey2024";
    
    return array($password, $apiKey, $dbPassword, $secretKey);
}

// Insecure Random Number Generation
function weakRandom() {
    // Weak random number generation
    $token = rand();
    $sessionId = mt_rand();
    
    return $token . $sessionId;
}

// Insecure File Upload
function vulnerableUpload() {
    if (isset($_FILES['upload'])) {
        // No validation - allows any file type
        move_uploaded_file($_FILES['upload']['tmp_name'], 
                          "uploads/" . $_FILES['upload']['name']);
    }
}

// Session Fixation
function sessionFixation() {
    // Session fixation vulnerability
    session_start();
    if (isset($_GET['sessionid'])) {
        session_id($_GET['sessionid']);
    }
}

// LDAP Injection
function ldapInjection($username) {
    // CWE-90: LDAP Injection
    $filter = "(uid=" . $username . ")";
    ldap_search($connection, "dc=example,dc=com", $filter);
}

// XML External Entity (XXE)
function xxeVulnerability($xmlData) {
    // CWE-611: XXE
    $dom = new DOMDocument();
    $dom->loadXML($xmlData, LIBXML_NOENT | LIBXML_DTDLOAD);
}

// Insecure Deserialization
function insecureDeserialization() {
    // CWE-502: Insecure Deserialization
    $data = unserialize($_POST['data']);
    return $data;
}

// Information Disclosure
function informationDisclosure() {
    // Exposing sensitive information
    phpinfo();
    error_reporting(E_ALL);
    ini_set('display_errors', 1);
    
    // Database error exposure
    mysql_query("INVALID SQL") or die(mysql_error());
}

// Main execution
if ($_SERVER['REQUEST_METHOD'] === 'GET') {
    vulnerableQuery($_GET['input']);
    vulnerableCommand();
    vulnerableInclusion();
    vulnerableOutput();
    vulnerableFileAccess();
    echo weakCrypto("sensitive data");
    print_r(hardcodedCredentials());
    echo weakRandom();
    vulnerableUpload();
    sessionFixation();
    ldapInjection($_GET['user']);
    xxeVulnerability($_POST['xml']);
    var_dump(insecureDeserialization());
    informationDisclosure();
}
?>