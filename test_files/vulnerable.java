/**
 * Test file with various Java vulnerabilities
 */

import java.io.*;
import java.sql.*;
import java.util.Random;
import java.security.MessageDigest;
import javax.servlet.http.HttpServletRequest;

public class VulnerableJavaCode {
    
    // Hard-coded credentials - CWE-798
    private static final String PASSWORD = "admin123";
    private static final String API_KEY = "sk-1234567890abcdef";
    private static final String DB_URL = "jdbc:mysql://localhost:3306/db?user=admin&password=secret";
    
    // SQL Injection vulnerability - CWE-89
    public ResultSet getUserData(String userId) throws SQLException {
        Connection conn = DriverManager.getConnection(DB_URL);
        Statement stmt = conn.createStatement();
        
        // Vulnerable: string concatenation in SQL
        String sql = "SELECT * FROM users WHERE id = " + userId;
        return stmt.executeQuery(sql);  // CWE-89: SQL Injection
    }
    
    // Command Injection vulnerability - CWE-78
    public void executeCommand(String userInput) throws IOException {
        // Vulnerable: direct command execution
        Runtime.getRuntime().exec("ping " + userInput);  // CWE-78: Command Injection
        
        // Also vulnerable through ProcessBuilder
        ProcessBuilder pb = new ProcessBuilder("sh", "-c", "cat " + userInput);
        pb.start();  // CWE-78: Command Injection
    }
    
    // Buffer overflow potential - CWE-787 (simulated in Java context)
    public void unsafeBufferOperation(String input) {
        // Vulnerable: no bounds checking
        char[] buffer = new char[256];
        for (int i = 0; i < input.length(); i++) {
            buffer[i] = input.charAt(i);  // CWE-787: Potential buffer overflow
        }
    }
    
    // Path Traversal vulnerability - CWE-22
    public String readFile(String filename) throws IOException {
        // Vulnerable: no path validation
        FileReader fileReader = new FileReader(filename);  // CWE-22: Path Traversal
        BufferedReader bufferedReader = new BufferedReader(fileReader);
        
        StringBuilder content = new StringBuilder();
        String line;
        while ((line = bufferedReader.readLine()) != null) {
            content.append(line).append("\n");
        }
        
        bufferedReader.close();
        return content.toString();
    }
    
    // Weak cryptography - CWE-327
    public String weakHash(String input) throws Exception {
        // Vulnerable: using MD5
        MessageDigest md5 = MessageDigest.getInstance("MD5");
        byte[] hash = md5.digest(input.getBytes());
        
        // Vulnerable: using SHA1
        MessageDigest sha1 = MessageDigest.getInstance("SHA-1");
        byte[] hash2 = sha1.digest(input.getBytes());
        
        return bytesToHex(hash);  // CWE-327: Weak Hash Algorithm
    }
    
    // XSS vulnerability simulation - CWE-79
    public String generateHtml(HttpServletRequest request) {
        String userInput = request.getParameter("comment");
        
        // Vulnerable: direct HTML output without encoding
        return "<div>" + userInput + "</div>";  // CWE-79: XSS
    }
    
    // Improper Input Validation - CWE-20
    public int processAge(String ageString) {
        // Vulnerable: no validation
        return Integer.parseInt(ageString);  // CWE-20: Could throw exception
    }
    
    // Weak random number generation - CWE-330
    public String generateSessionId() {
        Random random = new Random();
        
        // Vulnerable: using weak random for security
        return String.valueOf(random.nextInt(10000));  // CWE-330: Weak Random
    }
    
    // Use After Free simulation - CWE-416 (not directly applicable in Java, but similar pattern)
    public void useAfterClose() throws IOException {
        FileInputStream fis = new FileInputStream("test.txt");
        fis.close();
        
        // Vulnerable: using closed resource
        fis.read();  // CWE-416: Use After Free (equivalent in Java)
    }
    
    // Improper Authentication - CWE-287
    public boolean authenticateUser(String username, String password) {
        // Vulnerable: hardcoded authentication
        if (username.equals("admin") && password.equals("admin123")) {
            return true;  // CWE-287: Improper Authentication
        }
        return false;
    }
    
    // Missing Authorization - CWE-862
    public void deleteUser(String userId) {
        // Vulnerable: no authorization check
        // Should check if current user has permission to delete
        System.out.println("Deleting user: " + userId);  // CWE-862: Missing Authorization
    }
    
    // Utility method
    private String bytesToHex(byte[] bytes) {
        StringBuilder result = new StringBuilder();
        for (byte b : bytes) {
            result.append(String.format("%02x", b));
        }
        return result.toString();
    }
    
    public static void main(String[] args) {
        VulnerableJavaCode vulnerable = new VulnerableJavaCode();
        
        try {
            // Test various vulnerability patterns
            vulnerable.getUserData("1");
            vulnerable.executeCommand("localhost");
            vulnerable.unsafeBufferOperation("test input");
            vulnerable.readFile("test.txt");
            vulnerable.weakHash("password");
            vulnerable.processAge("25");
            vulnerable.generateSessionId();
            vulnerable.authenticateUser("admin", "admin123");
            vulnerable.deleteUser("123");
            
        } catch (Exception e) {
            System.err.println("Error: " + e.getMessage());
        }
    }
}