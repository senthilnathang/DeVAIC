public class VulnerableApp {
    public static void main(String[] args) {
        // SQL Injection vulnerability
        String query = "SELECT * FROM users WHERE id = " + args[0];
        
        // Hardcoded secret
        String api_key = "sk-1234567890abcdef1234567890abcdef";
        
        // Weak cryptography
        Cipher cipher = Cipher.getInstance("DES");
        
        // Command injection
        Runtime.getRuntime().exec("ls -la " + args[1]);
        
        // Path traversal
        new File("/tmp/" + args[2]);
    }
}