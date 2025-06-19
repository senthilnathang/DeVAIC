import java.sql.*;
import java.io.*;
import java.security.MessageDigest;
import java.util.Random;
import javax.xml.parsers.*;
import java.beans.XMLDecoder;
import java.lang.reflect.Method;
import java.nio.file.*;

public class VulnerableJavaApp {
    
    // JAVA008 - Hardcoded credentials
    private static final String DB_PASSWORD = "super_secret_password_123";
    private static final String API_KEY = "sk_live_abcdef123456789";
    private static final String SECRET_TOKEN = "my-secret-token-value";
    
    private Connection connection;
    
    // JAVA001, JAVA002 - SQL Injection vulnerabilities
    public void sqlInjectionExample(String userId, String userName) throws SQLException {
        // Direct string concatenation - SQL injection
        String query1 = "SELECT * FROM users WHERE id = " + userId;
        Statement stmt = connection.createStatement();
        ResultSet rs = stmt.executeQuery(query1);
        
        // PreparedStatement with concatenation - still vulnerable
        String query2 = "SELECT * FROM users WHERE name = '" + userName + "'";
        PreparedStatement pstmt = connection.prepareStatement(query2);
        pstmt.executeQuery();
        
        // User input directly in execution
        String userInput = getUserParameter("search");
        stmt.executeUpdate("DELETE FROM logs WHERE message = '" + userInput + "'");
    }
    
    // JAVA003 - Unsafe deserialization
    public Object deserializeUntrustedData(String filename) throws Exception {
        FileInputStream fis = new FileInputStream(filename);
        ObjectInputStream ois = new ObjectInputStream(fis);
        Object obj = ois.readObject();  // Dangerous - can execute arbitrary code
        ois.close();
        return obj;
    }
    
    public void xmlDeserializationVuln(InputStream input) throws Exception {
        XMLDecoder decoder = new XMLDecoder(input);
        Object result = decoder.readObject();  // XML deserialization vulnerability
        decoder.close();
    }
    
    // JAVA004 - XML External Entity (XXE) vulnerabilities
    public void parseXmlUnsafely(File xmlFile) throws Exception {
        // Unsafe XML parser - XXE vulnerable
        DocumentBuilderFactory factory = DocumentBuilderFactory.newInstance();
        DocumentBuilder builder = factory.newDocumentBuilder();
        builder.parse(xmlFile);  // No secure processing configured
        
        // Another XXE vulnerability
        SAXParserFactory saxFactory = SAXParserFactory.newInstance();
        SAXParser parser = saxFactory.newSAXParser();
        parser.parse(xmlFile, new DefaultHandler());
    }
    
    // JAVA005 - Weak cryptographic algorithms
    public void weakCryptography(String data) throws Exception {
        // Weak hash algorithms
        MessageDigest md5 = MessageDigest.getInstance("MD5");
        byte[] md5Hash = md5.digest(data.getBytes());
        
        MessageDigest sha1 = MessageDigest.getInstance("SHA1");
        byte[] sha1Hash = sha1.digest(data.getBytes());
        
        // Weak encryption
        Cipher desCipher = Cipher.getInstance("DES/ECB/PKCS5Padding");
        
        // Insecure random number generation
        Random random = new Random();
        int sessionId = random.nextInt();  // Predictable for session IDs
    }
    
    // JAVA009 - Insecure random number generation
    public String generateToken() {
        Random rand = new Random();  // Not cryptographically secure
        StringBuilder token = new StringBuilder();
        for (int i = 0; i < 16; i++) {
            token.append(rand.nextInt(10));
        }
        return token.toString();
    }
    
    // JAVA006 - Unsafe reflection with user input
    public void reflectionVulnerability(String className, String methodName) throws Exception {
        String userClassName = getUserParameter("class");
        Class<?> clazz = Class.forName(userClassName);  // User-controlled class loading
        Object instance = clazz.newInstance();
        
        Method method = clazz.getMethod(methodName);
        method.invoke(instance);  // User-controlled method invocation
    }
    
    // JAVA007 - Path traversal vulnerabilities
    public void fileOperations(String userFileName) throws IOException {
        String baseDir = "/app/uploads/";
        File file = new File(baseDir + userFileName);  // Path traversal possible
        
        FileInputStream fis = new FileInputStream(baseDir + userFileName);
        
        Path path = Paths.get("/secure/files/" + userFileName);
        Files.newInputStream(path);  // Another path traversal
    }
    
    // Multiple vulnerabilities in web endpoint simulation
    public void processUserRequest(String userId, String action, String filename) throws Exception {
        // SQL Injection
        String query = "SELECT * FROM audit_log WHERE user_id = " + userId + " AND action = '" + action + "'";
        connection.createStatement().executeQuery(query);
        
        // Path Traversal
        File logFile = new File("/var/log/app/" + filename);
        if (logFile.exists()) {
            // XXE vulnerability
            DocumentBuilderFactory factory = DocumentBuilderFactory.newInstance();
            DocumentBuilder builder = factory.newDocumentBuilder();
            builder.parse(logFile);
        }
        
        // Unsafe deserialization
        ObjectInputStream ois = new ObjectInputStream(new FileInputStream(logFile));
        Object data = ois.readObject();
        
        // Weak crypto for session
        Random rand = new Random();
        String sessionToken = String.valueOf(rand.nextLong());
        
        // Hardcoded secret for JWT
        String jwtSecret = "hardcoded-jwt-secret-key-do-not-use-in-production";
    }
    
    // Simulation of getting user parameters (like from HTTP request)
    private String getUserParameter(String paramName) {
        // Simulated user input
        return "'; DROP TABLE users; --";
    }
    
    public static void main(String[] args) {
        VulnerableJavaApp app = new VulnerableJavaApp();
        
        try {
            app.sqlInjectionExample("1' OR '1'='1", "admin'; DELETE FROM users; --");
            app.deserializeUntrustedData("/tmp/malicious.ser");
            app.parseXmlUnsafely(new File("/tmp/xxe.xml"));
            app.weakCryptography("sensitive data");
            app.reflectionVulnerability("java.lang.Runtime", "exec");
            app.fileOperations("../../../etc/passwd");
            app.processUserRequest("1' OR 1=1", "../../config", "../logs/app.xml");
        } catch (Exception e) {
            e.printStackTrace();
        }
    }
}