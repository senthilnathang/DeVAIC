package com.example.vulnerable

import android.content.Intent
import android.database.sqlite.SQLiteDatabase
import android.webkit.WebView
import android.content.Context
import android.net.Uri
import java.security.MessageDigest
import javax.crypto.Cipher
import java.io.File
import java.net.URL
import java.util.*
import kotlin.random.Random

class VulnerableAndroidApp {
    
    // SQL Injection vulnerabilities
    fun vulnerableDatabaseQuery(db: SQLiteDatabase, userInput: String) {
        // CWE-89: SQL Injection
        val query = "SELECT * FROM users WHERE id = $userInput"
        db.execSQL(query)
        
        // Raw query injection
        db.rawQuery("SELECT * FROM products WHERE name = '$userInput'", null)
    }
    
    // Intent Injection vulnerabilities
    fun vulnerableIntentHandling(context: Context, userAction: String) {
        // CWE-926: Intent Injection
        val intent = Intent(userAction)
        context.startActivity(intent)
        
        // Another intent injection
        val maliciousIntent = Intent()
        maliciousIntent.action = userAction
        context.startService(maliciousIntent)
    }
    
    // WebView Injection vulnerabilities
    fun vulnerableWebView(webView: WebView, userUrl: String, userScript: String) {
        // CWE-79: WebView XSS
        webView.loadUrl(userUrl)
        
        // JavaScript injection
        webView.evaluateJavascript(userScript, null)
        
        // Data URL injection
        webView.loadData("<script>$userScript</script>", "text/html", "UTF-8")
    }
    
    // Weak Cryptography
    fun weakCryptographicAlgorithms(data: String): String {
        // CWE-327: Weak cryptographic algorithms
        val md5 = MessageDigest.getInstance("MD5")
        val sha1 = MessageDigest.getInstance("SHA1")
        
        // Weak cipher
        val desCipher = Cipher.getInstance("DES")
        
        return md5.digest(data.toByteArray()).toString() + 
               sha1.digest(data.toByteArray()).toString()
    }
    
    // Hardcoded Secrets
    class HardcodedCredentials {
        // CWE-798: Hardcoded credentials
        companion object {
            const val PASSWORD = "SuperSecret123!"
            const val API_KEY = "sk_live_1234567890abcdef"
            const val DATABASE_PASSWORD = "MyDBPassword2024"
            const val ENCRYPTION_KEY = "MyEncryptionKey123"
        }
        
        private val adminPassword = "admin123"
        private val secretToken = "secret_token_2024"
    }
    
    // Path Traversal vulnerabilities
    fun vulnerableFileOperations(filename: String): String? {
        // CWE-22: Path Traversal
        val file = File(filename)
        return file.readText()
    }
    
    // Insecure Random Number Generation
    fun weakRandomGeneration(): String {
        // Weak random number generation
        val random1 = Math.random()
        val random2 = Random.nextInt()
        
        // Predictable session token
        return "${System.currentTimeMillis()}_$random1"
    }
    
    // Network Security Issues
    fun vulnerableNetworkCalls(userUrl: String) {
        // CWE-918: SSRF
        val url = URL(userUrl)
        val connection = url.openConnection()
        connection.getInputStream()
    }
    
    // Insecure Data Storage
    fun insecureDataStorage(context: Context, sensitiveData: String) {
        // Storing sensitive data in SharedPreferences without encryption
        val prefs = context.getSharedPreferences("app_prefs", Context.MODE_PRIVATE)
        prefs.edit().putString("password", sensitiveData).apply()
        
        // Writing sensitive data to external storage
        val file = File(context.getExternalFilesDir(null), "sensitive.txt")
        file.writeText(sensitiveData)
    }
    
    // Improper Certificate Validation
    fun vulnerableSSLHandling() {
        // Accepting all SSL certificates (dangerous)
        val trustAllCerts = arrayOf(object : javax.net.ssl.X509TrustManager {
            override fun checkClientTrusted(chain: Array<java.security.cert.X509Certificate>, authType: String) {}
            override fun checkServerTrusted(chain: Array<java.security.cert.X509Certificate>, authType: String) {}
            override fun getAcceptedIssuers(): Array<java.security.cert.X509Certificate> = arrayOf()
        })
    }
    
    // Logging Sensitive Information
    fun vulnerableLogging(password: String, creditCard: String) {
        // CWE-532: Information Exposure Through Log Files
        android.util.Log.d("DEBUG", "User password: $password")
        android.util.Log.i("INFO", "Credit card: $creditCard")
        println("API Key: ${HardcodedCredentials.API_KEY}")
    }
    
    // Broadcast Receiver vulnerabilities
    fun vulnerableBroadcast(context: Context, sensitiveData: String) {
        // Sending sensitive data via implicit broadcast
        val intent = Intent("com.example.SENSITIVE_ACTION")
        intent.putExtra("sensitive_data", sensitiveData)
        context.sendBroadcast(intent) // No permission required
    }
    
    // Content Provider vulnerabilities
    fun vulnerableContentProvider(context: Context, userInput: String) {
        // SQL injection in content provider query
        val uri = Uri.parse("content://com.example.provider/users")
        val selection = "name = '$userInput'" // SQL injection
        context.contentResolver.query(uri, null, selection, null, null)
    }
    
    // Insecure IPC (Inter-Process Communication)
    fun vulnerableIPC(context: Context, userData: String) {
        // Exposing sensitive data through exported components
        val intent = Intent()
        intent.component = android.content.ComponentName("com.malicious.app", "com.malicious.app.Receiver")
        intent.putExtra("sensitive_data", userData)
        context.sendBroadcast(intent)
    }
    
    // Memory Management Issues
    fun memoryLeakVulnerability(context: Context) {
        // Static reference causing memory leak
        companion object {
            var staticContext: Context? = null
        }
        staticContext = context // Memory leak
    }
    
    // Race Condition
    class RaceConditionExample {
        private var counter = 0
        
        fun incrementUnsafe() {
            // Race condition - no synchronization
            repeat(1000) {
                Thread {
                    counter++ // Unsafe concurrent access
                }.start()
            }
        }
    }
}

// Usage example demonstrating vulnerabilities
fun main() {
    val vulnerableApp = VulnerableAndroidApp()
    
    // Demonstrate various vulnerabilities
    println("Kotlin/Android vulnerabilities demonstrated")
    
    // Weak crypto
    val weakHash = vulnerableApp.weakCryptographicAlgorithms("sensitive data")
    println("Weak hash: $weakHash")
    
    // Hardcoded secrets
    println("API Key: ${VulnerableAndroidApp.HardcodedCredentials.API_KEY}")
    
    // Path traversal
    try {
        val fileContent = vulnerableApp.vulnerableFileOperations("../../../etc/passwd")
        println("File content: $fileContent")
    } catch (e: Exception) {
        println("File access error: ${e.message}")
    }
    
    // Weak random
    val weakToken = vulnerableApp.weakRandomGeneration()
    println("Weak token: $weakToken")
    
    // Race condition
    val raceExample = VulnerableAndroidApp.RaceConditionExample()
    raceExample.incrementUnsafe()
}