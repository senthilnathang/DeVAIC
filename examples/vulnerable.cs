// C# vulnerable code examples for .NET applications

using System;
using System.Data;
using System.Data.SqlClient;
using System.Diagnostics;
using System.IO;
using System.Net.Http;
using System.Security.Cryptography;
using System.Text;
using System.Web;
using System.Xml;
using System.Runtime.Serialization.Formatters.Binary;
using Newtonsoft.Json;

namespace VulnerableApp
{
    public class DatabaseVulnerabilities
    {
        // SQL Injection vulnerabilities
        public void VulnerableQuery(string userInput)
        {
            string connectionString = "Server=localhost;Database=TestDB;Trusted_Connection=true;";
            
            // Direct string concatenation - SQL injection
            using (SqlConnection connection = new SqlConnection(connectionString))
            {
                string query = "SELECT * FROM Users WHERE Id = " + userInput;
                SqlCommand command = new SqlCommand(query, connection);
                connection.Open();
                command.ExecuteReader();
            }
            
            // Another SQL injection pattern
            using (SqlConnection connection = new SqlConnection(connectionString))
            {
                SqlCommand command = new SqlCommand();
                command.Connection = connection;
                command.CommandText = "DELETE FROM Users WHERE Name = '" + userInput + "'";
                connection.Open();
                command.ExecuteNonQuery();
            }
            
            // Entity Framework SQL injection
            using (var context = new AppDbContext())
            {
                var users = context.Database.SqlQuery<User>("SELECT * FROM Users WHERE Email = '" + userInput + "'");
            }
        }
        
        // Hardcoded connection strings
        public void HardcodedSecrets()
        {
            // Hardcoded database password
            string connectionString = "Server=localhost;Database=MyApp;User Id=admin;Password=super_secret_password_123;";
            
            // Hardcoded API key
            string apiKey = "sk-1234567890abcdef1234567890abcdef";
            
            // Hardcoded encryption key
            string encryptionKey = "my_secret_encryption_key_32_chars";
            
            // Using hardcoded secrets
            ConnectToDatabase(connectionString);
            CallAPI(apiKey);
        }
        
        private void ConnectToDatabase(string connectionString) { }
        private void CallAPI(string apiKey) { }
    }
    
    public class CommandInjectionVulnerabilities
    {
        // Command injection vulnerabilities
        public void VulnerableProcessExecution(string userInput)
        {
            // Command injection via Process.Start
            Process.Start("cmd.exe", "/c ping " + userInput);
            
            // Another command injection pattern
            ProcessStartInfo startInfo = new ProcessStartInfo();
            startInfo.FileName = "cmd.exe";
            startInfo.Arguments = "/c dir " + userInput;
            Process.Start(startInfo);
            
            // PowerShell command injection
            Process.Start("powershell.exe", "-Command Get-Process " + userInput);
        }
        
        // File path traversal
        public void VulnerableFileOperations(string filename)
        {
            // Path traversal in file operations
            string content = File.ReadAllText("C:\\Data\\" + filename);
            
            // File write with user input
            File.WriteAllText("C:\\Uploads\\" + filename, "data");
            
            // Another path traversal
            FileStream fs = File.OpenRead("./files/" + filename);
            
            // Directory traversal
            string[] files = Directory.GetFiles("C:\\Temp\\" + filename);
        }
    }
    
    public class DeserializationVulnerabilities
    {
        // Insecure deserialization
        public void VulnerableDeserialization(byte[] data, string jsonData)
        {
            // Binary deserialization - dangerous
            BinaryFormatter formatter = new BinaryFormatter();
            MemoryStream stream = new MemoryStream(data);
            object obj = formatter.Deserialize(stream);
            
            // JSON deserialization without type validation
            JsonConvert.DeserializeObject(jsonData);
            
            // Another dangerous deserialization
            var settings = new JsonSerializerSettings
            {
                TypeNameHandling = TypeNameHandling.All
            };
            JsonConvert.DeserializeObject(jsonData, settings);
        }
    }
    
    public class CryptographyVulnerabilities
    {
        // Weak cryptography
        public void WeakCryptography()
        {
            // MD5 hashing (weak)
            using (MD5 md5 = MD5.Create())
            {
                byte[] hash = md5.ComputeHash(Encoding.UTF8.GetBytes("password"));
            }
            
            // SHA1 hashing (weak)
            using (SHA1 sha1 = SHA1.Create())
            {
                byte[] hash = sha1.ComputeHash(Encoding.UTF8.GetBytes("sensitive_data"));
            }
            
            // DES encryption (weak)
            using (DESCryptoServiceProvider des = new DESCryptoServiceProvider())
            {
                des.Key = Encoding.UTF8.GetBytes("weakkey1");
                des.IV = Encoding.UTF8.GetBytes("weakiv12");
            }
            
            // RC2 encryption (weak)
            using (RC2CryptoServiceProvider rc2 = new RC2CryptoServiceProvider())
            {
                rc2.Key = Encoding.UTF8.GetBytes("weakkey123456789");
            }
        }
        
        // Insecure random number generation
        public void InsecureRandom()
        {
            // Predictable random numbers for security purposes
            Random random = new Random();
            int sessionToken = random.Next(100000, 999999);
            
            // Another weak random pattern
            int nonce = new Random(DateTime.Now.Millisecond).Next();
            
            // Time-based predictable value
            long timestamp = DateTime.Now.Ticks;
            int predictableToken = (int)(timestamp % 1000000);
        }
    }
    
    public class NetworkVulnerabilities
    {
        // SSRF vulnerabilities
        public async void VulnerableHttpRequests(string url)
        {
            // SSRF via user-controlled URL
            using (HttpClient client = new HttpClient())
            {
                HttpResponseMessage response = await client.GetAsync(url);
                string content = await response.Content.ReadAsStringAsync();
            }
            
            // Another SSRF pattern
            System.Net.WebClient webClient = new System.Net.WebClient();
            string data = webClient.DownloadString(url);
            
            // HttpWebRequest SSRF
            System.Net.HttpWebRequest request = (System.Net.HttpWebRequest)System.Net.WebRequest.Create(url);
            System.Net.HttpWebResponse response2 = (System.Net.HttpWebResponse)request.GetResponse();
        }
        
        // Certificate validation bypass
        public void InsecureCertificateValidation()
        {
            // Accepting all certificates (dangerous)
            System.Net.ServicePointManager.ServerCertificateValidationCallback = 
                (sender, certificate, chain, sslPolicyErrors) => true;
            
            // Disabling certificate validation
            System.Net.ServicePointManager.CheckCertificateRevocationList = false;
        }
    }
    
    public class XmlVulnerabilities
    {
        // XML vulnerabilities
        public void VulnerableXmlParsing(string xmlData)
        {
            // XXE vulnerability
            XmlDocument doc = new XmlDocument();
            doc.LoadXml(xmlData);
            
            // Another XXE pattern
            XmlTextReader reader = new XmlTextReader(new StringReader(xmlData));
            reader.DtdProcessing = DtdProcessing.Parse; // Dangerous
            
            // XPath injection
            XmlNode node = doc.SelectSingleNode("//user[@id='" + xmlData + "']");
        }
    }
    
    public class LoggingVulnerabilities
    {
        // Logging sensitive information
        public void VulnerableLogging(string password, string creditCard)
        {
            // Logging sensitive data
            Console.WriteLine("User password: " + password);
            System.Diagnostics.Debug.WriteLine("Credit card: " + creditCard);
            
            // Another logging vulnerability
            System.Diagnostics.Trace.WriteLine("API Key: " + GetApiKey());
        }
        
        private string GetApiKey()
        {
            return "hardcoded_api_key_12345";
        }
    }
    
    public class RegexVulnerabilities
    {
        // Regular expression DoS
        public void VulnerableRegex(string userInput)
        {
            // ReDoS vulnerable patterns
            System.Text.RegularExpressions.Regex regex1 = new System.Text.RegularExpressions.Regex(@"^(a+)+$");
            System.Text.RegularExpressions.Regex regex2 = new System.Text.RegularExpressions.Regex(@"^(a*)*$");
            System.Text.RegularExpressions.Regex regex3 = new System.Text.RegularExpressions.Regex(@"^(a|a)*$");
            
            // Applying vulnerable regex to user input
            regex1.IsMatch(userInput);
            regex2.Match(userInput);
            regex3.Matches(userInput);
        }
    }
    
    // Model classes
    public class User
    {
        public int Id { get; set; }
        public string Name { get; set; }
        public string Email { get; set; }
    }
    
    public class AppDbContext : System.Data.Entity.DbContext
    {
        public System.Data.Entity.DbSet<User> Users { get; set; }
    }
    
    // Main program
    class Program
    {
        static void Main(string[] args)
        {
            Console.WriteLine("C# Vulnerability Examples");
            Console.WriteLine("These examples demonstrate common security vulnerabilities.");
            Console.WriteLine("DO NOT use these patterns in production code!");
            
            // Example usage (would be dangerous in real applications)
            var dbVulns = new DatabaseVulnerabilities();
            var cmdVulns = new CommandInjectionVulnerabilities();
            var cryptoVulns = new CryptographyVulnerabilities();
            
            // These would trigger security issues in a real application
            // dbVulns.VulnerableQuery("1 OR 1=1");
            // cmdVulns.VulnerableProcessExecution("google.com & del /f /q C:\\*");
            // cryptoVulns.WeakCryptography();
            
            Console.WriteLine("Vulnerability examples created for testing purposes only!");
        }
    }
}