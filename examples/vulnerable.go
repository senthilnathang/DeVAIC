package main

import (
	"database/sql"
	"fmt"
	"net/http"
	"os/exec"
	"crypto/md5"
	"crypto/sha1"
	"crypto/des"
	"log"
	"io/ioutil"
	"path/filepath"
	_ "github.com/go-sql-driver/mysql"
)

// SQL Injection vulnerabilities
func vulnerableQuery(db *sql.DB, userID string) {
	// CWE-89: SQL Injection
	query := "SELECT * FROM users WHERE id = " + userID
	rows, err := db.Query(query)
	if err != nil {
		log.Fatal(err)
	}
	defer rows.Close()
	
	// Another SQL injection
	db.Exec("DELETE FROM users WHERE name = '" + userID + "'")
}

// Command Injection vulnerabilities
func vulnerableCommand(userInput string) {
	// CWE-78: Command Injection
	cmd := exec.Command("sh", "-c", "echo "+userInput)
	output, _ := cmd.Output()
	fmt.Println(string(output))
	
	// Another command injection
	exec.CommandContext(nil, "grep", userInput, "/etc/passwd")
}

// Path Traversal vulnerabilities
func vulnerableFileAccess(filename string) {
	// CWE-22: Path Traversal
	fullPath := filepath.Join("/var/data", filename)
	content, _ := ioutil.ReadFile(fullPath)
	fmt.Println(string(content))
}

// SSRF vulnerabilities
func vulnerableHTTPRequest(url string) {
	// CWE-918: Server-Side Request Forgery
	resp, err := http.Get(url)
	if err != nil {
		log.Fatal(err)
	}
	defer resp.Body.Close()
	
	// Another SSRF
	http.Post(url, "application/json", nil)
}

// Weak Cryptography
func weakCrypto() {
	// CWE-327: Weak cryptographic algorithms
	h1 := md5.New()
	h1.Write([]byte("password"))
	
	h2 := sha1.New()
	h2.Write([]byte("secret"))
	
	// Weak cipher
	des.NewCipher([]byte("weakkey1"))
}

// Hardcoded Secrets
func hardcodedCredentials() {
	// CWE-798: Hardcoded credentials
	password := "SuperSecret123!"
	apiKey := "sk_live_1234567890abcdef"
	dbConnection := "mysql://user:password@localhost/db"
	
	fmt.Println(password, apiKey, dbConnection)
}

// Race condition vulnerability
var counter int

func raceCondition() {
	// Potential race condition - no synchronization
	for i := 0; i < 1000; i++ {
		go func() {
			counter++ // Unsafe concurrent access
		}()
	}
}

// Memory leak potential
func memoryLeak() {
	// Potential goroutine leak
	for {
		go func() {
			// Goroutine that never exits
			select {}
		}()
	}
}

func main() {
	// Demonstrate vulnerabilities
	db, _ := sql.Open("mysql", "user:pass@/dbname")
	defer db.Close()
	
	vulnerableQuery(db, "1 OR 1=1")
	vulnerableCommand("$(rm -rf /)")
	vulnerableFileAccess("../../../etc/passwd")
	vulnerableHTTPRequest("http://internal.service/admin")
	weakCrypto()
	hardcodedCredentials()
	raceCondition()
	memoryLeak()
}