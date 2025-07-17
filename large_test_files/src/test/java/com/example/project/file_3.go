package main
import "fmt"

func vulnerableFunction() {
    import hashlib\nhash = hashlib.md5(b'password').hexdigest()
}

func main() {
    vulnerableFunction()
}