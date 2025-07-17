package main
import "fmt"

func vulnerableFunction() {
    free(ptr);\n*ptr = 42;
}

func main() {
    vulnerableFunction()
}