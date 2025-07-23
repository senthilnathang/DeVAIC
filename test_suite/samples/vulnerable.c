#include <stdio.h>
#include <string.h>
#include <stdlib.h>

// Example of buffer overflow vulnerability
void unsafe_copy(char* input) {
    char buffer[10];
    strcpy(buffer, input);  // Vulnerable: no bounds checking
    printf("Buffer contains: %s\n", buffer);
}

// Example of format string vulnerability
void unsafe_print(char* user_input) {
    printf(user_input);  // Vulnerable: user input used as format string
}

// Example of potential integer overflow
int calculate_size(int user_value) {
    int result = user_value * 1024;  // Vulnerable: no overflow check
    return result;
}

// Example of null pointer dereference
void process_data(char* data) {
    // Vulnerable: no null check before dereference
    int len = strlen(data);
    printf("Data length: %d\n", len);
}

int main() {
    char input[100];
    printf("Enter data: ");
    gets(input);  // Vulnerable: gets() is unsafe
    
    unsafe_copy(input);
    unsafe_print(input);
    
    int size = calculate_size(atoi(input));
    printf("Calculated size: %d\n", size);
    
    process_data(NULL);  // This will cause null pointer dereference
    
    return 0;
}