#include <stdio.h>
#include <stdlib.h>
#include <string.h>

/**
 * Test file in nested directory with C vulnerabilities
 */

void nested_buffer_overflow() {
    char buffer[256];
    char *user_input = getenv("USER_INPUT");
    
    // CWE-787: Buffer overflow
    strcpy(buffer, user_input);
    printf("Buffer: %s\n", buffer);
}

void nested_use_after_free() {
    char *ptr = malloc(100);
    free(ptr);
    
    // CWE-416: Use after free
    *ptr = 'X';
}

void nested_command_injection() {
    char command[512];
    char *filename = getenv("FILENAME");
    
    // CWE-78: Command injection
    sprintf(command, "cat %s", filename);
    system(command);
}

int main() {
    nested_buffer_overflow();
    nested_use_after_free();
    nested_command_injection();
    return 0;
}