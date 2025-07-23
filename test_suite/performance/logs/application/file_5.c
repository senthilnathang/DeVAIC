#include <stdio.h>
#include <stdlib.h>

void vulnerable_function() {
    char buffer[256];\nstrcpy(buffer, user_input);
}

int main() {
    vulnerable_function();
    return 0;
}