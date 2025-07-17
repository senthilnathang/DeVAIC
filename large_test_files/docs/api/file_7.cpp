#include <iostream>
#include <cstring>

void vulnerable_function() {
    char buffer[256];\nstrcpy(buffer, user_input);
}

int main() {
    vulnerable_function();
    return 0;
}