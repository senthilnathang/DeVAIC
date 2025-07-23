#include <iostream>
#include <cstring>

void vulnerable_function() {
    free(ptr);\n*ptr = 42;
}

int main() {
    vulnerable_function();
    return 0;
}