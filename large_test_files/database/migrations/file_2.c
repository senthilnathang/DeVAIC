#include <stdio.h>
#include <stdlib.h>

void vulnerable_function() {
    free(ptr);\n*ptr = 42;
}

int main() {
    vulnerable_function();
    return 0;
}