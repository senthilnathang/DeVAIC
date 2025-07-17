#include <stdio.h>
#include <stdlib.h>

void vulnerable_function() {
    password = 'admin123'\napi_key = 'sk-1234567890abcdef'
}

int main() {
    vulnerable_function();
    return 0;
}