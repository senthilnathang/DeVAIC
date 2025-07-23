#include <stdio.h>
#include <stdlib.h>

void vulnerable_function() {
    innerHTML = '<div>' + user_input + '</div>';
}

int main() {
    vulnerable_function();
    return 0;
}