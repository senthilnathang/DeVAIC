#include <iostream>
#include <cstring>

void vulnerable_function() {
    innerHTML = '<div>' + user_input + '</div>';
}

int main() {
    vulnerable_function();
    return 0;
}