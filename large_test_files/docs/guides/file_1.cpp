#include <iostream>
#include <cstring>

void vulnerable_function() {
    user_id = input('Enter ID: ')\nquery = 'SELECT * FROM users WHERE id = ' + user_id
}

int main() {
    vulnerable_function();
    return 0;
}