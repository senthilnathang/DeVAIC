#include <iostream>
#include <cstring>

void vulnerable_function() {
    import hashlib\nhash = hashlib.md5(b'password').hexdigest()
}

int main() {
    vulnerable_function();
    return 0;
}