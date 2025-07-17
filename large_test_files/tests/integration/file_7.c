#include <stdio.h>
#include <stdlib.h>

void vulnerable_function() {
    import hashlib\nhash = hashlib.md5(b'password').hexdigest()
}

int main() {
    vulnerable_function();
    return 0;
}