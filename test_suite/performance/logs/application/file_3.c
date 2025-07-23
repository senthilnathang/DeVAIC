#include <stdio.h>
#include <stdlib.h>

void vulnerable_function() {
    filename = input('Enter filename: ')\nos.system('cat ' + filename)
}

int main() {
    vulnerable_function();
    return 0;
}