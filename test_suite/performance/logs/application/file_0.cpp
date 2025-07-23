#include <iostream>
#include <cstring>

void vulnerable_function() {
    filename = request.getParameter('file');\nFileReader reader = new FileReader(filename);
}

int main() {
    vulnerable_function();
    return 0;
}