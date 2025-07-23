#include <iostream>
#include <string>
#include <cstring>
#include <memory>

// CPP001, CPP003 - Raw pointer allocation without proper deallocation
void memory_leak_example() {
    int* leaked_memory = new int[1000];  // Memory leak - no delete[]
    
    char* another_leak = new char[256];  // Another memory leak
    // Missing delete[] another_leak;
}

// CPP002 - C-style memory management in C++
void c_style_memory() {
    char* buffer = (char*)malloc(512);
    // Missing free(buffer);
}

// CPP004 - Unsafe C functions in C++
void unsafe_functions() {
    char dest[10];
    char src[] = "This string is too long for dest buffer";
    
    strcpy(dest, src);  // Buffer overflow vulnerability
    strcat(dest, " more text");  // Potential buffer overflow
    
    char format_str[100];
    sprintf(format_str, "User input: %s", src);  // Unsafe formatting
}

// CPP005, CPP006 - Exception safety issues
void exception_problems() {
    try {
        throw std::runtime_error("Something went wrong");
    } catch (...) {  // Generic catch-all - information loss
        // Not handling specific exceptions
    }
    
    // Function that throws without noexcept specification
    throw std::invalid_argument("Bad argument");
}

// CPP007 - Iterator invalidation
void iterator_issues() {
    std::vector<int> vec = {1, 2, 3, 4, 5};
    
    for (auto it = vec.begin(); it != vec.end(); ++it) {
        if (*it == 3) {
            vec.erase(it);  // Iterator invalidation - undefined behavior
        }
    }
}

// CPP008 - std::find without proper checking
void find_without_check() {
    std::vector<int> numbers = {1, 2, 3, 4, 5};
    
    auto result = std::find(numbers.begin(), numbers.end(), 10);
    std::cout << *result << std::endl;  // Potential dereference of end() iterator
}

// CPP009 - Unsafe static_cast with pointers
void unsafe_casting() {
    int value = 42;
    int* int_ptr = &value;
    
    char* char_ptr = static_cast<char*>(static_cast<void*>(int_ptr));  // Dangerous cast
    *char_ptr = 'A';  // Potential undefined behavior
}

// CPP010 - Dangerous reinterpret_cast
void dangerous_reinterpret() {
    int number = 0x12345678;
    char* bytes = reinterpret_cast<char*>(&number);  // Very dangerous cast
    
    // Modifying through reinterpreted pointer
    bytes[0] = 0xFF;
}

// Multiple issues in one function
class UnsafeClass {
private:
    char* buffer;
    size_t size;
    
public:
    UnsafeClass(size_t s) : size(s) {
        buffer = new char[size];  // Raw pointer - should use smart pointer
    }
    
    ~UnsafeClass() {
        // Missing delete[] buffer; - memory leak
    }
    
    void copy_data(const char* source) {
        strcpy(buffer, source);  // No bounds checking - buffer overflow
    }
    
    void unsafe_access(int index) {
        // No bounds checking
        buffer[index] = 'X';  // Potential out-of-bounds access
    }
};

int main() {
    memory_leak_example();
    c_style_memory();
    unsafe_functions();
    exception_problems();
    iterator_issues();
    find_without_check();
    unsafe_casting();
    dangerous_reinterpret();
    
    UnsafeClass unsafe_obj(10);
    unsafe_obj.copy_data("This might be too long for the buffer allocated");
    unsafe_obj.unsafe_access(100);  // Out of bounds access
    
    return 0;
}