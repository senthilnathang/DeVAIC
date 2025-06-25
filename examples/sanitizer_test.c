// Google Sanitizers Test File for C
// This file contains various memory safety issues that should be detected by sanitizer rules

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <pthread.h>

// AddressSanitizer Detection Examples
void buffer_overflow_example() {
    char buffer[10];
    // Buffer overflow-prone function - should trigger AddressSanitizer warning
    strcpy(buffer, "This string is way too long for the buffer");
    
    // Another dangerous function
    char input[100];
    gets(input);  // Should trigger AddressSanitizer warning
}

void use_after_free_example() {
    char* ptr = malloc(100);
    free(ptr);
    // Use after free - should trigger AddressSanitizer warning
    *ptr = 'x';
}

void double_free_example() {
    char* ptr = malloc(100);
    free(ptr);
    free(ptr);  // Double free - should trigger AddressSanitizer warning
}

void heap_buffer_overflow() {
    char* buffer = malloc(10);
    // Potential heap buffer overflow
    strcpy(buffer, "This is longer than 10 characters");
}

// ThreadSanitizer Detection Examples
int shared_counter = 0;  // Global variable accessed by threads

void* worker_thread(void* arg) {
    // Data race - accessing shared variable without synchronization
    shared_counter++;
    return NULL;
}

void thread_example() {
    pthread_t threads[2];
    
    // Creating threads that access shared data - should trigger ThreadSanitizer warning
    pthread_create(&threads[0], NULL, worker_thread, NULL);
    pthread_create(&threads[1], NULL, worker_thread, NULL);
    
    pthread_join(threads[0], NULL);
    pthread_join(threads[1], NULL);
}

void mutex_deadlock_example() {
    pthread_mutex_t mutex1, mutex2;
    
    pthread_mutex_init(&mutex1, NULL);
    pthread_mutex_init(&mutex2, NULL);
    
    // Potential deadlock - multiple mutex locks
    pthread_mutex_lock(&mutex1);
    pthread_mutex_lock(&mutex2);
    
    pthread_mutex_unlock(&mutex2);
    pthread_mutex_unlock(&mutex1);
}

// MemorySanitizer Detection Examples
void uninitialized_variable_example() {
    int uninitialized_var;  // Should trigger MemorySanitizer warning
    
    if (uninitialized_var > 0) {  // Using uninitialized variable
        printf("Positive\n");
    }
}

void malloc_without_init_example() {
    char* buffer = malloc(100);  // Should suggest MemorySanitizer
    
    // Using malloc'd memory without initialization
    if (buffer[0] == 'x') {
        printf("Found x\n");
    }
    
    free(buffer);
}

void stack_array_uninit() {
    char array[100];  // Uninitialized stack array
    
    // Using uninitialized array
    printf("First char: %c\n", array[0]);
}

// UndefinedBehaviorSanitizer Detection Examples
void integer_overflow_example() {
    int a = 1000000;
    int b = 2000000;
    int result = a * b * 3;  // Potential integer overflow
}

void null_pointer_example() {
    char* ptr = NULL;
    *ptr = 'x';  // Null pointer dereference
}

void format_string_example() {
    char user_input[] = "Hello %s %d";
    printf(user_input);  // Format string vulnerability
}

// LeakSanitizer Detection Examples
void memory_leak_example() {
    char* leaked_memory = malloc(1000);  // Memory leak - no corresponding free()
    // Missing free(leaked_memory);
}

int main() {
    printf("Testing Google Sanitizers detection patterns...\n");
    
    buffer_overflow_example();
    use_after_free_example();
    thread_example();
    uninitialized_variable_example();
    memory_leak_example();
    
    return 0;
}