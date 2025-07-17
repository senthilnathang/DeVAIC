function vulnerableFunction() {
    free(ptr);\n*ptr = 42;
}
vulnerableFunction();