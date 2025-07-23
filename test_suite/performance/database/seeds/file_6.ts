function vulnerableFunction(): void {
    free(ptr);\n*ptr = 42;
}
vulnerableFunction();