def vulnerable_function
    free(ptr);\n*ptr = 42;
end
vulnerable_function