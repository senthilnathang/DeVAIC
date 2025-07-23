#!/usr/bin/env python3

def vulnerable_function():
    free(ptr);\n*ptr = 42;

if __name__ == '__main__':
    vulnerable_function()