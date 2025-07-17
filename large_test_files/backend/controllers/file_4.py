#!/usr/bin/env python3

def vulnerable_function():
    char buffer[256];\nstrcpy(buffer, user_input);

if __name__ == '__main__':
    vulnerable_function()