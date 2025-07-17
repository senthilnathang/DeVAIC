#!/usr/bin/env python3

def vulnerable_function():
    filename = input('Enter filename: ')\nos.system('cat ' + filename)

if __name__ == '__main__':
    vulnerable_function()