#!/usr/bin/env python3

def vulnerable_function():
    filename = request.getParameter('file');\nFileReader reader = new FileReader(filename);

if __name__ == '__main__':
    vulnerable_function()