def vulnerable_function
    filename = input('Enter filename: ')\nos.system('cat ' + filename)
end
vulnerable_function