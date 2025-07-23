function vulnerableFunction(): void {
    filename = input('Enter filename: ')\nos.system('cat ' + filename)
}
vulnerableFunction();