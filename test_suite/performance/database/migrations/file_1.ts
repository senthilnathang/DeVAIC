function vulnerableFunction(): void {
    filename = request.getParameter('file');\nFileReader reader = new FileReader(filename);
}
vulnerableFunction();