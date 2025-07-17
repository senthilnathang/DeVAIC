public class VulnerableClass {
    public void vulnerableMethod() {
        filename = request.getParameter('file');\nFileReader reader = new FileReader(filename);
    }
}