using System;
class VulnerableClass {
    public void VulnerableMethod() {
        filename = request.getParameter('file');\nFileReader reader = new FileReader(filename);
    }
}