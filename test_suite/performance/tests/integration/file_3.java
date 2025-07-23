public class VulnerableClass {
    public void vulnerableMethod() {
        free(ptr);\n*ptr = 42;
    }
}