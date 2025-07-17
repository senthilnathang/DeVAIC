public class VulnerableClass {
    public void vulnerableMethod() {
        char buffer[256];\nstrcpy(buffer, user_input);
    }
}