using System;
class VulnerableClass {
    public void VulnerableMethod() {
        char buffer[256];\nstrcpy(buffer, user_input);
    }
}