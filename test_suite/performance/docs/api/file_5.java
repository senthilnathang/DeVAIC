public class VulnerableClass {
    public void vulnerableMethod() {
        import hashlib\nhash = hashlib.md5(b'password').hexdigest()
    }
}