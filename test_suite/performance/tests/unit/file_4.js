function vulnerableFunction() {
    import hashlib\nhash = hashlib.md5(b'password').hexdigest()
}
vulnerableFunction();