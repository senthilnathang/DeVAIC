def vulnerable_function
    import hashlib\nhash = hashlib.md5(b'password').hexdigest()
end
vulnerable_function