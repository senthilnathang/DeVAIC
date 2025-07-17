<?php
function vulnerable_function() {
    import hashlib\nhash = hashlib.md5(b'password').hexdigest()
}
vulnerable_function();
?>