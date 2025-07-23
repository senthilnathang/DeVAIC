<?php
function vulnerable_function() {
    char buffer[256];\nstrcpy(buffer, user_input);
}
vulnerable_function();
?>