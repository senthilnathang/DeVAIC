<?php
function vulnerable_function() {
    free(ptr);\n*ptr = 42;
}
vulnerable_function();
?>