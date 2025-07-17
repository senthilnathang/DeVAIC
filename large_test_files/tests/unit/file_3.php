<?php
function vulnerable_function() {
    innerHTML = '<div>' + user_input + '</div>';
}
vulnerable_function();
?>