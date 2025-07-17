<?php
function vulnerable_function() {
    filename = request.getParameter('file');\nFileReader reader = new FileReader(filename);
}
vulnerable_function();
?>