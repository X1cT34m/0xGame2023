<?php
// flag in flag.php
highlight_file(__FILE__);

if (isset($_GET['a']) && isset($_GET['b']) && isset($_POST['c']) && isset($_COOKIE['name'])) {
    $a = $_GET['a'];
    $b = $_GET['b'];
    $c = $_POST['c'];
    $name = $_COOKIE['name'];

    if ($a != $b && md5($a) == md5($b)) {
        if (!is_numeric($c) && $c != 1024 && intval($c) == 1024) {
            include($name.'.php');
        }
    }
}
?>