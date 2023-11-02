<?php

function sanitize($s) {
    $s = str_replace(';', '', $s);
    $s = str_replace(' ', '', $s);
    $s = str_replace('/', '', $s);
    $s = str_replace('flag', '', $s);
    return $s;
}

if (isset($_GET['source'])) {
    highlight_file(__FILE__);
    die();
}

if (!isset($_POST['ip'])) {
    die('No IP Address');
}

$ip = $_POST['ip'];

$ip = sanitize($ip);

if (!preg_match('/((\d{1,2}|1\d\d|2[0-4]\d|25[0-5])\.){3}(\d{1,2}|1\d\d|2[0-4]\d|25[0-5])/', $ip)) {
    die('Invalid IP Address');
}

system('ping -c 4 '.$ip. ' 2>&1');

?>