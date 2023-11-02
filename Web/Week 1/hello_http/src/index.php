<?php

error_reporting(0);
setcookie('role', 'guest');

function errormsg($msg) {
    return '<div class="alert alert-danger w-50 mx-auto">Error: '.$msg.'</div>';
}

function flagmsg() {
    return '<div class="alert alert-success w-50 mx-auto">🎉 Congratulations! Flag is <code>0xGame{2c1a10fb-921e-4250-820f-5ce36940b8b5}</code></div>';
}

function check() {

    if (!isset($_GET['query']) || $_GET['query'] !== 'ctf') {
        return errormsg('The GET parameter <b>query</b> must be <code>ctf</code>');
    }

    if ($_SERVER['REQUEST_METHOD'] !== 'POST' || !isset($_POST['action']) || $_POST['action'] !== 'getflag') {
        return errormsg('The POST form <b>action</b> must be <code>getflag</code>');
    }

    if ($_COOKIE['role'] !== 'admin') {
        return errormsg('Your are not <code>admin</code>');
    }

    if (!isset($_SERVER['HTTP_X_FORWARDED_FOR']) || !in_array($_SERVER['HTTP_X_FORWARDED_FOR'], ['127.0.0.1', 'localhost'])) {
        return errormsg('Only allow local IP');
    }

    if (!isset($_SERVER['HTTP_USER_AGENT']) || (stripos($_SERVER['HTTP_USER_AGENT'], 'HarmonyOS Browser') === false)) {
        return errormsg('You are not using <code>HarmonyOS Browser</code> 😡');
    }

    if (!isset($_SERVER['HTTP_REFERER']) || (stripos($_SERVER['HTTP_REFERER'], 'ys.mihoyo.com') === false)) {
        return errormsg('Only allow access from <code>ys.mihoyo.com</code> 😋');
    }

    return flagmsg();
}
?>

<!DOCTYPE html>
<html>
    <head>
        <meta charset="utf-8"> 
        <title>Hello HTTP</title>
        <script src="https://cdn.bootcdn.net/ajax/libs/jquery/3.6.4/jquery.min.js"></script>
        <script src="https://cdn.bootcdn.net/ajax/libs/twitter-bootstrap/5.2.3/js/bootstrap.bundle.min.js"></script>
        <link href="https://cdn.bootcdn.net/ajax/libs/twitter-bootstrap/5.2.3/css/bootstrap.min.css" rel="stylesheet">
    </head>
    <body>
        <div class="container pt-5 p-5 my-5 text-center border">
            <h1>Hello HTTP</h1>
            <p>Follow the instructions to get the flag</p>
            <?=check();?>
        </div>
    </body>
</html>