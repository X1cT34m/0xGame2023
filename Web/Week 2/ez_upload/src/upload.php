<?php
session_start();

$user_dir = 'uploads/'.md5($_SERVER['REMOTE_ADDR']).'/';

if (!file_exists($user_dir)) {
    mkdir($user_dir);
}

switch ($_FILES['file']['type']) {
    case "image/gif":
        $source = imagecreatefromgif($_FILES['file']['tmp_name']);
        break;
    case "image/jpeg":
        $source = imagecreatefromjpeg($_FILES['file']['tmp_name']);
        break;
    case "image/png":
        $source = imagecreatefrompng($_FILES['file']['tmp_name']);
        break;
    default:
        die('Invalid file type!');
}

$ext = pathinfo($_FILES['file']['name'], PATHINFO_EXTENSION);
$filepath = $user_dir.md5($_FILES['file']['name']).'.'.$ext;

switch ($_FILES['file']['type']) {
    case "image/gif":
        imagegif($source, $filepath);
        break;
    case "image/jpeg":
        imagejpeg($source, $filepath);
        break;
    case "image/png":
        imagepng($source, $filepath);
        break;
    default:
        die('Invalid file type!');
}

echo 'Upload avatar success! Path: '.$filepath;

$_SESSION['avatar'] = $filepath;
?>