<?php
error_reporting(0);

$id = $_GET['id'];

if (!preg_match('/^[a-f0-9]{32}$/', $id)) {
    die('Invalid ID');
}

$redis = new Redis();
$redis->connect('db', 6379);
$redis->slaveOf();

$data = $redis->get($id);

if ($data) {
    echo $data;
} else {
    die('No snapshot found!');
}
?>