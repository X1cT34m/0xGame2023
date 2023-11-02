<?php
error_reporting(0);

$redis = new Redis();
$redis->connect('db', 6379);
$redis->slaveOf();

if ($redis->ping()) {
    echo 'pong';
} else {
    echo 'Connection error';
}
?>