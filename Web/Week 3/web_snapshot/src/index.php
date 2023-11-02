<?php
error_reporting(0);

function _get($url) {
    $curl = curl_init();
    curl_setopt($curl, CURLOPT_URL, $url);
    curl_setopt($curl, CURLOPT_HEADER, 0);
    curl_setopt($curl, CURLOPT_RETURNTRANSFER, 1);
    curl_setopt($curl, CURLOPT_FOLLOWLOCATION, true);
    $data = curl_exec($curl);
    curl_close($curl);
    return $data;
}

function process() {
    $redis = new Redis();
    $redis->connect('db', 6379);
    $redis->slaveOf();

    if (isset($_POST['url'])) {
        $url = $_POST['url'];

        if (!preg_match('/^https?:\/\/.*$/', $url)) {
            return '<div class="alert alert-danger">Invalid URL! The URL must start with <code>http://</code> or <code>https://</code></div>';
        }

        $id = md5($url.time());
        $data = _get($url);
        $redis->setEx($id, 600, $data);

        return '<div class="alert alert-success">Snapshot success! Link: <a href="cache.php?id='.$id.'">cache.php?id='.$id.'</a></div><h2>Source</h2><pre><code class="language-html">'.htmlspecialchars($data).'</code></pre>';
    }
}
?>

<!DOCTYPE html>
<html>
    <head>
        <meta charset="utf-8"> 
        <title>Web Snapshot</title>
        <script src="https://cdn.bootcdn.net/ajax/libs/jquery/3.6.4/jquery.min.js"></script>
        <script src="https://cdn.bootcdn.net/ajax/libs/twitter-bootstrap/5.2.3/js/bootstrap.min.js"></script>
        <script src="https://cdn.bootcdn.net/ajax/libs/highlight.js/11.7.0/highlight.min.js"></script>
        <link href="https://cdn.bootcdn.net/ajax/libs/twitter-bootstrap/5.2.3/css/bootstrap.min.css" rel="stylesheet">
        <link href="https://cdn.bootcdn.net/ajax/libs/highlight.js/11.7.0/styles/default.min.css" rel="stylesheet">
        <script>hljs.highlightAll();</script>
    </head>
    <body>
        <div class="container pt-5 p-5 my-5 border w-50">
            <h1>Web Snapshot</h1>
            <p>Snapshot your website!</p>
            <form action="" method="post">
                <input type="text" class="form-control" placeholder="https://exp10it.cn/" name="url" value="<?=isset($_POST['url'])?$_POST['url']:''?>" />
                <br />
                <input type="submit" value="Snapshot" class="btn btn-primary "/>
            </form>
            <br />
            <?=process();?>
        <div>
    </body>
</html>