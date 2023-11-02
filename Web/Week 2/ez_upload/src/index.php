<?php
session_start();

$user_dir = md5($_SERVER['REMOTE_ADDR']);

if (!file_exists('uploads/'.$user_dir)) {
    mkdir('uploads/'.$user_dir);
}
?>
<!DOCTYPE html>
<html>
    <head>
        <meta charset="utf-8"> 
        <title>Gravatar</title>
        <script src="https://cdn.bootcdn.net/ajax/libs/jquery/3.6.4/jquery.min.js"></script>
        <script src="https://cdn.bootcdn.net/ajax/libs/twitter-bootstrap/5.2.3/js/bootstrap.min.js"></script>
        <link href="https://cdn.bootcdn.net/ajax/libs/twitter-bootstrap/5.2.3/css/bootstrap.min.css" rel="stylesheet">
    </head>
    <body>
        <div class="container pt-5 p-5 my-5 border">
            <h1>Gravatar</h1>
            <p>Upload you personal avatar!</p>
            <p>Your upload path: <code><?='uploads/'.$user_dir.'/'?></code></p>
            <?php if (isset($_SESSION['avatar']) && file_exists($_SESSION['avatar'])) { ?>
                <p><img src="<?=$_SESSION['avatar']?>" class="rounded" width="200" height="200"></p>
            <?php } else { ?>
                <p>You have not uploaded your avatar yet!</p>
            <?php } ?>

            <div class="alert alert-info" id="msg" style="display:none"></div>
                <form onsubmit="upload(); return false;">
                    <div class="row">
                        <div class="col">
                            <input type="file" name="file" class="form-control" />
                        </div>
                        <div class="col">
                            <input type="submit" value="Upload" class="btn btn-primary"/>
                        </div>
                    </div>
                </form>
            </div>
        </div>
    </body>

    <script>
        function upload() {
            $.ajax({
                url: 'upload.php',
                type: 'POST',
                cache: false,
                data: new FormData($('form')[0]),
                processData: false,
                contentType: false,
                success: function (data) {
                    $('#msg').text(data).show();
                }
            });
        }
    </script>
</html>