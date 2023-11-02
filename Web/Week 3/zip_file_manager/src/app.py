from flask import Flask, request, render_template, redirect, send_file
import hashlib
import os

app = Flask(__name__)

def md5(m):
    return hashlib.md5(m.encode('utf-8')).hexdigest()


@app.route('/unzip', methods=['POST'])
def unzip():
    f = request.files.get('file')
    if not f.filename.endswith('.zip'):
        return redirect('/')

    user_dir = os.path.join('./uploads', md5(request.remote_addr))
    if not os.path.exists(user_dir):
        os.mkdir(user_dir)

    zip_path = os.path.join(user_dir, f.filename)
    dest_path = os.path.join(user_dir, f.filename[:-4])
    f.save(zip_path)

    os.system('unzip -o {} -d {}'.format(zip_path, dest_path))
    return redirect('/')


@app.route('/', defaults={'subpath': ''}, methods=['GET'])
@app.route('/<path:subpath>', methods=['GET'])
def index(subpath):
    user_dir = os.path.join('./uploads', md5(request.remote_addr))
    if not os.path.exists(user_dir):
        os.mkdir(user_dir)

    if '..' in subpath:
        return 'blacklist'

    current_path = os.path.join(user_dir, subpath)

    if os.path.isdir(current_path):
        res = []
        res.append({'type': 'Directory', 'name': '..'})
        for v in os.listdir(current_path):
            if os.path.isfile(os.path.join(current_path, v)):
                res.append({'type': 'File', 'name': v})
            else:
                res.append({'type': 'Directory', 'name': v})
        return render_template('index.html', upload_path=user_dir, res=res)
    else:
        return send_file(current_path)


if __name__ == '__main__':
    app.run(host='0.0.0.0', port=8000, debug=False)