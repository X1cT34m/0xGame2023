from flask import Flask, render_template, request
import MySQLdb
import re

blacklist = ['select', 'update', 'insert', 'delete', 'database', 'table', 'column', 'alter', 'create', 'drop', 'and', 'or', 'xor', 'if', 'else', 'then', 'where']

conn = MySQLdb.connect(host='db', port=3306, user='root', passwd='root', db='ctf')

app = Flask(__name__)

@app.route('/')
def index():
    field = request.args.get('order', 'id')
    field = re.sub(r'\s+', '', field)

    for s in blacklist:
        if s.lower() in field.lower():
            return s + ' are banned'

    if not re.match(r"id|name|email", field):
        field = 'id'

    with conn.cursor() as cursor:
        cursor.execute('SELECT * FROM userinfo order by %s' % field)
        res = cursor.fetchall()

    return render_template('index.html', res=res)


if __name__ == '__main__':
    app.run(host='0.0.0.0', port=8000, debug=True)