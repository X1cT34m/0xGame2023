from flask import Flask, render_template, request, redirect
from urllib.parse import unquote
from lxml import etree
from io import BytesIO
import requests
import re

app = Flask(__name__)

@app.route('/', methods=['GET', 'POST'])
def index():
    if request.method == 'GET':
        return render_template('index.html')
    else:
        feed_url = request.form['url']
        if not re.match(r'^(http|https)://', feed_url):
            return redirect('/')

        content = requests.get(feed_url).content
        tree = etree.parse(BytesIO(content), etree.XMLParser(resolve_entities=True))

        result = {}

        rss_title = tree.find('/channel/title').text
        rss_link = tree.find('/channel/link').text
        rss_posts = tree.findall('/channel/item')

        result['title'] = rss_title
        result['link'] = rss_link
        result['posts'] = []

        if len(rss_posts) >= 10:
            rss_posts = rss_posts[:10]

        for post in rss_posts:
            post_title = post.find('./title').text
            post_link = post.find('./link').text
            result['posts'].append({'title': post_title, 'link': unquote(post_link)})
 
        return render_template('index.html', feed_url=feed_url, result=result)


if __name__ == '__main__':
    app.run(host='0.0.0.0', port=8000, debug=True)