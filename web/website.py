#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import json

from har2tree import Har2Tree, hostname_treestyle
from ete3_webserver import NodeActions, WebTreeHandler

from flask import Flask, render_template  # , request
from flask_bootstrap import Bootstrap

app = Flask(__name__)
Bootstrap(app)
app.config['BOOTSTRAP_SERVE_LOCAL'] = True
app.debug = True


def load_tree():
    with open('../tests/data/libe.har', 'r') as f:
        har = json.load(f)
        har2tree = Har2Tree(har)
    har2tree.make_tree()
    actions = NodeActions()
    style = hostname_treestyle()
    return WebTreeHandler(har2tree.hostname_tree, actions, style)


@app.route('/', methods=['GET'])
def index():
    tree = load_tree()
    nodes, faces, base64 = tree.redraw()
    return render_template('tree.html', nodes=nodes, faces=faces, base64_img=base64)

if __name__ == '__main__':
    load_tree()
    app.run(port=5001)
