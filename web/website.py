#!/usr/bin/env python
# -*- coding: utf-8 -*-

from har2tree import Har2Tree, setup_treestyle
import json

from ete3 import WebTreeApplication


application = WebTreeApplication()
application.CONFIG["temp_dir"] = './tmp/'
application.CONFIG["temp_url"] = 'tmp'
application.CONFIG["DISPLAY"] = ":0"


with open('../tests/data/libe.har', 'r') as f:
    har = json.load(f)
    har2tree = Har2Tree(har)

application.set_tree_loader(har2tree.make_tree)
application.set_tree_style(setup_treestyle())
