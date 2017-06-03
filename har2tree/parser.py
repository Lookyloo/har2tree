#!/usr/bin/env python
# -*- coding: utf-8 -*-

from ete3 import Tree, TreeStyle, TextFace, add_face_to_node

try:
    from urllib.parse import urlparse
except ImportError:
    from urlparse import urlparse


class Har2Tree(object):

    def __init__(self, har):
        self.har = har

    def tree(self, tree_file):
        all_requests = {}
        all_referer = {}
        for entry in self.har['log']['entries']:
            all_requests[entry['request']['url']] = entry
            for h in entry['request']['headers']:
                if h['name'] == 'Referer':
                    if not all_referer.get(h['value']):
                        all_referer[h['value']] = []
                    all_referer[h['value']].append(entry['request']['url'])
        url_tree = Tree()
        self._make_subtree(url_tree, self.har['log']['entries'][0], all_referer, all_requests)
        # print(url_tree.get_ascii(show_internal=True))
        # url_tree.show()
        ts = TreeStyle()
        ts.show_leaf_name = False

        def my_layout(node):
            if node.is_root():
                F = TextFace(node.name, tight_text=True)
            else:
                if node.js and node.cookie:
                    fgcolor = 'red'
                elif node.cookie:
                    fgcolor = 'yellow'
                elif node.js:
                    fgcolor = 'blue'
                else:
                    fgcolor = 'black'
                if node.is_leaf():
                    F = TextFace(node.name[:50], tight_text=True, fgcolor=fgcolor)
                else:
                    F = TextFace(node.hostname, tight_text=True, fgcolor=fgcolor)
            add_face_to_node(F, node, column=0, position="branch-right")

        ts.layout_fn = my_layout
        url_tree.render(tree_file, tree_style=ts)

    def _make_subtree(self, root_node, url_entry, all_referer, all_requests):
        url = url_entry['request']['url']
        u_node = root_node.add_child(name=url)
        u_node.add_feature('hostname', urlparse(url).hostname)
        if url_entry['response']['cookies']:
            u_node.add_feature('cookie', True)
        else:
            u_node.add_feature('cookie', False)
        if url_entry['response']['content']['mimeType'].startswith('application/javascript'):
            u_node.add_feature('js', True)
        else:
            u_node.add_feature('js', False)

        if url_entry['response']['redirectURL']:
            url = url_entry['response']['redirectURL']
            if not url.startswith('http'):
                # internal redirect
                parsed = urlparse(url_entry['request']['url'])
                parsed._replace(path=url)
                url = '{}://{}{}'.format(parsed.scheme, parsed.netloc, url)
            if not all_requests.get(url):
                url += '/'
            self._make_subtree(u_node, all_requests[url], all_referer, all_requests)
        elif all_referer.get(url):
            # URL loads other URL
            for u in all_referer.get(url):
                self._make_subtree(u_node, all_requests[u], all_referer, all_requests)
