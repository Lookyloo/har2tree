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
        self.all_hostnames = set()
        self.url_tree = Tree()

    def process_tree(self, root_node):
        if root_node.is_leaf():
            return
        domains_nodes = {}
        for c in root_node.get_children():
            if not domains_nodes.get(c.hostname):
                domain = root_node.add_child(name=c.hostname)
                domain.add_feature('is_domain', True)
                domains_nodes[c.hostname] = domain
            else:
                domain = domains_nodes.get(c.hostname)
            c.detach()
            domain.add_child(child=c)
            self.process_tree(c)

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
        self._make_subtree(self.url_tree, self.har['log']['entries'][0], all_referer, all_requests)
        childs = self.url_tree.children
        self.process_tree(childs[0])
        # print(url_tree.get_ascii(show_internal=True))
        # url_tree.show()
        ts = TreeStyle()
        ts.show_leaf_name = False

        def my_layout(node):
            if node.is_root():
                F = TextFace(node.name, tight_text=True)
            elif node.is_domain:
                F = TextFace(node.name, tight_text=True, fgcolor='blue')
            else:
                if node.is_leaf():
                    F = TextFace(node.name[:50], tight_text=True)
                else:
                    F = TextFace(node.hostname, tight_text=True)
            add_face_to_node(F, node, column=5, position="branch-right")

        ts.layout_fn = my_layout
        self.url_tree.render(tree_file, tree_style=ts)

    def _make_subtree(self, root_node, url_entry, all_referer, all_requests):
        url = url_entry['request']['url']
        u_node = root_node.add_child(name=url)
        u_node.add_feature('hostname', urlparse(url).hostname)
        u_node.add_feature('is_domain', False)
        u_node.add_feature('response_cookie', False)
        u_node.add_feature('request_cookie', False)
        u_node.add_feature('js', False)
        self.all_hostnames.add(u_node.hostname)
        if url_entry['request']['cookies']:
            u_node.add_feature('request_cookie', True)
            u_node.add_face(TextFace('\U000027A1\U0001F36A'), column=0)
        if url_entry['response']['cookies']:
            u_node.add_feature('response_cookie', True)
            u_node.add_face(TextFace('\U00002B05\U0001F36A'), column=0)
        if url_entry['response']['content']['mimeType'].startswith('application/javascript'):
            u_node.add_feature('js', True)
            u_node.add_face(TextFace('\U0001F41B'), column=0)
        if url_entry['response']['redirectURL']:
            url = url_entry['response']['redirectURL']
            u_node.add_face(TextFace('\U000025B6'), column=0)
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
