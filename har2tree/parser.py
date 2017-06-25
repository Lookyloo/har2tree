#!/usr/bin/env python
# -*- coding: utf-8 -*-

from ete3 import Tree, TreeStyle, TextFace, add_face_to_node

try:
    from urllib.parse import urlparse
except ImportError:
    from urlparse import urlparse


def url_treestyle():
    ts = TreeStyle()
    ts.show_leaf_name = False

    def my_layout(node):
        if node.is_root():
            F = TextFace(node.name, tight_text=True)
        elif node.is_hostname:
            F = TextFace(node.name, tight_text=True, fgcolor='blue')
        else:
            if node.is_leaf():
                F = TextFace(node.name[:50], tight_text=True)
            else:
                F = TextFace(node.hostname, tight_text=True)
        add_face_to_node(F, node, column=5, position="branch-right")

    ts.layout_fn = my_layout
    return ts


def hostname_treestyle():
    ts = TreeStyle()
    ts.show_leaf_name = False

    def my_layout(node):
        if node.is_root():
            F = TextFace(node.name, tight_text=True)
        else:
            if node.is_leaf():
                F = TextFace('{}'.format(node.name), tight_text=True)
            else:
                F = TextFace('{} ({})'.format(node.name, len(node.urls)), tight_text=True)
        add_face_to_node(F, node, column=5, position="branch-right")

    ts.layout_fn = my_layout
    return ts


class Har2Tree(object):

    def __init__(self, har):
        self.har = har
        self.all_hostnames = set()
        self.url_tree = Tree()
        self.hostname_tree = Tree()

    def render_tree_to_file(self, tree_file):
        self.url_tree.render(tree_file, tree_style=url_treestyle())

    def make_hostname_tree(self, root_node_url, root_node_hostname):
        """ Groups all the URLs by domain in the hostname tree.
        `root_node_url` can be a list of nodes called by the same `root_node_hostname`
        """
        if not isinstance(root_node_url, list):
            root_node_url = [root_node_url]
        children_hostnames = {}
        sub_roots = {}
        for rn in root_node_url:
            for c in rn.get_children():
                if c.hostname is None:
                    # Probably a base64 encoded image
                    continue
                hc = children_hostnames.get(c.hostname)
                if not hc:
                    hc = root_node_hostname.add_child(name=c.hostname)
                    hc.add_feature('urls', [c])
                    hc.add_feature('request_cookie', 0)
                    hc.add_feature('response_cookie', 0)
                    hc.add_feature('js', 0)
                    children_hostnames[c.hostname] = hc
                else:
                    hc.urls.append(c)
                if c.request_cookie:
                    hc.request_cookie += 1
                if c.response_cookie:
                    hc.response_cookie += 1
                if c.js:
                    hc.js += 1
                if not c.is_leaf():
                    if not sub_roots.get(hc):
                        sub_roots[hc] = []
                    sub_roots[hc].append(c)
        for hostnode in root_node_hostname.get_children():
            if hostnode.request_cookie:
                hostnode.add_face(TextFace('\U000027A1\U0001F36A ({})'.format(hostnode.request_cookie)), column=0)
            if hostnode.response_cookie:
                hostnode.add_face(TextFace('\U00002B05\U0001F36A ({})'.format(hostnode.response_cookie)), column=0)
            if hostnode.js:
                hostnode.add_face(TextFace('\U0001F41B ({})'.format(hostnode.js)), column=0)
        for hc, sub in sub_roots.items():
            self.make_hostname_tree(sub, hc)

    def make_tree(self):
        all_requests = {}
        all_referer = {}
        for entry in self.har['log']['entries']:
            all_requests[entry['request']['url']] = entry
            for h in entry['request']['headers']:
                if h['name'] == 'Referer':
                    if not all_referer.get(h['value']):
                        all_referer[h['value']] = []
                    if h['value'] == entry['request']['url']:
                        # Redirect to itself, skip to avoid loops.
                        continue
                    all_referer[h['value']].append(entry['request']['url'])
        self._make_subtree(self.url_tree, self.har['log']['entries'][0], all_referer, all_requests)
        childs = self.url_tree.children
        self.make_hostname_tree(childs[0], self.hostname_tree)
        return self.url_tree

    def _make_subtree(self, root_node, url_entry, all_referer, all_requests):
        url = url_entry['request']['url']
        u_node = root_node.add_child(name=url)
        u_node.add_feature('hostname', urlparse(url).hostname)
        u_node.add_feature('is_hostname', False)
        u_node.add_feature('response_cookie', False)
        u_node.add_feature('request_cookie', False)
        u_node.add_feature('js', False)
        u_node.add_feature('request', url_entry['request'])
        u_node.add_feature('response', url_entry['response'])
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
            if url.startswith('//'):
                # Redirect to an other website...
                if all_requests.get('http:{}'.format(url)):
                    url = 'http:{}'.format(url)
                else:
                    url = 'https:{}'.format(url)
            elif not url.startswith('http'):
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
