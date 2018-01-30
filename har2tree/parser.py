#!/usr/bin/env python
# -*- coding: utf-8 -*-

from ete3 import TreeNode

try:
    from ete3 import TreeStyle, TextFace, add_face_to_node, ImgFace
    HAVE_PyQt = True
except ImportError:
    HAVE_PyQt = False

import os
import json
import copy
from datetime import datetime
import uuid
from urllib.parse import urlparse
from base64 import b64decode
from collections import defaultdict


class HarTreeNode(TreeNode):

    features_to_skip = ['dist', 'support']

    def __init__(self, **kwargs):
        super(HarTreeNode, self).__init__(**kwargs)
        self.add_feature('uuid', str(uuid.uuid4()))

    def to_dict(self):
        to_return = {'uuid': self.uuid}
        for feature in self.features:
            if feature in self.features_to_skip:
                continue
            to_return[feature] = getattr(self, feature)
        if not to_return.get('name'):
            to_return['name'] = 'root'
        if not self.is_leaf():
            to_return['children'] = []
        for child in self.children:
            to_return['children'].append(child.to_dict())
        return to_return

    def to_json(self):
        return json.dumps(self.to_dict())


class HostNode(HarTreeNode):

    def __init__(self, **kwargs):
        super(HostNode, self).__init__(**kwargs)
        # Do not add the URLs in the json dump
        self.features_to_skip.append('urls')


class URLNode(HarTreeNode):

    def __init__(self, **kwargs):
        super(URLNode, self).__init__(**kwargs)
        # Do not add the body in the json dump
        self.features_to_skip.append('body')


class CrawledTree(object):

    def __init__(self, harfiles):
        """ Load all the harfiles passed as parameter"""
        self.hartrees = self.load_all_harfiles(harfiles)
        self.root_hartree = None

    def load_all_harfiles(self, files):
        """Open all the HAR files"""
        loaded = []
        for har in files:
            with open(har, 'r') as f:
                har2tree = Har2Tree(json.load(f))
            if not har2tree.has_entries:
                continue
            har2tree.make_tree()
            loaded.append(har2tree)
        return loaded

    def find_parents(self):
        """Find all the trees where the first entry has a referer.
        Meaning: This is a sub-tree to attach to some other node.
        """
        self.referers = defaultdict(list)
        for hartree in self.hartrees:
            if hartree.root_referer:
                self.referers[hartree.root_referer].append(hartree)

    def join_trees(self, root=None, attach_to=None):
        if root is None:
            self.root_hartree = copy.deepcopy(self.hartrees[0])
            self.start_time = self.root_hartree.start_time
            self.user_agent = self.root_hartree.user_agent
            self.root_url = self.root_hartree.root_url
            root = self.root_hartree
            attach_to = root.url_tree
        if root.root_url_after_redirect:
            # If the first URL is redirected, the referer of the subtree
            # will be the redirect.
            sub_trees = self.referers.pop(root.root_url_after_redirect, None)
        else:
            sub_trees = self.referers.pop(root.root_url, None)
        if not sub_trees:
            # No subtree to attach
            return
        for sub_tree in sub_trees:
            to_attach = copy.deepcopy(sub_tree.url_tree)
            attach_to.add_child(to_attach)
            self.join_trees(sub_tree, to_attach)
        self.root_hartree.make_hostname_tree(self.root_hartree.url_tree, self.root_hartree.hostname_tree)

    def to_json(self):
        return self.root_hartree.to_json()

    def render_hostname_tree(self, tree_file):
        # NOTE: Requires PyQT stuff
        if not HAVE_PyQt:
            raise Exception('You need PyQt4 for exporting as image, please refer to the documentation.')
        self.root_hartree.hostname_tree.render(tree_file, tree_style=hostname_treestyle())


class Har2Tree(object):

    def __init__(self, har):
        self.har = har
        self.root_url_after_redirect = None
        self.root_referer = None
        self.all_hostnames = set()
        self.url_tree = URLNode()
        self.hostname_tree = HostNode()

        if not self.har['log']['entries']:
            self.has_entries = False
            return
        else:
            self.has_entries = True
        self.start_time = datetime.strptime(self.har['log']['entries'][0]['startedDateTime'], '%Y-%m-%dT%X.%fZ')
        for header in self.har['log']['entries'][0]['request']['headers']:
            if header['name'] == 'User-Agent':
                self.user_agent = header['value']
                break
        self.root_url = self.har['log']['entries'][0]['request']['url']
        self.set_root_after_redirect()
        self.set_root_referrer()

    def get_host_node_by_uuid(self, uuid):
        return self.hostname_tree.search_nodes(uuid=uuid)[0]

    def get_url_node_by_uuid(self, uuid):
        return self.url_tree.search_nodes(uuid=uuid)[0]

    def set_root_after_redirect(self):
        for e in self.har['log']['entries']:
            if e['response']['redirectURL']:
                self.root_url_after_redirect = e['response']['redirectURL']
                if not self.root_url_after_redirect.startswith('http'):
                    # internal redirect
                    parsed = urlparse(e['request']['url'])
                    parsed._replace(path=self.root_url_after_redirect)
                    self.root_url_after_redirect = '{}://{}{}'.format(parsed.scheme, parsed.netloc, self.root_url_after_redirect)
            else:
                break

    def to_json(self):
        return self.hostname_tree.to_json()

    def set_root_referrer(self):
        first_entry = self.har['log']['entries'][0]
        for h in first_entry['request']['headers']:
            if h['name'] == 'Referer':
                self.root_referer = h['value']
                break

    def render_tree_to_file(self, tree_file):
        # NOTE: Requires PyQT stuff
        if not HAVE_PyQt:
            raise Exception('You need PyQt4 for exporting as image, please refer to the documentation.')
        self.url_tree.render(tree_file, tree_style=url_treestyle())

    def make_hostname_tree(self, root_nodes_url, root_node_hostname):
        """ Groups all the URLs by domain in the hostname tree.
        `root_node_url` can be a list of nodes called by the same `root_node_hostname`
        """
        if not isinstance(root_nodes_url, list):
            root_nodes_url = [root_nodes_url]
        children_hostnames = {}
        sub_roots = defaultdict(list)
        for root_node_url in root_nodes_url:
            for child_node_url in root_node_url.get_children():
                if child_node_url.hostname is None:
                    # Probably a base64 encoded image
                    continue
                child_node_hostname = children_hostnames.get(child_node_url.hostname)
                if not child_node_hostname:
                    child_node_hostname = root_node_hostname.add_child(HostNode(name=child_node_url.hostname))
                    child_node_hostname.add_feature('urls', [child_node_url])
                    child_node_hostname.add_feature('request_cookie', 0)
                    child_node_hostname.add_feature('response_cookie', 0)
                    child_node_hostname.add_feature('js', 0)
                    child_node_hostname.add_feature('redirect', 0)
                    child_node_hostname.add_feature('redirect_to_nothing', 0)
                    children_hostnames[child_node_url.hostname] = child_node_hostname
                else:
                    child_node_hostname.urls.append(child_node_url)
                if hasattr(child_node_url, 'request_cookie'):
                    child_node_hostname.request_cookie += len(child_node_url.request_cookie)
                if hasattr(child_node_url, 'response_cookie'):
                    child_node_hostname.response_cookie += len(child_node_url.response_cookie)
                if hasattr(child_node_url, 'js'):
                    child_node_hostname.js += 1
                if hasattr(child_node_url, 'redirect'):
                    child_node_hostname.redirect += 1
                if hasattr(child_node_url, 'redirect_to_nothing'):
                    child_node_hostname.redirect_to_nothing += 1

                if not child_node_url.is_leaf():
                    sub_roots[child_node_hostname].append(child_node_url)
        for child_node_hostname, child_nodes_url in sub_roots.items():
            self.make_hostname_tree(child_nodes_url, child_node_hostname)

    def make_tree(self):
        all_requests = {}
        all_referer = defaultdict(list)
        if not self.har['log']['entries']:
            # No entries...
            return self.url_tree
        for entry in self.har['log']['entries'][1:]:
            all_requests[entry['request']['url']] = entry
            for h in entry['request']['headers']:
                if h['name'] == 'Referer':
                    if h['value'] == entry['request']['url'] or h['value'] == self.root_referer:
                        # Skip to avoid loops:
                        #   * referer to itself
                        #   * referer to root referer
                        continue
                    all_referer[h['value']].append(entry['request']['url'])
        self._make_subtree(all_referer, all_requests, self.url_tree, self.har['log']['entries'][0])
        # Initialize the hostname tree root
        self.hostname_tree.add_feature('name', self.url_tree.hostname)
        self.hostname_tree.add_feature('urls', [self.url_tree])
        self.hostname_tree.add_feature('request_cookie', 0)
        self.hostname_tree.add_feature('response_cookie', 0)
        self.hostname_tree.add_feature('js', 0)
        self.hostname_tree.add_feature('redirect', 0)
        self.hostname_tree.add_feature('redirect_to_nothing', 0)
        if hasattr(self.url_tree, 'request_cookie'):
            self.hostname_tree.request_cookie += len(self.url_tree.request_cookie)
        if hasattr(self.url_tree, 'response_cookie'):
            self.hostname_tree.response_cookie += len(self.url_tree.response_cookie)
        if hasattr(self.url_tree, 'js'):
            self.hostname_tree.js += 1
        if hasattr(self.url_tree, 'redirect'):
            self.hostname_tree.redirect += 1
        if hasattr(self.url_tree, 'redirect_to_nothing'):
            self.hostname_tree.redirect_to_nothing += 1
        self.make_hostname_tree(self.url_tree, self.hostname_tree)
        return self.url_tree

    def _make_subtree(self, all_referer, all_requests, root_node, url_entry):
        url = url_entry['request']['url']
        if not root_node.name:
            u_node = root_node
            u_node.add_feature('name', url)
        else:
            u_node = root_node.add_child(URLNode(name=url))
        u_node.add_feature('hostname', urlparse(url).hostname)
        u_node.add_feature('is_hostname', False)
        u_node.add_feature('response_cookie', url_entry['response']['cookies'])
        u_node.add_feature('request_cookie', url_entry['request']['cookies'])
        u_node.add_feature('empty_response', False)
        if url_entry['response']['content'].get('text'):
            u_node.add_feature('body', b64decode(url_entry['response']['content']['text']))
        u_node.add_feature('request', url_entry['request'])
        u_node.add_feature('response', url_entry['response'])
        self.all_hostnames.add(u_node.hostname)
        if url_entry['response']['content']['mimeType'].startswith('application/javascript') or url_entry['response']['content']['mimeType'].startswith('application/x-javascript'):
            u_node.add_feature('js', True)
        if url_entry['response']['content']['mimeType'].startswith('image'):
            u_node.add_feature('image', True)
        if url_entry['response']['content']['mimeType'].startswith('text/css'):
            u_node.add_feature('css', True)
        if url_entry['response']['content']['mimeType'].startswith('application/json'):
            u_node.add_feature('json', True)
        if not url_entry['response']['content'].get('text') or url_entry['response']['content']['text'] == '':
            u_node.add_feature('empty_response', True)

        if url_entry['response']['redirectURL']:
            url = url_entry['response']['redirectURL']
            u_node.add_feature('redirect', True)
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
                if all_requests.get(url + '/'):
                    url += '/'
                else:
                    u_node.add_feature('redirect_to_nothing', True)
                    return
            self._make_subtree(all_referer, all_requests, u_node, all_requests[url])
        elif all_referer.get(url):
            # URL loads other URL
            for u in all_referer.pop(url):
                self._make_subtree(all_referer, all_requests, u_node, all_requests[u])


def init_faces():
    # NOTE: Requires PyQT stuff
    def init_text_faces():
        face_request_cookie = TextFace('\U000027A1\U0001F36A')
        face_response_cookie = TextFace('\U00002B05\U0001F36A')
        face_javascript = TextFace('\U0001F41B')
        face_redirect = TextFace('\U000025B6')
        face_redirect_to_nothing = TextFace('¯\_(ツ)_/¯')
        return face_request_cookie, face_response_cookie, face_javascript, face_redirect, face_redirect_to_nothing

    def init_img_faces(path):
        face_request_cookie = ImgFace(os.path.join(path, "cookie_read.png"), height=16)
        face_response_cookie = ImgFace(os.path.join(path, "cookie_received.png"), height=16)
        face_javascript = ImgFace(os.path.join(path, "javascript.png"), height=16)
        face_redirect = ImgFace(os.path.join(path, "redirect.png"), height=16)
        face_redirect_to_nothing = ImgFace(os.path.join(path, "cookie_in_url.png"), height=16)
        return face_request_cookie, face_response_cookie, face_javascript, face_redirect, face_redirect_to_nothing

    img_path = os.path.join(os.path.abspath(os.path.dirname(__file__)), 'data', 'img')
    if img_path and os.path.exists(img_path):
        # Initialize image faces
        return init_img_faces(img_path)
    else:
        # Initialize default text faces
        return init_text_faces()


def url_treestyle():
    # NOTE: Requires PyQT stuff
    ts = TreeStyle()
    ts.show_leaf_name = False

    def my_layout(node):
        if node.is_root():
            F = TextFace(node.name, tight_text=True)
        else:
            if node.is_leaf():
                F = TextFace(node.name[:50], tight_text=True)
            else:
                F = TextFace(node.name, tight_text=True)
        add_face_to_node(F, node, column=5, position="branch-right")

    ts.layout_fn = my_layout
    return ts


def hostname_treestyle():
    # NOTE: Requires PyQT stuff
    ts = TreeStyle()
    ts.show_leaf_name = False
    face_request_cookie, face_response_cookie, face_javascript, face_redirect, face_redirect_to_nothing = init_faces()

    def my_layout(node):
        if node.is_root():
            node.add_face(TextFace(node.name, tight_text=True), column=0)
        else:
            # Tracking faces
            if node.request_cookie:
                node.add_face(face_request_cookie, column=0)
                node.add_face(TextFace(node.request_cookie), column=1)
            if node.response_cookie:
                node.add_face(face_response_cookie, column=0)
                node.add_face(TextFace(node.response_cookie), column=1)
            if node.js:
                node.add_face(face_javascript, column=0)
                node.add_face(TextFace(node.js), column=1)
            if node.redirect:
                node.add_face(face_redirect, column=0)
                node.add_face(TextFace(node.redirect), column=1)
            if node.redirect_to_nothing:
                node.add_face(face_redirect_to_nothing, column=0)
                node.add_face(TextFace(node.redirect_to_nothing), column=1)
            # Generic text faces
            if node.is_leaf():
                node.add_face(TextFace('{}'.format(node.name), tight_text=True), column=4)
            else:
                node.add_face(TextFace('{} ({})'.format(node.name, len(node.urls)), tight_text=True), column=4)
            # Modifies this node's style
            node.img_style["size"] = 2
            node.img_style["shape"] = "sphere"
            node.img_style["fgcolor"] = "#AA0000"

    ts.layout_fn = my_layout
    # ts.mode = "c"
    # ts.arc_start = -180
    # ts.arc_span = 360
    ts.branch_vertical_margin = 10
    return ts
