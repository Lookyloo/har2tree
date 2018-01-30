#!/usr/bin/env python
# -*- coding: utf-8 -*-

from ete3 import TreeNode

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
        to_return = {'uuid': self.uuid, 'children': []}
        for feature in self.features:
            if feature in self.features_to_skip:
                continue
            to_return[feature] = getattr(self, feature)

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

        self.add_feature('urls', [])
        self.add_feature('request_cookie', 0)
        self.add_feature('response_cookie', 0)
        self.add_feature('js', 0)
        self.add_feature('redirect', 0)
        self.add_feature('redirect_to_nothing', 0)

    def add_url(self, url):
        if not self.name:
            # Only used when initializing the root node
            self.add_feature('name', url.hostname)
        self.urls.append(url)
        if hasattr(url, 'request_cookie'):
            self.request_cookie += len(url.request_cookie)
        if hasattr(url, 'response_cookie'):
            self.response_cookie += len(url.response_cookie)
        if hasattr(url, 'js'):
            self.js += 1
        if hasattr(url, 'redirect'):
            self.redirect += 1
        if hasattr(url, 'redirect_to_nothing'):
            self.redirect_to_nothing += 1


class URLNode(HarTreeNode):

    def __init__(self, **kwargs):
        super(URLNode, self).__init__(**kwargs)
        # Do not add the body in the json dump
        self.features_to_skip.append('body')

    def load_har_entry(self, har_entry, all_requests):
        url = har_entry['request']['url']
        if not self.name:
            # We're in the actual root node
            self.add_feature('name', url)

        self.add_feature('hostname', urlparse(url).hostname)
        self.add_feature('response_cookie', har_entry['response']['cookies'])
        self.add_feature('request_cookie', har_entry['request']['cookies'])
        if har_entry['response']['content'].get('text'):
            self.add_feature('body', b64decode(har_entry['response']['content']['text']))
        self.add_feature('request', har_entry['request'])
        self.add_feature('response', har_entry['response'])
        if (har_entry['response']['content']['mimeType'].startswith('application/javascript') or
                har_entry['response']['content']['mimeType'].startswith('application/x-javascript')):
            self.add_feature('js', True)
        if har_entry['response']['content']['mimeType'].startswith('image'):
            self.add_feature('image', True)
        if har_entry['response']['content']['mimeType'].startswith('text/css'):
            self.add_feature('css', True)
        if har_entry['response']['content']['mimeType'].startswith('application/json'):
            self.add_feature('json', True)
        if not har_entry['response']['content'].get('text') or har_entry['response']['content']['text'] == '':
            self.add_feature('empty_response', True)

        if har_entry['response']['redirectURL']:
            url = har_entry['response']['redirectURL']
            self.add_feature('redirect', True)
            if url.startswith('//'):
                # Redirect to an other website...
                if all_requests.get('http:{}'.format(url)):
                    url = 'http:{}'.format(url)
                else:
                    url = 'https:{}'.format(url)
            elif not url.startswith('http'):
                # internal redirect
                parsed = urlparse(har_entry['request']['url'])
                parsed._replace(path=url)
                url = '{}://{}{}'.format(parsed.scheme, parsed.netloc, url)
            if not all_requests.get(url):
                if all_requests.get(url + '/'):
                    url += '/'
                else:
                    self.add_feature('redirect_to_nothing', True)
                    # Abord, no subtree
            self.add_feature('redirect_url', url)


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


class Har2Tree(object):

    def __init__(self, har):
        self.har = har
        self.root_url_after_redirect = None
        self.root_referer = None
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
                    children_hostnames[child_node_url.hostname] = child_node_hostname
                child_node_hostname.add_url(child_node_url)

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
        self.hostname_tree.add_url(self.url_tree)
        self.make_hostname_tree(self.url_tree, self.hostname_tree)
        return self.url_tree

    def _make_subtree(self, all_referer, all_requests, root_node, url_entry):
        if not root_node.name:
            # We're in the actual root node
            u_node = root_node
            u_node.add_feature('name', url_entry['request']['url'])
        else:
            u_node = root_node.add_child(URLNode(name=url_entry['request']['url']))
        u_node.load_har_entry(url_entry, all_requests)

        if hasattr(u_node, 'redirect') and not hasattr(u_node, 'redirect_to_nothing'):
            self._make_subtree(all_referer, all_requests, u_node, all_requests[u_node.redirect_url])
        elif all_referer.get(u_node.name):
            # URL loads other URL
            for u in all_referer.pop(u_node.name):
                self._make_subtree(all_referer, all_requests, u_node, all_requests[u])
