#!/usr/bin/env python
# -*- coding: utf-8 -*-

from ete3 import TreeNode

import json
import copy
from datetime import datetime
from datetime import timedelta
import uuid
from urllib.parse import urlparse
from base64 import b64decode
from collections import defaultdict
import logging
import re
import os
from io import BytesIO
import hashlib
from operator import itemgetter

from bs4 import BeautifulSoup


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


class IframeNode(HarTreeNode):

    def __init__(self, **kwargs):
        super(IframeNode, self).__init__(**kwargs)
        self.features_to_skip.append('body')

    def load_iframe(self, iframe):
        self.add_feature('body_hash', hashlib.sha256(iframe['html'].encode()).hexdigest())
        self.add_feature('body', iframe['html'])


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
        self.add_feature('image', 0)
        self.add_feature('css', 0)
        self.add_feature('json', 0)
        self.add_feature('html', 0)
        self.add_feature('font', 0)
        self.add_feature('octet_stream', 0)
        self.add_feature('text', 0)
        self.add_feature('video', 0)
        self.add_feature('livestream', 0)
        self.add_feature('unset_mimetype', 0)
        self.add_feature('unknown_mimetype', 0)

    def to_dict(self):
        to_return = super(HostNode, self).to_dict()
        to_return['urls_count'] = len(self.urls)
        return to_return

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
        if hasattr(url, 'image'):
            self.image += 1
        if hasattr(url, 'css'):
            self.css += 1
        if hasattr(url, 'json'):
            self.json += 1
        if hasattr(url, 'html'):
            self.html += 1
        if hasattr(url, 'font'):
            self.font += 1
        if hasattr(url, 'octet_stream'):
            self.octet_stream += 1
        if hasattr(url, 'text'):
            self.text += 1
        if hasattr(url, 'video'):
            self.video += 1
        if hasattr(url, 'livestream'):
            self.livestream += 1
        if hasattr(url, 'unset_mimetype'):
            self.unset_mimetype += 1
        if hasattr(url, 'unknown_mimetype'):
            self.unknown_mimetype += 1


class URLNode(HarTreeNode):

    def __init__(self, **kwargs):
        super(URLNode, self).__init__(**kwargs)
        # Do not add the body in the json dump
        self.features_to_skip.append('body')
        self.features_to_skip.append('start_time')
        self.features_to_skip.append('end_time')

    def load_har_entry(self, har_entry, all_requests):
        if not self.name:
            # We're in the actual root node
            self.add_feature('name', har_entry['request']['url'])

        self.add_feature('start_time', datetime.strptime(har_entry['startedDateTime'], '%Y-%m-%dT%X.%fZ'))
        self.add_feature('time', har_entry['time'])
        self.add_feature('end_time', self.start_time + timedelta(milliseconds=self.time))
        self.add_feature('hostname', urlparse(self.name).hostname)
        if not self.hostname:
            logging.warning('Something is broken in that node: {}'.format(har_entry))

        self.add_feature('request', har_entry['request'])
        # Try to get a referer from the headers
        for h in self.request['headers']:
            if h['name'] == 'Referer':
                self.add_feature('referer', h['value'])
            if h['name'] == 'User-Agent':
                self.add_feature('user_agent', h['value'])

        self.add_feature('response', har_entry['response'])

        self.add_feature('response_cookie', har_entry['response']['cookies'])
        self.add_feature('request_cookie', har_entry['request']['cookies'])

        if not har_entry['response']['content'].get('text') or har_entry['response']['content']['text'] == '':
            self.add_feature('empty_response', True)
        else:
            self.add_feature('body', BytesIO(b64decode(har_entry['response']['content']['text'])))
            self.add_feature('body_hash', hashlib.sha256(har_entry['response']['content']['text'].encode()).hexdigest())
            self.add_feature('mimetype', har_entry['response']['content']['mimeType'])
            parsed_response_url = urlparse(self.name)
            filename = os.path.basename(parsed_response_url.path)
            if filename:
                self.add_feature('filename', filename)
            else:
                self.add_feature('filename', 'file.bin')

        if ('javascript' in har_entry['response']['content']['mimeType'] or
                'ecmascript' in har_entry['response']['content']['mimeType']):
            self.add_feature('js', True)
        elif har_entry['response']['content']['mimeType'].startswith('image'):
            self.add_feature('image', True)
        elif har_entry['response']['content']['mimeType'].startswith('text/css'):
            self.add_feature('css', True)
        elif 'json' in har_entry['response']['content']['mimeType']:
            self.add_feature('json', True)
        elif har_entry['response']['content']['mimeType'].startswith('text/html'):
            self.add_feature('html', True)
        elif 'font' in har_entry['response']['content']['mimeType']:
            self.add_feature('font', True)
        elif 'octet-stream' in har_entry['response']['content']['mimeType']:
            self.add_feature('octet_stream', True)
        elif ('text/plain' in har_entry['response']['content']['mimeType'] or
                'xml' in har_entry['response']['content']['mimeType']):
            self.add_feature('text', True)
        elif 'video' in har_entry['response']['content']['mimeType']:
            self.add_feature('video', True)
        elif 'mpegurl' in har_entry['response']['content']['mimeType'].lower():
            self.add_feature('livestream', True)
        elif not har_entry['response']['content']['mimeType']:
            self.add_feature('unset_mimetype', True)
        else:
            self.add_feature('unknown_mimetype', True)
            logging.warning('Unknown mimetype: {}'.format(har_entry['response']['content']['mimeType']))

        if har_entry['response']['redirectURL']:
            self.add_feature('redirect', True)
            redirect_url = har_entry['response']['redirectURL']
            if re.match('^https?://', redirect_url):
                # we have a proper URL... hopefully
                # DO NOT REMOVE THIS CLAUSE, required to make the difference with a path
                pass
            elif redirect_url.startswith('//'):
                # URL without scheme => takes the scheme from the caller
                parsed_request_url = urlparse(self.name)
                redirect_url = '{}:{}'.format(parsed_request_url.scheme, redirect_url)
                if redirect_url not in all_requests:
                    logging.warning('URL without scheme: {original_url} - {original_redirect} - {modified_redirect}'.format(
                        original_url=self.name, original_redirect=har_entry['response']['redirectURL'], modified_redirect=redirect_url))
            elif redirect_url.startswith('/') or redirect_url[0] not in [';', '?', '#']:
                # We have a path
                if redirect_url[0] != '/':
                    # Yeah, that happens, and the browser fixes it...
                    redirect_url = '/{}'.format(redirect_url)
                parsed_request_url = urlparse(self.name)
                redirect_url = '{}://{}{}'.format(parsed_request_url.scheme, parsed_request_url.netloc, redirect_url)
                if redirect_url not in all_requests:
                    # There is something weird, to investigate
                    logging.warning('URL without netloc: {original_url} - {original_redirect} - {modified_redirect}'.format(
                        original_url=self.name, original_redirect=har_entry['response']['redirectURL'], modified_redirect=redirect_url))
            elif redirect_url.startswith(';'):
                # URL starts at the parameters
                redirect_url = '{}{}'.format(self.name.split(';')[0], redirect_url)
                if redirect_url not in all_requests:
                    logging.warning('URL with only parameter: {original_url} - {original_redirect} - {modified_redirect}'.format(
                        original_url=self.name, original_redirect=har_entry['response']['redirectURL'], modified_redirect=redirect_url))
            elif redirect_url.startswith('?'):
                # URL starts at the query
                redirect_url = '{}{}'.format(self.name.split('?')[0], redirect_url)
                if redirect_url not in all_requests:
                    logging.warning('URL with only query: {original_url} - {original_redirect} - {modified_redirect}'.format(
                        original_url=self.name, original_redirect=har_entry['response']['redirectURL'], modified_redirect=redirect_url))
            elif redirect_url.startswith('#'):
                # URL starts at the fragment
                redirect_url = '{}{}'.format(self.name.split('#')[0], redirect_url)
                if redirect_url not in all_requests:
                    logging.warning('URL with only fragment: {original_url} - {original_redirect} - {modified_redirect}'.format(
                        original_url=self.name, original_redirect=har_entry['response']['redirectURL'], modified_redirect=redirect_url))

            if redirect_url not in all_requests:
                # sometimes, the port is in the redirect, and striped later on...
                if redirect_url.startswith('https://') and ':443' in redirect_url:
                    redirect_url = redirect_url.replace(':443', '')
                if redirect_url.startswith('http://') and ':80' in redirect_url:
                    redirect_url = redirect_url.replace(':80', '')

            if redirect_url not in all_requests and redirect_url + '/' in all_requests:
                # last think I can think of
                redirect_url += '/'

            # At this point, we should have a URL available in all_requests...
            if redirect_url in all_requests:
                self.add_feature('redirect_url', redirect_url)
            else:
                # ..... Or not. Unable to find a URL for this redirect
                self.add_feature('redirect_to_nothing', True)
                self.add_feature('redirect_url', har_entry['response']['redirectURL'])
                logging.warning('Unable to find that URL: {original_url} - {original_redirect} - {modified_redirect}'.format(
                    original_url=self.name, original_redirect=har_entry['response']['redirectURL'], modified_redirect=redirect_url))


class CrawledTree(object):

    def __init__(self, harfiles):
        """ Load all the harfiles passed as parameter"""
        self.hartrees = self.load_all_harfiles(harfiles)
        self.root_hartree = None

    def load_all_harfiles(self, files):
        """Open all the HAR files"""
        loaded = []
        for har in files:
            # Only using the referrers isn't enough to build the tree (i.e. iframes).
            # The filename is supposed to be '[id].frames.json'
            iframefile = os.path.join(os.path.dirname(har), os.path.basename(har).split('.')[0] + '.frames.json')
            if os.path.isfile(iframefile):
                with open(har, 'r') as f, open(iframefile, 'r') as i:
                    har2tree = Har2Tree(json.load(f), json.load(i))
            else:
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

    def __init__(self, har, iframes=[]):
        self.har = har
        self.hostname_tree = HostNode()
        if not self.har['log']['entries']:
            self.has_entries = False
            return
        else:
            self.has_entries = True

        # Sorting the entries by start time (it isn't the case by default)
        # Reason: A specific URL cannot be loaded by something that hasn't been already started
        self.har['log']['entries'].sort(key=itemgetter('startedDateTime'))

        self.root_url = self.har['log']['entries'][0]['request']['url']
        self.root_url_after_redirect = self._find_root_after_redirect()

        if self.root_url_after_redirect:
            self.iframe_tree = IframeNode(name=self.root_url_after_redirect)
            iframe_scheme = urlparse(self.root_url_after_redirect).scheme
        else:
            self.iframe_tree = IframeNode(name=self.root_url)
            iframe_scheme = urlparse(self.root_url).scheme

        if iframes:
            self._load_iframes(iframes, root=self.iframe_tree, scheme=iframe_scheme)
        print(self.iframe_tree)

        self.nodes_list, self.all_url_requests, self.all_redirects, self.all_referer = self._load_url_entries()

        self.url_tree = self.nodes_list[0]
        self.start_time = self.url_tree.start_time
        self.user_agent = self.url_tree.user_agent

        self.root_referer = self._find_root_referrer()

    def _load_url_entries(self):
        '''Initialize the list of nodes to attach to the tree (as URLNode),
        and create a list of note for each URL we have in the HAR document'''
        nodes_list = []
        all_redirects = []
        all_referer = defaultdict(list)
        all_url_requests = {url_entry['request']['url']: [] for url_entry in self.har['log']['entries']}

        for url_entry in self.har['log']['entries']:
            n = URLNode(name=url_entry['request']['url'])
            n.load_har_entry(url_entry, all_url_requests.keys())
            if hasattr(n, 'redirect_url'):
                all_redirects.append(n.redirect_url)
            elif hasattr(n, 'referer'):
                if n.referer == n.name:
                    # Skip to avoid loops:
                    #   * referer to itself
                    logging.warning('Referer to itself ' + n.name)
                    continue
                else:
                    all_referer[n.referer].append(n.name)
            else:
                # Lookup in the iframe tree
                matching_urls = self.iframe_tree.search_nodes(name=n.name)
                if matching_urls:
                    n.add_feature('iframe', True)
                    for matching_url in matching_urls:
                        for parent in matching_url.get_ancestors():
                            if parent.name.startswith('about'):
                                continue
                            all_referer[parent.name].append(n.name)
                            break
                else:
                    print('No clue where it comes from: ', n.name)
            nodes_list.append(n)
            if all_url_requests[n.name]:
                # The same URL request has already been requested
                # TODO: Figure out how to attach the right URL to the right node
                # This bloc is for debug purposes only
                for node in all_url_requests[n.name]:
                    print(n.name)
                    if hasattr(node, 'empty_response') and hasattr(n, 'empty_response'):
                        print('\tNo body at all... -> Cookies?')
                        continue
                    if hasattr(node, 'empty_response') and not hasattr(n, 'empty_response'):
                        print('\tOld no body, new has body... ')
                        continue
                    if not hasattr(node, 'empty_response') and hasattr(n, 'empty_response'):
                        print('\tNew no body, old has body... ')
                        continue
                    if node.body_hash == n.body_hash:
                        print('\tDuplicate')
                    else:
                        print('\tNot duplicate')
            all_url_requests[n.name].append(n)
        return nodes_list, all_url_requests, all_redirects, all_referer

    def _load_iframes(self, iframes, root, scheme):
        for iframe in iframes:
            soup = BeautifulSoup(iframe['html'], 'html.parser')

            for link in soup.find_all(['img', 'script']):
                if link.get('src'):
                    to_attach = link.get('src')
                    if to_attach.startswith('//'):
                        to_attach = '{}:{}'.format(scheme, to_attach)
                    root.add_child(IframeNode(name=to_attach))

            for link in soup.find_all(['a', 'link']):
                if link.get('href'):
                    to_attach = link.get('href')
                    if to_attach.startswith('//'):
                        to_attach = '{}:{}'.format(scheme, to_attach)
                    root.add_child(IframeNode(name=to_attach))

            child = root.add_child(IframeNode(name=iframe['requestedUrl']))
            child.load_iframe(iframe)
            self._load_iframes(iframe['childFrames'], root=child, scheme=scheme)

    def get_host_node_by_uuid(self, uuid):
        return self.hostname_tree.search_nodes(uuid=uuid)[0]

    def get_url_node_by_uuid(self, uuid):
        return self.url_tree.search_nodes(uuid=uuid)[0]

    def _find_root_after_redirect(self):
        '''Iterate through the list of entries until there are no redirectURL in
        the response anymore: it is the first URL loading content.
        '''
        to_return = None
        for e in self.har['log']['entries']:
            print(e['request']['url'], e['response']['redirectURL'])
            if e['response']['redirectURL']:
                to_return = e['response']['redirectURL']
                if not to_return.startswith('http'):
                    # internal redirect
                    parsed = urlparse(e['request']['url'])
                    parsed._replace(path=to_return)
                    to_return = '{}://{}{}'.format(parsed.scheme, parsed.netloc, to_return)
            else:
                break
        return to_return

    def to_json(self):
        return self.hostname_tree.to_json()

    def _find_root_referrer(self):
        '''Useful when there are multiple tree to attach together'''
        first_entry = self.har['log']['entries'][0]
        for h in first_entry['request']['headers']:
            if h['name'] == 'Referer':
                return h['value']
        return None

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
                    logging.warning('Fucked up hostname: {}'.format(child_node_url))
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
        self._make_subtree(self.url_tree)
        # Initialize the hostname tree root
        self.hostname_tree.add_url(self.url_tree)
        self.make_hostname_tree(self.url_tree, self.hostname_tree)
        return self.url_tree

    def _make_subtree(self, root, nodes_to_attach=None):
        if nodes_to_attach is None:
            # We're in the actual root node
            unodes = [self.nodes_list[0]]
        else:
            unodes = []
            for url_node in nodes_to_attach:
                unodes.append(root.add_child(url_node))
        for unode in unodes:
            if hasattr(unode, 'redirect') and not hasattr(unode, 'redirect_to_nothing'):
                matching_urls = self.all_url_requests.get(unode.redirect_url)
                for matching_url in matching_urls:
                    if unode.start_time < matching_url.start_time:  # <= unode.end_time:
                        self._make_subtree(unode, [matching_url])
                    elif unode.start_time > matching_url.start_time:
                        print('\ttoo early', unode.redirect_url)
                    # else:
                    #    print('\ttoo late', unode.redirect_url)
            elif self.all_referer.get(unode.name):
                # URL loads other URL
                for u in self.all_referer.pop(unode.name):
                    matching_urls = self.all_url_requests.get(u)
                    for matching_url in matching_urls:
                        if unode.start_time < matching_url.start_time:  # <= unode.end_time:
                            self._make_subtree(unode, [matching_url])
                        elif unode.start_time > matching_url.start_time:
                            print('\ttoo early', unode.name)
                        # else:
                        #    print('\ttoo late', unode.name, unode.end_time, matching_url.name, matching_url.start_time)
            else:
                logging.debug('No child' + unode.name)
