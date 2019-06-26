#!/usr/bin/env python
# -*- coding: utf-8 -*-

from ete3 import TreeNode

from pathlib import Path
import json
import copy
from datetime import datetime, timedelta
import uuid
from urllib.parse import urlparse, unquote_plus
from base64 import b64decode
from collections import defaultdict
import logging
import re
import os
from io import BytesIO
import hashlib
from operator import itemgetter
from bs4 import BeautifulSoup
import html


class Har2TreeError(Exception):
    def __init__(self, message):
        super(Har2TreeError, self).__init__(message)
        self.message = message


def rebuild_url(base_url, partial, known_urls):
    splitted_base_url = urlparse(base_url)
    # Remove all possible quotes
    partial = partial.strip()
    partial = html.unescape(partial)
    partial = unquote_plus(partial)
    if not partial:
        return ''
    if re.match('^https?://', partial):
        # we have a proper URL... hopefully
        # DO NOT REMOVE THIS CLAUSE, required to make the difference with a path
        final_url = partial
    elif partial.startswith('//'):
        # URL without scheme => takes the scheme from the caller
        final_url = f'{splitted_base_url.scheme}:{partial}'
        if final_url not in known_urls:
            logging.info(f'URL without scheme: {base_url} - {partial} - {final_url}')
    elif partial.startswith('/') or partial[0] not in [';', '?', '#']:
        # We have a path
        if partial[0] != '/':
            # Yeah, that happens, and the browser appends the path in redirect_url to the current path
            if base_url[-1] == '/':
                # Example: http://foo.bar/some/path/ and some/redirect.html becomes http://foo.bar/some/path/some/redirect.html
                final_url = f'{base_url}{partial}'
            else:
                # Need to strip the last part of the URL down to the first / (included), and attach the redirect
                # Example: http://foo.bar/some/path/blah and some/redirect.html becomes http://foo.bar/some/path/some/redirect.html
                last_slash = base_url.rfind('/') + 1
                final_url = f'{base_url[:last_slash]}{partial}'
        else:
            final_url = f'{splitted_base_url.scheme}://{splitted_base_url.netloc}{partial}'
        if final_url not in known_urls:
            # There is something weird, to investigate
            logging.info(f'URL without netloc: {base_url} - {partial} - {final_url}')
    elif partial.startswith(';'):
        # URL starts at the parameters
        final_url = '{}{}'.format(base_url.split(';')[0], partial)
        if final_url not in known_urls:
            logging.info(f'URL with only parameter: {base_url} - {partial} - {final_url}')
    elif partial.startswith('?'):
        # URL starts at the query
        final_url = '{}{}'.format(base_url.split('?')[0], partial)
        if final_url not in known_urls:
            logging.info(f'URL with only query: {base_url} - {partial} - {final_url}')
    elif partial.startswith('#'):
        # URL starts at the fragment
        final_url = '{}{}'.format(base_url.split('#')[0], partial)
        if final_url not in known_urls:
            logging.info(f'URL with only fragment: {base_url} - {partial} - {final_url}')

    if final_url not in known_urls:
        # sometimes, the port is in the redirect, and striped later on...
        if final_url.startswith('https://') and ':443' in final_url:
            final_url = final_url.replace(':443', '')
        if final_url.startswith('http://') and ':80' in final_url:
            final_url = final_url.replace(':80', '')

    if final_url not in known_urls:
        # strip the single-dot crap: https://foo.bar/path/./blah.js => https://foo.bar/path/blah.js
        try:
            parsed = urlparse(final_url)
            if parsed.path:
                # NOTE: Path('').resolve() => PosixPath('/path/to/current/directory') <= if you run that from your home dir, it is the path to your home dir
                # FIXME: Path('sdsfs/../dsfsdfs/../..').resolve() => PosixPath('/path/to/current')
                final_url = parsed._replace(path=str(Path(parsed.path).resolve())).geturl()
            else:
                final_url = parsed._replace(path='/').geturl()
        except Exception:
            logging.info(f'Not a URL: {base_url} - {partial}')

    if final_url not in known_urls and final_url + '/' in known_urls:
        # last thing I can think of
        final_url = f'{final_url}/'

    return final_url


# Standalone methods to extract and cleanup content from an HTML blob.
def url_cleanup(dict_to_clean, base_url, all_requests):
    to_return = {}
    for key, urls in dict_to_clean.items():
        to_return[key] = []
        for url in urls:
            if url.startswith('data'):
                # print(html_doc.getvalue())
                continue
            to_attach = url.strip()
            if to_attach.startswith("\\'") or to_attach.startswith('\\"'):
                to_attach = to_attach[2:-2]
            if to_attach.startswith("'") or to_attach.startswith('"'):
                to_attach = to_attach[1:-1]
            if to_attach.endswith("'") or to_attach.endswith('"'):
                # A quote at the end of the URL can be selected by the fulltext regex
                to_attach = to_attach[:-1]
            to_attach = rebuild_url(base_url, to_attach, all_requests)
            if to_attach.startswith('http'):
                to_return[key].append(to_attach)
            else:
                logging.info('{} - not a URL - {}'.format(key, to_attach))
    return to_return


def find_external_ressources(html_doc, base_url, all_requests, full_text_search=True):
    # Source: https://stackoverflow.com/questions/31666584/beutifulsoup-to-extract-all-external-resources-from-html
    # Because this is awful.
    to_return = {'img': [], 'script': [], 'video': [], 'audio': [],
                 'iframe': [], 'embed': [], 'source': [],
                 'link': [],
                 'object': [],
                 'css': [],
                 'full_regex': [],
                 'javascript': [],
                 'meta_refresh': []}
    soup = BeautifulSoup(html_doc, 'lxml')
    for link in soup.find_all(['img', 'script', 'video', 'audio', 'iframe', 'embed', 'source']):
        if link.get('src'):
            # print('******** src', link.get('src'))
            to_return[link.name].append(unquote_plus(link.get('src')))

    for link in soup.find_all(['link']):
        if link.get('href'):
            to_return[link.name].append(unquote_plus(link.get('href')))

    for link in soup.find_all(['object']):
        if link.get('data'):
            to_return[link.name].append(unquote_plus(link.get('data')))

    # Search for meta refresh redirect madness
    # NOTE: we may want to move that somewhere else, but that's currently the only place BeautifulSoup is used.
    meta_refresh = soup.find('meta', attrs={'http-equiv': 'refresh'})
    if meta_refresh:
        to_return['meta_refresh'].append(meta_refresh['content'].partition('=')[2])

    # external stuff loaded from css content, because reasons.
    to_return['css'] = [url.decode() for url in re.findall(rb'url\((.*?)\)', html_doc.getvalue())]

    # Javascript changing the current page
    # I never found a website where it matched anything useful
    to_return['javascript'] = [url.decode() for url in re.findall(b'(?:window|self|top).location(?:.*)\"(.*?)\"', html_doc.getvalue())]

    if full_text_search:
        # Just regex in the whole blob, because we can
        to_return['full_regex'] = [url.decode() for url in re.findall(rb'(?:http[s]?:)?//(?:[a-zA-Z]|[0-9]|[$-_@.&+]|[!*\(\),]|(?:%[0-9a-fA-F][0-9a-fA-F]))+', html_doc.getvalue())]
        # print("################ REGEXES ", to_return['full_regex'])
    return url_cleanup(to_return, base_url, all_requests)

# ##################################################################


class HarTreeNode(TreeNode):

    def __init__(self, **kwargs):
        super(HarTreeNode, self).__init__(**kwargs)
        self.add_feature('uuid', str(uuid.uuid4()))
        self.features_to_skip = set(['dist', 'support'])

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
        self.features_to_skip.add('body')
        self.features_to_skip.add('external_ressources')

    def load_iframe(self, iframe, base_url, all_requests):
        self.add_feature('body', BytesIO(iframe['html'].encode()))
        self.add_feature('body_hash', hashlib.sha512(self.body.getvalue()).hexdigest())
        if self.body:
            ext = find_external_ressources(self.body, base_url, all_requests)
            # print('In Iframe Node', ext)
            self.add_feature('external_ressources', ext)


class HostNode(HarTreeNode):

    def __init__(self, **kwargs):
        super(HostNode, self).__init__(**kwargs)
        # Do not add the URLs in the json dump
        self.features_to_skip.add('urls')

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
        self.add_feature('iframe', 0)
        self.add_feature('http_content', False)
        self.add_feature('https_content', False)
        self.add_feature('mixed_content', False)

    def to_dict(self):
        to_return = super(HostNode, self).to_dict()
        to_return['urls_count'] = len(self.urls)
        if self.http_content and self.https_content:
            self.mixed_content = True
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
        if hasattr(url, 'video') or hasattr(url, 'livestream'):
            self.video += 1
        if hasattr(url, 'unknown_mimetype') or hasattr(url, 'unset_mimetype'):
            self.unknown_mimetype += 1
        if hasattr(url, 'iframe'):
            self.iframe += 1

        if url.name.startswith('http://'):
            self.http_content = True
        elif url.name.startswith('https://'):
            self.https_content = True


class URLNode(HarTreeNode):

    def __init__(self, **kwargs):
        super(URLNode, self).__init__(**kwargs)
        # Do not add the body in the json dump
        self.features_to_skip.add('body')
        self.features_to_skip.add('url_split')
        self.features_to_skip.add('start_time')
        self.features_to_skip.add('time')
        self.features_to_skip.add('time_content_received')

    def load_har_entry(self, har_entry, all_requests):
        if not self.name:
            # We're in the actual root node
            self.add_feature('name', unquote_plus(har_entry['request']['url']))  # NOTE: by the HAR specs: "Absolute URL of the request (fragments are not included)."

        self.add_feature('url_split', urlparse(self.name))

        # If the URL contains a fragment (i.e. something after a #), it is stripped in the referer.
        # So we need an alternative URL to do a lookup against
        self.add_feature('alternative_url_for_referer', self.name.split('#')[0])

        self.add_feature('start_time', datetime.strptime(har_entry['startedDateTime'], '%Y-%m-%dT%X.%fZ'))  # Instant the request is made
        self.add_feature('time', timedelta(milliseconds=har_entry['time']))
        self.add_feature('time_content_received', self.start_time + self.time)  # Instant the response is fully received (and the processing of the content by the browser can start)
        self.add_feature('hostname', urlparse(self.name).hostname)
        if not self.hostname:
            logging.warning('Something is broken in that node: {}'.format(har_entry))

        self.add_feature('request', har_entry['request'])
        # Try to get a referer from the headers
        for h in self.request['headers']:
            if h['name'] == 'Referer':
                self.add_feature('referer', unquote_plus(h['value']))
            if h['name'] == 'User-Agent':
                self.add_feature('user_agent', h['value'])

        self.add_feature('response', har_entry['response'])

        self.add_feature('response_cookie', har_entry['response']['cookies'])
        self.add_feature('request_cookie', har_entry['request']['cookies'])

        if not har_entry['response']['content'].get('text') or har_entry['response']['content']['text'] == '':
            self.add_feature('empty_response', True)
        else:
            self.add_feature('body', BytesIO(b64decode(har_entry['response']['content']['text'])))
            self.add_feature('body_hash', hashlib.sha512(self.body.getvalue()).hexdigest())
            self.add_feature('mimetype', har_entry['response']['content']['mimeType'])
            self.add_feature('external_ressources', find_external_ressources(self.body, self.name, all_requests))
            parsed_response_url = urlparse(self.name)
            filename = os.path.basename(parsed_response_url.path)
            if filename:
                self.add_feature('filename', filename)
            else:
                self.add_feature('filename', 'file.bin')

        if ('javascript' in har_entry['response']['content']['mimeType']
                or 'ecmascript' in har_entry['response']['content']['mimeType']):
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
        elif ('text/plain' in har_entry['response']['content']['mimeType']
                or 'xml' in har_entry['response']['content']['mimeType']):
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
            # Rebuild the redirect URL so it matches the entry that sould be in all_requests
            redirect_url = rebuild_url(self.name, redirect_url, all_requests)
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
        if not self.hartrees:
            raise Har2TreeError('No usable HAR files found.')
        self.root_hartree = None

    def load_all_harfiles(self, files):
        """Open all the HAR files"""
        loaded = []
        for har in files:
            # Only using the referrers isn't enough to build the tree (i.e. iframes).
            # The filename is supposed to be '[id].frames.json'
            har = Path(har)
            iframefile = har.parent / '{}.frames.json'.format(str(har.name).split('.')[0])
            htmlfile = har.parent / '{}.html'.format(str(har.name).split('.')[0])
            if iframefile.is_file() and htmlfile.is_file():
                with open(har, 'r') as f, open(iframefile, 'r') as i, open(htmlfile, 'rb') as h:
                    har2tree = Har2Tree(json.load(f), json.load(i), BytesIO(h.read()))
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

    def __init__(self, har, iframes=[], rendered_HTML=BytesIO()):
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
            iframe_base_url = self.root_url_after_redirect
        else:
            self.iframe_tree = IframeNode(name=self.root_url)
            iframe_base_url = self.root_url

        if iframes:
            all_requests = [unquote_plus(url_entry['request']['url']) for url_entry in self.har['log']['entries']]
            self._load_iframes(iframes, root=self.iframe_tree, base_url=iframe_base_url, all_requests=all_requests)

        self.nodes_list, self.all_url_requests, self.all_redirects, self.all_referer, self.all_iframes = self._load_url_entries()

        self.url_tree = self.nodes_list.pop(0)
        self.start_time = self.url_tree.start_time
        self.user_agent = self.url_tree.user_agent

        if self.root_url_after_redirect:
            self.all_ressources_rendered = find_external_ressources(rendered_HTML, self.root_url_after_redirect, self.all_url_requests)
        else:
            self.all_ressources_rendered = find_external_ressources(rendered_HTML, self.root_url, self.all_url_requests)
        self.root_referer = self._find_root_referrer()

    def _load_url_entries(self):
        '''Initialize the list of nodes to attach to the tree (as URLNode),
        and create a list of note for each URL we have in the HAR document'''
        nodes_list = []
        all_redirects = []
        all_referer = defaultdict(list)
        all_iframes = defaultdict(list)
        all_url_requests = {unquote_plus(url_entry['request']['url']): [] for url_entry in self.har['log']['entries']}

        for url_entry in self.har['log']['entries']:
            n = URLNode(name=unquote_plus(url_entry['request']['url']))
            n.load_har_entry(url_entry, all_url_requests.keys())
            if hasattr(n, 'redirect_url'):
                all_redirects.append(n.redirect_url)

            if hasattr(n, 'referer'):
                if n.referer == n.name:
                    # Skip to avoid loops:
                    #   * referer to itself
                    logging.warning('Referer to itself {}'.format(n.name))
                    continue
                else:
                    all_referer[n.referer].append(n.name)
            else:
                # Lookup in the iframe tree
                matching_urls_in_iframe_tree = self.iframe_tree.search_nodes(name=n.name)
                if matching_urls_in_iframe_tree:
                    # This URL is in the iframe tree
                    n.add_feature('iframe', True)
                    for iframe_node in matching_urls_in_iframe_tree:
                        for parent in iframe_node.get_ancestors():
                            if parent.name.startswith('about'):
                                continue
                            all_iframes[parent.name].append(n.name)
                            # Just in case we have an other node with the same URL that isn't from the iframe
                            n.add_feature('iframe_parent', parent.name)
                            if hasattr(iframe_node, 'iframe_rendered_body'):
                                # Doesn't exists if the node is created out of the HTML content of the iframe.
                                n.add_feature('iframe_rendered_body', iframe_node.body)
                                n.add_feature('iframe_rendered_body_hash', iframe_node.body_hash)
                                n.add_feature('iframe_external_ressources', iframe_node.external_ressources)
                            break

            nodes_list.append(n)
            all_url_requests[n.name].append(n)
        return nodes_list, all_url_requests, all_redirects, all_referer, all_iframes

    def _load_iframes(self, iframes, root, base_url, all_requests):
        if hasattr(root, 'external_ressources'):
            for external_tag, links in root.external_ressources.items():
                for link in links:
                    root.add_child(IframeNode(name=link))
        for iframe in iframes:
            child = root.add_child(IframeNode(name=unquote_plus(iframe['requestedUrl'])))
            child.load_iframe(iframe, base_url, all_requests)
            self._load_iframes(iframe['childFrames'], root=child, base_url=base_url, all_requests=all_requests)

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
        for root_node_url in root_nodes_url:
            children_hostnames = {}
            sub_roots = defaultdict(list)
            for child_node_url in root_node_url.get_children():
                if child_node_url.hostname is None:
                    logging.warning('Fucked up URL: {}'.format(child_node_url))
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

        if self.nodes_list:
            orphan = URLNode(name='orphan urls')
            orphan.add_feature('hostname', 'orphan.url')
            while self.nodes_list:
                node = self.nodes_list.pop(0)
                for key, values in self.all_ressources_rendered.items():
                    if node.name in values:
                        node.add_feature('dynamic', True)
                        self._make_subtree(self.url_tree, [node])
                        break
                else:
                    # Dirty attach everything else
                    print('Remaining URL:', node.name)
                    self._make_subtree(orphan, [node])
            if orphan.children:
                self.url_tree.add_child(orphan)

        # Initialize the hostname tree root
        self.hostname_tree.add_url(self.url_tree)
        self.make_hostname_tree(self.url_tree, self.hostname_tree)
        return self.url_tree

    def _make_subtree(self, root, nodes_to_attach=None):
        if nodes_to_attach is None:
            # We're in the actual root node
            unodes = [self.url_tree]
        else:
            unodes = []
            for url_node in nodes_to_attach:
                unodes.append(root.add_child(url_node))
        for unode in unodes:
            if hasattr(unode, 'redirect') and not hasattr(unode, 'redirect_to_nothing'):
                # If the subnode has a redirect URL set, we get all the requests matching this URL
                # One may think the entry related to this redirect URL has a referer to the parent. One would be wrong.
                # URL 1 has a referer, and redirects to URL 2. URL 2 has the same referer as URL 1.
                if unode.redirect_url not in self.all_redirects:
                    continue
                self.all_redirects.remove(unode.redirect_url)  # Makes sure we only follow a redirect once
                matching_urls = [url_node for url_node in self.all_url_requests.get(unode.redirect_url) if url_node in self.nodes_list]
                [self.nodes_list.remove(matching_url) for matching_url in matching_urls]
                self._make_subtree(unode, matching_urls)
            else:
                if self.all_referer.get(unode.name):
                    # The URL (unode.name) is in the list of known referers
                    for u in self.all_referer.get(unode.name):
                        matching_urls = [url_node for url_node in self.all_url_requests.get(u)
                                         if url_node in self.nodes_list and hasattr(url_node, 'referer') and url_node.referer == unode.name]
                        [self.nodes_list.remove(matching_url) for matching_url in matching_urls]
                        self._make_subtree(unode, matching_urls)
                    if not self.all_referer.get(unode.name):
                        # remove the referer from the list if empty
                        self.all_referer.pop(unode.name)
                if self.all_referer.get(unode.alternative_url_for_referer):
                    # The URL (unode.name) stripped at the first `#` is in the list of known referers
                    for u in self.all_referer.get(unode.alternative_url_for_referer):
                        matching_urls = [url_node for url_node in self.all_url_requests.get(u)
                                         if url_node in self.nodes_list and hasattr(url_node, 'referer') and url_node.referer == unode.alternative_url_for_referer]
                        [self.nodes_list.remove(matching_url) for matching_url in matching_urls]
                        self._make_subtree(unode, matching_urls)
                    # remove the referer from the list if empty
                    if not self.all_referer.get(unode.alternative_url_for_referer):
                        self.all_referer.pop(unode.alternative_url_for_referer)
                if self.all_iframes.get(unode.name):
                    # This node loads iframes. As we already have a tree, we just attach all the clildrens to the node.
                    for u in self.all_iframes.get(unode.name):
                        matching_urls = [url_node for url_node in self.all_url_requests.get(u)
                                         if url_node in self.nodes_list and hasattr(url_node, 'iframe_parent') and url_node.iframe_parent == unode.name]
                        [self.nodes_list.remove(matching_url) for matching_url in matching_urls]
                        self._make_subtree(unode, matching_urls)
                    # remove the referer from the list if empty
                    if not self.all_iframes.get(unode.name):
                        self.all_iframes.pop(unode.name)
                if hasattr(unode, 'external_ressources'):
                    # the url loads external things, and some of them have no referer....
                    for external_tag, links in unode.external_ressources.items():
                        for link in links:
                            if link not in self.all_url_requests:
                                # We have a lot of false positives
                                continue
                            matching_urls = [url_node for url_node in self.all_url_requests.get(link) if url_node in self.nodes_list]
                            [self.nodes_list.remove(matching_url) for matching_url in matching_urls]
                            self._make_subtree(unode, matching_urls)
                if hasattr(unode, 'iframe_external_ressources'):
                    # the iframes load external things too
                    for external_tag, links in unode.iframe_external_ressources.items():
                        for link in links:
                            if link not in self.all_url_requests:
                                # We have a lot of false positives
                                continue
                            matching_urls = [url_node for url_node in self.all_url_requests.get(link) if url_node in self.nodes_list]
                            [self.nodes_list.remove(matching_url) for matching_url in matching_urls]
                            self._make_subtree(unode, matching_urls)
