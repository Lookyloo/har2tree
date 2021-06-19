#!/usr/bin/env python
# -*- coding: utf-8 -*-

from pathlib import Path
import logging
from typing import Dict, Any, List, Optional, Tuple, Set, Union, Callable
import json
from urllib.parse import unquote_plus
from io import BytesIO
from operator import itemgetter
from collections import defaultdict
from .helper import rebuild_url, Har2TreeError, Har2TreeLogAdapter
from .nodes import HostNode, URLNode
from datetime import datetime, timedelta
from functools import wraps

# Dev debug mode is a mode that will print lots of things and will only be usable
# by someone with a pretty deep understanding of har2tree and how the tree is built
# The goal is to have a relatively simple way to investigate the construction of a tree itself
# In order to enable it, it is assumed that you have the repository cloned on your machine
# 1. Switch dev_debug_mode to True
# 2. path_to_debug_files set a path to a directory of your choice, where you will create a file "url" or "hostname", with one line (the URL or the hostname)
# 3. pip install .
# 4. kill & restart the webserver
# 5. Rebuild the tree, the debug messages will be in the terminal.

path_to_debug_files = ''
dev_debug_url = ''
dev_debug_hostname = ''
dev_debug_mode = False

if dev_debug_mode:
    logging.getLogger(__name__).critical('You are running har2tree in dev debug mode.')
    logging.getLogger(__name__).critical(f'Path to the debug files: {path_to_debug_files}.')


# ##################################################################

def trace_make_subtree_fallback(method: Callable[..., None]) -> Callable[..., None]:
    @wraps(method)
    def _impl(self: Any, node: URLNode, dev_debug: bool=False) -> None:
        if dev_debug_mode:
            __load_debug_files()
            if dev_debug_url and node.name == dev_debug_url:
                node.logger.warning(f'Debugging URL: {dev_debug_url}.')
                dev_debug = True
            elif dev_debug_hostname and node.hostname == dev_debug_hostname:
                node.logger.warning(f'Debugging Hostname: {dev_debug_hostname}.')
                dev_debug = True
        return method(self, node, dev_debug)
    return _impl


def trace_make_subtree(method: Callable[..., None]) -> Callable[..., None]:
    @wraps(method)
    def _impl(self: Any, root: URLNode, nodes_to_attach: Optional[List[URLNode]]=None, dev_debug: bool=False) -> None:
        if dev_debug_mode:
            __load_debug_files()
            if dev_debug_url and root.name == dev_debug_url or nodes_to_attach is not None and any(True for u in nodes_to_attach if u.name == dev_debug_url):
                root.logger.warning(f'Debugging URL: {dev_debug_url}.')
                dev_debug = True
            elif dev_debug_hostname and root.hostname == dev_debug_hostname or nodes_to_attach is not None and any(True for u in nodes_to_attach if u.hostname == dev_debug_hostname):
                root.logger.warning(f'Debugging Hostname: {dev_debug_hostname}.')
                dev_debug = True
        return method(self, root, nodes_to_attach, dev_debug)
    return _impl


def __load_debug_files() -> None:
    global dev_debug_url
    global dev_debug_hostname
    url_path = Path(path_to_debug_files) / 'url'
    hostname_path = Path(path_to_debug_files) / 'hostname'
    if url_path.exists():
        with url_path.open() as f:
            dev_debug_url = f.read().strip()
    if hostname_path.exists():
        with hostname_path.open() as f:
            dev_debug_hostname = f.read().strip()


class HarFile():

    def __init__(self, harfile: Path, capture_uuid: str):
        """Overview of the HAR file itself"""
        logger = logging.getLogger(f'{__name__}.{self.__class__.__name__}')
        self.capture_uuid: str = capture_uuid
        self.logger = Har2TreeLogAdapter(logger, {'uuid': self.capture_uuid})
        self.path = harfile

        with self.path.open() as f:
            self.har: Dict[str, Any] = json.load(f)

        # I mean it, that's the last URL the splash browser was on
        last_redirect_file = self.path.parent / f'{self.path.stem}.last_redirect.txt'
        if last_redirect_file.is_file():
            with last_redirect_file.open('r') as _lr:
                self.final_redirect: str = unquote_plus(_lr.read())
            self._search_final_redirect()
        else:
            self.logger.info('No last_redirect file available.')
            self.final_redirect = ''

        cookiefile = self.path.parent / f'{self.path.stem}.cookies.json'
        if cookiefile.is_file():
            with cookiefile.open() as c:
                self.cookies: List[Dict[str, Any]] = json.load(c)
        else:
            self.logger.info('No cookies file available.')
            self.cookies = []

        htmlfile = self.path.parent / f'{self.path.stem}.html'
        self.html_content: Optional[BytesIO]
        if htmlfile.is_file():
            with htmlfile.open('rb') as _h:
                self.html_content = BytesIO(_h.read())
        else:
            self.logger.info('No rendered HTML content.')
            self.html_content = None

        # Sorting the entries by start time (it isn't the case by default)
        # Reason: A specific URL cannot be loaded by something that hasn't been already started
        self.entries.sort(key=itemgetter('startedDateTime'))

        # Used to find the root entry of a page in the capture
        # NOTE 2020-05-19: Turns out multiple pages can have the exact same timestamp...
        self.pages_start_times: Dict[str, List[Dict[str, Any]]] = defaultdict(list)
        for page in self.har['log']['pages']:
            self.pages_start_times[page['startedDateTime']].append(page)
        # The first entry has a different start time as the one from the list, add that
        if self.entries:
            self.pages_start_times[self.initial_start_time].append(self.har['log']['pages'][0])

        # Set to false if initial_redirects fails to find the chain.
        self.need_tree_redirects = False

    def _search_final_redirect(self) -> None:
        """Try to find the final path to the final redirect without building the tree"""
        for e in self.entries:
            unquoted_url = unquote_plus(e['request']['url'])
            if unquoted_url == self.final_redirect:
                break
            elif unquoted_url.startswith(f'{self.final_redirect}?'):
                # WARNING: the URL in that file may not be present in the HAR: the query part is stripped by splash
                self.final_redirect = unquoted_url
                break
        else:
            # Update 2020-04-01: .. but the fragment is not striped so self.final_redirect may not be found
            # Unless we find the entry in the har, we need to search again without the fragment
            if '#' in self.final_redirect:
                self.final_redirect = self.final_redirect.split('#', 1)[0]
                self._search_final_redirect()
            elif '?' in self.final_redirect:
                # At this point, we're trying things. The final URL returned by splash may have been changed
                # in JavaScript and never appear in the HAR. Let's try to find the closest one with the same path
                self.final_redirect = self.final_redirect.split('?', 1)[0]
                self._search_final_redirect()
            else:
                self.logger.warning(f'Unable to find the final redirect: {self.final_redirect}')

    @property
    def number_entries(self) -> int:
        """Number of entries in the HAR file"""
        return len(self.entries)

    @property
    def initial_title(self) -> str:
        """Title of the first page in the capture"""
        if self.har['log']['pages'][0]['title']:
            return self.har['log']['pages'][0]['title']
        else:
            return '!! No title found !!'

    @property
    def initial_start_time(self) -> str:
        """Start time of the capture (UTC)"""
        if self.entries:
            return self.entries[0]['startedDateTime']
        return '-'

    @property
    def entries(self) -> List[Dict[str, Any]]:
        """List of all the entries in the capture"""
        if not self.har['log']['entries']:
            raise Har2TreeError('Empty HAR file (no entries), invalid capture.')
        return self.har['log']['entries']

    @property
    def root_url(self) -> str:
        """First URL of the capture"""
        return self.entries[0]['request']['url']

    def __find_referer(self, har_entry: Dict[str, Any]) -> Optional[str]:
        """Return the referer of the entry, if it exists."""
        for header_entry in har_entry['request']['headers']:
            if header_entry['name'] == 'Referer':
                return header_entry['value']
        return None

    @property
    def has_initial_redirects(self) -> bool:
        """True is the capture has redirects"""
        if self.final_redirect:
            return self.entries[0]['request']['url'] != self.final_redirect
        return False

    @property
    def initial_redirects(self) -> List[str]:
        '''All the initial redirects from the URL given by the user (if they can be found without building the tree)'''
        to_return = []
        if self.has_initial_redirects:
            # First request different of self.final_redirect, there is at least one redirect
            previous_entry = self.entries[0]
            for e in self.entries[1:]:
                # Lightweight way to hopefully skip the other URLs loaded in parallel with the redirect
                if (previous_entry['response']['redirectURL']):
                    # <insert flip a table GIF>, yes, rebuilding a redirectURL is *fun*
                    # NOTE: Google HAR file doesn't have an 'url' key in the 'response' bloc.
                    full_redirect = rebuild_url(previous_entry['request']['url'],
                                                previous_entry['response']['redirectURL'], [e['request']['url']])
                    if full_redirect == e['request']['url']:
                        to_return.append(e['request']['url'])
                        previous_entry = e
                    else:
                        continue
                elif (self.__find_referer(e) and (self.__find_referer(e) == previous_entry['response']['url'])):
                    to_return.append(e['request']['url'])
                    previous_entry = e
                else:
                    continue

                if e['request']['url'] == self.final_redirect:
                    break
            else:
                # Unable to find redirects chain, needs the whole tree
                to_return = []
                to_return.append(self.final_redirect)
                self.need_tree_redirects = True

        return to_return

    @property
    def root_referrer(self) -> Optional[str]:
        '''Get the referer if the first entry. Only relevant when there are multiple tree to attach together'''
        return self.__find_referer(self.entries[0])

    def __repr__(self) -> str:
        return f'HarFile({self.path}, {self.capture_uuid})'


class Har2Tree(object):

    def __init__(self, har_path: Path, capture_uuid: str):
        """Build the ETE Toolkit tree based on the HAR file, cookies, and HTML content
        :param har: harfile of a capture
        """
        logger = logging.getLogger(f'{__name__}.{self.__class__.__name__}')
        self.logger = Har2TreeLogAdapter(logger, {'uuid': capture_uuid})
        self.har = HarFile(har_path, capture_uuid)
        self.hostname_tree = HostNode(capture_uuid=self.har.capture_uuid)

        self._nodes_list: List[URLNode] = []
        self.all_url_requests: Dict[str, List[URLNode]] = {unquote_plus(url_entry['request']['url']): [] for url_entry in self.har.entries}

        # Format: pageref: node UUID
        self.pages_root: Dict[str, str] = {}

        self.all_redirects: List[str] = []
        self.all_referer: Dict[str, List[str]] = defaultdict(list)
        self.all_initiator_url: Dict[str, List[str]] = defaultdict(list)
        self._load_url_entries()

        # Generate cookies lookup tables
        # All the initial cookies sent with the initial request given to splash
        self.initial_cookies: Dict[str, Dict[str, Any]] = {}
        if hasattr(self._nodes_list[0], 'cookies_sent'):
            self.initial_cookies = {key: cookie for key, cookie in self._nodes_list[0].cookies_sent.items()}

        # Dictionary of all cookies received during the capture
        self.cookies_received: Dict[str, List[Tuple[str, URLNode, bool]]] = defaultdict(list)
        for n in self._nodes_list:
            if hasattr(n, 'cookies_received'):
                for domain, c_received, is_3rd_party in n.cookies_received:
                    self.cookies_received[c_received].append((domain, n, is_3rd_party))

        # Dictionary of all cookies sent during the capture
        self.cookies_sent: Dict[str, List[URLNode]] = defaultdict(list)
        for n in self._nodes_list:
            if hasattr(n, 'cookies_sent'):
                for c_sent in n.cookies_sent.keys():
                    self.cookies_sent[c_sent].append(n)

        # NOTE: locally_created contains all cookies not present in a response, and not passed at the begining of the capture to splash
        self.locally_created: Dict[str, Dict[str, Any]] = {}
        for c in self.har.cookies:
            c_identifier = f'{c["name"]}={c["value"]}'
            if (c_identifier not in self.cookies_received
                    and c_identifier not in self.initial_cookies):
                self.locally_created[f'{c["name"]}={c["value"]}'] = c

        # NOTE: locally_created_not_sent only contains cookies that are created locally, and never sent during the capture
        self.locally_created_not_sent: Dict[str, Dict[str, Any]] = self.locally_created.copy()
        # Cross reference the source of the cookie
        for n in self._nodes_list:
            if hasattr(n, 'cookies_sent'):
                for c_sent in n.cookies_sent:
                    # Remove cookie from list if sent during the capture.
                    self.locally_created_not_sent.pop(c_sent, None)
                    for domain, setter_node, is_3rd_party in self.cookies_received[c_sent]:
                        # Make sure the cookie wasn't set by an other response from an other domain,
                        # and only add the entry in the list if the query setting the cookie started before the
                        # current one
                        if n.hostname.endswith(domain) and setter_node.start_time < n.start_time:
                            # This cookie could have been set by this URL
                            n.cookies_sent[c_sent].append({'setter': setter_node,
                                                           '3rd_party': is_3rd_party})
        if self.locally_created_not_sent:
            self.logger.debug(f'Cookies locally created & never sent {json.dumps(self.locally_created_not_sent, indent=2)}')

        # Add context if urls are found in external_ressources
        for n in self._nodes_list:
            if hasattr(n, 'external_ressources'):
                for type_ressource, urls in n.external_ressources.items():
                    for url in urls:
                        if url not in self.all_url_requests:
                            continue
                        for node in self.all_url_requests[url]:
                            if node.empty_response:
                                # If the body of the response was empty, skip.
                                continue
                            if type_ressource == 'img':
                                node.add_feature('image', True)

                            if type_ressource == 'script':
                                node.add_feature('js', True)

                            if type_ressource == 'video':
                                node.add_feature('video', True)

                            if type_ressource == 'audio':
                                node.add_feature('audio', True)

                            if type_ressource == 'iframe':
                                node.add_feature('iframe', True)

                            if type_ressource == 'embed':  # FIXME other icon?
                                node.add_feature('octet_stream', True)

                            if type_ressource == 'source':  # FIXME: Can be audio, video, or picture
                                node.add_feature('octet_stream', True)

                            # NOTE: the URL is probably not a CSS
                            # if type_ressource == 'link':  # FIXME: Probably a css?
                            #    node.add_feature('css', True)

                            if type_ressource == 'object':  # FIXME: Same as embed, but more things
                                node.add_feature('octet_stream', True)

        self.url_tree = self._nodes_list.pop(0)

    @property
    def total_load_time(self) -> timedelta:
        return sum([urlnode.time for urlnode in self.url_tree.traverse()], timedelta())

    @property
    def total_size_responses(self) -> int:
        return sum(urlnode.body.getbuffer().nbytes for urlnode in self.url_tree.traverse() if not urlnode.empty_response)

    @property
    def stats(self) -> Dict[str, Any]:
        """Statistics about the capture"""
        to_return: Dict[str, Any] = {'total_hostnames': 0}
        to_return['total_urls'] = sum(1 for _ in self.url_tree.traverse())
        to_return['total_unique_urls'] = len({node.name for node in self.url_tree.traverse()})

        all_cookies_sent: Set[str] = set()
        all_cookies_received: Set[Tuple[str, str, bool]] = set()
        all_hostnames: Set[str] = set()
        for host_node in self.hostname_tree.traverse():
            to_return['total_hostnames'] += 1
            all_hostnames.add(host_node.name)
            all_cookies_sent.update(host_node.cookies_sent)
            all_cookies_received.update(host_node.cookies_received)

        to_return['total_unique_hostnames'] = len(all_hostnames)
        to_return['total_cookies_sent'] = len(all_cookies_sent)
        to_return['total_cookies_received'] = len(all_cookies_received)
        node, distance = self.hostname_tree.get_farthest_leaf()
        to_return['tree_depth'] = int(distance) + 1
        to_return['total_redirects'] = len(self.redirects)
        to_return['total_load_time'] = str(self.total_load_time)
        to_return['total_size_responses'] = self.total_size_responses
        return to_return

    @property
    def redirects(self) -> List[str]:
        """List of redirects for this tree"""
        if not self.root_after_redirect:
            return []
        redirect_node = self.url_tree.search_nodes(name=self.root_after_redirect)
        if not redirect_node:
            self.logger.warning(f'Unable to find node {self.root_after_redirect}')
            return []
        elif len(redirect_node) > 1:
            self.logger.warning(f'Too many nodes found for {self.root_after_redirect}: {redirect_node}')
        return [a.name for a in reversed(redirect_node[0].get_ancestors())] + [redirect_node[0].name]

    @property
    def root_referer(self) -> Optional[str]:
        '''Referer if the first entry. Only relevant when there are multiple tree to attach together'''
        return self.har.root_referrer

    @property
    def user_agent(self) -> str:
        """User agent used for the capture"""
        return self.url_tree.user_agent

    @property
    def start_time(self) -> datetime:
        """Start time of the capture"""
        return self.url_tree.start_time

    def _load_url_entries(self) -> None:
        '''Initialize the list of nodes to attach to the tree (as URLNode),
        and create a list of note for each URL we have in the HAR document'''

        got_final_redirect: bool = False

        for i, url_entry in enumerate(self.har.entries):
            n = URLNode(capture_uuid=self.har.capture_uuid, name=unquote_plus(url_entry['request']['url']))
            if self.har.html_content and n.name == self.har.final_redirect and not got_final_redirect:
                n.load_har_entry(url_entry, list(self.all_url_requests.keys()), self.har.html_content)
                # NOTE 2021-05-28: only mark one node as final redirect
                got_final_redirect = True
            else:
                n.load_har_entry(url_entry, list(self.all_url_requests.keys()))
            if hasattr(n, 'redirect_url'):
                self.all_redirects.append(n.redirect_url)

            if hasattr(n, 'initiator_url'):
                # The HAR file was created by chrome/chromium and we got the _initiator key
                self.all_initiator_url[n.initiator_url].append(n.name)

            if url_entry['startedDateTime'] in self.har.pages_start_times:
                for page in self.har.pages_start_times[url_entry['startedDateTime']]:
                    if page['id'] == n.pageref:
                        # This node is the root entry of a page. Can be used as a fallback when we build the tree
                        self.pages_root[n.pageref] = n.uuid
                        break

            # NOTE 2021-05-28: Ignore referer for first entry
            if hasattr(n, 'referer') and i > 0:
                # NOTE 2021-05-14: referer to self are a real thing: url -> POST to self
                if n.name != n.referer or ('method' in n.request and n.request['method'] == 'POST'):
                    self.all_referer[n.referer].append(n.name)

            self._nodes_list.append(n)
            self.all_url_requests[n.name].append(n)

        # So, sometimes, the startedDateTime in the page list is fucked up
        # Ex: start time of page 3 == start time of page 1. This is wrong, but it happens
        # Solution: if we miss an entry in self.pages_root, we put the first node with that page ref.
        for _, pages in self.har.pages_start_times.items():
            for page in pages:
                if page['id'] not in self.pages_root:
                    for node in self._nodes_list:
                        if node.pageref == page['id']:
                            self.pages_root[node.pageref] = node.uuid
                            break

    def get_host_node_by_uuid(self, uuid: str) -> HostNode:
        """Returns the node with this UUID from the HostNode tree"""
        return self.hostname_tree.search_nodes(uuid=uuid)[0]

    def get_url_node_by_uuid(self, uuid: str) -> URLNode:
        """Returns the node with this UUID from the URLNode tree"""
        return self.url_tree.search_nodes(uuid=uuid)[0]

    @property
    def root_after_redirect(self) -> Optional[str]:
        '''Iterate through the list of entries until there are no redirectURL in
        the response anymore: it is the first URL loading content.
        '''
        if self.har.has_initial_redirects:
            return self.har.final_redirect
        return None

    @property
    def rendered_node(self) -> URLNode:
        node = self.url_tree.search_nodes(name=self.har.final_redirect)
        if node:
            return node[0]
        raise Har2TreeError('Unable to find the rendered node.')

    def to_json(self) -> str:
        """Dump the whole HostNode tree to json (for d3js)"""
        return self.hostname_tree.to_json()

    def make_hostname_tree(self, root_nodes_url: Union[URLNode, List[URLNode]], root_node_hostname: HostNode) -> None:
        """ Groups all the URLs by domain in the HostNode tree.
        `root_node_url` can be a list of nodes called by the same `root_node_hostname`
        """
        if not isinstance(root_nodes_url, list):
            root_nodes_url = [root_nodes_url]
        for root_node_url in root_nodes_url:
            children_hostnames: Dict[str, HostNode] = {}
            sub_roots: Dict[HostNode, List[URLNode]] = defaultdict(list)
            for child_node_url in root_node_url.get_children():
                if child_node_url.hostname is None:
                    self.logger.warning(f'Fucked up URL: {child_node_url}')
                    continue
                if child_node_url.hostname in children_hostnames:
                    child_node_hostname = children_hostnames[child_node_url.hostname]
                else:
                    child_node_hostname = root_node_hostname.add_child(HostNode(capture_uuid=self.har.capture_uuid, name=child_node_url.hostname))
                    children_hostnames[child_node_url.hostname] = child_node_hostname
                child_node_hostname.add_url(child_node_url)
                child_node_url.add_feature('hostnode_uuid', child_node_hostname.uuid)

                if not child_node_url.is_leaf():
                    sub_roots[child_node_hostname].append(child_node_url)
            for child_node_hostname, child_nodes_url in sub_roots.items():
                self.make_hostname_tree(child_nodes_url, child_node_hostname)

    def make_tree(self) -> URLNode:
        """Build URL and Host trees"""
        self._make_subtree(self.url_tree)
        while self._nodes_list:
            # We were not able to attach a few things using the referers, redirects, or grepping on the page.
            # The remaining nodes are things we cannot attach for sure, so we try a few things, knowing it won't be perfect.
            node = self._nodes_list.pop(0)
            self._make_subtree_fallback(node)

        # Initialize the hostname tree root
        self.hostname_tree.add_url(self.url_tree)
        self.make_hostname_tree(self.url_tree, self.hostname_tree)
        return self.url_tree

    @trace_make_subtree_fallback
    def _make_subtree_fallback(self, node: URLNode, dev_debug: bool=False) -> None:
        # Sometimes, the har has a list of pages, generally when we have HTTP redirects.
        # IF we have more than one page in the list
        # AND the orphan node's pageref points to an other page than the first one <= FIXME not enabled yet
        # AND we already have a node in the tree with this pageref
        # => attach to that node.
        if len(self.har.har['log']['pages']) > 1 and node.pageref != self.har.har['log']['pages'][0] and self.pages_root[node.pageref] != node.uuid:
            # In that case, we check if there is already a page with the pageref of the orphan node,
            # and attach the node to that. NOTE: we can only do that if thre is already a node withi this pageref in the tree.
            # This node is not a page root, we can attach it \o/
            page_root_node = self.get_url_node_by_uuid(self.pages_root[node.pageref])
            if dev_debug:
                self.logger.warning(f'Failed to attach URLNode in the normal process, attaching node to page {node.pageref} - Node: {page_root_node.uuid} - {page_root_node.name}.')
            self._make_subtree(page_root_node, [node])
        elif self.url_tree.search_nodes(name=self.root_after_redirect):
            # Generally, when we have a bunch of redirects, they do not branch out before the final landing page
            # *but* it is not always the case: some intermediary redirects will have calls to 3rd party pages.
            # Hopefully, this last case was taken care of in the branch above.
            # In this branch, we get the landing page after the redirects (if any), and attach the node to it.
            if dev_debug:
                self.logger.warning(f'Failed to attach URLNode in the normal process, attaching node to final redirect: {self.root_after_redirect}.')
            self._make_subtree(self.url_tree.search_nodes(name=self.root_after_redirect)[0], [node])
        else:
            # No luck, the node is root for this pageref, let's attach it to the prior page in the list, or the very first node (tree root)
            page_before = self.har.har['log']['pages'][0]
            for page in self.har.har['log']['pages'][1:]:
                if page['id'] == node.pageref:
                    break
                # Sometimes, the page listed in the list of pages is not related to
                # any of the entries. Go figure what happened.
                # If that's the case, we cannot use it as a reference
                if page['id'] in self.pages_root:
                    page_before = page
            page_root_node = self.get_url_node_by_uuid(self.pages_root[page_before['id']])
            if dev_debug:
                self.logger.warning(f'Failed to attach URLNode in the normal process, best guess attach to page {node.pageref} - Node: {page_root_node.uuid} - {page_root_node.name}.')
            self._make_subtree(page_root_node, [node])

    @trace_make_subtree
    def _make_subtree(self, root: URLNode, nodes_to_attach: Optional[List[URLNode]]=None, dev_debug: bool=False) -> None:
        """Recursive method building each level of the tree"""
        matching_urls: List[URLNode]
        if nodes_to_attach is None:
            # We're in the actual root node
            unodes = [self.url_tree]
        else:
            unodes = []
            # NOTE 2021-05-14: skip nodes with status 0: Loading the URL failed, splash retried it, and we have an other node with the same URL in the list.
            url_valid_status = [unode.name for unode in nodes_to_attach if unode.response['status'] != 0]
            for unode in nodes_to_attach:
                if unode.response['status'] == 0 and unode.name in url_valid_status:
                    self.logger.info(f'Status code 0 for {unode.name}, skip node.')
                    continue

                if dev_debug:
                    self.logger.warning(f'Attaching URLNode {unode.name} to {root.name}.')

                unodes.append(root.add_child(unode))

        if dev_debug:
            self.logger.warning(f'Tracing subnodes appended to {root.uuid} - {root.hostname} - {root.name}.')
            if not unodes:
                self.logger.warning('No subnodes were attached, the tree ends there.')
            else:
                self.logger.warning('The following subnodes were attached:')
                for unode in unodes:
                    self.logger.warning(unode.name)

        for unode in unodes:
            # NOTE: as we're calling the method recursively, a node containing URLs in its external_ressources will attach
            # the the subnodes to itself, even if the subnodes have a different referer. It will often be correct, but not always.
            if hasattr(unode, 'redirect') and not hasattr(unode, 'redirect_to_nothing'):
                # If the subnode has a redirect URL set, we get all the requests matching this URL
                # One may think the entry related to this redirect URL has a referer to the parent. One would be wrong.
                # URL 1 has a referer, and redirects to URL 2. URL 2 has the same referer as URL 1.
                # => In that case, we want to attach URL 2 to URL 1, and not to the referer of URL 1.
                if unode.redirect_url in self.all_redirects:
                    self.all_redirects.remove(unode.redirect_url)  # Makes sure we only follow a redirect once
                    matching_urls = [url_node for url_node in self.all_url_requests[unode.redirect_url] if url_node in self._nodes_list]
                    if len(matching_urls) > 1:
                        # NOTE 2021-05-14: a redirect only redirects to one url, if there are a more, we probably have the same url somewhere else in the tree.
                        # *but* we may still have more than one entry here: splash will sometimes add a response with status code 0, and retry it.
                        # If that's the case, pass all the URLs up to the point we have a valid status code.
                        to_attach = []
                        for url in matching_urls:
                            to_attach.append(url)
                            if url.response['status'] != 0:
                                break
                        matching_urls = to_attach
                    self._nodes_list = [node for node in self._nodes_list if node not in matching_urls]
                    if dev_debug:
                        self.logger.warning(f'Redirections from {unode.name} to {matching_urls}.')
                    self._make_subtree(unode, matching_urls)
                    # NOTE 2021-05-15: in case the redirect goes to self, we want to attach the remaining part of the tree to the redirected node
                    if root.name == unode.name:
                        continue
                else:
                    self.logger.warning(f'The URLNode has a redirect to something we already processed ({unode.redirect_url}), this should not happen.')

            # The node can have a redirect, but also trigger ressources refering to themselves, we need to trigger this code on each node.

            if self.all_initiator_url.get(unode.name):
                # The URL (unode.name) is in the list of known urls initiating calls
                for u in self.all_initiator_url[unode.name]:
                    matching_urls = [url_node for url_node in self.all_url_requests[u]
                                     if url_node in self._nodes_list and hasattr(url_node, 'initiator_url') and url_node.initiator_url == unode.name]
                    self._nodes_list = [node for node in self._nodes_list if node not in matching_urls]
                    if dev_debug:
                        self.logger.warning(f'Found via initiator from {unode.name} to {matching_urls}.')
                    self._make_subtree(unode, matching_urls)

            if self.all_referer.get(unode.name):
                # The URL (unode.name) is in the list of known referers
                for u in self.all_referer[unode.name]:
                    matching_urls = [url_node for url_node in self.all_url_requests[u]
                                     if url_node in self._nodes_list and hasattr(url_node, 'referer') and url_node.referer == unode.name]
                    self._nodes_list = [node for node in self._nodes_list if node not in matching_urls]
                    if dev_debug:
                        self.logger.warning(f'Found via referer from {unode.name} to {matching_urls}.')
                    self._make_subtree(unode, matching_urls)

            if self.all_referer.get(unode.alternative_url_for_referer):
                # The URL (unode.name) stripped at the first `#` is in the list of known referers
                for u in self.all_referer[unode.alternative_url_for_referer]:
                    matching_urls = [url_node for url_node in self.all_url_requests[u]
                                     if url_node in self._nodes_list and hasattr(url_node, 'referer') and url_node.referer == unode.alternative_url_for_referer]
                    self._nodes_list = [node for node in self._nodes_list if node not in matching_urls]
                    if dev_debug:
                        self.logger.warning(f'Found via alternative referer from {unode.name} to {matching_urls}.')
                    self._make_subtree(unode, matching_urls)

            if hasattr(unode, 'external_ressources'):
                # the url loads external things, and some of them have no referer....
                for external_tag, links in unode.external_ressources.items():
                    for link in links:
                        if link not in self.all_url_requests or link == self.har.final_redirect:
                            # We have a lot of false positives
                            # 2021-06-19: or the URL of the final redirect is somewhere in an embeded content. In that case, we don't want to attach to the sub-node.
                            continue
                        matching_urls = [url_node for url_node in self.all_url_requests[link] if url_node in self._nodes_list]
                        self._nodes_list = [node for node in self._nodes_list if node not in matching_urls]
                        if dev_debug:
                            self.logger.warning(f'Found from {unode.name} via external ressources ({external_tag}): {matching_urls}.')
                        self._make_subtree(unode, matching_urls)

    def __repr__(self) -> str:
        return f'Har2Tree({self.har.path}, {self.har.capture_uuid})'
