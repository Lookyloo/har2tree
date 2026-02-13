#!/usr/bin/env python

from __future__ import annotations

import gzip
import hashlib
import json
import logging

from collections import defaultdict
from datetime import datetime, timedelta
from functools import wraps, lru_cache
from io import BytesIO
from operator import itemgetter
from pathlib import Path
from typing import Any, TypedDict
from collections.abc import Iterator
from collections.abc import Callable
from urllib.parse import unquote_plus, urlparse

from .helper import rebuild_url, Har2TreeError, Har2TreeLogAdapter
from .nodes import HostNode, URLNode

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
    def _impl(self: Any, root: URLNode, nodes_to_attach: list[URLNode] | None=None,
              dev_debug: bool=False, fallback: bool=False) -> None:
        if dev_debug_mode:
            __load_debug_files()
            if dev_debug_url and root.name == dev_debug_url or nodes_to_attach is not None and any(True for u in nodes_to_attach if u.name == dev_debug_url):
                root.logger.warning(f'Debugging URL: {dev_debug_url}.')
                dev_debug = True
            elif dev_debug_hostname and root.hostname == dev_debug_hostname or nodes_to_attach is not None and any(True for u in nodes_to_attach if u.hostname == dev_debug_hostname):
                root.logger.warning(f'Debugging Hostname: {dev_debug_hostname}.')
                dev_debug = True
        return method(self, root, nodes_to_attach, dev_debug, fallback)
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


# NOTE: Copy from PlaywrightCapture to avoid extra dep
class FramesResponse(TypedDict, total=False):

    name: str
    url: str
    content: str | None
    children: list[FramesResponse] | None


class HarFile():

    def __init__(self, harfile: Path, capture_uuid: str):
        """Overview of the HAR file itself"""
        logger = logging.getLogger(f'{__name__}.{self.__class__.__name__}')
        self.capture_uuid: str = capture_uuid
        self.logger = Har2TreeLogAdapter(logger, {'uuid': self.capture_uuid})
        self.path = harfile

        try:
            self.har: dict[str, Any]
            if self.path.suffix == '.gz':
                self.is_compressed = True
                with gzip.open(self.path, 'rb') as f:
                    self.har = json.load(f)
            else:
                self.is_compressed = False
                with self.path.open() as f:
                    self.har = json.load(f)
        except json.decoder.JSONDecodeError as e:
            raise Har2TreeError(f'HAR file is not a valid JSON file: {e}')

        root_name = self.path.stem
        if self.is_compressed:
            # we have .har.gz, and we want what comes *before* that
            root_name = Path(root_name).stem

        # I mean it, that's the last URL the browser was on
        last_redirect_file = self.path.parent / f'{root_name}.last_redirect.txt'
        if last_redirect_file.is_file():
            with last_redirect_file.open('r') as _lr:
                last_redirect = unquote_plus(_lr.read())
            self.final_redirect: str = last_redirect
            if not self._search_final_redirect():
                if last_redirect.startswith('chrome') or last_redirect.startswith('about'):
                    # the capture failed.
                    pass
                else:
                    self.logger.info(f'Final redirect URL from address bar not in tree: {last_redirect}')
        else:
            self.logger.debug('No last_redirect file available.')
            self.final_redirect = ''

        cookiefile = self.path.parent / f'{root_name}.cookies.json'
        if cookiefile.is_file():
            with cookiefile.open() as c:
                self.cookies: list[dict[str, Any]] = json.load(c)
        else:
            self.logger.debug('No cookies file available.')
            self.cookies = []

        framesfile = self.path.parent / f'{root_name}.frames.json'
        if framesfile.is_file():
            with framesfile.open() as c:
                self.frames: FramesResponse = json.load(c)
        else:
            self.logger.debug('No frames file available.')
            self.frames = {}

        dlfile = self.path.parent / f'{root_name}.data'
        dlfilename = self.path.parent / f'{root_name}.data.filename'
        self.downloaded_file: BytesIO | None
        self.downloaded_filename: str
        if dlfile.is_file() and dlfilename.is_file():
            with dlfilename.open('r') as _fn:
                self.downloaded_filename = _fn.read()
            with dlfile.open('rb') as _f:
                self.downloaded_file = BytesIO(_f.read())
        else:
            self.logger.debug('No downloaded file.')
            self.downloaded_file = None
            self.downloaded_filename = ''

        htmlfile = self.path.parent / f'{root_name}.html'
        self.html_content: BytesIO | None
        if htmlfile.is_file():
            with htmlfile.open('rb') as _h:
                self.html_content = BytesIO(_h.read())
        else:
            self.logger.debug('No rendered HTML content.')
            self.html_content = None

        # Sorting the entries by start time (it isn't the case by default)
        # Reason: A specific URL cannot be loaded by something that hasn't been already started
        self.entries.sort(key=itemgetter('startedDateTime'))

        # Used to find the root entry of a page in the capture
        # NOTE 2020-05-19: Turns out multiple pages can have the exact same timestamp...
        self.pages_start_times: dict[str, list[dict[str, Any]]] = defaultdict(list)
        if 'pages' in self.har['log']:
            for page in self.har['log']['pages']:
                self.pages_start_times[page['startedDateTime']].append(page)
            # The first entry has a different start time as the one from the list, add that
            if self.entries:
                self.pages_start_times[self.initial_start_time].append(self.har['log']['pages'][0])

        # Set to false if initial_redirects fails to find the chain.
        self.need_tree_redirects = False

    def _search_final_redirect(self) -> bool:
        """Try to find the final path to the final redirect without building the tree"""
        for e in self.entries:
            unquoted_url = unquote_plus(e['request']['url'])
            if unquoted_url == self.final_redirect:
                return True
            elif unquoted_url.startswith(f'{self.final_redirect}?'):
                # WARNING: the URL in that file may not be present in the HAR: the query part is stripped by splash
                self.final_redirect = unquoted_url
                return True
        else:
            # Update 2020-04-01: .. but the fragment is not striped so self.final_redirect may not be found
            # Unless we find the entry in the har, we need to search again without the fragment
            if '#' in self.final_redirect:
                self.final_redirect = self.final_redirect.split('#', 1)[0]
                return self._search_final_redirect()
            elif '?' in self.final_redirect:
                # At this point, we're trying things. The final URL returned by splash may have been changed
                # in JavaScript and never appear in the HAR. Let's try to find the closest one with the same path
                self.final_redirect = self.final_redirect.split('?', 1)[0]
                return self._search_final_redirect()
            else:
                self.logger.info(f'Unable to find the final redirect: {self.final_redirect}')
        return False

    @property
    def number_entries(self) -> int:
        """Number of entries in the HAR file"""
        return len(self.entries)

    @property
    def initial_title(self) -> str:
        """Title of the first page in the capture"""
        if 'pages' in self.har['log'] and self.har['log']['pages'][0]['title']:
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
    def entries(self) -> list[dict[str, Any]]:
        """List of all the entries in the capture"""
        if not self.har['log']['entries']:
            raise Har2TreeError('Empty HAR file (no entries), invalid capture.')
        return self.har['log']['entries']

    @property
    def root_url(self) -> str:
        """First URL of the capture"""
        return self.entries[0]['request']['url'].strip()

    def __find_header_value(self, har_entry: dict[str, Any], header_name: str) -> str | None:
        """Get the value of a specific header"""
        for header_entry in har_entry['request']['headers']:
            if header_entry['name'].lower() == header_name.lower():
                return header_entry['value']
        return None

    @property
    def has_initial_redirects(self) -> bool:
        """True is the capture has redirects.
        Meaning: the first URL in the HAR is different from the URL in the address bar"""
        return self.entries[0]['request']['url'] != self.final_redirect

    @property
    def initial_redirects(self) -> list[str]:
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
                elif (self.__find_header_value(e, 'Referer') and 'url' in previous_entry['response']
                        and (self.__find_header_value(e, 'Referer') == previous_entry['response']['url'])):
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
    def root_referrer(self) -> str | None:
        '''Get the referer if the first entry. Only relevant when there are multiple tree to attach together'''
        return self.__find_header_value(self.entries[0], 'Referer')

    @property
    def root_user_agent(self) -> str | None:
        '''Get the User Agent of the first entry'''
        return self.__find_header_value(self.entries[0], 'User-Agent')

    def __repr__(self) -> str:
        return f'HarFile({self.path}, {self.capture_uuid})'


class Har2Tree:

    def __init__(self, har_path: Path, capture_uuid: str):
        """Build the ETE Toolkit tree based on the HAR file, cookies, and HTML content
        :param har: harfile of a capture
        """
        logger = logging.getLogger(f'{__name__}.{self.__class__.__name__}')
        self.logger = Har2TreeLogAdapter(logger, {'uuid': capture_uuid})
        self.har = HarFile(har_path, capture_uuid)
        self.hostname_tree = HostNode(capture_uuid=self.har.capture_uuid)

        self._nodes_list: list[URLNode] = []
        self.all_url_requests: dict[str, list[URLNode]] = {unquote_plus(url_entry['request']['url']): [] for url_entry in self.har.entries}

        # Format: pageref: node UUID
        self.pages_root: dict[str, str] = {}

        self.all_redirects: list[str] = []
        # 2025-11-16: make values of referers and initiators sets because there will be duplicates
        self.all_referer: dict[str, set[str]] = defaultdict(set)
        self.all_initiator_url: dict[str, set[str]] = defaultdict(set)
        self._load_url_entries()

        # Generate cookies lookup tables
        # All the initial cookies sent with the initial request given to splash
        self.initial_cookies: dict[str, dict[str, Any]] = {}
        if hasattr(self._nodes_list[0], 'cookies_sent'):
            self.initial_cookies = {key: cookie for key, cookie in self._nodes_list[0].cookies_sent.items()}

        # Dictionary of all cookies received during the capture
        self.cookies_received: dict[str, list[tuple[str, URLNode, bool]]] = defaultdict(list)
        for n in self._nodes_list:
            if hasattr(n, 'cookies_received'):
                for domain, c_received, is_3rd_party in n.cookies_received:
                    self.cookies_received[c_received].append((domain, n, is_3rd_party))

        # Dictionary of all cookies sent during the capture
        self.cookies_sent: dict[str, list[URLNode]] = defaultdict(list)
        for n in self._nodes_list:
            if hasattr(n, 'cookies_sent'):
                for c_sent in n.cookies_sent.keys():
                    self.cookies_sent[c_sent].append(n)

        # NOTE: locally_created contains all cookies not present in a response, and not passed at the begining of the capture to splash
        self.locally_created: dict[str, dict[str, Any]] = {}
        for c in self.har.cookies:
            c_identifier = f'{c["name"]}={c["value"]}'
            if (c_identifier not in self.cookies_received
                    and c_identifier not in self.initial_cookies):
                self.locally_created[f'{c["name"]}={c["value"]}'] = c

        # NOTE: locally_created_not_sent only contains cookies that are created locally, and never sent during the capture
        self.locally_created_not_sent: dict[str, dict[str, Any]] = self.locally_created.copy()
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

    def _url_to_local_only_content(self, url: str | None) -> bool:
        return (url is None
                or url in ['about:blank', 'about:srcdoc', '']  # not loading anything remotely
                or url.startswith('data')  # base64 encoded content
                or url.startswith('chrome-error')  # not in the HAR/tree
                or url.startswith('blob')  # blobs aren't URLs
                )

    def _load_iframes(self, current: URLNode, frames: FramesResponse) -> None:
        if not frames.get('content') or frames['content'] is None:
            # NOTE: debug stuff, no content makes it pretty useless.
            if frames.get('url'):
                if self._url_to_local_only_content(frames['url']):
                    self.logger.info('Got an empty frame to local content.')
                else:
                    u = unquote_plus(frames['url'])
                    self.logger.warning(f'Got a url ({u}) for the frame, but no content')
            else:
                self.logger.info('Got a frame, but no content.')
            return

        if frames.get('url') and not self._url_to_local_only_content(frames['url']):
            u = unquote_plus(frames['url'])
            possible_child_name = {u, u.split('#', 1)[0]}
            # this url should be in a node directly attached to that one
            # we need to find that node
            for child in current.traverse():
                if child.name in possible_child_name:
                    self.logger.debug(f'Found URL "{u}".')
                    # Found the node, adding the content
                    if not hasattr(child, 'rendered_frame'):
                        child.rendered_frame = []
                    child.rendered_frame.append(BytesIO(frames['content'].encode()))
                    # and mark the node as iframe
                    child.add_feature('iframe', True)
                    # if there are children, use that node as parent and call the current method recursvely
                    if f_children := frames.get('children'):
                        for f_child in f_children:
                            self._load_iframes(child, f_child)
                    break
            else:
                # Couldn'd find the node Oo
                to_print = ', '.join(possible_child_name)
                children_to_print = ', '.join([child.name for child in current.traverse()])
                self.logger.warning(f'Unable to find "{to_print}" in the children of "{current.name}" - {children_to_print}')
        else:
            self.logger.debug(f'"{current.name}" contains an iFrame.')
            # No URL, this frame is directly in the parent frame.
            if not hasattr(current, 'rendered_frame'):
                current.rendered_frame = []
            current.rendered_frame.append(BytesIO(frames['content'].encode()))
            self.logger.debug(f'"{current.name}" has {len(current.rendered_frame)} iFrames.')
            # and mark the node as iframe
            current.add_feature('iframe', True)
            # if there are children, use that node as parent and call the current method recursvely
            if f_children := frames.get('children'):
                for f_child in f_children:
                    self._load_iframes(current, f_child)

    @property
    def initial_referer(self) -> str | None:
        '''The referer passed to the first URL in the tree'''
        if hasattr(self.url_tree, 'referer'):
            return self.url_tree.referer
        return None

    @property
    def total_load_time(self) -> timedelta:
        return sum((urlnode.time for urlnode in self.url_tree.traverse()), timedelta())

    @property
    def total_size_responses(self) -> int:
        return sum(urlnode.body.getbuffer().nbytes for urlnode in self.url_tree.traverse() if not urlnode.empty_response)

    @property
    def stats(self) -> dict[str, Any]:
        """Statistics about the capture"""
        to_return: dict[str, Any] = {'total_hostnames': 0}
        to_return['total_urls'] = sum(1 for _ in self.url_tree.traverse())
        to_return['total_unique_urls'] = len({node.name for node in self.url_tree.traverse()})

        all_cookies_sent: set[str] = set()
        all_cookies_received: set[tuple[str, str, bool]] = set()
        all_hostnames: set[str] = set()
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
    def redirects(self) -> list[str]:
        """List of redirects for this tree"""
        return [a.name for a in reversed(self.rendered_node.get_ancestors())] + [self.rendered_node.name]

    @property
    def root_referer(self) -> str | None:
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

    @lru_cache
    def build_all_hashes(self, algorithm: str='sha1') -> dict[str, list[URLNode]]:
        '''Build on demand hashes for all the ressources of the tree, in the alorighm provided by the user'''
        if algorithm not in hashlib.algorithms_available:
            raise Har2TreeError(f'Invalid algorithm ({algorithm}), only the following are supported: {hashlib.algorithms_available}')

        to_return: dict[str, list[URLNode]] = defaultdict(list)
        for urlnode in self.url_tree.traverse():
            if urlnode.empty_response:
                continue
            h = hashlib.new(algorithm)
            h.update(urlnode.body.getbuffer())
            to_return[h.hexdigest()].append(urlnode)
            if hasattr(urlnode, 'embedded_ressources'):
                for _mimetype, blobs in urlnode.embedded_ressources.items():
                    for blob in blobs:
                        h = hashlib.new(algorithm)
                        h.update(blob[1].getbuffer())
                        to_return[h.hexdigest()].append(urlnode)
        return to_return

    def _load_url_entries(self) -> None:
        '''Initialize the list of nodes to attach to the tree (as URLNode),
        and create a list of note for each URL we have in the HAR document'''

        #  NOTE 2021-09-06 - Clear URL entries:
        # Some responses have a HTTP status code set to 0. It is generally incorrect,
        # but it is also the default code set by splash when something went bad when
        # loading a specific URL, and we often have an other entry requesting the same URL (but not always)
        # * If we have an other query to the same URL in the list, discard the one with a status code to 0
        # * If we don't, use the entry in the tree.
        entries_with_0_status: dict[str, list[int]] = defaultdict(list)
        entries_with_negative_status: dict[str, list[int]] = defaultdict(list)
        ignore: list[int] = []
        for i, url_entry in enumerate(self.har.entries):
            url = unquote_plus(url_entry["request"]["url"])
            if url_entry['response']['status'] == 0:
                entries_with_0_status[url].append(i)
                self.logger.debug(f'Status code 0 for {url}, maybe skip node.')
                continue
            if url_entry['response']['status'] < 0:
                entries_with_negative_status[url].append(i)
                self.logger.debug(f'Status code {url_entry["response"]["status"]} for {url}, maybe skip node.')
                continue
            # Response status is not 0 or negative
            if url in entries_with_0_status:
                ignore.extend(entries_with_0_status[url])
            elif url in entries_with_negative_status:
                ignore.extend(entries_with_negative_status[url])

        for i, url_entry in enumerate(self.har.entries):
            if i in ignore:
                continue

            n = URLNode(capture_uuid=self.har.capture_uuid)
            n.load_har_entry(url_entry, list(self.all_url_requests.keys()))
            if hasattr(n, 'redirect_url'):
                self.all_redirects.append(n.redirect_url)

            if hasattr(n, 'initiator_url'):
                # The HAR file was created by chrome/chromium and we got the _initiator key
                self.all_initiator_url[n.initiator_url].add(n.name)

            if url_entry['startedDateTime'] in self.har.pages_start_times:
                for page in self.har.pages_start_times[url_entry['startedDateTime']]:
                    if hasattr(n, 'pageref') and page['id'] == n.pageref:
                        # This node is the root entry of a page. Can be used as a fallback when we build the tree
                        self.pages_root[n.pageref] = n.uuid
                        break

            # NOTE 2021-05-28: Ignore referer for first entry
            if hasattr(n, 'referer') and i > 0:
                # NOTE 2021-05-14: referer to self are a real thing: url -> POST to self
                if n.name != n.referer or ('method' in n.request and n.request['method'] == 'POST'):
                    self.all_referer[n.referer].add(n.name)

            self._nodes_list.append(n)
            self.all_url_requests[n.name].append(n)
        # So, sometimes, the startedDateTime in the page list is fucked up
        # Ex: start time of page 3 == start time of page 1. This is wrong, but it happens
        # Solution: if we miss an entry in self.pages_root, we put the first node with that page ref.
        for _, pages in self.har.pages_start_times.items():
            for page in pages:
                if page['id'] not in self.pages_root:
                    for node in self._nodes_list:
                        if not hasattr(node, 'pageref'):
                            # 2022-11-19: No pageref for this node in the HAR file,
                            #             this is weird but we need it as a fallback.
                            node.add_feature('pageref', page['id'])
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
    def rendered_node(self) -> URLNode:
        node = self.url_tree.search_nodes(name=self.har.final_redirect)
        if node:
            return node[0]

        # Just try to get the best guess: first node after JS/HTTP redirects
        curnode = self.url_tree
        while hasattr(curnode, 'redirect') and curnode.redirect:
            for child in curnode.children:
                if child.name == curnode.redirect_url:
                    curnode = child
                    break
            else:
                # 2022-09-06: the current node has a redirect but it cannot be located in the childrens
                # This is a bug and shouldn't happen, but when it does, we must break out of the while loop
                self.logger.critical('Unable to find redirected node in childrens. This capture is buggy.')
                break
        return curnode

    def to_json(self) -> str:
        """Dump the whole HostNode tree to json (for d3js)"""
        return self.hostname_tree.to_json()

    def make_hostname_tree(self, root_nodes_url: URLNode | list[URLNode], root_node_hostname: HostNode) -> None:
        """ Groups all the URLs by domain in the HostNode tree.
        `root_node_url` can be a list of nodes called by the same `root_node_hostname`
        """
        if not isinstance(root_nodes_url, list):
            root_nodes_url = [root_nodes_url]
        for root_node_url in root_nodes_url:
            children_hostnames: dict[str, HostNode] = {}
            sub_roots: dict[HostNode, list[URLNode]] = defaultdict(list)
            for child_node_url in root_node_url.get_children():
                if child_node_url.hostname is None:
                    self.logger.warning(f'Fucked up URL: {child_node_url}')
                    continue
                # Attempt to find an existing HostNode with the same hostname
                if child_node_url.hostname not in children_hostnames:
                    # create a new hostnode, add it in the tree
                    child_node_hostname = HostNode(capture_uuid=self.har.capture_uuid)
                    root_node_hostname.add_child(child_node_hostname)
                    children_hostnames[child_node_url.hostname] = child_node_hostname
                else:
                    child_node_hostname = children_hostnames[child_node_url.hostname]

                child_node_hostname.add_url(child_node_url)

                if not child_node_url.is_leaf():
                    sub_roots[child_node_hostname].append(child_node_url)

            for child_node_hostname, child_nodes_url in sub_roots.items():
                self.make_hostname_tree(child_nodes_url, child_node_hostname)

    def _all_urlnodes_in_host_tree(self) -> None:
        # debug: check if all the nodes in the URL tree are in the hostnode tree (they must have an UUID)
        self.logger.warning('Validating host tree....')
        for urlnode in self.url_tree.traverse():
            if not hasattr(urlnode, 'hostnode_uuid'):
                self.logger.error(f'URL Node not un host tree: {urlnode}')
        self.logger.warning('host tree validated.')

    def make_tree(self) -> URLNode:
        """Build URL and Host trees"""
        self._make_subtree(self.url_tree)
        # at this point, if the nodes that couldn't be attached is huge, something bad happened.
        # We only take the first 1000 and break off
        max_dangling_nodes = 1000
        while self._nodes_list:
            # We were not able to attach a few things using the referers, redirects, or grepping on the page.
            # The remaining nodes are things we cannot attach for sure, so we try a few things, knowing it won't be perfect.
            node = self._nodes_list.pop(0)
            self._make_subtree_fallback(node)
            max_dangling_nodes -= 1
            if max_dangling_nodes <= 0:
                self.logger.warning(f'Way too many dangling nodes {len(self._nodes_list)}, this capture is broken.')
                self._nodes_list = []

        # 2022-08-25: We now have a tree, we have a self.rendered_node, attach the features.
        # 2023-09-26: Turns out we can have a download *and* a rendered HTML if the JS on the page triggers a download
        downloaded_file = None
        if self.har.downloaded_filename and self.har.downloaded_file:
            downloaded_file = (self.har.downloaded_filename if self.har.downloaded_filename else '',
                               self.har.downloaded_file if self.har.downloaded_file else None)
        if not self.rendered_node.empty_response:
            self.rendered_node.add_rendered_features(list(self.all_url_requests.keys()),
                                                     rendered_html=self.har.html_content if self.har.html_content else None,
                                                     downloaded_file=downloaded_file)

        # Initialize the hostname tree root
        self.hostname_tree.add_url(self.url_tree)
        self.make_hostname_tree(self.url_tree, self.hostname_tree)
        if dev_debug_mode:
            self._all_urlnodes_in_host_tree()
        if isinstance(self.har.frames, dict):
            if self.har.frames.get('children') and self.har.frames['children'] is not None:
                # we have frames in the main one
                for f_child in self.har.frames['children']:
                    self._load_iframes(self.rendered_node, f_child)
        else:
            self.logger.warning(f'Wrong format for the frames ({type(self.har.frames)}), very old capture.')
        return self.url_tree

    def _guess_best_node_for_partial_referer(self, node: URLNode, potential_parents: list[URLNode]) -> URLNode:
        # we have more than one node with the hostname of the referer *and* content.
        # 2025-12-17:
        # 1. find the deepest HTML node in the list
        for pp in reversed(potential_parents):
            if 'html' in pp.mimetype:
                return pp
        else:
            # 2. if there are no HTML node anywhere in the list, attach to the deepest node
            return potential_parents[-1]

    @trace_make_subtree_fallback
    def _make_subtree_fallback(self, node: URLNode, dev_debug: bool=False) -> None:
        if hasattr(node, 'referer') and node.referer:
            # 2022-04-28: the node has a referer, but for some reason, it could't be attached to the tree
            #             Probable reason: the referer is a part of the URL (hostname)
            if (referer_hostname := urlparse(node.referer).hostname):
                if (nodes_with_hostname := self.url_tree.search_nodes(hostname=referer_hostname)):
                    attach_to: URLNode
                    # 2025-12-17: we have at least one node with that hostname.
                    if len(nodes_with_hostname) == 1:
                        # That's the only one, use it
                        attach_to = nodes_with_hostname[0]
                    else:
                        # check if there are empty nodes
                        if (nodes_with_hostname_and_response := [n for n in nodes_with_hostname if not n.empty_response]):
                            if len(nodes_with_hostname_and_response) == 1:
                                attach_to = nodes_with_hostname_and_response[0]
                            else:
                                # multiple non-empty nodes with that hostname, this is the more difficult one
                                attach_to = self._guess_best_node_for_partial_referer(node, nodes_with_hostname_and_response)
                        else:
                            # more than one node with that hostname, but they're all empty, attach to the first one
                            attach_to = nodes_with_hostname[0]
                    return self._make_subtree(attach_to, [node], fallback=True)
                else:
                    # no node with that hostname at all, this should not happen
                    self.logger.warning(f'Unable to find any node with the hostname {referer_hostname}, despites it being set as referer.')
            else:
                # the referer has no hostname and it is fascinating
                self.logger.warning(f'Unable to get hostname out of referer: "{node.referer}"')

        # Sometimes, the har has a list of pages, generally when we have HTTP redirects.
        # IF we have more than one page in the list
        # AND the orphan node's pageref points to an other page than the first one
        # AND we already have a node in the tree with this pageref
        # => attach to that node.
        if ('pages' in self.har.har['log'] and len(self.har.har['log']['pages']) > 1
                and hasattr(node, 'pageref') and node.pageref != self.har.har['log']['pages'][0]
                and self.pages_root[node.pageref] != node.uuid):
            # In that case, we check if there is already a page with the pageref of the orphan node,
            # and attach the node to that.
            # NOTE: we can only do that if there is already a node with this pageref in the tree.
            # This node is not a page root, we can attach it \o/
            page_root_node = self.get_url_node_by_uuid(self.pages_root[node.pageref])
            if dev_debug:
                self.logger.warning(f'Failed to attach URLNode in the normal process, attaching node to page {node.pageref} - Node: {page_root_node.uuid} - {page_root_node.name}.')
            self._make_subtree(page_root_node, [node], fallback=True)
        elif self.rendered_node != self.url_tree:
            # Generally, when we have a bunch of redirects, they (generally) do not branch out
            # before the final landing page *but* it is not always the case: some intermediary
            # redirects will have calls to 3rd party pages.
            # Hopefully, this last case was taken care of in the branch above.
            # In this branch, we get the landing page after the redirects, and attach the node to it.

            # We skip this call if there are no redirects as it is the very last fallback at the
            # end of this method anyway
            if dev_debug:
                self.logger.warning(f'Failed to attach URLNode in the normal process, attaching node to final redirect: {self.har.final_redirect}.')
            self._make_subtree(self.rendered_node, [node], fallback=True)
        elif 'pages' in self.har.har['log']:
            # No luck, the node is root for this pageref, let's attach it to the prior page in the list, or the very first node (tree root)
            page_before = self.har.har['log']['pages'][0]
            for page in self.har.har['log']['pages'][1:]:
                if hasattr(node, 'pageref') and page['id'] == node.pageref:
                    break
                # Sometimes, the page listed in the list of pages is not related to
                # any of the entries. Go figure what happened.
                # If that's the case, we cannot use it as a reference
                if page['id'] in self.pages_root:
                    page_before = page
            try:
                page_root_node = self.get_url_node_by_uuid(self.pages_root[page_before['id']])
                if dev_debug:
                    self.logger.warning(f'Failed to attach URLNode in the normal process, best guess attach to page {node.pageref} - Node: {page_root_node.uuid} - {page_root_node.name}.')
            except IndexError:
                # So when that thing fails, it means that the the pageref is somehow in the wrong order
                # like pageref 2 is loaded before pageref 1. In that case, we have no choice but attaching the
                # node to the root node
                page_root_node = self.url_tree
                self.logger.warning('The pages in the HAR are in in the wrong order, this should not happen but here we are')
            self._make_subtree(page_root_node, [node], fallback=True)
        else:
            # no way to attach it to anything else, attach to the root node
            self._make_subtree(self.url_tree, [node], fallback=True)

    def all_real_urls_in_children(self, frame: FramesResponse) -> Iterator[str]:
        # from a frame, search all the real urls in each of the children, stop at the first one
        if (frame.get('url') and frame['url'] is not None and not self._url_to_local_only_content(frame['url'])):
            yield frame['url']
        else:
            # got no real URL, try the children
            if frame.get('children') and frame['children'] is not None:
                for c in frame['children']:
                    yield from self.all_real_urls_in_children(c)

    def search_in_frames(self, urls: set[str], frame: FramesResponse) -> Iterator[str]:
        # If the frame doesn't have children, there are no potential URLs to attach
        if not isinstance(frame, dict) or not frame.get('children') or frame['children'] is None:
            return None

        if frame.get('url'):
            u = unquote_plus(frame['url'])
            if urls & {u, u.split('#', 1)[0]}:
                # got a matching URL, get list of potential iframes urls
                for c in frame['children']:
                    yield from self.all_real_urls_in_children(c)
        for c in frame['children']:
            yield from self.search_in_frames(urls, c)

    @trace_make_subtree
    def _make_subtree(self, root: URLNode, nodes_to_attach: list[URLNode] | None=None,
                      dev_debug: bool=False, fallback: bool=False) -> None:
        """Recursive method building each level of the tree"""
        matching_urls: list[URLNode]
        if nodes_to_attach is None:
            # We're in the actual root node
            unodes = [self.url_tree]
        else:
            unodes = []
            for unode in nodes_to_attach:
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
                    # NOTE 2022-04-28: if the node is empty, and it is a redirect, it cannot have more than one single child
                    if unode.empty_response:
                        continue
                else:
                    self.logger.warning(f'The URLNode has a redirect to something we already processed ({unode.redirect_url}), this should not happen.')

            # 2025-02-06: If a node has no redirect **and** no content (empty response), we don't want to attach anything to it (it is a leaf)
            # Example: A POST to self that triggers the **parent** to load an other URL. In this case,
            # the proper attachment point is the parent, not this node, even if we have other nodes with this node URL as a referer.
            if unode.empty_response:
                continue

            # 2025-11-14
            # the referer of an iframe is the hostname of the parent, even if the parent
            # is a URL with a full path. Before using the referer, we need to check if we have
            # the current url in the frame tree. If we do, find nodes (in the remaining list)
            # with the URLs of the children - any fragment will be missing - and attach that node
            possible_iframe_urls = {unode.name, unode.name.split('#', 1)[0]}
            for possible_url in self.search_in_frames(possible_iframe_urls, self.har.frames):
                cu = unquote_plus(possible_url)
                for u in {cu, cu.split('#', 1)[0]}:
                    if u not in self.all_url_requests:
                        if '#' not in u:
                            self.logger.info(f'"{u}" in the frames URLs, but not in the HAR.')
                        continue
                    matching_urls = [url_node for url_node in self.all_url_requests[u]
                                     if url_node in self._nodes_list]
                    self._nodes_list = [node for node in self._nodes_list if node not in matching_urls]
                    if dev_debug:
                        self.logger.warning(f'Found via initiator from {unode.name} to {matching_urls}.')
                    self._make_subtree(unode, matching_urls)
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

            # 2022-04-27: Referers are supposed to be the complete URL, but they can also be only part of it.
            #             what we do here is going from best to worse in the hope one of them matches
            _referer_strings: list[str] = [
                unode.name,  # full URL
                unode.alternative_url_for_referer,  # URL up to the first `#`
            ]
            for ref in _referer_strings:
                if self.all_referer.get(ref):
                    matching_urls = []
                    # 2024-11-20: Referers are kinda weak, we can have multiple URLs with the same referer even one of the nodes should be attached somewhere else.
                    #             Let's attach the nodes one by one there (if they've not been attached recursively)
                    for u in self.all_referer[ref]:
                        for url_node in self.all_url_requests[u]:
                            if url_node in self._nodes_list and hasattr(url_node, 'referer') and url_node.referer == ref:
                                self._nodes_list = [node for node in self._nodes_list if node != url_node]
                                self._make_subtree(unode, [url_node])

            if hasattr(unode, 'external_ressources'):
                # the url loads external things, and some of them have no referer....
                for external_tag, links in unode.external_ressources.items():
                    # 2025-11-06: skip full regex until we're calling this method in the fallback
                    #             the iframes will often (not always) have a referer set and the URL
                    #             might be found by the regex and it will not be attached at the
                    #             right place
                    if external_tag == 'full_regex' and not fallback:
                        continue
                    for link in links:
                        if link not in self.all_url_requests or link == self.har.final_redirect:
                            # We have a lot of false positives
                            # 2021-06-19: or the URL of the final redirect is somewhere in an embeded content. In that case, we don't want to attach to the sub-node.
                            continue
                        # 2024-11-21: We only want to attach via external ressources *if*
                        # 1. the node has no referer
                        # 2. the node has a referer, but it is not in the list of potental nodes we can attach them to so they would be dangling.

                        matching_urls = [url_node for url_node in self.all_url_requests[link]
                                         if url_node in self._nodes_list
                                         and (not hasattr(url_node, 'referer') or url_node.referer not in self.all_url_requests)]
                        self._nodes_list = [node for node in self._nodes_list if node not in matching_urls]
                        if dev_debug:
                            self.logger.warning(f'Found from {unode.name} via external ressources ({external_tag}): {matching_urls}.')
                        self._make_subtree(unode, matching_urls)

    def __repr__(self) -> str:
        return f'Har2Tree({self.har.path}, {self.har.capture_uuid})'
