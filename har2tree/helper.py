#!/usr/bin/env python
# -*- coding: utf-8 -*-

import os
import re
from pathlib import Path
from collections import defaultdict
from typing import Callable, Any, Optional, List, MutableMapping, Tuple, Dict, Mapping
from functools import wraps
from .nodes import URLNode, HarTreeNode
from .parser import logger, path_to_debug_files, dev_debug_mode
from base64 import b64decode
import binascii
import hashlib
from urllib.parse import urlparse, unquote_plus, unquote_to_bytes
from io import BytesIO
from bs4 import BeautifulSoup

import filetype  # type: ignore


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


def trace_make_subtree_fallback(method: Callable[..., None]) -> Callable[..., None]:
    @wraps(method)
    def _impl(self: Any, node: URLNode, dev_debug: bool=False) -> None:
        if dev_debug_mode:
            __load_debug_files()
            if dev_debug_url and node.name == dev_debug_url:
                logger.warning(f'Debugging URL: {dev_debug_url}.')
                dev_debug = True
            elif dev_debug_hostname and node.hostname == dev_debug_hostname:
                logger.warning(f'Debugging Hostname: {dev_debug_hostname}.')
                dev_debug = True
        return method(self, node, dev_debug)
    return _impl


def trace_make_subtree(method: Callable[..., None]) -> Callable[..., None]:
    @wraps(method)
    def _impl(self: Any, root: URLNode, nodes_to_attach: Optional[List[URLNode]]=None, dev_debug: bool=False) -> None:
        if dev_debug_mode:
            __load_debug_files()
            if dev_debug_url and root.name == dev_debug_url or nodes_to_attach is not None and any(True for u in nodes_to_attach if u.name == dev_debug_url):
                logger.warning(f'Debugging URL: {dev_debug_url}.')
                dev_debug = True
            elif dev_debug_hostname and root.hostname == dev_debug_hostname or nodes_to_attach is not None and any(True for u in nodes_to_attach if u.hostname == dev_debug_hostname):
                logger.warning(f'Debugging Hostname: {dev_debug_hostname}.')
                dev_debug = True
        return method(self, root, nodes_to_attach, dev_debug)
    return _impl


def harnode_json_default(obj: 'HarTreeNode') -> MutableMapping[str, Any]:
    if isinstance(obj, HarTreeNode):
        return obj.to_dict()


def parse_data_uri(uri: str) -> Optional[Tuple[str, str, bytes]]:
    if not uri.startswith('data:'):
        return None
    uri = uri[5:]
    if ';base64' in uri:
        mime, b64data = uri.split(';base64', 1)
        if b64data[0] != ',':
            return None
        b64data = b64data[1:].strip()
        if not re.fullmatch('[A-Za-z0-9+/]*={0,2}', b64data):
            return None
        if len(b64data) % 4:
            # Note: Too many = isn't a problem.
            b64data += "==="
        try:
            data = b64decode(b64data)
        except binascii.Error:
            # Incorrect padding
            return None
    else:
        if ',' not in uri:
            return None
        mime, d = uri.split(',', 1)
        data = d.encode()

    if mime:
        if ';' in mime:
            mime, mimeparams = mime.split(';', 1)
        else:
            mimeparams = ''
    else:
        mime = '[No mimetype given]'
        mimeparams = ''
    return mime, mimeparams, data


def rebuild_url(base_url: str, partial: str, known_urls: List[str]) -> str:
    """
    The last part of a URL can be reconnected to its base in plenty different ways.
    This method aims to do that in a generic manner.
    As we know the list of possible URLs in the capture, we check for a match against that list.
    """
    splitted_base_url = urlparse(base_url)
    # Remove all possible quotes
    partial = partial.strip()
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
            logger.debug(f'URL without scheme: {base_url} - {partial} - {final_url}')
    elif partial.startswith('/') or partial[0] not in [';', '?', '#']:
        # We have a path, but not necessarily a complete one (see below)
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
            # Just slap the partial right after the netloc (and the nto hostname, because we could have a port.
            final_url = f'{splitted_base_url.scheme}://{splitted_base_url.netloc}{partial}'
        if final_url not in known_urls:
            logger.debug(f'URL without netloc: {base_url} - {partial} - {final_url}')
    elif partial.startswith(';'):
        # partial starts with a parameter. Replace the existing ones in base_url with partial
        final_url = '{}{}'.format(base_url.split(';')[0], partial)
        if final_url not in known_urls:
            logger.debug(f'URL with only parameter: {base_url} - {partial} - {final_url}')
    elif partial.startswith('?'):
        # partial starts with a query. Replace the existing ones in base_url with partial
        final_url = '{}{}'.format(base_url.split('?')[0], partial)
        if final_url not in known_urls:
            logger.debug(f'URL with only query: {base_url} - {partial} - {final_url}')
    elif partial.startswith('#'):
        # partial starts with a fragment. Replace the existing ones in base_url with partial
        final_url = '{}{}'.format(base_url.split('#')[0], partial)
        if final_url not in known_urls:
            logger.debug(f'URL with only fragment: {base_url} - {partial} - {final_url}')
    else:
        # The 2nd elif should catch all the other cases
        logger.debug(f'That should never happen: {base_url} - {partial}')

    if final_url not in known_urls:
        # sometimes, the port is in the partial, but striped in the list of known urls.
        try:
            final_parsed = urlparse(final_url)
            if final_url.startswith('https://') and final_parsed.netloc.endswith(':443'):
                final_url = final_url.replace(':443', '', 1)
            if final_url.startswith('http://') and final_parsed.netloc.endswith(':80'):
                final_url = final_url.replace(':80', '', 1)
        except Exception:
            logger.debug(f'Not a URL: {base_url} - {partial}')

    if final_url not in known_urls:
        # strip the single-dot crap: https://foo.bar/path/./blah.js => https://foo.bar/path/blah.js
        try:
            parsed = urlparse(final_url)
            if parsed.path:
                # NOTE Path('<complex path>').resolve() can return a path on the local system, and follow the symlinks. We don't want that.
                # That's the reason we use os.path.normpath
                resolved_path = os.path.normpath(parsed.path)
                final_url = parsed._replace(path=resolved_path).geturl()
                if final_url not in known_urls and resolved_path[-1] != '/':
                    # NOTE: the last '/' at the end of the path is stripped by normpath, we try to re-add it
                    resolved_path += '/'
                    final_url = parsed._replace(path=resolved_path).geturl()
            else:
                # No path, just make it a /
                final_url = parsed._replace(path='/').geturl()
        except Exception:
            logger.debug(f'Not a URL: {base_url} - {partial}')

    if final_url not in known_urls and splitted_base_url.fragment:
        # On a redirect, if the initial URL has a fragment, it is appended to the destination URL
        try:
            parsed = urlparse(final_url)
            final_url = parsed._replace(fragment=splitted_base_url.fragment).geturl()
        except Exception:
            logger.debug(f'Not a URL: {base_url} - {partial}')

    return final_url


def url_cleanup(dict_to_clean: Mapping[str, List[str]], base_url: str, all_requests: List[str]) -> Dict[str, List[str]]:
    """
    Standalone methods to cleanup URLs extracted from an HTML blob.
    """
    to_return: Dict[str, List[str]] = {}
    for key, urls in dict_to_clean.items():
        to_return[key] = []
        for url in urls:
            if url.startswith('data'):
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

            if to_attach == base_url:
                # Ignore what is basically a loop.
                continue

            if to_attach.startswith('http'):
                to_return[key].append(to_attach)
            else:
                logger.debug('{key} - not a URL - {to_attach}')
    return to_return


def _unpack_data_uri(data: str) -> Optional[Tuple[str, str, BytesIO]]:
    try:
        parsed_uri = parse_data_uri(data)
        if parsed_uri:
            mime, mimeparams, unpacked_data = parsed_uri
            if '/' not in mime:
                # Turns out, it happens. The mimetype can be null for example.
                kind = filetype.guess(unpacked_data)
                if kind:
                    mime = kind.mime
                else:
                    mime = ''

            blob = BytesIO(unpacked_data)
            b_hash = hashlib.sha512(blob.getvalue()).hexdigest()
            return mime, b_hash, blob
    except ValueError as e:
        logger.warning(e, data)
    return None


def find_external_ressources(html_doc: BytesIO, base_url: str, all_requests: List[str], full_text_search: bool=True) -> Tuple[Dict[str, List[str]], Dict[str, List[Tuple[str, BytesIO]]]]:
    """ Get URLs to external contents out of an HTML blob."""
    # Source: https://stackoverflow.com/questions/31666584/beutifulsoup-to-extract-all-external-resources-from-html
    # Because this is awful.
    # img: https://www.w3schools.com/TAGs/tag_img.asp -> longdesc src srcset
    # script: https://www.w3schools.com/TAGs/tag_script.asp -> src
    # video: https://www.w3schools.com/TAGs/tag_video.asp -> poster src
    # audio: https://www.w3schools.com/TAGs/tag_audio.asp -> src
    # iframe: https://www.w3schools.com/TAGs/tag_iframe.asp -> src
    # embed: https://www.w3schools.com/TAGs/tag_embed.asp -> src
    # source: https://www.w3schools.com/TAGs/tag_source.asp -> src srcset
    # link: https://www.w3schools.com/TAGs/tag_link.asp -> href
    # object: https://www.w3schools.com/TAGs/tag_object.asp -> data
    external_ressources: Dict[str, List[str]] = {'img': [], 'script': [], 'video': [], 'audio': [],
                                                 'iframe': [], 'embed': [], 'source': [],
                                                 'link': [],
                                                 'object': [],
                                                 'css': [],
                                                 'full_regex': [],
                                                 'javascript': [],
                                                 'meta_refresh': []}

    embedded_ressources: Dict[str, List[Tuple[str, BytesIO]]] = defaultdict(list)

    soup = BeautifulSoup(html_doc.getvalue(), 'lxml')
    for link in soup.find_all(['img', 'script', 'video', 'audio', 'iframe', 'embed', 'source', 'link', 'object']):
        uri = None
        if link.get('src'):  # img script video audio iframe embed source
            uri = link.get('src')
        if link.get('srcset'):  # img source
            uri = link.get('srcset')
        if link.get('longdesc'):  # img
            uri = link.get('longdesc')
        if link.get('poster'):  # video
            uri = link.get('poster')
        if link.get('href'):  # link
            uri = link.get('href')
        if link.get('data'):  # object
            uri = link.get('data')
        if not uri:
            continue

        if uri.startswith('data:'):
            unpacked = _unpack_data_uri(uri)
            if unpacked:
                mime, b_hash, blob = unpacked
                embedded_ressources[mime].append((b_hash, blob))
        else:
            external_ressources[link.name].append(unquote_plus(uri))

    # Search for meta refresh redirect madness
    # NOTE: we may want to move that somewhere else, but that's currently the only place BeautifulSoup is used.
    meta_refresh = soup.find('meta', attrs={'http-equiv': 'refresh'})
    if meta_refresh and 'content' in meta_refresh:
        external_ressources['meta_refresh'].append(meta_refresh['content'].partition('=')[2])

    # external stuff loaded from css content, because reasons.
    for url in re.findall(rb'url\((.*?)\)', html_doc.getvalue()):
        try:
            url = url.decode()
        except UnicodeDecodeError as e:
            logger.info(f'Unable to decode {url}: {e}')
            continue
        if url.startswith('data:'):
            unpacked = _unpack_data_uri(url)
            if unpacked:
                mime, b_hash, blob = unpacked
                embedded_ressources[mime].append((b_hash, blob))
        else:
            external_ressources['css'].append(url)

    # Javascript changing the current page
    # I never found a website where it matched anything useful
    external_ressources['javascript'] = [url.decode() for url in re.findall(b'(?:window|self|top).location(?:.*)\"(.*?)\"', html_doc.getvalue())]
    # Just in case, there is sometimes an unescape call in JS code
    for to_unescape in re.findall(br'unescape\(\'(.*)\'\)', html_doc.getvalue()):
        unescaped = unquote_to_bytes(to_unescape)
        kind = filetype.guess(unescaped)
        if kind:
            mimetype = kind.mime
        else:
            mimetype = ''
        blob = BytesIO(unescaped)
        b_hash = hashlib.sha512(blob.getvalue()).hexdigest()
        embedded_ressources[mimetype].append((b_hash, blob))

    if full_text_search:
        # Just regex in the whole blob, because we can
        external_ressources['full_regex'] = [url.decode() for url in re.findall(rb'(?:http[s]?:)?//(?:[a-zA-Z]|[0-9]|[$-_@.&+]|[!*\(\),]|(?:%[0-9a-fA-F][0-9a-fA-F]))+', html_doc.getvalue())]
        # print("################ REGEXES ", external_ressources['full_regex'])
    # NOTE: unescaping a potential URL as HTML content can make it unusable (example: (...)&ltime=(...>) => (...)<ime=(...))
    return url_cleanup(external_ressources, base_url, all_requests), embedded_ressources
