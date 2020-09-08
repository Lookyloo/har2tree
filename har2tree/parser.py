#!/usr/bin/env python
# -*- coding: utf-8 -*-

from pathlib import Path
import json
import copy
from datetime import datetime, timedelta
import uuid
from urllib.parse import urlparse, unquote_plus, unquote_to_bytes
from base64 import b64decode
import binascii
from collections import defaultdict
import re
import os
from io import BytesIO
import hashlib
from operator import itemgetter
from typing import List, Dict, Optional, Union, Tuple, Set, MutableMapping, Any, Mapping, Iterator
import ipaddress
import sys
import logging

from publicsuffix2 import PublicSuffixList, fetch  # type: ignore
from ete3 import TreeNode  # type: ignore
from bs4 import BeautifulSoup  # type: ignore
import filetype  # type: ignore

logger = logging.getLogger(__name__)

# Initialize Public Suffix List
try:
    psl_file = fetch()
    psl = PublicSuffixList(psl_file=psl_file)
except Exception:
    psl = PublicSuffixList()


class Har2TreeLogAdapter(logging.LoggerAdapter):
    """
    Prepend log entry with the UUID of the capture
    """
    def process(self, msg: str, kwargs: MutableMapping[str, Any]) -> Tuple[str, MutableMapping[str, Any]]:
        return '[%s] %s' % (self.extra['uuid'], msg), kwargs


class Har2TreeError(Exception):
    def __init__(self, message: str):
        """
        Har2Tree Exception
        """
        super(Har2TreeError, self).__init__(message)
        self.message = message


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
            if to_attach.startswith('http'):
                to_return[key].append(to_attach)
            else:
                logger.debug('{key} - not a URL - {to_attach}')
    return to_return


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

    soup = BeautifulSoup(html_doc, 'lxml')
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

        if uri:
            if uri.startswith('data:'):
                try:
                    parsed_uri = parse_data_uri(uri)
                    if parsed_uri:
                        mime, mimeparams, data = parsed_uri
                        blob = BytesIO(data)
                        b_hash = hashlib.sha512(blob.getvalue()).hexdigest()
                        embedded_ressources[mime].append((b_hash, blob))
                except ValueError as e:
                    logger.warning(e, uri)
            else:
                external_ressources[link.name].append(unquote_plus(uri))

    # Search for meta refresh redirect madness
    # NOTE: we may want to move that somewhere else, but that's currently the only place BeautifulSoup is used.
    meta_refresh = soup.find('meta', attrs={'http-equiv': 'refresh'})
    if meta_refresh:
        external_ressources['meta_refresh'].append(meta_refresh['content'].partition('=')[2])

    # external stuff loaded from css content, because reasons.
    for url in re.findall(rb'url\((.*?)\)', html_doc.getvalue()):
        url = url.decode()
        if url.startswith('data:'):
            try:
                parsed_uri = parse_data_uri(url)
                if parsed_uri:
                    mime, mimeparams, data = parsed_uri
                    blob = BytesIO(data)
                    b_hash = hashlib.sha512(blob.getvalue()).hexdigest()
                    embedded_ressources[mime].append((b_hash, blob))
            except ValueError as e:
                logger.warning(e, url)
        else:
            external_ressources['css'].append(url)

    # Javascript changing the current page
    # I never found a website where it matched anything useful
    external_ressources['javascript'] = [url.decode() for url in re.findall(b'(?:window|self|top).location(?:.*)\"(.*?)\"', html_doc.getvalue())]
    # Just in case, there is sometimes an unescape call is JS code
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

# ##################################################################


class HarTreeNode(TreeNode):

    def __init__(self, **kwargs: Any):
        """Node dumpable in json to display with d3js"""
        super(HarTreeNode, self).__init__(**kwargs)
        self.logger = logging.getLogger(f'{__name__}.{self.__class__.__name__}')
        self.add_feature('uuid', str(uuid.uuid4()))
        self.features_to_skip = set(['dist', 'support'])

    def to_dict(self) -> MutableMapping[str, Any]:
        """Make a dict that can then be dumped in json.
        """
        to_return = {'uuid': self.uuid, 'children': []}
        for feature in self.features:
            if feature in self.features_to_skip:
                continue
            to_return[feature] = getattr(self, feature)

        for child in self.children:
            to_return['children'].append(child)

        return to_return

    def to_json(self) -> str:
        """Make d3js compatible json"""
        return json.dumps(self.to_dict(), default=harnode_json_default)


class URLNode(HarTreeNode):

    def __init__(self, **kwargs: Any):
        """Node of the URL Tree"""
        super(URLNode, self).__init__(**kwargs)
        # Do not add the body in the json dump
        self.features_to_skip.add('body')
        self.features_to_skip.add('url_split')
        self.features_to_skip.add('start_time')
        self.features_to_skip.add('time')
        self.features_to_skip.add('time_content_received')
        self.features_to_skip.add('ip_address')

    def load_har_entry(self, har_entry: MutableMapping[str, Any], all_requests: List[str], rendered_html: Optional[BytesIO]=None) -> None:
        """Load one entry of the HAR file, initialize most of the features of the node"""
        if not self.name:
            # We're in the actual root node
            # NOTE: by the HAR specs: "Absolute URL of the request (fragments are not included)."
            self.add_feature('name', unquote_plus(har_entry['request']['url']))

        self.add_feature('url_split', urlparse(self.name))

        if rendered_html:
            self.add_feature('rendered_html', rendered_html)

        # If the URL contains a fragment (i.e. something after a #), it is stripped in the referer.
        # So we need an alternative URL to do a lookup against
        self.add_feature('alternative_url_for_referer', self.name.split('#')[0])

        # Instant the request is made
        if sys.version_info < (3, 7) and har_entry['startedDateTime'][-1] == 'Z':
            # Python 3.7:
            #   * fromisoformat does not like Z at the end of the string, and wants +XX:XX (not +XXXX)
            #   * strptime %z is cool with Z (=>tzinfo=datetime.timezone.utc) or +XXXX or +XX:XX
            # Python 3.6:
            #   * No fromisoformat
            #   * strptime %z does not like Z at the end of the string, and doesn't like +XX:XX either (wants +XXXX)
            har_entry['startedDateTime'] = har_entry['startedDateTime'].replace('Z', '+0000')
        self.add_feature('start_time', datetime.strptime(har_entry['startedDateTime'], '%Y-%m-%dT%H:%M:%S.%f%z'))

        self.add_feature('pageref', har_entry['pageref'])

        self.add_feature('time', timedelta(milliseconds=har_entry['time']))
        self.add_feature('time_content_received', self.start_time + self.time)  # Instant the response is fully received (and the processing of the content by the browser can start)
        self.add_feature('hostname', self.url_split.hostname)

        if not self.hostname:
            self.logger.warning(f'Something is broken in that node: {har_entry}')

        tld = psl.get_tld(self.hostname)
        if tld:
            if tld in psl.tlds:
                self.add_feature('known_tld', tld)
            else:
                if tld.isdigit():
                    # IPV4
                    pass
                elif ':' in tld:
                    # IPV6
                    pass
                else:
                    self.logger.warning(f'###### TLD WAT {self.name} {tld}')
                    self.add_feature('unknown_tld', tld)
        else:
            self.logger.warning(f'###### No TLD/domain broken {self.name}')

        self.add_feature('request', har_entry['request'])
        # Try to get a referer from the headers
        for h in self.request['headers']:
            if h['name'].lower() == 'referer':
                self.add_feature('referer', unquote_plus(h['value']))
            if h['name'].lower() == 'user-agent':
                self.add_feature('user_agent', h['value'])

        if 'method' in self.request and self.request['method'] == 'POST' and 'postData' in self.request:
            # If the content is empty, we don't care
            if self.request['postData']['text']:
                # We have a POST request, the data can be base64 encoded or urlencoded
                posted_data: Union[str, bytes] = self.request['postData']['text']
                if 'encoding' in self.request['postData']:
                    if self.request['postData']['encoding'] == 'base64':
                        if len(posted_data) % 4:
                            # a this point, we have a string for sure
                            posted_data += '==='  # type: ignore
                        posted_data = b64decode(posted_data)
                    else:
                        self.logger.warning(f'Unexpected encoding: {self.request["postData"]["encoding"]}')

                if 'mimeType' in self.request['postData']:
                    if self.request['postData']['mimeType'].startswith('application/x-www-form-urlencoded'):
                        # 100% sure there will be websites where decode will fail
                        if isinstance(posted_data, bytes):
                            try:
                                posted_data = posted_data.decode()
                            except Exception:
                                self.logger.warning(f'Expected urlencoded, got garbage: {posted_data!r}')
                        if isinstance(posted_data, str):
                            posted_data = unquote_plus(posted_data)
                    elif self.request['postData']['mimeType'].startswith('application/json') or self.request['postData']['mimeType'].startswith('application/csp-report'):
                        try:
                            posted_data = json.loads(posted_data)
                        except Exception:
                            self.logger.warning(f"Expected json, got garbage: {self.request['postData']['mimeType']} - {posted_data!r}")

                    elif self.request['postData']['mimeType'].startswith('multipart/form-data'):
                        # FIXME multipart content (similar to email). Not totally sure what do do with it tight now.
                        pass
                    elif self.request['postData']['mimeType'].startswith('application/x-protobuffer'):
                        # FIXME If possible, decode?
                        pass
                    elif self.request['postData']['mimeType'].startswith('text'):
                        # We got text, keep what we already have
                        pass
                    elif self.request['postData']['mimeType'] == '?':
                        # Just skip it, no need to go in the warnings
                        pass
                    elif self.request['postData']['mimeType'] == 'application/octet-stream':
                        # Should flag it.
                        pass
                    else:
                        # Weird stuff: Image/GIF application/unknown application/grpc-web+proto
                        self.logger.warning(f'Unexpected mime type: {self.request["postData"]["mimeType"]}')

                # The data may be json, try to load it
                try:
                    posted_data = json.loads(posted_data)
                except Exception:
                    pass

                if isinstance(posted_data, bytes):
                    # Try to decode it as utf-8
                    try:
                        posted_data = posted_data.decode('utf-8')
                    except Exception:
                        pass
                self.add_feature('posted_data', posted_data)

        self.add_feature('response', har_entry['response'])

        self.add_feature('response_cookie', har_entry['response']['cookies'])
        if self.response_cookie:
            self.add_feature('set_third_party_cookies', False)
            # https://developer.mozilla.org/en-US/docs/Web/HTTP/headers/Set-Cookie
            # Cookie name must not contain "=", so we can use it safely
            self.add_feature('cookies_received', [])
            for cookie in self.response_cookie:
                is_3rd_party = False
                # If the domain is set, the cookie will be sent in any request to that domain, and any related subdomains
                # Otherwise, it will only be sent to requests to the exact hostname
                # There are other limitations, like secure and path, but in our case, we won't care about it for now as we mainly want to track where the cookies are sent
                if 'domain' in cookie and cookie['domain']:
                    cookie_domain = cookie['domain']
                    if cookie_domain[0] == '.':
                        cookie_domain = cookie_domain[1:]
                else:
                    cookie_domain = self.hostname
                if not self.hostname.endswith(cookie_domain):
                    self.add_feature('set_third_party_cookies', True)
                    is_3rd_party = True
                self.cookies_received.append((cookie_domain, f'{cookie["name"]}={cookie["value"]}', is_3rd_party))

        self.add_feature('request_cookie', har_entry['request']['cookies'])
        if self.request_cookie:
            # https://developer.mozilla.org/en-US/docs/Web/HTTP/headers/Set-Cookie
            # Cookie name must not contain "=", so we can use it safely
            # The content of this feature is initialized in Har2Tree.__init__
            # And it contains a reference to the URL Node the cookies comes from initially
            # (the cookie was in the response of that request)
            self.add_feature('cookies_sent', {})
            for cookie in self.request_cookie:
                self.cookies_sent[f'{cookie["name"]}={cookie["value"]}'] = []

        if not har_entry['response']['content'].get('text') or har_entry['response']['content']['text'] == '':
            # If the content of the response is empty, skip.
            self.add_feature('empty_response', True)
        else:
            self.add_feature('empty_response', False)
            if har_entry['response']['content'].get('encoding') == 'base64':
                self.add_feature('body', BytesIO(b64decode(har_entry['response']['content']['text'])))
            else:
                self.add_feature('body', BytesIO(har_entry['response']['content']['text'].encode()))
            self.add_feature('body_hash', hashlib.sha512(self.body.getvalue()).hexdigest())
            if har_entry['response']['content']['mimeType']:
                self.add_feature('mimetype', har_entry['response']['content']['mimeType'])
            else:
                kind = filetype.guess(self.body.getvalue())
                if kind:
                    self.add_feature('mimetype', kind.mime)
                else:
                    self.add_feature('mimetype', '')

            external_ressources, embedded_ressources = find_external_ressources(self.body, self.name, all_requests)
            if 'rendered_html' in self.features:
                rendered_external, rendered_embedded = find_external_ressources(self.rendered_html, self.name, all_requests)
                # for the external ressources, the keys are always the same
                external_ressources = {initiator_type: urls + rendered_external[initiator_type] for initiator_type, urls in external_ressources.items()}

                # for the embedded ressources, the keys are the mimetypes, they may not overlap
                mimetypes = list(embedded_ressources.keys()) + list(rendered_embedded.keys())
                embedded_ressources = {mimetype: embedded_ressources.get(mimetype, []) + rendered_embedded.get(mimetype, []) for mimetype in mimetypes}

            self.add_feature('external_ressources', external_ressources)
            self.add_feature('embedded_ressources', embedded_ressources)
            filename = Path(self.url_split.path).name
            if filename:
                self.add_feature('filename', filename)
            else:
                self.add_feature('filename', 'file.bin')

            # Common JS redirect we can catch easily
            # NOTE: maybe make it a function.
            js_redirects = ['window.location.href', 'window.location', 'top.location']
            for js_redirect in js_redirects:
                url = re.findall(f'{js_redirect}.*"(.*)".*'.encode(), self.body.getvalue())
                if url:
                    # TODO: new type, redirect_js or something like that
                    redirect_url = rebuild_url(self.name, url[0].decode(), all_requests)
                    if redirect_url in all_requests:
                        self.add_feature('redirect', True)
                        self.add_feature('redirect_url', redirect_url)

            if 'meta_refresh' in self.external_ressources and self.external_ressources.get('meta_refresh'):
                if self.external_ressources['meta_refresh'][0] in all_requests:
                    # TODO: new type, redirect_html or something like that
                    self.add_feature('redirect', True)
                    self.add_feature('redirect_url', self.external_ressources['meta_refresh'][0])

            if 'javascript' in self.mimetype or 'ecmascript' in self.mimetype:
                self.add_feature('js', True)
            elif self.mimetype.startswith('image'):
                self.add_feature('image', True)
            elif self.mimetype.startswith('text/css'):
                self.add_feature('css', True)
            elif 'json' in self.mimetype:
                self.add_feature('json', True)
            elif 'html' in self.mimetype:
                self.add_feature('html', True)
            elif 'font' in self.mimetype:
                self.add_feature('font', True)
            elif 'octet-stream' in self.mimetype:
                self.add_feature('octet_stream', True)
            elif ('text/plain' in self.mimetype or 'xml' in self.mimetype
                    or 'application/x-www-form-urlencoded' in self.mimetype):
                self.add_feature('text', True)
            elif 'video' in self.mimetype:
                self.add_feature('video', True)
            elif 'audio' in self.mimetype:
                self.add_feature('audio', True)
            elif 'mpegurl' in self.mimetype.lower():
                self.add_feature('livestream', True)
            elif ('application/x-shockwave-flash' in self.mimetype
                    or 'application/x-shockware-flash' in self.mimetype):  # Yes, shockwaRe
                self.add_feature('flash', True)
            elif 'application/pdf' in self.mimetype:
                self.add_feature('pdf', True)
            elif not self.mimetype:
                self.add_feature('unset_mimetype', True)
            else:
                self.add_feature('unknown_mimetype', True)
                self.logger.warning('Unknown mimetype: {}'.format(self.mimetype))

        # NOTE: Chrome/Chromium only features
        if har_entry.get('serverIPAddress'):
            self.add_feature('ip_address', ipaddress.ip_address(har_entry['serverIPAddress']))
        if '_initiator' in har_entry:
            if har_entry['_initiator']['type'] == 'other':
                pass
            elif har_entry['_initiator']['type'] == 'parser' and har_entry['_initiator']['url']:
                self.add_feature('initiator_url', unquote_plus(har_entry['_initiator']['url']))
            elif har_entry['_initiator']['type'] == 'script':
                url_stack = self._find_initiator_in_stack(har_entry['_initiator']['stack'])
                if url_stack:
                    self.add_feature('initiator_url', url_stack)
            elif har_entry['_initiator']['type'] == 'redirect':
                # FIXME: Need usecase
                raise Exception(f'Got a redirect! - {har_entry}')
            else:
                # FIXME: Need usecase
                raise Exception(har_entry)

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
                self.logger.warning('Unable to find that URL: {original_url} - {original_redirect} - {modified_redirect}'.format(
                    original_url=self.name, original_redirect=har_entry['response']['redirectURL'], modified_redirect=redirect_url))

    def _find_initiator_in_stack(self, stack: MutableMapping[str, Any]) -> Optional[str]:
        # Because everything is terrible, and the call stack can have parents
        if stack['callFrames']:
            return unquote_plus(stack['callFrames'][0]['url'])
        if stack['parent']:
            return self._find_initiator_in_stack(stack['parent'])
        return None

    @property
    def resources_hashes(self) -> Set[str]:
        all_ressources_hashes = set()
        if 'body_hash' in self.features:
            all_ressources_hashes.add(self.body_hash)
            if 'embedded_ressources' in self.features:
                for mimetype, blobs in self.embedded_ressources.items():
                    all_ressources_hashes.update([h for h, b in blobs])
        return all_ressources_hashes


class HostNode(HarTreeNode):

    def __init__(self, **kwargs: Any):
        """Node of the Hostname Tree"""
        super(HostNode, self).__init__(**kwargs)
        # Do not add the URLs in the json dump
        self.features_to_skip.add('urls')

        self.add_feature('urls', [])
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
        self.add_feature('pdf', 0)
        self.add_feature('video', 0)
        self.add_feature('unset_mimetype', 0)
        self.add_feature('unknown_mimetype', 0)
        self.add_feature('iframe', 0)
        self.add_feature('http_content', False)
        self.add_feature('https_content', False)
        self.cookies_sent: Set[str] = set()
        self.cookies_received: Set[Tuple[str, str, bool]] = set()

    def to_dict(self) -> MutableMapping[str, Any]:
        """Make a dictionary that is json dumpable for d3js"""
        to_return = super(HostNode, self).to_dict()
        to_return['urls_count'] = self.urls_count
        to_return['request_cookie'] = self.request_cookie
        to_return['response_cookie'] = self.response_cookie
        to_return['third_party_cookies_received'] = self.third_party_cookies_received
        to_return['mixed_content'] = self.mixed_content
        return to_return

    @property
    def mixed_content(self) -> bool:
        """Is there http and https URL Nodes"""
        if self.http_content and self.https_content:
            return True
        return False

    @property
    def urls_count(self) -> int:
        """Number of URLs"""
        return len(self.urls)

    @property
    def request_cookie(self) -> int:
        """Number of unique cookies sent in the requests of all the URL nodes"""
        return len(self.cookies_sent)

    @property
    def response_cookie(self) -> int:
        """Number of unique cookies received in the responses of all the URL nodes"""
        return len(self.cookies_received)

    @property
    def third_party_cookies_received(self) -> int:
        """Number of unique 3rd party cookies received in the responses of all the URL nodes"""
        return sum(third for _, _, third in self.cookies_received if third)

    def add_url(self, url: URLNode) -> None:
        """Add a URL node to the Host node, initialize/update the features"""
        if not self.name:
            # Only used when initializing the root node
            self.add_feature('name', url.hostname)
        self.urls.append(url)

        # Add to URLNode a reference to the HostNode UUID
        url.add_feature('hostnode_uuid', self.uuid)

        if hasattr(url, 'cookies_sent'):
            # Keep a set of cookies sent: different URLs will send the same cookie
            self.cookies_sent.update(set(url.cookies_sent.keys()))
        if hasattr(url, 'cookies_received'):
            # Keep a set of cookies received: different URLs will receive the same cookie
            self.cookies_received.update({(domain, cookie, is_3rd_party)
                                          for domain, cookie, is_3rd_party in url.cookies_received})
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
        if hasattr(url, 'pdf'):
            self.pdf += 1  # FIXME: need icon
        if hasattr(url, 'video') or hasattr(url, 'livestream') or hasattr(url, 'audio') or hasattr(url, 'flash'):
            self.video += 1
        if hasattr(url, 'unknown_mimetype') or hasattr(url, 'unset_mimetype'):
            self.unknown_mimetype += 1
        if hasattr(url, 'iframe'):
            self.iframe += 1

        if url.name.startswith('http://'):
            self.http_content = True
        elif url.name.startswith('https://'):
            self.https_content = True


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
            self.final_redirect = ''

        cookiefile = self.path.parent / f'{self.path.stem}.cookies.json'
        if cookiefile.is_file():
            with cookiefile.open() as c:
                self.cookies: List[Dict[str, Any]] = json.load(c)
        else:
            self.cookies = []

        htmlfile = self.path.parent / f'{self.path.stem}.html'
        if htmlfile.is_file():
            with htmlfile.open('rb') as _h:
                self.html_content: BytesIO = BytesIO(_h.read())
        else:
            self.html_content = BytesIO()

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
                    full_redirect = rebuild_url(previous_entry['response']['url'],
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

    def __init__(self, har_path: Path, html_path: Optional[Path], capture_uuid: str):
        """Build the ETE Toolkit tree based on the HAR file, cookies, and HTML content
        :param har: harfile of a capture
        """
        logger = logging.getLogger(f'{__name__}.{self.__class__.__name__}')
        self.logger = Har2TreeLogAdapter(logger, {'uuid': capture_uuid})
        self.har = HarFile(har_path, capture_uuid)
        self.rendered_html: Optional[BytesIO]
        if html_path and html_path.exists():
            with html_path.open('rb') as f:
                self.rendered_html = BytesIO(f.read())
        else:
            self.rendered_html = None
        self.hostname_tree = HostNode()

        self.nodes_list: List[URLNode] = []
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
        if hasattr(self.nodes_list[0], 'cookies_sent'):
            self.initial_cookies = {key: cookie for key, cookie in self.nodes_list[0].cookies_sent.items()}

        # Dictionary of all cookies received during the capture
        self.cookies_received: Dict[str, List[Tuple[str, URLNode, bool]]] = defaultdict(list)
        for n in self.nodes_list:
            if hasattr(n, 'cookies_received'):
                for domain, c_received, is_3rd_party in n.cookies_received:
                    self.cookies_received[c_received].append((domain, n, is_3rd_party))

        # Dictionary of all cookies sent during the capture
        self.cookies_sent: Dict[str, List[URLNode]] = defaultdict(list)
        for n in self.nodes_list:
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
        for n in self.nodes_list:
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
        for n in self.nodes_list:
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

        self.url_tree = self.nodes_list.pop(0)

    @property
    def stats(self) -> Dict[str, Any]:
        """Statistics about the capture"""
        to_return: Dict[str, Any] = {'total_hostnames': 0}
        to_return['total_urls'] = sum(1 for _ in self.url_tree.traverse())

        all_cookies_sent: Set[str] = set()
        all_cookies_received: Set[Tuple[str, str, bool]] = set()
        for host_node in self.hostname_tree.traverse():
            to_return['total_hostnames'] += 1
            all_cookies_sent.update(host_node.cookies_sent)
            all_cookies_received.update(host_node.cookies_received)

        to_return['total_cookies_sent'] = len(all_cookies_sent)
        to_return['total_cookies_received'] = len(all_cookies_received)
        return to_return

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

        for url_entry in self.har.entries:
            n = URLNode(name=unquote_plus(url_entry['request']['url']))
            if self.rendered_html and n.name == self.har.final_redirect:
                n.load_har_entry(url_entry, list(self.all_url_requests.keys()), self.rendered_html)
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

            if hasattr(n, 'referer'):
                if n.referer == n.name:
                    # Skip to avoid loops:
                    #   * referer to itself
                    self.logger.warning(f'Referer to itself {n.name}')
                else:
                    self.all_referer[n.referer].append(n.name)

            self.nodes_list.append(n)
            self.all_url_requests[n.name].append(n)

        # So, sometimes, the startedDateTime in the page list is fucked up
        # Ex: start time of page 3 == start time of page 1. This is wrong, but it happens
        # Solution: if we miss an entry in self.pages_root, we put the first node with that page ref.
        for _, pages in self.har.pages_start_times.items():
            for page in pages:
                if page['id'] not in self.pages_root:
                    for node in self.nodes_list:
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
                    child_node_hostname = root_node_hostname.add_child(HostNode(name=child_node_url.hostname))
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
        if self.nodes_list:
            # We were not able to attach a few things.
            while self.nodes_list:
                node = self.nodes_list.pop(0)
                if self.pages_root[node.pageref] != node.uuid:
                    # This node is not a page root, we can attach it \o/
                    page_root_node = self.get_url_node_by_uuid(self.pages_root[node.pageref])
                    self._make_subtree(page_root_node, [node])
                else:
                    # No luck, let's attach it to the prior page in the list
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
                    self._make_subtree(page_root_node, [node])

        # Initialize the hostname tree root
        self.hostname_tree.add_url(self.url_tree)
        self.make_hostname_tree(self.url_tree, self.hostname_tree)
        return self.url_tree

    def _make_subtree(self, root: URLNode, nodes_to_attach: List[URLNode]=None) -> None:
        """Recursive method building each level of the tree"""
        matching_urls: List[URLNode]
        if nodes_to_attach is None:
            # We're in the actual root node
            unodes = [self.url_tree]
        else:
            unodes = []
            for unode in nodes_to_attach:
                unodes.append(root.add_child(unode))
        for unode in unodes:
            if hasattr(unode, 'redirect') and not hasattr(unode, 'redirect_to_nothing'):
                # If the subnode has a redirect URL set, we get all the requests matching this URL
                # One may think the entry related to this redirect URL has a referer to the parent. One would be wrong.
                # URL 1 has a referer, and redirects to URL 2. URL 2 has the same referer as URL 1.
                if unode.redirect_url not in self.all_redirects:
                    continue
                self.all_redirects.remove(unode.redirect_url)  # Makes sure we only follow a redirect once
                matching_urls = [url_node for url_node in self.all_url_requests[unode.redirect_url] if url_node in self.nodes_list]
                self.nodes_list = [node for node in self.nodes_list if node not in matching_urls]
                self._make_subtree(unode, matching_urls)
            else:
                if self.all_initiator_url.get(unode.name):
                    # The URL (unode.name) is in the list of known urls initiating calls
                    for u in self.all_initiator_url[unode.name]:
                        matching_urls = [url_node for url_node in self.all_url_requests[u]
                                         if url_node in self.nodes_list and hasattr(url_node, 'initiator_url') and url_node.initiator_url == unode.name]
                        self.nodes_list = [node for node in self.nodes_list if node not in matching_urls]
                        self._make_subtree(unode, matching_urls)
                    if not self.all_initiator_url.get(unode.name):
                        # remove the initiator url from the list if empty
                        self.all_initiator_url.pop(unode.name)
                if self.all_referer.get(unode.name):
                    # The URL (unode.name) is in the list of known referers
                    for u in self.all_referer[unode.name]:
                        matching_urls = [url_node for url_node in self.all_url_requests[u]
                                         if url_node in self.nodes_list and hasattr(url_node, 'referer') and url_node.referer == unode.name]
                        self.nodes_list = [node for node in self.nodes_list if node not in matching_urls]
                        self._make_subtree(unode, matching_urls)
                    if not self.all_referer.get(unode.name):
                        # remove the referer from the list if empty
                        self.all_referer.pop(unode.name)
                if self.all_referer.get(unode.alternative_url_for_referer):
                    # The URL (unode.name) stripped at the first `#` is in the list of known referers
                    for u in self.all_referer[unode.alternative_url_for_referer]:
                        matching_urls = [url_node for url_node in self.all_url_requests[u]
                                         if url_node in self.nodes_list and hasattr(url_node, 'referer') and url_node.referer == unode.alternative_url_for_referer]
                        self.nodes_list = [node for node in self.nodes_list if node not in matching_urls]
                        self._make_subtree(unode, matching_urls)
                    # remove the referer from the list if empty
                    if not self.all_referer.get(unode.alternative_url_for_referer):
                        self.all_referer.pop(unode.alternative_url_for_referer)
                if hasattr(unode, 'external_ressources'):
                    # the url loads external things, and some of them have no referer....
                    for external_tag, links in unode.external_ressources.items():
                        for link in links:
                            if link not in self.all_url_requests:
                                # We have a lot of false positives
                                continue
                            matching_urls = [url_node for url_node in self.all_url_requests[link] if url_node in self.nodes_list]
                            self.nodes_list = [node for node in self.nodes_list if node not in matching_urls]
                            self._make_subtree(unode, matching_urls)

    def __repr__(self) -> str:
        return f'Har2Tree({self.har.path}, {self.har.capture_uuid})'


class CrawledTree(object):

    def __init__(self, harfiles: Iterator[Tuple[Path, Optional[Path]]], uuid: str):
        """ Convert a list of HAR files into a ETE Toolkit tree"""
        self.uuid = uuid
        logger = logging.getLogger(__name__)
        self.logger = Har2TreeLogAdapter(logger, {'uuid': uuid})
        self.hartrees: List[Har2Tree] = self.load_all_harfiles(harfiles)
        if not self.hartrees:
            raise Har2TreeError('No usable HAR files found.')
        self.root_hartree = self.hartrees.pop(0)
        self.find_parents()
        self.join_trees()

    def load_all_harfiles(self, files: Iterator[Tuple[Path, Optional[Path]]]) -> List[Har2Tree]:
        """Open all the HAR files and build the trees"""
        loaded = []
        for har_path, html_path in files:
            try:
                har2tree = Har2Tree(har_path, html_path, capture_uuid=self.uuid)
            except Har2TreeError:
                continue
            har2tree.make_tree()
            loaded.append(har2tree)
        return loaded

    def find_parents(self) -> None:
        """Find all the trees where the first entry has a referer.
        Meaning: This is a sub-tree to attach to some other node.
        """
        self.referers: Dict[str, List[Har2Tree]] = defaultdict(list)
        for hartree in self.hartrees:
            if hartree.root_referer:
                self.referers[hartree.root_referer].append(hartree)

    def join_trees(self, root: Optional[Har2Tree]=None, parent_root: Optional[URLNode]=None) -> None:
        """Connect the trees together if we have more than one HAR file"""
        if root is None:
            root = self.root_hartree
            parent = root.url_tree
        elif parent_root is not None:
            parent = parent_root
        if root.root_after_redirect:
            # If the first URL is redirected, the referer of the subtree
            # will be the redirect.
            sub_trees = self.referers.pop(root.root_after_redirect, None)
        else:
            sub_trees = self.referers.pop(root.har.root_url, None)
        if not sub_trees:
            # No subtree to attach
            return
        for sub_tree in sub_trees:
            to_attach = copy.deepcopy(sub_tree.url_tree)
            parent.add_child(to_attach)
            self.join_trees(sub_tree, to_attach)
        self.root_hartree.make_hostname_tree(self.root_hartree.url_tree, self.root_hartree.hostname_tree)

    def to_json(self) -> str:
        """JSON output for d3js"""
        return self.root_hartree.to_json()

    @property
    def redirects(self) -> List[str]:
        """List of redirects for this capture"""
        if not self.root_hartree.root_after_redirect:
            return []
        redirect_node = self.root_hartree.url_tree.search_nodes(name=self.root_hartree.root_after_redirect)
        if not redirect_node:
            self.logger.warning(f'Unable to find node {self.root_hartree.root_after_redirect}')
            return []
        elif len(redirect_node) > 1:
            self.logger.warning(f'Too many nodes found for {self.root_hartree.root_after_redirect}: {redirect_node}')
        return [a.name for a in reversed(redirect_node[0].get_ancestors())]

    @property
    def root_url(self) -> str:
        """First URL of the capture"""
        return self.root_hartree.har.root_url

    @property
    def start_time(self) -> datetime:
        """Start time of the capture"""
        return self.root_hartree.start_time

    @property
    def user_agent(self) -> str:
        """User agent used for the capture"""
        return self.root_hartree.user_agent
