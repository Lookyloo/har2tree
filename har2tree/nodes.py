#!/usr/bin/env python

from __future__ import annotations

import binascii
import copy
import hashlib
import ipaddress
import json
import logging
import uuid
import re

from base64 import b64decode
from datetime import datetime, timedelta
from functools import lru_cache, cached_property
from hashlib import sha256
from io import BytesIO, StringIO
from pathlib import Path
from typing import Any
from collections.abc import MutableMapping
from urllib.parse import unquote_plus, urlparse, urljoin, parse_qs

import filetype  # type: ignore
import json_stream  # type: ignore

from bs4 import BeautifulSoup
from ete3 import TreeNode  # type: ignore
from publicsuffixlist import PublicSuffixList  # type: ignore
from w3lib.html import strip_html5_whitespace
from w3lib.url import canonicalize_url, safe_url_string

from .helper import find_external_ressources, rebuild_url, find_identifiers, make_soup
from .helper import Har2TreeError, Har2TreeLogAdapter, make_hhhash, HHHashError, HHHashNote


@lru_cache(64)
def get_public_suffix_list() -> PublicSuffixList:
    # Initialize Public Suffix List
    # TODO (?): fetch the list
    return PublicSuffixList()


class HarTreeNode(TreeNode):  # type: ignore[misc]

    def __init__(self, capture_uuid: str, **kwargs: Any):
        """Node dumpable in json to display with d3js"""
        super().__init__(**kwargs)
        logger = logging.getLogger(f'{__name__}.{self.__class__.__name__}')
        self.logger = Har2TreeLogAdapter(logger, {'uuid': capture_uuid})
        self.add_feature('uuid', str(uuid.uuid4()))
        self.features_to_skip = {'dist', 'support'}

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

    start_time: datetime

    def __init__(self, capture_uuid: str, **kwargs: Any):
        """Node of the URL Tree"""
        super().__init__(capture_uuid=capture_uuid, **kwargs)
        # Do not add the body in the json dump
        self.features_to_skip.add('body')
        self.features_to_skip.add('url_split')
        self.features_to_skip.add('start_time')
        self.features_to_skip.add('time')
        self.features_to_skip.add('time_content_received')
        self.features_to_skip.add('ip_address')

    def _compute_domhash(self) -> str:
        to_hash = "|".join(t.name for t in self.rendered_soup.find_all()).encode()
        return sha256(to_hash).hexdigest()[:32]

    def add_rendered_features(self, all_requests: list[str], rendered_html: BytesIO | None=None, downloaded_file: tuple[str, BytesIO | None] | None=None) -> None:
        if rendered_html:
            self.add_feature('rendered_html', rendered_html)
            rendered_external, rendered_embedded = find_external_ressources(self.mimetype, self.rendered_html.getvalue(), self.name, all_requests)
            if hasattr(self, 'external_ressources'):
                # for the external ressources, the keys are always the same
                self.external_ressources: dict[str, list[str]] = {initiator_type: urls + rendered_external[initiator_type] for initiator_type, urls in self.external_ressources.items()}
            else:
                self.add_feature('external_ressources', rendered_external)

            if hasattr(self, 'embedded_ressources'):
                # for the embedded ressources, the keys are the mimetypes, they may not overlap
                mimetypes = list(self.embedded_ressources.keys()) + list(rendered_embedded.keys())
                self.embedded_ressources: dict[str, list[tuple[str, BytesIO]]] = {mimetype: self.embedded_ressources.get(mimetype, []) + rendered_embedded.get(mimetype, []) for mimetype in mimetypes}
            else:
                self.add_feature('embedded_ressources', rendered_embedded)

            if identifiers := find_identifiers(self.rendered_soup):
                self.add_feature('identifiers', identifiers)

            if domhash := self._compute_domhash():
                self.add_feature('domhash', domhash)

        if downloaded_file:
            downloaded_filename, downloaded_file_data = downloaded_file
            self.add_feature('downloaded_file', downloaded_file_data)
            self.add_feature('downloaded_filename', downloaded_filename)

    def _dirty_safe_b64decode(self, to_decode: str | bytes) -> bytes:
        if isinstance(to_decode, str):
            # make it bytes
            _to_decode = to_decode.encode()
        else:
            # Make sure we're not modifying it
            _to_decode = copy.copy(to_decode)
        # Make sure the padding is right
        if len(_to_decode) % 4:
            _to_decode += b'==='

        if any(altchar in _to_decode for altchar in [b'-', b'_']):
            # Emulate urlsafe b64decode
            return b64decode(_to_decode, altchars=b'-_', validate=True)
        return b64decode(_to_decode, validate=True)

    def load_har_entry(self, har_entry: MutableMapping[str, Any], all_requests: list[str]) -> None:
        """Load one entry of the HAR file, initialize most of the features of the node"""
        if not self.name:
            # We're in the actual root node
            # NOTE: by the HAR specs: "Absolute URL of the request (fragments are not included)."
            self.add_feature('name', unquote_plus(har_entry['request']['url']))

        splitted_url = urlparse(self.name)
        if splitted_url.scheme == 'blob':
            # this is a new weird feature, but it seems to be usable as a URL, so let's do that
            self.add_feature('url_split', urlparse(splitted_url.path))
        elif splitted_url.scheme == 'file':
            # file on disk, we do not have a proper URL
            self.add_feature('file_on_disk', True)
            self.add_feature('url_split', urlparse(splitted_url.path))
        else:
            self.add_feature('url_split', splitted_url)

        # If the URL contains a fragment (i.e. something after a #), it is stripped in the referer.
        # So we need an alternative URL to do a lookup against
        self.add_feature('alternative_url_for_referer', self.name.split('#')[0])

        if '.' in har_entry['startedDateTime']:
            self.add_feature('start_time', datetime.strptime(har_entry['startedDateTime'], '%Y-%m-%dT%H:%M:%S.%f%z'))
        else:
            self.add_feature('start_time', datetime.strptime(har_entry['startedDateTime'], '%Y-%m-%dT%H:%M:%S%z'))

        if 'pageref' in har_entry:
            self.add_feature('pageref', har_entry['pageref'])

        self.add_feature('time', timedelta(milliseconds=har_entry['time']))
        self.add_feature('time_content_received', self.start_time + self.time)  # Instant the response is fully received (and the processing of the content by the browser can start)

        if hasattr(self, 'file_on_disk'):
            # TODO: Do something better? hostname is the feature name used for the aggregated tree
            # so we need that unless we want to change the JS
            self.add_feature('hostname', str(Path(self.url_split.path).parent))
        else:
            if self.url_split.hostname:
                self.add_feature('hostname', self.url_split.hostname)
            else:
                self.add_feature('hostname', self.name)

        if not self.hostname:
            self.logger.warning(f'Something is broken in that node: {har_entry}')

        try:
            ipaddress.ip_address(self.hostname)
            self.add_feature('hostname_is_ip', True)
        except ValueError:
            # Not an IP
            pass

        if not hasattr(self, 'hostname_is_ip'):
            try:
                # attempt to decode if the hostname is idna encoded
                idna_decoded = self.hostname.encode().decode('idna')
                if idna_decoded != self.hostname:
                    self.add_feature('idna', idna_decoded)
            except UnicodeError:
                pass

        if not hasattr(self, 'hostname_is_ip') and not hasattr(self, 'file_on_disk'):
            tld = get_public_suffix_list().publicsuffix(self.hostname)
            if tld:
                self.add_feature('known_tld', tld)
            else:
                self.logger.debug(f'No TLD/domain broken {self.name}')

        self.add_feature('request', har_entry['request'])
        # Try to get a referer from the headers
        for h in self.request['headers']:
            if h['name'].lower() == 'referer':
                self.add_feature('referer', unquote_plus(h['value']))
            if h['name'].lower() == 'user-agent':
                self.add_feature('user_agent', h['value'])

        if 'user_agent' not in self.features:
            self.add_feature('user_agent', '')

        if 'method' in self.request and self.request['method'] == 'POST':
            decoded_posted_data: list[Any] | str | bytes | int | float | bool | dict[str, str] | dict[str, list[str]] | None = None
            if 'postData' not in self.request or 'text' not in self.request['postData']:
                self.logger.debug('POST request with no content.')
            elif not self.request['postData']['text']:
                # If the POST content is empty
                self.logger.debug('Empty POST request.')
                decoded_posted_data = ''
            elif self.request['postData']['text'].startswith('\x1f\uFFFD\x08'):
                # b'\x1f\xef\xbf\xbd\x08', decoded to UTF-8
                # => the replacement character
                # https://www.cogsci.ed.ac.uk/~richard/utf-8.cgi?input=%EF%BF%BD&mode=char
                self.logger.debug('Got a garbled gzipped POST blob.')
                self.add_feature('posted_data_info', "It was a POSTed gzipped blob, but the data has been garbled.")
                decoded_posted_data = self.request['postData']['text']
            elif self.request['postData'].get('params'):
                # NOTE 2025-08-08
                # if the posted data mimetype is "application/x-www-form-urlencoded"
                # the HAR contains the decoded entry in the params key
                # The params key is a list of dicts with a key and a value
                #   {"name": <key>, "value": <data>}
                # I'd rather have it as {<key>: <data>}
                # TODO: some processing on the data part (it's often a json blob)
                self.logger.debug('Got a params POST.')
                decoded_posted_data = {entry['name']: entry['value'] for entry in self.request['postData']['params']}
            else:
                # NOTE 2023-08-22: Blind attempt to base64 decode the data
                self.logger.debug('Got a normal POST')
                try:
                    decoded_posted_data = self._dirty_safe_b64decode(self.request['postData']['text'])
                except binascii.Error:
                    decoded_posted_data = self.request['postData']['text']
                if 'mimeType' in self.request['postData']:
                    # make it easier to compare.
                    mimetype_lower = self.request['postData']['mimeType'].lower()
                    if mimetype_lower.startswith('application/x-www-form-urlencoded'):
                        # NOTE: this should never happen as there should
                        # be something in self.request['postData']['params']
                        # and we already processed it before but just in case...
                        self.logger.debug('Got a application/x-www-form-urlencoded without params key')
                        # 100% sure there will be websites where decode will fail
                        try:
                            if isinstance(decoded_posted_data, bytes):
                                decoded_posted_data = decoded_posted_data.decode()
                            if isinstance(decoded_posted_data, str):
                                decoded_posted_data = unquote_plus(decoded_posted_data)
                            if isinstance(decoded_posted_data, str):
                                decoded_posted_data = parse_qs(decoded_posted_data)
                        except Exception as e:
                            self.logger.warning(f'Unable to unquote or parse form data "{decoded_posted_data!r}": {e}')
                    elif (mimetype_lower.startswith('application/json')
                          or mimetype_lower.startswith('application/csp-report')
                          or mimetype_lower.startswith('application/x-amz-json-1.1')
                          or mimetype_lower.startswith('application/reports+json')
                          or mimetype_lower.endswith('json')
                          ):
                        if isinstance(decoded_posted_data, (str, bytes)):
                            # at this stage, it will always be bytes or str
                            try:
                                # NOTE 2023-08-22: loads here may give us a int, float or a bool.
                                decoded_posted_data = json.loads(decoded_posted_data)
                            except Exception:
                                if isinstance(decoded_posted_data, (str, bytes)):
                                    self.logger.warning(f"Expected json, got garbage: {mimetype_lower} - {decoded_posted_data[:20]!r}[...]")
                                else:
                                    self.logger.warning(f"Expected json, got garbage: {mimetype_lower} - {decoded_posted_data}")
                    elif mimetype_lower.startswith('application/x-json-stream'):
                        try:
                            to_stream: StringIO | BytesIO
                            if isinstance(decoded_posted_data, str):
                                to_stream = StringIO(decoded_posted_data)
                            elif isinstance(decoded_posted_data, bytes):
                                to_stream = BytesIO(decoded_posted_data)
                            else:
                                raise ValueError(f'Invalid type: {type(decoded_posted_data)}')
                            streamed_data = json_stream.load(to_stream)
                            decoded_posted_data = json_stream.to_standard_types(streamed_data)
                        except Exception:
                            if isinstance(decoded_posted_data, (str, bytes)):
                                self.logger.warning(f"Expected json stream, got garbage: {mimetype_lower} - {decoded_posted_data[:20]!r}[...]")
                            else:
                                self.logger.warning(f"Expected json stream, got garbage: {mimetype_lower} - {decoded_posted_data}")
                    elif mimetype_lower.startswith('multipart/form-data'):
                        # FIXME multipart content (similar to email). Not totally sure what do do with it tight now.
                        self.logger.debug(f'Got a POST {mimetype_lower}: {decoded_posted_data!r}')
                        pass
                    elif mimetype_lower.startswith('application/x-protobuf'):
                        # FIXME If possible, decode?
                        self.logger.debug(f'Got a POST {mimetype_lower}: {decoded_posted_data!r}')
                        pass
                    elif mimetype_lower.startswith('text') and isinstance(decoded_posted_data, (str, bytes)):
                        try:
                            # NOTE 2023-08-22: Quite a few text entries are in fact json, give it a shot.
                            # loads here may give us a int, float or a bool.
                            decoded_posted_data = json.loads(decoded_posted_data)
                        except Exception:
                            # keep it as it is otherwise.
                            pass
                    elif mimetype_lower.endswith('javascript'):
                        # keep it as it is
                        self.logger.warning(f'Got a POST {mimetype_lower}: {decoded_posted_data!r}')
                        pass
                    elif mimetype_lower == '?':
                        # Just skip it, no need to go in the warnings
                        self.logger.warning(f'Got a POST {mimetype_lower}: {decoded_posted_data!r}')
                        pass
                    elif mimetype_lower == 'application/binary':
                        # generally a broken gzipped blob
                        self.logger.debug(f'Got a POST {mimetype_lower}, most probably a broken gziped blob: {decoded_posted_data!r}')
                    elif mimetype_lower in ['application/octet-stream']:
                        # Should flag it, maybe?
                        self.logger.warning(f'Got a POST {mimetype_lower}: {decoded_posted_data!r}')
                        pass
                    elif mimetype_lower in ['application/grpc-web+proto']:
                        # Can be decoded?
                        self.logger.warning(f'Got a POST {mimetype_lower} - can be decoded: {decoded_posted_data!r}')
                    elif mimetype_lower in ['application/unknown']:
                        # Weird but already seen stuff
                        self.logger.warning(f'Got a POST {mimetype_lower}: {decoded_posted_data!r}')
                        pass
                    else:
                        self.logger.warning(f'Unexpected mime type: {mimetype_lower}')
                else:
                    self.logger.warning(f'Missing mimetype in POST: {self.request["postData"]}')

            # NOTE 2023-08-22: Blind attempt to process the data as json
            if isinstance(decoded_posted_data, (str, bytes)):
                try:
                    decoded_posted_data = json.loads(decoded_posted_data)
                except Exception:
                    pass

            if isinstance(decoded_posted_data, bytes):
                # NOTE 2023-08-22: Blind attempt to decode the bytes
                # Try to decode it as utf-8
                try:
                    decoded_posted_data = decoded_posted_data.decode('utf-8')
                except Exception:
                    pass
            self.add_feature('posted_data', decoded_posted_data)
            if 'postData' in self.request and self.request['postData'].get('mimeType'):
                self.add_feature('posted_data_mimetype', self.request['postData']['mimeType'])

        self.add_feature('response', har_entry['response'])
        try:
            self.add_feature('hhhash', make_hhhash(self.response))
        except HHHashNote as e:
            self.logger.debug(e)
        except HHHashError as e:
            self.logger.warning(e)

        self.add_feature('response_cookie', self.response['cookies'])
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

        if not self.response['content'].get('text') or self.response['content']['text'] == '':
            # If the content of the response is empty, skip.
            self.add_feature('empty_response', True)
            self.add_feature('mimetype', 'inode/x-empty')
        else:
            self.add_feature('empty_response', False)
            if self.response['content'].get('encoding') == 'base64':
                try:
                    self.add_feature('body', BytesIO(self._dirty_safe_b64decode(self.response['content']['text'])))
                except binascii.Error:
                    self.add_feature('body', BytesIO(self.response['content']['text'].encode()))
            else:
                self.add_feature('body', BytesIO(self.response['content']['text'].encode()))

            self.add_feature('body_hash', hashlib.sha512(self.body.getvalue()).hexdigest())
            if self.response['content']['mimeType']:
                mt = self.response['content']['mimeType'].lower()
                if mt not in ["application/octet-stream", "x-unknown"]:
                    self.add_feature('mimetype', mt)

            if not hasattr(self, 'mimetype'):
                # try to guess something better
                if kind := filetype.guess(self.body.getvalue()):
                    self.add_feature('mimetype', kind.mime)

            if not hasattr(self, 'mimetype'):
                self.add_feature('mimetype', '')

            external_ressources, embedded_ressources = find_external_ressources(self.mimetype, self.body.getvalue(), self.name, all_requests)
            self.add_feature('external_ressources', external_ressources)
            self.add_feature('embedded_ressources', embedded_ressources)

            filename = Path(self.url_split.path).name
            if filename:
                self.add_feature('filename', filename)
            else:
                self.add_feature('filename', 'file.bin')

            # Common JS redirect we can catch easily
            # NOTE: it is extremely fragile and doesn't work very often but is kinda better than nothing.
            # Source: https://stackoverflow.com/questions/13363174/regular-expression-to-catch-as-many-javascript-redirections-as-possible
            regex = re.compile(br"""((location.href)|(window.location)|(location.replace)|(location.assign))(( ?= ?)|( ?\( ?))("|')([^'"]*)("|')( ?\) ?)?;""", re.I)
            matches = re.findall(regex, self.body.getvalue())
            for m in matches:
                # TODO: new type, redirect_js or something like that
                redirect_url = rebuild_url(self.name, m[9].decode(), all_requests)
                if redirect_url in all_requests:
                    self.add_feature('redirect', True)
                    self.add_feature('redirect_url', redirect_url)

            if 'meta_refresh' in self.external_ressources and self.external_ressources.get('meta_refresh'):
                if self.external_ressources['meta_refresh'][0] in all_requests:
                    # TODO: new type, redirect_html or something like that
                    self.add_feature('redirect', True)
                    self.add_feature('redirect_url', self.external_ressources['meta_refresh'][0])

        # NOTE: Chrome/Chromium/Playwright only feature
        if har_entry.get('serverIPAddress'):
            # check ipv6 format
            if har_entry['serverIPAddress'].startswith('['):
                _ipaddress = har_entry['serverIPAddress'][1:-1]
            else:
                _ipaddress = har_entry['serverIPAddress']
            self.add_feature('ip_address', ipaddress.ip_address(_ipaddress))

        # NOTE: Chrome/Chromium only feature
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

        # NOTE: Playwright only feature
        if '_securityDetails' in har_entry and har_entry.get('_securityDetails'):
            if 'validFrom' in har_entry['_securityDetails']:
                har_entry['_securityDetails']['validFrom'] = datetime.fromtimestamp(har_entry['_securityDetails']['validFrom'])
            if 'validTo' in har_entry['_securityDetails']:
                har_entry['_securityDetails']['validTo'] = datetime.fromtimestamp(har_entry['_securityDetails']['validTo'])
            self.add_feature('security_details', har_entry['_securityDetails'])

        if self.response['redirectURL']:
            self.add_feature('redirect', True)
            redirect_url = self.response['redirectURL']
            # Rebuild the redirect URL so it matches the entry that sould be in all_requests
            redirect_url = rebuild_url(self.name, redirect_url, all_requests)
            # At this point, we should have a URL available in all_requests...
            if redirect_url in all_requests:
                self.add_feature('redirect_url', redirect_url)
            else:
                # ..... Or not. Unable to find a URL for this redirect
                self.add_feature('redirect_to_nothing', True)
                self.add_feature('redirect_url', self.response['redirectURL'])
                self.logger.warning('Unable to find that URL: {original_url} - {original_redirect} - {modified_redirect}'.format(
                    original_url=self.name,
                    original_redirect=self.response['redirectURL'],
                    modified_redirect=redirect_url))

    def _find_initiator_in_stack(self, stack: MutableMapping[str, Any]) -> str | None:
        # Because everything is terrible, and the call stack can have parents
        if stack['callFrames']:
            return unquote_plus(stack['callFrames'][0]['url'])
        if stack['parent']:
            return self._find_initiator_in_stack(stack['parent'])
        return None

    @property
    def resources_hashes(self) -> set[str]:
        all_ressources_hashes = set()
        if 'body_hash' in self.features:
            all_ressources_hashes.add(self.body_hash)
            if 'embedded_ressources' in self.features:
                for _mimetype, blobs in self.embedded_ressources.items():
                    all_ressources_hashes.update([h for h, b in blobs])
        return all_ressources_hashes

    @property
    def urls_in_rendered_page(self) -> list[str]:

        def _sanitize(maybe_url: str) -> str | None:
            href = strip_html5_whitespace(maybe_url)
            href = safe_url_string(href)

            href = urljoin(self.name, href)

            href = canonicalize_url(href, keep_fragments=True)
            parsed = urlparse(href)
            if not parsed.netloc:
                return None
            return href

        if not hasattr(self, 'rendered_html') or not self.rendered_html:
            raise Har2TreeError('Not the node of a page rendered, invalid request.')
        urls: set[str] = set()

        # The simple ones: the links.
        for a_tag in self.rendered_soup.find_all(["a", "area"]):
            href = a_tag.attrs.get("href")
            if not href:
                continue
            if href := _sanitize(href):
                urls.add(href)

        # The rest of the mess
        for tag in self.rendered_soup.find_all(True):
            if tag.name in ["a", "area", 'img', 'script', 'video', 'audio', 'iframe', 'embed',
                            'source', 'link', 'object']:
                # processed either above or as external resources
                continue
            for attr_name, value in tag.attrs.items():
                if not isinstance(value, str):
                    continue
                if value.startswith('http'):
                    if href := _sanitize(value):
                        urls.add(href)

        return sorted(urls)

    @cached_property
    def rendered_soup(self) -> BeautifulSoup:
        if not hasattr(self, 'rendered_html') or not self.rendered_html:
            raise Har2TreeError('Not the node of a page rendered, invalid request.')
        return make_soup(self.rendered_html.getvalue())


class HostNode(HarTreeNode):

    def __init__(self, capture_uuid: str, **kwargs: Any):
        """Node of the Hostname Tree"""
        super().__init__(capture_uuid=capture_uuid, **kwargs)
        # Do not add the URLs in the json dump
        self.features_to_skip.add('urls')

        self.add_feature('urls', [])
        self.add_feature('http_content', False)
        self.add_feature('https_content', False)
        self.add_feature('contains_rendered_urlnode', False)
        self.cookies_sent: set[str] = set()
        self.cookies_received: set[tuple[str, str, bool]] = set()

    def to_dict(self) -> MutableMapping[str, Any]:
        """Make a dictionary that is json dumpable for d3js"""
        to_return = super().to_dict()
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
            self.add_feature('name', url.hostname)
            if hasattr(url, 'idna'):
                self.add_feature('idna', url.idna)

        if hasattr(url, 'hostname_is_ip') and url.hostname_is_ip:
            self.add_feature('hostname_is_ip', True)

        self.urls.append(url)

        # Add to URLNode a reference to the HostNode UUID
        url.add_feature('hostnode_uuid', self.uuid)

        if hasattr(url, 'rendered_html') or hasattr(url, 'downloaded_filename'):
            self.contains_rendered_urlnode = True
            if hasattr(url, 'downloaded_filename'):
                self.add_feature('downloaded_filename', url.downloaded_filename)

        if hasattr(url, 'cookies_sent'):
            # Keep a set of cookies sent: different URLs will send the same cookie
            self.cookies_sent.update(set(url.cookies_sent.keys()))
        if hasattr(url, 'cookies_received'):
            # Keep a set of cookies received: different URLs will receive the same cookie
            self.cookies_received.update({(domain, cookie, is_3rd_party)
                                          for domain, cookie, is_3rd_party in url.cookies_received})
        if url.name.startswith('http://'):
            self.http_content = True
        elif url.name.startswith('https://'):
            self.https_content = True


def harnode_json_default(obj: HarTreeNode) -> MutableMapping[str, Any]:
    if isinstance(obj, HarTreeNode):
        return obj.to_dict()
