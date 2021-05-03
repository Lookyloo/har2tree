#!/usr/bin/env python
# -*- coding: utf-8 -*-

from pathlib import Path
from typing import List, Optional, Union, Tuple, Set, MutableMapping, Any
import logging
import uuid
import json
from .helper import find_external_ressources, rebuild_url
from io import BytesIO
from urllib.parse import unquote_plus, urlparse, urljoin
import sys
from datetime import datetime, timedelta
import ipaddress
from base64 import b64decode
import hashlib
import re
from .helper import Har2TreeError

import filetype  # type: ignore
from bs4 import BeautifulSoup  # type: ignore
from ete3 import TreeNode  # type: ignore
from publicsuffix2 import PublicSuffixList, fetch  # type: ignore
from w3lib.html import strip_html5_whitespace  # type: ignore
from w3lib.url import canonicalize_url, safe_url_string  # type: ignore

# Initialize Public Suffix List

logger = logging.getLogger(__name__)

try:
    psl_file = fetch()
    psl = PublicSuffixList(psl_file=psl_file)
except Exception as e:
    logger.warning(f'Unable to fetch the PublicSuffixList: {e}')
    psl = PublicSuffixList()


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
        if '.' in har_entry['startedDateTime']:
            self.add_feature('start_time', datetime.strptime(har_entry['startedDateTime'], '%Y-%m-%dT%H:%M:%S.%f%z'))
        else:
            self.add_feature('start_time', datetime.strptime(har_entry['startedDateTime'], '%Y-%m-%dT%H:%M:%S%z'))

        self.add_feature('pageref', har_entry['pageref'])

        self.add_feature('time', timedelta(milliseconds=har_entry['time']))
        self.add_feature('time_content_received', self.start_time + self.time)  # Instant the response is fully received (and the processing of the content by the browser can start)
        self.add_feature('hostname', self.url_split.hostname)

        if not self.hostname:
            self.logger.warning(f'Something is broken in that node: {har_entry}')

        try:
            ipaddress.ip_address(self.hostname)
            self.add_feature('hostname_is_ip', True)
        except ValueError:
            # Not an IP
            pass

        if not hasattr(self, 'hostname_is_ip'):
            tld = psl.get_tld(self.hostname, strict=True)
            if tld:
                self.add_feature('known_tld', tld)
            else:
                self.logger.info(f'###### No TLD/domain broken {self.name}')

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
                    original_url=self.name,
                    original_redirect=har_entry['response']['redirectURL'],
                    modified_redirect=redirect_url))

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

    @property
    def urls_in_rendered_page(self) -> List[str]:
        if not self.rendered_html:
            raise Har2TreeError('Not the node of a page rendered, invalid request.')
        urls: Set[str] = set()
        soup = BeautifulSoup(self.rendered_html.getvalue(), "lxml")
        for a_tag in soup.find_all(["a", "area"]):
            href = a_tag.attrs.get("href")
            if not href:
                continue

            href = strip_html5_whitespace(href)
            href = safe_url_string(href)

            href = urljoin(self.name, href)

            href = canonicalize_url(href, keep_fragments=True)
            parsed = urlparse(href)
            if not parsed.netloc:
                continue
            urls.add(href)
        return sorted(urls)


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
        self.add_feature('contains_rendered_urlnode', False)
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

        if hasattr(url, 'rendered_html'):
            self.contains_rendered_urlnode = True

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


def harnode_json_default(obj: 'HarTreeNode') -> MutableMapping[str, Any]:
    if isinstance(obj, HarTreeNode):
        return obj.to_dict()
