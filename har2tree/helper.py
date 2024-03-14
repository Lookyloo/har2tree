#!/usr/bin/env python

from __future__ import annotations

import binascii
import hashlib
import logging
import os
import re
import warnings

from base64 import b64decode
from collections import defaultdict
from functools import lru_cache
from io import BytesIO
from logging import LoggerAdapter
from typing import Mapping, MutableMapping, Any
from urllib.parse import urlparse, unquote_plus, unquote_to_bytes, urljoin

import filetype  # type: ignore

from bs4 import BeautifulSoup, Tag, MarkupResemblesLocatorWarning
from charset_normalizer import from_bytes

warnings.simplefilter("ignore", MarkupResemblesLocatorWarning)

logger = logging.getLogger(__name__)


class Har2TreeError(Exception):
    def __init__(self, message: str):
        """
        Har2Tree Exception
        """
        super().__init__(message)
        self.message = message


class HHHashError(Har2TreeError):
    pass


class HHHashNote(Har2TreeError):
    pass


def make_hhhash(entry: dict[str, Any]) -> str:
    """Generate a HTTP Headers Hash following as described: https://github.com/adulau/HHHash"""
    # NOTES:
    #   * Even if the headers are in a list, some implementations of HTTP Archive will sort
    #     the HTTP headers alphabetically by name. It is incorrect, but happens (chromium in playwright v1.36.0).
    #     We have no way to know so we build the hash anyway.
    #   * Playwright will split the value of the HTTP header on a comma (,).
    #     Which means that we have the same header name multiples times in a row instead of once.
    #     It makes senses for cookies but breaks the hashes. In this implementation,
    #     we remove from the headers names with the same name if they follow eachother.
    #     Example: [Date, Date, Cache-Control] becomes [Date, Cache-Control]
    prec: str | None = None
    to_hash: str = ''
    for header in entry['headers']:
        if prec is None:
            to_hash = header['name']
        elif prec != header['name']:
            to_hash += f':{header["name"]}'
        prec = header['name']
    if not to_hash:
        raise HHHashNote('Unable to generate HHHash: no HTTP headers.')
    sha256 = hashlib.sha256(to_hash.encode()).hexdigest()
    # We need the HTTP version used for the query:
    # * The HTTP Header names in HTTP 1.1 can have uppercase characters
    # * The HTTP Header names in HTTP 2 *must* be lowercase: https://www.rfc-editor.org/rfc/rfc7540#section-8.1.2
    if entry['httpVersion'].lower() in ["http/1.1", "http/1.0"]:
        return f'hhh:1:{sha256}'
    if entry['httpVersion'].lower() == "http/2.0":
        return f'hhh:2:{sha256}'
    if entry['httpVersion'].lower() == "h3":
        return f'hhh:3:{sha256}'
    if entry['httpVersion'].lower() in ["blob", "file"]:
        raise HHHashNote('Unable to generate HHHash: known incompatible HTTP version')
    raise HHHashError(f'Unable to generate HHHash: invalid http version ({entry["httpVersion"]})')


def parse_data_uri(uri: str) -> tuple[str, str, bytes] | None:
    if not uri.startswith('data:'):
        return None
    uri = uri[5:]
    if ';base64' in uri:
        mime, b64data = uri.split(';base64', 1)
        if not b64data or b64data[0] != ',':
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


def rebuild_url(base_url: str, partial: str, known_urls: list[str]) -> str:
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
        final_url = partial
    else:
        # If the partial is a valid URL part, urljoin does the trick.
        try:
            final_url = urljoin(base_url, partial)
            # NOTE 2021-05-04: if a partial has empty parts (query/fragment), it will be stripped by urljoin
            if final_url not in known_urls and '?' in partial and '?' not in final_url:
                final_url += '?'
            if final_url not in known_urls and '#' in partial and '#' not in final_url:
                final_url += '#'
        except Exception:
            logger.debug(f'Partial {partial} probably not a url')
            return ''

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
        # On a redirect, if the initial URL has a fragment, it is appended to the destination URL
        if splitted_base_url.fragment:
            try:
                parsed = urlparse(final_url)
                final_url = parsed._replace(fragment=splitted_base_url.fragment).geturl()
            except Exception:
                logger.debug(f'Not a URL: {base_url} - {partial}')
        elif '#' in base_url and '#' not in final_url:
            # NOTE 2021-05-26: if the fragment is empty, splitted_base_url.fragment is false, but the # will still be in the redirect
            final_url += '#'

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

    return final_url


def url_cleanup(dict_to_clean: Mapping[str, list[str]], base_url: str, all_requests: list[str]) -> dict[str, list[str]]:
    """
    Standalone methods to cleanup URLs extracted from an HTML blob.
    """
    to_return: dict[str, list[str]] = {}
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
                logger.debug(f'{key} - not a URL - {to_attach}')
    return to_return


def _unpack_data_uri(data: str) -> tuple[str, str, BytesIO] | None:
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


@lru_cache(maxsize=5)
def init_bs4(html_doc: bytes) -> BeautifulSoup | None:
    # make BS4 life easier and avoid it to attempt to decode
    doc_as_str = str(from_bytes(html_doc).best())
    if not doc_as_str:
        # no need to bother.
        return None
    if doc_as_str.startswith('<?xml'):
        return BeautifulSoup(doc_as_str, 'lxml-xml')
    else:
        return BeautifulSoup(doc_as_str, 'lxml')


def find_identifiers(html_doc: bytes) -> dict[str, list[str]] | None:
    ''' Extracts the identifiers from the HTML blob.
    The identifier we extract now is the recapthca site key, but there will be more.
    '''
    soup = init_bs4(html_doc)
    if soup is None:
        return None
    to_return: dict[str, list[str]] = defaultdict(list)

    if recaptchas := soup.select(".g-recaptcha"):
        # We should have only one recaptcha per page, but have you seen the web?
        for recaptcha in recaptchas:
            if sitekey := recaptcha.get('data-sitekey'):
                if isinstance(sitekey, list):
                    # Should not happen, but once again...
                    to_return['recaptcha'] += sitekey
                else:
                    to_return['recaptcha'].append(sitekey)

    if recaptchas := soup.select(".h-captcha"):
        # We should have only one recaptcha per page, but have you seen the web?
        for recaptcha in recaptchas:
            if sitekey := recaptcha.get('data-sitekey'):
                if isinstance(sitekey, list):
                    # Should not happen, but once again...
                    to_return['hcaptcha'] += sitekey
                else:
                    to_return['hcaptcha'].append(sitekey)
    return to_return


def find_external_ressources(html_doc: bytes, base_url: str, all_requests: list[str], full_text_search: bool=True) -> tuple[dict[str, list[str]], dict[str, list[tuple[str, BytesIO]]]]:
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
    external_ressources: dict[str, list[str]] = {'img': [], 'script': [], 'video': [], 'audio': [],
                                                 'iframe': [], 'embed': [], 'source': [],
                                                 'link': [],
                                                 'object': [],
                                                 'css': [],
                                                 'full_regex': [],
                                                 'javascript': [],
                                                 'meta_refresh': []}

    embedded_ressources: dict[str, list[tuple[str, BytesIO]]] = defaultdict(list)
    soup = init_bs4(html_doc)
    if soup is None:
        return external_ressources, embedded_ressources
    for link in soup.find_all(['img', 'script', 'video', 'audio', 'iframe', 'embed',
                               'source', 'link', 'object']):
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
    meta_refresh = soup.find('meta', attrs={'http-equiv': re.compile("^refresh$", re.I)})
    if meta_refresh and isinstance(meta_refresh, Tag) and meta_refresh.get('content'):
        # NOTE 2021-05-15: in theory, a meta key look like that: <number>;url=<url>
        # but the url= part may not be present
        content = meta_refresh['content']
        if isinstance(content, str):
            content = content.strip()
            if ';' in content:
                timeout, url = content.split(';', 1)
                if timeout.isdigit():
                    # Strip timeout
                    content = url.strip()
            if content[:4].lower() == 'url=':
                content = content[4:].strip()
            external_ressources['meta_refresh'].append(content)

    # external stuff loaded from css content, because reasons.
    for u in re.findall(rb'url\((?:[\'"])?(.*?)(?:[\'"])?\)', html_doc):
        try:
            url = u.decode()
        except UnicodeDecodeError as e:
            logger.info(f'Unable to decode ressource in CSS {u[:20]}[...]: {e}')
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
    for u in re.findall(b'(?:window|self|top).location(?:.*)\"(.*?)\"', html_doc):
        try:
            url = u.decode()
        except UnicodeDecodeError as e:
            logger.info(f'Unable to decode ressource in JS {u[:20]}[...]: {e}')
            continue
        external_ressources['javascript'].append(url)
    # NOTE: we may want to extract calls to decodeURI and decodeURIComponent
    # https://developer.mozilla.org/en-US/docs/Web/JavaScript/Reference/Global_Objects/decodeURI
    # https://developer.mozilla.org/en-US/docs/Web/JavaScript/Reference/Global_Objects/decodeURIComponent
    # Just in case, there is sometimes an unescape call in JS code
    for to_unescape in re.findall(br'unescape\(\'(.*)\'\)', html_doc):
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
        external_ressources['full_regex'] = [url.decode() for url in re.findall(rb'(?:http[s]?:)?//(?:[a-zA-Z]|[0-9]|[$-_@.&+]|[!*\(\),]|(?:%[0-9a-fA-F][0-9a-fA-F]))+', html_doc)]
        # print("################ REGEXES ", external_ressources['full_regex'])
    # NOTE: unescaping a potential URL as HTML content can make it unusable (example: (...)&ltime=(...>) => (...)<ime=(...))
    return url_cleanup(external_ressources, base_url, all_requests), embedded_ressources


class Har2TreeLogAdapter(LoggerAdapter):  # type: ignore[type-arg]
    """
    Prepend log entry with the UUID of the capture
    """
    def process(self, msg: str, kwargs: MutableMapping[str, Any]) -> tuple[str, MutableMapping[str, Any]]:
        return '[{}] {}'.format(self.extra['uuid'], msg), kwargs  # type: ignore[index]
