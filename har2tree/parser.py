#!/usr/bin/env python
# -*- coding: utf-8 -*-

from pathlib import Path
import json
import copy
from datetime import datetime, timedelta
import uuid
from urllib.parse import urlparse, unquote_plus, unquote_to_bytes, urljoin
from base64 import b64decode
import binascii
from collections import defaultdict
import re
import os
from io import BytesIO
import hashlib
from operator import itemgetter
from typing import List, Dict, Optional, Union, Tuple, Set, MutableMapping, Any, Mapping, Iterable, Callable
import ipaddress
import sys
import logging
from functools import wraps
from .helper import __load_debug_files, trace_make_subtree_fallback, trace_make_subtree, harnode_json_default, parse_data_uri, rebuild_url, url_cleanup, _unpack_data_uri, find_external_ressources

from publicsuffix2 import PublicSuffixList, fetch  # type: ignore
from ete3 import TreeNode  # type: ignore
from bs4 import BeautifulSoup  # type: ignore
import filetype  # type: ignore
from w3lib.html import strip_html5_whitespace  # type: ignore
from w3lib.url import canonicalize_url, safe_url_string  # type: ignore

logger = logging.getLogger(__name__)


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
    logger.critical('You are running har2tree in dev debug mode.')
    logger.critical(f'Path to the debug files: {path_to_debug_files}.')


# ##################################################################

class CrawledTree(object):

    def __init__(self, harfiles: Iterable[Path], uuid: str):
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

    def load_all_harfiles(self, files: Iterable[Path]) -> List[Har2Tree]:
        """Open all the HAR files and build the trees"""
        loaded = []
        for har_path in files:
            try:
                har2tree = Har2Tree(har_path, capture_uuid=self.uuid)
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
        return self.root_hartree.redirects

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
