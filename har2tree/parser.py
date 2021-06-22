#!/usr/bin/env python
# -*- coding: utf-8 -*-

from pathlib import Path
import copy
from datetime import datetime
from collections import defaultdict
from typing import List, Dict, Optional, Iterable
import logging
from .har2tree import Har2Tree
from .nodes import URLNode
from .helper import Har2TreeError, Har2TreeLogAdapter


class CrawledTree(object):

    def __init__(self, harfiles: Iterable[Path], uuid: str):
        """ Convert a list of HAR files into a ETE Toolkit tree"""
        self.uuid = uuid
        logger = logging.getLogger(f'{__name__}.{self.__class__.__name__}')
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

    @property
    def referer(self) -> Optional[str]:
        """Referer given to the first URL of the capture"""
        return self.root_hartree.initial_referer
