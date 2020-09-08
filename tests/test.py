#!/usr/bin/env python
# -*- coding: utf-8 -*-

import unittest
from har2tree import CrawledTree
from pathlib import Path
import os
import uuid
from itertools import zip_longest

from typing import List, Tuple, Optional, Iterator


class TestBasic(unittest.TestCase):

    def test_lalibre(self) -> None:
        test_dir = Path(os.path.abspath(os.path.dirname(__file__))) / 'data' / 'lalibre'
        har_to_process = sorted(test_dir.glob('*.har'))
        html_to_process = sorted(test_dir.glob('*.html'))
        to_process: Iterator[Tuple[Path, Optional[Path]]] = zip_longest(har_to_process, html_to_process)
        crawled_tree = CrawledTree(to_process, str(uuid.uuid4()))
        crawled_tree.to_json()

    def test_wired(self) -> None:
        test_dir = Path(os.path.abspath(os.path.dirname(__file__))) / 'data' / 'wired'
        har_to_process = sorted(test_dir.glob('*.har'))
        html_to_process = sorted(test_dir.glob('*.html'))
        to_process: Iterator[Tuple[Path, Optional[Path]]] = zip_longest(har_to_process, html_to_process)
        crawled_tree = CrawledTree(to_process, str(uuid.uuid4()))
        crawled_tree.to_json()


if __name__ == '__main__':
    unittest.main()
