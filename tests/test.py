#!/usr/bin/env python

import unittest
from har2tree import CrawledTree
from pathlib import Path
import os
import uuid

from typing import Iterable


class TestBasic(unittest.TestCase):

    def test_lalibre(self) -> None:
        test_dir = Path(os.path.abspath(os.path.dirname(__file__))) / 'data' / 'lalibre'
        har_to_process: Iterable[Path] = test_dir.glob('*.har')
        crawled_tree = CrawledTree(har_to_process, str(uuid.uuid4()))
        crawled_tree.to_json()

    def test_wired(self) -> None:
        test_dir = Path(os.path.abspath(os.path.dirname(__file__))) / 'data' / 'wired'
        har_to_process: Iterable[Path] = sorted(test_dir.glob('*.har'))
        crawled_tree = CrawledTree(har_to_process, str(uuid.uuid4()))
        crawled_tree.to_json()


if __name__ == '__main__':
    unittest.main()
