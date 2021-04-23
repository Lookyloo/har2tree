#!/usr/bin/env python
# -*- coding: utf-8 -*-

import unittest
from har2tree import CrawledTree
from pathlib import Path
import os
import uuid

from typing import Iterable


class SimpleTest(unittest.TestCase):

    crawled_tree: CrawledTree

    @classmethod
    def setUpClass(cls) -> None:
        test_dir = Path(os.path.abspath(os.path.dirname(__file__))) / 'data' / 'simple'
        har_to_process = [test_dir / 'heroku_index.har']
        cls.index_tree = CrawledTree(har_to_process, str(uuid.uuid4()))


    def test_root_url(self) -> None:
        self.assertEqual(self.index_tree.root_url, 'https://lookyloo-testing.herokuapp.com/')
    
    def test_user_agent(self) -> None:
        self.assertEqual(self.index_tree.user_agent, "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/89.0.4389.128 Safari/537.36")


if __name__ == '__main__':
    unittest.main()



