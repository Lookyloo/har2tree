#!/usr/bin/env python
# -*- coding: utf-8 -*-

import unittest
from har2tree import CrawledTree, Har2Tree
from pathlib import Path
import datetime
import os
import uuid


class SimpleTest(unittest.TestCase):

    http_redirect_tree: CrawledTree


    @classmethod
    def setUpClass(cls) -> None:
        test_dir = Path(os.path.abspath(os.path.dirname(__file__))) / 'capture_samples' / 'http_redirect'

        har_to_process = [test_dir / '0.har']
        # ct means CrawledTree
        cls.http_redirect_ct = CrawledTree(har_to_process, str(uuid.uuid4()))

        # Har2Tree needs a string path contrarily to CrawledTree which needs Iterable
        har_to_process_string = test_dir / '0.har'
        cls.http_redirect_tree = Har2Tree(har_to_process_string, str(uuid.uuid4()))
        

    def test_root_url(self) -> None:
        self.assertEqual(self.http_redirect_ct.root_url, 'https://lookyloo-testing.herokuapp.com/redirect_http')

    def test_user_agent(self) -> None:
        self.assertEqual(self.http_redirect_ct.user_agent, "Mozilla/5.0 (Windows NT 6.1; WOW64) AppleWebKit/534+ (KHTML, like Gecko) BingPreview/1.0b")
    
    def test_redirects(self) -> None:
        self.assertEqual(self.http_redirect_ct.redirects[1], "https://www.youtube.com/watch?v=iwGFalTRHDA")

    def test_start_time(self) -> None:
        self.assertEqual(self.http_redirect_ct.start_time, datetime.datetime(2021, 4, 22, 15, 57, 51, 686108, tzinfo=datetime.timezone.utc))

    def test_root_referer(self) -> None:
        self.assertEqual(self.http_redirect_tree.root_referer, '')

if __name__ == '__main__':
    unittest.main()



