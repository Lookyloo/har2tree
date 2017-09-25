#!/usr/bin/env python
# -*- coding: utf-8 -*-

import unittest
from har2tree import CrawledTree
import os
from glob import glob


class TestBasic(unittest.TestCase):

    def test_lalibre(self):
        test_dir = os.path.join(os.path.abspath(os.path.dirname(__file__)), 'data', 'lalibre')
        out_dir = os.path.join(os.path.abspath(os.path.dirname(__file__)), 'out')
        to_process = sorted(glob(os.path.join(test_dir, '*.har')))
        crawled_tree = CrawledTree(to_process)
        crawled_tree.find_parents()
        crawled_tree.join_trees()
        crawled_tree.jsonify()
        crawled_tree.render_hostname_tree(os.path.join(out_dir, 'lalibre.png'))


if __name__ == '__main__':
    unittest.main()
