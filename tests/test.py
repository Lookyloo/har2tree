#!/usr/bin/env python
# -*- coding: utf-8 -*-

import unittest
from har2tree import Har2Tree
import json


class TestBasic(unittest.TestCase):

    def test_buzzfeed(self):
        with open('tests/data/buzzfeed.har', 'r') as f:
            h2t = Har2Tree(json.load(f))
            h2t.tree('test/out/buzzfeed.pdf')

    def test_circl(self):
        with open('tests/data/circl.har', 'r') as f:
            h2t = Har2Tree(json.load(f))
            h2t.tree('test/out/circl.pdf')

    def test_lemonde(self):
        with open('tests/data/lemonde.har', 'r') as f:
            h2t = Har2Tree(json.load(f))
            h2t.tree('test/out/lemonde.pdf')

    def test_liberation(self):
        with open('tests/data/libe.har', 'r') as f:
            h2t = Har2Tree(json.load(f))
            h2t.tree('test/out/libe.pdf')

    def test_nyt(self):
        with open('tests/data/nyt.har', 'r') as f:
            h2t = Har2Tree(json.load(f))
            h2t.tree('test/out/nyt.pdf')


if __name__ == '__main__':
    unittest.main()
