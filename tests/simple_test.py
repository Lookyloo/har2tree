#!/usr/bin/env python
# -*- coding: utf-8 -*-

import unittest
from har2tree import CrawledTree
from har2tree.helper import parse_data_uri, rebuild_url
from pathlib import Path
import datetime
import os
import uuid


class SimpleTest(unittest.TestCase):

    http_redirect_ct: CrawledTree

    @classmethod
    def setUpClass(cls) -> None:

        test_dir = Path(os.path.abspath(os.path.dirname(__file__))) / 'capture_samples' / 'http_redirect'
        har_to_process = [test_dir / '0.har']
        # ct means CrawledTree
        cls.http_redirect_ct = CrawledTree(har_to_process, str(uuid.uuid4()))

    # First 3 tests make sure that CrawledTree methods access the contents of the .har file properly
    def test_root_url(self) -> None:
        self.assertEqual(self.http_redirect_ct.root_url, 'https://lookyloo-testing.herokuapp.com/redirect_http')

    def test_user_agent(self) -> None:
        self.assertEqual(self.http_redirect_ct.user_agent, "Mozilla/5.0 (Windows NT 6.1; WOW64) AppleWebKit/534+ (KHTML, like Gecko) BingPreview/1.0b")

    def test_redirects(self) -> None:
        self.assertEqual(self.http_redirect_ct.redirects[1], "https://www.youtube.com/watch?v=iwGFalTRHDA")

    # Assert that start_time property gives correct date in correct format
    def test_start_time(self) -> None:
        self.assertEqual(self.http_redirect_ct.start_time, datetime.datetime(2021, 4, 22, 15, 57, 51, 686108, tzinfo=datetime.timezone.utc))

    def test_root_referer(self) -> None:
        # We did not pass any referer in Lookyloo, we should get an empty response
        self.assertEqual(self.http_redirect_ct.root_hartree.root_referer, '')

    def test_stats(self) -> None:
        stats = {'total_hostnames': 5,  # Nodes in hostname tree
                 'total_urls': 7,  # Nodes in URL tree
                 'total_cookies_sent': 1,  # Number of unique cookies sent
                 'total_cookies_received': 1,  # Number of unique cookies received
                 'total_redirects': 4,  # number of redirects leading to the landing page
                 'total_unique_hostnames': 4,  # Number of unique hostnames
                 'total_unique_urls': 6,  # Number of unique urls
                 'tree_depth': 5  # Max depth of the tree (from the initial URL)
                 }
        self.assertEqual(self.http_redirect_ct.root_hartree.stats, stats)

    def test_root_after_redirect(self) -> None:
        self.assertEqual(self.http_redirect_ct.root_hartree.root_after_redirect, "https://consent.youtube.com/ml?continue=https://www.youtube.com/watch?v=iwGFalTRHDA&gl=LU&hl=en&pc=yt&uxe=23983172&src=1")

    def test_search_final_redirect(self) -> None:
        # make sure the program has access to the final_redirect.txt file
        self.http_redirect_ct.root_hartree.har._search_final_redirect()
        self.assertEqual(self.http_redirect_ct.root_hartree.har.final_redirect, "https://consent.youtube.com/ml?continue=https://www.youtube.com/watch?v=iwGFalTRHDA&gl=LU&hl=en&pc=yt&uxe=23983172&src=1")

    def test_rendered_node_name_equals_last_redirect(self) -> None:
        self.assertEqual(self.http_redirect_ct.root_hartree.rendered_node.name, self.http_redirect_ct.root_hartree.har.final_redirect)

    def test_tree_start_time_equals_har_start_time(self) -> None:
        # Need some formatting because ct.start_time is in datetime fromat natively;
        # alternatively, har start_time contains a T before time that would mess the comparison
        tree_start_time = self.http_redirect_ct.start_time.strftime("%Y-%m-%d %H:%M:%S")
        har_start_time = self.http_redirect_ct.root_hartree.har.initial_start_time[0:19].replace('T', ' ')
        self.assertEqual(tree_start_time, har_start_time)

    def test_initial_redirect_equals_final_redirect(self) -> None:
        # As there is only one redirect, both initial and final redirects should return the same URL
        self.assertEqual(self.http_redirect_ct.root_hartree.har.initial_redirects[0], self.http_redirect_ct.root_hartree.har.final_redirect)

    def test_parse_data_uri(self) -> None:
        # decodes base 64 into hello world; gives an idea of what the function does
        self.assertEqual(parse_data_uri("data:text/plain;charset=US-ASCII;base64,SGVsbG8sIFdvcmxkIQ=="), ('text/plain', 'charset=US-ASCII', b'Hello, World!'))

    def test_rebuild_url_end_slash(self) -> None:
        # parser.py L#188 shows that rebuild_url should behave differently if there is a slash or not at the end of the base URL despite having same known urls;
        # see next two tests
        rebuilt_url_no_end_slash = rebuild_url('https://lookyloo-testing.herokuapp.com/subdir', 'redirect_http_partial_no_slash_dest', ['https://lookyloo-testing.herokuapp.com/subdir/redirect_http_partial_no_slash_dest'])
        rebuilt_url_with_end_slash = rebuild_url('https://lookyloo-testing.herokuapp.com/subdir/', 'redirect_http_partial_no_slash_dest', ['https://lookyloo-testing.herokuapp.com/subdir/redirect_http_partial_no_slash_dest'])
        self.assertNotEqual(rebuilt_url_no_end_slash, rebuilt_url_with_end_slash)

    def test_rebuild_url_no_end_slash(self) -> None:
        # in this case, /subdir disappears because the algorithm splits before the last found /
        rebuilt_url_no_end_slash = rebuild_url('https://lookyloo-testing.herokuapp.com/subdir', 'redirect_http_partial_no_slash_dest', ['https://lookyloo-testing.herokuapp.com/subdir/redirect_http_partial_no_slash_dest'])
        self.assertEqual(rebuilt_url_no_end_slash, 'https://lookyloo-testing.herokuapp.com/redirect_http_partial_no_slash_dest/')

    def test_rebuild_url_with_end_slash(self) -> None:
        # on the other hand, this test will simply add the partial URL to the given base url
        rebuilt_url_with_end_slash = rebuild_url('https://lookyloo-testing.herokuapp.com/subdir/', 'redirect_http_partial_no_slash_dest', ['https://lookyloo-testing.herokuapp.com/subdir/redirect_http_partial_no_slash_dest'])
        self.assertEqual(rebuilt_url_with_end_slash, 'https://lookyloo-testing.herokuapp.com/subdir/redirect_http_partial_no_slash_dest')

    def test_rebuild_url_partial_double_slash(self) -> None:
        # a partial url starting with // means that it will redirect on the same scheme as the base url (if its https, it will redirect on https too)
        rebuild_url_double_slash = rebuild_url('https://lookyloo-testing.herokuapp.com/redirect_http_partial_no_scheme', '//www.youtube.com/watch?v=iwGFalTRHDA', ['https://www.youtube.com/watch?v=iwGFalTRHDA'])
        self.assertEqual(rebuild_url_double_slash, 'https://www.youtube.com/watch?v=iwGFalTRHDA')

    def test_hostname_tree_features(self) -> None:
        self.assertEqual(self.http_redirect_ct.root_hartree.hostname_tree.features, {'name', 'js', 'html', 'pdf', 'json', 'text', 'video', 'css', 'iframe', 'http_content', 'https_content', 'support', 'dist', 'octet_stream', 'font', 'redirect',
                                                                                     'unknown_mimetype', 'contains_rendered_urlnode', 'urls', 'uuid', 'redirect_to_nothing', 'unset_mimetype', 'image'})

    def test_url_node_resources_hashes(self) -> None:
        self.assertEqual(self.http_redirect_ct.root_hartree.url_tree.resources_hashes, {'b271f214df6b3351a4fb9b94b3680b62a53b1f555153539bdfbfe464b423e0d0a2d172607d40607ba306a17eae30dd1146ecc96e4a7de03ed2188974b915ddea'})


if __name__ == '__main__':
    unittest.main()
