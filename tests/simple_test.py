#!/usr/bin/env python
# -*- coding: utf-8 -*-

import unittest
from har2tree import CrawledTree
from har2tree.helper import parse_data_uri, rebuild_url
from pathlib import Path
import datetime
import os
import uuid
import json


class SimpleTest(unittest.TestCase):

    http_redirect_ct: CrawledTree
    user_agent_android_ct: CrawledTree
    user_agent_macos_ct: CrawledTree
    referer_ct: CrawledTree
    no_referer_ct: CrawledTree
    cookie_ct: CrawledTree
    no_cookie_ct: CrawledTree
    iframe_ct: CrawledTree
    lonely_har_ct: CrawledTree
    final_redirect_questionmark_ct: CrawledTree
    final_redirect_dash_ct: CrawledTree
    maxDiff = None

    @classmethod
    def setUpClass(cls) -> None:

        setattr(cls, 'test_dir', Path(os.path.abspath(os.path.dirname(__file__))) / 'capture_samples')

        # Iterates over capture_samples folder and makes a CrawledTree out of each folder
        for x in cls.test_dir.iterdir():
            if x.is_dir():
                folder_name = str(x).split('/')[-1]
                tree_name = f'{folder_name}_ct'
                har = cls.test_dir / folder_name / '0.har'
                setattr(cls, tree_name, CrawledTree([har], str(uuid.uuid4())))

    # First 3 tests make sure that CrawledTree methods access the contents of the .har file properly
    def test_root_url(self) -> None:
        self.assertEqual(self.http_redirect_ct.root_url, 'https://lookyloo-testing.herokuapp.com/redirect_http')

    def test_user_agent_http_redirect(self) -> None:
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

    # Make sure that the correct user agent is detected
    def test_user_agent_android(self) -> None:
        self.assertEqual(self.user_agent_android_ct.user_agent, "Mozilla/5.0 (Linux; Android 7.0;) AppleWebKit/537.36 (KHTML, like Gecko) Mobile Safari/537.36 (compatible; PetalBot;+https://webmaster.petalsearch.com/site/petalbot)")

    def test_user_agent_macos(self) -> None:
        self.assertEqual(self.user_agent_macos_ct.user_agent, "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_5) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/13.1.1 Safari/605.1.15 (Applebot/0.1; +http://www.apple.com/go/applebot)")

    # Test that the redirect is correctly made and detected depending on the user agent
    # We want to make sure that the use cases depicted in this link are working properly:
    # https://github.com/Lookyloo/testing/blob/0ca5571ad9ee0a092318f2c2d70c591df2c561f8/website/__init__.py#L245

    def test_redirect_user_agent_android(self) -> None:
        # Using second url instead of final because it's much cleaner (it doesn't contain youtube consent url)
        redirect_url = self.user_agent_android_ct.root_hartree.redirects[1]
        self.assertEqual(redirect_url, 'https://www.youtube.com/watch?v=z1APG3HjO4Q')

    def test_redirect_user_agent_macos(self) -> None:
        redirect_url = self.user_agent_macos_ct.root_hartree.redirects[1]
        self.assertEqual(redirect_url, 'https://www.youtube.com/watch?v=0NwkczSuwL8')

    def test_referer_ct_has_referer(self) -> None:
        self.assertEqual(self.referer_ct.root_hartree.root_referer, 'http://circl.lu')

    def test_referer_cts_same_urls(self) -> None:
        self.assertEqual(self.referer_ct.root_url, self.no_referer_ct.root_url)

    def test_referer_cts_have_different_redirects_despite_same_url(self) -> None:
        # Emphasize that the referer capture has a different final redirect than the no_referer capture despite having same URL
        self.assertNotEqual(self.referer_ct.root_hartree.har.final_redirect, self.no_referer_ct.root_hartree.har.final_redirect)

    # We want to check the redirect made in case there is a cookie
    # Just making sure the two urls are the same
    def test_cookie_captures_same_urls(self) -> None:
        self.assertEqual(self.cookie_ct.root_url, self.no_cookie_ct.root_url)

    # For that we make sure there is no eventual referer interfering with the cookie redirection
    def test_cookie_captures_have_no_referer(self) -> None:
        self.assertFalse(self.cookie_ct.root_hartree.root_referer or self.no_cookie_ct.root_hartree.root_referer)

    # Finally we check that the two last redirects are indeed different
    def test_cookie_captures_different_redirects(self) -> None:
        self.assertNotEqual(self.cookie_ct.root_hartree.har.final_redirect, self.no_cookie_ct.root_hartree.har.final_redirect)

    def test_urls_in_rendered_page(self) -> None:
        self.assertEquals
        (
            self.cookie_ct.root_hartree.rendered_node.urls_in_rendered_page,
            ['https://accounts.google.com/ServiceLogin?continue=https%3A%2F%2Fwww.youtube.com%2Fwatch%3Fv%3DiwGFalTRHDA&gae=cb-23983172&hl=en',
                'https://consent.youtube.com/d?continue=https%3A%2F%2Fwww.youtube.com%2Fwatch%3Fv%3DiwGFalTRHDA&gl=FR&hl=en&pc=yt&src=1&uxe=23983172',
                'https://policies.google.com/privacy?hl=en&utm_source=ucb',
                'https://policies.google.com/privacy?hl=en&utm_soure=ucb',
                'https://policies.google.com/technologies/cookies?hl=en&utm_source=ucb',
                'https://policies.google.com/terms?hl=en&utm_source=ucb',
                'https://policies.google.com/terms?hl=en&utm_soure=ucb']
        )

    def test_iframe_feature(self) -> None:
        self.assertTrue('iframe' in self.iframe_ct.root_hartree.hostname_tree.features)

    def test_iframe_capture_name(self) -> None:
        self.assertEqual(self.iframe_ct.root_hartree.har.initial_title, '!! No title found !!')

    def test_cookie_number_entries(self) -> None:
        self.assertEqual(self.cookie_ct.root_hartree.har.number_entries, 63)

    def test_iframe_has_no_initial_redirects(self) -> None:
        self.assertFalse(self.iframe_ct.root_hartree.har.has_initial_redirects)

    def test_lonely_har_no_final_redirect(self) -> None:
        self.assertFalse(self.lonely_har_ct.root_hartree.har.final_redirect)

    def test_lonely_har_no_cookie_file(self) -> None:
        self.assertFalse(self.lonely_har_ct.root_hartree.har.cookies)

    def test_lonely_har_no_html_file(self) -> None:
        self.assertFalse(self.lonely_har_ct.root_hartree.har.html_content)

    def test_final_redirect_has_to_get_a_trim(self) -> None:
        # Both final redirects have a ? or # that needs to be removed, apart from that the URLs are the same
        # We make sure that they are correctly trimmed (if so they should give the same URL)
        self.assertEqual(self.final_redirect_dash_ct.root_hartree.har.final_redirect, self.final_redirect_questionmark_ct.root_hartree.har.final_redirect)

    # Using http_redirect_ct as much as possible because it's much faster than with cookie
    def test_mixed_content(self) -> None:
        self.assertFalse(self.http_redirect_ct.root_hartree.hostname_tree.mixed_content)

    # Only one URL in the capture
    def test_urls_count(self) -> None:
        self.assertEqual(self.http_redirect_ct.root_hartree.hostname_tree.urls_count, 1)

    # Should be 1 as capture was made with a request cookie
    def test_request_cookie(self) -> None:
        self.assertEqual(self.cookie_ct.root_hartree.hostname_tree.request_cookie, 1)

    # Should be 0 as capture was made without cookie
    def test_request_cookie_no_cookie(self) -> None:
        self.assertEqual(self.no_cookie_ct.root_hartree.hostname_tree.request_cookie, 0)

    def test_response_cookie(self) -> None:
        self.assertEqual(self.http_redirect_ct.root_hartree.hostname_tree.response_cookie, 0)

    def test_third_party_cookies_received(self) -> None:
        self.assertEqual(self.http_redirect_ct.root_hartree.hostname_tree.response_cookie, 0)

    def test_hostnode_to_json(self) -> None:

        # Easiest way to test the to_json method without having a huge string here is extracting one from a file
        # This file is already cleaned, no UUIDs (see)
        with open(self.test_dir / 'iframe' / 'to_json.json') as json_file:
            expected_dict = json.load(json_file)

        to_test = json.loads(self.iframe_ct.root_hartree.hostname_tree.to_json())

        # Removing all the UUIDs from this capture
        # as a new UUID is generated on every instanciation of a CrawledTree
        del to_test['uuid']
        del to_test['children'][0]['uuid']

        self.assertEqual(to_test, expected_dict)


if __name__ == '__main__':
    unittest.main()
