from pathlib import Path
import uuid
from har2tree import CrawledTree
har_path = Path()  / 'tests' / 'capture_samples' / 'http_redirect' / '0.har'
my_first_crawled_tree = CrawledTree([har_path], str(uuid.uuid4()))
my_first_crawled_tree.root_hartree.rendered_node.show()