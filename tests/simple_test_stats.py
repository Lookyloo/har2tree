#!/usr/bin/env python
# -*- coding: utf-8 -*-

import pstats
from pstats import SortKey

# Read the file restats
p = pstats.Stats('restats')

# Remove unwanted directory paths that are way too long (remove if needed)
p.strip_dirs()

# Sort by cumulated time and display the first 25 first calls; then display their callers (the above functions)
p.sort_stats(SortKey.CUMULATIVE).print_stats(25)
p.print_callers(25)

# Note: it might not be very clear what the program does with this tool
# Instead, you could use snakeviz:
# Simply type in:
# pip install snakeviz 
# and then 
# snakeviz restats
