import pstats
from pstats import SortKey

# Read the file restats
p = pstats.Stats('restats')

# Remove unwanted directory paths that are way too long (remove if needed)
p.strip_dirs()

# Sort by cumulated time and display the first 25 first calls; then display their callers (the above functions)
p.sort_stats(SortKey.CUMULATIVE).print_stats(25)
p.print_callers(25)
