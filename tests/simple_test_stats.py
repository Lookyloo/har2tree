import pstats
from pstats import SortKey
p = pstats.Stats('restats')
p.strip_dirs()
p.sort_stats(SortKey.CUMULATIVE)
p.print_callers(100)

