"""Event-shape pilot for a later kernel campaign.

Parses Falco-like and Tetragon-like JSON *shapes*. Does not load BPF, open
sockets, or execute Falco or Tetragon. See docs/kernel-lab.md.
"""

from evadeagent.kernel_lab.pilot import PILOT_CELLS, run_pilot
from evadeagent.kernel_lab.dumps import write_bundled_dumps

__all__ = ["PILOT_CELLS", "run_pilot", "write_bundled_dumps"]
