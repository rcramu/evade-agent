"""Kernel-lab pilot: Observation adapter plus optional live Falco/Tetragon dumps.

See docs/kernel-lab.md. Does not open sockets.
"""

from evadeagent.kernel_lab.pilot import PILOT_CELLS, run_pilot
from evadeagent.kernel_lab.dumps import write_bundled_dumps

__all__ = ["PILOT_CELLS", "run_pilot", "write_bundled_dumps"]
