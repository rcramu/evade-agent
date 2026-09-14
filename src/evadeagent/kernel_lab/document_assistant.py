"""document-assistant five-cell fixtures. Delegates to agent_cells."""

from evadeagent.kernel_lab.agent_cells import (
    ENCODING_KIND,
    EXPECTED,
    context_for as _context_for,
    observations_for as _observations_for,
    records_for as _records_for,
)

AGENT = "document-assistant"
CONTEXT = _context_for(AGENT, "L1", f"{AGENT}-L1")


def context_for(cell: str, run_id: str):
    return _context_for(AGENT, cell, run_id)


def records_for(cell: str):
    return _records_for(AGENT, cell)


def observations_for(cell: str, run_id: str):
    return _observations_for(AGENT, cell, run_id)
