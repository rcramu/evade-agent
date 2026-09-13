from pathlib import Path

from evadeagent.kernel_lab.phase2 import run_phase2, split_audit
from evadeagent.kernel_lab.pilot import PILOT_CELLS

_ROOT = Path(__file__).resolve().parents[1]
_LIVE = _ROOT / "kernel-lab" / "dumps" / "live-m1" / "falco.jsonl"
_TG = _ROOT / "kernel-lab" / "dumps" / "live-tetragon" / "tetragon.jsonl"


def test_split_audit_assigns_a8_extra_read() -> None:
    rows = [{"uri": "mcp://documents/search", "tool": "document.search", "t": i} for i in range(11)]
    # overwrite tools so grouping still works by count
    rows[0]["tool"] = "document.search"
    per = split_audit(rows)
    assert list(per) == list(PILOT_CELLS)
    assert len(per["L1"]) == 2
    assert len(per["A8"]) == 3
    assert per["A8"][-1]["t"] == 5


def test_phase2_pilot_matches_expected(tmp_path: Path) -> None:
    payload = run_phase2(tmp_path / "phase2", _LIVE, _TG)
    assert payload["mismatches"] == []
    assert payload["mcp_executed"] is True
    assert payload["observer_executed"] is True
    assert payload["tls_version"] == "TLSv1.3"
    assert payload["products_executed"] is True
    assert payload["cells"]["A8"]["capture"]["complete"] is False
