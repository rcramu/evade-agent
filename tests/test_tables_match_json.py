"""Guard manuscript table cells against the v3 JSON."""

from __future__ import annotations

import json
from pathlib import Path

_ROOT = Path(__file__).resolve().parents[1]
_JSON = json.loads(
    (_ROOT / "evaluation" / "results" / "approach_comparison.json").read_text(encoding="utf-8")
)
_TABLES = (_ROOT.parent / "jss-submission" / "tables.md").read_text(encoding="utf-8")


def _frac(prevented: int, n: int) -> str:
    return f"{prevented}/{n}"


def test_table8_prevention_matches_json() -> None:
    t4 = _JSON["tables"]["table4"]
    assert "| Static malicious prevented (M1–M2) |" in _TABLES
    row = _TABLES.split("| Static malicious prevented (M1–M2) |", 1)[1].splitlines()[0]
    for mode in ("B1", "B2", "B3", "B4", "B5", "C5"):
        assert _frac(t4[mode]["static_prevented"], t4[mode]["static_n"]) in row


def test_table9_c5_matches_json() -> None:
    c5 = _JSON["tables"]["table5"]["C5"]
    assert "| C5 | 500 | 0 | 32 | 84 | 1.00 | 0.94 | 0.97 |" in _TABLES
    assert c5["tp"] == 500
    assert c5["fn"] == 32
    assert round(c5["f1"], 2) == 0.97


def test_table11_median_matches_json() -> None:
    lat = _JSON["tables"]["table7"]
    assert "0.00154" in _TABLES
    assert abs(lat["C5"]["median_ms"] - 0.0015409896150231361) < 1e-9


def test_table13_coding_residual() -> None:
    coding = _JSON["tables"]["per_agent_c5"]["agents"]["coding-agent"]
    assert coding["blocked"] == 68
    assert coding["residual_allow"] == {"A8": 4, "N7": 4}
    assert "| coding-agent | 68/76 | A8 (4) and N7 (4) |" in _TABLES
