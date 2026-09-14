from pathlib import Path

from evadeagent.kernel_lab.agent_cells import EXPECTED, PILOT_AGENTS, PILOT_CELLS

_ROOT = Path(__file__).resolve().parents[1]
_FIGS = _ROOT / "figures"
_JSON = _ROOT / "evaluation" / "results"


def test_campaign_and_kernel_figures_exist() -> None:
    for name in (
        "figure-11-detection.png",
        "figure-12-ablation.png",
        "figure-13-residual.png",
        "figure-14-latency.png",
        "figure-15-kernel-decisions.png",
        "figure-16-kernel-capture.png",
    ):
        path = _FIGS / name
        assert path.is_file(), path
        assert path.stat().st_size > 1000


def test_kernel_tables_match_expected_decisions() -> None:
    import json

    agents = json.loads((_JSON / "kernel_pilot_agents.json").read_text(encoding="utf-8"))
    assert agents["mismatches"] == []
    for agent in PILOT_AGENTS:
        row = agents["agents"][agent]
        assert row["products_executed"] is True
        for cell in PILOT_CELLS:
            shape = row["cells"][cell]["shape"]
            assert shape["B4"] == EXPECTED[cell]["B4"]
            assert shape["B5"] == EXPECTED[cell]["B5"]
            assert shape["C5"] == EXPECTED[cell]["C5"]


def test_lab_slo_has_three_agents_and_no_field() -> None:
    import json

    slo = json.loads((_JSON / "lab_slo.json").read_text(encoding="utf-8"))
    assert slo["field_executed"] is False
    assert slo["lab"]["agent_count"] == len(PILOT_AGENTS)
    assert slo["lab"]["agent_mismatches"] == []
    assert slo["lab"]["tetragon_process_exec"] >= 13
    assert slo["lab"]["tetragon_extra_process_exec"] >= 14
    assert slo["lab"]["falco_alerts"] >= 4
    assert slo["lab"]["a2_product_path_alerts"] >= 1
    assert slo["lab"]["a4_product_path_alerts"] >= 1
    assert slo["lab"]["a8_product_path_alerts"] == 0
    assert slo["lab"]["a9_product_alerts"] == 0
    assert set(slo["agents"]) == set(PILOT_AGENTS)
