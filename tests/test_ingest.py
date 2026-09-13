from pathlib import Path

from evadeagent.kernel_lab.ingest import select_m1_alerts, write_hybrid_dumps
from evadeagent.kernel_lab.collect import load_jsonl
from evadeagent.kernel_lab.pilot import run_pilot

_LIVE = (
    Path(__file__).resolve().parents[1]
    / "kernel-lab"
    / "dumps"
    / "live-m1"
    / "falco.jsonl"
)


def test_select_m1_keeps_lab_container_only() -> None:
    import json

    alerts = [json.loads(line) for line in _LIVE.read_text(encoding="utf-8").splitlines() if line.strip()]
    kept = select_m1_alerts(alerts)
    assert kept
    assert any(row["output_fields"].get("fd.name") == "/lab/secrets/token" for row in kept)
    assert any(row["output_fields"].get("proc.name") == "sh" for row in kept)
    containers = {row["output_fields"].get("container.id") for row in kept}
    assert len(containers) == 1


def test_hybrid_m1_still_matches_expected(tmp_path) -> None:
    dump = write_hybrid_dumps(tmp_path / "hybrid", _LIVE)
    assert load_jsonl(dump / "M1" / "falco.jsonl")
    payload = run_pilot(dump)
    assert payload["cells"]["M1"]["shape"]["B4"] == "BLOCK"
    assert payload["mismatches"] == []
    assert payload["falco_executed"] is True
    assert payload["tetragon_executed"] is False
    assert payload["products_executed"] is False
