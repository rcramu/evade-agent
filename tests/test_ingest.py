from pathlib import Path

from evadeagent.kernel_lab.ingest import (
    select_m1_alerts,
    select_tetragon_cell,
    write_hybrid_dumps,
)
from evadeagent.kernel_lab.collect import load_jsonl
from evadeagent.kernel_lab.pilot import run_pilot

_ROOT = Path(__file__).resolve().parents[1]
_LIVE = _ROOT / "kernel-lab" / "dumps" / "live-m1" / "falco.jsonl"
_TG = _ROOT / "kernel-lab" / "dumps" / "live-tetragon" / "tetragon.jsonl"


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


def test_select_tetragon_splits_l1_and_a6() -> None:
    import json

    events = [json.loads(line) for line in _TG.read_text(encoding="utf-8").splitlines() if line.strip()]
    l1 = select_tetragon_cell(events, "L1", "document-assistant")
    a6 = select_tetragon_cell(events, "A6", "document-assistant")
    assert {row["process_exec"]["process"]["binary"].rsplit("/", 1)[-1] for row in l1} == {
        "document-assistant",
        "document-reader",
    }
    assert any(
        row["process_exec"]["parent"]["binary"].endswith("document-assistant") for row in l1
    )
    assert {row["process_exec"]["process"]["binary"].rsplit("/", 1)[-1] for row in a6} == {
        "unrelated-init",
        "document-reader",
    }
    assert any(row["process_exec"]["parent"]["binary"].endswith("unrelated-init") for row in a6)


def test_select_tetragon_splits_coding_and_devops() -> None:
    import json

    events = [json.loads(line) for line in _TG.read_text(encoding="utf-8").splitlines() if line.strip()]
    coding_l1 = select_tetragon_cell(events, "L1", "coding-agent")
    coding_a6 = select_tetragon_cell(events, "A6", "coding-agent")
    devops_l1 = select_tetragon_cell(events, "L1", "devops-agent")
    devops_a6 = select_tetragon_cell(events, "A6", "devops-agent")
    assert {row["process_exec"]["process"]["binary"].rsplit("/", 1)[-1] for row in coding_l1} == {
        "coding-agent",
        "git",
        "test-runner",
    }
    assert {row["process_exec"]["process"]["binary"].rsplit("/", 1)[-1] for row in coding_a6} == {
        "unrelated-init",
        "git",
    }
    assert {row["process_exec"]["process"]["binary"].rsplit("/", 1)[-1] for row in devops_l1} == {
        "devops-agent",
        "kubectl",
    }
    assert {row["process_exec"]["process"]["binary"].rsplit("/", 1)[-1] for row in devops_a6} == {
        "unrelated-init",
        "kubectl",
    }
    coding_init = next(
        row["process_exec"]["process"]["exec_id"]
        for row in coding_a6
        if row["process_exec"]["process"]["binary"].endswith("unrelated-init")
    )
    devops_init = next(
        row["process_exec"]["process"]["exec_id"]
        for row in devops_a6
        if row["process_exec"]["process"]["binary"].endswith("unrelated-init")
    )
    assert coding_init != devops_init


def test_hybrid_both_products_match_expected(tmp_path) -> None:
    dump = write_hybrid_dumps(tmp_path / "hybrid", _LIVE, _TG)
    payload = run_pilot(dump)
    assert payload["mismatches"] == []
    assert payload["falco_executed"] is True
    assert payload["tetragon_executed"] is True
    assert payload["products_executed"] is True
    assert payload["cells"]["L1"]["shape"]["B5"] == "ALLOW"
    assert payload["cells"]["A6"]["shape"]["B5"] == "BLOCK"
