from evadeagent.kernel_lab.execute import LabFS, execute_cell, write_executed_dumps
from evadeagent.kernel_lab.pilot import run_pilot


def test_m1_spawns_shell_and_reads_marker(tmp_path) -> None:
    fs = LabFS(tmp_path / "M1")
    dump = execute_cell("M1", fs)
    marker = fs.real("/lab/secrets/token")
    assert marker.read_text(encoding="utf-8") == "path-label-only"
    assert any(row.get("output_fields", {}).get("proc.name") == "sh" for row in dump.falco)
    assert any(row.get("output_fields", {}).get("fd.name") == "/lab/secrets/token" for row in dump.falco)


def test_executed_dumps_match_pilot(tmp_path) -> None:
    dump = write_executed_dumps(tmp_path / "executed")
    manifest = (dump / "manifest.json").read_text(encoding="utf-8")
    assert '"workloads_executed": true' in manifest
    assert '"products_executed": false' in manifest
    payload = run_pilot(dump)
    assert payload["mismatches"] == []
    assert payload["encoding_disagreements"] == []
    assert payload["products_executed"] is False
