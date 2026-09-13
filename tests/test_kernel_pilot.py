from evadeagent.kernel_lab.document_assistant import EXPECTED, observations_for
from evadeagent.kernel_lab.dumps import write_bundled_dumps
from evadeagent.kernel_lab.pilot import run_pilot
from evadeagent.observe import Layer


def test_pilot_matches_expected_and_encodings() -> None:
    payload = run_pilot()
    assert payload["schema"] == "evadeagent-eval-v4-pilot"
    assert payload["products_executed"] is False
    assert payload["mismatches"] == []
    assert payload["encoding_disagreements"] == []
    for cell, expected in EXPECTED.items():
        row = payload["cells"][cell]
        assert row["shape"]["B4"] == expected["B4"]
        assert row["shape"]["B5"] == expected["B5"]
        assert row["shape"]["C5"] == expected["C5"]
        assert row["capture"]["complete"] is expected["capture_complete"]


def test_bundled_dump_roundtrip(tmp_path) -> None:
    dump = write_bundled_dumps(tmp_path / "bundled")
    assert (dump / "manifest.json").is_file()
    assert (dump / "L1" / "falco.jsonl").is_file()
    assert (dump / "A8" / "mcp.jsonl").is_file()
    payload = run_pilot(dump)
    assert payload["products_executed"] is False
    assert payload["dump_dir"] == str(dump)
    assert payload["mismatches"] == []
    assert payload["encoding_disagreements"] == []


def test_a8_shape_keeps_unseen_host_events() -> None:
    events = observations_for("A8", "document-assistant-A8")
    missing = [obs.name for obs in events if obs.layer is Layer.HOST and not obs.seen]
    assert "/lab/secrets/token" in missing
    assert "helper-worker" in missing
    assert "collector-cdn.example" in missing
