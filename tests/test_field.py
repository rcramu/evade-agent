from pathlib import Path

from evadeagent.kernel_lab.field import apply_field_slo, field_log_path, load_field_slo


def test_field_log_absent_without_env(monkeypatch) -> None:
    monkeypatch.delenv("EVADE_FIELD_LOG", raising=False)
    assert field_log_path() is None
    assert load_field_slo() is None
    payload = apply_field_slo({"schema": "evadeagent-eval-v5-lab"})
    assert payload["field_executed"] is False
    assert "field" not in payload


def test_field_log_import_when_file_exists(tmp_path: Path, monkeypatch) -> None:
    log = tmp_path / "field.json"
    log.write_text(
        '{"detect_p50_ms": 1.5, "capture_complete_rate": 0.9, "n_runs": 12}\n',
        encoding="utf-8",
    )
    monkeypatch.setenv("EVADE_FIELD_LOG", str(log))
    payload = apply_field_slo({"schema": "evadeagent-eval-v5-lab"})
    assert payload["field_executed"] is True
    assert payload["field"]["n_runs"] == 12
    assert payload["field"]["detect_p50_ms"] == 1.5
    assert "token" not in str(payload["field"])
