"""Field SLO import. Never fabricates a production log.

EVADE_FIELD_LOG must point at an existing JSON export that is not committed.
The file may be a single object or JSONL of objects. No secrets are read as
credentials; only operational counters are copied.
"""

from __future__ import annotations

import json
import os
from pathlib import Path
from typing import Any

_ALLOWED = (
    "detect_p50_ms",
    "detect_p95_ms",
    "capture_complete_rate",
    "mismatch_rate",
    "window",
    "platform",
    "n_runs",
    "note",
)


def field_log_path() -> Path | None:
    raw = os.environ.get("EVADE_FIELD_LOG", "").strip()
    if not raw:
        return None
    path = Path(raw)
    return path if path.is_file() else None


def load_field_slo(path: Path | None = None) -> dict[str, Any] | None:
    """Return a field SLO object or None. Does not write files."""
    src = path if path is not None else field_log_path()
    if src is None:
        return None
    text = src.read_text(encoding="utf-8").strip()
    if not text:
        return None
    if text[0] == "{":
        data = json.loads(text)
    else:
        rows = [json.loads(line) for line in text.splitlines() if line.strip()]
        data = rows[-1] if rows else {}
    if not isinstance(data, dict):
        return None
    inner = data.get("slo") if isinstance(data.get("slo"), dict) else data
    out = {key: inner[key] for key in _ALLOWED if key in inner}
    out["source"] = str(src)
    return out


def apply_field_slo(payload: dict[str, Any], path: Path | None = None) -> dict[str, Any]:
    """Set field_executed only when a production export exists."""
    slo = load_field_slo(path)
    if slo is None:
        payload["field_executed"] = False
        return payload
    payload["field_executed"] = True
    payload["source"] = slo.get("source")
    payload["field"] = slo
    payload["note"] = (
        "Field SLO imported from EVADE_FIELD_LOG. "
        "This is not a laboratory encoding result and is not Section 8."
    )
    return payload
