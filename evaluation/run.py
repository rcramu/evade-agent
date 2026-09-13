"""Seeded EVADE-AGENT campaign. Writes evaluation/results/approach_comparison.json."""

from __future__ import annotations

import argparse
import json
import math
import platform
import resource
import statistics
import sys
import time
from collections import defaultdict
from datetime import datetime, timezone
from pathlib import Path
from random import Random

_ROOT = Path(__file__).resolve().parents[1]
if str(_ROOT / "src") not in sys.path:
    sys.path.insert(0, str(_ROOT / "src"))

from evadeagent.contracts import AGENTS
from evadeagent.detectors import detect
from evadeagent.lab import build_trace, vary_trace
from evadeagent.manuscript_tables import alignment_walk, per_agent_c5
from evadeagent.models import Decision, DetectorMode, Label
from evadeagent.plans import PLAN_COUNT
from evadeagent.traces import (
    ADVERSARIAL_IDS,
    ATTACK_IDS,
    BENIGN_IDS,
    SCENARIOS,
    STATIC_IDS,
)

MODES = (
    DetectorMode.B1,
    DetectorMode.B2,
    DetectorMode.B3,
    DetectorMode.B4,
    DetectorMode.B5,
    DetectorMode.C1,
    DetectorMode.C2,
    DetectorMode.C3,
    DetectorMode.C4,
    DetectorMode.C5,
)
REPORT_MODES = ("B1", "B2", "B3", "B4", "B5", "C5")
SCHEMA = "evadeagent-eval-v3"
DEFAULT_REPEATS = 200
DEFAULT_SEED = 20260911


def _confusion(y_true_attack: list[bool], y_pred_block: list[bool]) -> dict[str, float | int]:
    tp = sum(1 for t, p in zip(y_true_attack, y_pred_block, strict=True) if t and p)
    fp = sum(1 for t, p in zip(y_true_attack, y_pred_block, strict=True) if (not t) and p)
    fn = sum(1 for t, p in zip(y_true_attack, y_pred_block, strict=True) if t and (not p))
    tn = sum(1 for t, p in zip(y_true_attack, y_pred_block, strict=True) if (not t) and (not p))
    precision = tp / (tp + fp) if (tp + fp) else 0.0
    recall = tp / (tp + fn) if (tp + fn) else 0.0
    f1 = 2 * precision * recall / (precision + recall) if (precision + recall) else 0.0
    fpr = fp / (fp + tn) if (fp + tn) else 0.0
    fnr = fn / (fn + tp) if (fn + tp) else 0.0
    return {
        "tp": tp,
        "fp": fp,
        "fn": fn,
        "tn": tn,
        "precision": precision,
        "recall": recall,
        "f1": f1,
        "fpr": fpr,
        "fnr": fnr,
    }


def _ers(fnr_b: float, fnr_a: float) -> float:
    denom = 1.0 - fnr_b
    if denom <= 0.0:
        return 0.0
    return max(0.0, min(1.0, 1.0 - (fnr_a - fnr_b) / denom))


def _latency_block(samples: list[float]) -> dict[str, float]:
    ordered = sorted(samples)
    if not ordered:
        return {}
    p95 = ordered[max(0, int(round(0.95 * (len(ordered) - 1))))]
    p99 = ordered[max(0, int(round(0.99 * (len(ordered) - 1))))]
    return {
        "mean_ms": statistics.fmean(ordered),
        "median_ms": statistics.median(ordered),
        "stdev_ms": statistics.pstdev(ordered) if len(ordered) > 1 else 0.0,
        "p95_ms": p95,
        "p99_ms": p99,
    }


def _log_comb(n: int, k: int) -> float:
    if k < 0 or k > n:
        return float("-inf")
    return math.lgamma(n + 1) - math.lgamma(k + 1) - math.lgamma(n - k + 1)


def fisher_one_sided(allowed_ctrl: int, denied_ctrl: int, allowed_tx: int, denied_tx: int) -> float:
    a, b, c, d = allowed_ctrl, denied_ctrl, allowed_tx, denied_tx
    n = a + b + c + d
    row1 = a + b
    row2 = c + d
    col1 = a + c
    lo = max(0, col1 - row1)
    log_den = _log_comb(n, col1)
    total = 0.0
    for k in range(lo, c + 1):
        total += math.exp(_log_comb(row2, k) + _log_comb(row1, col1 - k) - log_den)
    return min(1.0, total)


def run(repeats: int, seed: int) -> dict:
    started = datetime.now(timezone.utc).isoformat()
    cells: dict[str, dict[str, dict[str, int]]] = defaultdict(
        lambda: defaultdict(lambda: {"n": 0, "blocked": 0, "allowed": 0})
    )
    latencies: dict[str, list[float]] = {mode.value: [] for mode in MODES}
    true_attack: dict[str, list[bool]] = {mode.value: [] for mode in MODES}
    pred_block: dict[str, list[bool]] = {mode.value: [] for mode in MODES}
    static_true: dict[str, list[bool]] = {mode.value: [] for mode in MODES}
    static_pred: dict[str, list[bool]] = {mode.value: [] for mode in MODES}
    adv_true: dict[str, list[bool]] = {mode.value: [] for mode in MODES}
    adv_pred: dict[str, list[bool]] = {mode.value: [] for mode in MODES}
    semantic: list[float] = []
    unique_decisions: dict[tuple[str, str, int, str], Decision] = {}
    invariance_mismatches = 0
    variant_checks = 0

    for plan_id in range(PLAN_COUNT):
        for sid, label, kind in SCENARIOS:
            for agent in AGENTS:
                template = build_trace(agent, kind, plan_id=plan_id, scenario_id=sid)
                is_attack = label in {Label.MALICIOUS, Label.ADVERSARIAL, Label.CROSS_LAYER}
                if sid in ADVERSARIAL_IDS or sid == "A7":
                    benign = build_trace(agent, "legitimate", plan_id=plan_id)
                    semantic.append(template.semantic_similarity(benign))
                for mode in MODES:
                    decision = detect(mode, template)
                    unique_decisions[(sid, agent, plan_id, mode.value)] = decision
                    blocked = decision is Decision.BLOCK
                    cells[sid][mode.value]["n"] += 1
                    if blocked:
                        cells[sid][mode.value]["blocked"] += 1
                    else:
                        cells[sid][mode.value]["allowed"] += 1
                    true_attack[mode.value].append(is_attack)
                    pred_block[mode.value].append(blocked)
                    if sid in STATIC_IDS:
                        static_true[mode.value].append(True)
                        static_pred[mode.value].append(blocked)
                    if sid in ADVERSARIAL_IDS:
                        adv_true[mode.value].append(True)
                        adv_pred[mode.value].append(blocked)

    for repeat in range(repeats):
        rng = Random(seed + repeat)
        for sid, _label, kind in SCENARIOS:
            for agent in AGENTS:
                variant = vary_trace(build_trace(agent, kind, plan_id=0, scenario_id=sid), rng)
                for mode in MODES:
                    t0 = time.perf_counter()
                    decision = detect(mode, variant)
                    latencies[mode.value].append((time.perf_counter() - t0) * 1000.0)
                    variant_checks += 1
                    if decision is not unique_decisions[(sid, agent, 0, mode.value)]:
                        invariance_mismatches += 1

    summary = {}
    for mode in MODES:
        quality = _confusion(true_attack[mode.value], pred_block[mode.value])
        static_q = _confusion(static_true[mode.value], static_pred[mode.value])
        adv_q = _confusion(adv_true[mode.value], adv_pred[mode.value])
        ers = _ers(float(static_q["fnr"]), float(adv_q["fnr"]))
        s_i = statistics.fmean(semantic) if semantic else 1.0
        summary[mode.value] = {
            "authorization_quality": quality,
            "static_malicious": static_q,
            "adversarial": adv_q,
            "ers": ers,
            "semantic_preservation": s_i,
            "aers": ers * s_i,
            "latency": _latency_block(latencies[mode.value]),
        }

    def _allowed(mode: str, ids: tuple[str, ...]) -> tuple[int, int]:
        allowed = sum(cells[sid][mode]["allowed"] for sid in ids)
        n = sum(cells[sid][mode]["n"] for sid in ids)
        return allowed, n - allowed

    tests = {}
    for name, ids, ctrl, tx in (
        ("H1_B1_vs_C5_all_attacks", ATTACK_IDS, "B1", "C5"),
        ("H1_B2_vs_C5_all_attacks", ATTACK_IDS, "B2", "C5"),
        ("H1_B3_vs_C5_all_attacks", ATTACK_IDS, "B3", "C5"),
        ("H1_B4_vs_C5_all_attacks", ATTACK_IDS, "B4", "C5"),
        ("H1_B5_vs_C5_all_attacks", ATTACK_IDS, "B5", "C5"),
        ("H3_B3_vs_C5_adversarial", ADVERSARIAL_IDS, "B3", "C5"),
        ("H3_C4_vs_C5_A6", ("A6",), "C4", "C5"),
        ("H3_C4_vs_C5_A9", ("A9",), "C4", "C5"),
        ("H3_B5_vs_C5_A9", ("A9",), "B5", "C5"),
    ):
        a, b = _allowed(ctrl, ids)
        c, d = _allowed(tx, ids)
        p = fisher_one_sided(a, b, c, d)
        tests[name] = {
            "control": ctrl,
            "treatment": tx,
            "ids": list(ids),
            "allowed_control": a,
            "denied_control": b,
            "allowed_treatment": c,
            "denied_treatment": d,
            "p": 0.0 if p == 0.0 else p,
            "p_underflow": p == 0.0,
            "note": "Deterministic unique templates; not a sampling inference.",
        }

    residual = {
        "A8_event_loss": {
            "label": "unauthorized",
            "n": sum(cells["A8"][mode]["n"] for mode in REPORT_MODES) // len(REPORT_MODES),
            "blocked": {mode: cells["A8"][mode]["blocked"] for mode in (*REPORT_MODES, "C4")},
            "note": "Capture loss removes the unauthorized file, sink, helper, and credential flag.",
        },
        "L3_plan_token_collision": {
            "label": "benign",
            "n": sum(cells["L3"][mode]["n"] for mode in REPORT_MODES) // len(REPORT_MODES),
            "blocked": {mode: cells["L3"][mode]["blocked"] for mode in (*REPORT_MODES, "C4")},
            "note": "Legitimate runtime; plan text contains B2 surface tokens.",
        },
        "A6_ancestry_only": {
            "label": "unauthorized",
            "n": cells["A6"]["C5"]["n"],
            "blocked": {mode: cells["A6"][mode]["blocked"] for mode in (*REPORT_MODES, "C4")},
            "note": "B5 lineage encoding also blocks A6; C4 does not.",
        },
        "A9_temporal_only": {
            "label": "unauthorized",
            "n": cells["A9"]["C5"]["n"],
            "blocked": {mode: cells["A9"][mode]["blocked"] for mode in (*REPORT_MODES, "C4")},
            "note": "Allowlisted entities; inverted timestamps. Isolates C5 from B5 and C4.",
        },
    }

    usage = resource.getrusage(resource.RUSAGE_SELF)
    table4 = {}
    for mode in REPORT_MODES:
        table4[mode] = {
            "static_prevented": cells["M1"][mode]["blocked"] + cells["M2"][mode]["blocked"],
            "static_n": cells["M1"][mode]["n"] + cells["M2"][mode]["n"],
            "adversarial_prevented": sum(cells[sid][mode]["blocked"] for sid in ADVERSARIAL_IDS),
            "adversarial_n": sum(cells[sid][mode]["n"] for sid in ADVERSARIAL_IDS),
            "benign_blocked": sum(cells[sid][mode]["blocked"] for sid in BENIGN_IDS),
            "benign_n": sum(cells[sid][mode]["n"] for sid in BENIGN_IDS),
        }

    table5 = {mode: summary[mode]["authorization_quality"] for mode in REPORT_MODES}
    table6 = {
        mode: {
            "f1": summary[mode]["authorization_quality"]["f1"],
            "fnr_static": summary[mode]["static_malicious"]["fnr"],
            "fnr_adversarial": summary[mode]["adversarial"]["fnr"],
            "ers": summary[mode]["ers"],
            "aers": summary[mode]["aers"],
        }
        for mode in (m.value for m in MODES)
    }
    table7 = {mode: summary[mode]["latency"] for mode in REPORT_MODES}

    return {
        "schema": SCHEMA,
        "generated_utc": started,
        "repeats": repeats,
        "base_seed": seed,
        "unique_templates": len(SCENARIOS) * len(AGENTS) * PLAN_COUNT,
        "plan_count": PLAN_COUNT,
        "agents": list(AGENTS),
        "scenarios": {sid: {mode: dict(cells[sid][mode]) for mode in (m.value for m in MODES)} for sid, _, _ in SCENARIOS},
        "scenario_meta": {sid: {"label": label.value, "kind": kind} for sid, label, kind in SCENARIOS},
        "summary": summary,
        "tests": tests,
        "residual": residual,
        "invariance": {
            "variant_checks": variant_checks,
            "mismatches": invariance_mismatches,
            "note": "Detection tables use unique templates. Repeats measure latency and confirm decision invariance.",
        },
        "tables": {
            "table4": table4,
            "table5": table5,
            "table6": table6,
            "table7": table7,
            "alignment_walk": alignment_walk(),
            "per_agent_c5": per_agent_c5(),
        },
        "host": {
            "system": platform.system(),
            "release": platform.release(),
            "machine": platform.machine(),
            "python": platform.python_version(),
            "cpu_seconds": usage.ru_utime + usage.ru_stime,
            "peak_rss_mib": usage.ru_maxrss / (1024 * 1024 if platform.system() == "Darwin" else 1024),
        },
    }


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--repeats", type=int, default=DEFAULT_REPEATS)
    parser.add_argument("--seed", type=int, default=DEFAULT_SEED)
    args = parser.parse_args()
    payload = run(args.repeats, args.seed)
    out = _ROOT / "evaluation" / "results" / "approach_comparison.json"
    out.parent.mkdir(parents=True, exist_ok=True)
    out.write_text(json.dumps(payload, indent=2) + "\n", encoding="utf-8")
    print(f"wrote {out} schema={SCHEMA} templates={payload['unique_templates']} repeats={args.repeats}")
    print(f"invariance mismatches={payload['invariance']['mismatches']}")
    for mode in REPORT_MODES:
        q = payload["summary"][mode]["authorization_quality"]
        print(f"{mode} F1={q['f1']:.3f} FNR={q['fnr']:.3f} AERS={payload['summary'][mode]['aers']:.3f}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
