"""Render manuscript Figures 11–16 from evaluation JSON. Not generative AI.

Figures 11–14 use approach_comparison.json (Section 8).
Figures 15–16 use kernel_pilot_agents.json (Appendix D; not Section 8).
"""

from __future__ import annotations

import json
from pathlib import Path
import shutil

import matplotlib.pyplot as plt

ROOT = Path(__file__).resolve().parents[1]
SOURCE = ROOT / "evaluation" / "results" / "approach_comparison.json"
AGENTS_SOURCE = ROOT / "evaluation" / "results" / "kernel_pilot_agents.json"
OUT = ROOT / "figures"
PILOT_CELLS = ("L1", "M1", "A6", "A8", "A9")
PILOT_MODES = ("B4", "B5", "C5")
AGENT_SHORT = {
    "document-assistant": "document",
    "coding-agent": "coding",
    "devops-agent": "devops",
    "database-agent": "database",
    "knowledge-agent": "knowledge",
    "ticket-agent": "ticket",
    "mail-agent": "mail",
}
MODES = ("B1", "B2", "B3", "B4", "B5", "C5")
LABELS = {
    "B1": "B1 policy",
    "B2": "B2 telemetry",
    "B3": "B3 signatures",
    "B4": "B4 host rules",
    "B5": "B5 lineage",
    "C5": "C5 EVADE-AGENT",
}
COLORS = {
    "B1": "#9aa0a6",
    "B2": "#5f7c8a",
    "B3": "#3d6b8a",
    "B4": "#2a5874",
    "B5": "#1f5a73",
    "C5": "#1b4d6e",
}
ABLATION = ("C1", "C2", "C3", "C4", "C5")
ABLATION_LABELS = {
    "C1": "C1 intent",
    "C2": "C2 +signatures",
    "C3": "C3 +graph",
    "C4": "C4 +contract",
    "C5": "C5 +invariant",
}


def figure6(data: dict) -> None:
    groups = [
        ("Static M1–M2", ("M1", "M2")),
        ("Adversarial A1–A9+N", ("A1", "A2", "A3", "A4", "A5", "A6", "A7", "A8", "A9", "N1", "N2", "N3", "N4", "N5", "N6", "N7", "N8")),
        ("Benign L1–L3 (1−FPR)", ("L1", "L2", "L3")),
    ]
    x = range(len(groups))
    width = 0.12
    fig, ax = plt.subplots(figsize=(9.2, 4.3))
    for i, mode in enumerate(MODES):
        xs = [xi + (i - 2.5) * width for xi in x]
        ys = []
        for name, ids in groups:
            blocked = sum(data["scenarios"][sid][mode]["blocked"] for sid in ids)
            n = sum(data["scenarios"][sid][mode]["n"] for sid in ids)
            rate = blocked / n if n else 0.0
            if name.startswith("Benign"):
                rate = 1.0 - rate
            ys.append(rate)
        ax.bar(xs, ys, width=width, label=LABELS[mode], color=COLORS[mode])
    ax.set_xticks(list(x))
    ax.set_xticklabels([name for name, _ in groups])
    ax.set_ylim(0, 1.05)
    ax.set_ylabel("Rate")
    templates = data.get("unique_templates", 616)
    ax.set_title(f"Figure 11. Detection and benign acceptance ({templates} unique templates)")
    ax.legend(frameon=False, ncol=3)
    fig.tight_layout()
    fig.savefig(OUT / "figure-11-detection.png", dpi=200)
    plt.close(fig)


def figure7(data: dict) -> None:
    fig, ax = plt.subplots(figsize=(7.6, 4.3))
    xs = range(len(ABLATION))
    aers = [data["summary"][mode]["aers"] for mode in ABLATION]
    f1 = [data["summary"][mode]["authorization_quality"]["f1"] for mode in ABLATION]
    ax.plot(xs, f1, marker="o", color="#5f7c8a", label="$F_1$")
    ax.plot(xs, aers, marker="s", color="#1b4d6e", label="AERS")
    ax.set_xticks(list(xs))
    ax.set_xticklabels([ABLATION_LABELS[m] for m in ABLATION], rotation=15)
    ax.set_ylim(0, 1.05)
    ax.set_ylabel("Score")
    ax.set_title("Figure 12. Ablation of EVADE-AGENT components")
    ax.legend(frameon=False)
    fig.tight_layout()
    fig.savefig(OUT / "figure-12-ablation.png", dpi=200)
    plt.close(fig)


def figure8(data: dict) -> None:
    lat = {mode: data["summary"][mode]["latency"] for mode in MODES}
    metrics = [("median", "median_ms"), ("p95", "p95_ms"), ("p99", "p99_ms")]
    x = range(len(metrics))
    width = 0.12
    fig, ax = plt.subplots(figsize=(8.4, 4.3))
    for i, mode in enumerate(MODES):
        xs = [xi + (i - 2.5) * width for xi in x]
        ys = [lat[mode][key] for _, key in metrics]
        ax.bar(xs, ys, width=width, label=LABELS[mode], color=COLORS[mode])
    ax.set_xticks(list(x))
    ax.set_xticklabels([name for name, _ in metrics])
    ax.set_ylabel("detect() latency (ms)")
    ax.set_title("Figure 14. In-process detection latency (seeded variants)")
    ax.legend(frameon=False, ncol=3)
    fig.tight_layout()
    fig.savefig(OUT / "figure-14-latency.png", dpi=200)
    plt.close(fig)


def figure13(data: dict) -> None:
    """Residual heatmap of Table A.1. Blocked / n per scenario and detector."""
    modes = ("B1", "B2", "B3", "B4", "B5", "C3", "C4", "C5")
    scenarios = list(data["scenarios"])
    grid = []
    for sid in scenarios:
        row = []
        for mode in modes:
            cell = data["scenarios"][sid][mode]
            row.append(cell["blocked"] / cell["n"] if cell["n"] else 0.0)
        grid.append(row)
    fig, ax = plt.subplots(figsize=(8.8, 7.2))
    im = ax.imshow(grid, cmap="Blues", vmin=0, vmax=1, aspect="auto")
    ax.set_xticks(range(len(modes)))
    ax.set_xticklabels(modes)
    ax.set_yticks(range(len(scenarios)))
    ax.set_yticklabels(scenarios)
    ax.set_title("Figure 13. Residual heatmap (blocked / n unique templates)")
    fig.colorbar(im, ax=ax, fraction=0.03, pad=0.02, label="Block rate")
    fig.tight_layout()
    dest = OUT / "figure-13-residual.png"
    fig.savefig(dest, dpi=200)
    plt.close(fig)


def figure15(agents: dict) -> None:
    """Appendix D. Three-agent B4/B5/C5 decisions. Not Section 8."""
    labels = []
    grid = []
    for agent, row in agents.items():
        short = AGENT_SHORT.get(agent, agent)
        for cell in PILOT_CELLS:
            labels.append(f"{short} {cell}")
            shape = ((row.get("cells") or {}).get(cell) or {}).get("shape") or {}
            grid.append([1.0 if shape.get(mode) == "BLOCK" else 0.0 for mode in PILOT_MODES])
    fig, ax = plt.subplots(figsize=(6.4, 11.2))
    im = ax.imshow(grid, cmap="Blues", vmin=0, vmax=1, aspect="auto")
    ax.set_xticks(range(len(PILOT_MODES)))
    ax.set_xticklabels(PILOT_MODES)
    ax.set_yticks(range(len(labels)))
    ax.set_yticklabels(labels)
    ax.set_title("Figure 15. Five-cell decisions after product join (three agents)")
    cbar = fig.colorbar(im, ax=ax, fraction=0.046, pad=0.08, ticks=[0, 1])
    cbar.ax.set_yticklabels(["ALLOW", "BLOCK"])
    cbar.set_label("Decision")
    fig.tight_layout()
    fig.savefig(OUT / "figure-15-kernel-decisions.png", dpi=200)
    plt.close(fig)


def figure16(agents: dict) -> None:
    """Appendix D. Capture completeness. Not Section 8."""
    labels = []
    emitted = []
    seen = []
    for agent, row in agents.items():
        short = AGENT_SHORT.get(agent, agent)
        for cell in PILOT_CELLS:
            cap = ((row.get("cells") or {}).get(cell) or {}).get("capture") or {}
            labels.append(f"{short} {cell}")
            emitted.append(int(cap.get("emitted") or 0))
            seen.append(int(cap.get("seen") or 0))
    y = range(len(labels))
    fig, ax = plt.subplots(figsize=(7.6, 11.2))
    ax.barh([yi + 0.16 for yi in y], emitted, height=0.3, color="#9aa0a6", label="emitted")
    ax.barh([yi - 0.16 for yi in y], seen, height=0.3, color="#1b4d6e", label="seen")
    ax.set_yticks(list(y))
    ax.set_yticklabels(labels)
    ax.invert_yaxis()
    ax.set_xlabel("Observations")
    ax.set_title("Figure 16. Capture completeness after product join")
    ax.legend(frameon=False)
    fig.tight_layout()
    fig.savefig(OUT / "figure-16-kernel-capture.png", dpi=200)
    plt.close(fig)


def _copy_pack() -> None:
    pack = ROOT.parent / "jss-submission" / "figures"
    if not pack.is_dir():
        return
    for name in (
        "figure-11-detection.png",
        "figure-12-ablation.png",
        "figure-13-residual.png",
        "figure-14-latency.png",
        "figure-15-kernel-decisions.png",
        "figure-16-kernel-capture.png",
    ):
        src = OUT / name
        if src.is_file():
            shutil.copy2(src, pack / name)


def main() -> int:
    data = json.loads(SOURCE.read_text(encoding="utf-8"))
    OUT.mkdir(parents=True, exist_ok=True)
    figure6(data)
    figure7(data)
    figure8(data)
    figure13(data)
    if AGENTS_SOURCE.is_file():
        agents = json.loads(AGENTS_SOURCE.read_text(encoding="utf-8")).get("agents") or {}
        if agents:
            figure15(agents)
            figure16(agents)
    _copy_pack()
    for name in (
        "figure-11-detection.png",
        "figure-12-ablation.png",
        "figure-13-residual.png",
        "figure-14-latency.png",
        "figure-15-kernel-decisions.png",
        "figure-16-kernel-capture.png",
    ):
        path = OUT / name
        if path.is_file():
            print(f"wrote {path}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
