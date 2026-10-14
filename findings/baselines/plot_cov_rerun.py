#!/usr/bin/env python3
"""Coverage-over-time small-multiples for the recovered re-run repos (5x budget).
Reads cov_rerun.json {label:[[t,cov_edges],...]}, marks the original 60s budget."""
import json, os
import matplotlib
matplotlib.use("Agg")
import matplotlib.pyplot as plt

HERE = os.path.dirname(os.path.abspath(__file__))
data = json.load(open(os.path.join(HERE, "cov_rerun.json")))

# display name + recovery driver (from rerun_results_20260922.md)
META = {
    "memorymesh":      ("CheMiguel23/memorymesh",       "reflected-xss  (+14)"),
    "mcpfirebird":     ("PuroDelphi/mcpFirebird",        "reflected-xss  (+2)"),
    "mcpdocserver":    ("ruan11223344/McpDocServer",     "reflected-xss  (+1)"),
    "mcpollinations":  ("pinkpixel-dev/MCPollinations",  "reflected-xss  (+1)"),
    "fetcher-mcp":     ("jae-jae/fetcher-mcp",           "resource-exhaustion (+1)"),
    "agentic-tools":   ("pimzino/agentic-tools-mcp",     "path-traversal  (+5)"),
    "excalidraw":      ("i-tozer/excalidraw-mcp",        "temp-file leak  (+1)"),
    "meta-mcp-server": ("dmontgomery40/meta-mcp-server", "path-traversal  (+1)"),
}
# order: biggest climbers first
order = ["memorymesh", "fetcher-mcp", "mcpdocserver", "mcpollinations",
         "mcpfirebird", "agentic-tools", "excalidraw", "meta-mcp-server"]
order = [k for k in order if k in data]

ORIG_BUDGET = 60.0
plt.rcParams.update({"font.size": 9, "axes.grid": True,
                     "grid.alpha": 0.3, "axes.spines.top": False,
                     "axes.spines.right": False})
fig, axes = plt.subplots(2, 4, figsize=(15, 6.6))
axes = axes.ravel()

for i, key in enumerate(order):
    ax = axes[i]
    pts = sorted(data[key])
    xs = [p[0] for p in pts]
    ys = [p[1] for p in pts]
    disp, driver = META.get(key, (key, ""))

    # coverage at ~60s vs final -> quantify the post-budget gain
    cov60 = next((y for x, y in zip(xs, ys) if x >= ORIG_BUDGET), ys[-1])
    covF = ys[-1]
    gain = covF - cov60
    pct = (gain / cov60 * 100) if cov60 else 0

    ax.plot(xs, ys, color="#1f6feb", lw=1.8)
    ax.axvspan(ORIG_BUDGET, max(xs), color="#2da44e", alpha=0.07)
    ax.axvline(ORIG_BUDGET, color="#cf222e", ls="--", lw=1.1)
    ax.scatter([xs[-1]], [covF], color="#1f6feb", s=18, zorder=5)

    ax.set_title(disp, fontsize=9, fontweight="bold", pad=9)
    ax.text(0.5, 1.005, driver, transform=ax.transAxes, ha="center",
            va="bottom", fontsize=7.5, color="#6e7781")
    ax.set_xlim(0, max(310, max(xs)))
    ymin = min(ys); ymax = max(ys)
    pad = max(2, (ymax - ymin) * 0.15)
    ax.set_ylim(ymin - pad, ymax + pad)
    # annotate post-60s gain
    ax.annotate(f"+{gain} edges after 60s\n({cov60}→{covF}, +{pct:.0f}%)",
                xy=(xs[-1], covF), xytext=(0.96, 0.08),
                textcoords="axes fraction", ha="right", va="bottom",
                fontsize=7.3, color="#24292f",
                bbox=dict(boxstyle="round,pad=0.3", fc="#fff8c5", ec="#d4a72c", lw=0.6))
    if i % 4 == 0:
        ax.set_ylabel("coverage edges")
    if i >= 4:
        ax.set_xlabel("fuzz time (s)")

# one shared legend line for the 60s marker
from matplotlib.lines import Line2D
from matplotlib.patches import Patch
leg = [Line2D([0], [0], color="#cf222e", ls="--", lw=1.1, label="original 60 s budget"),
       Patch(fc="#2da44e", alpha=0.12, label="extended budget region (60–300 s)")]
fig.legend(handles=leg, loc="upper center", ncol=2, frameon=False,
           bbox_to_anchor=(0.5, 1.005), fontsize=9)
fig.suptitle("ToFu coverage keeps growing past the 60 s budget on recovered re-run repos "
             "(5× budget = 300 s, cache-accelerated, 0 extra LLM calls)",
             fontsize=11, fontweight="bold", y=1.05)
fig.tight_layout(rect=[0, 0, 1, 0.98])
out = os.path.join(HERE, "coverage_rerun_20260922.png")
fig.savefig(out, dpi=150, bbox_inches="tight", facecolor="white")
print("wrote", out)
