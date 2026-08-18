#!/usr/bin/env python3
"""Publication-style figures for the WISP paper.

Design goals vs. the earlier version:
  * serif typography (matches the Times-based IEEE body) instead of the default
    matplotlib sans-serif "notebook" look;
  * NO titles / descriptive captions baked into the image -- those belong in the
    LaTeX \\caption, and baking them in is the tell-tale of an auto-generated chart;
  * one restrained three-colour palette shared with the TikZ architecture figure;
  * numbers read from this project's own result JSON (not hard-coded).

Outputs vector PDF (for the paper) + 300-dpi PNG (for quick inspection). Set WISP_FIGURE_DIR to
redirect them, and WISP_WORKSPACE if the result JSONs are not in the parent of the repository.
"""
import os
import json
import math
from decimal import Decimal, ROUND_HALF_UP
import matplotlib
matplotlib.use("Agg")
import matplotlib.pyplot as plt

# Paths are derived, not hard-coded: this file lives in <repo>/eval/, so the analysis root is two
# levels up and the workspace that holds the result JSONs is one above that. It is the single copy
# of this script; the paper build invokes it from here rather than keeping a second one beside the
# LaTeX, which is how a regenerated figure once sat unused while the paper kept a stale one.
_HERE = os.path.dirname(os.path.abspath(__file__))
REPO = os.path.dirname(_HERE)
ROOT = os.environ.get("WISP_WORKSPACE", os.path.dirname(REPO))
OUT = os.environ.get("WISP_FIGURE_DIR", os.path.join(ROOT, "2026-07-07", "figures"))
os.makedirs(OUT, exist_ok=True)

# palette shared with the architecture diagram
C_WISP, C_SG, C_PP = "#1B6CA8", "#E08E0B", "#9AA0A6"
C_MISS, C_POOL = "#B23A48", "#B23A48"
# tint of C_MISS. The palette is shared across figures, so a tool colour never
# stands for anything but that tool: blue is always WISP, red is always a miss.
C_MISS_LT = "#D9949C"

plt.rcParams.update({
    "font.family": "serif",
    "font.serif": ["Nimbus Roman", "Times New Roman", "DejaVu Serif"],
    "mathtext.fontset": "stix",
    "font.size": 8.5,
    "axes.linewidth": 0.7,
    "axes.edgecolor": "#333333",
    "axes.spines.top": False,
    "axes.spines.right": False,
    "xtick.major.width": 0.7,
    "ytick.major.width": 0.7,
    "xtick.color": "#333333",
    "ytick.color": "#333333",
    "figure.dpi": 150,
})



def r3(v):
    """round-half-up to 3 decimals so figures agree with the tables."""
    return str(Decimal(str(v)).quantize(Decimal("0.001"), rounding=ROUND_HALF_UP))


def load(path, default=None):
    try:
        return json.load(open(path))
    except Exception:
        return default


def _assert_nothing_clipped(fig, name):
    """Refuse to write a figure whose axes cut off data they are drawing.

    Figure 3(b) shipped with `set_ylim(0, 0.70)` while WISP reached 0.730 at K=5 and 0.740 at K=10,
    so the panel silently disagreed with Table 6 on the facing page. A constant limit does not move
    when a re-measurement does, and no reader of the code can see the collision. Every figure goes
    through save(), so the check goes here rather than into each panel."""
    bad = []
    for ax in fig.get_axes():
        (y0, y1), (x0, x1) = ax.get_ylim(), ax.get_xlim()
        for ln in ax.lines:
            xs, ys = ln.get_xdata(), ln.get_ydata()
            for x, y in zip(xs, ys):
                try:
                    x, y = float(x), float(y)
                except (TypeError, ValueError):
                    continue
                if y != y or x != x:          # NaN placeholders are legitimate
                    continue
                if not (min(y0, y1) - 1e-9 <= y <= max(y0, y1) + 1e-9):
                    bad.append(f"{ax.get_ylabel() or 'y'}: point {y:g} outside [{y0:g}, {y1:g}]")
                if not (min(x0, x1) - 1e-9 <= x <= max(x0, x1) + 1e-9):
                    bad.append(f"{ax.get_xlabel() or 'x'}: point {x:g} outside [{x0:g}, {x1:g}]")
        for p in ax.patches:                  # bars
            try:
                top = p.get_y() + p.get_height()
            except AttributeError:
                continue
            if not (min(y0, y1) - 1e-9 <= top <= max(y0, y1) + 1e-9):
                bad.append(f"{ax.get_ylabel() or 'y'}: bar top {top:g} outside [{y0:g}, {y1:g}]")
    if bad:
        raise SystemExit(f"FIGURE {name} CLIPS ITS OWN DATA, refusing to write it:\n  "
                         + "\n  ".join(sorted(set(bad))))


def save(fig, name):
    _assert_nothing_clipped(fig, name)
    for ext in ("pdf", "png"):
        fig.savefig(os.path.join(OUT, f"{name}.{ext}"), bbox_inches="tight", dpi=300)
    plt.close(fig)
    print("wrote", name)


def _headroom(vmax, step=0.10):
    """Smallest multiple of `step` that clears the data, with a little air above it.

    Axis limits written as constants are a silent way to lose a data point: a cap of 0.70 clipped
    WISP's 0.730 and 0.740 off the top of Figure 3(b) the moment the engine moved to v1.3, and the
    panel then disagreed with Table 6 on the facing page. Deriving the limit means a value that grows
    past the frame widens the frame instead of vanishing."""
    return max(step, math.ceil((vmax + 1e-9) / step) * step)


def panel_tag(ax, s):
    ax.text(0.02, 1.02, s, transform=ax.transAxes, fontsize=9,
            fontweight="bold", va="bottom", ha="left")


# ---- Figure 1: localization head-to-head (figure*, full text width) ---------
C_WT = "#3E8E5A"


def fig_main():
    fig, (axL, axR) = plt.subplots(1, 2, figsize=(7.1, 2.75),
                                   gridspec_kw={"width_ratios": [1.05, 1.0]})
    ks = [1, 3, 5, 10]
    # This panel pair and tab:localize must be the same run. They were not: the figure read the
    # 2026-07-14/17 files under final/results/ while the table read the corrected contract run,
    # so the drawn curve said 0.51 where the table said 0.440 and Progpilot was drawn flat at
    # zero, which was the pre-fix exit-code bug rather than the tool. Both now read the one file
    # that also drives every Loc* macro.
    pf = load(os.path.join(ROOT, "revision-cns-v2/out/PAIRED_FAMILY_V3.json"), {})
    pe = pf.get("point_estimates", {})

    def at(tool, metric):
        """{K: rate} for one tool, keyed as the plotting code expects."""
        d = pe.get(tool)
        if not d:
            raise SystemExit(f"PAIRED_FAMILY_V3.json has no point_estimates.{tool}")
        out = {}
        for k in ks:
            key = f"{metric}@{k}"
            if key not in d:
                raise SystemExit(f"PAIRED_FAMILY_V3.json missing point_estimates.{tool}.{key}")
            out[str(k)] = d[key]
        return out

    series = [("WISP", C_WISP, at("wisp", "cf")),
              ("Semgrep", C_SG, at("semgrep", "cf")),
              ("Progpilot", C_PP, at("progpilot", "cf")),
              ("wp-taint-scan", C_WT, at("wpt", "cf"))]
    w = 0.19
    offs = [-1.5 * w, -0.5 * w, 0.5 * w, 1.5 * w]
    for (tool, c, values), off in zip(series, offs):
        vals = [values[str(k)] for k in ks]
        xpos = [i + off for i in range(len(ks))]
        axL.bar(xpos, vals, w, color=c, label=tool,
                edgecolor="white", linewidth=0.4)
    axL.set_xticks(range(len(ks)))
    axL.set_xticklabels([f"$K$={k}" for k in ks])
    axL.set_ylabel("Class-and-file success@$K$")
    axL.set_ylim(0, 0.40)
    axL.yaxis.grid(True, color="#e6e6e6", lw=0.6)
    axL.set_axisbelow(True)
    axL.legend(frameon=False, fontsize=6.2, ncol=2, loc="upper left",
               handlelength=1.1, borderpad=0.2, columnspacing=0.9,
               handletextpad=0.4)
    panel_tag(axL, "(a)")

    patch_series = [("WISP", C_WISP, at("wisp", "pf")),
                    ("Semgrep", C_SG, at("semgrep", "pf")),
                    ("Progpilot", C_PP, at("progpilot", "pf")),
                    ("wp-taint-scan", C_WT, at("wpt", "pf"))]
    patch_max = 0.0
    for tool, c, values in patch_series:
        vals = [values[str(k)] for k in ks]
        patch_max = max(patch_max, max(vals))
        axR.plot(ks, vals, "-o", color=c, lw=1.4, ms=4, label=tool)
    axR.set_xticks(ks)
    axR.set_xlabel(r"$K$ (top-$K$ of each tool's ranked shortlist)")
    axR.set_ylabel(r"Patch-file success@$K$")
    # Derived from the data, never a constant. A hardcoded 0.70 clipped WISP's 0.730 at K=5 and
    # 0.740 at K=10 straight off the top of the panel, a figure that disagreed with Table 6 on the
    # same page. The cap moved when the engine went to v1.3 and nothing recomputed the axis.
    axR.set_ylim(0, _headroom(patch_max))
    axR.yaxis.grid(True, color="#e6e6e6", lw=0.6)
    axR.set_axisbelow(True)
    axR.legend(frameon=False, fontsize=6.2, loc="lower right", handlelength=1.6,
               labelspacing=0.3)
    panel_tag(axR, "(b)")
    fig.subplots_adjust(wspace=0.32)
    save(fig, "fig1_head_to_head")


# ---- Figure 2: per-class recall (single column) -----------------------------
def fig_perclass():
    # All ten classes for WISP on the full 1108-record corpus, on the contract failure policy, so
    # the bars and the sentence printed above them in the supplement are the same quantity. They
    # were not: the figure read a 2026-07-13 scan with non-convergence ignored and drew access
    # control at 0.90 where the paragraph beside it said 0.66. Rates and intervals now both come
    # from the join in eval/auth_split_v3.py, which is what generates that paragraph.
    classes = ["csrf", "deserial", "auth", "rce", "ssrf", "lfi",
               "upload", "xss", "sqli", "other"]
    pc = load(os.path.join(
        ROOT, "revision-cns-v2/out/PERCLASS_CONTRACT_V3.json"))["per_class"]
    missing = [c for c in classes if c not in pc]
    if missing:
        raise SystemExit(f"PERCLASS_CONTRACT_V3.json has no per_class entry for {missing}")
    wisp = [pc[c]["rate"] for c in classes]
    # plugin-clustered 95% bootstrap CIs per class, so a class with 15 records is
    # not read with the confidence of one with 355
    lo = [wisp[i] - pc[c]["ci95"][0] for i, c in enumerate(classes)]
    hi = [pc[c]["ci95"][1] - wisp[i] for i, c in enumerate(classes)]
    err = [[max(0, v) for v in lo], [max(0, v) for v in hi]]
    y = range(len(classes))
    fig, ax = plt.subplots(figsize=(3.45, 4.1))
    ax.barh(list(y), wisp, 0.48, label="WISP", color=C_WISP,
            edgecolor="white", linewidth=0.3,
            xerr=err, error_kw={"ecolor": "#333333", "elinewidth": 0.8, "capsize": 2})
    ax.set_yticks(list(y))
    ax.set_yticklabels(classes)
    ax.invert_yaxis()
    ax.set_xlabel("WISP class emission, full corpus (1108 records)\n"
                  "(contract failure policy: non-convergence counts as a miss)",
                  fontsize=7.5)
    ax.set_xlim(0, 1.10)
    ax.xaxis.grid(True, color="#e6e6e6", lw=0.6)
    ax.set_axisbelow(True)
    # shade the WP-specific block (csrf/deserial/auth); label it in the right
    # gutter, rotated, so it never touches the deserial bar (0.981)
    ax.axhspan(-0.5, 2.5, color=C_WISP, alpha=0.06, zorder=0)
    ax.text(1.045, 1.0, "WordPress-specific\nblock", fontsize=6.2,
            va="center", ha="center", color=C_WISP, rotation=90,
            multialignment="center")
    ax.legend(frameon=False, fontsize=6.6, loc="lower right",
              bbox_to_anchor=(1.0, 0.30), handlelength=1.1)
    save(fig, "fig2_perclass_recall")


# ---- Figure 3: miss anatomy (figure*, full text width) ----------------------
def fig_miss():
    # Every height here used to be a constant typed into this function, where no check in the
    # repository could see it. They were right, which was luck rather than process. They now come
    # from the same join that generates the per-class rates.
    ma = load(os.path.join(ROOT, "revision-cns-v2/out/MISS_ANALYSIS_V3.json"))
    mtot = ma["misses"]["total"]
    wrong = ma["misses"]["wrong_class_engine_active"]
    blind = ma["misses"]["blind_zero_findings"]
    fig, (axL, axR) = plt.subplots(1, 2, figsize=(7.1, 2.5),
                                   gridspec_kw={"width_ratios": [0.8, 1.1]})
    axL.bar(["wrong-class\n(engine active)", "blind\n(0 findings)"],
            [wrong, blind], color=[C_MISS_LT, C_MISS], width=0.58,
            edgecolor="white", linewidth=0.4)
    for xi, v in ((0, wrong), (1, blind)):
        axL.text(xi, v + 6, f"{v} ({100 * v / mtot:.1f}%)", ha="center", va="bottom", fontsize=7.5)
    axL.set_ylabel(f"# of the {mtot} full-corpus misses")
    axL.set_ylim(0, 270)
    axL.yaxis.grid(True, color="#e6e6e6", lw=0.6)
    axL.set_axisbelow(True)
    panel_tag(axL, "(a)")

    bars = ["All\nclasses", "In-scope\n(no 'other')", "WP-specific\n(auth/csrf/des.)",
            "Generic\ntaint"]
    # This panel decomposes WHERE the class was emitted, so it is on the same basis as the
    # supplement's miss analysis: non-convergence ignored. It is deliberately NOT the headline
    # figure, which applies the contract failure policy and is lower; the axis label says so,
    # because a bar chart with an unqualified "class emission" axis is exactly how a reader
    # ends up quoting the wrong number.
    vals = [ma["emission"][k]["emission"] for k in
            ("all_classes", "in_scope_no_other", "wordpress_specific", "generic_taint")]
    # every bar is WISP class emission on a different subset, so they share one colour. The
    # subset is carried by the tick label, not by hue.
    b = axR.bar(bars, vals, color=C_WISP, width=0.6, edgecolor="white", linewidth=0.4)
    for r in b:
        axR.text(r.get_x() + r.get_width() / 2, r.get_height() + 0.015,
                 f"{r.get_height():.3f}", ha="center", va="bottom", fontsize=7.5)
    axR.set_ylabel("WISP class emission\n(non-convergence ignored)", fontsize=8)
    axR.set_ylim(0, 1.0)
    axR.tick_params(axis="x", labelsize=7)
    axR.yaxis.grid(True, color="#e6e6e6", lw=0.6)
    axR.set_axisbelow(True)
    panel_tag(axR, "(b)")
    fig.subplots_adjust(wspace=0.28)
    save(fig, "fig3_miss_analysis")


# ---- Figure 4: exploitability-ranked precision@K (single column) ------------
def fig_precision_at_k():
    ks = [1, 3, 5, 10]
    d = load(os.path.join(ROOT, "final/results/granularity_gda_off_after_emission_final.json"), {})
    nes = [d.get("summary", {}).get("at_k", {}).get("patch_file", {}).get(str(k), 0.0)
           for k in ks]
    fig, ax = plt.subplots(figsize=(3.45, 3.0))
    ax.plot(ks, nes, "-o", color=C_WISP, lw=1.7, ms=4.5)
    for k, v in zip(ks, nes):
        ax.annotate(r3(v), (k, v), textcoords="offset points",
                    xytext=(0, 6), ha="center", fontsize=7)
    ax.set_xticks(ks)
    ax.set_xlabel(r"$K$ (top-$K$ of the ranked shortlist)")
    ax.set_ylabel(r"Patch-file success@$K$")
    ax.set_ylim(0.40, 0.80)
    ax.yaxis.grid(True, color="#e6e6e6", lw=0.6)
    ax.set_axisbelow(True)
    # single series, so the axis label and the caption identify it. A one-entry
    # legend would only repeat them.
    save(fig, "fig4_precision_at_k")


# ---- Figure 5: token-free scalability on real apps (single column) ----------
def fig_scalability():
    from eval.scalability_fit import load_apps, fit
    a4 = load_apps()
    rows = sorted(a4["results"], key=lambda r: r["php_own_code"])
    xs = [r["php_own_code"] for r in rows]
    ys = [r["scan_seconds"] for r in rows]
    fig, ax = plt.subplots(figsize=(3.45, 2.85))
    ax.scatter(xs, ys, s=22, color=C_WISP, zorder=3, edgecolor="white", linewidth=0.4)
    # Least-squares power-law fit in log-log space (scan_s = a * files^b) with R^2, so the
    # near-linear scaling is a stated diagnostic and not an eyeballed claim. The fit lives in
    # eval/scalability_fit.py because the supplement quotes the same two numbers in prose, and
    # a legend and a sentence computing the same thing twice is how they come apart.
    import math
    f = fit(a4)
    b, a0, r2 = f["slope"], f["intercept"], f["r2"]
    fx = [min(xs), max(xs)]
    ax.plot(fx, [10 ** (a0 + b * math.log10(v)) for v in fx], "--", color=C_MISS,
            lw=1.1, zorder=2, label=f"fit: slope {b:.2f}, $R^2$={r2:.2f}")
    ax.legend(frameon=False, fontsize=6.6, loc="lower right", handlelength=1.6)
    # a sparse, non-overlapping set of anchor apps with hand-tuned label offsets
    notable = {
        "DVWA-1.9":      (-4, 5, "right"),
        "phpbb":         (-4, -9, "right"),
        "WordPress-6.6": (-6, 6, "right"),
        "dolibarr":      (4, 4, "left"),
        "shopware":      (5, -2, "left"),
    }
    for r in rows:
        if r["app"] in notable:
            dx, dy, ha = notable[r["app"]]
            ax.annotate(r["app"], (r["php_own_code"], r["scan_seconds"]),
                        fontsize=6.4, xytext=(dx, dy), textcoords="offset points",
                        color="#444", ha=ha)
    ax.set_xlabel("Own-code PHP files (log scale)")
    ax.set_ylabel("Scan seconds (log scale)")
    ax.set_xscale("log")
    ax.set_yscale("log")
    ax.grid(True, which="both", color="#eeeeee", lw=0.5)
    ax.set_axisbelow(True)
    tot_f = a4.get("total_own_php")
    tot_s = a4.get("total_scan_seconds")
    ax.text(0.03, 0.97, f"24 apps, {tot_f:,} files\nin {tot_s:,.0f} s, single engine",
            transform=ax.transAxes, fontsize=6.8, va="top", ha="left", color="#444")
    save(fig, "fig5_scalability")


if __name__ == "__main__":
    fig_main()
    fig_perclass()
    fig_miss()
    fig_precision_at_k()
    fig_scalability()
    print("all figures ->", OUT)
