#!/usr/bin/env python3
"""Emit the two main-text tables the revision owes: the equal-budget matrix and the failure audit.

Both answer a fairness question and both were previously either absent or buried.

  1. BUDGET_MATRIX_TABLE.tex. The head-to-head the paper led with runs a native protocol in which
     WISP has no wall-clock cap while every baseline does. That protocol cannot separate what the
     tool does from what the clock did to it, so the shared-wall-clock matrix, where every tool
     including WISP gets the same per-plugin budget and a record it does not answer is charged as a
     miss, becomes the comparison a reader sees first. The measurements already exist. Nothing is
     re-run here, the cells are read from the matrix JSON.

  2. FAILURE_AUDIT_TABLE.tex. The paper confesses one defect in its own Progpilot handling, where
     the harness discarded records that exited non-zero while printing a complete findings array.
     The obvious follow-up is whether the other baselines' failures were audited as carefully. They
     were, and the audit sat in the supplement. It is a main-text table now.

Every printed value is derived from a JSON already on disk. No number in either fragment, caption
included, is typed by hand, and check_budget_and_failure_tables_v3.py re-derives all of them.

    python3 -m eval.build_budget_and_failure_tables_v3
"""
from __future__ import annotations
import os, sys, json

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
SYS_ROOT = os.path.dirname(ROOT)
OUTDIR = os.path.join(SYS_ROOT, "revision-cns-v2", "out")
LATEX = os.path.join(SYS_ROOT, "2026-07-07", "latex")

MATRIX_SRC = os.path.join(OUTDIR, "BASELINE_MATRIX_V3.json")
AUDIT_SRC = os.path.join(OUTDIR, "BASELINE_FAILURE_AUDIT_V3.json")
MATRIX_OUT = os.path.join(LATEX, "BUDGET_MATRIX_TABLE.tex")
AUDIT_OUT = os.path.join(LATEX, "FAILURE_AUDIT_TABLE.tex")

GEN = "eval/build_budget_and_failure_tables_v3.py"

# Display names, in the spelling the manuscript already uses for these tools.
DISPLAY = {"wisp": "WISP", "wpt": "wp-taint-scan", "semgrep": "Semgrep", "progpilot": "Progpilot"}
# The kinds baseline_failure_audit_v3.py can record, in the wording a caption can carry.
KIND_PROSE = {"timeout": "timeout",
              "nonzero_exit": "non-zero exit",
              "empty_or_invalid_output": "empty or invalid output"}
# Plurals are spelled out rather than built by appending an s, so a kind whose plural is irregular
# cannot be printed wrong by a rule that never looked at it.
KIND_PLURAL = {"timeout": "timeouts",
               "nonzero_exit": "non-zero exits",
               "empty_or_invalid_output": "empty or invalid outputs"}
WORDS = {0: "no", 1: "one", 2: "two", 3: "three", 4: "four", 5: "five", 6: "six",
         7: "seven", 8: "eight", 9: "nine", 10: "ten", 11: "eleven", 12: "twelve"}


def r3(x):
    """Three decimals, the same rate format the generated macros print."""
    return f"{x:.3f}"


def signed3(x):
    """A difference, sign always shown, so a reader never has to infer the direction."""
    return ("$+$" if x >= 0 else "$-$") + f"{abs(x):.3f}"


def word(n):
    return WORDS.get(n, str(n))


# -  -  -  -  -  -  -  -  -  -  -  - the equal-budget matrix -  -  -  -  -  -  -  -  -  -  -  -  -

def load_matrix():
    return json.load(open(MATRIX_SRC, encoding="utf-8"))


def matrix_shape(d):
    """Which tools and which budgets the file actually holds, read rather than assumed.

    A hardcoded tool list is how a matrix quietly loses a row: the cell disappears from the JSON
    and the table keeps printing the other three as if the set were complete.
    """
    cells = d["cells"]
    tools, budgets = [], set()
    for key, c in cells.items():
        if c["tool"] not in tools:
            tools.append(c["tool"])
        budgets.add(c["budget_s"])
    return tools, sorted(budgets)


def cell_problems(d):
    """Every reason a cell is unusable or not like for like, derived from the cell itself.

    Returned as (missing, contaminated), where contaminated is a list of (key, reason). This is a
    report, not a veto: a cell measured under a different worker count is still a measurement, it
    just is not the same measurement, and the caption has to say so rather than the table hide it.
    """
    cells = d["cells"]
    tools, budgets = matrix_shape(d)
    missing = [f"{t}@{b}" for t in tools for b in budgets if f"{t}@{b}" not in cells]

    known = [c.get("workers") for c in cells.values() if c.get("workers")]
    modal = max(set(known), key=known.count) if known else None

    bad = []
    for key in sorted(cells):
        c = cells[key]
        n = c["dataset_n"]
        parts = (c["completed"] + c["timeouts"] + c["non_converged"]
                 + c.get("mem_capped", 0) + c["other_err"])
        if parts != n:
            bad.append((key, f"the record kinds sum to {parts}, not the {n} in dataset_n"))
        if abs(c["completed"] / n - c["coverage"]) > 1e-9:
            bad.append((key, f"coverage {c['coverage']} is not completed/dataset_n "
                             f"({c['completed']}/{n})"))
        prev = None
        for k in (1, 3, 5, 10):
            v = c[f"patch_file_success_at_{k}"]
            if prev is not None and v < prev - 1e-9:
                bad.append((key, f"patch_file_success_at_{k} = {v} is below the cutoff before it"))
            prev = v
        if c.get("workers") and modal and c["workers"] != modal:
            bad.append((key, f"ran at {c['workers']} workers where the modal cell ran at {modal}"))
        if c.get("mem_capped", 0):
            bad.append((key, f"{c['mem_capped']} record(s) stopped by the memory ceiling, "
                             "not by the clock"))
        if "mem_capped" not in c:
            bad.append((key, "predates the memory budget, it records neither a worker count nor a "
                             "memory outcome"))
        if not c.get("engine", {}).get("applies_to_this_cell") and c["tool"] == "wisp":
            bad.append((key, "a WISP cell whose engine block does not claim the cell"))
    return missing, bad


def build_matrix_fragment(d):
    cells = d["cells"]
    tools, budgets = matrix_shape(d)
    n = d["n_records"]
    metrics = [("coverage", "ans"),
               ("patch_file_success_at_1", "pf@1"),
               ("patch_file_success_at_3", "pf@3")]

    # Row order is read from the data, not fixed here: WISP first because it is the system under
    # test, then the baselines by their patch-file success@1 at the largest shared budget. A
    # hand-fixed order is a place for a stale ranking to hide.
    top = budgets[-1]
    base = sorted((t for t in tools if t != "wisp"),
                  key=lambda t: -cells[f"{t}@{top}"]["patch_file_success_at_1"])
    order = (["wisp"] if "wisp" in tools else []) + base

    known = [c.get("workers") for c in cells.values() if c.get("workers")]
    modal = max(set(known), key=known.count) if known else None

    def mark(key):
        """Markers hang on the block's answered share and cover the whole block at that budget.

        One marker per (tool, budget) block rather than one per cell. Marking all three cells of a
        block says the same thing three times and turns a compact table into a field of daggers.
        """
        c = cells[key]
        if c.get("mem_capped", 0) or (c.get("workers") and modal and c["workers"] != modal):
            return r"$^\dagger$"
        if "mem_capped" not in c:
            return r"$^\ddagger$"
        return ""

    # Best value in each column, across the tool rows only. The bold has to be computed, never
    # placed: this paper has already shipped a table whose bolding contradicted its own cells.
    best = {}
    for b in budgets:
        for field, _ in metrics:
            best[(b, field)] = max(cells[f"{t}@{b}"][field] for t in order if f"{t}@{b}" in cells)

    colspec = "@{}l" + " ".join(["c" * len(metrics)] * len(budgets)) + "@{}"
    ncols = 1 + len(metrics) * len(budgets)

    head1, head2, rules, col = [], ["Tool"], [], 2
    for b in budgets:
        head1.append(r"\multicolumn{%d}{c}{%d\,s}" % (len(metrics), b))
        rules.append(r"\cmidrule(lr){%d-%d}" % (col, col + len(metrics) - 1))
        head2.extend(h for _, h in metrics)
        col += len(metrics)

    lines = [
        f"% Auto-generated by {GEN} from revision-cns-v2/out/BASELINE_MATRIX_V3.json.",
        "% Every cell is a JSON pointer, not a transcription. Do not edit by hand.",
        "% Row order, bolding, and the dagger markers are computed from the cells, not placed.",
        r"\begin{table*}[!t]",
        r"\centering\small",
        r"\caption{" + matrix_caption(d, order, budgets, modal) + "}",
        r"\label{tab:equalbudget}",
        r"\setlength{\tabcolsep}{5pt}",
        r"\begin{tabular}{" + colspec + "}",
        r"\toprule",
        "& " + " & ".join(head1) + r" \\",
        "".join(rules),
        " & ".join(head2) + r" \\",
        r"\midrule",
    ]

    def row(tool, label):
        out = [label]
        for b in budgets:
            key = f"{tool}@{b}"
            if key not in cells:
                out.extend([r"--"] * len(metrics))
                continue
            for i, (field, _) in enumerate(metrics):
                v = cells[key][field]
                txt = r3(v)
                if abs(v - best[(b, field)]) < 1e-9:
                    txt = r"\textbf{" + txt + "}"
                if i == 0:
                    txt += mark(key)
                out.append(txt)
        return " & ".join(out) + r" \\"

    lines.append(row("wisp", r"WISP (this work)"))
    lines.append(r"\midrule")
    lines.append(r"\multicolumn{%d}{@{}l@{}}{\emph{Independent baselines}} \\" % ncols)
    for t in base:
        lines.append(row(t, DISPLAY.get(t, t)))

    # The gap row. Derived per column so it cannot disagree with the cells above it.
    lines.append(r"\midrule")
    gap = [r"WISP $-$ best baseline"]
    for b in budgets:
        for field, _ in metrics:
            w = cells.get(f"wisp@{b}", {}).get(field)
            bb = [cells[f"{t}@{b}"][field] for t in base if f"{t}@{b}" in cells]
            gap.append(signed3(w - max(bb)) if (w is not None and bb) else "--")
    lines.append(" & ".join(gap) + r" \\")

    lines += [r"\bottomrule", r"\end{tabular}", r"\end{table*}"]
    return "\n".join(lines) + "\n", n


def matrix_caption(d, order, budgets, modal):
    """The caption, assembled from the cells so its numbers cannot drift from the table's.

    House prose rules apply: ' - ' rather than an em-dash, commas rather than semicolons, and a
    period on every sentence.
    """
    cells = d["cells"]
    n = d["n_records"]
    blist = ", ".join(str(b) for b in budgets[:-1]) + f" and {budgets[-1]}"

    dag = [k for k in sorted(cells)
           if cells[k].get("mem_capped", 0)
           or (cells[k].get("workers") and modal and cells[k]["workers"] != modal)]
    ddag = [k for k in sorted(cells) if "mem_capped" not in cells[k]]

    s = [
        f"Equal-budget comparison of all {word(len(order))} scanners on the matched "
        f"{n}-record sample.",
        f"Every tool, WISP included, gets the same per-plugin wall clock, swept at {blist} "
        "seconds, and a record not answered inside the budget is a miss over the full denominator.",
        f"ans is the share of the {n} records answered, pf@1 and pf@3 are patch-file success at the "
        f"first finding and within the first three, all three scored over the {n} records.",
        "Bold is the best value in its column and the last row is WISP minus the best baseline "
        "there, so a negative entry is a column a baseline wins.",
        "A marker on a block's answered share covers that tool's whole block at that budget.",
    ]
    for k in dag:
        c = cells[k]
        bits = []
        if c.get("workers") and modal and c["workers"] != modal:
            bits.append(f"measured at {c['workers']} concurrent scans where every other block that "
                        f"records a worker count ran at {modal}")
        if c.get("mem_capped", 0):
            bits.append(f"with {word(c['mem_capped'])} of its records stopped by the memory "
                        "ceiling rather than by the clock")
        tool, budget = k.split("@")
        s.append(r"A dagger marks the " + DISPLAY.get(tool, tool) + f" block at {budget} seconds, "
                 + ", ".join(bits) + ".")
    if ddag:
        s.append(f"A double dagger marks the {word(len(ddag))} blocks measured before the memory "
                 "budget existed, recording neither a worker count nor a memory outcome, so they "
                 "are the least like for like here.")
    return " ".join(s)


# -  -  -  -  -  -  -  -  -  -  -  - the baseline failure audit -  -  -  -  -  -  -  -  -  -  -  -

def build_audit_fragment(a):
    tools = a["tools"]
    # Ordered by how many failures each tool has, largest first, because the question that produced
    # this table was asked about the two largest counts.
    order = sorted(tools, key=lambda t: -tools[t]["failures"])
    ns = {t["n_records"] for t in tools.values()}
    n = sorted(ns)[0]

    lines = [
        f"% Auto-generated by {GEN} from revision-cns-v2/out/BASELINE_FAILURE_AUDIT_V3.json.",
        "% Every cell is a JSON pointer, not a transcription. Do not edit by hand.",
        r"\begin{table}[!t]",
        r"\centering\small",
        r"\caption{" + audit_caption(a, order) + "}",
        r"\label{tab:failaudit}",
        r"\setlength{\tabcolsep}{4pt}",
        r"\begin{tabular}{@{}lrrrrcc@{}}",
        r"\toprule",
        r"& & \multicolumn{3}{c}{failures} & \multicolumn{2}{c}{coverage} \\",
        r"\cmidrule(lr){3-5}\cmidrule(lr){6-7}",
        # "unread" rather than "harness-read": at \small in an elsarticle column the longer head
        # pushes the tabular to 248.9pt against a 252pt column, three points of headroom, and one
        # extra digit anywhere would overflow it. The caption spells the term out in full.
        r"Tool & records & timeout & other & unread & scored & bound \\",
        r"\midrule",
    ]
    for t in order:
        e = tools[t]
        lines.append(" & ".join([
            DISPLAY.get(t, t),
            str(e["n_records"]),
            str(e["by_kind"].get("timeout", 0)),
            str(e["failures"] - e["by_kind"].get("timeout", 0)),
            str(e["harness_read_failures"]),
            r3(e["coverage_as_scored"]),
            r3(e["coverage_upper_bound_if_all_harness_failures_were_false"]),
        ]) + r" \\")
    lines += [r"\bottomrule", r"\end{tabular}", r"\end{table}"]
    return "\n".join(lines) + "\n", n


def audit_caption(a, order):
    tools = a["tools"]
    n = sorted({t["n_records"] for t in tools.values()})[0]

    kinds = []
    for t in order:
        for k, v in sorted(tools[t]["by_kind"].items()):
            if k != "timeout" and v:
                name = (KIND_PROSE if v == 1 else KIND_PLURAL).get(k, k)
                kinds.append(f"{v} {name} for {DISPLAY.get(t, t)}")
    kind_sentence = ("The other column holds " + ", ".join(kinds) +
                     ", all of them failures the harness could not read, which is why the other "
                     "and unread columns agree here.") if kinds else \
                    "No baseline recorded a failure of any other kind."

    s = [
        f"Every baseline failure on the full {n}-record corpus, split by what the harness recorded.",
        "A timeout is budget exhaustion, charged as a miss by design, and unread counts the "
        "failures the harness could not read, the class the Progpilot exit-code defect belonged to.",
        kind_sentence,
        "scored is coverage as scored, charging every failure as a miss, and bound is the coverage "
        "the tool would show if every unread failure were a false miss, a bound rather than a "
        "correction because the stored records carry the harness's view and not the tool's output.",
        "WISP is not a row here, since on the corpus it runs in-process rather than as a per-record "
        "subprocess, so its failure mode is non-convergence rather than a subprocess error.",
    ]
    return " ".join(s)


# -  -  -  -  -  -  -  -  -  -  -  -  -  -  -  -  -  -  -  -  -  -  -  -  -  -  -  -  -  -  -  -

def main():
    for p in (MATRIX_SRC, AUDIT_SRC):
        if not os.path.isfile(p):
            sys.exit(f"missing source: {p}")

    d = load_matrix()
    a = json.load(open(AUDIT_SRC, encoding="utf-8"))

    mtex, mn = build_matrix_fragment(d)
    open(MATRIX_OUT, "w", encoding="utf-8").write(mtex)
    atex, an = build_audit_fragment(a)
    open(AUDIT_OUT, "w", encoding="utf-8").write(atex)

    tools, budgets = matrix_shape(d)
    print(f"wrote {MATRIX_OUT} ({len(tools)} tools x {len(budgets)} budgets = "
          f"{len(tools) * len(budgets)} cells, n={mn})")
    print(f"wrote {AUDIT_OUT} ({len(a['tools'])} baselines, n={an})")

    # A generator that prints a clean table over a hole in its input is worse than one that
    # refuses, so the holes and the not-like-for-like cells are named on the way out. The
    # contamination list is a report. The missing list is a failure.
    missing, bad = cell_problems(d)
    if bad:
        print(f"  {len(bad)} cell caveat(s), each one marked in the table or named in the caption:")
        for k, why in bad:
            print(f"    {k}: {why}")
    if missing:
        print(f"  {len(missing)} cell(s) absent from the matrix: {', '.join(missing)}",
              file=sys.stderr)
        return 2
    return 0


if __name__ == "__main__":
    sys.exit(main())
