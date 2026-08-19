#!/usr/bin/env python3
"""Build guard for the two generated main-text tables. Exit nonzero = fail the build.

A generated fragment is only as trustworthy as the last time the generator ran. Both of these
fragments are checked into the paper directory beside hand-written ones, so a stale copy, a hand
edit, or a JSON that moved under them all look identical to LaTeX, which will happily typeset any
number at all.

This guard does not re-run the generator and diff its output. Diffing a generator against itself
proves the generator is deterministic, not that the fragment says what the data says, and it goes
green the moment someone edits the generator to match a fragment. So every printed value is parsed
back out of the fragment and compared to a derivation written here, from the JSON, independently:

  * the equal-budget matrix, every (tool, budget) block's answered share and patch-file success at
    the first and third cutoff, the bold on each column's best value, the dagger markers, and the
    WISP-minus-best-baseline row,
  * the failure audit, every count and both coverages per baseline,
  * the numbers each caption spells out in prose, which no other guard in this repo reads, and
  * the house prose rules for a caption, no em-dash, no semicolon, a period on every sentence, and
    never the retired tool name.

    python3 -m eval.check_budget_and_failure_tables_v3        # exit 0 pass, 2 fail
"""
from __future__ import annotations
import os, sys, re, json

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
SYS_ROOT = os.path.dirname(ROOT)
OUTDIR = os.path.join(SYS_ROOT, "revision-cns-v2", "out")
LATEX = os.path.join(SYS_ROOT, "2026-07-07", "latex")

MATRIX_SRC = os.path.join(OUTDIR, "BASELINE_MATRIX_V3.json")
AUDIT_SRC = os.path.join(OUTDIR, "BASELINE_FAILURE_AUDIT_V3.json")
MATRIX_TEX = os.path.join(LATEX, "BUDGET_MATRIX_TABLE.tex")
AUDIT_TEX = os.path.join(LATEX, "FAILURE_AUDIT_TABLE.tex")

# Row label to JSON tool key. Written here rather than imported, so a rename in the generator that
# quietly repoints a row cannot also repoint the guard that is supposed to catch it.
LABEL_TO_TOOL = {
    "WISP (this work)": "wisp",
    "wp-taint-scan": "wpt",
    "Semgrep": "semgrep",
    "Progpilot": "progpilot",
}
NUMBER_WORD = {"no": 0, "one": 1, "two": 2, "three": 3, "four": 4, "five": 5, "six": 6,
               "seven": 7, "eight": 8, "nine": 9, "ten": 10, "eleven": 11, "twelve": 12}
GAP_LABEL = "WISP $-$ best baseline"


# -  -  -  -  -  -  -  -  -  -  -  -  - reading the fragment -  -  -  -  -  -  -  -  -  -  -  -  -

def read(path, fails):
    if not os.path.isfile(path):
        fails.append(f"{os.path.basename(path)} does not exist, the generator has never been run")
        return None
    return open(path, encoding="utf-8").read()


def caption_of(tex):
    """The caption body, with balanced braces. \\caption{...} holds braces of its own."""
    i = tex.find(r"\caption{")
    if i < 0:
        return None
    j, depth = i + len(r"\caption{"), 1
    while j < len(tex) and depth:
        if tex[j] == "\\":
            j += 2
            continue
        depth += 1 if tex[j] == "{" else -1 if tex[j] == "}" else 0
        j += 1
    return tex[i + len(r"\caption{"):j - 1] if depth == 0 else None


def body_rows(tex):
    """Every data row of the tabular as a list of raw cells.

    A row is a line ending in \\\\ that is not part of the header, the rules, or a spanning label.
    """
    rows = []
    inside = False
    for line in tex.split("\n"):
        s = line.strip()
        if s.startswith(r"\begin{tabular}"):
            inside = True
            continue
        if s.startswith(r"\end{tabular}"):
            inside = False
            continue
        if not inside or not s.endswith(r"\\"):
            continue
        if s.startswith(r"\multicolumn") or r"\multicolumn{" in s.split("&")[0]:
            continue
        if r"\multicolumn{" in s and not s.split("&")[0].strip():
            # A header continuation row that spans the budget or metric groups. It carries no
            # tool label in column one, so it is not a data row. Rows with a label still fall
            # through, so a real data row can never be skipped by this test.
            continue
        cells = [c.strip() for c in s[:-2].split("&")]
        rows.append(cells)
    return rows


BOLD = re.compile(r"^\\textbf\{(.*)\}$")
MARK = re.compile(r"\$\^\\(dagger|ddagger)\$$")


def decode(cell):
    """A printed cell into (value string, bolded, marker). Anything else is a parse failure."""
    c = cell.strip()
    mark = ""
    m = MARK.search(c)
    if m:
        mark = m.group(1)
        c = c[:m.start()].strip()
    bold = False
    m = BOLD.match(c)
    if m:
        bold, c = True, m.group(1).strip()
    return c, bold, mark


def decode_signed(cell):
    """A signed difference cell, $+$0.030 or $-$0.010, back into a float."""
    m = re.match(r"^\$([+-])\$([0-9.]+)$", cell.strip())
    if not m:
        return None
    return float(m.group(2)) * (1 if m.group(1) == "+" else -1)


# -  -  -  -  -  -  -  -  -  -  -  -  - the equal-budget matrix -  -  -  -  -  -  -  -  -  -  -  -

def check_matrix(fails):
    tex = read(MATRIX_TEX, fails)
    if tex is None:
        return 0
    d = json.load(open(MATRIX_SRC, encoding="utf-8"))
    cells = d["cells"]
    name = os.path.basename(MATRIX_TEX)
    checked = 0

    budgets = sorted({c["budget_s"] for c in cells.values()})
    tools = sorted({c["tool"] for c in cells.values()})
    fields = ["coverage", "patch_file_success_at_1", "patch_file_success_at_3"]

    # A wide table in a two-column journal has to be a table*, or it silently overprints the
    # neighbouring column. This is the one structural fact the reviewer's demand depends on.
    if r"\begin{table*}" not in tex:
        fails.append(f"{name} is not a table*, a matrix this wide cannot sit in one column")
    if r"\label{tab:equalbudget}" not in tex:
        fails.append(f"{name} has no \\label{{tab:equalbudget}}, nothing can point at it")

    # The header must name the budgets that are in the file, in the order the cells are printed.
    for b in budgets:
        if r"{%d\,s}" % b not in tex:
            fails.append(f"{name} header does not carry the {b}s budget the JSON holds")

    rows = {}
    gap_row = None
    for cells_of_row in body_rows(tex):
        label = cells_of_row[0]
        if label == GAP_LABEL:
            gap_row = cells_of_row[1:]
        elif label in LABEL_TO_TOOL:
            rows[LABEL_TO_TOOL[label]] = cells_of_row[1:]
        elif label.startswith("Tool"):
            continue
        else:
            fails.append(f"{name} has a data row this guard does not recognise: {label!r}")

    for t in tools:
        if t not in rows:
            fails.append(f"{name} prints no row for {t}, which the matrix JSON has cells for")
    for t in rows:
        if t not in tools:
            fails.append(f"{name} prints a row for {t}, which the matrix JSON has no cells for")

    # Column-wise best, re-derived. The bolding in this paper has been wrong before, on the wrong
    # column of a table whose numbers were all correct, so the bold is checked as a claim.
    best = {}
    for b in budgets:
        for f in fields:
            vals = [cells[f"{t}@{b}"][f] for t in tools if f"{t}@{b}" in cells]
            best[(b, f)] = max(vals) if vals else None

    known = [c.get("workers") for c in cells.values() if c.get("workers")]
    modal = max(set(known), key=known.count) if known else None

    for t, printed in sorted(rows.items()):
        want_n = len(budgets) * len(fields)
        if len(printed) != want_n:
            fails.append(f"{name} row {t} has {len(printed)} value cells, expected {want_n}")
            continue
        i = 0
        for b in budgets:
            key = f"{t}@{b}"
            c = cells.get(key)
            for pos, f in enumerate(fields):
                got, bold, mark = decode(printed[i])
                i += 1
                if c is None:
                    if got != "--":
                        fails.append(f"{name} {key} prints {got!r} for a cell the JSON does not have")
                    continue
                want = f"{c[f]:.3f}"
                if got != want:
                    fails.append(f"{name} {key} {f} prints {got}, JSON says {want}")
                checked += 1
                should_bold = abs(c[f] - best[(b, f)]) < 1e-9
                if bold != should_bold:
                    fails.append(f"{name} {key} {f} is {'bold' if bold else 'not bold'} but the "
                                 f"column best is {best[(b, f)]:.3f} and this cell is {c[f]:.3f}")
                # Markers hang on the first column of each block and nowhere else.
                if pos == 0:
                    off_protocol = bool(c.get("mem_capped", 0)) or (
                        c.get("workers") and modal and c["workers"] != modal)
                    pre_budget = "mem_capped" not in c
                    want_mark = "dagger" if off_protocol else "ddagger" if pre_budget else ""
                    if mark != want_mark:
                        fails.append(f"{name} {key} carries marker {mark or 'none'!r}, the cell's "
                                     f"own record says {want_mark or 'none'!r}")
                elif mark:
                    fails.append(f"{name} {key} {f} carries a marker, only a block's first column "
                                 "may carry one")

    if gap_row is None:
        fails.append(f"{name} has no {GAP_LABEL!r} row, the gap a reader is asked to see is not "
                     "computed anywhere")
    else:
        i = 0
        for b in budgets:
            for f in fields:
                got = decode_signed(gap_row[i]) if i < len(gap_row) else None
                i += 1
                w = cells.get(f"wisp@{b}", {}).get(f)
                bb = [cells[f"{t}@{b}"][f] for t in tools
                      if t != "wisp" and f"{t}@{b}" in cells]
                if w is None or not bb:
                    continue
                want = round(w - max(bb), 3)
                if got is None:
                    fails.append(f"{name} gap row cell {i} for {f}@{b}s does not parse as a "
                                 "signed difference")
                elif abs(got - want) > 5e-4:
                    fails.append(f"{name} gap row {f}@{b}s prints {got:+.3f}, "
                                 f"WISP minus best baseline is {want:+.3f}")
                else:
                    checked += 1

    checked += check_matrix_caption(tex, d, modal, name, fails)
    return checked


def check_matrix_caption(tex, d, modal, name, fails):
    """The caption spells out numbers in prose, and prose is where this project's claims rot.

    Nothing else reads a caption. The macro guard reads macros, the length guard counts words, and
    LaTeX renders whatever is typed. So each number the caption asserts is pulled back out and
    re-derived.
    """
    cap = caption_of(tex)
    if cap is None:
        fails.append(f"{name} has no parsable \\caption")
        return 0
    cells = d["cells"]
    n = d["n_records"]
    budgets = sorted({c["budget_s"] for c in cells.values()})
    tools = sorted({c["tool"] for c in cells.values()})
    checked = 0

    m = re.search(r"all (\w+) scanners on the matched (\d+)-record sample", cap)
    if not m:
        fails.append(f"{name} caption does not state the tool count and the sample size")
    else:
        if NUMBER_WORD.get(m.group(1)) != len(tools):
            fails.append(f"{name} caption says {m.group(1)} scanners, the JSON has {len(tools)}")
        elif int(m.group(2)) != n:
            fails.append(f"{name} caption says a {m.group(2)}-record sample, "
                         f"n_records is {n}")
        else:
            checked += 2

    m = re.search(r"swept at ([\d, and]+) seconds", cap)
    if not m:
        fails.append(f"{name} caption does not state the budgets it was swept at")
    else:
        got = [int(x) for x in re.findall(r"\d+", m.group(1))]
        if got != budgets:
            fails.append(f"{name} caption sweeps {got}, the JSON holds {budgets}")
        else:
            checked += 1

    # Every dagger the caption explains must correspond to a cell, and every cell that earns one
    # must be explained. An unexplained marker is a footnote to nothing.
    dag = sorted(k for k, c in cells.items()
                 if c.get("mem_capped", 0)
                 or (c.get("workers") and modal and c["workers"] != modal))
    ddag = sorted(k for k, c in cells.items() if "mem_capped" not in c)

    named = re.findall(r"A dagger marks the ([\w-]+) block at (\d+) seconds", cap)
    want = {(k.split("@")[0], k.split("@")[1]) for k in dag}
    got = {(t, b) for t, b in named}
    inv = {"wpt": "wp-taint-scan", "wisp": "WISP", "semgrep": "Semgrep", "progpilot": "Progpilot"}
    want_disp = {(inv.get(t, t), b) for t, b in want}
    if got != want_disp:
        fails.append(f"{name} caption explains daggers for {sorted(got)}, the cells that earn one "
                     f"are {sorted(want_disp)}")
    else:
        checked += len(want_disp)

    for k in dag:
        c = cells[k]
        if c.get("workers") and modal and c["workers"] != modal:
            if f"measured at {c['workers']} concurrent scans" not in cap:
                fails.append(f"{name} caption does not state that {k} ran at {c['workers']} "
                             "concurrent scans")
            elif f"records a worker count ran at {modal}" not in cap:
                fails.append(f"{name} caption does not state the modal worker count {modal}")
            else:
                checked += 2
        if c.get("mem_capped", 0):
            m = re.search(r"with (\w+) of its records stopped by the memory ceiling", cap)
            if not m or NUMBER_WORD.get(m.group(1)) != c["mem_capped"]:
                fails.append(f"{name} caption does not state that {k} had {c['mem_capped']} "
                             "records stopped by the memory ceiling")
            else:
                checked += 1

    m = re.search(r"A double dagger marks the (\w+) blocks measured before", cap)
    if ddag and (not m or NUMBER_WORD.get(m.group(1)) != len(ddag)):
        fails.append(f"{name} caption does not state that {len(ddag)} blocks predate the memory "
                     f"budget, the cells without a mem_capped record are {ddag}")
    elif ddag:
        checked += 1
    return checked


# -  -  -  -  -  -  -  -  -  -  -  -  - the failure audit -  -  -  -  -  -  -  -  -  -  -  -  -  -

def check_audit(fails):
    tex = read(AUDIT_TEX, fails)
    if tex is None:
        return 0
    a = json.load(open(AUDIT_SRC, encoding="utf-8"))["tools"]
    name = os.path.basename(AUDIT_TEX)
    checked = 0

    if r"\label{tab:failaudit}" not in tex:
        fails.append(f"{name} has no \\label{{tab:failaudit}}, nothing can point at it")

    rows = {}
    for cells_of_row in body_rows(tex):
        label = cells_of_row[0]
        if label.startswith("Tool") or label.startswith("&"):
            continue
        if label not in LABEL_TO_TOOL:
            fails.append(f"{name} has a data row this guard does not recognise: {label!r}")
            continue
        rows[LABEL_TO_TOOL[label]] = cells_of_row[1:]

    for t in a:
        if t not in rows:
            fails.append(f"{name} prints no row for {t}, which the audit JSON covers")
    for t in rows:
        if t not in a:
            fails.append(f"{name} prints a row for {t}, which the audit JSON does not cover")

    for t, printed in sorted(rows.items()):
        if t not in a:
            continue
        e = a[t]
        to = e["by_kind"].get("timeout", 0)
        want = [str(e["n_records"]),
                str(to),
                str(e["failures"] - to),
                str(e["harness_read_failures"]),
                f'{e["coverage_as_scored"]:.3f}',
                f'{e["coverage_upper_bound_if_all_harness_failures_were_false"]:.3f}']
        head = ["records", "timeout", "other", "unread", "scored", "bound"]
        if len(printed) != len(want):
            fails.append(f"{name} row {t} has {len(printed)} value cells, expected {len(want)}")
            continue
        for h, got, w in zip(head, printed, want):
            if decode(got)[0] != w:
                fails.append(f"{name} {t} {h} prints {got}, JSON says {w}")
            else:
                checked += 1
        # An identity the table asserts by having both columns: budget exhaustion plus everything
        # else is the whole failure count, and everything else is exactly the unread column.
        if e["budget_exhaustion"] + e["harness_read_failures"] != e["failures"]:
            fails.append(f"audit JSON {t} does not split cleanly, "
                         f"{e['budget_exhaustion']} + {e['harness_read_failures']} "
                         f"!= {e['failures']}")

    checked += check_audit_caption(tex, a, name, fails)
    return checked


def check_audit_caption(tex, a, name, fails):
    cap = caption_of(tex)
    if cap is None:
        fails.append(f"{name} has no parsable \\caption")
        return 0
    checked = 0

    ns = {t["n_records"] for t in a.values()}
    m = re.search(r"on the full (\d+)-record corpus", cap)
    if not m:
        fails.append(f"{name} caption does not state the corpus size")
    elif int(m.group(1)) not in ns or len(ns) != 1:
        fails.append(f"{name} caption says a {m.group(1)}-record corpus, the JSON records {ns}")
    else:
        checked += 1

    # The by-kind breakdown lives only in the caption. It is the part of the audit that answers
    # whether another baseline could be carrying the defect we found in our own Progpilot handling,
    # so it is re-derived rather than trusted.
    prose = {"nonzero_exit": ("non-zero exit", "non-zero exits"),
             "empty_or_invalid_output": ("empty or invalid output", "empty or invalid outputs")}
    inv = {v: k for k, v in LABEL_TO_TOOL.items()}
    for t, e in sorted(a.items()):
        for kind, v in sorted(e["by_kind"].items()):
            if kind == "timeout" or not v:
                continue
            if kind not in prose:
                fails.append(f"{name} caption cannot describe failure kind {kind!r} for {t}, the "
                             "guard and the generator both need a wording for it")
                continue
            phrase = f"{v} {prose[kind][0 if v == 1 else 1]} for {inv[t]}"
            if phrase not in cap:
                fails.append(f"{name} caption does not carry {phrase!r}, which the JSON's "
                             f"by_kind for {t} says")
            else:
                checked += 1
    return checked


# -  -  -  -  -  -  -  -  -  -  -  -  - house prose rules -  -  -  -  -  -  -  -  -  -  -  -  -  -

def check_prose(fails):
    """The caption is prose and the paper has prose rules. Nothing else enforces them on a caption.

    The retired tool name is checked over the whole fragment, not just the caption. A rebrand that
    leaves the old name in a generated file is exactly the kind of thing that ships.
    """
    checked = 0
    for path in (MATRIX_TEX, AUDIT_TEX):
        if not os.path.isfile(path):
            continue
        name = os.path.basename(path)
        whole = open(path, encoding="utf-8").read()
        if re.search(r"\bNES\b", whole):
            fails.append(f"{name} carries the retired tool name")
        else:
            checked += 1
        cap = caption_of(whole)
        if cap is None:
            continue
        for bad, why in (("---", "an em-dash"), ("--", "an en-dash used as a dash"),
                         (";", "a semicolon")):
            if bad in cap:
                fails.append(f"{name} caption contains {why}, the house rule is ' - ' and commas")
            else:
                checked += 1
        # Every sentence ends with a period. A caption that trails off is a caption someone edited.
        if not cap.rstrip().endswith("."):
            fails.append(f"{name} caption does not end with a period")
        else:
            checked += 1
    return checked


def main():
    fails = []
    for p in (MATRIX_SRC, AUDIT_SRC):
        if not os.path.isfile(p):
            print(f"BUDGET/FAILURE TABLE CHECK: FAIL, missing source {p}")
            return 2
    checked = check_matrix(fails) + check_audit(fails) + check_prose(fails)
    if fails:
        print("BUDGET/FAILURE TABLE CHECK: FAIL")
        for f in fails:
            print("  x " + f)
        return 2
    print(f"BUDGET/FAILURE TABLE CHECK: PASS ({checked} printed values re-derived from "
          "BASELINE_MATRIX_V3.json and BASELINE_FAILURE_AUDIT_V3.json, captions included)")
    return 0


if __name__ == "__main__":
    sys.exit(main())
