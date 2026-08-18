#!/usr/bin/env python3
"""Quantify how many inter-procedural findings depend on an ambiguous summary
(Reviewer Report 2026-07-11, item 2.2: "does not quantify ... the fraction of
findings relying on ambiguous summaries").

A summary is ambiguous when its unqualified function/method name is defined by
two or more functions in the same plugin, so the name-indexed summary table
cannot tell which definition a call resolves to. For each plugin we:
  1. count how many definitions share each unqualified name (ambiguous set),
  2. run the real WISP scan,
  3. for every inter-procedural finding, extract its callee name from the trace
     and mark it ambiguous iff that name is in the ambiguous set.

This measures exposure, not correctness: an ambiguous-summary finding may still
be right, but its inter-procedural step is unverified by the current engine.

Usage: python3 measure_ambiguous_summaries.py [--sample keys.txt] [--out ...]
"""
import os, sys, re, json, argparse
from collections import Counter, defaultdict

WISP = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
R = os.path.dirname(WISP)
sys.path.insert(0, WISP)

from wisp.engine import taint_engine as te                     # noqa: E402
from wisp.engine import l1_ingest                              # noqa: E402
from wisp.engine.taint_engine import _parser                  # noqa: E402
from wisp.engine.taint_ast import _collect_functions, _fn_name  # noqa: E402
from eval.datasets.patchstack import load_rows               # noqa: E402

_VIA = re.compile(r"via (\w+)\(\)")


def ambiguous_names(plugin):
    names = Counter()
    for abs_file in plugin.php_files:
        try:
            src = open(abs_file, "rb").read()
        except OSError:
            continue
        if b"<?" not in src:
            continue
        try:
            root = _parser().parse(src).root_node
            for fn in _collect_functions(root, src):
                names[_fn_name(fn, src)] += 1
        except Exception:
            continue
    ambig = {n for n, c in names.items() if c > 1}
    ndefs = sum(names.values())
    # same statistic as measure_convergence.py: definitions whose name is shared
    defs_sharing = sum(c for c in names.values() if c > 1)
    return ambig, ndefs, len(names), defs_sharing


def callee_of(f):
    # inter-procedural sink is "<sink> (via <name>())"; trace also carries it
    m = _VIA.search(f.sink or "")
    if m:
        return m.group(1)
    for t in (f.trace or []):
        m = _VIA.search(t)
        if m:
            return m.group(1)
    return None


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--sample", default="", help="file of slug|cve keys (default: all)")
    ap.add_argument("--out", default=os.path.join(WISP, "out", "ambiguous_summaries.json"))
    ap.add_argument("--limit", type=int, default=0)
    a = ap.parse_args()
    rows = load_rows()
    if a.sample:
        want = {s.strip() for s in open(a.sample) if s.strip()}
        rows = [r for r in rows if r["slug"] + "|" + r["cve"] in want]
    if a.limit:
        rows = rows[:a.limit]

    tot_find = tot_interproc = tot_interproc_ambig = 0
    tot_defs = tot_shared = 0
    per_plugin = []
    seen_zip = set()
    for r in rows:
        zp = r["vuln_zip"]
        if not os.path.exists(zp) or zp in seen_zip:
            continue
        seen_zip.add(zp)
        plug = l1_ingest.load_plugin(zp)
        if not (plug and plug.php_files):
            continue
        try:
            ambig, ndefs, nnames, defs_sharing = ambiguous_names(plug)
            fnds = te.detect(plug)
        except Exception:
            plug.cleanup()
            continue
        ip = [f for f in fnds if getattr(f, "interprocedural", False)]
        ip_ambig = 0
        for f in ip:
            c = callee_of(f)
            if c and c in ambig:
                ip_ambig += 1
        tot_find += len(fnds)
        tot_interproc += len(ip)
        tot_interproc_ambig += ip_ambig
        tot_defs += ndefs
        tot_shared += defs_sharing
        per_plugin.append({"slug": r["slug"], "findings": len(fnds),
                           "interproc": len(ip), "interproc_ambiguous": ip_ambig,
                           "defs": ndefs, "collision_names": len(ambig)})
        plug.cleanup()

    rep = {
        "n_plugins": len(per_plugin),
        "total_findings": tot_find,
        "total_interprocedural": tot_interproc,
        "interprocedural_ambiguous": tot_interproc_ambig,
        "pct_interprocedural_ambiguous":
            round(tot_interproc_ambig / tot_interproc, 4) if tot_interproc else 0.0,
        "pct_findings_interprocedural":
            round(tot_interproc / tot_find, 4) if tot_find else 0.0,
        "pct_findings_ambiguous_interproc":
            round(tot_interproc_ambig / tot_find, 4) if tot_find else 0.0,
        "pct_definitions_sharing_name":
            round(tot_shared / tot_defs, 4) if tot_defs else 0.0,
        "details": per_plugin,
    }
    os.makedirs(os.path.dirname(a.out), exist_ok=True)
    json.dump(rep, open(a.out, "w"), indent=1)
    print(json.dumps({k: rep[k] for k in list(rep)[:-1]}, indent=1))


if __name__ == "__main__":
    main()
