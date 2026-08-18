#!/usr/bin/env python3
"""Which finding types are pure noise? For each sink signature, count how often it
is the advisory finding (right class in a patched file) versus how often it BURIES
the advisory finding (ranked above it under the current GDA ranking). A sink that
buries a lot and is rarely the advisory is a demotion/prune candidate.

    python3 -m eval.gda_noise out/gda_dump_sink.json
"""
from __future__ import annotations
import sys, json
from collections import defaultdict
from eval.gda_sweep import score


def _sig(f):
    """Coarse sink signature: the source==unserialize risk pattern, the sink name,
    else the class. Groups speculative-callback rce, echo XSS, etc."""
    if f.get("src") == "unserialize(untrusted)":
        return "risk:unserialize"
    sink = (f.get("sink") or "").lstrip("$>-")
    if sink:
        return f"{f['cls']}:{sink}"
    return f"{f['cls']}:?"


def main():
    dump = json.load(open(sys.argv[1]))
    adv = defaultdict(int)      # sig -> times it is the advisory finding
    bury = defaultdict(int)     # sig -> times it outranks the advisory finding
    total = defaultdict(int)    # sig -> total emissions
    for d in dump:
        gt = set(d["gt_files"])
        cls = d["cls"]
        feats = sorted(d["findings"], key=lambda f: score(f, 1.0, 0.5, None, None, 0.0),
                       reverse=True)
        for f in feats:
            total[_sig(f)] += 1
        right_idx = [i for i, f in enumerate(feats)
                     if f["file"] in gt and f["cls"] == cls]
        if not right_idx:
            continue
        ri = right_idx[0]
        adv[_sig(feats[ri])] += 1
        for f in feats[:ri]:
            bury[_sig(f)] += 1
    # rank signatures by burial, show advisory count and noise ratio
    sigs = sorted(total, key=lambda s: -bury[s])
    print(f"{'sink signature':34}{'total':>7}{'buries':>8}{'advisory':>9}{'noise=bury/(adv+1)':>20}")
    for s in sigs[:25]:
        noise = bury[s] / (adv[s] + 1)
        print(f"{s:34}{total[s]:>7}{bury[s]:>8}{adv[s]:>9}{noise:>20.1f}")


if __name__ == "__main__":
    main()
