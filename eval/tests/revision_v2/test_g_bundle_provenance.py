"""G. Generated-bundle provenance is rewritten after the fact.

`final/update-final.sh` (section 6e) rewrites the provenance recorded in the
shipped JSONs with `sed -i`, mapping the run-time commit and source hashes to the
released identity (e64fe02 -> 7beac3d, 9d814504 -> 4131f876, a704ff06 ->
cf6b8b51). Provenance should be whatever the run actually stamped, not a value
edited in post. A post-hoc `sed -i` on provenance means the shipped
`engine_commit` / source-hash fields no longer record the run that produced the
numbers.

Desired invariant (fails now): the build script must not rewrite provenance
commit/hash fields with sed after the run.
"""
from __future__ import annotations
import re
import os
from ._common import UPDATE_FINAL, SYS_ROOT, Evidence

# The revision bundle is built by update-final-v2.sh; the legacy final/update-final.sh is the
# one that carried the sed rewrite. Check every build script that exists, and say which of them
# actually produces the shipped bundle, so a green result cannot come from testing a dead file.
BUILD_SCRIPTS = [
    (os.path.join(SYS_ROOT, "2026-07-07", "latex", "update-final-v2.sh"), "SHIPPED (revision v2)"),
    (UPDATE_FINAL, "legacy (not used by the revision bundle)"),
]

# the specific run-time identities the script maps onto the released identity
PROVENANCE_HASHES = ["e64fe028183a", "9d81450490d2", "a704ff0697a2",
                     "7beac3d7a2b0", "4131f876d1fb", "cf6b8b516cbd"]


def _offending(path):
    lines = open(path, encoding="utf-8").read().splitlines()
    out, in_sed = [], False
    for i, ln in enumerate(lines, 1):
        s = ln.strip()
        if s.startswith("#"):
            continue
        if "sed -i" in ln:
            in_sed = True
        if in_sed and any(h in ln for h in PROVENANCE_HASHES):
            out.append((i, s))
        if in_sed and not ln.rstrip().endswith("\\"):
            in_sed = False
    return out


def test_no_posthoc_provenance_rewrite():
    ev = Evidence("G. generated-bundle provenance rewrite")
    bad = []
    for path, role in BUILD_SCRIPTS:
        if not os.path.isfile(path):
            ev.show(f"{os.path.basename(path):22} [{role}] MISSING")
            continue
        off = _offending(path)
        ev.show(f"{os.path.basename(path):22} [{role}] {len(off)} provenance sed -i line(s)")
        for i, s in off[:4]:
            ev.show(f"    L{i}: {s[:100]}")
        if off and role.startswith("SHIPPED"):
            bad.append((path, off))

    assert not bad, (
        "BUG G: the script that builds the shipped bundle rewrites provenance commit/source-hash "
        "fields with sed -i after the run. Shipped provenance must come from the real run, not a "
        "post-hoc substitution: " + ", ".join(os.path.basename(p) for p, _ in bad))


if __name__ == "__main__":
    test_no_posthoc_provenance_rewrite()
