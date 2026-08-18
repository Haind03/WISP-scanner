"""B. Identifier collision.

`build_adjudication_v2.py` minted the row id as

    "E" + sha1(f"{slug}|{tool}|{file}|{line}")[:8]

which omits `cve`, `rank` and `reported_class`. Two logically distinct rows sharing
slug/tool/file/line collided, and `key[fid] = ...` kept only the last one.

As with bug A the repair is not in that retired builder. The live identifier is
`eval/patch_geometry.py::finding_uid`, a full uuid5 over the run, the record, the tool, the
rank, the normalized path, the line, the reported classes and an occurrence index. This test
pins the two properties that matter: the id separates rows the v2 scheme merged, and it is
unique across the whole shipped population, not just a 200-row sample.
"""
from __future__ import annotations
import hashlib
import json
from collections import Counter

from ._common import Evidence


def _v2_fid(slug, tool, file, line):
    """The retired scheme, kept here only to show what it merged."""
    return "E" + hashlib.sha1(f"{slug}|{tool}|{file}|{line}".encode()).hexdigest()[:8]


def test_finding_id_is_unique_per_row():
    ev = Evidence("B. identifier collision, live v3 identifier")
    from eval import patch_geometry as pg
    from eval import adjudication_v3_common as C

    # --- mechanism: rows the retired scheme merged must now separate ---
    a2 = _v2_fid("acme", "wisp", "inc/ajax.php", 42)
    b2 = _v2_fid("acme", "wisp", "inc/ajax.php", 42)
    ev.show(f"retired v2 id, two rows differing only in cve/rank/class: {a2} vs {b2} "
            f"collide={a2 == b2}")
    assert a2 == b2, "fixture broken: the v2 scheme should collide on this pair"

    run, rec = "run-1", "rec-1"
    a3 = pg.finding_uid(run, rec, "wisp", 1, "inc/ajax.php", 42, ["sqli"], 0)
    b3 = pg.finding_uid(run, rec, "wisp", 3, "inc/ajax.php", 42, ["xss"], 0)
    c3 = pg.finding_uid(run, rec, "wisp", 1, "inc/ajax.php", 42, ["sqli"], 1)
    ev.show(f"v3 finding_uid, same file+line, rank 1/class sqli -> {a3[:13]}")
    ev.show(f"v3 finding_uid, same file+line, rank 3/class xss  -> {b3[:13]}")
    ev.show(f"v3 finding_uid, identical tuple, occurrence 1     -> {c3[:13]}")
    assert len({a3, b3, c3}) == 3, (
        "the live finding_uid still merges rows that differ in rank, reported class or "
        "occurrence index")

    # a different record must not reuse an id either
    d3 = pg.finding_uid(run, "rec-2", "wisp", 1, "inc/ajax.php", 42, ["sqli"], 0)
    assert d3 != a3, "finding_uid does not separate two records at the same file and line"

    # --- population: uniqueness at scale, not on a 200-row sample ---
    pop = C.load_population()
    ids = [r["finding_uid"] for r in pop]
    dup = [i for i, n in Counter(ids).items() if n > 1]
    ev.show(f"shipped population: {len(ids)} findings, {len(set(ids))} distinct finding_uid, "
            f"{len(dup)} duplicate(s)")
    assert not dup, f"{len(dup)} duplicate finding_uid in the shipped population"
