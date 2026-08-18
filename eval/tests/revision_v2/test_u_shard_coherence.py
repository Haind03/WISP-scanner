"""U. The ten corpus localization shards must all come from the same run.

`eval/fullcorpus_failure_as_miss_v3.py` reads WISP's corpus findings by globbing
`out/paired_20260717/loc_full/loc_*.json` and merging all ten shards into one record map. It does not
check that they agree about anything, and 89 of the paper's macros come out of the result.

`eval/run_paired_loc.sh` runs the ten shards as ten independent processes and each writes its own file
when it finishes. So an interrupted run, a machine that sleeps, or one shard that dies leaves a
directory holding some shards from the new engine and some from the old one. Nothing downstream would
notice. The merged map would be a mixture of two engines, and every number derived from it would
belong to neither.

That is not hypothetical here: the shards were re-run on 2026-08-12 to move the corpus cache from an
unstamped July build onto wisp-scanner-v1.3, and the previous set is kept at
`loc_full_v12_backup/`. A partial rerun has to be finished or rolled back from that backup, never
consumed as it stands.

The check is deliberately crude, because the shards carry no provenance at all, which is the deeper
defect. Modification times within one window of each other is the only signal the files themselves
offer. If provenance is ever added to these shards, replace this with an engine-hash check.
"""
from __future__ import annotations
import os, glob
from ._common import REPO, MissingInput

SHARDS = os.path.join(REPO, "out", "paired_20260717", "loc_full", "loc_*.json")
EXPECTED = 10
# One run of ten parallel shards spans hours, so the window is generous. It is meant to catch a
# mixture of runs weeks apart, not to police minutes.
MAX_SPREAD_HOURS = 12


def _shards():
    files = sorted(glob.glob(SHARDS))
    if not files:
        raise MissingInput(SHARDS)
    return files


def test_all_ten_shards_are_present():
    files = _shards()
    assert len(files) == EXPECTED, (
        f"expected {EXPECTED} corpus localization shards, found {len(files)}: "
        f"{[os.path.basename(f) for f in files]}. A missing shard silently shrinks the corpus "
        f"denominator for every number derived from this cache.")


def test_the_shards_come_from_one_run():
    files = _shards()
    mtimes = {os.path.basename(f): os.path.getmtime(f) for f in files}
    spread_h = (max(mtimes.values()) - min(mtimes.values())) / 3600.0
    if spread_h <= MAX_SPREAD_HOURS:
        return
    newest = max(mtimes, key=mtimes.get)
    oldest = min(mtimes, key=mtimes.get)
    raise AssertionError(
        f"the corpus localization shards span {spread_h:.1f} hours, {oldest} to {newest}, so they "
        f"are not one run. Merging them mixes engines and every macro derived from "
        f"FULLCORPUS_FAILURE_AS_MISS_V3.json would belong to neither. Finish the rerun, or restore "
        f"the whole set from out/paired_20260717/loc_full_v12_backup/, before building anything.")


def test_no_shard_is_empty_or_truncated():
    """A shard killed mid-write is worse than a missing one, because the glob still finds it."""
    import json
    bad = []
    for f in _shards():
        try:
            d = json.load(open(f, encoding="utf-8"))
            if not isinstance(d.get("details"), list) or not d["details"]:
                bad.append((os.path.basename(f), "no details"))
        except Exception as e:
            bad.append((os.path.basename(f), f"{type(e).__name__}: {str(e)[:60]}"))
    assert not bad, f"corpus localization shards that cannot be read as a complete result: {bad}"
