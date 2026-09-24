#!/usr/bin/env python3
"""What a uniformly random finding inside a patched file would score at the exact-line rung.

The ladder reports P(exact line | patched file). A reviewer can reasonably ask what that
conditional probability would be for a tool that carries no information at all, that is, for a
finding placed uniformly at random on some line of a file the vendor patch changed. Without that
number the reported conditional is a level with no scale: 0.110 could be chance, or it could be
three times chance, and the manuscript did not say which.

The quantity computed here is

    chance = (changed vulnerable-side lines in modified PHP files)
             / (total vulnerable-side lines in those same files)

over the untouched 325-plugin test set, which is the corpus on this machine whose archives are
complete. That set is slug-disjoint from the development corpus, so a chance level measured on it
cannot have been tuned.

Scope of the claim, stated so it is not over-read:

  * Only PHP files the patch MODIFIED enter. A deleted file has no vulnerable-side changed line and
    a purely inserted file has no vulnerable-side target at all, which is the same rule
    patch_shape_census_v3 applies when it decides has_exact_line_target. Counting them would put
    lines in the denominator that no tool could ever hit and would depress chance artificially.
  * Lines are counted on the VULNERABLE side, because that is the tree every scanner was run over.
  * This is a file-weighted chance. It answers "pick a line uniformly at random from the changed
    files of a record". It is not finding-weighted, because findings do not distribute uniformly
    over files, and no claim is made here about how they do distribute.

    python3 -m eval.chance_baseline_v3
"""
from __future__ import annotations
import os, sys, json, time, platform, statistics

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, ROOT)
SYS_ROOT = os.path.dirname(ROOT)

from eval import patch_geometry as pg
from eval import patch_shape_census_v3 as PSC

OUT = os.path.join(SYS_ROOT, "revision-cns-v2", "out", "CHANCE_BASELINE_V3.json")


def main() -> int:
    base = os.path.join(SYS_ROOT, "2026-07-12", "testset-untouched")
    rows = PSC._manifest_rows(os.path.join(base, "testset_manifest.json"),
                             os.path.join(base, "plugins"))
    tot_changed = tot_lines = 0
    per_record, errors = [], []
    for row in rows:
        key = row["slug"] + "|" + row["cve"]
        try:
            pm = pg.build_patchmap_from_archives(row)
        except Exception as exc:
            errors.append({"key": key, "error": f"{type(exc).__name__}: {exc}"})
            continue
        c = n = 0
        for path, fd in pm.per_file.items():
            # per_file holds FileDiff as a dict, not as the dataclass, so this reads keys. Getting
            # that wrong is silent: attribute access on a dict raises, but a wrong key would have
            # returned nothing and produced a chance of zero.
            if not fd["is_php"] or fd["status"] != "modified":
                continue
            c += len(fd["changed_vuln_lines"])
            n += fd["vuln_lines"]
        if n == 0:
            continue
        tot_changed += c
        tot_lines += n
        per_record.append({"key": key, "changed": c, "lines": n, "chance": round(c / n, 6)})

    pooled = tot_changed / tot_lines if tot_lines else None
    rates = sorted(r["chance"] for r in per_record)
    res = {
        "schema_version": "chance-baseline-v3",
        "script": "eval/chance_baseline_v3.py",
        "question": ("P(a uniformly random vulnerable-side line of a modified PHP file is a line the "
                     "vendor patch changed)"),
        "population": "untouched 325-plugin test set, slug-disjoint from the development corpus",
        "rule": ("modified PHP files only, vulnerable-side line counts, deleted and pure-insertion "
                 "files excluded because they carry no vulnerable-side exact-line target"),
        "n_records_scored": len(per_record),
        "n_records_error": len(errors),
        "errors": errors[:20],
        "total_changed_lines": tot_changed,
        "total_lines": tot_lines,
        "chance_pooled": round(pooled, 4) if pooled is not None else None,
        "chance_record_median": round(statistics.median(rates), 4) if rates else None,
        "chance_record_mean": round(statistics.fmean(rates), 4) if rates else None,
        "chance_record_p25": round(rates[len(rates) // 4], 4) if rates else None,
        "chance_record_p75": round(rates[3 * len(rates) // 4], 4) if rates else None,
        "per_record": per_record,
        "timestamp_utc": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
        "python_version": platform.python_version(),
    }
    os.makedirs(os.path.dirname(OUT), exist_ok=True)
    json.dump(res, open(OUT, "w"), indent=1, sort_keys=True)
    print("wrote " + OUT)
    print("  %d records scored, %d errors" % (len(per_record), len(errors)))
    print("  pooled chance %.4f  (%d changed lines of %d)" % (pooled, tot_changed, tot_lines))
    print("  per-record median %.4f, mean %.4f, IQR [%.4f, %.4f]"
          % (res["chance_record_median"], res["chance_record_mean"],
             res["chance_record_p25"], res["chance_record_p75"]))
    return 0


if __name__ == "__main__":
    sys.exit(main())
