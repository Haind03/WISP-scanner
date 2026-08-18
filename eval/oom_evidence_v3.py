#!/usr/bin/env python3
"""Capture the kernel's own record of the out-of-memory kills, before it scrolls away.

The manuscript states how large a single scan grew before the host stopped it. That number cannot
come from the harness, because the harness is exactly what was not watching, and it cannot be typed
into the text either, because every primary number in this paper is generated from a result file.
Its only source is the kernel ring buffer, which is per-boot and volatile, so it is captured here
into a result file like any other measurement.

    python3 -m eval.oom_evidence_v3

Writes OOM_EVIDENCE_V3.json: one entry per kill, with the process name and its resident and virtual
size at death, plus the count of records lost in the cell that the kills contaminated. Re-running it
merges by (boot_id, pid) so a later capture never drops an earlier boot's evidence.
"""
from __future__ import annotations
import os, re, json, glob, time, subprocess, collections

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
SYS_ROOT = os.path.dirname(ROOT)
OUT = os.path.join(SYS_ROOT, "revision-cns-v2", "out")
CELL_DIR = os.path.join(SYS_ROOT, "revision-cns-v2", "baseline_v3", "cells")
DST = os.path.join(OUT, "OOM_EVIDENCE_V3.json")

KILL = re.compile(
    r"Out of memory: Killed process (\d+) \((\S+)\) total-vm:(\d+)kB, anon-rss:(\d+)kB")


def _boot_id():
    for p in ("/proc/sys/kernel/random/boot_id",):
        try:
            return open(p).read().strip()
        except OSError:
            pass
    return "unknown"


def _dmesg():
    for cmd in (["dmesg"], ["journalctl", "-k", "--no-pager"]):
        try:
            r = subprocess.run(cmd, capture_output=True, text=True, timeout=30)
            if r.returncode == 0 and r.stdout:
                return r.stdout
        except (OSError, subprocess.SubprocessError):
            continue
    return ""


def _contaminated_cells():
    """Records lost to host failure in any cell still on disk, from the cell files themselves."""
    host = ("nonzero_exit:-9", "nonzero_exit:-15", "host_memory_floor")
    rows = []
    for f in sorted(glob.glob(os.path.join(CELL_DIR, "*.json"))
                    + glob.glob(os.path.join(CELL_DIR, "**", "*.json"))):
        try:
            d = json.load(open(f))
        except (OSError, ValueError):
            continue
        det = d.get("details")
        if not isinstance(det, list):
            continue
        c = collections.Counter(x.get("err") for x in det if x.get("err"))
        killed = sum(v for k, v in c.items() if k in host)
        archive = c.get("archive_extract_error", 0)
        if killed or archive > 0.01 * len(det):
            rows.append({"cell_file": os.path.relpath(f, SYS_ROOT), "n_records": len(det),
                         "killed": killed, "archive_extract_error": archive,
                         "lost_to_host": killed + archive,
                         "workers": (d.get("provenance") or {}).get("workers")})
    return rows


def main():
    prev = {}
    if os.path.isfile(DST):
        for e in json.load(open(DST)).get("kills", []):
            prev[(e["boot_id"], e["pid"])] = e
    boot = _boot_id()
    for m in KILL.finditer(_dmesg()):
        pid, name, vm_kb, rss_kb = int(m.group(1)), m.group(2), int(m.group(3)), int(m.group(4))
        prev[(boot, pid)] = {"boot_id": boot, "pid": pid, "process": name,
                             "total_vm_kb": vm_kb, "anon_rss_kb": rss_kb,
                             "anon_rss_gb": round(rss_kb / 1048576, 2),
                             "total_vm_gb": round(vm_kb / 1048576, 2)}
    kills = sorted(prev.values(), key=lambda e: (e["boot_id"], e["pid"]))
    by_proc = {}
    for e in kills:
        by_proc.setdefault(e["process"], []).append(e["anon_rss_gb"])
    out = {"schema_version": "oom-evidence-v3",
           "note": "kernel ring buffer is per-boot and volatile; entries merge by (boot_id, pid) "
                   "across captures, so an earlier boot's evidence survives a later run",
           "host_ram_gb": round(os.sysconf("SC_PAGE_SIZE") * os.sysconf("SC_PHYS_PAGES") / 2**30, 1),
           "n_kills": len(kills), "kills": kills,
           "max_anon_rss_gb_by_process": {k: max(v) for k, v in sorted(by_proc.items())},
           "contaminated_cells": _contaminated_cells(),
           "generated_utc": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())}
    json.dump(out, open(DST, "w"), indent=1)
    print(f"wrote {os.path.relpath(DST, SYS_ROOT)}: {len(kills)} kill(s), "
          f"host {out['host_ram_gb']} GB")
    for k, v in out["max_anon_rss_gb_by_process"].items():
        print(f"  largest kill of {k}: {v} GB resident")
    for c in out["contaminated_cells"]:
        print(f"  contaminated: {os.path.basename(c['cell_file'])[:52]:54} "
              f"lost {c['lost_to_host']} of {c['n_records']} at {c['workers']} workers")


if __name__ == "__main__":
    main()
