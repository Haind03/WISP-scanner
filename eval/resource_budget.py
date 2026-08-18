#!/usr/bin/env python3
"""One resource budget for every tool: a wall clock and a resident-memory ceiling.

The equal-budget protocol gives every tool the same wall clock and scores whatever it fails to
produce inside it as a miss. Memory was left unbudgeted, and that turned out to matter. wp-taint-scan
is configured with `-mem-limit-mb 2048`, which its own flag help calls a soft ceiling that "a fast
single-statement allocation burst can still exceed", recommending instead that each plugin run in a
memory-capped subprocess. On the corpus it blew through that ceiling to 13.2 GB of resident memory on
a 15.7 GB host, and the kernel out-of-memory killer answered. That is the worst possible failure mode
for a measurement, for two reasons. It is global, so the kernel may kill a sibling scan that did
nothing wrong, which is where a burst of archive-extraction errors in one cell came from. And it is
unattributable, because a record lost that way reads in the results exactly like a tool that found
nothing, so it depresses coverage and patch-file success and looks like a capability difference.

So the budget is declared and enforced here instead. The process runs in its own session, its
resident set is sampled, and crossing the ceiling stops it the same way crossing the wall clock does,
with a distinct label. A ceiling hit is then a fact about the tool on that input under a stated
budget, which is the same kind of fact a timeout is, and it is scored the same way.

Resident memory is the quantity to bound, not address space. Measured on this corpus the virtual
mapping runs 1.9 to 3.7 times the resident set, so an address-space rlimit tight enough to stop a
runaway also kills ordinary scans, while resident memory is both what the tool actually consumes and
what the kernel counts when it chooses a victim.
"""
from __future__ import annotations
import os, re, signal, subprocess, sys, tempfile, time

# Sampling interval for the resident set. Fine enough to stop a runaway well before it can threaten
# the host, coarse enough to cost nothing against scans that run for tens of seconds.
POLL_S = 0.2

# A per-process ceiling bounds one scan and says nothing about several at once. Concurrent scans can
# still add up to more than the host has, and if they do the kernel picks a victim, which is the
# unattributable failure this module exists to prevent. So the host's own free memory is watched too,
# and a scan running while it falls through the floor is recorded as measured under host pressure
# rather than as a result. It is a distinct label from the ceiling on purpose: the ceiling is a fact
# about the tool, and the floor is a fact about the run, and only one of them is publishable.
HOST_FLOOR_MB = 1536


_RSS = re.compile(r"VmRSS:\s+(\d+) kB")

# Peak resident set of the most recent run_capped call in THIS process, so a caller can record what
# each scan actually cost without threading a return value through three tool adapters. Safe because
# every scan runs in its own pool worker process and the calls inside one worker are serial. A budget
# nobody can audit per record is a budget a reader has to take on trust.
LAST_PEAK_KB = 0


class BudgetExceeded(Exception):
    """Raised with 'timeout' or 'mem_cap_exceeded'. The caller turns it into a ToolFailure.

    Carries the peak resident set observed before the process was stopped, because how close a
    tool came to the ceiling is the evidence for whether the ceiling is set fairly."""

    def __init__(self, reason, peak_kb=0):
        super().__init__(reason)
        self.reason, self.peak_kb = reason, peak_kb


def _rss_kb(pid):
    """Resident set of one process, or None once it is gone or reaped to a zombie."""
    try:
        with open(f"/proc/{pid}/status") as fh:
            m = _RSS.search(fh.read())
    except OSError:
        return None
    return int(m.group(1)) if m else None


def _tree_rss_kb(pid):
    """Resident set of the process and its children.

    A tool that forks (wp-taint-scan re-invokes itself, semgrep and progpilot may spawn helpers)
    would otherwise hide most of its footprint from a ceiling that only watched the parent."""
    total = _rss_kb(pid)
    if total is None:
        return None
    try:
        with open(f"/proc/{pid}/task/{pid}/children") as fh:
            kids = fh.read().split()
    except OSError:
        return total
    for k in kids:
        child = _tree_rss_kb(int(k))
        if child:
            total += child
    return total


def _host_available_mb():
    """Memory the host could hand out right now, or None where /proc/meminfo is unavailable."""
    try:
        with open("/proc/meminfo") as fh:
            for line in fh:
                if line.startswith("MemAvailable:"):
                    return int(line.split()[1]) // 1024
    except OSError:
        pass
    return None


def _kill_group(p):
    try:
        os.killpg(os.getpgid(p.pid), signal.SIGKILL)
    except (ProcessLookupError, PermissionError):
        try:
            p.kill()
        except ProcessLookupError:
            pass
    try:
        p.wait(timeout=10)
    except subprocess.TimeoutExpired:
        pass


def run_capped(cmd, budget_s, mem_cap_mb, capture=True, **popen_kw):
    """Run cmd under both budgets. Returns a CompletedProcess-like result on normal exit.

    Raises BudgetExceeded('timeout') or BudgetExceeded('mem_cap_exceeded'). The whole process group
    is killed either way, because the tools spawn children and killing only the parent leaves them
    running, which has cost us two eval runs already."""
    if mem_cap_mb is None:
        raise ValueError("run_capped needs a memory ceiling; call subprocess directly if you want none")
    kw = dict(popen_kw)
    kw.setdefault("start_new_session", True)
    # Capture through temporary files, never pipes. This loop does not read while it waits, and a
    # tool that fills the 64 KB pipe buffer would block forever on a write nobody is draining.
    # semgrep --json on a large plugin emits megabytes, so a pipe here is a deadlock, not a risk.
    fout = ferr = None
    if capture:
        fout, ferr = tempfile.TemporaryFile(), tempfile.TemporaryFile()
        kw["stdout"], kw["stderr"] = fout, ferr
        kw.pop("text", None)
    global LAST_PEAK_KB
    LAST_PEAK_KB = 0
    p = subprocess.Popen(cmd, **kw)
    cap_kb = mem_cap_mb * 1024
    t0 = time.time()
    peak_kb = 0
    try:
        while True:
            rc = p.poll()
            if rc is not None:
                break
            rss = _tree_rss_kb(p.pid)
            if rss:
                peak_kb = LAST_PEAK_KB = max(peak_kb, rss)
                if rss > cap_kb:
                    _kill_group(p)
                    raise BudgetExceeded("mem_cap_exceeded", peak_kb)
            avail = _host_available_mb()
            if avail is not None and avail < HOST_FLOOR_MB:
                _kill_group(p)
                # Loud, because this one invalidates a cell and the sooner a run is stopped and
                # restarted with fewer workers the less machine time is thrown away.
                print(f"HOST_MEMORY_FLOOR: {avail} MB available, below {HOST_FLOOR_MB} MB, "
                      f"stopped a scan at {peak_kb // 1024} MB", file=sys.stderr, flush=True)
                raise BudgetExceeded("host_memory_floor", peak_kb)
            if time.time() - t0 > budget_s:
                _kill_group(p)
                raise BudgetExceeded("timeout", peak_kb)
            time.sleep(POLL_S)
        out = err = ""
        if capture:
            for fh, name in ((fout, "out"), (ferr, "err")):
                fh.seek(0)
                data = fh.read().decode("utf-8", "replace")
                if name == "out":
                    out = data
                else:
                    err = data
        return subprocess.CompletedProcess(cmd, p.returncode, out, err), peak_kb
    finally:
        for fh in (fout, ferr):
            if fh is not None:
                fh.close()
