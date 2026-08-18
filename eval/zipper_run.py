#!/usr/bin/env python3
"""Score ZIPPER (USENIX Security '25) on the taint-representable slice of the corpus.

ZIPPER is the strongest published PHP taint engine and its artifact is public, so the paper
should report it rather than argue non-comparability from the sidelines. It only models
taint-style classes, so it is scored on the 686 records whose advisory class is not
missing-guard (auth/csrf), which is the subset where the comparison is meaningful at all.

Fairness contract, mirroring the other baselines in fullcorpus_atk.py:
  * ZIPPER runs with the README's RQ1 default flags, which is its best-performing config.
  * Findings keep ZIPPER's own emission order, exactly as Semgrep keeps its severity order.
  * Ground truth, class mapping, and the @K metric all come from the shared harness, so no
    endpoint is redefined in ZIPPER's favour or against it.
  * A record ZIPPER fails or times out on is an error, not a silent drop (failure-as-miss).
"""
import os, re, sys, json, argparse, shutil, subprocess, tempfile, random, time
from multiprocessing import Pool

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from eval.testset.scan_testset import ToolFailure, _gt, map_class, _keyof
from eval.datasets.patchstack import load_rows
from eval.fullcorpus_atk import _unzip

KS = (1, 3, 5, 10)
IMAGE = os.environ.get("ZIPPER_IMAGE", "zipper-public:v4")
JAR = "/tool/zipper-scan-jar-with-dependencies.jar"

# Docker Desktop cannot bind-mount a path inside the WSL filesystem: the container just sees an
# empty directory, ZIPPER parses nothing, and every record silently scores zero findings. The
# scan copy therefore has to live on a Windows-drive path that the daemon can actually share.
WORK = os.environ.get("ZIPPER_WORK") or os.path.join(
    os.environ.get("WISP_SYS_ROOT") or os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__)))),
    "zipper", "work")

# The comparison runs on the records whose advisory class ZIPPER's vocabulary can express at
# all, which is the most generous scoping available to it. Two separate limits carve this out:
# auth and csrf are missing-guard classes that no taint engine can represent, because an absent
# check is not a flow; and deserial, ssrf, upload, and other have no counterpart in ZIPPER's
# five VulnKind values. Scoring ZIPPER where it has no rule would measure our corpus, not ZIPPER.
ZIPPER_CLASSES = {"xss", "sqli", "rce", "lfi"}

RQ1_FLAGS = ["--enable-sanitizer-keyword-match", "--enable-enhanced-dynamic-call",
             "--enable-global-data-dependency", "--enable-ondemand-alias-analysis",
             "--enable-reachability-analysis"]

# At the JVM's defaults a chunk of the corpus dies with an uncaught StackOverflowError in
# IterativeDynamicCallPass.findMethod, which recurses through the dynamic-call graph that
# --enable-enhanced-dynamic-call asks for. ZIPPER catches that error in its alias analysis but
# not in this pass, so the process exits 1 with no result. Reporting that as a ZIPPER failure at
# stock defaults would be blaming the tool for our configuration, so every run gets a 512 MB
# thread stack and a 10 GB heap. Neither flag changes what the analysis computes, only whether it
# survives computing it, so a tuned rerun cannot alter a record that already completed, and it can
# only ever help ZIPPER. A failure that persists here is reported as the tool's.
JVM_FLAGS = ["-Xss512m", "-Xmx10g"]

# The recursion that overflows lives in the dynamic-call linking pass, which is what
# --enable-enhanced-dynamic-call turns on. Dropping just that flag lets the same plugin complete
# (exit 0, a well-formed empty result), so a crash is not evidence that ZIPPER cannot analyze the
# plugin at all, only that its best-performing configuration cannot. Every crashed record is
# therefore retried once on this reduced configuration and the surviving config is recorded per
# record, so the paper can separate "ZIPPER crashed" from "ZIPPER completed with a weaker
# analysis". The fallback is strictly generous on coverage, but it disables a precision feature
# ZIPPER's own RQ1 config enables, so results carrying it are reported as such and never silently
# merged into the headline configuration.
FALLBACK_FLAGS = [f for f in RQ1_FLAGS if f != "--enable-enhanced-dynamic-call"]


def _unzip_visible(path):
    """Extract onto a daemon-visible path. Only the vulnerable tree needs this: the patched
    tree is read by the host to build ground truth and never enters a container."""
    import zipfile
    os.makedirs(WORK, exist_ok=True)
    d = tempfile.mkdtemp(dir=WORK)
    try:
        zipfile.ZipFile(path).extractall(d)
    except Exception:
        shutil.rmtree(d, ignore_errors=True)
        return None
    return d


def _zipper_ranked(vroot, budget, flags=None, jvm=None):
    """Run ZIPPER in its own container over vroot and return harness-shaped ranked rows.

    ZIPPER writes its result under ./output relative to the working directory, so the scan runs
    in a container-local directory and the JSON is streamed back on stdout. Binding a host
    directory for output was silently unreliable here, and a lost result file would be scored
    as a ZIPPER failure, which is precisely the unfairness the Progpilot exit-code bug caused.
    A run that finds nothing still emits {"clusterSize": 0, "clusters": []}, so an empty
    stdout means the tool really failed and is reported as an error rather than as zero hits.
    """
    name = f"zip_{os.getpid()}_{int(time.time()*1000)%10**7}"
    # java's stderr is kept, not discarded, so a heap exhaustion can be told apart from a genuine
    # ZIPPER crash. Running two workers on this box means each JVM gets a smaller heap, and a
    # record that dies for want of heap must never be scored as a ZIPPER failure: that would blame
    # the tool for our scheduling. On failure the stderr tail is echoed after a marker so the
    # caller can classify it.
    # java's own exit status has to be captured inside the container. bash keeps going after java
    # dies, so docker's exit code is the trailing `if`, not java's, and a JVM killed by the kernel
    # would otherwise surface as a clean exit with no result.
    inner = ("cd /tmp && java %s -jar %s taint %s --language PHP /target "
             ">/dev/null 2>/tmp/j.err; JRC=$?; "
             "if [ -s /tmp/output/taint-analysis-result.json ]; then "
             "cat /tmp/output/taint-analysis-result.json; else "
             "echo \"___ZIPFAIL___$JRC\"; "
             # The throwable is named on the FIRST line of a trace and these traces run to tens of
             # thousands of frames, so a tail of the stderr loses exactly the word that classifies
             # the failure. Grep the whole file for the names that matter, then add a tail for
             # anything unrecognised.
             "grep -ohE 'OutOfMemoryError|GC overhead limit exceeded|StackOverflowError' "
             "/tmp/j.err | sort -u; "
             "echo '___TAIL___'; tail -c 600 /tmp/j.err; fi"
             % (" ".join(jvm or JVM_FLAGS), JAR, " ".join(flags or RQ1_FLAGS)))
    cmd = ["docker", "run", "--rm", "--name", name, "--security-opt", "seccomp=unconfined",
           "-v", f"{os.path.abspath(vroot)}:/target:ro", IMAGE, "bash", "-c", inner]
    try:
        p = subprocess.run(cmd, capture_output=True, text=True, timeout=budget)
    except subprocess.TimeoutExpired:
        # the docker client is dead but the container is not: reap it or it leaks a JVM
        subprocess.run(["docker", "rm", "-f", name], capture_output=True)
        raise ToolFailure("timeout")
    out = p.stdout.strip()
    if not out:
        tail = (p.stderr or "").strip().splitlines()
        raise ToolFailure(f"no_output:{p.returncode}:{tail[-1][:50] if tail else ''}")
    if out.startswith("___ZIPFAIL___"):
        rest = out[len("___ZIPFAIL___"):]
        jrc, _, rest = rest.partition("\n")
        found, _, tail = rest.partition("___TAIL___")
        jrc, found = jrc.strip(), found.strip()
        # Two failures here are ours, not ZIPPER's, and both must be kept out of its score.
        # A JVM that ran out of heap names the error somewhere on stderr. A JVM the kernel OOM
        # killer took names nothing at all and exits 137, which is the mode that silently cost 12
        # records in the first sweep. Either way the record is redone later at a full heap.
        if "OutOfMemoryError" in found or "GC overhead" in found or jrc == "137":
            raise ToolFailure("oom_our_config")
        if "StackOverflowError" in found:
            raise ToolFailure(f"no_output:{jrc}:StackOverflowError")
        last = [l for l in tail.splitlines() if l.strip()]
        raise ToolFailure(f"no_output:{jrc}:{last[-1][:50] if last else 'no stderr'}")
    try:
        data = json.loads(out)
    except json.JSONDecodeError:
        raise ToolFailure("malformed_json")
    return _rows(data, vroot)


# ZIPPER's whole vocabulary, read off VulnKind.scala in the artifact. The shared map_class()
# must NOT be used on these: it keys on hyphenated rule text, so "CmdInjection" and
# "CodeInjection" match nothing and would silently fall through to "other", which would
# understate ZIPPER's class emission through a harness artefact rather than a real limit.
ZIPPER_KIND = {
    "Xss": "xss",
    "SqlInjection": "sqli",
    "CmdInjection": "rce",     # our rce class covers command execution
    "CodeInjection": "rce",    # ... and code execution
    "FileInclusion": "lfi",
}


def _rows(data, vroot):
    """Flatten ZIPPER clusters into {file, line, classes}, keeping ZIPPER's own order.

    A cluster is one distinct sink, which is ZIPPER's own analyst-facing unit and the closest
    match to a WISP/Semgrep finding. Counting each redundant flow to the same sink instead
    would inflate the denominator and depress ZIPPER's per-finding precision unfairly.
    """
    if not isinstance(data, dict) or not isinstance(data.get("clusters"), list):
        raise ToolFailure("invalid_schema")
    rows = []
    for c in data["clusters"]:
        if not isinstance(c, dict):
            continue
        kind = str(c.get("kind", ""))
        cls = ZIPPER_KIND.get(kind)
        if cls is None:  # unknown kind: keep the finding, do not invent a class for it
            cls = map_class(kind)
        f, ln = _sink_loc(c)
        if not f:
            continue
        rows.append({"file": _keyof(f, vroot).replace(os.sep, "/"), "line": ln,
                     "classes": [cls], "rule": kind})
    return rows


def _sink_loc(cluster):
    """Sink file/line: last node of a taint path, falling back to the 'file:line code' string."""
    for v in cluster.get("vulns", []) or []:
        path = v.get("path") or []
        if path and isinstance(path[-1], dict) and path[-1].get("file"):
            last = path[-1]
            return str(last["file"]), int(last.get("line") or 0)
    m = re.match(r"^(.*):(\d+)\s", str(cluster.get("sink", "")))
    return (m.group(1), int(m.group(2))) if m else (None, 0)


def scan_one(task):
    r, budget = task
    res = {"slug": r["slug"], "cve": r["cve"], "cls": r["cls"], "err": "",
           "config": "rq1", "rq1_err": "",
           "gt_files": 0, "findings": 0, "file_tp": 0,
           "topk_tp": {str(k): 0 for k in KS}, "topk_n": {str(k): 0 for k in KS},
           "top10": [], "detected": [], "hit": False, "secs": 0.0}
    t0 = time.time()
    vzip, pzip = r["vuln_zip"], r["patched_zip"]
    if not (os.path.isfile(vzip) and os.path.isfile(pzip)):
        res["err"] = "missing_archive"; return res
    vroot = proot = None
    try:
        vroot, proot = _unzip_visible(vzip), _unzip(pzip)
        if not (vroot and proot):
            res["err"] = "archive_extract_error"; return res
        gt = set(_gt(vroot, proot).keys())
        res["gt_files"] = len(gt)
        try:
            ranked = _zipper_ranked(vroot, budget)
        except ToolFailure as e:
            # A crash (no result file) is retried once without the dynamic-call flag that owns the
            # overflow. A timeout is not retried: the budget here already exceeds the slowest
            # record that ever completed, so a second slower-to-no-avail pass would only measure
            # our patience. Both outcomes are recorded, never silently dropped.
            if not str(e).startswith("no_output"):
                res["err"] = str(e); return res
            res["rq1_err"] = str(e)
            try:
                ranked = _zipper_ranked(vroot, budget, flags=FALLBACK_FLAGS)
                res["config"] = "rq1_minus_dyncall"
            except ToolFailure as e2:
                res["err"] = f"fallback_{e2}"; return res
            except Exception as e2:
                res["err"] = f"harness:{type(e2).__name__}"; return res
        except Exception as e:
            res["err"] = f"harness:{type(e).__name__}"; return res
        files = [f["file"] for f in ranked]
        res["detected"] = sorted({c for f in ranked for c in f.get("classes", [])})
        res["hit"] = r["cls"] in res["detected"]
        res["findings"] = len(files)
        res["file_tp"] = sum(1 for f in files if f in gt)
        for k in KS:
            top = files[:k]
            res["topk_n"][str(k)] = len(top)
            res["topk_tp"][str(k)] = sum(1 for f in top if f in gt)
        res["top10"] = files[:10]
    finally:
        for d in (vroot, proot):
            shutil.rmtree(d, ignore_errors=True) if d else None
        res["secs"] = round(time.time() - t0, 1)
    return res


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--out", required=True)
    ap.add_argument("--workers", type=int, default=4)
    ap.add_argument("--budget", type=int, default=300, help="seconds per record")
    ap.add_argument("--sample", type=int, default=0, help="0 = all taint-representable records")
    ap.add_argument("--seed", type=int, default=42)
    ap.add_argument("--only", default="", help="file of slug|cve keys; retries just these")
    ap.add_argument("--heap", default="10g", help="JVM -Xmx per worker; lower it only to fit more "
                                                  "workers, oom records are redone at full heap")
    a = ap.parse_args()
    global JVM_FLAGS
    JVM_FLAGS = [f for f in JVM_FLAGS if not f.startswith("-Xmx")] + [f"-Xmx{a.heap}"]

    rows = [r for r in load_rows() if os.path.exists(r["vuln_zip"])
            and r["cls"] in ZIPPER_CLASSES]
    if a.only:
        # Retry pass. The first sweep shared the machine with WISP and the kernel OOM-killed
        # JVMs, so a chunk of the errors are our own resource contention rather than anything
        # about ZIPPER. Those records are rerun on an idle box with a wider budget, and only a
        # failure that survives that counts against the tool.
        keys = {s.strip() for s in open(a.only) if s.strip()}
        rows = [r for r in rows if r["slug"] + "|" + r["cve"] in keys]
    if a.sample and a.sample < len(rows):
        # stratify by class so the sample keeps the subset's class mix
        by = {}
        for r in rows:
            by.setdefault(r["cls"], []).append(r)
        rng = random.Random(a.seed)
        keep = []
        for cls, rs in sorted(by.items()):
            rng.shuffle(rs)
            n = max(1, round(a.sample * len(rs) / len(rows)))
            keep.extend(rs[:n])
        rows = keep
    print(f"[zipper] {len(rows)} records, budget {a.budget}s, {a.workers} workers", flush=True)

    done = []
    if os.path.exists(a.out):  # resume: background jobs die with the session
        done = json.load(open(a.out)).get("details", [])
        # A record starved of heap by our own worker count is not a result. It is dropped from
        # the resume set so a later pass with a full heap redoes it, rather than freezing an
        # artefact of our scheduling into ZIPPER's score.
        oom = [d for d in done if d["err"] == "oom_our_config"]
        done = [d for d in done if d["err"] != "oom_our_config"]
        seen = {(d["slug"], d["cve"]) for d in done}
        rows = [r for r in rows if (r["slug"], r["cve"]) not in seen]
        print(f"[zipper] resuming, {len(done)} already done, {len(rows)} left"
              + (f", redoing {len(oom)} oom" if oom else ""), flush=True)

    with Pool(a.workers) as pool:
        for i, res in enumerate(pool.imap_unordered(scan_one, [(r, a.budget) for r in rows]), 1):
            done.append(res)
            # Checkpoint every record. A record here can occupy the whole budget, so batching the
            # writes would throw away an hour of work each time the job dies, which it does.
            json.dump({"tool": "zipper", "image": IMAGE, "flags": RQ1_FLAGS,
                       "fallback_flags": FALLBACK_FLAGS, "jvm": JVM_FLAGS,
                       "budget_s": a.budget, "details": done}, open(a.out, "w"), indent=1)
            ok = sum(1 for d in done if not d["err"])
            print(f"[zipper] {i}/{len(rows)}  ok={ok}  err={len(done)-ok}  "
                  f"{res['slug'][:24]} {res['config']} {res['err'][:24]}", flush=True)
    json.dump({"tool": "zipper", "image": IMAGE, "flags": RQ1_FLAGS, "budget_s": a.budget,
               "details": done}, open(a.out, "w"), indent=1)
    print(f"[zipper] wrote {a.out}", flush=True)


if __name__ == "__main__":
    main()
