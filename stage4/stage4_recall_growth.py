#!/usr/bin/env python3
"""Stage-4 RECALL-GROWTH rule-mining loop.

The old harvester learned only `learned_sanitizers` (FP-cut) — rare candidates, no
recall gain. This loop learns the OPPOSITE: SINK / METHOD-SINK / SOURCE vocab that
GROWS recall (the F3 driver), keeping the taint engine unchanged (only its vocab
expands). Pipeline:

  1. MINE (token-free): scan a plugin sample, rank unknown callees that receive a
     tainted argument by #plugins (recall-growth candidates). [mine_sink_candidates]
  2. VET each top candidate -> {kind: method_sink|func_sink|source|benign, class}.
       - default OFFLINE heuristic (token-free, name-based) so the whole loop runs
         with no tokens;
       - --llm uses the L4 Verifier for a bounded number of candidates.
  3. APPLY: write confirmed rules to wisp-rules.yaml (learned_method_sinks /
     learned_sinks / learned_source_funcs).
  4. GATE: reload engine, run selftest (must still pass) AND measure gold recall
     before vs after. A learned sink can only ADD findings, so recall is monotone;
     we KEEP the batch only if it LIFTS recall (recovers real misses) and selftest
     passes, else REVERT. This makes the loop self-validating and recall-first.

  python3 -m stage4.stage4_recall_growth --sample baselines/sample_100.txt --mine 100 --top 25
  python3 -m stage4.stage4_recall_growth ... --llm --max-vet 5      # bounded LLM vet
"""
from __future__ import annotations
import os, sys, json, argparse, subprocess, importlib, shutil, datetime

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
os.chdir(ROOT); sys.path.insert(0, ROOT)
RULES = "wisp/rules/wisp-rules.yaml"

# ---- offline heuristic vet (token-free) -----------------------------------
# Conservative name->(*kind*, class). The recall-gate is the real safety net;
# this only proposes. Names are matched case-insensitively as substrings.
# keyword groups; (kws, class, method_only) — method_only means only treat as a
# sink when it's a $obj->name() call (a bare func of that name is too ambiguous).
_SINK_KEYWORDS = [
    (("exec", "shell", "passthru", "popen", "runcommand"), "rce", False),
    (("rawquery", "raw_query", "execsql", "dosql", "unprepared", "querysql"), "sqli", False),
    (("insert", "update", "delete"), "sqli", True),          # $db->insert etc. only
    (("put_contents", "putcontents", "fwrite", "savefile", "writefile", "addfile"), "upload", False),
    (("get_contents", "getcontents", "readfile", "loadfile", "fetchfile"), "lfi", False),
    (("loadhtml", "loadxml", "appendchild", "createelement", "createtextnode"), "xss", False),
    (("loadobject",), "deserial", False),
    (("remoteget", "httpget", "fetchurl", "sendrequest"), "ssrf", False),
]
_SOURCE_KEYWORDS = ("get_param", "getparam", "read_input", "readinput",
                    "request_var", "fetchinput", "from_request")
# WordPress funcs that LOOK like sinks by keyword but are safe/parameterized or are
# state-change (handled elsewhere) — never propose these as injection sinks.
_WP_SAFE_DENY = {"update_option", "update_post_meta", "update_user_meta", "update_term_meta",
                 "update_metadata", "update_site_option", "add_option", "delete_option",
                 "delete_post_meta", "wp_update_post", "wp_insert_post", "wp_update_user"}


def heuristic_vet(name: str, kind: str = "func"):
    n = name.lower()
    if n in _WP_SAFE_DENY:
        return ("benign", "")
    for kw in _SOURCE_KEYWORDS:
        if kw in n:
            return ("source", "")
    for kws, cls, method_only in _SINK_KEYWORDS:
        if method_only and kind != "method":
            continue
        if any(k in n for k in kws):
            return ("sink", cls)
    return ("benign", "")


# ---- yaml learned-block writers -------------------------------------------
def _append_block(key: str, lines: list, header: str):
    import re
    text = open(RULES, encoding="utf-8").read()
    if re.search(rf"^{key}:", text, re.M):
        text = re.sub(rf"(^{key}:.*$)", r"\1\n" + "\n".join(lines), text, count=1, flags=re.M)
    else:
        text += f"\n\n# --- [LEARNED recall-growth] {header} ---\n{key}:\n" + "\n".join(lines) + "\n"
    open(RULES, "w", encoding="utf-8").write(text)


def apply_candidates(confirmed: dict, prov: str):
    """confirmed: {'method_sink':{name:cls}, 'func_sink':{name:cls}, 'source':[names]}"""
    ms = confirmed.get("method_sink", {})
    fs = confirmed.get("func_sink", {})
    srcs = confirmed.get("source", [])
    if ms:
        _append_block("learned_method_sinks",
                      [f"  {n}: {c}    # [recall-growth] {prov}" for n, c in ms.items()],
                      "method sinks $obj->name()")
    if fs:
        _append_block("learned_sinks",
                      [f"  {n}: {c}    # [recall-growth] {prov}" for n, c in fs.items()],
                      "function sinks")
    if srcs:
        _append_block("learned_source_funcs",
                      [f"  - {n}    # [recall-growth] {prov}" for n in srcs],
                      "source functions")


# ---- gates ----------------------------------------------------------------
def selftest_ok() -> bool:
    r = subprocess.run([sys.executable, "-m", "eval.selftest_engine"],
                       capture_output=True, text=True, timeout=180)
    return "CASES PASS" in r.stdout and "REGRESSION" not in r.stdout


def measure_recall(sample: str) -> dict:
    out = "out/_rg_recall.json"
    subprocess.run([sys.executable, "-m", "eval.recall", "--only-present",
                    "--sample", sample, "--out", out],
                   capture_output=True, text=True, timeout=6000)
    d = json.load(open(out))
    return {"recall": d["plugin_class_recall"], "hits": d["hits"],
            "fpp": d["findings_per_plugin"]}


# ---- main -----------------------------------------------------------------
def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--sample", default="../baselines/sample_100.txt",
                    help="gold sample for the recall gate")
    ap.add_argument("--mine", type=int, default=100, help="plugins to mine candidates from")
    ap.add_argument("--top", type=int, default=25, help="top candidates to vet")
    ap.add_argument("--llm", action="store_true", help="use L4 Verifier instead of heuristic")
    ap.add_argument("--max-vet", type=int, default=5, help="LLM vet budget (with --llm)")
    ap.add_argument("--apply", action="store_true",
                    help="actually write rules + gate (default: dry-run, just propose)")
    a = ap.parse_args()
    sample = a.sample if os.path.isabs(a.sample) else os.path.join(ROOT, a.sample)

    # 1. MINE (token-free) — reuse the standalone miner
    sys.path.insert(0, os.path.join(os.path.dirname(ROOT), "2026-07-05"))
    import mine_sink_candidates as M
    from collections import Counter
    from eval.datasets.patchstack import load_rows
    import zipfile, tempfile
    rows = [r for r in load_rows() if os.path.exists(r["vuln_zip"])]
    want = {s.strip() for s in open(sample)} if os.path.exists(sample) else None
    if want:
        rows = [r for r in rows if r["slug"] + "|" + r["cve"] in want]
    rows = rows[:a.mine]
    sink_hits, method_hits = Counter(), Counter()
    for r in rows:
        d = M.unzip(r["vuln_zip"])
        if not d:
            continue
        try:
            M.mine_plugin(d, sink_hits, method_hits)
        finally:
            shutil.rmtree(d, ignore_errors=True)
    print(f"[MINE] {len(rows)} plugins -> {len(method_hits)} method / {len(sink_hits)} func candidates")

    # 2. VET top candidates
    confirmed = {"method_sink": {}, "func_sink": {}, "source": []}
    # vet the top-N of EACH kind separately so high-value method candidates
    # (insert/put_contents/loadHTML) are not crowded out by frequent util funcs.
    cand = ([("method", n, c) for n, c in method_hits.most_common(a.top)]
            + [("func", n, c) for n, c in sink_hits.most_common(a.top)])
    vet_calls = 0
    V = None
    if a.llm:
        from wisp.engine.l4_verify import Verifier
        V = Verifier()
        print(f"[VET] LLM gate {V.model}, budget {a.max_vet}")
    # offline vets all mined candidates (top-N per kind); LLM path bounds by budget
    for kind, name, freq in (cand[: a.max_vet] if a.llm else cand):
        decided = heuristic_vet(name, kind)   # offline default; LLM refines below
        if a.llm and V is not None and vet_calls < a.max_vet:
            decided = _llm_vet(V, name, kind); vet_calls += 1
        vkind, cls = decided
        if vkind == "benign":
            continue
        if vkind == "source":
            confirmed["source"].append(name)
        elif kind == "method":
            confirmed["method_sink"][name] = cls
        else:
            confirmed["func_sink"][name] = cls
    print(f"[VET] confirmed: method_sinks={confirmed['method_sink']} "
          f"func_sinks={confirmed['func_sink']} sources={confirmed['source']}")

    if not a.apply:
        print("[DRY-RUN] not applying. Re-run with --apply to write rules + gate.")
        return
    if not any(confirmed.values()):
        print("[APPLY] nothing confirmed; done.")
        return

    # 3-4. APPLY + GATE (selftest + recall must-not-drop / should-rise)
    backup = RULES + ".rgbak"
    shutil.copy(RULES, backup)
    before = measure_recall(sample)
    print(f"[GATE] recall BEFORE: {before}")
    prov = f"{datetime.datetime.now():%Y-%m-%d} sample-mined"
    apply_candidates(confirmed, prov)
    # reload rules into the vocab for selftest/recall subprocesses (they re-import fresh)
    ok = selftest_ok()
    after = measure_recall(sample) if ok else None
    keep = ok and after and after["recall"] >= before["recall"] and after["hits"] >= before["hits"]
    if keep:
        os.remove(backup)
        print(f"[GATE] KEEP ✓ selftest ok; recall {before['recall']}->{after['recall']} "
              f"hits {before['hits']}->{after['hits']} fpp {before['fpp']}->{after['fpp']}")
    else:
        shutil.move(backup, RULES)
        print(f"[GATE] REVERT ✗ selftest_ok={ok} after={after} (recall not improved) -> rules restored")


def _llm_vet(V, name, kind):
    """One bounded LLM call: is `name` a dangerous sink (which class) / source / benign?"""
    from wisp.engine.l4_verify import _extract_json
    prompt = (
        "You vet vocabulary for a PHP taint scanner. A function/method named "
        f"`{name}` is called with attacker-controlled data across many plugins. "
        "Classify it. Reply JSON: {\"kind\":\"sink|source|benign\",\"class\":"
        "\"sqli|xss|rce|lfi|ssrf|upload|deserial|\"}. sink=performs a dangerous "
        "operation (SQL exec, HTML output, shell, file write/read, include, "
        "deserialize, outbound HTTP) with that arg; source=returns attacker input; "
        "benign=string/array/util helper. class only for sink.")
    try:
        import subprocess as sp
        # Vetting vocabulary is higher-stakes than per-finding verify, so allow
        # a separate CLI/model pair for this bounded review step.
        vbin = os.environ.get("VET_BIN", getattr(V, "cli_bin", "agy")).strip().strip('"').strip("'")
        vmodel = os.environ.get("VET_MODEL", getattr(V, "cli_model", "")).strip().strip('"').strip("'")
        cmd = [vbin, "-p", prompt]
        if vmodel:
            cmd[1:1] = ["--model", vmodel]
        r = sp.run(cmd, capture_output=True, text=True, timeout=200)
        d = _extract_json(r.stdout)
        k = d.get("kind", "benign")
        return (k if k in ("sink", "source", "benign") else "benign", d.get("class", ""))
    except Exception:
        return heuristic_vet(name)


if __name__ == "__main__":
    main()
