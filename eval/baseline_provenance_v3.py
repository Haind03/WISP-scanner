#!/usr/bin/env python3
"""Snapshot the four baseline tools and the Semgrep registry rules with real, run-time provenance.

Prompt 5 forbids depending on dynamic registry ids in the final artifact and forbids post-processing
provenance with sed. This module resolves the Semgrep registry configs to local YAML files, hashes
every rule, and records each tool's exact identity (binary/phar/commit hash, version, config), so a
re-run reads local files and the recorded hashes prove what ran.

    python3 -m eval.baseline_provenance_v3            # writes RULE_MANIFEST_V3 + TOOL_MANIFEST_V3
"""
from __future__ import annotations
import os, sys, json, time, hashlib, subprocess, platform

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, ROOT)
SYS_ROOT = os.path.dirname(ROOT)
from eval import wisp_contract as WC
OUT = os.path.join(SYS_ROOT, "revision-cns-v2", "out")
SNAP = os.path.join(SYS_ROOT, "revision-cns-v2", "baseline_v3", "semgrep_rules")
SEMGREP_CONFIGS = {"p/php": "p_php.yaml", "p/security-audit": "p_security_audit.yaml"}
# progpilot.phar declares PHP >= 8.3 and fatal-errors on this PHP 8.1 host; progpilot_ok.phar is the
# compatible build that actually runs. The fair re-run uses progpilot_ok.phar.
PROGPILOT_PHAR = os.path.join(SYS_ROOT, "baselines", "progpilot_ok.phar")
PROGPILOT_PHAR_INCOMPAT = os.path.join(SYS_ROOT, "baselines", "progpilot.phar")
WPT_DIR = os.path.join(SYS_ROOT, "external", "wp-taint-scan")


def _sha256_file(p):
    return hashlib.sha256(open(p, "rb").read()).hexdigest() if os.path.isfile(p) else ""


def _sha256_bytes(b):
    return hashlib.sha256(b if isinstance(b, bytes) else b.encode()).hexdigest()


def _run(cmd, timeout=120):
    try:
        r = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout)
        return {"cmd": " ".join(cmd), "rc": r.returncode,
                "stdout": r.stdout[-4000:], "stderr": r.stderr[-2000:]}
    except Exception as e:
        return {"cmd": " ".join(cmd), "rc": None, "error": f"{type(e).__name__}: {e}"}


def _git(dirp, *args):
    try:
        return subprocess.check_output(["git", "-C", dirp, *args],
                                       stderr=subprocess.DEVNULL).decode().strip()
    except Exception:
        return ""


# ----------------------------------------------------------------- semgrep rule snapshot
def snapshot_semgrep_rules():
    os.makedirs(SNAP, exist_ok=True)
    version = subprocess.run(["semgrep", "--version"], capture_output=True, text=True).stdout.strip()
    resolution_date = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())
    configs = {}
    try:
        import yaml
        have_yaml = True
    except Exception:
        have_yaml = False
    for reg_id, fname in SEMGREP_CONFIGS.items():
        dst = os.path.join(SNAP, fname)
        url = f"https://semgrep.dev/c/{reg_id}"
        fetch = _run(["curl", "-sS", "-L", url, "-o", dst], timeout=90)
        rules = []
        file_sha = _sha256_file(dst)
        if have_yaml and os.path.isfile(dst):
            try:
                doc = yaml.safe_load(open(dst, encoding="utf-8"))
                for r in (doc.get("rules") or []):
                    rules.append({"id": r.get("id"),
                                  "sha256": _sha256_bytes(yaml.safe_dump(r, sort_keys=True))})
            except Exception as e:
                rules = [{"parse_error": str(e)}]
        else:
            # fall back to line-based id extraction, still hashing the whole file
            for line in open(dst, encoding="utf-8", errors="ignore"):
                s = line.strip()
                if s.startswith("- id:"):
                    rules.append({"id": s.split(":", 1)[1].strip(), "sha256": ""})
        configs[reg_id] = {
            "registry_id": reg_id, "local_file": os.path.relpath(dst, SYS_ROOT),
            "file_sha256": file_sha, "n_rules": len([r for r in rules if r.get("id")]),
            "rules": rules, "fetch": {"url": url, "http_rc": fetch.get("rc")}}
    manifest = {"schema_version": "baseline-provenance-v3", "artifact_kind": "rule_manifest",
                "semgrep_version": version, "registry_resolution_date_utc": resolution_date,
                "yaml_parser": "pyyaml" if have_yaml else "line-based-fallback",
                "exact_scan_command_template":
                    "semgrep --config <local_file>... --json --timeout <budget> --quiet <target>",
                "note": "The final run uses these LOCAL yaml files via --config, not the registry id.",
                "configs": configs}
    return manifest


# ----------------------------------------------------------------- tool manifest
def _wisp_env_flags():
    """Every WISP_* flag the engine reads, with its default and the value the fair eval fixes."""
    import re
    flags = {}
    pat = re.compile(r'os\.environ\.get\("(WISP_[A-Z_]+)"(?:\s*,\s*("[^"]*"|\'[^\']*\'))?\)')
    for r, _, files in os.walk(os.path.join(ROOT, "wisp")):
        for fn in files:
            if fn.endswith(".py"):
                try:
                    txt = open(os.path.join(r, fn), encoding="utf-8", errors="ignore").read()
                except OSError:
                    continue
                for m in pat.finditer(txt):
                    default = m.group(2).strip("\"'") if m.group(2) else None
                    flags.setdefault(m.group(1), default)
    return flags


def tool_manifest():
    host = {"platform": platform.platform(), "python": platform.python_version(),
            "php": _run(["php", "--version"]).get("stdout", "").splitlines()[:1]}
    # semgrep
    semgrep = {"tool": "semgrep", "version": _run(["semgrep", "--version"]).get("stdout", "").strip(),
               "rules": "see RULE_MANIFEST_V3.json (local snapshot, not registry id)",
               "exit_code_handling": "nonzero rc tolerated if JSON parses; else counted as error"}
    # progpilot
    pv = _run(["php", PROGPILOT_PHAR, "--version"])
    progpilot = {"tool": "progpilot", "phar": os.path.relpath(PROGPILOT_PHAR, SYS_ROOT),
                 "phar_sha256": _sha256_file(PROGPILOT_PHAR),
                 "version_probe": pv.get("stdout", "")[:400] or pv.get("stderr", "")[:400],
                 "php_runtime": _run(["php", "--version"]).get("stdout", "").splitlines()[:1],
                 "compatibility_audit": {
                     "incompatible_phar": os.path.relpath(PROGPILOT_PHAR_INCOMPAT, SYS_ROOT),
                     "incompatible_phar_sha256": _sha256_file(PROGPILOT_PHAR_INCOMPAT),
                     "finding": "progpilot.phar declares PHP >= 8.3 and fatal-errors on this PHP 8.1 "
                                "host, emitting nothing; if the earlier baseline used it on PHP < 8.3, "
                                "progpilot's zero findings were a platform artifact, not a capability "
                                "result. The fair matrix uses the compatible progpilot_ok.phar."},
                 "config_rules": "progpilot built-in ruleset (default)",
                 "exit_code_handling": "progpilot may exit 1 while still emitting findings; the "
                                       "harness reads findings from the JSON regardless of exit code, "
                                       "and only a timeout or a parse failure is a miss",
                 "timeout_behavior": "subprocess killed at the per-plugin budget (process group)"}
    # wp-taint-scan
    wpt_bin = os.path.join(WPT_DIR, "bin", "taint-scan")
    wpt = {"tool": "wp-taint-scan", "dir": os.path.relpath(WPT_DIR, SYS_ROOT),
           "git_commit": _git(WPT_DIR, "rev-parse", "HEAD"),
           "git_dirty": bool(_git(WPT_DIR, "status", "--porcelain")),
           "binary": os.path.relpath(wpt_bin, SYS_ROOT), "binary_sha256": _sha256_file(wpt_bin),
           "go_mod_sha256": _sha256_file(os.path.join(WPT_DIR, "go.mod")),
           "go_sum_sha256": _sha256_file(os.path.join(WPT_DIR, "go.sum")),
           "ranking_extraction": "findings read in tool order; rank = emission order (see _wpt_ranked)",
           "exit_code_handling": "findings read from stdout JSON; nonzero rc with valid JSON is not a miss"}
    # wisp
    vocab_files = [os.path.join(ROOT, "wisp", "rules", "wisp-rules.yaml"),
                   os.path.join(ROOT, "wisp", "engine", "taint_vocab.py")]
    vocab_hash = _sha256_bytes(b"".join(open(p, "rb").read() for p in vocab_files if os.path.isfile(p)))
    wisp = {"tool": "wisp", "git_commit": _git(ROOT, "rev-parse", "HEAD"),
            "git_dirty": bool(_git(ROOT, "status", "--porcelain")),
            "taint_engine_sha256": _sha256_file(os.path.join(ROOT, "wisp", "engine", "taint_engine.py")),
            "vocabulary_files": [os.path.relpath(p, SYS_ROOT) for p in vocab_files],
            "vocabulary_sha256": vocab_hash,
            "env_flags_read": _wisp_env_flags(),
            # Read from the evaluation contract, never typed here. This block was a hand-written
            # string and by 2026-08-14 it contradicted the paper on three points at once: it claimed
            # GDA on where the paper disables it, claimed class-scoped sanitizer propagation OFF
            # "matching the manuscript prose" where both the engine default and the manuscript say
            # ON, and sat beside a taint_engine_sha256 three engine generations old. A manifest
            # whose job is to record the configuration cannot have the configuration typed into it.
            "eval_env_fixed": WC.CANONICAL_ENV,
            "eval_env_source": "eval.wisp_contract.CANONICAL_ENV (the evaluation contract), read at "
                               "generation time so this block cannot drift from the runs",
            "engine_tag": WC.ENGINE_TAG,
            "llm_disabled": True,
            "ranking_configuration": "exploitability rank, weights WISP_RANK_WFLOW=1.0/WGUARD=0.5 (defaults)",
            "timeout_behavior": "no in-process cap; the harness runs WISP in a child process group and "
                                "kills the group at the per-plugin budget (partial output DROPPED)"}
    return {"schema_version": "baseline-provenance-v3", "artifact_kind": "tool_manifest",
            "generated_utc": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
            "host": host, "tools": {"wisp": wisp, "semgrep": semgrep,
                                    "progpilot": progpilot, "wp-taint-scan": wpt}}


def main():
    os.makedirs(OUT, exist_ok=True)
    print("snapshotting semgrep registry rules to local yaml ...")
    rule_manifest = snapshot_semgrep_rules()
    json.dump(rule_manifest, open(os.path.join(OUT, "RULE_MANIFEST_V3.json"), "w"), indent=1)
    for cid, c in rule_manifest["configs"].items():
        print(f"  {cid}: {c['n_rules']} rules -> {c['local_file']} (sha {c['file_sha256'][:12]})")
    print("building tool manifest ...")
    tm = tool_manifest()
    json.dump(tm, open(os.path.join(OUT, "TOOL_MANIFEST_V3.json"), "w"), indent=1)
    for t, d in tm["tools"].items():
        h = d.get("phar_sha256") or d.get("binary_sha256") or d.get("taint_engine_sha256") or ""
        print(f"  {t:14} {d.get('version') or d.get('git_commit','')[:12]:20} hash {h[:12]}")
    print(f"\nwrote RULE_MANIFEST_V3.json + TOOL_MANIFEST_V3.json -> {OUT}")


if __name__ == "__main__":
    main()
