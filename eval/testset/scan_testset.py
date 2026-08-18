#!/usr/bin/env python3
"""Score WISP + three baselines on a post-development, slug-disjoint test set.

The harness uses the artifact engine from this repository, not a mutable sibling
checkout.  It records the engine revision and input hashes, applies
failure-as-miss over every manifest row, and uses the same granularity ladder as
the development-corpus evaluation:

Per record we unzip the vulnerable + patched trees once, compute the patch-diff
GT file set, then run each tool and score:
  class emission      : advisory class appears in any finding (diagnostic only)
  patch-file@K        : a top-K finding lies in a patch-changed file
  class-and-file@K    : patch file and advisory class both match
  class-and-function@K: additionally, finding and changed line share a function
  class-and-hunk@K    : additionally, finding is within +/-window changed lines

Tool binaries and the manifest are explicit CLI options; run ``--help`` for a
portable example.  wp-taint-scan normalization and access-tier ranking are
shared with the primary-corpus evaluator through :mod:`eval.wpt_adapter`.
"""
import os, sys, json, argparse, subprocess, tempfile, shutil, zipfile, time, hashlib
from multiprocessing import Pool

HERE = os.path.dirname(os.path.abspath(__file__))
PROJECT_ROOT = os.path.dirname(os.path.dirname(HERE))
sys.path.insert(0, PROJECT_ROOT)
from eval.datasets.patchstack import classify_type
from eval.localize import _unzip, _php_map, _changed_lines, _fn_ranges, _enclosing_fn
from eval.wpt_adapter import compact_findings
from eval import wisp_contract as WC
from eval import patch_geometry as pg
from eval.resource_budget import run_capped, BudgetExceeded
from wisp.engine import taint_engine as te
from wisp.engine import l1_ingest

DEFAULT_DATA_DIR = os.environ.get("WISP_TESTSET_DIR", os.path.join(HERE, "data"))
DEFAULT_MANIFEST = os.environ.get(
    "WISP_TESTSET_MANIFEST", os.path.join(DEFAULT_DATA_DIR, "testset_manifest.json"))
PROGPILOT = os.environ.get("PROGPILOT_BIN", "")
WPT_BIN = os.environ.get("WPT_BIN", "")
SEMGREP_BIN = os.environ.get("SEMGREP_BIN", "semgrep")
TOOL_TIMEOUTS = {"semgrep": 300, "progpilot": 60, "wpt": 60}
SG_CONFIGS = ["--config", "p/php", "--config", "p/security-audit"]
KS = (1, 3, 5, 10)
_SEV = {"ERROR": 3, "WARNING": 2, "INFO": 1}


class ToolFailure(RuntimeError):
    """A tool did not produce a valid, scoreable result."""

# baseline native-label -> WISP class (same map as the dev-corpus baseline runners)
_CLASS_PATTERNS = [
    ("sqli", ["sql", "tainted-sql"]),
    ("xss", ["xss", "cross-site-scripting", "tainted-html", "echoed-request"]),
    ("lfi", ["lfi", "rfi", "file-inclusion", "path-traversal", "tainted-filename",
             "include", "require"]),
    ("rce", ["rce", "code-execution", "command-injection", "eval", "tainted-exec",
             "os-command", "system"]),
    ("deserial", ["deserial", "unserialize", "object-injection"]),
    ("ssrf", ["ssrf", "server-side-request"]),
    ("upload", ["upload", "move-uploaded", "arbitrary-file-upload"]),
    ("auth", ["auth", "access-control", "capability", "privilege", "nonce-missing"]),
    ("csrf", ["csrf", "nonce", "cross-site-request"]),
]


def map_class(label):
    s = (label or "").lower()
    for cls, pats in _CLASS_PATTERNS:
        if any(p in s for p in pats):
            return cls
    return "other"


def _keyof(p, root):
    rel = os.path.relpath(p, root) if os.path.isabs(p) else p
    parts = rel.split(os.sep) if os.sep in rel else rel.split("/")
    return "/".join(parts[1:]) if len(parts) > 1 else rel


def _gt(vroot, proot):
    """Map patch-changed PHP files to vulnerable-side changed lines and function ranges, under the one
    Evaluation Contract (v1 s2): a PHP file is patch-changed if it was modified (either side) or
    deleted; a deleted or pure-insertion file counts at FILE level only (empty changed-line set), so a
    finding in it is a patch-file hit but never a line-, callable-, or hunk-level hit. This matches
    eval/patch_geometry.py so the equal-budget matrix and the geometric ladder share one ground truth."""
    vmap, pmap = _php_map(vroot), _php_map(proot)
    gt = {}
    for rel, vf in vmap.items():
        key = rel.replace(os.sep, "/")
        if rel not in pmap:
            gt[key] = (set(), _fn_ranges(vf))              # deleted: file-level only
            continue
        # One ground truth. eval/localize.py:_changed_lines anchors a pure insertion on
        # its boundary line, patch_geometry does not, and this harness used to call the
        # first while the geometric ladder used the second: the same insert-only patch
        # was a scoreable line target in one table and not in another. Delegate to
        # patch_geometry so there is exactly one definition of "changed line".
        lines = set(_pg_changed_vuln_lines(key, vf, pmap[rel]))
        if lines:
            gt[key] = (lines, _fn_ranges(vf))              # modified, vulnerable-side changed lines
        elif _file_differs(vf, pmap[rel]):
            gt[key] = (set(), _fn_ranges(vf))              # modified pure-insertion: file-level only
        # else: identical file, not patch-changed
    return gt


def _pg_changed_vuln_lines(rel, vpath, ppath):
    """The contract's changed-line set for one file pair, from eval/patch_geometry.py."""
    def _read(p):
        try:
            with open(p, "r", encoding="utf-8", errors="replace") as fh:
                return fh.read()
        except OSError:
            return ""
    return pg._diff_file(rel, _read(vpath), _read(ppath), "modified").changed_vuln_lines


def _file_differs(a, b):
    """True if two files' bytes differ (a modified file with no vulnerable-side changed line is a pure
    insertion and still counts at file level; an identical file is not patch-changed)."""
    try:
        return open(a, "rb").read() != open(b, "rb").read()
    except OSError:
        return True


def _score(ranked, gt, cls, window):
    """Score one ranked list at every endpoint in the granularity ladder."""
    classes = {c for finding in ranked for c in finding["classes"]}
    pf, cf, ch, cfn = {}, {}, {}, {}
    for k in KS:
        top = ranked[:k]
        pf[k] = int(any(finding["file"] in gt for finding in top))
        cf[k] = ch[k] = cfn[k] = 0
        for finding in top:
            path = finding["file"]
            line = finding["line"]
            finding_classes = finding["classes"]
            if path not in gt or cls not in finding_classes:
                continue
            cf[k] = 1
            changed, ranges = gt[path]
            if line and any(abs(line - changed_line) <= window for changed_line in changed):
                ch[k] = 1
            enclosing = _enclosing_fn(line, ranges) if line else None
            if enclosing and any(enclosing[0] <= changed_line <= enclosing[1]
                                 for changed_line in changed):
                cfn[k] = 1
    return int(cls in classes), pf, cf, ch, cfn


# Set by _wisp_ranked so _one can apply contract v1 s4 rule 3 (non-convergence is a
# miss). Process-local, which is what the multiprocessing Pool workers need.
LAST_WISP_STATUS: dict = {}


def _wisp_ranked(vzip, config):
    """Run WISP under the Evaluation Contract's Section 1 configuration.

    This used to set WISP_NO_GDA by hand and inherit every other flag from whatever
    shell invoked the harness, which meant the 325 and Wordfence-100 tables were not
    pinned to the contract at all. eval.wisp_contract is now the one source of the
    configuration here, exactly as in eval.baseline_matrix_v3, and the engine's
    stabilization status is captured so the caller can enforce the failure policy.
    """
    global LAST_WISP_STATUS
    LAST_WISP_STATUS = {}
    plug = l1_ingest.load_plugin(vzip)
    if not (plug and plug.php_files):
        raise ToolFailure("plugin_load_error")
    saved = {k: os.environ.get(k) for k in WC.CANONICAL_ENV}
    overrides = {"WISP_NO_GDA": None} if config.get("wisp_gda") else {}
    # A caller running a sensitivity arm (eval/_wisp_worker.py resolving a variant or the
    # ablation's sani_class) has already set its flag. apply_canonical_env rebuilds the whole
    # canonical mapping, so without merging that override here the second application silently
    # resets the arm to the canonical default and the arm measures the default against itself.
    if isinstance(config.get("env"), dict):
        overrides.update(config["env"])
    WC.apply_canonical_env(overrides)
    try:
        fnds = te.detect(plug)
        LAST_WISP_STATUS = dict(getattr(te, "LAST_ANALYSIS_STATUS", {}) or {})
    finally:
        plug.cleanup()
        for k, v in saved.items():
            if v is None:
                os.environ.pop(k, None)
            else:
                os.environ[k] = v
    return [{"file": _keyof(f.file, "").replace(os.sep, "/"),
             "line": getattr(f, "line", 0), "classes": [f.vuln_class],
             "function": getattr(f, "function", ""),
             "sink_file": _keyof(getattr(f, "sink_file", ""), "").replace(os.sep, "/"),
             "sink_line": getattr(f, "sink_line", 0),
             "sink_function": getattr(f, "sink_function", ""),
             "rule": getattr(f, "sink", ""), "source": getattr(f, "source", ""),
             "message": getattr(f, "message", ""), "trace": getattr(f, "trace", []),
             "entry_point": getattr(f, "entry_point", "unknown"),
             "confidence": getattr(f, "confidence", 0.0),
             "guard_deficit": getattr(f, "guard_deficit", -1.0)} for f in fnds]


def _run_budgeted(cmd, config, tool, **kw):
    """Run a tool under the wall clock, and under a memory ceiling when one is budgeted.

    `mem_cap_mb` is opt-in. Callers that do not set it get exactly the previous behaviour, byte for
    byte, so the experiments already measured without a memory budget are not silently rescored by
    a harness that changed under them. The equal-budget matrix sets it, because declaring a resource
    budget and enforcing it is what that experiment is for."""
    cap = config.get("mem_cap_mb")
    budget = config["timeouts"][tool]
    if not cap:
        try:
            return subprocess.run(cmd, capture_output=True, text=True, timeout=budget, **kw)
        except subprocess.TimeoutExpired:
            raise ToolFailure("timeout")
    try:
        done, _peak = run_capped(cmd, budget, cap, **kw)
    except BudgetExceeded as e:
        raise ToolFailure(str(e))
    return done


def _semgrep_ranked(vroot, config):
    config_args = [item for value in config["semgrep_configs"]
                   for item in ("--config", value)]
    cmd = [config["semgrep_bin"], *config_args, "--json", "--quiet", "--metrics=off", "--jobs", "1",
           "--timeout", "20", "--max-target-bytes", "2000000", vroot]
    p = _run_budgeted(cmd, config, "semgrep")
    if p.returncode != 0:
        raise ToolFailure(f"nonzero_exit:{p.returncode}")
    if not p.stdout.strip():
        raise ToolFailure("empty_output")
    try:
        data = json.loads(p.stdout)
    except json.JSONDecodeError:
        raise ToolFailure("malformed_json")
    if not isinstance(data, dict) or not isinstance(data.get("results"), list):
        raise ToolFailure("invalid_schema")
    rows = []
    for r in data.get("results", []):
        sev = _SEV.get(r.get("extra", {}).get("severity", "INFO"), 1)
        ln = r.get("start", {}).get("line", 0)
        rows.append({"file": _keyof(r.get("path", ""), vroot).replace(os.sep, "/"),
                     "line": ln, "classes": [map_class(r.get("check_id", ""))],
                     "rule": r.get("check_id", ""), "native_severity": sev,
                     "message": r.get("extra", {}).get("message", "")})
    rows.sort(key=lambda row: row["native_severity"], reverse=True)
    return rows


def _progpilot_ranked(vroot, config):
    """The one Progpilot runner (Evaluation Contract v1 s5: one build, one cap, one
    parser, every table).

    Progpilot writes non-fatal PHP notices to stderr and then exits 1 while still
    printing a complete JSON findings array on stdout, so a returncode check
    discards valid findings. It did: on matched-100 an exit-code check dropped 34
    of 100 records as `nonzero_exit:1` and Progpilot was then reported at 0.00 on
    every rung as though that were a capability result. Parse stdout regardless of
    the exit code and fail only on a timeout or genuinely unusable output.
    """
    p = _run_budgeted(["php", config["progpilot_bin"], vroot], config, "progpilot")
    out = (p.stdout or "").strip()
    i = out.find("[")
    if i < 0:
        raise ToolFailure("empty_or_invalid_output")
    try:
        res = json.loads(out[i:])
    except json.JSONDecodeError:
        raise ToolFailure("malformed_json")
    if not isinstance(res, list):
        raise ToolFailure("invalid_schema")
    rows = []
    for x in res:
        fp = x.get("sink_file") or ""
        if isinstance(fp, list):
            fp = fp[0] if fp else ""
        label = x.get("vuln_name") or x.get("name") or x.get("vuln_type") or ""
        ln = x.get("sink_line") or x.get("line") or 0
        if isinstance(ln, list):
            ln = ln[0] if ln else 0
        sl = x.get("source_line") or 0
        if isinstance(sl, list):
            sl = sl[0] if sl else 0
        sf = x.get("source_file") or ""
        if isinstance(sf, list):
            sf = sf[0] if sf else ""
        rows.append({"file": _keyof(fp, vroot).replace(os.sep, "/"), "line": ln,
                     "classes": [map_class(label)], "rule": label,
                     "source_file": sf, "source_line": sl})
    return rows


def _wpt_ranked(vzip, config):
    with tempfile.TemporaryDirectory(prefix="wpt-") as td:
        src = os.path.join(td, "src"); out = os.path.join(td, "out")
        os.makedirs(src)
        try:
            zipfile.ZipFile(vzip).extractall(src)
        except Exception:
            raise ToolFailure("archive_extract_error")
        wpt_bin = config["wpt_bin"]
        cmd = [wpt_bin, "-target", src, "-output-dir", out,
               "-mem-limit-mb", "2048", "-phparser-workers", "1"]
        p = _run_budgeted(cmd, config, "wpt", cwd=os.path.dirname(os.path.dirname(wpt_bin)))
        pf = os.path.join(out, "taint-results.json")
        if p.returncode != 0:
            raise ToolFailure(f"nonzero_exit:{p.returncode}")
        if not os.path.isfile(pf):
            raise ToolFailure("missing_results_file")
        try:
            with open(pf, encoding="utf-8") as handle:
                payload = json.load(handle)
        except (OSError, json.JSONDecodeError):
            raise ToolFailure("malformed_json")
        if not isinstance(payload, dict) or not isinstance(payload.get("results"), list):
            raise ToolFailure("invalid_schema")
        rows = compact_findings(payload, src)
        return [{"file": row.pop("path"), **row} for row in rows]


def _zero_at_k():
    return {k: 0 for k in KS}


def _zero_result(error):
    zeros = _zero_at_k()
    return {"err": error, "n": 0, "hit": 0, "pf": dict(zeros), "cf": dict(zeros),
            "ch": dict(zeros), "cfn": dict(zeros), "findings": [],
            "findings_sample": []}


def _sha256_file(path):
    digest = hashlib.sha256()
    with open(path, "rb") as handle:
        for block in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(block)
    return digest.hexdigest()


def _one(args):
    rec, tools, window, config = args
    slug = rec["slug"]
    vzip, pzip = rec["vuln_zip"], rec["patched_zip"]
    # Fail closed. classify_type(None) returns "other", a real class, so a manifest
    # that omits vuln_type silently scores every record as "other" and every
    # class-dependent metric then asks "did the tool report other?". That happened:
    # the 2026-07-13 matched-100 run was fed a manifest without the field and
    # understated wp-taint-scan's class emission by 2.7x. A missing label is a
    # broken input, not a class.
    if not rec.get("vuln_type"):
        raise ValueError(f"{slug}|{rec.get('cve')}: manifest row has no vuln_type; "
                         f"refusing to score it as 'other'")
    cls = classify_type(rec.get("vuln_type"))
    res = {"slug": slug, "cve": rec.get("cve"), "cls": cls,
           "disclosure": rec.get("disclosure_date"), "gt_files": 0}
    archive_errors = []
    for label, path in (("vulnerable", vzip), ("patched", pzip)):
        if not path or not os.path.isfile(path):
            archive_errors.append(f"missing_{label}_archive")
        elif not zipfile.is_zipfile(path):
            archive_errors.append(f"invalid_{label}_zip")
    if archive_errors:
        res["record_error"] = ";".join(archive_errors)
        for tool in tools:
            res[tool] = _zero_result(res["record_error"])
        return res
    try:
        res["input_sha256"] = {
            "vulnerable": _sha256_file(vzip),
            "patched": _sha256_file(pzip),
        }
    except OSError:
        res["record_error"] = "archive_hash_error"
        for tool in tools:
            res[tool] = _zero_result(res["record_error"])
        return res
    vroot, proot = _unzip(vzip), _unzip(pzip)
    if not vroot or not proot:
        res["record_error"] = "archive_extract_error"
        for tool in tools:
            res[tool] = _zero_result("archive_extract_error")
        if vroot:
            shutil.rmtree(vroot, ignore_errors=True)
        if proot:
            shutil.rmtree(proot, ignore_errors=True)
        return res
    try:
        gt = _gt(vroot, proot)
        res["gt_files"] = len(gt)
        rankers = {
            "wisp": lambda: _wisp_ranked(vzip, config),
            "semgrep": lambda: _semgrep_ranked(vroot, config),
            "progpilot": lambda: _progpilot_ranked(vroot, config),
            "wpt": lambda: _wpt_ranked(vzip, config),
        }
        for t in tools:
            try:
                ranked = rankers[t]()
            except ToolFailure as exc:
                res[t] = _zero_result(str(exc))
                continue
            except Exception as exc:
                res[t] = _zero_result(f"harness_exception:{type(exc).__name__}")
                continue
            hit, pf, cf, ch, cfn = _score(ranked, gt, cls, window)
            findings = [{"rank": rank, **finding}
                        for rank, finding in enumerate(ranked, start=1)]
            res[t] = {"err": "", "n": len(ranked), "hit": hit, "pf": pf, "cf": cf,
                      "ch": ch, "cfn": cfn, "findings": findings,
                      "findings_sample": findings[:15]}
            if t == "wisp":
                status = dict(LAST_WISP_STATUS)
                res[t]["analysis_status"] = status
                # Contract v1 s4 rule 3: an analysis that stopped at a bounded
                # approximation is a miss over the full denominator, exactly like a
                # timeout. The findings and the scored-as-if-complete metrics are kept
                # alongside so the contract's required robustness arm ("metrics with
                # non-converged records kept") is derivable without a re-run.
                if status and not status.get("complete", True):
                    res[t] = {**res[t], "err": "non_converged",
                              "hit": 0, "pf": _zero_at_k(), "cf": _zero_at_k(),
                              "ch": _zero_at_k(), "cfn": _zero_at_k(),
                              "kept_if_nonconvergence_ignored": {
                                  "hit": hit, "pf": pf, "cf": cf, "ch": ch, "cfn": cfn}}
    except Exception as exc:
        res["record_error"] = f"record_harness_exception:{type(exc).__name__}"
        for tool in tools:
            if tool not in res:
                res[tool] = _zero_result(res["record_error"])
    finally:
        shutil.rmtree(vroot, ignore_errors=True)
        shutil.rmtree(proot, ignore_errors=True)
    return res


def _resolve_archive(path, manifest_dir, plugins_dir, slug):
    """Resolve legacy absolute manifest paths against a local extracted dataset."""
    path = os.path.expanduser(path or "")
    if not path:
        return ""
    candidates = [path]
    if path and not os.path.isabs(path):
        candidates.append(os.path.join(manifest_dir, path))
    if plugins_dir and path:
        candidates.extend([
            os.path.join(plugins_dir, slug, os.path.basename(path)),
            os.path.join(plugins_dir, os.path.basename(path)),
        ])
    for candidate in candidates:
        if candidate and os.path.exists(candidate):
            return os.path.abspath(candidate)
    return os.path.abspath(candidates[-1] if candidates else path)


def _git_dirty():
    """Contract v1 s6 requires a clean checkout; record the truth either way."""
    try:
        out = subprocess.check_output(["git", "status", "--porcelain"],
                                      cwd=PROJECT_ROOT, text=True)
        return bool(out.strip())
    except (OSError, subprocess.SubprocessError):
        return None


def _git_revision():
    try:
        return subprocess.check_output(
            ["git", "rev-parse", "HEAD"], cwd=PROJECT_ROOT, text=True).strip()
    except (OSError, subprocess.SubprocessError):
        return "unknown"


def _artifact_sha256():
    digest = hashlib.sha256()
    roots = [os.path.join(PROJECT_ROOT, "wisp"), os.path.join(PROJECT_ROOT, "eval")]
    for root in roots:
        for directory, dirs, files in os.walk(root):
            dirs[:] = sorted(d for d in dirs if d not in {"__pycache__", "out"})
            for name in sorted(files):
                if not name.endswith((".py", ".yaml", ".yml", ".txt")):
                    continue
                path = os.path.join(directory, name)
                rel = os.path.relpath(path, PROJECT_ROOT).replace(os.sep, "/")
                digest.update(rel.encode() + b"\0")
                with open(path, "rb") as handle:
                    digest.update(handle.read())
    return digest.hexdigest()


def _resolve_executable(path):
    if path and os.path.isfile(path):
        return os.path.abspath(path)
    resolved = shutil.which(path or "")
    return os.path.abspath(resolved) if resolved else ""


def _command_version(command):
    try:
        completed = subprocess.run(command, capture_output=True, text=True, timeout=15)
    except (OSError, subprocess.SubprocessError):
        return "unknown"
    text_out = (completed.stdout or completed.stderr).strip().splitlines()
    return text_out[0] if text_out else "unknown"


def _nearest_git_revision(path):
    directory = os.path.dirname(os.path.abspath(path))
    for _ in range(5):
        try:
            return subprocess.check_output(
                ["git", "rev-parse", "HEAD"], cwd=directory,
                stderr=subprocess.DEVNULL, text=True).strip()
        except (OSError, subprocess.SubprocessError):
            parent = os.path.dirname(directory)
            if parent == directory:
                break
            directory = parent
    return "unknown"


def _tool_identity(label, configured_path):
    resolved = _resolve_executable(configured_path)
    identity = {"configured_path": configured_path, "resolved_path": resolved}
    if resolved and os.path.isfile(resolved):
        identity["sha256"] = _sha256_file(resolved)
    if label == "semgrep" and resolved:
        identity["version"] = _command_version([resolved, "--version"])
    elif label == "progpilot":
        identity["runtime"] = _command_version(["php", "--version"])
    elif label == "wpt" and resolved:
        identity["source_commit"] = _nearest_git_revision(resolved)
    return identity


def _config_identities(configs):
    out = []
    for value in configs:
        if os.path.isfile(value):
            out.append({"path": os.path.abspath(value), "sha256": _sha256_file(value),
                        "pinned_local_file": True})
        else:
            out.append({"registry_id": value, "pinned_local_file": False})
    return out


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--limit", type=int, default=0)
    ap.add_argument("--workers", type=int, default=6)
    ap.add_argument("--tools", default="wisp,semgrep,progpilot,wpt")
    ap.add_argument("--manifest", default=DEFAULT_MANIFEST,
                    help="testset_manifest.json from the released dataset")
    ap.add_argument("--plugins-dir", default=os.path.join(DEFAULT_DATA_DIR, "plugins"),
                    help="local plugins directory; repairs legacy absolute manifest paths")
    ap.add_argument("--progpilot-bin", default=PROGPILOT,
                    help="Progpilot PHAR (or set PROGPILOT_BIN)")
    ap.add_argument("--wpt-bin", default=WPT_BIN,
                    help="wp-taint-scan executable (or set WPT_BIN)")
    ap.add_argument("--semgrep-bin", default=SEMGREP_BIN)
    ap.add_argument("--semgrep-config", action="append", dest="semgrep_configs",
                    help="repeat for each pinned config; defaults to p/php and p/security-audit")
    ap.add_argument("--wisp-gda", action="store_true",
                    help="enable exploratory GDA reranking (headline protocol leaves it off)")
    ap.add_argument("--window", type=int, default=5,
                    help="line distance for class-and-hunk@K")
    ap.add_argument("--semgrep-timeout", type=int, default=300)
    ap.add_argument("--progpilot-timeout", type=int, default=60)
    ap.add_argument("--wpt-timeout", type=int, default=60)
    ap.add_argument("--out", default=os.path.join(HERE, "out", "testset_scored.json"))
    a = ap.parse_args()
    tools = [tool.strip() for tool in a.tools.split(",") if tool.strip()]
    unknown = sorted(set(tools) - {"wisp", "semgrep", "progpilot", "wpt"})
    if unknown:
        ap.error(f"unknown tools: {', '.join(unknown)}")
    if not os.path.isfile(a.manifest):
        ap.error(f"manifest not found: {a.manifest}")
    semgrep_configs = a.semgrep_configs or ["p/php", "p/security-audit"]
    config = {
        "semgrep_bin": a.semgrep_bin,
        "semgrep_configs": semgrep_configs,
        "progpilot_bin": a.progpilot_bin,
        "wpt_bin": a.wpt_bin,
        "wisp_gda": a.wisp_gda,
        "timeouts": {"semgrep": a.semgrep_timeout,
                     "progpilot": a.progpilot_timeout, "wpt": a.wpt_timeout},
    }
    if "semgrep" in tools and not _resolve_executable(a.semgrep_bin):
        ap.error(f"Semgrep executable not found: {a.semgrep_bin}")
    if "progpilot" in tools and not os.path.isfile(a.progpilot_bin):
        ap.error("--progpilot-bin is required when selecting progpilot")
    if "wpt" in tools and not os.path.isfile(a.wpt_bin):
        ap.error("--wpt-bin is required when selecting wpt")
    # Registry IDs such as ``p/php`` and ``p/security-audit`` intentionally
    # contain a slash but are resolved by Semgrep itself.  Only reject values
    # that are explicitly local config paths (existing extension or an
    # existing path-like parent); otherwise a registry lookup must be allowed.
    missing_configs = [value for value in semgrep_configs
                       if value.endswith((".yml", ".yaml")) and not os.path.isfile(value)]
    if "semgrep" in tools and missing_configs:
        ap.error(f"Semgrep config not found: {missing_configs[0]}")

    with open(a.manifest, encoding="utf-8") as handle:
        recs = json.load(handle)
    manifest_dir = os.path.dirname(os.path.abspath(a.manifest))
    for rec in recs:
        rec["vuln_zip"] = _resolve_archive(
            rec.get("vuln_zip"), manifest_dir, a.plugins_dir, rec["slug"])
        rec["patched_zip"] = _resolve_archive(
            rec.get("patched_zip"), manifest_dir, a.plugins_dir, rec["slug"])
    if a.limit:
        recs = recs[:a.limit]
    print(f"scoring {len(recs)} records, tools={tools}, workers={a.workers}", flush=True)
    t0 = time.time()
    with Pool(a.workers) as pool:
        det = pool.map(_one, [(r, tools, a.window, config) for r in recs])
    n = len(det)
    summ = {"n": n, "tools": tools, "window": a.window,
            "elapsed_min": round((time.time() - t0) / 60, 1)}
    for t in tools:
        rows = [d[t] for d in det if t in d]
        answered = [r for r in rows if not r["err"]]
        summ[t] = {
            "class_emission": round(sum(r["hit"] for r in rows) / n, 4) if n else 0,
            "answered": len(answered),
            "coverage": round(len(answered) / n, 4) if n else 0,
            "pf_at_k": {k: round(sum(r["pf"][k] for r in rows) / n, 4) for k in KS},
            "cf_at_k": {k: round(sum(r["cf"][k] for r in rows) / n, 4) for k in KS},
            "ch_at_k": {k: round(sum(r["ch"][k] for r in rows) / n, 4) for k in KS},
            "cfn_at_k": {k: round(sum(r["cfn"][k] for r in rows) / n, 4) for k in KS},
            "findings_per_plugin": round(sum(r["n"] for r in answered) / len(answered), 1) if answered else 0,
        }
        # Contract v1 s4: every dataset reports its non-convergence census, and the
        # robustness arm with non-converged records kept rather than zeroed.
        nc = [r for r in rows if r["err"] == "non_converged"]
        summ[t]["errors_by_kind"] = {
            kind: sum(1 for r in rows if r["err"] == kind)
            for kind in sorted({r["err"] for r in rows if r["err"]})}
        if t == "wisp":
            summ[t]["non_converged"] = len(nc)
            summ[t]["non_convergence_rate"] = round(len(nc) / n, 4) if n else 0
            if nc:
                kept = lambda key, k=None: sum(
                    (r.get("kept_if_nonconvergence_ignored", {}).get(key, {}).get(k, 0)
                     if k is not None else
                     r.get("kept_if_nonconvergence_ignored", {}).get(key, 0))
                    for r in nc)
                summ[t]["robustness_nonconvergence_kept"] = {
                    "class_emission": round(
                        (sum(r["hit"] for r in rows) + kept("hit")) / n, 4) if n else 0,
                    "pf_at_k": {k: round(
                        (sum(r["pf"][k] for r in rows) + kept("pf", k)) / n, 4) for k in KS},
                }
    provenance = {
        "engine_commit": _git_revision(),
        "git_dirty": _git_dirty(),
        "artifact_source_sha256": _artifact_sha256(),
        # Contract v1 s6: every result JSON stamps the engine tag, the engine sha256 and
        # the whole Section 1 config table. Recording only engine_commit + wisp_gda, as
        # this runner used to, made the 325 and Wordfence-100 tables unattributable.
        "wisp_config": WC.config_stamp({"WISP_NO_GDA": None} if a.wisp_gda else None),
        "taint_engine_sha256": _sha256_file(
            os.path.join(PROJECT_ROOT, "wisp", "engine", "taint_engine.py")),
        "manifest_sha256": _sha256_file(a.manifest),
        "manifest": os.path.abspath(a.manifest),
        "command": sys.argv,
        "wisp_gda": a.wisp_gda,
        "tool_identities": {
            "semgrep": _tool_identity("semgrep", a.semgrep_bin),
            "progpilot": _tool_identity("progpilot", a.progpilot_bin),
            "wpt": _tool_identity("wpt", a.wpt_bin),
        },
        "semgrep_configs": _config_identities(semgrep_configs),
        "timeouts_seconds": config["timeouts"],
        "failure_as_miss": True,
        "failure_rule": "failure-as-miss (contract v1 s4): a timeout, an error, OR WISP "
                        "analysis non-convergence (analysis_status.complete==false) counts "
                        "as no finding over the full denominator for every metric",
        "ground_truth_module": "eval.patch_geometry (contract v1 s2: one scorer)",
        "scorer": "eval.testset.scan_testset._score, window=%d, K=%s" % (a.window, KS),
    }
    os.makedirs(os.path.dirname(a.out), exist_ok=True)
    with open(a.out, "w", encoding="utf-8") as handle:
        json.dump({"provenance": provenance, "summary": summ, "details": det}, handle, indent=1)
    print(json.dumps(summ, indent=1))


if __name__ == "__main__":
    main()
