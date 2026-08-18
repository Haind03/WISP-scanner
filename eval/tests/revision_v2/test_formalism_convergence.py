"""Prompt 6: formalism, summary multi-value, convergence status, and determinism.

Eight behavioral tests for the revision-6 changes. Each asserts a post-fix
invariant and is expected to PASS. They cover the multi-valued summary
(one parameter to several sinks), declaration-order invariance of A->B->C chains,
mutual recursion termination, virtual dispatch, the per-key cap being reached and
reported, non-convergence being surfaced through detect(), the sanitizer on/off
behavior, and determinism of the finding set under different PYTHONHASHSEED values.

    python3 -m eval.tests.revision_v2.test_formalism_convergence
"""
from __future__ import annotations
import os, sys, json, tempfile, shutil, subprocess, itertools
from ._common import Evidence, REPO

from wisp.engine import taint_engine as te


def _force_nonconvergence():
    """Patch _build_summary so every rebuild differs (never reaches a fixpoint) while
    still returning a valid _Summary that detect()'s later stages can use. Returns
    the original for restoration."""
    real = te._build_summary
    counter = itertools.count()
    def always_changes(*a, **k):
        s = real(*a, **k)
        # append an ever-growing suffix to the display name so the dataclass never
        # equals the previous summary (forces non-convergence) while every field the
        # engine indexes on (param lists, effect sets) stays valid and unchanged.
        s.name = f"{s.name}~{next(counter)}"
        return s
    te._build_summary = always_changes
    return real


class _Plugin:
    def __init__(self, root, files):
        self.root, self.php_files = root, files

    def cleanup(self):
        shutil.rmtree(self.root, ignore_errors=True)


def _plugin(*sources):
    d = tempfile.mkdtemp()
    files = []
    for i, text in enumerate(sources):
        f = os.path.join(d, f"f{i}.php")
        open(f, "w").write(text)
        files.append(f)
    return _Plugin(d, files)


def _classes(plug):
    try:
        return {f.vuln_class for f in te.detect(plug)}
    finally:
        plug.cleanup()


def _signature(plug):
    """Order-independent signature of a finding set."""
    try:
        return sorted((f.vuln_class, os.path.basename(f.file), f.line,
                       getattr(f, "sink", "")) for f in te.detect(plug))
    finally:
        plug.cleanup()


# 1 ------------------------------------------------------------ multi-valued summary
def test_multiple_sink_effects():
    ev = Evidence("1. one parameter, multiple sink effects")
    # helper param $x reaches two DIFFERENT-class sinks; T_ps($x) must retain both
    plug = _plugin(
        "<?php function helper($x){ echo $x; global $wpdb; $wpdb->query($x); }\n"
        "function h(){ helper($_GET['q']); }\n"
        "add_action('wp_ajax_nopriv_h','h');")
    classes = _classes(plug)
    ev.show(f"emitted classes for a param reaching echo AND query: {sorted(classes)}")
    assert "xss" in classes and "sqli" in classes, (
        "a single tainted parameter reaching two different-class sinks must produce both classes, "
        "so T_ps is multi-valued")


# 2 ----------------------------------------------------- declaration-order invariance
def test_declaration_order_invariance():
    ev = Evidence("2. A->B->C declaration-order invariance")
    a = "function a($x){ b($x); }"
    b = "function b($x){ c($x); }"
    c = "function c($x){ echo $x; }"
    entry = "function h(){ a($_GET['q']); } add_action('wp_ajax_nopriv_h','h');"
    orders = {
        "natural": [a, b, c, entry],
        "reverse": [entry, c, b, a],
        "shuffled": [b, entry, a, c],
    }
    results = {}
    for name, defs in orders.items():
        plug = _plugin("<?php\n" + "\n".join(defs))
        results[name] = "xss" in _classes(plug)
        ev.show(f"order={name}: xss reached = {results[name]}")
    assert all(results.values()), "the A->B->C chain must be found regardless of declaration order"


# 3 --------------------------------------------------------------- mutual recursion
def test_mutual_recursion_terminates():
    ev = Evidence("3. mutual recursion terminates and reports status")
    plug = _plugin(
        "<?php function a($x){ if ($x) b($x); echo $x; }\n"
        "function b($x){ if ($x) a($x); }\n"
        "function h(){ a($_GET['q']); } add_action('wp_ajax_nopriv_h','h');")
    try:
        res = te.detect(plug)
        classes = {f.vuln_class for f in res}
        status = res.analysis_status
    finally:
        plug.cleanup()
    ev.show(f"mutual recursion a<->b: classes={sorted(classes)} converged={status['complete']} "
            f"capped={status['n_capped_keys']}")
    # it must terminate (we got here) and the sink under recursion must be found
    assert "xss" in classes, "the echo sink reachable under mutual recursion must be found"


# 4 --------------------------------------------------------------- virtual dispatch
def test_virtual_dispatch_includes_override():
    ev = Evidence("4. virtual dispatch includes unsafe override")
    plug = _plugin(
        "<?php class Base { function run($x){} }\n"
        "class Evil extends Base { function run($x){ echo $x; } }\n"
        "function h(){ $o = new Evil(); $o->run($_GET['q']); }\n"
        "add_action('wp_ajax_nopriv_h','h');")
    classes = _classes(plug)
    ev.show(f"virtual dispatch to unsafe override: classes={sorted(classes)}")
    assert "xss" in classes, "dispatch to the unsafe override must include its sink"


# 5 --------------------------------------------------------------- per-key cap reached
def test_per_key_cap_reached_is_reported():
    ev = Evidence("5. per-key cap reached is reported")
    # two mutually-requeueing keys whose rebuild always differs: the per-key cap fires
    saved = te._build_summary
    te._build_summary = lambda *a, **k: object()
    # The subject here is the mechanism, not the shipped default. The global bound has a floor of
    # 64, so with the v1.3 default of 32 a two-key cycle reaches 2*32 = 64 and the GLOBAL cap fires
    # first, leaving capped_keys empty and this test asserting nothing. Pin the per-key cap low for
    # the duration so the per-key path is the one under test at any default.
    saved_cap = te._PER_KEY_UPDATE_CAP
    te._PER_KEY_UPDATE_CAP = 4
    try:
        definitions = {"x": (None, None, "r", "a"), "y": (None, None, "r", "a")}
        callers = {"x": ["y"], "y": ["x"]}
        status = te._stabilize_summaries(definitions, {}, callers=callers)
    finally:
        te._build_summary = saved
        te._PER_KEY_UPDATE_CAP = saved_cap
    ev.show(f"cyclic pair -> converged={status.converged} capped_keys={list(status.capped_keys)} "
            f"updates={status.updates} rounds={status.rounds}")
    assert status.converged is False, "a persistently-changing cycle must not be reported converged"
    assert status.capped_keys, "the per-key cap must record the capped keys"
    assert status.updates <= status.max_updates


# 6 ------------------------------------------------------------- non-convergence surfaced
def test_nonconvergence_surfaced_in_detect():
    ev = Evidence("6. non-convergence surfaced by detect()")
    plug = _plugin("<?php function a($x){ b($x); } function b($x){ a($x); echo $x; }\n"
                   "function h(){ a($_GET['q']); } add_action('wp_ajax_nopriv_h','h');")
    saved = _force_nonconvergence()
    try:
        res = te.detect(plug)
    finally:
        te._build_summary = saved
        plug.cleanup()
    st = res.analysis_status
    ev.show(f"forced non-convergence -> complete={st['complete']} pending={st['pending_count']} "
            f"n_capped={st['n_capped_keys']} global_cap={st['hit_global_cap']}")
    assert st["complete"] is False, "detect() must mark a non-converged record incomplete"
    assert te.LAST_ANALYSIS_STATUS["complete"] is False, "module-level status must agree"


# 7 --------------------------------------------------------------- sanitizer on/off
def test_sanitizer_on_off_behavior():
    ev = Evidence("7. sanitizer class propagation on vs off")
    # sanitize_text_field neutralizes XSS but not SQLi. With class-carrying ON the
    # value stays SQL-tainted so the query sink fires; with OFF it is stored clean.
    text = ("<?php function h(){ $v = sanitize_text_field($_GET['q']); global $wpdb; "
            "$wpdb->query($v); } add_action('wp_ajax_nopriv_h','h');")
    saved = os.environ.get("WISP_SANI_CLASS")
    try:
        os.environ["WISP_SANI_CLASS"] = "1"          # ON (default)
        on = _classes(_plugin(text))
        os.environ["WISP_SANI_CLASS"] = "0"          # OFF (ablation)
        off = _classes(_plugin(text))
    finally:
        if saved is None:
            os.environ.pop("WISP_SANI_CLASS", None)
        else:
            os.environ["WISP_SANI_CLASS"] = saved
    ev.show(f"ON classes={sorted(on)}  OFF classes={sorted(off)}")
    assert "sqli" in on, "with class-carrying ON, an XSS-only sanitizer must leave SQL taint live"
    assert "sqli" not in off, "with class propagation OFF, the sanitized value is stored fully clean"


# 8 --------------------------------------------------- determinism under PYTHONHASHSEED
def _detect_signature_subprocess(php_text, seed):
    script = (
        "import os,sys,tempfile,json\n"
        "sys.path.insert(0, sys.argv[2])\n"
        "import wisp.engine.taint_engine as te\n"
        "d=tempfile.mkdtemp(); f=os.path.join(d,'p.php'); open(f,'w').write(sys.argv[1])\n"
        "class P:\n"
        "    root=d; php_files=[f]\n"
        "    def cleanup(self): pass\n"
        "sig=sorted((x.vuln_class, os.path.basename(x.file), x.line, getattr(x,'sink','')) "
        "for x in te.detect(P()))\n"
        "print(json.dumps(sig))\n")
    env = dict(os.environ, PYTHONHASHSEED=str(seed))
    env.pop("WISP_SANI_CLASS", None)
    out = subprocess.check_output([sys.executable, "-c", script, php_text, REPO], env=env, text=True)
    return json.loads(out.strip().splitlines()[-1])


def test_determinism_under_hashseed():
    ev = Evidence("8. finding set deterministic across PYTHONHASHSEED")
    php = ("<?php function helper($x){ echo $x; global $wpdb; $wpdb->query($x); }\n"
           "function g($y){ include $y; }\n"
           "function h(){ helper($_GET['a']); g($_GET['b']); echo $_POST['c']; }\n"
           "add_action('wp_ajax_nopriv_h','h');")
    sigs = [_detect_signature_subprocess(php, seed) for seed in (0, 1, 12345)]
    for seed, sig in zip((0, 1, 12345), sigs):
        ev.show(f"PYTHONHASHSEED={seed}: {len(sig)} findings, signature hash "
                f"{hash(json.dumps(sig)) & 0xffffff:06x}")
    assert sigs[0] == sigs[1] == sigs[2], (
        "the finding set (class, file, line, sink) must be identical under different hash seeds")


TESTS = [
    test_multiple_sink_effects,
    test_declaration_order_invariance,
    test_mutual_recursion_terminates,
    test_virtual_dispatch_includes_override,
    test_per_key_cap_reached_is_reported,
    test_nonconvergence_surfaced_in_detect,
    test_sanitizer_on_off_behavior,
    test_determinism_under_hashseed,
]


def run():
    passed = 0
    for t in TESTS:
        try:
            t()
            print(f"  [PASS] {t.__name__}")
            passed += 1
        except AssertionError as e:
            print(f"  [FAIL] {t.__name__}: {str(e).splitlines()[0] if str(e) else ''}")
        except Exception as e:
            import traceback
            traceback.print_exc()
            print(f"  [ERROR] {t.__name__}: {type(e).__name__}: {e}")
    print(f"\nPrompt-6 formalism/convergence: {passed}/{len(TESTS)} PASS")
    return 0 if passed == len(TESTS) else 1


if __name__ == "__main__":
    raise SystemExit(run())
