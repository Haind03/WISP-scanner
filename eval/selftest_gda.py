#!/usr/bin/env python3
"""Regression selftest for the inter-procedural guard-dominance analysis (GDA).

Each case is a synthetic mini-plugin exercising one guard-placement pattern that
the intra-procedural presence test cannot distinguish. We assert the guard deficit
attached to the emitted missing-guard finding, which is the ranking signal GDA
contributes. Run: python3 -m eval.selftest_gda
"""
from __future__ import annotations
import os, sys, tempfile, shutil

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, ROOT)
from wisp.engine import taint_engine as te


def _mkplugin(files):
    d = tempfile.mkdtemp()
    for name, code in files.items():
        open(os.path.join(d, name), "w").write(code)

    class P:
        root = d
        php_files = [os.path.join(d, n) for n in files]
        slug = "t"

        def cleanup(self):
            shutil.rmtree(d, ignore_errors=True)
    return P()


def _deficits(files):
    p = _mkplugin(files)
    try:
        fs = te.detect(p)
    finally:
        p.cleanup()
    return {(f.vuln_class, f.line): round(float(getattr(f, "guard_deficit", -1)), 2)
            for f in fs if f.source == "request"}


CASES = []


def case(name):
    def deco(fn):
        CASES.append((name, fn))
        return fn
    return deco


@case("unauthenticated unguarded writer -> csrf+auth deficit 1.0")
def _c1():
    d = _deficits({"a.php": "<?php\nadd_action('wp_ajax_nopriv_save','my_save');\n"
                            "function my_save(){ update_option('opt', $_POST['v']); }\n"})
    assert d.get(("csrf", 3)) == 1.0, d
    assert d.get(("auth", 3)) == 1.0, d


@case("caller-side capability guard -> auth deficit 0.0")
def _c2():
    d = _deficits({"a.php": "<?php\nadd_action('admin_post_do','dispatch');\n"
                            "function dispatch(){ if(!current_user_can('manage_options')) wp_die(); do_write(); }\n"
                            "function do_write(){ update_option('opt', $_POST['v']); }\n"})
    assert d.get(("auth", 4)) == 0.0, d


@case("REST route permission_callback -> auth deficit 0.0")
def _c3():
    d = _deficits({"a.php": "<?php\nregister_rest_route('ns/v1','/x', array('methods'=>'POST',"
                            "'callback'=>'rest_cb','permission_callback'=>'my_perm'));\n"
                            "function rest_cb($request){ update_option('opt', $request->get_param('v')); }\n"})
    assert d.get(("auth", 3)) == 0.0, d


@case("REST public route (__return_true) -> auth deficit 1.0")
def _c4():
    d = _deficits({"a.php": "<?php\nregister_rest_route('ns/v1','/x', array('methods'=>'POST',"
                            "'callback'=>'rest_pub','permission_callback'=>'__return_true'));\n"
                            "function rest_pub($request){ update_option('opt', $request->get_param('v')); }\n"})
    assert d.get(("auth", 3)) == 1.0, d


@case("admin-menu capability registration -> auth deficit 0.0")
def _c5():
    d = _deficits({"a.php": "<?php\nadd_action('admin_menu','reg');\n"
                            "function reg(){ add_submenu_page('parent','T','T','manage_options','slug','admin_page'); }\n"
                            "function admin_page(){ if(isset($_POST['v'])) update_option('opt', $_POST['v']); }\n"})
    assert d.get(("auth", 4)) == 0.0, d


@case("branch-specific nonce (does not dominate) -> auth deficit 1.0")
def _c6():
    d = _deficits({"a.php": "<?php\nadd_action('wp_ajax_nopriv_x','h');\n"
                            "function h(){ if($_POST['m']=='a'){ check_admin_referer('n'); } update_option('opt',$_POST['v']); }\n"})
    assert d.get(("auth", 3)) == 1.0, d


@case("fully dominating nonce+capability -> finding suppressed")
def _c7():
    d = _deficits({"a.php": "<?php\nadd_action('wp_ajax_nopriv_x','h');\n"
                            "function h(){ if(!current_user_can('manage_options')) wp_die(); check_admin_referer('n'); update_option('opt',$_POST['v']); }\n"})
    assert d == {}, d


def main():
    failed = 0
    for name, fn in CASES:
        try:
            fn()
            print(f"  [PASS] {name}")
        except AssertionError as e:
            failed += 1
            print(f"  [FAIL] {name}\n         {e}")
    print(f"\n{'ALL ' + str(len(CASES)) + ' GDA CASES PASS' if not failed else str(failed) + ' FAILED'}")
    sys.exit(1 if failed else 0)


if __name__ == "__main__":
    main()
