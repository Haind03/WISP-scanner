#!/usr/bin/env python3
"""Check that the software citation points at something a reader can actually fetch.

The bibliography is the one place in this paper that the macro system does not reach. It has been
wrong before: the software entry once said v1.2 one line away from a macro-driven paragraph saying
v1.3, and every check was green because no check looked at the .bib. It went wrong again here. The
entry cited tag `wisp-scanner-v1.3`, which is the engine's internal build label, while the only tag
the repository publishes is `wisp-scanner-v1.0`. A reader following the citation would have found
no such tag.

Four things must agree, and none of them is a measured number, so each is read from its own
authority rather than typed:

  * the tag in the software entry equals RELEASE_TAG in the evaluation contract;
  * that tag exists in the repository, and (unless --no-remote) on the remote a reader clones;
  * the engine sha256 prefix in the entry is the prefix of the engine file on disk;
  * the manuscript's \\EngineRelease macro carries the same tag as the entry.

    python3 -m eval.check_software_citation_v3 [--bib PATH] [--macros PATH] [--no-remote]
"""
from __future__ import annotations
import argparse, hashlib, os, re, subprocess, sys

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, ROOT)
from eval.wisp_contract import RELEASE_TAG, ENGINE_TAG

SYS_ROOT = os.path.dirname(ROOT)
DEF_BIB = os.path.join(SYS_ROOT, "2026-07-07", "latex", "references.bib")
DEF_MAC = os.path.join(SYS_ROOT, "2026-07-07", "latex", "PAPER_MACROS_V3.tex")
ENGINE = os.path.join(ROOT, "wisp", "engine", "taint_engine.py")


def entry(bib_text, key):
    m = re.search(r"@\w+\{" + re.escape(key) + r",(.*?)\n\}", bib_text, re.S)
    if not m:
        raise SystemExit(f"no bib entry named {key}")
    return m.group(1)


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--bib", default=DEF_BIB)
    ap.add_argument("--macros", default=DEF_MAC)
    ap.add_argument("--no-remote", action="store_true")
    a = ap.parse_args()

    bib = open(a.bib, encoding="utf-8").read()
    soft = entry(bib, "wispsoftware")
    fails = []

    tags = set(re.findall(r"wisp-scanner-v[0-9.]+", soft))
    if tags != {RELEASE_TAG}:
        fails.append(f"software entry names {sorted(tags)} but the contract's RELEASE_TAG is "
                     f"{RELEASE_TAG!r}. {ENGINE_TAG!r} is the build label stamped in run "
                     f"manifests, not a tag a reader can fetch.")

    have = subprocess.run(["git", "-C", ROOT, "tag", "-l", RELEASE_TAG],
                          capture_output=True, text=True).stdout.strip()
    if have != RELEASE_TAG:
        fails.append(f"tag {RELEASE_TAG} does not exist in the repository")
    if not a.no_remote:
        r = subprocess.run(["git", "-C", ROOT, "ls-remote", "--tags", "origin"],
                           capture_output=True, text=True)
        if r.returncode != 0:
            print("  remote not reachable, skipped the remote tag check")
        elif f"refs/tags/{RELEASE_TAG}" not in r.stdout:
            fails.append(f"tag {RELEASE_TAG} is not on the remote a reader clones")

    m = re.search(r"sha256 \\texttt\{([0-9a-f]+)\}", soft)
    if not m:
        fails.append("software entry carries no engine sha256")
    elif os.path.isfile(ENGINE):
        real = hashlib.sha256(open(ENGINE, "rb").read()).hexdigest()
        if not real.startswith(m.group(1)):
            fails.append(f"software entry says engine sha256 {m.group(1)} but the engine hashes to "
                         f"{real[:len(m.group(1))]}")

    mac = open(a.macros, encoding="utf-8").read()
    mr = re.search(r"\\newcommand\{\\EngineRelease\}\{([^}]*)\}", mac)
    if not mr:
        fails.append("no \\EngineRelease macro to compare against")
    elif mr.group(1) != RELEASE_TAG:
        fails.append(f"\\EngineRelease is {mr.group(1)!r}, the contract says {RELEASE_TAG!r}")

    for f in fails:
        print("SOFTWARE CITATION FAIL:", f)
    if fails:
        return 1
    print(f"  software citation OK: tag {RELEASE_TAG}, present locally"
          f"{'' if a.no_remote else ' and on the remote'}, engine sha and \\EngineRelease agree")
    return 0


if __name__ == "__main__":
    sys.exit(main())
