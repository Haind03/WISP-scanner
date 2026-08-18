#!/usr/bin/env python3
"""Collect an UNTOUCHED test set for the WISP generalization experiment:
Patchstack advisories whose plugin slug is NOT in the 854-plugin development
corpus, with a downloadable vulnerable + patched WordPress.org version pair.

This is the reviewer's demanded slug-disjoint test set. We freeze the engine and
evaluate on plugins it has never seen. Prefer records that carry a CVE and a
recent disclosure date (temporally-later bonus), but slug-disjointness is the
hard requirement.

Resumable: checkpoints candidates_test.json after every hit.
Usage: python3 collect_testset.py [target] [pages]
"""
import json, os, sys, time
import collect as C
from topup import fetch_block_aware

HERE = os.path.dirname(os.path.abspath(__file__))
BASE = os.path.dirname(HERE)
OUT = os.path.join(BASE, "candidates_test.json")
DEV = os.path.join(BASE, "dev_slugs_854.txt")
PROBED = os.path.join(BASE, "probed_slugs.txt")   # every slug we already tried


def popular_slugs(pages):
    slugs = []
    for pg in range(1, pages + 1):
        url = ("https://api.wordpress.org/plugins/info/1.2/?action=query_plugins"
               f"&request[browse]=popular&request[per_page]=100&request[page]={pg}")
        raw = C.curl(url, timeout=40)
        try:
            d = json.loads(raw)
        except Exception:
            continue
        for p in d.get("plugins", []):
            s = p.get("slug")
            if s:
                slugs.append(s)
        time.sleep(0.4)
    return slugs


def newest_slugs(pages):
    """Also pull the 'new' and 'updated' browse orders so the pool skews to
    plugins outside the older development corpus (temporally-later bonus)."""
    out = []
    for browse in ("new_versions", "updated"):
        for pg in range(1, pages + 1):
            url = ("https://api.wordpress.org/plugins/info/1.2/?action=query_plugins"
                   f"&request[browse]={browse}&request[per_page]=100&request[page]={pg}")
            raw = C.curl(url, timeout=40)
            try:
                d = json.loads(raw)
            except Exception:
                continue
            for p in d.get("plugins", []):
                s = p.get("slug")
                if s:
                    out.append(s)
            time.sleep(0.4)
    return out


def main():
    target = int(sys.argv[1]) if len(sys.argv) > 1 else 340
    pages = int(sys.argv[2]) if len(sys.argv) > 2 else 40
    dev = {s.strip() for s in open(DEV) if s.strip()}
    results = json.load(open(OUT)) if os.path.exists(OUT) else []
    have = {r["slug"] for r in results}
    probed = {s.strip() for s in open(PROBED)} if os.path.exists(PROBED) else set()
    pool = popular_slugs(pages) + newest_slugs(pages // 2)
    seen = set()
    probe = []
    for s in pool:
        if s not in dev and s not in have and s not in probed and s not in seen:
            seen.add(s)
            probe.append(s)
    print(f"dev-excluded {len(dev)}, pool {len(pool)}, {len(probe)} fresh disjoint slugs "
          f"to probe, have {len(results)}, already-probed {len(probed)}, target {target}",
          flush=True)

    probed_fh = open(PROBED, "a")

    def mark(slug):
        probed_fh.write(slug + "\n")
        probed_fh.flush()

    tried = 0
    for slug in probe:
        if len(results) >= target:
            break
        tried += 1
        try:
            wpv = C.wp_versions(slug)
            time.sleep(0.4)
            if not wpv or not wpv.get("versions"):
                mark(slug)
                continue
            html = fetch_block_aware(
                f"https://patchstack.com/database/wordpress/plugin/{slug}/vulnerabilities",
                tries=3)
            if not html:
                print(f"  ~ {slug}: blocked (will retry next run)", flush=True)
                continue    # do NOT mark: allow retry on a later run
            recs = [r for r in C.parse_devalue_records(html) if r.get("product_slug") == slug]
            mark(slug)
            if not recs:
                time.sleep(2.4)
                continue
            pair = C.pick_pair(slug, recs, wpv)
            time.sleep(2.4)
            if not pair or pair["slug"] in dev:
                continue
            results.append(pair)
            have.add(slug)
            json.dump(results, open(OUT, "w"), indent=1)
            print(f"  [{len(results):3}] (try {tried:3}) {slug}: "
                  f"{(pair['vuln_type'] or '')[:22]:22} {pair['vulnerable_version']}"
                  f"->{pair['patched_version']} {pair['cve']} {pair['disclosure_date']}",
                  flush=True)
        except Exception as e:
            print(f"  !! {slug}: {type(e).__name__}: {e}", flush=True)
            continue
    json.dump(results, open(OUT, "w"), indent=1)
    print(f"\nDONE: {len(results)} disjoint candidates (probed {tried} this run)", flush=True)


if __name__ == "__main__":
    main()
