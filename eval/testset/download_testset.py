#!/usr/bin/env python3
"""Download vulnerable + patched plugin zips from a candidate manifest
candidates (candidates_test.json), into per-record folders mirroring the dev
corpus layout so the existing eval harness can read them:

  plugins/<slug>/<slug>.<vulnver>_VULNERABLE.zip
  plugins/<slug>/<slug>.<patchver>_PATCHED.zip

Skips records already downloaded. Verifies each zip is a real archive.
The released archive already contains these files; this is retained for a new
candidate list. Paths written to the output manifest are relative and portable.
"""
import json, os, subprocess, zipfile, argparse

HERE = os.path.dirname(os.path.abspath(__file__))
DEFAULT_DATA = os.environ.get("WISP_TESTSET_DIR", os.path.join(HERE, "data"))
UA = ("Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 "
      "(KHTML, like Gecko) Chrome/126.0 Safari/537.36")


def fetch(url, dest, timeout=120):
    try:
        r = subprocess.run(["curl", "-gsL", "--max-time", str(timeout),
                            "-H", f"User-Agent: {UA}", "-o", dest, url],
                           capture_output=True, text=True)
        if r.returncode != 0 or not os.path.exists(dest):
            return False
        return zipfile.is_zipfile(dest)
    except Exception:
        return False


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--limit", type=int, default=0)
    ap.add_argument("--candidates", default=os.path.join(DEFAULT_DATA, "candidates_test.json"))
    ap.add_argument("--plugins-dir", default=os.path.join(DEFAULT_DATA, "plugins"))
    ap.add_argument("--manifest", default=os.path.join(DEFAULT_DATA, "testset_manifest.json"))
    a = ap.parse_args()
    with open(a.candidates, encoding="utf-8") as handle:
        cands = json.load(handle)
    if a.limit:
        cands = cands[:a.limit]
    ok = skip = fail = 0
    manifest = []
    for c in cands:
        slug = c["slug"]
        d = os.path.join(a.plugins_dir, slug)
        os.makedirs(d, exist_ok=True)
        vz = os.path.join(d, f"{slug}.{c['vulnerable_version']}_VULNERABLE.zip")
        pz = os.path.join(d, f"{slug}.{c['patched_version']}_PATCHED.zip")
        if os.path.exists(vz) and os.path.exists(pz) and \
                zipfile.is_zipfile(vz) and zipfile.is_zipfile(pz):
            skip += 1
            base = os.path.dirname(os.path.abspath(a.manifest))
            manifest.append({**c, "vuln_zip": os.path.relpath(vz, base),
                             "patched_zip": os.path.relpath(pz, base)})
            continue
        gv = os.path.exists(vz) and zipfile.is_zipfile(vz) or fetch(c["vulnerable_url"], vz)
        gp = os.path.exists(pz) and zipfile.is_zipfile(pz) or fetch(c["patched_url"], pz)
        if gv and gp:
            ok += 1
            base = os.path.dirname(os.path.abspath(a.manifest))
            manifest.append({**c, "vuln_zip": os.path.relpath(vz, base),
                             "patched_zip": os.path.relpath(pz, base)})
            print(f"  [{ok+skip:3}] {slug}: v={c['vulnerable_version']} p={c['patched_version']}",
                  flush=True)
        else:
            fail += 1
            for z in (vz, pz):
                if os.path.exists(z) and not zipfile.is_zipfile(z):
                    os.remove(z)
            print(f"  xx {slug}: download failed (v={gv} p={gp})", flush=True)
    os.makedirs(os.path.dirname(a.manifest) or ".", exist_ok=True)
    with open(a.manifest, "w", encoding="utf-8") as handle:
        json.dump(manifest, handle, indent=1)
    print(f"\nDONE downloaded {ok}, skipped {skip}, failed {fail}; "
          f"manifest {len(manifest)} usable records", flush=True)


if __name__ == "__main__":
    main()
