"""Convert the released WISP-testset-325.csv to the scanner manifest schema."""
from __future__ import annotations
import argparse, csv, json, os


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("csv", help="released WISP-testset-325.csv")
    parser.add_argument("--plugins-dir", default="plugins",
                        help="extracted plugins directory, relative or absolute")
    parser.add_argument("--out", default="testset_manifest.json")
    args = parser.parse_args()
    rows = []
    with open(args.csv, newline="", encoding="utf-8-sig") as handle:
        for source in csv.DictReader(handle):
            rows.append({
                "slug": source["Slug"],
                "plugin_name": source.get("Plugin") or source["Slug"],
                "cve": source.get("CVE") or "",
                "vuln_type": source.get("Vulnerability Type") or source.get("Class") or "",
                "cvss": source.get("CVSS") or None,
                "vulnerable_version": source.get("Vulnerable Version") or "",
                "patched_version": source.get("Patched Version") or "",
                "disclosure_date": source.get("Disclosure") or "",
                "patchstack_url": source.get("Patchstack Reference") or "",
                "vuln_zip": os.path.join(args.plugins_dir, source["Slug"],
                                         os.path.basename(source["Vulnerable File"])),
                "patched_zip": os.path.join(args.plugins_dir, source["Slug"],
                                            os.path.basename(source["Patched File"])),
            })
    if len({row["slug"] for row in rows}) != len(rows):
        raise SystemExit("expected one record per plugin slug")
    os.makedirs(os.path.dirname(args.out) or ".", exist_ok=True)
    with open(args.out, "w", encoding="utf-8") as handle:
        json.dump(rows, handle, indent=1)
    print(f"wrote {len(rows)} records to {args.out}")


if __name__ == "__main__":
    main()
