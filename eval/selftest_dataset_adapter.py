"""Regression-test and audit the Patchstack dataset archive identities."""
from __future__ import annotations

import argparse
import csv
import json
import os
import tempfile
import zipfile

from eval.datasets.patchstack import (
    PS_DIR,
    DatasetSchemaError,
    archive_provenance,
    load_rows,
)


def _write_zip(path, php_source):
    """Write byte-stable fixture ZIPs so their hashes are meaningful."""
    os.makedirs(os.path.dirname(path), exist_ok=True)
    info = zipfile.ZipInfo("identity-fixture/plugin.php", (1980, 1, 1, 0, 0, 0))
    info.compress_type = zipfile.ZIP_STORED
    info.external_attr = 0o100644 << 16
    with zipfile.ZipFile(path, "w") as archive:
        archive.writestr(info, php_source.encode("utf-8"))


def _write_workbook(path, vuln_file, patched_file):
    import openpyxl

    workbook = openpyxl.Workbook()
    sheet = workbook.active
    sheet.title = "Vulnerable Plugins"
    sheet.append([
        "Slug", "CVE", "Vulnerability Type", "Vulnerable Version",
        "Patched Version", "Vulnerable File", "Patched File",
    ])
    sheet.append([
        "identity-fixture", "CVE-2099-0001", "Cross Site Scripting (XSS)",
        "1.0.0", "1.0.1", vuln_file, patched_file,
    ])
    workbook.save(path)


def _regression_fixture():
    """One vulnerable + two patched ZIPs; metadata must select 1.0.1 exactly."""
    with tempfile.TemporaryDirectory(prefix="wisp-dataset-identity-") as data_dir:
        rel_dir = "plugins_01/identity-fixture"
        vuln_rel = f"{rel_dir}/identity-fixture.1.0.0-VULNERABLE.zip"
        patched_rel = f"{rel_dir}/identity-fixture.1.0.1-PATCHED.zip"
        decoy_rel = f"{rel_dir}/identity-fixture.9.9.9-PATCHED.zip"
        _write_zip(os.path.join(data_dir, vuln_rel), "<?php\necho $_GET['name'];\n")
        _write_zip(os.path.join(data_dir, patched_rel), "<?php\necho esc_html($_GET['name']);\n")
        _write_zip(os.path.join(data_dir, decoy_rel), "<?php\necho $_GET['name']; // unrelated\n")
        _write_workbook(
            os.path.join(data_dir, "patchstack_identity_fixture.xlsx"),
            vuln_rel,
            patched_rel,
        )

        rows = load_rows(data_dir)
        assert len(rows) == 1, rows
        row = rows[0]
        assert (row["slug"], row["cve"]) == ("identity-fixture", "CVE-2099-0001")
        assert row["vuln_file"] == vuln_rel
        assert row["patched_file"] == patched_rel
        assert os.path.basename(row["patched_zip"]) == "identity-fixture.1.0.1-PATCHED.zip"
        assert os.path.abspath(row["patched_zip"]) != os.path.abspath(
            os.path.join(data_dir, decoy_rel))
        identity = archive_provenance(row)
        assert identity["vulnerable_sha256"]
        assert identity["patched_sha256"]
        assert identity["patched_sha256"] != archive_provenance({
            "patched_zip": os.path.join(data_dir, decoy_rel),
        })["patched_sha256"]

        # A public CSV without Patched File (and without an identity manifest)
        # must fail closed instead of guessing from the directory contents.
        os.remove(os.path.join(data_dir, "patchstack_identity_fixture.xlsx"))
        with open(os.path.join(data_dir, "WISP-1108-CVE-Dataset.csv"), "w",
                  encoding="utf-8", newline="") as handle:
            handle.write("Slug,CVE,Vulnerability Type,Vulnerable File\n")
            handle.write(f"identity-fixture,CVE-2099-0001,XSS,{vuln_rel}\n")
        try:
            load_rows(data_dir)
        except DatasetSchemaError:
            pass
        else:
            raise AssertionError("public metadata without Patched File did not fail closed")

        manifest_dir = os.path.join(data_dir, "metadata")
        os.makedirs(manifest_dir)
        with open(os.path.join(manifest_dir, "archive-manifest.csv"), "w",
                  encoding="utf-8", newline="") as handle:
            writer = csv.DictWriter(handle, fieldnames=[
                "Slug", "CVE", "Vulnerable File", "Patched File",
                "Vulnerable SHA256", "Patched SHA256",
            ])
            writer.writeheader()
            writer.writerow({
                "Slug": "identity-fixture", "CVE": "CVE-2099-0001",
                "Vulnerable File": vuln_rel, "Patched File": patched_rel,
                "Vulnerable SHA256": identity["vulnerable_sha256"],
                "Patched SHA256": identity["patched_sha256"],
            })
        public_row = load_rows(data_dir)[0]
        assert public_row["patched_file"] == patched_rel
        public_identity = archive_provenance(public_row)
        assert public_identity["vulnerable_hash_matches_metadata"]
        assert public_identity["patched_hash_matches_metadata"]


def _audit_dataset(data_dir, expected, audit_out):
    rows = load_rows(data_dir)
    if len(rows) != expected:
        raise SystemExit(f"expected {expected} rows, loaded {len(rows)}")
    if len({(row["slug"], row["cve"]) for row in rows}) != len(rows):
        raise SystemExit("duplicate (slug, cve) keys")

    bad = []
    for row in rows:
        for field in ("vuln_zip", "patched_zip"):
            path = row[field]
            if not os.path.isfile(path):
                bad.append(f"{row['slug']}|{row['cve']}: missing {field}: {path}")
            elif not zipfile.is_zipfile(path):
                bad.append(f"{row['slug']}|{row['cve']}: invalid ZIP in {field}: {path}")
    if bad:
        raise SystemExit("dataset archive audit failed:\n" + "\n".join(bad[:20]))

    if audit_out:
        records = []
        for index, row in enumerate(rows, 1):
            identity = archive_provenance(row)
            if not (identity["vulnerable_hash_matches_metadata"]
                    and identity["patched_hash_matches_metadata"]):
                raise SystemExit(f"archive hash mismatch for {row['slug']}|{row['cve']}")
            records.append({
                "index": index,
                "slug": row["slug"],
                "cve": row["cve"],
                **identity,
            })
        report = {
            "schema_version": 1,
            "dataset_dir": os.path.abspath(data_dir),
            "record_count": len(records),
            "records": records,
        }
        os.makedirs(os.path.dirname(os.path.abspath(audit_out)), exist_ok=True)
        with open(audit_out, "w", encoding="utf-8") as handle:
            json.dump(report, handle, indent=2)
            handle.write("\n")
        print(f"archive identity report: {audit_out}")

    print(f"DATASET ADAPTER PASS: {len(rows)} exact vulnerable/patched archive pairs")


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--data-dir", default=os.environ.get("PS_DIR") or PS_DIR)
    parser.add_argument("--expected", type=int, default=1108)
    parser.add_argument("--audit-out", default="",
                        help="optional JSON report with both archive SHA-256 values per row")
    args = parser.parse_args()

    _regression_fixture()
    print("DATASET IDENTITY REGRESSION PASS: exact Patched File wins over decoy ZIP")
    if not os.path.isdir(args.data_dir):
        raise SystemExit(f"dataset directory not found: {args.data_dir}")
    _audit_dataset(args.data_dir, args.expected, args.audit_out)


if __name__ == "__main__":
    main()
