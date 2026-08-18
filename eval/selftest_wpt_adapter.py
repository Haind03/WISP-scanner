"""Offline regression checks for the wp-taint-scan result adapter."""
from eval.wpt_adapter import compact_findings


def main() -> None:
    payload = {
        "results": [
            {
                "check_id": "wp-open-redirect",
                "path": "/tmp/src/demo/redirect.php",
                "start": {"line": 7},
                "extra": {"context": {"access": "unknown"}},
            },
            {
                "check_id": "unsafe-use",
                "path": "/tmp/src/demo/inc/a.php",
                "start": {"line": 41},
                "extra": {
                    "context": {"access": "unknown"},
                    "dataflow_trace": {
                        "source": {"path": "demo/input.php", "line": 3},
                        "sink": {"path": "demo/inc/a.php", "line": 41},
                    },
                },
            },
            {
                "check_id": "wp-request-file-upload-without-cap-check",
                "path": "/tmp/src/demo/upload.php",
                "start": {"line": 12},
                "extra": {"context": {"access": "unauthenticated"}},
            },
            {
                "check_id": "render-callback-execution",
                "path": "/tmp/src/demo/render.php",
                "start": {"line": 8},
                "extra": {
                    "context": {"access": "unknown"},
                    "dataflow_trace": {
                        "source": {"path": "demo/render.php", "line": 8,
                                   "snippet": "apply_filters($tag, $_POST['value'])"},
                        "sink": {"path": "demo/render.php", "line": 19},
                    },
                },
            },
            {
                "check_id": "unsafe-use",
                "path": "/tmp/src/demo/inc/b.php",
                "start": {"line": 51},
                "extra": {"context": {"access": "unknown"}},
            },
        ]
    }
    rows = compact_findings(payload, "/tmp/src")
    assert rows[0]["path"] == "upload.php"
    assert rows[0]["line"] == 12
    assert rows[0]["classes"] == ["auth", "upload"]
    assert rows[1]["rule"] == "render-callback-execution"
    assert rows[1]["line"] == 19
    assert rows[1]["score"] == 360
    assert rows[2]["rule"] == "wp-open-redirect"
    assert rows[3]["line"] == 41
    assert rows[3]["classes"] == ["rce"]
    assert rows[3]["path"].endswith("inc/a.php")
    assert rows[4]["path"].endswith("inc/b.php")  # stable native tie order
    print("ALL WPT ADAPTER CASES PASS")


if __name__ == "__main__":
    main()
