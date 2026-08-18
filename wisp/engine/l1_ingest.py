"""L0 Ingest & Normalize.

Enumerate plugins from a directory. Each plugin may be either an extracted
directory or a .zip archive. For each plugin we recover its WordPress slug and
version from the main plugin header, which is what the ground-truth (CVE) table
keys on.
"""
from __future__ import annotations
import os
import re
import zipfile
import tempfile
import shutil
from dataclasses import dataclass, field


HEADER_NAME = re.compile(r"^[ \t/*#@]*Plugin Name:\s*(.+?)\s*$", re.IGNORECASE | re.MULTILINE)
HEADER_VER = re.compile(r"^[ \t/*#@]*Version:\s*(.+?)\s*$", re.IGNORECASE | re.MULTILINE)


@dataclass
class Plugin:
    slug: str
    version: str
    name: str
    root: str                       # directory holding the PHP files
    php_files: list[str] = field(default_factory=list)
    _tmp: str | None = None         # tempdir to clean up if extracted from zip

    def cleanup(self) -> None:
        if self._tmp and os.path.isdir(self._tmp):
            shutil.rmtree(self._tmp, ignore_errors=True)


def _read_header(root: str) -> tuple[str, str]:
    """Find the main plugin file header (Plugin Name / Version)."""
    name, version = "", ""
    for dirpath, _dirs, files in os.walk(root):
        for fn in files:
            if not fn.endswith(".php"):
                continue
            fp = os.path.join(dirpath, fn)
            try:
                with open(fp, "r", encoding="utf-8", errors="ignore") as fh:
                    head = fh.read(4096)
            except OSError:
                continue
            m = HEADER_NAME.search(head)
            if m:
                name = m.group(1).strip()
                v = HEADER_VER.search(head)
                version = v.group(1).strip() if v else ""
                return name, version
    return name, version


def _php_files(root: str) -> list[str]:
    out = []
    for dirpath, _dirs, files in os.walk(root):
        for fn in files:
            if fn.endswith(".php"):
                out.append(os.path.join(dirpath, fn))
    return out


def load_plugin(path: str) -> Plugin | None:
    """Load a single plugin from a directory or a .zip."""
    tmp = None
    if path.endswith(".zip"):
        tmp = tempfile.mkdtemp(prefix="wisp_")
        try:
            with zipfile.ZipFile(path) as zf:
                zf.extractall(tmp)
        except (zipfile.BadZipFile, OSError):
            shutil.rmtree(tmp, ignore_errors=True)
            return None
        root = tmp
        slug = os.path.splitext(os.path.basename(path))[0]
    else:
        root = path
        slug = os.path.basename(path.rstrip("/"))

    files = _php_files(root)
    if not files:
        if tmp:
            shutil.rmtree(tmp, ignore_errors=True)
        return None
    name, version = _read_header(root)
    # WordPress slug is normally the top folder name; strip a trailing version.
    slug = re.sub(r"[._-]?v?\d[\d.]*$", "", slug) or slug
    return Plugin(slug=slug, version=version, name=name or slug,
                  root=root, php_files=files, _tmp=tmp)


def iter_plugins(plugins_dir: str, limit: int = 0):
    """Yield Plugin objects from every entry in plugins_dir."""
    entries = sorted(os.listdir(plugins_dir))
    count = 0
    for entry in entries:
        p = os.path.join(plugins_dir, entry)
        if os.path.isdir(p) or p.endswith(".zip"):
            pl = load_plugin(p)
            if pl is None:
                continue
            yield pl
            count += 1
            if limit and count >= limit:
                return
