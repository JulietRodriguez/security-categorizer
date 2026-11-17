"""Regenerate the sample outputs in samples/*/output from samples/*/system.yaml.

    python tools/make_samples.py            # write
    python tools/make_samples.py --check    # exit 1 if committed outputs differ

The timestamp is fixed so the files only change when the code or the data changes.
"""

from __future__ import annotations

import argparse
import sys
import tempfile
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))

from security_categorizer.baseline import select_baseline  # noqa: E402
from security_categorizer.categorize import categorize  # noqa: E402
from security_categorizer.cli import write_outputs  # noqa: E402
from security_categorizer.datasets import load_info_types  # noqa: E402
from security_categorizer.system import load_spec  # noqa: E402

TIMESTAMP = "2026-11-17T12:00:00+00:00"
SAMPLES = sorted(p.parent for p in (ROOT / "samples").glob("*/system.yaml"))


def build(target_root: Path | None = None) -> dict[Path, str]:
    catalog = load_info_types()
    files: dict[Path, str] = {}
    for folder in SAMPLES:
        spec = load_spec(folder / "system.yaml")
        cat = categorize(spec, catalog)
        selection = select_baseline(cat)
        with tempfile.TemporaryDirectory() as tmp:
            for path in write_outputs(spec, cat, selection, catalog, Path(tmp), TIMESTAMP):
                files[folder / "output" / path.name] = path.read_text(encoding="utf-8")
    return files


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument("--check", action="store_true")
    args = ap.parse_args(argv)
    files = build()
    if args.check:
        stale = [p for p, t in files.items() if not p.is_file() or p.read_text(encoding="utf-8") != t]
        extra = [p for f in SAMPLES for p in (f / "output").glob("*") if p not in files]
        for p in stale + extra:
            print(f"out of date: {p.relative_to(ROOT)}", file=sys.stderr)
        return 1 if stale or extra else 0
    for path, text in files.items():
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(text, encoding="utf-8")
        print(f"wrote {path.relative_to(ROOT)}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
