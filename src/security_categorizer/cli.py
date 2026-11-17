"""Command-line interface.

    security-categorizer categorize system.yaml -o out/
    security-categorizer types --search "monitoring"
    security-categorizer show C.3.5.8

Exit codes: 0 = done, 2 = bad input (file, data or categorization error).
"""

from __future__ import annotations

import argparse
import contextlib
import json
import sys
from datetime import datetime, timezone
from pathlib import Path

from security_categorizer import __version__
from security_categorizer.baseline import select_baseline
from security_categorizer.categorize import MODES, CategorizationError, categorize
from security_categorizer.datasets import DataError, load_info_types, load_nss_data
from security_categorizer.levels import OBJECTIVES
from security_categorizer.oscal import baseline_profile, system_characteristics
from security_categorizer.report import baseline_text, to_json, to_markdown
from security_categorizer.system import SpecError, load_spec


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="security-categorizer",
        description="FIPS 199 / CNSSI 1253 security categorization from NIST SP 800-60 information types.",
    )
    p.add_argument("--version", action="version", version=f"%(prog)s {__version__}")
    p.add_argument("--info-types", metavar="FILE", help="use this information-type dataset instead of SP 800-60 Rev. 1")
    sub = p.add_subparsers(dest="command", required=True)

    c = sub.add_parser("categorize", help="categorize a system and select its baseline")
    c.add_argument("system", help="system description (YAML or JSON)")
    c.add_argument("--mode", choices=MODES, help="override the mode in the file")
    c.add_argument("--nss-data", metavar="FILE", help="CNSSI 1253 Appendix D baseline data (JSON) for nss mode")
    c.add_argument("-o", "--out-dir", help="write categorization.{md,json}, baseline.txt, OSCAL files here")
    c.add_argument("--timestamp", help=argparse.SUPPRESS)  # fixed timestamp for reproducible samples

    t = sub.add_parser("types", help="list or search the information types")
    t.add_argument("--search", default="", help="words to match in ID, title or group")

    s = sub.add_parser("show", help="show one information type")
    s.add_argument("id", help="information type ID or title, e.g. C.3.5.8")
    return p


def write_outputs(spec, cat, selection, catalog, out_dir: Path, timestamp: str) -> list[Path]:
    out_dir.mkdir(parents=True, exist_ok=True)
    files = {
        "categorization.md": to_markdown(cat, selection, catalog),
        "categorization.json": to_json(cat, selection, catalog),
        "system-characteristics.json": json.dumps(system_characteristics(cat, spec.description), indent=2) + "\n",
    }
    if selection.controls:  # no baseline files when nss mode had no CNSSI data
        files["baseline.txt"] = baseline_text(selection)
        files["baseline-profile.json"] = json.dumps(baseline_profile(cat, selection, timestamp), indent=2) + "\n"
    written = []
    for name, text in files.items():
        path = out_dir / name
        path.write_text(text, encoding="utf-8")
        written.append(path)
    return written


def _categorize(args, catalog) -> int:
    spec = load_spec(args.system)
    if args.mode:
        from dataclasses import replace

        spec = replace(spec, mode=args.mode)
    cat = categorize(spec, catalog)
    nss_data = load_nss_data(args.nss_data) if args.nss_data else None
    selection = select_baseline(cat, nss_data)
    if cat.mode == "federal":
        print(f"{cat.system_name}: {cat.overall.label} ({cat.fips199_statement})")
    else:
        print(f"{cat.system_name}: CNSSI 1253 {cat.trigraph}")
    if selection.controls:
        print(f"Baseline: {selection.name}, {len(selection.controls)} controls")
    else:
        print(f"Baseline: not selected ({selection.source})")
    for note in cat.warnings:
        print(f"  note: {note}")
    if args.out_dir:
        timestamp = args.timestamp or datetime.now(timezone.utc).replace(microsecond=0).isoformat()
        for path in write_outputs(spec, cat, selection, catalog, Path(args.out_dir), timestamp):
            print(f"wrote {path}")
    print("Draft for review: the AO or designated representative approves the categorization (SP 800-37 task C-2).")
    return 0


def main(argv: list[str] | None = None) -> int:
    for stream in (sys.stdout, sys.stderr):
        if hasattr(stream, "reconfigure"):
            with contextlib.suppress(ValueError, OSError):
                stream.reconfigure(encoding="utf-8")
    args = build_parser().parse_args(argv)
    try:
        catalog = load_info_types(args.info_types)
        if args.command == "categorize":
            return _categorize(args, catalog)
        if args.command == "types":
            for t in catalog.search(args.search):
                levels = "/".join(t.provisional(o).letter for o in OBJECTIVES)
                print(f"{t.id:<9} {levels:<6} {t.title}")
            return 0
        t = catalog.get(args.id)
        print(f"{t.id} {t.title}")
        print(f"  group: {t.group_title}")
        for o in OBJECTIVES:
            note = " (footnoted exception in the source)" if o in t.footnoted else ""
            print(f"  {o}: {t.provisional(o).label}{note}")
        print(f"  source: {catalog.source.get('title', catalog.name)}")
        return 0
    except (SpecError, CategorizationError, DataError) as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 2


if __name__ == "__main__":  # pragma: no cover
    raise SystemExit(main())
